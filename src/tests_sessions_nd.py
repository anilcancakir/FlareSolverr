"""Session bookkeeping tests for the nodriver storage.

These run without a browser. `utils` and `nodriver` are replaced with
stubs before `sessions_nd` is imported, because the thing under test is
which proxy a session is built with, not what the browser then does with
it.

Why this file exists: `get()` used to call `create()` with the session id
alone, so both of its browser-creating branches built an unproxied
browser and said nothing about it. A request that named a proxy still
egressed from the host's own address, and every response reported
success. The cases below pin the binding down at each branch.
"""

import asyncio
import sys
import threading
import types
import unittest
from datetime import timedelta

# Stub the two imports sessions_nd reaches for, before importing it.
_nodriver_stub = types.ModuleType('nodriver')


class _FakeBrowser:
    """Stands in for a real Chromium.

    Records the proxy it was built on and the event loop it was built on,
    because a real nodriver Browser can only be driven from that loop.
    """

    def __init__(self, proxy=None):
        self.proxy = proxy
        self.stopped = False
        self.built_on = asyncio.get_running_loop()
        self.stopped_on = None


_nodriver_stub.Browser = _FakeBrowser
sys.modules.setdefault('nodriver', _nodriver_stub)

_utils_stub = types.ModuleType('utils')
_utils_stub.built_with = []


async def _fake_get_webdriver_nd(proxy=None):
    _utils_stub.built_with.append(proxy)
    return _FakeBrowser(proxy)


async def _fake_after_run_cleanup(driver):
    driver.stopped = True
    driver.stopped_on = asyncio.get_running_loop()


_utils_stub.get_webdriver_nd = _fake_get_webdriver_nd
_utils_stub.after_run_cleanup = _fake_after_run_cleanup
sys.modules['utils'] = _utils_stub

import sessions_nd  # noqa: E402


PROXY_A = {'url': 'http://10.0.0.1:3128', 'username': 'u', 'password': 'p'}
PROXY_B = {'url': 'http://10.0.0.2:3128', 'username': 'u', 'password': 'p'}


def run(coro):
    return asyncio.run(coro)


class TestSessionsStorageProxyBinding(unittest.TestCase):

    def setUp(self):
        self.storage = sessions_nd.SessionsStorage()
        _utils_stub.built_with.clear()

    def tearDown(self):
        for session_id in self.storage.session_ids():
            run(self.storage.destroy(session_id))

    def test_create_remembers_the_proxy_it_was_given(self):
        session, fresh = run(self.storage.create('s1', proxy=PROXY_A))

        self.assertTrue(fresh)
        self.assertEqual(PROXY_A, session.proxy)
        self.assertEqual([PROXY_A], _utils_stub.built_with)

    def test_get_on_an_unknown_id_builds_with_the_requested_proxy(self):
        """The measured bypass.

        A caller naming a session FlareSolverr no longer has (the operator
        restarted the container, a reaper collected it) still named a
        proxy. The browser minted to serve that request must use it.
        """
        session, fresh = run(self.storage.get('ghost', proxy=PROXY_A))

        self.assertTrue(fresh)
        self.assertEqual([PROXY_A], _utils_stub.built_with)
        self.assertEqual(PROXY_A, session.proxy)

    def test_ttl_recreate_keeps_the_proxy_the_session_was_born_with(self):
        """The second door onto the same defect.

        A caller that sent the proxy once at `sessions.create` and then
        asks for a TTL-bounded reuse does not repeat it. The recreate has
        to carry the original binding forward rather than dropping to a
        direct connection.
        """
        run(self.storage.create('s1', proxy=PROXY_A))
        _utils_stub.built_with.clear()

        session, _ = run(self.storage.get('s1', ttl=timedelta(seconds=-1)))

        self.assertEqual([PROXY_A], _utils_stub.built_with)
        self.assertEqual(PROXY_A, session.proxy)

    def test_a_request_naming_a_different_proxy_is_refused(self):
        """Answering it would report an address the request never used."""
        run(self.storage.create('s1', proxy=PROXY_A))

        with self.assertRaises(Exception) as caught:
            run(self.storage.get('s1', proxy=PROXY_B))

        self.assertIn('bound to a different proxy', str(caught.exception))

    def test_a_request_naming_no_proxy_reuses_the_session_as_it_stands(self):
        """No proxy named is no opinion expressed, not a demand to go direct."""
        created, _ = run(self.storage.create('s1', proxy=PROXY_A))
        _utils_stub.built_with.clear()

        session, fresh = run(self.storage.get('s1'))

        self.assertFalse(fresh)
        self.assertIs(created.driver, session.driver)
        self.assertEqual([], _utils_stub.built_with)


class TestSessionsStorageEventLoopOwnership(unittest.TestCase):
    """A session's browser has to outlive the request that created it.

    flaresolverr.py answers every HTTP request with its own asyncio.run,
    so a browser built inside `sessions.create` used to be bound to a loop
    that was closed by the time the next request touched it. nodriver's
    browser-level websocket and the futures waiting on it stay tied to the
    loop they were made on, so the first browser-level CDP call from a
    later request never got an answer. Measured on 2026-11-01: a session
    `request.get` on a Cloudflare challenge hung in click_verify_nd's
    update_targets() until maxTimeout, while the same request without a
    session solved it in about 13 seconds.
    """

    def setUp(self):
        self.storage = sessions_nd.SessionsStorage()

    def tearDown(self):
        for session_id in self.storage.session_ids():
            run(self.storage.destroy(session_id))

    def test_the_browser_is_built_on_a_loop_that_outlives_the_creating_request(self):
        session, _ = run(self.storage.create('s1'))

        self.assertFalse(session.driver.built_on.is_closed())
        self.assertTrue(session.driver.built_on.is_running())

    def test_a_later_request_drives_the_browser_on_the_loop_it_was_built_on(self):
        session, _ = run(self.storage.create('s1'))

        async def current_loop():
            return asyncio.get_running_loop()

        used_on = run(session.loop.run(current_loop()))

        self.assertIs(session.driver.built_on, used_on)

    def test_cancelling_the_caller_cancels_the_work_on_the_session_loop(self):
        """A request that hits maxTimeout must not leave its solve running."""
        session, _ = run(self.storage.create('s1'))
        cancelled = threading.Event()

        async def solve_forever():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                cancelled.set()
                raise

        async def caller():
            await asyncio.wait_for(session.loop.run(solve_forever()), timeout=0.05)

        with self.assertRaises(TimeoutError):
            run(caller())

        self.assertTrue(cancelled.wait(timeout=2))

    def test_destroy_stops_the_session_loop(self):
        session, _ = run(self.storage.create('s1'))
        loop = session.driver.built_on

        run(self.storage.destroy('s1'))

        self.assertTrue(session.driver.stopped)
        self.assertTrue(loop.is_closed())

    def test_a_browser_that_fails_to_start_does_not_leak_its_loop(self):
        threads_before = threading.active_count()

        async def failing_get_webdriver_nd(proxy=None):
            raise RuntimeError('chromium did not start')

        original = _utils_stub.get_webdriver_nd
        _utils_stub.get_webdriver_nd = failing_get_webdriver_nd
        try:
            with self.assertRaises(RuntimeError):
                run(self.storage.create('s1'))
        finally:
            _utils_stub.get_webdriver_nd = original

        self.assertFalse(self.storage.exists('s1'))
        self.assertEqual(threads_before, threading.active_count())


if __name__ == '__main__':
    unittest.main()
