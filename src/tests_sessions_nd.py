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
import types
import unittest
from datetime import timedelta

# Stub the two imports sessions_nd reaches for, before importing it.
_nodriver_stub = types.ModuleType('nodriver')


class _FakeBrowser:
    """Stands in for a real Chromium. Records the proxy it was built on."""

    def __init__(self, proxy=None):
        self.proxy = proxy
        self.stopped = False


_nodriver_stub.Browser = _FakeBrowser
sys.modules.setdefault('nodriver', _nodriver_stub)

_utils_stub = types.ModuleType('utils')
_utils_stub.built_with = []


async def _fake_get_webdriver_nd(proxy=None):
    _utils_stub.built_with.append(proxy)
    return _FakeBrowser(proxy)


async def _fake_after_run_cleanup(driver):
    driver.stopped = True


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


if __name__ == '__main__':
    unittest.main()
