import logging
import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple
from uuid import uuid1

from nodriver import Browser

import utils


@dataclass
class Session:
    session_id: str
    driver: Browser
    created_at: datetime
    proxy: Optional[dict] = None

    def lifetime(self) -> timedelta:
        return datetime.now() - self.created_at


class SessionsStorage:
    """SessionsStorage creates, stores and process all the sessions"""

    def __init__(self):
        self.sessions = {}

    async def create(
        self,
        session_id: Optional[str] = None,
        proxy: Optional[dict] = None,
        force_new: Optional[bool] = False,
    ) -> Tuple[Session, bool]:
        """create new instance of Browser if necessary,
        assign defined (or newly generated) session_id to the instance
        and returns the session object. If a new session has been created
        second argument is set to True.

        Note: The function is idempotent, so if session_id
        already exists in the storage, a new instance of WebDriver won't be created
        and existing session will be returned. Second argument defines if
        new session has been created (True) or an existing one was used (False).
        """
        session_id = session_id or str(uuid1())
        logging.debug(f"[SESSION] create() called: session_id={session_id}, force_new={force_new}")

        if force_new:
            logging.debug(f"[SESSION] force_new=True, destroying existing session...")
            await self.destroy(session_id)

        if self.exists(session_id):
            logging.debug(f"[SESSION] Session already exists: {session_id}")
            return self.sessions[session_id], False

        logging.debug(f"[SESSION] Creating new session: {session_id}")
        driver = await utils.get_webdriver_nd(proxy)
        created_at = datetime.now()
        session = Session(session_id, driver, created_at, proxy)

        self.sessions[session_id] = session
        logging.debug(f"[SESSION] Session created successfully: {session_id}")
        logging.debug(f"[SESSION] Total active sessions: {len(self.sessions)}")

        return session, True

    def exists(self, session_id: str) -> bool:
        return session_id in self.sessions

    async def destroy(self, session_id: str) -> bool:
        """destroy closes the Browser instance and removes session from the storage.
        The function is noop if session_id doesn't exist.
        The function returns True if session was found and destroyed,
        and False if session_id wasn't found.
        """
        logging.debug(f"[SESSION] destroy() called: session_id={session_id}")
        if not self.exists(session_id):
            logging.debug(f"[SESSION] Session not found: {session_id}")
            return False

        session = self.sessions.pop(session_id)
        logging.debug(f"[SESSION] Cleaning up browser for session: {session_id}")
        await utils.after_run_cleanup(driver=session.driver)
        logging.debug(f"[SESSION] Session destroyed: {session_id}")
        logging.debug(f"[SESSION] Remaining active sessions: {len(self.sessions)}")
        return True

    async def get(
        self,
        session_id: str,
        ttl: Optional[timedelta] = None,
        proxy: Optional[dict] = None,
    ) -> Tuple[Session, bool]:
        """resolve the browser a request should run in.

        The proxy argument is not decoration. This function used to call
        create() with the session id alone, which meant both of its
        browser-creating branches built an UNPROXIED browser: the branch
        that runs when the id is unknown, and the branch that runs when
        the session outlived its ttl. Neither said anything about it, so
        the request egressed from the host's own address while every
        response still reported success. Measured on 2026-08-25: a
        request.get naming an unknown session with a dead proxy attached
        returned the live page instead of a proxy error, and the browser
        it silently minted then showed up healthy in sessions.list, so a
        caller reconciling against that list kept reusing it.

        So the proxy travels with the session now, and a recreate reuses
        whatever the session was born with when the caller does not
        name one.
        """
        logging.debug(f"[SESSION] get() called: session_id={session_id}, ttl={ttl}")

        if not self.exists(session_id):
            logging.warning(
                f"[SESSION] Unknown session {session_id}; creating it for this request. "
                "The caller believed this browser already existed."
            )

        session, fresh = await self.create(session_id, proxy=proxy)

        if not fresh:
            self.guard_proxy_matches(session, proxy)

        if ttl is not None and not fresh and session.lifetime() > ttl:
            logging.debug(
                f"[SESSION] Session's lifetime ({session.lifetime()}) has expired (ttl={ttl}), recreating..."
            )
            session, fresh = await self.create(
                session_id, proxy=proxy or session.proxy, force_new=True
            )

        logging.debug(f"[SESSION] get() returning: session_id={session_id}, fresh={fresh}")
        return session, fresh

    @staticmethod
    def guard_proxy_matches(session: Session, proxy: Optional[dict]) -> None:
        """refuse to serve a request through the wrong egress.

        A caller naming both a session and a proxy is asserting both. If
        the live browser was built on a different proxy we cannot honour
        that assertion, and answering anyway is how a scrape ends up
        reporting an address it never used. A caller that names no proxy
        is expressing no opinion and gets the session as it stands.
        """
        if proxy is None or proxy == session.proxy:
            return

        raise Exception(
            f"Session {session.session_id} is bound to a different proxy than the one "
            "supplied with this request. Destroy the session and create it again."
        )

    def session_ids(self) -> list[str]:
        return list(self.sessions.keys())
