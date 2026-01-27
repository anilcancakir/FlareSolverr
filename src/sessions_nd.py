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
        session = Session(session_id, driver, created_at)

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
        self, session_id: str, ttl: Optional[timedelta] = None
    ) -> Tuple[Session, bool]:
        logging.debug(f"[SESSION] get() called: session_id={session_id}, ttl={ttl}")
        session, fresh = await self.create(session_id)

        if ttl is not None and not fresh and session.lifetime() > ttl:
            logging.debug(
                f"[SESSION] Session's lifetime ({session.lifetime()}) has expired (ttl={ttl}), recreating..."
            )
            session, fresh = await self.create(session_id, force_new=True)

        logging.debug(f"[SESSION] get() returning: session_id={session_id}, fresh={fresh}")
        return session, fresh

    def session_ids(self) -> list[str]:
        return list(self.sessions.keys())
