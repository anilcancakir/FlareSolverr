import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple
from uuid import uuid1

from selenium.webdriver.chrome.webdriver import WebDriver

import utils


@dataclass
class Session:
    session_id: str
    driver: WebDriver
    created_at: datetime
    proxy: Optional[dict] = None

    def lifetime(self) -> timedelta:
        return datetime.now() - self.created_at


class SessionsStorage:
    """SessionsStorage creates, stores and process all the sessions"""

    def __init__(self):
        self.sessions = {}

    def create(self, session_id: Optional[str] = None, proxy: Optional[dict] = None,
               force_new: Optional[bool] = False) -> Tuple[Session, bool]:
        """create creates new instance of WebDriver if necessary,
        assign defined (or newly generated) session_id to the instance
        and returns the session object. If a new session has been created
        second argument is set to True.

        Note: The function is idempotent, so in case if session_id
        already exists in the storage a new instance of WebDriver won't be created
        and existing session will be returned. Second argument defines if 
        new session has been created (True) or an existing one was used (False).
        """
        session_id = session_id or str(uuid1())

        if force_new:
            self.destroy(session_id)

        if self.exists(session_id):
            return self.sessions[session_id], False

        driver = utils.get_webdriver_uc(proxy)
        created_at = datetime.now()
        session = Session(session_id, driver, created_at, proxy)

        self.sessions[session_id] = session

        return session, True

    def exists(self, session_id: str) -> bool:
        return session_id in self.sessions

    def destroy(self, session_id: str) -> bool:
        """destroy closes the driver instance and removes session from the storage.
        The function is noop if session_id doesn't exist.
        The function returns True if session was found and destroyed,
        and False if session_id wasn't found.
        """
        if not self.exists(session_id):
            return False

        session = self.sessions.pop(session_id)
        if utils.PLATFORM_VERSION == "nt":
            session.driver.close()
        session.driver.quit()
        return True

    def get(self, session_id: str, ttl: Optional[timedelta] = None,
            proxy: Optional[dict] = None) -> Tuple[Session, bool]:
        """resolve the driver a request should run in.

        Carries the proxy for the same reason as the nodriver storage:
        both branches here build a driver, and calling create() with the
        session id alone built them unproxied without saying so, which
        sent the request out of the host's own address while the response
        still reported success.
        """
        if not self.exists(session_id):
            logging.warning(
                f'unknown session {session_id}; creating it for this request. '
                'the caller believed this driver already existed'
            )

        session, fresh = self.create(session_id, proxy=proxy)

        if not fresh and proxy is not None and proxy != session.proxy:
            raise Exception(
                f'Session {session_id} is bound to a different proxy than the one '
                'supplied with this request. Destroy the session and create it again.'
            )

        if ttl is not None and not fresh and session.lifetime() > ttl:
            logging.debug(f'session\'s lifetime has expired, so the session is recreated (session_id={session_id})')
            session, fresh = self.create(session_id, proxy=proxy or session.proxy, force_new=True)

        return session, fresh

    def session_ids(self) -> list[str]:
        return list(self.sessions.keys())
