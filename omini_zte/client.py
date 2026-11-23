"""Client for the ZTE ONT web interface, on the SDK's HTTP client.

How the interface works (F670L, firmware V9):

- ``GET /`` gives the ``SID`` cookie; ``GET /?_type=loginData&_tag=login_entry``
  a form token (and ``lockingTime`` while the login is locked);
  ``GET /?_type=loginData&_tag=login_token`` a random number; the login is a
  ``POST`` of ``sha256(password + random)`` to ``login_entry``, which answers
  ``{"login_need_refresh": true}`` when it worked.
- Every screen is a **page** (``/?_type=menuView&_tag=<menu>``) whose data
  comes from **data** URLs (``/?_type=menuData&_tag=<name>.lua``). The data
  answers only after its page was loaded in the same session, and every page
  carries the session token (``_sessionTmpToken``) changes must send back.
- A change is a ``POST`` of the page's form to its data URL
  (``IF_ACTION=Apply`` or ``Delete``, the instance in ``_InstID``, ``-1`` for
  a new one), signed with the ``Check`` header (crypto.py).
- **One session at a time**: signing in signs out whoever was signed in (the
  web interface in a browser too). So the plugin signs in at the start of
  each run and **signs out at the end**, holding the session only seconds.
  A data URL answering ``SessionTimeout`` (someone signed in meanwhile) is
  asked again once after signing in again.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
from omini_sdk import PluginError, log
from omini_sdk.http import Client as HttpClient
from omini_sdk.http import Forbidden, HttpError, LoginBackoff, NotFound, Unauthorized

from omini_zte import crypto
from omini_zte.answer import Answer, parse

TOKEN = re.compile(r'_sessionTmpToken\s*=\s*"((?:\\x[0-9a-fA-F]{2})*)"')
RANDOM = re.compile(r">\s*([^<\s]+)\s*<")

# As jQuery's $.ajax sends a form, and the device checks the Check header
# against the body as sent.
FORM = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}


class LoginRefused(Unauthorized):
    """The device refused the credentials: it counts the attempt and locks
    the login after a few, so the plugin waits before signing in again."""


class SessionLost(PluginError):
    """The session ended (someone else signed in, or it timed out)."""


def encode_uri(value: str) -> str:
    # JavaScript's encodeURIComponent, as the web interface encodes values.
    return quote(value, safe="-_.!~*'()")


class Client(HttpClient):
    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        *,
        verify_tls: bool = False,
        timeout: float = 15,
        state_dir: Path | str | None = None,
        transport: httpx.BaseTransport | None = None,
        public_key: bytes | None = None,
    ):
        super().__init__(
            url,
            name="the ONT",
            scheme="http",
            verify_tls=verify_tls,
            timeout=timeout,
            user_agent="omini-plugin-zte",
            headers={"X-Requested-With": "XMLHttpRequest"},
            transport=transport,
        )
        self.username = username
        self.password = password
        self.key = crypto.public_key(public_key or crypto.PUBLIC_KEY)
        self.backoff_login = LoginBackoff(state_dir, self.base, username, password, minutes=10)
        self.signed_in = False
        self.view: str | None = None
        self.token = ""

    def __exit__(self, *exc: object) -> None:
        try:
            self.logout()
        finally:
            super().__exit__(*exc)

    # --- session ----------------------------------------------------------------

    def login(self) -> None:
        self.backoff_login.check()
        try:
            self._login()
        except LoginRefused as e:
            # Only a refused password: a device out of reach or busy is asked
            # again next run.
            self.backoff_login.refused(str(e))
            raise
        self.backoff_login.clear()

    def _login(self) -> None:
        self.http.cookies.clear()
        self.signed_in = False
        self.view = None
        self.check(self.send("GET", "/"), "GET", "/")
        entry = self._json("GET", "/?_type=loginData&_tag=login_entry")
        locked = _int(entry.get("lockingTime"))
        if locked:
            raise PluginError(
                f"the ONT locked its login after failed attempts: try again in {locked} s"
            )
        if "sess_token" not in entry:
            raise PluginError("this does not look like a ZTE ONT (no login form)")
        r = self.send("GET", "/?_type=loginData&_tag=login_token")
        self.check(r, "GET", "login_token")
        m = RANDOM.search(r.text)
        if not m:
            raise PluginError("this does not look like a ZTE ONT (no login token)")
        answer = self._json(
            "POST",
            "/?_type=loginData&_tag=login_entry",
            data={
                "action": "login",
                "Password": crypto.login_hash(self.password, m.group(1)),
                "Username": self.username,
                "_sessionTOKEN": entry["sess_token"],
            },
        )
        if answer.get("login_need_refresh") is True:
            self.signed_in = True
            return
        locked = _int(answer.get("lockingTime"))
        why = str(answer.get("loginErrMsg") or answer.get("promptMsg") or "").strip()
        if locked:
            raise LoginRefused(
                f"wrong username or password: the ONT locked its login for {locked} s",
                resource="login",
            )
        raise LoginRefused(
            f"wrong username or password{f' ({why})' if why else ''}", resource="login"
        )

    def logout(self) -> None:
        """Frees the device's only session (the web interface in a browser
        can sign in again). Errors are ignored: the session times out."""
        if not self.signed_in:
            return
        self.signed_in = False
        try:
            self.send(
                "POST",
                "/?_type=loginData&_tag=logout_entry",
                data={"IF_LogOff": "1", "_sessionTOKEN": self.token},
                headers=FORM,
            )
        except PluginError as e:
            log.info("could not sign out of the ONT: %s", e)

    def _json(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        r = self.send(method, path, **kw)
        self.check(r, method, path.rsplit("=", 1)[-1])
        try:
            data = r.json()
        except ValueError as e:
            raise PluginError("this does not look like a ZTE ONT (unexpected login answer)") from e
        return data if isinstance(data, dict) else {}

    # --- pages and data -----------------------------------------------------------

    def page(self, view: str) -> None:
        """Loads a page (its data answers only then) and keeps its token."""
        if not self.signed_in:
            self.login()
        path = f"/?_type=menuView&_tag={view}&Menu3Location=0"
        r = self.send("GET", path)
        self.check(r, "GET", view)
        m = TOKEN.search(r.text)
        if not m:
            # A signed-out session gets an error page without the token.
            self.view = None
            raise SessionLost(f"the ONT has no page {view}, or the session ended")
        self.token = bytes.fromhex(m.group(1).replace("\\x", "")).decode()
        self.view = view

    def _ensure(self, view: str) -> None:
        if self.view == view:
            return
        try:
            self.page(view)
        except SessionLost:
            log.info("the ONT session ended, signing in again")
            self.login()
            try:
                self.page(view)
            except SessionLost as e:
                # Signed in and still no page: the account may not open it (the
                # "user" account sees a few pages only), or this model lacks it.
                raise Forbidden(
                    f"the account cannot open the page {view}", method="GET", resource=view
                ) from e

    def _get(self, tag: str) -> str:
        r = self.send("GET", f"/?_type=menuData&_tag={tag}")
        self.check(r, "GET", tag)
        return r.text

    def data(self, view: str, tag: str) -> Answer:
        """A data URL of a page, as parsed name/value objects."""
        for again in (True, False):
            self._ensure(view)
            answer = parse(self._get(tag))
            if answer.expired and again:
                log.info("the ONT session ended reading %s, signing in again", tag)
                self.signed_in = False
                self.view = None
                continue
            if answer.expired:
                raise SessionLost(f"the ONT ended the session reading {tag}")
            if not answer.ok:
                raise NotFound(
                    f"the ONT could not read {tag} ({answer.status})", method="GET", resource=tag
                )
            return answer
        raise AssertionError("unreachable")

    def raw(self, view: str, tag: str) -> str:
        """A data URL that answers JSON (the topology)."""
        self._ensure(view)
        return self._get(tag)

    def secret(self, value: str) -> str:
        """A secret field the device sent (encrypted with the page's token)."""
        return crypto.aes_decrypt(value, self.token, self.token[::-1]) if value else ""

    # --- changes ----------------------------------------------------------------

    def change(
        self,
        view: str,
        tag: str,
        fields: list[tuple[str, Any]],
        secrets: dict[str, str] | None = None,
    ) -> Answer:
        """Posts a page's form (as its Apply or Delete button does): loads
        the page for a fresh token, reads its data as the page does, then
        sends the fields signed with the Check header. ``secrets`` are sent
        encrypted (with their key in ``encode``)."""
        self.view = None
        self._ensure(view)
        self._get(tag)
        items = [(k, "" if v is None else str(v)) for k, v in fields]
        if secrets:
            key, iv = crypto.random_digits(), crypto.random_digits()
            items += [(k, crypto.aes_encrypt(v, key, iv)) for k, v in secrets.items()]
            items.append(("encode", crypto.rsa_b64(self.key, f"{key}+{iv}")))
        body = "&".join(f"{k}={encode_uri(v)}" for k, v in items)
        body += f"&_sessionTOKEN={self.token}"
        r = self.send(
            "POST",
            f"/?_type=menuData&_tag={tag}",
            content=body,
            headers={**FORM, "Check": crypto.check_header(self.key, body)},
        )
        self.check(r, "POST", tag)
        # The page changes its token after a change.
        self.view = None
        answer = parse(r.text)
        if answer.expired:
            raise SessionLost("the ONT ended the session before the change")
        if not answer.ok:
            param = answer.values.get("IF_ERRORPARAM") or ""
            code = answer.values.get("IF_ERRORID") or ""
            what = f" (field {param})" if param and param != "SUCC" else ""
            raise HttpError(
                f"the ONT refused the change{what}, error {code}".rstrip(", "),
                method="POST",
                resource=tag,
            )
        return answer


def _int(value: Any) -> int:
    """A count of seconds; the device answers -1 for none."""
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0
