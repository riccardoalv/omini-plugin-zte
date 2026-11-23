"""A fake ZTE ONT speaking the web interface's protocol over the recorded
(anonymized) answers of a real F670L in tests/fixtures/<page>__<data>.xml.

It checks what the real one checks: the login hash, one session at a time,
data only after its page was loaded, the Check header of every change (with a
key pair of the test, the plugin's public key swapped for it) and secret
fields encrypted with the key the ``encode`` field carries. Changes edit its
tables, which later reads return; quirks seen on the real device are kept
(a reservation named with more than 10 characters is accepted and dropped;
one MAC filter rule per MAC; channel 0 refused).
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from functools import partial
from pathlib import Path
from urllib.parse import parse_qsl
from xml.sax.saxutils import escape

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import omini_zte.collect as collect_module
from omini_zte import crypto
from omini_zte.answer import parse
from omini_zte.client import Client

FIXTURES = Path(__file__).parent / "fixtures"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC = KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)
BASE = "64:db:38:00:00:46"
HOST = "192.168.100.1"

HTML_404 = "<html><head><title>404 Not Found</title></head><body>404</body></html>"


def xml_answer(objects: dict, values: dict | None = None, encoded=()) -> str:
    out = ["<ajax_response_xml_root>"]
    for k, v in {
        "IF_ERRORPARAM": "SUCC",
        "IF_ERRORTYPE": "SUCC",
        "IF_ERRORSTR": "SUCC",
        "IF_ERRORID": "0",
        **(values or {}),
    }.items():
        out.append(f"<{k}>{escape(str(v))}</{k}>")
    for obj, rows in objects.items():
        out.append(f"<{obj}>")
        for row in rows:
            out.append("<Instance>")
            for name, value in row.items():
                out.append(
                    f"<ParaName>{escape(name)}</ParaName><ParaValue>{escape(value)}</ParaValue>"
                )
            out.append("</Instance>")
        out.append(f"</{obj}>")
        enc = [e for e in encoded if e[0] == obj]
        if enc:
            out.append(f"<encode>{','.join(e[1] for e in enc)}</encode>")
    out.append("</ajax_response_xml_root>")
    return "".join(out)


def error(code: str, param: str = "SUCC") -> str:
    return xml_answer(
        {},
        {"IF_ERRORSTR": "FAIL", "IF_ERRORID": code, "IF_ERRORPARAM": param, "IF_ERRORTYPE": "-1"},
    )


TIMEOUT = (
    '<?xml version="1.0"?><ajax_response_xml_root><IF_ERRORSTR>SessionTimeout</IF_ERRORSTR>'
    "<IF_ERRORPARAM>SUCC</IF_ERRORPARAM><IF_ERRORTYPE>SUCC</IF_ERRORTYPE></ajax_response_xml_root>"
)


class FakeZte:
    def __init__(self):
        self.username, self.password = "admin", "secret"
        self.tables: dict[tuple[str, str], dict] = {}
        self.raw: dict[tuple[str, str], str] = {}
        for f in sorted(FIXTURES.glob("*.xml")):
            view, name = f.stem.split("__", 1)
            text = f.read_text()
            if text.lstrip().startswith("{"):
                self.raw[(view, name)] = text
                continue
            a = parse(text)
            self.tables[(view, name)] = {
                "objects": a.objects,
                "values": {k: v for k, v in a.values.items() if not k.startswith("IF_")},
            }
        # The Wi-Fi passwords (the device sends them encrypted).
        self.psk = {f"DEV.WIFI.AP{i}": f"default-pass-{i}" for i in range(1, 8)}
        self.psk["DEV.WIFI.AP1"] = self.psk["DEV.WIFI.AP5"] = "home-password"
        self.session: str | None = None
        self.form_token = ""
        self.random = ""
        self.view: str | None = None
        self.token = ""
        self.logins = self.logouts = 0
        self.locked = 0
        self.posts: list[tuple[str, dict]] = []
        self.ignore: set[str] = set()  # data whose changes "succeed" and do nothing
        self.counter = 100

    # --- tables ------------------------------------------------------------------

    def rows(self, view: str, name: str, obj: str) -> list[dict]:
        return self.tables[(view, name)]["objects"].setdefault(obj, [])

    def row(self, view, name, obj, inst):
        return next(r for r in self.rows(view, name, obj) if r.get("_InstID") == inst)

    def kick(self):
        """Someone else signs in (a browser): this session ends."""
        self.session = None

    # --- HTTP ----------------------------------------------------------------------

    def handler(self, request: httpx.Request) -> httpx.Response:
        q = dict(request.url.params)
        kind, tag = q.get("_type"), q.get("_tag", "")
        cookie = request.headers.get("cookie", "")
        signed = self.session is not None and f"SID={self.session}" in cookie
        if not kind:
            return httpx.Response(
                200,
                text="<html>login</html>",
                headers={"set-cookie": "SID=anonymous; PATH=/; HttpOnly"},
            )
        if kind == "loginData":
            return self.login_data(request, tag)
        if kind == "menuView":
            known = {v for v, _ in self.tables} | {v for v, _ in self.raw}
            if not signed or tag not in known:
                return httpx.Response(200, text=HTML_404)
            self.view = tag
            self.token = secrets.token_hex(12)
            esc = "".join(f"\\x{b:02x}" for b in self.token.encode())
            return httpx.Response(
                200, text=f'<html><script>_sessionTmpToken = "{esc}";</script></html>'
            )
        if kind == "menuData":
            if not signed:
                return httpx.Response(200, text=TIMEOUT)
            name = tag.split("&")[0].removesuffix(".lua")
            if request.method == "POST":
                return self.change(request, name)
            return self.read(name)
        return httpx.Response(404, text=HTML_404)

    def login_data(self, request, tag):
        if tag == "login_entry" and request.method == "GET":
            self.form_token = secrets.token_hex(8)
            return httpx.Response(
                200,
                json={
                    "lockingTime": self.locked,
                    "loginErrMsg": "",
                    "promptMsg": "",
                    "sess_token": self.form_token,
                },
            )
        if tag == "login_token":
            self.random = str(secrets.randbelow(10**8))
            return httpx.Response(
                200, text=f"<ajax_response_xml_root>{self.random}</ajax_response_xml_root>"
            )
        if tag == "login_entry":
            form = dict(parse_qsl(request.content.decode()))
            assert form["_sessionTOKEN"] == self.form_token
            good = hashlib.sha256((self.password + self.random).encode()).hexdigest()
            if form["Username"] != self.username or form["Password"] != good:
                return httpx.Response(
                    200,
                    json={
                        "sess_token": "x",
                        "loginErrMsg": "Login failed",
                        "lockingTime": 0,
                        "promptMsg": "",
                    },
                )
            self.logins += 1
            self.session = secrets.token_hex(16)
            self.view = None
            return httpx.Response(
                200,
                json={"sess_token": "y", "login_need_refresh": True},
                headers={"set-cookie": f"SID={self.session}; PATH=/; HttpOnly"},
            )
        if tag == "logout_entry":
            self.logouts += 1
            self.session = None
            return httpx.Response(200, text="")
        return httpx.Response(404)

    def read(self, name: str) -> httpx.Response:
        key = (self.view, name)
        if key in self.raw:
            return httpx.Response(200, text=self.raw[key])
        if key not in self.tables:
            # Data of another page than the one loaded: the device refuses it.
            return httpx.Response(200, text=TIMEOUT)
        t = self.tables[key]
        objects = dict(t["objects"])
        encoded = []
        if name == "wlan_wlansssidconf_lua":
            objects["OBJ_WLANPSK_ID"] = [
                {
                    "_InstID": f"{ap}.PSK1",
                    "KeyPassphrase": crypto.aes_encrypt(pw, self.token, self.token[::-1]),
                }
                for ap, pw in self.psk.items()
            ]
            encoded.append(("OBJ_WLANPSK_ID", "KeyPassphrase"))
        return httpx.Response(200, text=xml_answer(objects, t["values"], encoded))

    # --- changes ----------------------------------------------------------------------

    def change(self, request, name: str) -> httpx.Response:
        body = request.content.decode()
        check = base64.b64decode(request.headers["Check"])
        assert (
            KEY.decrypt(check, padding.PKCS1v15()).decode()
            == hashlib.sha256(body.encode()).hexdigest()
        ), "bad Check header"
        form = dict(parse_qsl(body, keep_blank_values=True))
        assert form.pop("_sessionTOKEN") == self.token, "stale page token"
        if "encode" in form:
            key, iv = (
                KEY.decrypt(base64.b64decode(form.pop("encode")), padding.PKCS1v15())
                .decode()
                .split("+")
            )
            for k in ("KeyPassphrase",):
                if k in form:
                    form[k] = crypto.aes_decrypt(form[k], key, iv)
        self.posts.append((name, form))
        if name in self.ignore:
            return httpx.Response(
                200, text=xml_answer({}, {"INSTIDENTITY": form.get("_InstID", "")})
            )
        handler = getattr(self, f"post_{name}", None)
        assert handler, f"unexpected change of {name}"
        return httpx.Response(200, text=handler(form))

    def _table(self, view, name, obj, form, prefix, fields, limit=None, unique=None):
        rows = self.rows(view, name, obj)
        inst = form["_InstID"]
        if form["IF_ACTION"] == "Delete":
            rows[:] = [r for r in rows if r["_InstID"] != inst]
            return xml_answer({}, {"_InstID": ""})
        values = {k: form.get(k, "") for k in fields}
        if inst == "-1":
            if unique and any(r.get(unique) == values[unique] for r in rows):
                return error("-257")
            self.counter += 1
            new = f"{prefix}{self.counter}"
            if not (limit and len(values.get("Name", "")) > limit):
                rows.append({"_InstID": new, **values})
            return xml_answer({}, {"INSTIDENTITY": new, "_InstID": new})
        if limit and len(values.get("Name", "")) > limit:
            return error("-257")
        row = next(r for r in rows if r["_InstID"] == inst)
        row.update(values)
        return xml_answer({}, {"INSTIDENTITY": inst, "_InstID": inst})

    def post_Localnet_LanMgrIpv4_DHCPStaticRule_lua(self, form):
        return self._table(
            "lanMgrIpv4",
            "Localnet_LanMgrIpv4_DHCPStaticRule_lua",
            "OBJ_DHCPBIND_ID",
            form,
            "DEV.V4DHCP.Server.Pool1.Bind",
            ("Name", "IPAddr", "MACAddr"),
            limit=10,
        )

    def post_dns_hostname_lua(self, form):
        assert form.get("OBJID") == "DNS"
        return self._table(
            "dns", "dns_hostname_lua", "ALLDNSHOST", form, "IGD.DNSHL", ("IPAddress", "HostName")
        )

    def post_firewall_macfilterv3_lua(self, form):
        if form["IF_ACTION"] != "Delete":
            assert form["Protocol"] == "ALL" and form["Type"] == "Route"
        return self._table(
            "filterCriteria",
            "firewall_macfilterv3_lua",
            "OBJ_MACFILTER_ID",
            form,
            "DEV.FW.CHAIN1.MACF",
            ("Type", "Protocol", "Name", "SrcMacAddr"),
            unique="SrcMacAddr",
        )

    def post_firewall_filterglobal_lua(self, form):
        row = self.row("filterCriteria", "firewall_filterglobal_lua", "OBJ_FWBASE_ID", "IGD")
        for k in ("MacFilterEnable", "MacFilterTarget", "UrlFilterEnable", "UrlFilterTarget"):
            row[k] = form[k]
        return xml_answer({}, {"INSTIDENTITY": "IGD"})

    def post_wlan_wlansssidconf_lua(self, form):
        row = self.row("wlanBasic", "wlan_wlansssidconf_lua", "OBJ_WLANAP_ID", form["_InstID"])
        for k in ("ESSID", "Enable", "BeaconType", "11iAuthMode", "11iEncryptType"):
            if k in form:
                row[k] = form[k]
        if "KeyPassphrase" in form:
            assert form["_InstID_PSK"] == form["_InstID"] + ".PSK1"
            self.psk[form["_InstID"]] = form["KeyPassphrase"]
        return xml_answer({}, {"INSTIDENTITY": form["_InstID"]})

    def post_wlan_wlanbasicadconf_lua(self, form):
        if form.get("Channel") == "0":
            return error("-257", "Channel")
        row = self.row(
            "wlanBasic", "wlan_wlanbasicadconf_lua", "OBJ_WLANSETTING_ID", form["_InstID"]
        )
        row.update({k: form[k] for k in ("Channel", "AutoChannelEnabled") if k in form})
        if row.get("RadioStatus") == "1":
            for r in self.rows("localNetStatus", "wlan_wlanstatus_lua", "OBJ_WLANCONFIGDRV_ID"):
                if r.get("WLANViewName") == form["_InstID"]:
                    r["ChannelInUsed"] = row["Channel"]
        return xml_answer({}, {"INSTIDENTITY": form["_InstID"]})


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Tests never reach a real device (a wrong password counts against its
    login lock)."""

    def refuse(self, request):
        raise AssertionError(f"a test tried to reach {request.url}")

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", refuse)


@pytest.fixture
def zte(monkeypatch):
    fake = FakeZte()
    monkeypatch.setattr(crypto, "PUBLIC_KEY", PUBLIC)
    monkeypatch.setattr(
        collect_module, "Client", partial(Client, transport=httpx.MockTransport(fake.handler))
    )
    # apply_verify waits between checks.
    monkeypatch.setattr("time.sleep", lambda s: None)
    return fake


@pytest.fixture
def cfg(tmp_path):
    from omini_sdk.plugin import Config

    return Config(
        {"url": f"http://{HOST}", "username": "admin", "password": "secret"}, state_dir=tmp_path
    )


def run(plugin, config: dict, action: str = "collect", change: dict | None = None, state=None):
    request = {
        "protocol": 1,
        "action": action,
        "config": config,
        "state_dir": str(state) if state else None,
    }
    if change is not None:
        request["change"] = change
    response, _ = plugin.handle(json.dumps(request))
    return response
