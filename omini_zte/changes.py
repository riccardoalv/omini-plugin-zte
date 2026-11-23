"""The changes the plugin makes, each as the web interface's own form does it,
then read back (``apply_verify``) and undone when it does not take. The device
saves a change to its configuration as it applies it: there is no separate
save step."""

from __future__ import annotations

import ipaddress
from typing import Any

from omini_sdk import Change, Device, PluginError, log
from omini_sdk.changes import Failed, apply_verify

from omini_zte import reads
from omini_zte.client import Client
from omini_zte.collect import (
    PAUSE_PREFIX,
    Data,
    Slot,
    base_mac,
    build,
    client,
    mac,
    own_macs,
    radio_names,
    read,
    slots,
)

CHECK_IN = "in the ONT's web interface"
NAME_MAX = 32
# A reservation's name: longer ones are accepted and then silently dropped
# (F670L V9.0.11), so they are cut to this length.
RESERVATION_NAME_MAX = 10


def apply(cfg: Any, change: Change) -> list[Device]:
    with client(cfg) as c:
        handler = HANDLERS.get(change.kind)
        if handler is None:
            raise PluginError(f"the ZTE plugin does not make {change.kind} changes")
        value = change.value if isinstance(change.value, dict) else {}
        handler(c, value)
        return [build(read(c), c.host)]


def fresh(c: Client, r: reads.Read):
    return c.data(r.view, r.tag)


# --- DHCP reservations ---------------------------------------------------------------


def _bindings(c: Client) -> list[dict[str, str]]:
    return fresh(c, reads.RESERVATIONS).rows("OBJ_DHCPBIND_ID")


def _post_binding(c: Client, inst: str, m: str, ip: str, name: str, delete: bool = False):
    return c.change(
        reads.RESERVATIONS.view,
        reads.RESERVATIONS.tag,
        [
            ("IF_ACTION", "Delete" if delete else "Apply"),
            ("_InstID", inst),
            ("MACAddr", m),
            ("IPAddr", ip),
            ("Name", name),
        ],
    )


def _ipv4(value: Any, what: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value or "").strip()))
    except ValueError as e:
        raise PluginError(f"{what} must be an IPv4 address") from e


def _name(value: Any, fallback: str, limit: int = NAME_MAX) -> str:
    name = " ".join(str(value or "").split())[:limit].strip()
    return name or fallback


def reservation_set(c: Client, value: dict[str, Any]) -> None:
    m = mac(value.get("mac"))
    if not m:
        raise PluginError("a reservation needs a MAC address")
    ip = _ipv4(value.get("ip"), "the reserved address")
    name = _name(
        value.get("name"), m.replace(":", "")[-RESERVATION_NAME_MAX:], RESERVATION_NAME_MAX
    )
    before = [r for r in _bindings(c) if mac(r.get("MACAddr")) == m]
    clash = [r for r in _bindings(c) if r.get("IPAddr") == ip and mac(r.get("MACAddr")) != m]
    if clash:
        raise PluginError(f"{ip} is already reserved for {clash[0].get('MACAddr')}")

    def do():
        inst = before[0]["_InstID"] if before else "-1"
        _post_binding(c, inst, m, ip, name)
        # One reservation per MAC.
        for r in before[1:]:
            _post_binding(c, r["_InstID"], m, r.get("IPAddr", ""), r.get("Name", ""), True)

    def verify():
        mine = [r for r in _bindings(c) if mac(r.get("MACAddr")) == m]
        return len(mine) == 1 and mine[0].get("IPAddr") == ip and mine[0].get("Name") == name

    def undo():
        for r in [r for r in _bindings(c) if mac(r.get("MACAddr")) == m]:
            _post_binding(c, r["_InstID"], m, r.get("IPAddr", ""), r.get("Name", ""), True)
        for r in before:
            _post_binding(c, "-1", m, r.get("IPAddr", ""), r.get("Name", ""))

    apply_verify(do, verify, undo, message=f"could not reserve {ip} for {m}", check_in=CHECK_IN)


def reservation_delete(c: Client, value: dict[str, Any]) -> None:
    m = mac(value.get("mac"))
    if not m:
        raise PluginError("which reservation? (no MAC address)")
    before = [r for r in _bindings(c) if mac(r.get("MACAddr")) == m]
    if not before:
        return

    def do():
        for r in before:
            _post_binding(c, r["_InstID"], m, r.get("IPAddr", ""), r.get("Name", ""), True)

    def undo():
        have = {r.get("IPAddr") for r in _bindings(c) if mac(r.get("MACAddr")) == m}
        for r in before:
            if r.get("IPAddr") not in have:
                _post_binding(c, "-1", m, r.get("IPAddr", ""), r.get("Name", ""))

    apply_verify(
        do,
        lambda: not any(mac(r.get("MACAddr")) == m for r in _bindings(c)),
        undo,
        message=f"could not delete the reservation of {m}",
        check_in=CHECK_IN,
    )


# --- local DNS names -------------------------------------------------------------------


def _hosts(c: Client) -> list[dict[str, str]]:
    return fresh(c, reads.DNS_HOSTS).rows("ALLDNSHOST")


def _post_host(c: Client, inst: str, name: str, ip: str, delete: bool = False):
    return c.change(
        reads.DNS_HOSTS.view,
        reads.DNS_HOSTS.tag,
        [
            ("IF_ACTION", "Delete" if delete else "Apply"),
            ("_InstID", inst),
            ("OBJID", "DNS"),
            ("LeaseTime", "isDNSHOSTInst"),
            ("HostName", name),
            ("IPAddress", ip),
        ],
    )


def _dns_name(value: Any) -> str:
    name = str(value or "").strip().rstrip(".").lower()
    if not name or len(name) > 253 or " " in name:
        raise PluginError("a DNS name is needed (letters, digits, dots and dashes)")
    return name


def _is_v4(value: str | None) -> bool:
    try:
        ipaddress.IPv4Address(value or "")
        return True
    except ValueError:
        return False


def dns_set(c: Client, value: dict[str, Any]) -> None:
    name = _dns_name(value.get("name"))
    ip = _ipv4(value.get("ip"), "the address of a DNS name")
    before = [
        r
        for r in _hosts(c)
        if (r.get("HostName") or "").lower() == name and _is_v4(r.get("IPAddress"))
    ]

    def do():
        _post_host(c, before[0]["_InstID"] if before else "-1", name, ip)
        for r in before[1:]:
            _post_host(c, r["_InstID"], r.get("HostName", ""), r.get("IPAddress", ""), True)

    def mine():
        return [
            r
            for r in _hosts(c)
            if (r.get("HostName") or "").lower() == name and _is_v4(r.get("IPAddress"))
        ]

    def verify():
        found = mine()
        return len(found) == 1 and found[0].get("IPAddress") == ip

    def undo():
        for r in mine():
            _post_host(c, r["_InstID"], r.get("HostName", ""), r.get("IPAddress", ""), True)
        for r in before:
            _post_host(c, "-1", r.get("HostName", ""), r.get("IPAddress", ""))

    apply_verify(do, verify, undo, message=f"could not set {name}", check_in=CHECK_IN)


def dns_delete(c: Client, value: dict[str, Any]) -> None:
    name = _dns_name(value.get("name"))
    before = [
        r
        for r in _hosts(c)
        if (r.get("HostName") or "").lower() == name and _is_v4(r.get("IPAddress"))
    ]
    if not before:
        return

    def do():
        for r in before:
            _post_host(c, r["_InstID"], r.get("HostName", ""), r.get("IPAddress", ""), True)

    def undo():
        have = {(r.get("HostName"), r.get("IPAddress")) for r in _hosts(c)}
        for r in before:
            if (r.get("HostName"), r.get("IPAddress")) not in have:
                _post_host(c, "-1", r.get("HostName", ""), r.get("IPAddress", ""))

    apply_verify(
        do,
        lambda: (
            not any(
                (r.get("HostName") or "").lower() == name and _is_v4(r.get("IPAddress"))
                for r in _hosts(c)
            )
        ),
        undo,
        message=f"could not delete {name}",
        check_in=CHECK_IN,
    )


# --- pausing a device (the MAC filter) ---------------------------------------------------


def _filter(c: Client) -> dict[str, str]:
    return fresh(c, reads.MAC_FILTER).row("OBJ_FWBASE_ID")


def _rules(c: Client) -> list[dict[str, str]]:
    return fresh(c, reads.MAC_RULES).rows("OBJ_MACFILTER_ID")


def _post_rule(c: Client, inst: str, m: str, name: str, kind: str, delete: bool = False):
    return c.change(
        reads.MAC_RULES.view,
        reads.MAC_RULES.tag,
        [
            ("IF_ACTION", "Delete" if delete else "Apply"),
            ("_InstID", inst),
            ("SrcMacAddr", m),
            ("Protocol", "ALL"),
            ("Name", name),
            ("Type", kind),
        ],
    )


def _post_filter(c: Client, enabled: bool, target: str, url: dict[str, str]):
    return c.change(
        reads.MAC_FILTER.view,
        reads.MAC_FILTER.tag,
        [
            ("IF_ACTION", "Apply"),
            ("_InstID", "IGD"),
            ("MacFilterEnable", "1" if enabled else "0"),
            ("MacFilterTarget", target),
            ("UrlFilterEnable", url.get("UrlFilterEnable", "0")),
            ("UrlFilterTarget", url.get("UrlFilterTarget", "0")),
        ],
    )


def _own(c: Client) -> set[str]:
    data = Data(status=fresh(c, reads.STATUS))
    data.wan = fresh(c, reads.WAN)
    data.wlan_status = fresh(c, reads.WLAN_STATUS)
    return own_macs(data, base_mac(data))


def pause_set(c: Client, value: dict[str, Any]) -> None:
    m = mac(value.get("mac"))
    if not m:
        raise PluginError("which device? (no MAC address)")
    if m in _own(c):
        raise PluginError("the ONT cannot pause itself")
    g = _filter(c)
    if g.get("MacFilterEnable") == "1" and g.get("MacFilterTarget") != "Discard":
        raise PluginError(
            "the ONT's MAC filter is an allow list: a device cannot be paused without "
            "cutting off every other one (switch it to a block list in the ONT first)"
        )
    name = _name(f"{PAUSE_PREFIX} {_name(value.get('name'), '')}".strip(), PAUSE_PREFIX)
    # The ONT takes one rule per MAC.
    existing = [r for r in _rules(c) if mac(r.get("SrcMacAddr")) == m]
    if existing and "Route" not in existing[0].get("Type", ""):
        raise PluginError(
            f"the ONT's MAC filter already has a rule for {m} that does not cut its internet "
            f"({existing[0].get('Type')}): change it in the ONT"
        )
    was_on = g.get("MacFilterEnable") == "1"

    def do():
        if not existing:
            _post_rule(c, "-1", m, name, "Route")
        if not was_on:
            _post_filter(c, True, "Discard", g)

    def verify():
        now = _filter(c)
        on = now.get("MacFilterEnable") == "1" and now.get("MacFilterTarget") == "Discard"
        return on and any(mac(r.get("SrcMacAddr")) == m for r in _rules(c))

    def undo():
        if not was_on:
            _post_filter(c, False, g.get("MacFilterTarget") or "Discard", g)
        if not existing:
            for r in _rules(c):
                if mac(r.get("SrcMacAddr")) == m:
                    _post_rule(c, r["_InstID"], m, r.get("Name", ""), r.get("Type", ""), True)

    apply_verify(do, verify, undo, message=f"could not pause {m}", check_in=CHECK_IN)


def pause_delete(c: Client, value: dict[str, Any]) -> None:
    m = mac(value.get("mac"))
    if not m:
        raise PluginError("which device? (no MAC address)")
    before = [r for r in _rules(c) if mac(r.get("SrcMacAddr")) == m]
    if not before:
        return

    def do():
        for r in before:
            _post_rule(c, r["_InstID"], m, r.get("Name", ""), r.get("Type", "Route"), True)

    def undo():
        if not any(mac(r.get("SrcMacAddr")) == m for r in _rules(c)):
            for r in before:
                _post_rule(c, "-1", m, r.get("Name", ""), r.get("Type", "Route"))

    # The filter stays on: with no rule, a block list blocks nothing.
    apply_verify(
        do,
        lambda: not any(mac(r.get("SrcMacAddr")) == m for r in _rules(c)),
        undo,
        message=f"could not resume {m}",
        check_in=CHECK_IN,
    )


# --- Wi-Fi networks ---------------------------------------------------------------------


def _wifi(c: Client) -> tuple[list[Slot], dict[str, str]]:
    """The slots, and their passwords (decrypted with the page's token)."""
    answer = fresh(c, reads.SSIDS)
    data = Data(status=answer, ssids=answer)
    passwords = {}
    for r in answer.rows("OBJ_WLANPSK_ID"):
        try:
            passwords[r.get("_InstID", "").rsplit(".", 1)[0]] = c.secret(r.get("KeyPassphrase", ""))
        except ValueError:
            log.info("could not read the password of %s", r.get("_InstID"))
    return slots(data), passwords


def _post_slot(
    c: Client,
    slot: Slot,
    ssid: str,
    enabled: bool,
    password: str | None = None,
    secure: bool = False,
):
    fields: list[tuple[str, Any]] = [
        ("IF_ACTION", "Apply"),
        ("_InstID", slot.inst),
        ("ESSID", ssid),
        ("Enable", "1" if enabled else "0"),
    ]
    if secure:
        # WPA2-PSK with AES, as the web interface's "WPA2-PSK-AES".
        fields += [
            ("BeaconType", "11i"),
            ("11iAuthMode", "PSKAuthentication"),
            ("11iEncryptType", "AESEncryption"),
        ]
    if password is None:
        return c.change(reads.SSIDS.view, reads.SSIDS.tag, fields)
    fields += [("_InstID_PSK", f"{slot.inst}.PSK1"), ("_PSKCONIG", "Y")]
    return c.change(reads.SSIDS.view, reads.SSIDS.tag, fields, {"KeyPassphrase": password})


def _password(value: Any) -> str | None:
    if value in (None, ""):
        return None
    pw = str(value)
    if not 8 <= len(pw) <= 63:
        raise PluginError("a Wi-Fi password has 8 to 63 characters")
    return pw


def wifi_set(c: Client, value: dict[str, Any]) -> None:
    ssid = str(value.get("ssid") or "").strip()
    if not 1 <= len(ssid) <= 32:
        raise PluginError("a Wi-Fi network needs a name of 1 to 32 characters")
    if value.get("vlan") not in (None, 1):
        raise PluginError("the ONT does not put Wi-Fi networks on VLANs")
    password = _password(value.get("password"))
    enabled = value.get("enabled") is not False
    previous = str(value.get("previous") or "").strip() or ssid
    all_slots, passwords = _wifi(c)

    targets = [s for s in all_slots if s.ssid in (previous, ssid) and not s.default]
    new = not targets
    if new:
        if password is None:
            raise PluginError("a new Wi-Fi network needs a password (8 to 63 characters)")
        # The first free slot of each radio: the network on every band.
        for radio in sorted({s.radio for s in all_slots}):
            free = [s for s in all_slots if s.radio == radio and s.default]
            if free:
                targets.append(free[0])
        if not targets:
            raise PluginError("the ONT has no free Wi-Fi network left (8 at most)")

    def do():
        for s in targets:
            secure = password is not None and (new or s.security in ("open", None))
            _post_slot(c, s, ssid, enabled, password, secure)

    def verify():
        now, pw = _wifi(c)
        by = {s.inst: s for s in now}
        for t in targets:
            s = by.get(t.inst)
            if s is None or s.ssid != ssid or s.enabled != enabled:
                return False
            if password is not None and pw.get(t.inst) not in (None, password):
                raise Failed(f"{t.alias} kept its previous password")
        return True

    def undo():
        for s in targets:
            old_pw = passwords.get(s.inst) if password is not None else None
            _post_slot(c, s, s.ssid, s.enabled, old_pw or None)

    apply_verify(
        do, verify, undo, message=f"could not set the Wi-Fi network {ssid}", check_in=CHECK_IN
    )


def wifi_delete(c: Client, value: dict[str, Any]) -> None:
    ssid = str(value.get("ssid") or "").strip()
    all_slots, _ = _wifi(c)
    targets = [s for s in all_slots if s.ssid == ssid and not s.default]
    if not targets:
        return

    def do():
        for s in targets:
            # Off, and named as the device names the slot (SSID2): free again.
            _post_slot(c, s, s.alias, False)

    def verify():
        by = {s.inst: s for s in _wifi(c)[0]}
        return all(by.get(t.inst) and by[t.inst].default for t in targets)

    def undo():
        for s in targets:
            _post_slot(c, s, s.ssid, s.enabled)

    apply_verify(
        do, verify, undo, message=f"could not delete the Wi-Fi network {ssid}", check_in=CHECK_IN
    )


# --- a radio's channel ----------------------------------------------------------------------


def wifi_channel(c: Client, value: dict[str, Any]) -> None:
    radio = str(value.get("radio") or "")
    try:
        channel = int(value.get("channel"))
    except (TypeError, ValueError) as e:
        raise PluginError("which channel?") from e
    cfg = fresh(c, reads.RADIOS)
    data = Data(status=cfg, radios=cfg)
    bands = radio_names(data)
    inst = next((i for i, band in bands.items() if band == radio or i == radio), None)
    row = next((r for r in cfg.rows("OBJ_WLANSETTING_ID") if r.get("_InstID") == inst), None)
    if inst is None or row is None:
        raise PluginError(f"the ONT has no radio {radio}")
    if row.get("RadioStatus") != "1":
        raise PluginError(f"the {radio} radio is off")
    allowed = _channels(cfg, row)
    if allowed and channel not in allowed:
        raise PluginError(f"channel {channel} is not allowed on the {radio} radio")
    old = (row.get("Channel", ""), row.get("AutoChannelEnabled", ""))

    def post(ch: str, auto: str):
        return c.change(
            reads.RADIOS.view,
            reads.RADIOS.tag,
            [
                ("IF_ACTION", "Apply"),
                ("_InstID", inst),
                ("Channel", ch),
                ("AutoChannelEnabled", auto),
            ],
        )

    def verify():
        now = next(
            (
                x
                for x in fresh(c, reads.RADIOS).rows("OBJ_WLANSETTING_ID")
                if x.get("_InstID") == inst
            ),
            {},
        )
        if now.get("Channel") != str(channel) or now.get("AutoChannelEnabled") != "0":
            return False
        # The radio itself on the new channel (it restarts: a few seconds).
        status = fresh(c, reads.WLAN_STATUS).rows("OBJ_WLANCONFIGDRV_ID")
        used = {x.get("ChannelInUsed") for x in status if x.get("WLANViewName") == inst}
        return not used or str(channel) in used

    apply_verify(
        lambda: post(str(channel), "0"),
        verify,
        lambda: post(old[0] or str(channel), old[1] or "0"),
        message=f"could not move the {radio} radio to channel {channel}",
        check_in=CHECK_IN,
        undo_failed_apply=False,
    )


def _channels(cfg, row: dict[str, str]) -> set[int]:
    for r in cfg.rows("OBJ_CHANNEL_ID"):
        if (
            r.get("Band") == row.get("Band")
            and r.get("CountryCode") == row.get("CountryCode")
            and r.get("BandWidth") == row.get("BandWidth")
        ):
            return {int(x) for x in r.get("ChannelList", "").split(",") if x.strip().isdigit()}
    return set()


HANDLERS = {
    "reservation.set": reservation_set,
    "reservation.delete": reservation_delete,
    "dns.set": dns_set,
    "dns.delete": dns_delete,
    "pause.set": pause_set,
    "pause.delete": pause_delete,
    "wifi.set": wifi_set,
    "wifi.delete": wifi_delete,
    "wifi.channel": wifi_channel,
}
