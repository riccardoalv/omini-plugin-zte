"""Reads a ZTE ONT (F670L and others with the same web interface) into one
Omini device."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from omini_sdk import (
    ArpEntry,
    Device,
    DhcpLease,
    DhcpReservation,
    DnsRecord,
    FdbEntry,
    Firmware,
    Gateway,
    Interface,
    PausedDevice,
    PluginError,
    PortForward,
    Radio,
    Service,
    Transceiver,
    WifiNetwork,
    WirelessClient,
    optional,
)
from omini_sdk.http import settings

from omini_zte import reads
from omini_zte.answer import Answer, Row
from omini_zte.client import Client

MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
LAN_PORT = re.compile(r"^LAN\d+$")
SSID_PORT = re.compile(r"^SSID\d+$")
# Rules the plugin creates to pause a device (the MAC filter's names).
PAUSE_PREFIX = "Omini pause"
SPEEDS = {"1": 10, "2": 100, "3": 1000, "4": 2500, "5": 5000, "6": 10000}
DUPLEX = {"1": "half", "2": "full"}
BANDS = {"2.4GHz": "2.4ghz", "5GHz": "5ghz", "6GHz": "6ghz"}


def client(cfg: Any) -> Client:
    url = cfg.str("url") or cfg.str("host")
    if not url or not cfg.str("password"):
        raise PluginError("the address and the password are required")
    return Client(
        url,
        cfg.str("username", "admin") or "admin",
        cfg.str("password"),
        state_dir=cfg.state_dir,
        **settings(cfg),
    )


# --- helpers ---------------------------------------------------------------------


def mac(value: str | None) -> str | None:
    m = (value or "").strip().lower().replace("-", ":")
    if not MAC.match(m) or m in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    return m


def num(value: str | None) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except ValueError:
        return None


def whole(value: str | None) -> int | None:
    n = num(value)
    return int(n) if n is not None else None


def ip(value: str | None) -> str | None:
    """An address the device set, never its placeholders (0.0.0.0, ::)."""
    try:
        a = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    return None if a.is_unspecified else str(a)


def prefix(address: str, mask: str | None) -> str:
    try:
        bits = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen if mask else 32
    except ValueError:
        bits = 32
    return f"{address}/{bits}"


def duid_mac(duid: str) -> str | None:
    """The MAC in a DUID-LLT (type 1) or DUID-LL (type 3) over Ethernet."""
    h = re.sub(r"[^0-9a-f]", "", duid.lower())
    if h.startswith("00010001") and len(h) == 28:
        raw = h[16:]
    elif h.startswith("00030001") and len(h) == 20:
        raw = h[8:]
    else:
        return None
    return mac(":".join(raw[i : i + 2] for i in range(0, 12, 2)))


# --- the reads -------------------------------------------------------------------


@dataclass
class Data:
    status: Answer
    optical: Answer | None = None
    wan: Answer | None = None
    lan: Answer | None = None
    lan_devices: Answer | None = None
    wlan_status: Answer | None = None
    wlan_clients: Answer | None = None
    arp: Answer | None = None
    macs: Answer | None = None
    leases: Answer | None = None
    reservations: Answer | None = None
    dhcp: Answer | None = None
    leases6: Answer | None = None
    radios: Answer | None = None
    ssids: Answer | None = None
    dns_hosts: Answer | None = None
    mac_filter: Answer | None = None
    mac_rules: Answer | None = None
    forwards: Answer | None = None
    upnp_maps: Answer | None = None
    dmz: Answer | None = None
    upnp: Answer | None = None
    ntp: Answer | None = None
    ddns: Answer | None = None
    topology: dict[str, Any] = field(default_factory=dict)


def read(c: Client, missing: list[str] | None = None) -> Data:
    def opt(r: reads.Read) -> Answer | None:
        return optional(r.name, lambda: c.data(r.view, r.tag), None, missing=missing)

    data = Data(status=c.data(reads.STATUS.view, reads.STATUS.tag))
    for name, r in (
        ("optical", reads.OPTICAL),
        ("wan", reads.WAN),
        ("lan", reads.LAN_PORTS),
        ("lan_devices", reads.LAN_DEVICES),
        ("wlan_status", reads.WLAN_STATUS),
        ("wlan_clients", reads.WLAN_CLIENTS),
        ("arp", reads.ARP),
        ("macs", reads.MACS),
        ("leases", reads.LEASES),
        ("reservations", reads.RESERVATIONS),
        ("dhcp", reads.DHCP),
        ("leases6", reads.LEASES6),
        ("radios", reads.RADIOS),
    ):
        setattr(data, name, opt(r))
    data.ssids = opt(reads.SSIDS)
    for name, r in (
        ("dns_hosts", reads.DNS_HOSTS),
        ("mac_filter", reads.MAC_FILTER),
        ("mac_rules", reads.MAC_RULES),
        ("forwards", reads.FORWARDS),
        ("upnp_maps", reads.UPNP_MAPS),
        ("dmz", reads.DMZ),
        ("upnp", reads.UPNP),
        ("ntp", reads.NTP),
        ("ddns", reads.DDNS),
    ):
        setattr(data, name, opt(r))
    topo = optional(
        reads.TOPOLOGY.name,
        lambda: json.loads(c.raw(reads.TOPOLOGY.view, reads.TOPOLOGY.tag)),
        {},
        missing=missing,
    )
    data.topology = topo if isinstance(topo, dict) else {}
    return data


def rows(answer: Answer | None, obj: str) -> list[Row]:
    return answer.rows(obj) if answer else []


def first(answer: Answer | None, obj: str) -> Row:
    return answer.row(obj) if answer else {}


# --- building the device -----------------------------------------------------------


@dataclass
class Slot:
    """One of the device's fixed Wi-Fi networks (SSID1..SSID8)."""

    inst: str  # DEV.WIFI.AP1
    alias: str  # SSID1
    radio: str  # DEV.WIFI.RD1
    ssid: str
    enabled: bool
    security: str | None
    row: Row

    @property
    def default(self) -> bool:
        """Untouched: off and named as the device names the slot."""
        return not self.enabled and self.ssid == self.alias


def security(row: Row) -> str | None:
    beacon = row.get("BeaconType", "")
    if beacon == "None":
        return "open"
    if "WPA3" in beacon or "SAE" in row.get("11iAuthMode", ""):
        return "wpa2wpa3" if "11i" in beacon or "WPA2" in beacon else "wpa3"
    if beacon in ("11i", "WPAand11i", "WPA"):
        return "wpa2"
    return None


def slots(data: Data) -> list[Slot]:
    out = []
    for r in rows(data.ssids, "OBJ_WLANAP_ID"):
        inst = r.get("_InstID", "")
        if not inst:
            continue
        out.append(
            Slot(
                inst=inst,
                alias=r.get("Alias") or inst.rsplit(".", 1)[-1],
                radio=r.get("WLANViewName", ""),
                ssid=r.get("ESSID", ""),
                enabled=r.get("Enable") == "1",
                security=security(r),
                row=r,
            )
        )
    return out


def radio_names(data: Data) -> dict[str, str]:
    """DEV.WIFI.RD1 → its band as the device names it (2.4GHz)."""
    names = {}
    for src in (data.radios, data.ssids, data.wlan_status):
        for r in rows(src, "OBJ_WLANSETTING_ID"):
            if r.get("_InstID") and r.get("Band"):
                names.setdefault(r["_InstID"], r["Band"])
    return names


def base_mac(data: Data) -> str | None:
    master = data.topology.get("master") if isinstance(data.topology, dict) else None
    found = mac((master or {}).get("MacAddr")) if isinstance(master, dict) else None
    if found:
        return found
    bssids = [mac(r.get("Bssid")) for r in rows(data.wlan_status, "OBJ_WLANCONFIGDRV_ID")]
    wans = [mac(r.get("WorkIFMac")) for r in rows(data.wan, "ID_WAN_COMFIG")]
    candidates = sorted(m for m in bssids[:1] + wans if m)
    return candidates[0] if candidates else None


def own_macs(data: Data, base: str | None) -> set[str]:
    found = {base} if base else set()
    for r in rows(data.wan, "ID_WAN_COMFIG"):
        if m := mac(r.get("WorkIFMac")):
            found.add(m)
    for r in rows(data.wlan_status, "OBJ_WLANCONFIGDRV_ID"):
        if m := mac(r.get("Bssid")):
            found.add(m)
    return found


def lan_ports(data: Data) -> list[Interface]:
    out = []
    for r in rows(data.lan, "OBJ_PON_PORT_BASIC_STATUS_ID"):
        n = re.search(r"(\d+)$", r.get("_InstID", ""))
        if not n:
            continue
        status = r.get("Status")
        up = status == "0"
        out.append(
            Interface(
                name=f"LAN{n.group(1)}",
                type="ethernet",
                connector="rj45",
                up=up,
                enabled=status != "3",
                speed_mbps=SPEEDS.get(r.get("Speed", "")) if up else None,
                duplex=DUPLEX.get(r.get("Duplex", "")) if up else None,
                rx_bytes=whole(r.get("InBytes")),
                tx_bytes=whole(r.get("OutBytes")),
                rx_errors=whole(r.get("InError")),
                tx_errors=whole(r.get("OutError")),
            )
        )
    return out


def pon(data: Data) -> Interface | None:
    o = first(data.optical, "OBJ_PON_OPTICALPARA_ID")
    if not data.optical:
        return None
    los = first(data.optical, "OBJ_LOS_INFO_ID").get("LosInfo")
    state = first(data.optical, "OBJ_GPONREGSTATUS_ID").get("RegStatus")
    volt = num(o.get("Volt"))
    return Interface(
        name="PON",
        description="GPON",
        type="other",
        # Registered with the OLT (state O5, operation) and receiving light.
        up=(state == "5" and los != "1") if state or los else None,
        transceiver=Transceiver(
            type="GPON",
            rx_power_dbm=num(o.get("RxPower")),
            tx_power_dbm=num(o.get("TxPower")),
            temperature_c=num(o.get("Temp")),
            # Millivolts.
            voltage_v=round(volt / 1000, 3) if volt is not None else None,
            bias_ma=num(o.get("Current")),
        )
        if o
        else None,
    )


def wans(data: Data) -> list[Row]:
    return [r for r in rows(data.wan, "ID_WAN_COMFIG") if r.get("Enable") == "1"]


def wan_interfaces(data: Data, has_pon: bool) -> list[Interface]:
    out = []
    for r in wans(data):
        name = r.get("WANCName") or r.get("_InstID", "WAN")
        ips = []
        if a := ip(r.get("IPAddress")):
            ips.append(prefix(a, r.get("SubnetMask")))
        for k in ("Gua1", "Gua2", "Gua3"):
            if a := ip(r.get(k)):
                bits = whole(r.get(f"{k}PrefixLen")) or 64
                ips.append(f"{a}/{bits}")
        vlan = whole(r.get("VLANID")) if r.get("VlanEnable") == "1" else None
        out.append(
            Interface(
                name=name,
                description=r.get("TransType") or None,
                type="other",
                mac=mac(r.get("WorkIFMac")),
                ips=ips or None,
                wan=r.get("mode") == "route",
                parent="PON" if has_pon else None,
                vlan=vlan if vlan and 1 <= vlan <= 4094 else None,
                up=r.get("ConnStatus") == "Connected" or r.get("ConnStatus6") == "Connected",
            )
        )
    return out


def gateways(data: Data) -> list[Gateway]:
    internet = [
        r for r in wans(data) if r.get("mode") == "route" and "INTERNET" in r.get("StrServList", "")
    ]
    connected = [r for r in internet if r.get("ConnStatus") == "Connected"]
    out = []
    for r in internet:
        name = r.get("WANCName") or r.get("_InstID", "WAN")
        if r.get("ConnStatus") == "Connected":
            status = "up"
        elif connected:
            # Another internet connection carries the traffic: this one is a
            # leftover of the operator's configuration, not an outage.
            status = "unknown"
        else:
            status = "down"
        out.append(
            Gateway(
                name=name,
                interface=name,
                address=ip(r.get("GateWay")) or ip(r.get("Gateway6")),
                status=status,
            )
        )
    return out


def lan_bridge(data: Data, base: str | None, ports: list[Interface]) -> Interface | None:
    cfg = first(data.dhcp, "OBJ_Br0AndDhcpsHosCfg_ID")
    address = ip(cfg.get("IPAddr"))
    if not address and not ports:
        return None
    return Interface(
        name="LAN",
        type="bridge",
        mac=base,
        ips=[prefix(address, cfg.get("SubnetMask") or cfg.get("SubMask"))] if address else None,
        members=[p.name for p in ports] or None,
        up=True,
    )


def ssid_interfaces(data: Data, radio_on: dict[str, bool]) -> list[Interface]:
    drv = {r.get("_InstID"): r for r in rows(data.wlan_status, "OBJ_WLANCONFIGDRV_ID")}
    out = []
    for s in slots(data):
        if s.default:
            continue
        d = drv.get(s.inst, {})
        out.append(
            Interface(
                name=s.alias,
                description=s.ssid,
                type="wireless",
                mac=mac(d.get("Bssid")),
                up=s.enabled and radio_on.get(s.radio, False),
                enabled=s.enabled,
                rx_bytes=whole(d.get("TotalBytesReceived")),
                tx_bytes=whole(d.get("TotalBytesSent")),
            )
        )
    return out


def radios(data: Data) -> list[Radio]:
    used = {}
    for r in rows(data.wlan_status, "OBJ_WLANCONFIGDRV_ID"):
        ch = whole(r.get("ChannelInUsed"))
        if ch and r.get("WLANViewName"):
            used.setdefault(r["WLANViewName"], ch)
    out = []
    for r in rows(data.radios, "OBJ_WLANSETTING_ID"):
        band = BANDS.get(r.get("Band", ""))
        if not band:
            continue
        auto = r.get("AutoChannelEnabled") == "1"
        channel = used.get(r.get("_InstID")) or (None if auto else whole(r.get("Channel")))
        width = re.fullmatch(r"(\d+)MHz", r.get("BandWidth", ""))
        out.append(
            Radio(
                name=r["Band"],
                band=band,
                channel=channel if channel and 1 <= channel <= 233 else None,
                width_mhz=int(width.group(1)) if width else None,
                auto=auto,
                enabled=r.get("RadioStatus") == "1",
            )
        )
    return out


def wifi_networks(data: Data) -> list[WifiNetwork]:
    by: dict[str, WifiNetwork] = {}
    for s in slots(data):
        if s.default or not s.ssid:
            continue
        net = by.get(s.ssid)
        if net is None:
            by[s.ssid] = WifiNetwork(ssid=s.ssid, security=s.security, enabled=s.enabled)
        elif s.enabled:
            net.enabled = True
    return list(by.values())


def wireless_clients(data: Data, bands: dict[str, str]) -> list[WirelessClient]:
    by_alias = {s.alias: s for s in slots(data)}
    out = []
    for r in rows(data.wlan_clients, "OBJ_WLAN_AD_ID"):
        m = mac(r.get("MACAddress"))
        if not m:
            continue
        alias = r.get("AliasName") or None
        slot = by_alias.get(alias or "")
        band = BANDS.get(bands.get(slot.radio, "")) if slot else None
        if not band:
            b = r.get("BAND", "").replace(" ", "").upper()
            band = "5ghz" if b.startswith("5") else "2.4ghz" if b.startswith("2") else None
        rssi = whole(r.get("RSSI"))
        tx, rx = num(r.get("TxRate")), num(r.get("RxRate"))
        out.append(
            WirelessClient(
                mac=m,
                interface=alias,
                ssid=r.get("ESSID") or (slot.ssid if slot else None),
                band=band,
                signal_dbm=rssi if rssi is not None and rssi < 0 else None,
                tx_rate_mbps=tx if tx and tx > 0 else None,
                rx_rate_mbps=rx if rx and rx > 0 else None,
            )
        )
    return out


def arp(data: Data) -> list[ArpEntry]:
    out = []
    for r in rows(data.arp, "OBJ_GETARPINST_ID"):
        m, a = mac(r.get("MACAddr")), ip(r.get("DestIP"))
        if m and a:
            out.append(ArpEntry(ip=a, mac=m, interface="LAN"))
    return out


def ndp(data: Data) -> list[ArpEntry]:
    out = []
    for r in rows(data.lan_devices, "OBJ_ACCESSDEV_ID"):
        m = mac(r.get("MACAddress"))
        for a in re.split(r"[,;\s]+", r.get("IPV6Address", "")):
            if m and (a := ip(a)) and ":" in a:
                out.append(ArpEntry(ip=a, mac=m, interface="LAN"))
    return out


def fdb(data: Data, own: set[str]) -> list[FdbEntry]:
    seen: dict[str, FdbEntry] = {}
    for r in rows(data.macs, "OBJ_GETMACINST_ID"):
        m, port = mac(r.get("MACAddr")), r.get("LanName", "")
        if m and m not in own and (LAN_PORT.match(port) or SSID_PORT.match(port)):
            seen[m] = FdbEntry(mac=m, port=port)
    # The connected devices list says the port too (when the MAC table aged out).
    for r in rows(data.lan_devices, "OBJ_ACCESSDEV_ID"):
        m, port = mac(r.get("MACAddress")), r.get("AliasName", "")
        if m and m not in own and m not in seen and LAN_PORT.match(port):
            seen[m] = FdbEntry(mac=m, port=port)
    return list(seen.values())


def leases(data: Data, now: datetime) -> list[DhcpLease]:
    out = []
    for r in rows(data.leases, "OBJ_DHCPHOSTINFO_ID"):
        m, a = mac(r.get("MACAddr")), ip(r.get("IPAddr"))
        if not (m and a):
            continue
        left = whole(r.get("ExpiredTime"))
        out.append(
            DhcpLease(
                ip=a,
                mac=m,
                hostname=r.get("HostName") or None,
                expires_at=now + timedelta(seconds=left) if left and left > 0 else None,
            )
        )
    for r in rows(data.leases6, "OBJ_DHCP6C_ID"):
        m, a = duid_mac(r.get("Duid", "")), ip(r.get("IpAddr"))
        if not (m and a):
            continue
        left = whole(r.get("ExpiredTime"))
        out.append(
            DhcpLease(
                ip=a, mac=m, expires_at=now + timedelta(seconds=left) if left and left > 0 else None
            )
        )
    return out


def reservations(data: Data) -> list[DhcpReservation]:
    out = []
    for r in rows(data.reservations, "OBJ_DHCPBIND_ID"):
        m, a = mac(r.get("MACAddr")), ip(r.get("IPAddr"))
        if m and a:
            out.append(DhcpReservation(mac=m, ip=a, name=r.get("Name") or None))
    return out


def dns_records(data: Data) -> list[DnsRecord]:
    out = []
    for r in rows(data.dns_hosts, "ALLDNSHOST"):
        name, a = (r.get("HostName") or "").strip().lower(), ip(r.get("IPAddress"))
        if name and a:
            out.append(DnsRecord(name=name, ip=a))
    return out


def filter_blocks(data: Data) -> bool:
    """The MAC filter is on, as a block list (its rules cut devices off)."""
    g = first(data.mac_filter, "OBJ_FWBASE_ID")
    return g.get("MacFilterEnable") == "1" and g.get("MacFilterTarget") == "Discard"


def paused(
    data: Data, arp_entries: list[ArpEntry], lease_list: list[DhcpLease]
) -> list[PausedDevice]:
    if not filter_blocks(data):
        return []
    ips: dict[str, list[str]] = {}
    for e in [*arp_entries, *lease_list]:
        if ":" not in e.ip and e.ip not in ips.setdefault(e.mac, []):
            ips[e.mac].append(e.ip)
    out: dict[str, PausedDevice] = {}
    for r in rows(data.mac_rules, "OBJ_MACFILTER_ID"):
        m = mac(r.get("SrcMacAddr"))
        if not m or "Route" not in r.get("Type", "Route"):
            continue
        name = r.get("Name") or ""
        ours = name.startswith(PAUSE_PREFIX)
        label = name[len(PAUSE_PREFIX) :].strip(" :-") if ours else name
        if m in out:
            if not ours:
                out[m].rule = out[m].rule or name or None
            continue
        out[m] = PausedDevice(
            mac=m,
            ips=sorted(ips.get(m, [])) or None,
            name=label or None,
            rule=None if ours else (name or "MAC filter"),
        )
    return list(out.values())


def port_forwards(data: Data) -> list[PortForward]:
    protocols = {"TCP": "tcp", "UDP": "udp", "BOTH": "tcp/udp", "TCP AND UDP": "tcp/udp"}
    out = []
    for r in rows(data.forwards, "OBJ_FWPM_ID"):
        ext = whole(r.get("ExternalPort"))
        proto = protocols.get(r.get("Protocol", "").upper())
        if not ext or not proto or not 1 <= ext <= 65535:
            continue
        end = whole(r.get("ExternalPortEndRange"))
        internal = whole(r.get("InternalPort"))
        out.append(
            PortForward(
                protocol=proto,
                external_port=ext,
                external_port_end=end if end and ext < end <= 65535 else None,
                internal_ip=ip(r.get("InternalClient")),
                internal_port=internal if internal and 1 <= internal <= 65535 else None,
                source=ip(r.get("RemoteHost")) if r.get("RemoteHost") else None,
                interface=None if r.get("AllInterface") == "1" else (r.get("Interface") or None),
                description=r.get("Description") or r.get("Alias") or None,
                enabled=r.get("Enable") == "1",
            )
        )
    for r in rows(data.upnp_maps, "OBJ_UPNPPORTMAP_ID"):
        ext = whole(r.get("ExternalPort"))
        proto = protocols.get(r.get("Protocol", "").upper())
        if not ext or not proto or not 1 <= ext <= 65535:
            continue
        internal = whole(r.get("InternalPort"))
        out.append(
            PortForward(
                protocol=proto,
                external_port=ext,
                internal_ip=ip(r.get("InternalClient")),
                internal_port=internal if internal and 1 <= internal <= 65535 else None,
                source=ip(r.get("ServerIPAddress")),
                enabled=True,
                upnp=True,
            )
        )
    d = first(data.dmz, "OBJ_FWDMZ_ID")
    if d.get("Enable") == "1" and ip(d.get("InternalClient")):
        # Every port of the WAN goes to the DMZ host.
        out.append(
            PortForward(
                protocol="tcp/udp",
                external_port=1,
                external_port_end=65535,
                internal_ip=ip(d.get("InternalClient")),
                description="DMZ",
                enabled=True,
            )
        )
    return out


def services(data: Data) -> list[Service]:
    out = []
    u = first(data.upnp, "OBJ_UPNPCONFIG_ID")
    if u:
        out.append(Service(name="UPnP IGD", enabled=u.get("EnableUPnPIGD") == "1"))
    n = first(data.ntp, "OBJ_SNTP_ID")
    if n:
        out.append(
            Service(
                name="SNTP",
                description=", ".join(s for s in (n.get("NtpServer1"), n.get("NtpServer2")) if s)
                or None,
                enabled=n.get("Enable") == "1",
            )
        )
    for r in rows(data.ddns, "OBJ_DDNSCLIENT_ID"):
        enabled = r.get("Enable") == "1"
        out.append(
            Service(
                name="Dynamic DNS",
                enabled=enabled,
                running=r.get("Status") == "Connected" if enabled else None,
            )
        )
        break
    return out


def build(data: Data, host: str, now: datetime | None = None) -> Device:
    now = now or datetime.now(timezone.utc)
    info = first(data.status, "OBJ_DEVINFO_ID")
    usage = first(data.status, "OBJ_CPUMEMUSAGE_ID")
    model = info.get("ModelName") or None
    if not info:
        raise PluginError("this does not look like a ZTE ONT (no device information)")
    base = base_mac(data)
    own = own_macs(data, base)

    cpus = [
        n for k, v in sorted(usage.items()) if k.startswith("CpuUsage") if (n := num(v)) is not None
    ]
    mem = num(usage.get("MemUsage"))
    uptime = whole(first(data.status, "OBJ_POWERONTIME_ID").get("PowerOnTime"))

    bands = radio_names(data)
    radio_list = radios(data)
    radio_on = {
        inst: any(r.name == band and r.enabled for r in radio_list) for inst, band in bands.items()
    }
    ports = lan_ports(data)
    pon_port = pon(data)
    interfaces = [
        *ports,
        *([b] if (b := lan_bridge(data, base, ports)) else []),
        *([pon_port] if pon_port else []),
        *wan_interfaces(data, pon_port is not None),
        *ssid_interfaces(data, radio_on),
    ]
    arp_entries = arp(data)
    lease_list = leases(data, now)
    wan_rows = wans(data)
    routing = any(r.get("mode") == "route" for r in wan_rows)

    ips = [i for x in interfaces if x.ips and x.type == "bridge" for i in x.ips]
    ips += [i for x in interfaces if x.ips and x.wan for i in x.ips]

    return Device(
        key=base or host,
        name=info.get("OnuAlias") or (f"ZTE {model}" if model else "ZTE ONT"),
        host=host,
        # An ONT that routes (PPPoE, NAT) is the router; one that only
        # bridges the fiber to a router behind it is not.
        role="router" if routing or not wan_rows else "unknown",
        vendor="ZTE",
        model=model,
        serial=info.get("SerialNumber") or None,
        os_version=info.get("SoftwareVer") or None,
        uptime_s=uptime if uptime and uptime > 0 else None,
        cpu_pct=round(sum(cpus) / len(cpus), 1) if cpus else None,
        mem_pct=mem if mem is not None and 0 <= mem <= 100 else None,
        firmware=Firmware(current=info["SoftwareVer"]) if info.get("SoftwareVer") else None,
        macs=sorted(own) or None,
        ips=[i.split("/")[0] for i in ips] or None,
        interfaces=interfaces or None,
        arp=arp_entries or None,
        ndp=ndp(data) or None,
        fdb=fdb(data, own) or None,
        dhcp_leases=lease_list or None,
        dhcp_reservations=reservations(data) if data.reservations else None,
        wireless_clients=wireless_clients(data, bands) or None,
        gateways=gateways(data) or None,
        wifi_networks=wifi_networks(data) if data.ssids else None,
        radios=radio_list or None,
        dns_records=dns_records(data) if data.dns_hosts else None,
        paused=paused(data, arp_entries, lease_list) if data.mac_filter else None,
        port_forwards=port_forwards(data) or None,
        services=services(data) or None,
    )


def device_key(c: Client) -> str:
    """The key collect reports, with the fewest reads (for backups)."""
    data = Data(status=c.data(reads.STATUS.view, reads.STATUS.tag))
    topo = optional(
        reads.TOPOLOGY.name, lambda: json.loads(c.raw(reads.TOPOLOGY.view, reads.TOPOLOGY.tag)), {}
    )
    data.topology = topo if isinstance(topo, dict) else {}
    if not base_mac(data):
        data.wan = optional(reads.WAN.name, lambda: c.data(reads.WAN.view, reads.WAN.tag), None)
        data.wlan_status = optional(
            reads.WLAN_STATUS.name,
            lambda: c.data(reads.WLAN_STATUS.view, reads.WLAN_STATUS.tag),
            None,
        )
    return base_mac(data) or c.host


def collect_one(c: Client, missing: list[str] | None = None) -> Device:
    return build(read(c, missing), c.host)


def collect(cfg: Any) -> list[Device]:
    with client(cfg) as c:
        return [collect_one(c)]


def test(cfg: Any) -> str:
    missing: list[str] = []
    with client(cfg) as c:
        device = collect_one(c, missing)
    text = f"Connected to {device.name}"
    if device.os_version:
        text += f" ({device.os_version})"
    if missing:
        text += f"; could not read {', '.join(missing)}"
    return text
