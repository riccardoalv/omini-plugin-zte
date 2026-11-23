"""Configuration backup: the settings of the web interface's pages as sorted
JSON. The device's own configuration file (Management → Default configuration)
is an encrypted binary, unreadable as text, so it is not used.

Left out: every field the device sends encrypted (passwords, PPPoE and TR-069
credentials, the Wi-Fi keys: they are encrypted with the session, so they
would differ on every backup anyway) and every status value (counters, times,
connection states), so two backups differ only when the configuration
changed."""

from __future__ import annotations

import json
from typing import Any

from omini_sdk import ConfigBackup, optional

from omini_zte import reads
from omini_zte.answer import Answer
from omini_zte.client import Client
from omini_zte.collect import client, device_key
from omini_zte.reads import Read

# Pages whose data is configuration: (page, data URL, objects to keep).
CONFIG: list[tuple[str, Read, tuple[str, ...]]] = [
    ("device", reads.STATUS, ("OBJ_DEVINFO_ID",)),
    ("wan", Read("ethWanConfig", "wan_internet_lua.lua&TypeUplink=2&pageType=0", "WAN"), ()),
    ("lan", reads.DHCP, ()),
    ("dhcp_reservations", reads.RESERVATIONS, ()),
    ("dhcpv6_server", Read("lanMgrIpv6", "dhcp6s_dhcpserver_lua.lua", "DHCPv6"), ()),
    ("wifi_radios", reads.RADIOS, ("OBJ_WLANSETTING_ID",)),
    ("wifi_networks", reads.SSIDS, ("OBJ_WLANAP_ID",)),
    ("wifi_band_steering", Read("wifibandsteer", "wlan_BandSteering_lua.lua", "band steering"), ()),
    ("wifi_mac_filter", Read("wlanAdvanced", "wlan_macfilteraclpolicy_lua.lua", "Wi-Fi ACL"), ()),
    (
        "wifi_mac_filter_rules",
        Read("wlanAdvanced", "wlan_macfilterrule_lua.lua", "Wi-Fi ACL rules"),
        (),
    ),
    ("dns_names", reads.DNS_HOSTS, ()),
    ("dns_servers", reads.DNS, ()),
    ("firewall", Read("firewall", "firewall_config_lua.lua", "firewall"), ()),
    ("filter", reads.MAC_FILTER, ()),
    ("mac_filter", reads.MAC_RULES, ()),
    ("ip_filter", Read("filterCriteria", "firewall_ipfilter_lua.lua", "IP filter"), ()),
    (
        "local_services",
        Read("localServiceCtrl", "firewall_ipv4service_lua.lua", "local services"),
        (),
    ),
    (
        "local_services_v6",
        Read("localServiceCtrl", "firewall_ipv6service_lua.lua", "local services v6"),
        (),
    ),
    ("port_forwards", reads.FORWARDS, ()),
    ("dmz", reads.DMZ, ()),
    ("alg", Read("alg", "firewall_alg_lua.lua", "ALG"), ()),
    ("upnp", reads.UPNP, ()),
    ("ddns", reads.DDNS, ()),
    ("ntp", reads.NTP, ()),
    ("static_routes", Read("routeIpv4", "route_routestaticipv4_lua.lua", "static routes"), ()),
    (
        "static_routes_v6",
        Read("routeIpv6", "route_routestaticipv6_lua.lua", "static routes v6"),
        (),
    ),
    ("port_binding", Read("portBinding", "portbinding_lua.lua", "port binding"), ()),
    ("tr069", Read("remoteMgr", "tr069_remotemgr_lua.lua", "TR-069"), ()),
    ("accounts", Read("accountMgr", "devauth_accountmgr_lua.lua", "accounts"), ()),
    ("login_timeout", Read("accountMgr", "web_login_timeout_lua.lua", "login timeout"), ()),
]

# Status values, never configuration.
VOLATILE = {
    "CurrentLocalTime",
    "Status",
    "ConnStatus",
    "ConnStatus6",
    "ConnError",
    "UpTime",
    "UpTimeV6",
    "PowerOnTime",
    "RadioStatus",
    # The PPP session's link-local addresses change on every reconnection.
    "LLA",
    "RemoteLLA",
    "GuaNum",
}


def section(answer: Answer, keep: tuple[str, ...]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for obj, items in sorted(answer.objects.items()):
        if keep and obj not in keep:
            continue
        out[obj] = [
            {k: v for k, v in sorted(row.items()) if k not in answer.encoded and k not in VOLATILE}
            for row in items
        ]
    return out


def config(c: Client) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, r, keep in CONFIG:
        answer = optional(r.name, lambda r=r: c.data(r.view, r.tag), None)
        if answer is not None:
            out[name] = section(answer, keep)
    return out


def backup(cfg: Any) -> list[ConfigBackup]:
    with client(cfg) as c:
        key = device_key(c)
        content = json.dumps(config(c), indent=1, sort_keys=True, ensure_ascii=False)
    return [ConfigBackup(device=key, format="json", content=content)]
