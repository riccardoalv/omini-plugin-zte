from datetime import datetime, timezone

import pytest
from omini_sdk import PluginError

import main
from omini_zte.collect import collect, duid_mac
from omini_zte.collect import test as connection_test
from tests.conftest import BASE, HOST, run


def device(cfg):
    (d,) = collect(cfg)
    return d


def by_name(d):
    return {i.name: i for i in d.interfaces}


def test_identity_and_health(zte, cfg):
    d = device(cfg)
    assert d.key == BASE  # the mesh controller's MAC (the LAN side)
    assert (d.name, d.vendor, d.model, d.role) == ("ZTE F670L", "ZTE", "F670L", "router")
    assert d.serial == "ZTEG00000001"
    assert d.os_version == "V9.0.11P1N49" and d.firmware.current == "V9.0.11P1N49"
    assert d.uptime_s == 531180
    assert d.cpu_pct == pytest.approx((50 + 14 + 0 + 0) / 4, abs=0.1)
    assert d.mem_pct == 65
    assert d.host == HOST
    assert "192.168.100.1" in d.ips and "100.64.0.10" in d.ips


def test_lan_ports(zte, cfg):
    ports = by_name(device(cfg))
    lan4 = ports["LAN4"]
    assert (lan4.up, lan4.speed_mbps, lan4.duplex, lan4.connector) == (True, 1000, "full", "rj45")
    assert (lan4.rx_bytes, lan4.tx_bytes) == (82192219950, 385714190667)
    # No link: no speed nor duplex.
    assert (ports["LAN1"].up, ports["LAN1"].speed_mbps, ports["LAN1"].duplex) == (False, None, None)
    bridge = ports["LAN"]
    assert bridge.type == "bridge" and bridge.ips == ["192.168.100.1/24"]
    assert bridge.members == ["LAN1", "LAN2", "LAN3", "LAN4"]


def test_pon_optics(zte, cfg):
    pon = by_name(device(cfg))["PON"]
    assert pon.up is True
    t = pon.transceiver
    assert (t.type, t.rx_power_dbm, t.tx_power_dbm) == ("GPON", -20.0436, 2.32)
    assert (t.temperature_c, t.voltage_v, t.bias_ma) == (41.347, 3.268, 11.65)
    # GPON's receiver sensitivity (class B+), not an Ethernet SFP's limit.
    assert t.rx_power_low_dbm == -27


def test_pon_without_light_is_down(zte, cfg):
    zte.rows("ponopticalinfo", "optical_info_lua", "OBJ_LOS_INFO_ID")[0]["LosInfo"] = "1"
    assert by_name(device(cfg))["PON"].up is False


def test_wan_connections_and_gateways(zte, cfg):
    d = device(cfg)
    wan = by_name(d)["omci_ipv4_pppoe_1"]
    assert wan.wan and wan.up and wan.parent == "PON" and wan.vlan == 2000
    assert wan.ips == ["100.64.0.10/32", "2001:db8:1:1:66db:38ff:fe00:47/64"]
    assert wan.mac == "64:db:38:00:00:47"
    (gw,) = d.gateways
    assert (gw.name, gw.status, gw.address) == ("omci_ipv4_pppoe_1", "up", "100.64.0.1")
    # The operator's leftover connection, while the other carries the internet:
    # not a WAN (no WAN node on the map, no gateway down).
    brd = by_name(d)["BRD"]
    assert (brd.wan, brd.up) == (False, False)


def test_every_internet_connection_down_is_down(zte, cfg):
    for r in zte.rows("ethWanStatus", "wan_internetstatus_lua", "ID_WAN_COMFIG"):
        r.update(ConnStatus="Connecting", ConnStatus6="Disconnected")
    d = device(cfg)
    assert {g.name: g.status for g in d.gateways} == {"BRD": "down", "omci_ipv4_pppoe_1": "down"}
    assert by_name(d)["BRD"].wan is True


def test_an_ont_in_bridge_mode_is_not_the_router(zte, cfg):
    for r in zte.rows("ethWanStatus", "wan_internetstatus_lua", "ID_WAN_COMFIG"):
        r["mode"] = "bridge"
    d = device(cfg)
    assert d.role == "unknown" and not d.gateways


def test_arp_fdb_and_leases(zte, cfg):
    d = device(cfg)
    assert {(a.ip, a.mac) for a in d.arp} == {
        ("192.168.100.4", "64:49:7d:00:00:04"),
        ("192.168.100.3", "bc:24:11:00:00:03"),
        ("192.168.100.2", "02:00:00:00:00:02"),
    }
    # Only LAN ports: the upstream "Bridge_Default" entry is not a port.
    assert {(f.mac, f.port) for f in d.fdb} == {
        ("1c:86:0b:00:00:05", "LAN4"),
        ("bc:24:11:00:00:03", "LAN4"),
    }
    (lease,) = d.dhcp_leases
    assert (lease.ip, lease.mac, lease.hostname) == (
        "192.168.100.3",
        "bc:24:11:00:00:03",
        "OPNsense",
    )
    left = (lease.expires_at - datetime.now(timezone.utc)).total_seconds()
    assert 78300 < left <= 78376


def test_dhcpv6_leases_by_duid(zte, cfg):
    zte.rows("lanMgrIpv6", "dhcp6s_hostinfo_lua", "OBJ_DHCP6C_ID").extend(
        [
            {
                "Duid": "00:01:00:01:2a:3b:4c:5d:bc:24:11:00:00:03",
                "IpAddr": "2001:db8:ef00::3",
                "ExpiredTime": "3600",
            },
            {"Duid": "00:04:12:34", "IpAddr": "2001:db8:ef00::9", "ExpiredTime": "3600"},
        ]
    )
    v6 = [x for x in device(cfg).dhcp_leases if ":" in x.ip]
    assert [(x.ip, x.mac) for x in v6] == [("2001:db8:ef00::3", "bc:24:11:00:00:03")]


def test_duid_mac():
    assert duid_mac("000300016449 7d000004") == "64:49:7d:00:00:04"
    assert duid_mac("0001000100000000bc2411000003") == "bc:24:11:00:00:03"
    assert duid_mac("0002000004d2") is None


def test_wifi(zte, cfg):
    d = device(cfg)
    assert [(n.ssid, n.security, n.enabled) for n in d.wifi_networks] == [
        ("ZTE_2.4G_Home", "wpa2", True),
        ("ZTE_5G_Home", "wpa2", True),
    ]
    radios = {r.name: r for r in d.radios}
    # Both radios off, on automatic channel.
    assert (radios["2.4GHz"].band, radios["2.4GHz"].width_mhz) == ("2.4ghz", 40)
    assert (radios["5GHz"].auto, radios["5GHz"].enabled, radios["5GHz"].channel) == (
        True,
        False,
        None,
    )
    ifs = by_name(d)
    assert ifs["SSID1"].description == "ZTE_2.4G_Home" and ifs["SSID1"].up is False
    assert "SSID2" not in ifs  # untouched slots are not networks


def test_a_radio_on_reports_the_channel_in_use(zte, cfg):
    zte.row("wlanBasic", "wlan_wlanbasicadconf_lua", "OBJ_WLANSETTING_ID", "DEV.WIFI.RD1")[
        "RadioStatus"
    ] = "1"
    for r in zte.rows("localNetStatus", "wlan_wlanstatus_lua", "OBJ_WLANCONFIGDRV_ID"):
        if r["WLANViewName"] == "DEV.WIFI.RD1":
            r["ChannelInUsed"] = "11"
    d = device(cfg)
    radio = next(r for r in d.radios if r.name == "2.4GHz")
    assert (radio.enabled, radio.channel, radio.auto) == (True, 11, True)
    assert by_name(d)["SSID1"].up is True


def test_wireless_clients(zte, cfg):
    zte.rows("localNetStatus", "wlan_client_stat_lua", "OBJ_WLAN_AD_ID").append(
        {
            "MACAddress": "AA:BB:CC:00:00:01",
            "AliasName": "SSID5",
            "ESSID": "ZTE_5G_Home",
            "RSSI": "-61",
            "TxRate": "866",
            "RxRate": "780",
            "BAND": "5G",
        }
    )
    (w,) = device(cfg).wireless_clients
    assert (w.mac, w.interface, w.ssid, w.band) == (
        "aa:bb:cc:00:00:01",
        "SSID5",
        "ZTE_5G_Home",
        "5ghz",
    )
    assert (w.signal_dbm, w.tx_rate_mbps, w.rx_rate_mbps) == (-61, 866, 780)


def test_port_forwards_upnp_and_dmz(zte, cfg):
    zte.rows("portForwarding", "firewall_portforwarding_lua", "OBJ_FWPM_ID").append(
        {
            "_InstID": "DEV.NAT.PtMapping1",
            "InternalPortEndRange": "8080",
            "Protocol": "BOTH",
            "ExternalPort": "8080",
            "Enable": "1",
            "Description": "camera",
            "InternalPort": "80",
            "InternalClient": "192.168.100.3",
            "ExternalPortEndRange": "8081",
            "AllInterface": "1",
            "Alias": "cam",
        }
    )
    zte.rows("upnpportmapss", "upnp_portmap_lua", "OBJ_UPNPPORTMAP_ID").append(
        {
            "_InstID": "x",
            "Protocol": "UDP",
            "ExternalPort": "3478",
            "InternalPort": "3478",
            "InternalClient": "192.168.100.3",
            "ServerIPAddress": "",
        }
    )
    dmz = zte.rows("dmz", "firewall_dmz_lua", "OBJ_FWDMZ_ID")[0]
    dmz.update(Enable="1", InternalClient="192.168.100.3")
    fwd, upnp, dmz_fwd = device(cfg).port_forwards
    assert (fwd.protocol, fwd.external_port, fwd.external_port_end, fwd.internal_port) == (
        "tcp/udp",
        8080,
        8081,
        80,
    )
    assert (fwd.description, fwd.enabled, fwd.interface) == ("camera", True, None)
    assert (upnp.protocol, upnp.external_port, upnp.upnp, upnp.source) == ("udp", 3478, True, None)
    assert (dmz_fwd.external_port, dmz_fwd.external_port_end, dmz_fwd.internal_ip) == (
        1,
        65535,
        "192.168.100.3",
    )


def test_paused_devices_only_when_the_filter_blocks(zte, cfg):
    rules = zte.rows("filterCriteria", "firewall_macfilterv3_lua", "OBJ_MACFILTER_ID")
    rules += [
        {
            "_InstID": "a",
            "Type": "Route",
            "Protocol": "ALL",
            "Name": "Omini pause Kid tablet",
            "SrcMacAddr": "bc:24:11:00:00:03",
            "DstMacAddr": "00:00:00:00:00:00",
        },
        {
            "_InstID": "b",
            "Type": "Bridge+Route",
            "Protocol": "ALL",
            "Name": "neighbour",
            "SrcMacAddr": "02:00:00:00:00:02",
            "DstMacAddr": "00:00:00:00:00:00",
        },
        {
            "_InstID": "c",
            "Type": "Bridge",
            "Protocol": "ALL",
            "Name": "lan only",
            "SrcMacAddr": "64:49:7d:00:00:04",
            "DstMacAddr": "00:00:00:00:00:00",
        },
    ]
    assert device(cfg).paused == []  # the filter is off
    zte.rows("filterCriteria", "firewall_filterglobal_lua", "OBJ_FWBASE_ID")[0][
        "MacFilterEnable"
    ] = "1"
    kid, neighbour = device(cfg).paused
    assert (kid.mac, kid.name, kid.rule, kid.ips) == (
        "bc:24:11:00:00:03",
        "Kid tablet",
        None,
        ["192.168.100.3"],
    )
    assert (neighbour.mac, neighbour.rule) == ("02:00:00:00:00:02", "neighbour")


def test_services(zte, cfg):
    s = {x.name: x for x in device(cfg).services}
    assert s["UPnP IGD"].enabled is True
    assert s["SNTP"].enabled is True and "a.ntp.br" in s["SNTP"].description
    assert s["Dynamic DNS"].enabled is False


def test_signs_in_once_and_out_after_the_run(zte, cfg):
    device(cfg)
    assert (zte.logins, zte.logouts, zte.session) == (1, 1, None)


def test_signs_in_again_when_someone_else_signed_in(zte, cfg, monkeypatch):
    original = zte.read
    calls = {"n": 0}

    def read(name):
        calls["n"] += 1
        if calls["n"] == 5:
            zte.kick()  # a browser signs in mid-run
        return original(name)

    monkeypatch.setattr(zte, "read", read)
    d = device(cfg)
    assert zte.logins == 2 and d.interfaces


def test_wrong_password_waits_before_trying_again(zte, cfg):
    cfg["password"] = "wrong"
    with pytest.raises(PluginError, match="wrong username or password"):
        collect(cfg)
    with pytest.raises(PluginError, match="waiting a few minutes"):
        collect(cfg)
    assert zte.logins == 0


def test_a_locked_login(zte, cfg):
    zte.locked = 60
    with pytest.raises(PluginError, match=r"locked its login.*60 s"):
        collect(cfg)


def test_optional_reads_do_not_fail_the_collection(zte, cfg):
    del zte.tables[("arpTable", "arp_arptable_lua")]
    del zte.raw[("mmTopology", "topo_lua")]
    d = device(cfg)
    assert d.arp is None
    # Without the topology, the lowest of the LAN-side MACs.
    assert d.key == BASE


def test_connection_test(zte, cfg):
    assert connection_test(cfg) == "Connected to ZTE F670L (V9.0.11P1N49)"
    del zte.tables[("macTable", "macinfo_mactable_lua")]
    assert connection_test(cfg).endswith("could not read the MAC table")


def test_the_whole_protocol_validates(zte, tmp_path):
    config = {"url": HOST, "username": "admin", "password": "secret"}
    response = run(main.plugin, config, state=tmp_path)
    assert "devices" in response, response
    assert response["devices"][0]["key"] == BASE
