import pytest
from omini_sdk import Change, PluginError

import main
from omini_zte.changes import apply
from tests.conftest import BASE, HOST, run


def change(kind, **value):
    return Change(device=BASE, kind=kind, value=value)


def reservations(zte):
    return zte.rows("lanMgrIpv4", "Localnet_LanMgrIpv4_DHCPStaticRule_lua", "OBJ_DHCPBIND_ID")


def hosts(zte):
    return zte.rows("dns", "dns_hostname_lua", "ALLDNSHOST")


def rules(zte):
    return zte.rows("filterCriteria", "firewall_macfilterv3_lua", "OBJ_MACFILTER_ID")


def mac_filter(zte):
    return zte.rows("filterCriteria", "firewall_filterglobal_lua", "OBJ_FWBASE_ID")[0]


def ssids(zte):
    return {
        r["_InstID"]: r for r in zte.rows("wlanBasic", "wlan_wlansssidconf_lua", "OBJ_WLANAP_ID")
    }


def radio(zte, inst="DEV.WIFI.RD1"):
    return zte.row("wlanBasic", "wlan_wlanbasicadconf_lua", "OBJ_WLANSETTING_ID", inst)


# --- reservations -------------------------------------------------------------------------


def test_reserves_an_address(zte, cfg):
    (d,) = apply(
        cfg, change("reservation.set", mac="AA:BB:CC:00:00:01", ip="192.168.100.50", name="Printer")
    )
    assert [(r["MACAddr"], r["IPAddr"], r["Name"]) for r in reservations(zte)] == [
        ("aa:bb:cc:00:00:01", "192.168.100.50", "Printer")
    ]
    assert [(r.mac, r.ip, r.name) for r in d.dhcp_reservations] == [
        ("aa:bb:cc:00:00:01", "192.168.100.50", "Printer")
    ]
    assert zte.logouts == 1


def test_a_reservation_name_is_cut_to_what_the_ont_keeps(zte, cfg):
    # Longer names are accepted and then dropped by the device.
    apply(
        cfg,
        change(
            "reservation.set",
            mac="aa:bb:cc:00:00:01",
            ip="192.168.100.50",
            name="Kid tablet upstairs",
        ),
    )
    assert reservations(zte)[0]["Name"] == "Kid tablet"
    apply(cfg, change("reservation.set", mac="aa:bb:cc:00:00:02", ip="192.168.100.51"))
    assert reservations(zte)[1]["Name"] == "bbcc000002"


def test_changes_a_reservation_in_place(zte, cfg):
    apply(cfg, change("reservation.set", mac="aa:bb:cc:00:00:01", ip="192.168.100.50", name="a"))
    apply(cfg, change("reservation.set", mac="aa:bb:cc:00:00:01", ip="192.168.100.60", name="b"))
    assert [(r["IPAddr"], r["Name"]) for r in reservations(zte)] == [("192.168.100.60", "b")]


def test_refuses_an_address_reserved_for_another_device(zte, cfg):
    apply(cfg, change("reservation.set", mac="aa:bb:cc:00:00:01", ip="192.168.100.50"))
    with pytest.raises(PluginError, match="already reserved"):
        apply(cfg, change("reservation.set", mac="aa:bb:cc:00:00:02", ip="192.168.100.50"))


def test_deletes_a_reservation(zte, cfg):
    apply(cfg, change("reservation.set", mac="aa:bb:cc:00:00:01", ip="192.168.100.50"))
    (d,) = apply(cfg, change("reservation.delete", mac="aa:bb:cc:00:00:01"))
    assert reservations(zte) == [] and d.dhcp_reservations == []


def test_a_change_the_ont_ignores_is_undone_and_reported(zte, cfg):
    reservations(zte).append(
        {
            "_InstID": "DEV.V4DHCP.Server.Pool1.Bind1",
            "Name": "old",
            "IPAddr": "192.168.100.40",
            "MACAddr": "aa:bb:cc:00:00:01",
        }
    )
    zte.ignore.add("Localnet_LanMgrIpv4_DHCPStaticRule_lua")
    with pytest.raises(PluginError, match=r"could not reserve 192.168.100.50.*\(undone\)"):
        apply(cfg, change("reservation.set", mac="aa:bb:cc:00:00:01", ip="192.168.100.50"))


# --- DNS names ---------------------------------------------------------------------------------


def test_sets_and_deletes_a_dns_name(zte, cfg):
    (d,) = apply(cfg, change("dns.set", name="NAS.home.lan.", ip="192.168.100.10"))
    assert [(r["HostName"], r["IPAddress"]) for r in hosts(zte)] == [
        ("nas.home.lan", "192.168.100.10")
    ]
    assert [(r.name, r.ip) for r in d.dns_records] == [("nas.home.lan", "192.168.100.10")]
    apply(cfg, change("dns.set", name="nas.home.lan", ip="192.168.100.11"))
    assert [r["IPAddress"] for r in hosts(zte)] == ["192.168.100.11"]
    apply(cfg, change("dns.delete", name="nas.home.lan"))
    assert hosts(zte) == []


def test_a_dns_name_is_ipv4_only(zte, cfg):
    with pytest.raises(PluginError, match="IPv4"):
        apply(cfg, change("dns.set", name="nas.home.lan", ip="2001:db8::1"))


# --- pausing --------------------------------------------------------------------------------------


def test_pauses_and_resumes_a_device(zte, cfg):
    (d,) = apply(
        cfg, change("pause.set", mac="bc:24:11:00:00:03", ips=["192.168.100.3"], name="OPNsense")
    )
    assert [(r["SrcMacAddr"], r["Name"], r["Type"]) for r in rules(zte)] == [
        ("bc:24:11:00:00:03", "Omini pause OPNsense", "Route")
    ]
    assert (mac_filter(zte)["MacFilterEnable"], mac_filter(zte)["MacFilterTarget"]) == (
        "1",
        "Discard",
    )
    (p,) = d.paused
    assert (p.mac, p.name, p.rule, p.ips) == (
        "bc:24:11:00:00:03",
        "OPNsense",
        None,
        ["192.168.100.3"],
    )
    # Pausing again keeps the one rule the ONT allows per MAC.
    apply(cfg, change("pause.set", mac="bc:24:11:00:00:03", ips=[], name="OPNsense"))
    assert len(rules(zte)) == 1
    (d,) = apply(cfg, change("pause.delete", mac="bc:24:11:00:00:03"))
    assert rules(zte) == [] and d.paused == []
    # The filter stays on: with no rule it blocks nothing.
    assert mac_filter(zte)["MacFilterEnable"] == "1"


def test_does_not_pause_with_an_allow_list(zte, cfg):
    mac_filter(zte).update(MacFilterEnable="1", MacFilterTarget="Permit")
    with pytest.raises(PluginError, match="allow list"):
        apply(cfg, change("pause.set", mac="bc:24:11:00:00:03"))
    assert rules(zte) == []


def test_does_not_pause_itself(zte, cfg):
    with pytest.raises(PluginError, match="itself"):
        apply(cfg, change("pause.set", mac=BASE))


# --- Wi-Fi networks ---------------------------------------------------------------------


def test_creates_a_wifi_network_on_both_radios(zte, cfg):
    (d,) = apply(cfg, change("wifi.set", ssid="Guests", password="guest-pass-1", enabled=True))
    s = ssids(zte)
    # The first free slot of each radio.
    for inst in ("DEV.WIFI.AP2", "DEV.WIFI.AP6"):
        assert (s[inst]["ESSID"], s[inst]["Enable"], s[inst]["BeaconType"]) == (
            "Guests",
            "1",
            "11i",
        )
        assert zte.psk[inst] == "guest-pass-1"
    assert s["DEV.WIFI.AP3"]["ESSID"] == "SSID3"
    assert ("Guests", "wpa2", True) in [(n.ssid, n.security, n.enabled) for n in d.wifi_networks]
    # The password went encrypted, never in clear.
    for _, form in zte.posts:
        assert "guest-pass-1" not in str({k: v for k, v in form.items() if k != "KeyPassphrase"})


def test_renames_turns_off_and_changes_the_password(zte, cfg):
    apply(
        cfg,
        change(
            "wifi.set",
            ssid="Home",
            previous="ZTE_2.4G_Home",
            enabled=False,
            password="new-password",
        ),
    )
    s = ssids(zte)
    assert (s["DEV.WIFI.AP1"]["ESSID"], s["DEV.WIFI.AP1"]["Enable"]) == ("Home", "0")
    assert zte.psk["DEV.WIFI.AP1"] == "new-password"
    # The other band's network has another name: untouched.
    assert (
        s["DEV.WIFI.AP5"]["ESSID"] == "ZTE_5G_Home" and zte.psk["DEV.WIFI.AP5"] == "home-password"
    )


def test_a_new_wifi_network_needs_a_password(zte, cfg):
    with pytest.raises(PluginError, match="needs a password"):
        apply(cfg, change("wifi.set", ssid="Guests"))
    with pytest.raises(PluginError, match="8 to 63"):
        apply(cfg, change("wifi.set", ssid="Guests", password="short"))


def test_wifi_networks_have_no_vlan(zte, cfg):
    with pytest.raises(PluginError, match="VLAN"):
        apply(cfg, change("wifi.set", ssid="IoT", password="iot-pass-123", vlan=30))


def test_deletes_a_wifi_network(zte, cfg):
    apply(cfg, change("wifi.set", ssid="Guests", password="guest-pass-1"))
    (d,) = apply(cfg, change("wifi.delete", ssid="Guests"))
    s = ssids(zte)
    assert (s["DEV.WIFI.AP2"]["ESSID"], s["DEV.WIFI.AP2"]["Enable"]) == ("SSID2", "0")
    assert "Guests" not in [n.ssid for n in d.wifi_networks]


def test_a_password_the_ont_did_not_take_is_undone(zte, cfg, monkeypatch):
    original = zte.post_wlan_wlansssidconf_lua

    def keep_password(form):
        form.pop("KeyPassphrase", None)
        form.pop("_InstID_PSK", None)
        return original(form)

    monkeypatch.setattr(zte, "post_wlan_wlansssidconf_lua", keep_password)
    with pytest.raises(PluginError, match=r"kept its previous password.*undone"):
        apply(cfg, change("wifi.set", ssid="ZTE_5G_Home", password="other-password"))


# --- channels ----------------------------------------------------------------------------


def test_moves_a_radio_to_a_channel(zte, cfg):
    radio(zte)["RadioStatus"] = "1"
    (d,) = apply(cfg, change("wifi.channel", radio="2.4GHz", channel=6))
    assert (radio(zte)["Channel"], radio(zte)["AutoChannelEnabled"]) == ("6", "0")
    r = next(x for x in d.radios if x.name == "2.4GHz")
    assert (r.channel, r.auto, r.width_mhz) == (6, False, 40)


def test_does_not_move_a_radio_that_is_off(zte, cfg):
    with pytest.raises(PluginError, match="off"):
        apply(cfg, change("wifi.channel", radio="2.4GHz", channel=6))


def test_refuses_a_channel_the_country_does_not_allow(zte, cfg):
    radio(zte, "DEV.WIFI.RD2")["RadioStatus"] = "1"
    with pytest.raises(PluginError, match="not allowed"):
        apply(cfg, change("wifi.channel", radio="5GHz", channel=14))


def test_an_unknown_radio(zte, cfg):
    with pytest.raises(PluginError, match="no radio"):
        apply(cfg, change("wifi.channel", radio="6GHz", channel=5))


def test_apply_through_the_protocol(zte, tmp_path):
    config = {"url": HOST, "username": "admin", "password": "secret"}
    response = run(
        main.plugin,
        config,
        "apply",
        {"device": BASE, "kind": "dns.set", "value": {"name": "nas.lan", "ip": "192.168.100.10"}},
        state=tmp_path,
    )
    assert response["devices"][0]["dns_records"] == [{"name": "nas.lan", "ip": "192.168.100.10"}]
