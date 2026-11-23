"""What the plugin reads: each data URL with the page it belongs to."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Read:
    view: str
    tag: str
    name: str  # for logs and the connection test


STATUS = Read("statusMgr", "devmgr_statusmgr_lua.lua", "the device status")
OPTICAL = Read("ponopticalinfo", "optical_info_lua.lua", "the PON optical module")
WAN = Read(
    "ethWanStatus", "wan_internetstatus_lua.lua&TypeUplink=2&pageType=1", "the WAN connections"
)
LAN_PORTS = Read("localNetStatus", "status_lan_info_lua.lua", "the LAN ports")
LAN_DEVICES = Read("localNetStatus", "accessdev_landevs_lua.lua", "the connected devices")
WLAN_STATUS = Read("localNetStatus", "wlan_wlanstatus_lua.lua", "the Wi-Fi status")
WLAN_CLIENTS = Read("localNetStatus", "wlan_client_stat_lua.lua", "the Wi-Fi clients")
ARP = Read("arpTable", "arp_arptable_lua.lua", "the ARP table")
MACS = Read("macTable", "macinfo_mactable_lua.lua", "the MAC table")
LEASES = Read("lanMgrIpv4", "Localnet_LanMgrIpv4_DHCPHostInfo_lua.lua", "the DHCP leases")
RESERVATIONS = Read(
    "lanMgrIpv4", "Localnet_LanMgrIpv4_DHCPStaticRule_lua.lua", "the DHCP reservations"
)
DHCP = Read("lanMgrIpv4", "Localnet_LanMgrIpv4_DHCPBasicCfg_lua.lua", "the LAN and DHCP server")
LEASES6 = Read("lanMgrIpv6", "dhcp6s_hostinfo_lua.lua", "the DHCPv6 leases")
RADIOS = Read("wlanBasic", "wlan_wlanbasicadconf_lua.lua", "the Wi-Fi radios")
SSIDS = Read("wlanBasic", "wlan_wlansssidconf_lua.lua", "the Wi-Fi networks")
DNS_HOSTS = Read("dns", "dns_hostname_lua.lua", "the local DNS names")
DNS = Read("dns", "dns_localdns_lua.lua", "the DNS servers")
MAC_FILTER = Read("filterCriteria", "firewall_filterglobal_lua.lua", "the MAC filter mode")
MAC_RULES = Read("filterCriteria", "firewall_macfilterv3_lua.lua", "the MAC filter rules")
FORWARDS = Read("portForwarding", "firewall_portforwarding_lua.lua", "the port forwards")
UPNP_MAPS = Read("upnpportmapss", "upnp_portmap_lua.lua", "the UPnP port mappings")
DMZ = Read("dmz", "firewall_dmz_lua.lua", "the DMZ host")
UPNP = Read("upnp", "upnp_upnp_lua.lua", "UPnP")
NTP = Read("sntp", "sntp_lua.lua", "the time (SNTP)")
DDNS = Read("ddns", "ddns_lua.lua", "dynamic DNS")
TOPOLOGY = Read("mmTopology", "topo_lua.lua", "the topology")
