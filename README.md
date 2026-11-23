# omini-plugin-zte

[Omini](https://github.com/riccardoalv/omini) plugin for **ZTE fiber ONTs** (GPON), through the ONT's own web interface — the boxes operators install, tested on a **ZTE F670L** with firmware **V9.0.11**. Other ZTE ONTs with the same interface (F670, F680, F6600 and similar, firmware V9) may work. It reads the ONT for the map and can set **fixed addresses**, **local DNS names**, the **Wi-Fi networks** and a **radio's channel**, **pause a device's internet** and make **configuration backups**.

> **Experimental.** Every read and change below was run against a real F670L (V9.0.11P1N49), and the tests replay its anonymized answers. Wi-Fi clients could not be checked (the radios of the test unit were off): their fields come from the web interface's code.

## What it reads

Every page is the web interface's own (`/?_type=menuView&_tag=<page>`), and its data the URL that page reads (`/?_type=menuData&_tag=<data>.lua`).

| Data | Page → data | Used for |
|---|---|---|
| Model, serial, firmware, CPU (per core), memory, uptime | `statusMgr` → `devmgr_statusmgr_lua` (**required**) | The device on the map, health |
| **PON optics**: receive and transmit power (dBm), module temperature, voltage, bias current; loss of signal and registration state (O5). The ONT reports no alarm threshold, so the low receive limit is GPON's class B+ sensitivity, −27 dBm (ITU-T G.984.2): Omini's weak-signal alert fires below it, not at a normal −20 dBm | `ponopticalinfo` → `optical_info_lua` | The `PON` port, with its transceiver; down without light or registration |
| WAN connections: PPPoE/IP, mode (route or bridge), IPv4 and IPv6 addresses, gateway, VLAN, MAC, connected or not | `ethWanStatus` → `wan_internetstatus_lua` | WAN interfaces on the PON port, gateways |
| LAN ports: link, speed, duplex, byte and error counters | `localNetStatus` → `status_lan_info_lua` | Ports `LAN1`…`LAN4` |
| Connected devices (port, IPv6 address) | `localNetStatus` → `accessdev_landevs_lua` | MAC table, IPv6 neighbors |
| Wi-Fi status: BSSID, channel in use, traffic of each network | `localNetStatus` → `wlan_wlanstatus_lua` | Wi-Fi interfaces (`SSID1`…), radio channels |
| Wi-Fi clients: MAC, network, band, RSSI, rates | `localNetStatus` → `wlan_client_stat_lua` | Wi-Fi clients on the map |
| ARP table | `arpTable` → `arp_arptable_lua` | Which IP is which MAC |
| MAC table (per LAN port and Wi-Fi network) | `macTable` → `macinfo_mactable_lua` | Where each device hangs |
| DHCP leases, the LAN address, fixed addresses | `lanMgrIpv4` → `Localnet_LanMgrIpv4_DHCPHostInfo_lua`, `…DHCPBasicCfg_lua`, `…DHCPStaticRule_lua` | Leases, the `LAN` bridge, reservations |
| DHCPv6 leases (the MAC from a DUID-LLT or DUID-LL) | `lanMgrIpv6` → `dhcp6s_hostinfo_lua` | IPv6 leases |
| Radios: band, channel, automatic, width, on or off, allowed channels | `wlanBasic` → `wlan_wlanbasicadconf_lua` | Wi-Fi channels |
| Wi-Fi networks: name, on or off, security (passwords come encrypted and are never reported) | `wlanBasic` → `wlan_wlansssidconf_lua` | Wi-Fi networks |
| Local DNS names | `dns` → `dns_hostname_lua` | DNS names |
| MAC filter (mode and rules) | `filterCriteria` → `firewall_filterglobal_lua`, `firewall_macfilterv3_lua` | Paused devices |
| Port forwards, UPnP mappings, DMZ host | `portForwarding`, `upnpportmapss`, `dmz` | Exposed to the internet |
| UPnP, SNTP and dynamic DNS settings | `upnp`, `sntp`, `ddns` | Services in the device panel |
| The device's own MAC | `mmTopology` → `topo_lua` (JSON) | The device's key |

Everything but the device status is optional: when a page is missing (another model, or an account that cannot open it) the rest is still collected, and **Test connection** lists what could not be read.

The device's key is its LAN-side MAC (the mesh controller's in `topo_lua`, else the lowest of its Wi-Fi and WAN MACs). It is a **router** when a WAN connection routes (PPPoE with NAT); an ONT in bridge mode, with a router behind it doing PPPoE, is not. A WAN connection that is not connected while another internet connection is (a leftover of the operator's configuration) is not reported as a WAN nor a gateway: no WAN node on the map and no outage alert for it. With every internet connection down, they are all WANs and their gateways are down.

## What it changes

Each change is posted like the page's own **Apply** or **Delete** button: the page is loaded for its session token, the form is sent with the `Check` header (the SHA-256 of the body encrypted with the device's RSA key, as its JavaScript does), the data is read back until it shows the change (`apply_verify`), and the change is undone when it does not. The ONT saves a change as it applies it.

| Change | How |
|---|---|
| `reservation.set` `{mac, ip, name}` | A DHCP binding (`Localnet_LanMgrIpv4_DHCPStaticRule_lua`), changed in place when the MAC has one. **The name keeps 10 characters**: the firmware accepts longer ones and then drops the binding |
| `reservation.delete` `{mac}` | Deletes the MAC's bindings |
| `dns.set` `{name, ip}` / `dns.delete` `{name}` | A local DNS name (`dns_hostname_lua`, *Local network → DNS → Host name*), IPv4 only |
| `wifi.set` `{ssid, previous, password, enabled}` | The ONT has **fixed networks**, four per radio (`SSID1`–`SSID4` on 2.4 GHz, `SSID5`–`SSID7` on 5 GHz). The networks named `previous` (or `ssid`) are renamed, turned on or off and get the password; a new network takes the first free one of each radio (off and named `SSIDn`) with WPA2-PSK (AES) and needs a password. The password is sent AES-encrypted, with its key encrypted with the device's RSA key, and checked by reading it back. VLANs are refused |
| `wifi.delete` `{ssid}` | Turns the network off and gives it back its slot name (`SSID2`): free again |
| `wifi.channel` `{radio, channel}` | `radio` as reported (`2.4GHz`, `5GHz`): a fixed channel (automatic off), width untouched; refused for a radio that is off and for a channel the radio's country and width do not allow |
| `pause.set` `{mac, name}` | A **MAC filter** rule `Omini pause <name>` of type *Route* (the internet only, not the LAN), and the MAC filter turned on as a **block list** when it was off. Refused when the filter is an **allow list** (pausing one device would mean listing every other), and for the ONT's own MACs. The ONT takes one rule per MAC |
| `pause.delete` `{mac}` | Deletes the MAC's rules; the filter stays on (a block list without rules blocks nothing) |

A device blocked by a MAC filter rule made by hand is reported as paused with that rule's name; resuming it deletes the rule (the ONT's rules cannot be turned off).

Not supported, because the web interface has no such setting: turning ports off, VLANs and networks, Wake-on-LAN.

### Backups

`backup` returns the settings of the configuration pages (WAN, LAN and DHCP, reservations, DHCPv6, radios, Wi-Fi networks, band steering, Wi-Fi access lists, DNS, firewall, filters, local service control, port forwards, DMZ, ALG, UPnP, DDNS, SNTP, static routes, port binding, TR-069, accounts) as sorted JSON. Fields the device sends encrypted (passwords, keys, credentials: encrypted with the session, so they would change on every backup) and status values (times, connection states, uptimes) are left out, so two backups differ only when the configuration changed. The ONT's own configuration file is an encrypted binary and is not used.

## One session at a time

The ONT keeps a **single web session**: signing in signs out whoever was signed in, the web interface in your browser included. So the plugin signs in at the start of every run and **signs out at the end**: the session is held a few seconds per collection, and you can use the web interface between collections (a collection that runs while you are signed in signs you out; sign in again). When someone signs in during a collection, the plugin signs in again once and goes on.

After a refused password the plugin waits **10 minutes** before trying again (the ONT locks its login after a few failed attempts), and says so when the ONT reports a lock.

## Requirements

- **Omini 1.7 or later** (the SDK's HTTP client, optional reads and `apply_verify`).
- The ONT's web interface reachable from Omini (the plugin uses `http://` unless the address says `https://`).
- The **administrator account** (`admin`), usually printed on the ONT's label or given by the operator. The `user` account (not tested) usually sees fewer pages; the plugin then reads what it can.

## Form fields

| Field | Meaning |
|---|---|
| Address | The ONT's web interface, e.g. `http://192.168.1.1` (operators' ONTs often use `http://192.168.100.1`) |
| Username | `admin` |
| Password | The administrator password |
| Verify the TLS certificate (Advanced) | Only for an `https://` address |
| Timeout (Advanced) | Seconds to wait for each answer (15) |

## Known issues

- Wi-Fi client fields (RSSI, rates, band) are read as the web interface shows them, not yet seen on a unit with clients.
- The PON optics are reported as the `PON` port's transceiver; CATV (`RFTxPower`, `VideoRxPower`) is not reported.
- Only GPON F670L V9 firmware was tested. Other firmware may name pages differently: a missing page is skipped and listed by **Test connection**.

## Development

```bash
uv run pytest            # tests (a fake ONT replaying recorded answers)
uv run ruff check .      # lint
uv run ruff format .     # format
```

The tests never reach the network. The fixtures in `tests/fixtures/` are a real F670L's answers, anonymized (MACs, serial, public addresses, network names).

## License

MIT
