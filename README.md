# OpenWrt-802.11krv



roaming-config.json:

```
{
  "ssid": "WIFI-NAME",
  "mobility_domain": "beef",
  "ssh_user": "root",
  "dry_run": true,
  "ap_hosts": [
    "ap-1",
    "ap-2",
    "ap-3"
  ]
}
```

## Allgemein
### OpenWrt Wifi Optionen
https://openwrt.org/docs/guide-user/network/wifi/basic

https://openwrt.org/docs/guide-user/network/wifi/roaming

### Speichern und WLAN neu starten
```
uci commit wireless
wifi reload
```
### checken mit:
```
uci show wireless
```

### wireshark am Accesspoint:
```
sudo cp /usr/bin/dumpcap ~/tmp/my-dumpcap
sudo chmod a+x ~/tmp/my-dumpcap
# wichtig !!! <( command ) macht eine unnamed pipe auf, das wird dann durch den fd ersetzt . z.b.   wireshark -S -k -i /dev/fd/63'
# d.h. -i 'KEINSPACE<( ...
unshare --user --map-root-user --mount --propagation private bash -c '
  mount --bind ~/tmp/my-dumpcap /usr/bin/dumpcap
  HOME=/home/chris \
  XDG_CACHE_HOME=/home/chris/.cache \
  XDG_CONFIG_HOME=/home/chris/.config \
  XDG_DATA_HOME=/home/chris/.local/share \
  wireshark -S -k -i '<( ssh "$REMOTE_HOST" "su='' ; if [ \"\$USER\" != \"root\" ]; then echo 'tcpdump needs sudo' >&2 ; su='sudo' ; fi ; \$su tcpdump --immediate-mode -w - $*" )
```

### Allgemeine OpenWrt Optionen
Clients früher aus dem Wlan raushauen (nicht im script eingebaut)
```
wireless.default_radio0.rssi_reject_assoc_rssi='-75'
```

## 802.11k Neighbour Reports
hints mit andern Accesspoints in dem Wlan

das script installiert das Paket static-neighbor-reports

Alternative: usteer auf allen accesspoints installieren und das usteer die neghborhood reports machen lassen

### 802.11k aktivieren (macht das script)
```
uci set wireless.default_radio0.ieee80211k='1'
uci set wireless.default_radio0.rrm_neighbor_report='1'
uci set wireless.default_radio0.rrm_beacon_report='1'
```
mit dem da können die neigborhood reports manuell generiert werden:
https://github.com/openwrt/packages/tree/openwrt-22.03/net/static-neighbor-reports

mit usteer automatisch

### checken

#### am AP:
```
uci show static-neighbor-report
ubus call hostapd.phy1-ap0 rrm_nr_list
```

#### am PC:
```
wpa_cli -p /run/wpactrl -i wlan1 neighbor_rep_request
```
vorher muss eventuell der wpa_supplicant neu gestartet werden:
```
/usr/sbin/wpa_supplicant -dd -c /etc/wpa_supplicant/wpa_supplicant.conf -u -t -O /run/wpactrl
```
eventuell könnte auch gehen systemctl start wpa_supplicant@wlan1

## 802.11r Fast Transition
geräte die im wlan schon eingeloggt sind schneller authentifizieren

### aktivieren (macht das script)

### config keys:
```
nasid = r0kh_id, r1kh_id MAC adresse ohne : nehmen

r0kh	ff:ff:ff:ff:ff:ff,*,$key                    << steht nicht in der docu, das bedeutet alle accesspoints im Netzwerk
#       ^^^^^^^^^^^^^^^^^ die BSSID des AP[x]
#                         ^ die nasid (=R0KH_ID) des AP[x] ohne :
#                           ^^^ der key für die kommunikation
r1kh	00:00:00:00:00:00,00:00:00:00:00:00,$key    << detto
#       ^^^^^^^^^^^^^^^^^ die BSSID des AP[x]
#                         ^^^^^^^^^^^^^^^^^ R1KH_ID des AP[x] MIT : 
#                                           ^^^ der key für die kommunikation
```

### checken

#### am Handy
WiFiAnalyzer zeigts an

#### am Accesspoint
hostapd-utils installieren
```
hostapd_cli log_level DEBUG

hostapd_cli -i phy1-ap0 all_sta
ubus list | grep hostapd
ubus call 'hostapd.phy1-ap0' rrm_nr_get_own
```

#### am PC:
```
wpa_cli -p /run/wpactrl -i wlan1 get_network 0 key_mgmt
WPA-PSK FT-PSK WPA-PSK-SHA256 SAE FT-SAE
```
mit wireshark
tcpdump -i any -e -X -n ether proto 0x890d

#### am AP:
für das radio wo ma DEBUG loglevel ham will:
```
uci set wireless.radio0.log_level='1'
uci set wireless.radio1.log_level='1'
uci commit wireless
wifi reload
```
im log sieht man dan
```
Sat Jan 24 19:57:59 2026 daemon.debug hostapd: phy1-ap0: STA 11:22:33:44:55:66 WPA: FT authentication already completed - do not start 4-way handshake
```
wenn FT nicht geht:
```
Sat Jan 24 19:01:57 2026 daemon.notice hostapd: phy1-ap0: EAPOL-4WAY-HS-COMPLETED 11:22:33:44:55:66
```



## 802.11v Clients Empfehlungen geben zu einem anderen Accesspoint zu wechseln
benötigt den full-hostapd, basic reicht nicht!
hostap unterstützung aktivieren, das alleine tut noch nix
uci set wireless.default_radio0.bss_transition='1'

* dawn
* usteer

```
hostapd_cli -i phy1-ap0 bss_tm_req <client-mac> neighbor=<target-ap>
```
