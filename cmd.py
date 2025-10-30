Here is a comprehensive list of the commands we discussed, complete with their purpose and example outputs.

-----

### 1\. `ping -c 5 google.com`

  * **Use:** Checks connectivity to a host. Sends 5 (`-c 5`) packets and then stops, showing a summary.
  * **Example Output:**
    ```
    PING google.com (142.250.196.14) 56(84) bytes of data.
    64 bytes from lhr4a-in-f14.1e100.net (142.250.196.14): icmp_seq=1 ttl=116 time=4.58 ms
    64 bytes from lhr4a-in-f14.1e100.net (142.250.196.14): icmp_seq=2 ttl=116 time=4.51 ms
    64 bytes from lhr4a-in-f14.1e100.net (142.250.196.14): icmp_seq=3 ttl=116 time=4.55 ms
    64 bytes from lhr4a-in-f14.1e100.net (142.250.196.14): icmp_seq=4 ttl=116 time=4.62 ms
    64 bytes from lhr4a-in-f14.1e100.net (142.250.196.14): icmp_seq=5 ttl=116 time=4.53 ms

    --- google.com ping statistics ---
    5 packets transmitted, 5 received, 0% packet loss, time 4006ms
    rtt min/avg/max/mdev = 4.510/4.558/4.621/0.039 ms
    ```

### 2\. `ip addr show`

  * **Use:** Shows IP addresses and details for all network interfaces. (Modern replacement for `ifconfig`).
  * **Example Output:**
    ```
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
    2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
        link/ether 0c:54:15:6f:b8:66 brd ff:ff:ff:ff:ff:ff
        inet 192.168.1.101/24 brd 192.168.1.255 scope global dynamic eth0
           valid_lft 86056sec preferred_lft 86056sec
    ```

### 3\. `ip route show`

  * **Use:** Shows the IP routing table (how your system sends packets).
  * **Example Output:**
    ```
    default via 192.168.1.1 dev eth0 
    192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.101
    ```
      * **Interpretation:** The `default` line shows that all traffic (to the internet) is sent to the router at `192.168.1.1`.

### 4\. `ifconfig`

  * **Use:** The **older** command to show interface details and IP addresses.
  * **Example Output:**
    ```
    eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
            inet 192.168.1.101  netmask 255.255.255.0  broadcast 192.168.1.255
            ether 0c:54:15:6f:b8:66  txqueuelen 1000  (Ethernet)
            RX packets 12345  bytes 11223344
            TX packets 6789  bytes 998877

    lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
            inet 127.0.0.1  netmask 255.0.0.0
            loop  txqueuelen 1000  (Local Loopback)
    ```

### 5\. `route -n`

  * **Use:** The **older** command to show the routing table. The `-n` shows numeric IP addresses (it's faster).
  * **Example Output:**
    ```
    Kernel IP routing table
    Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
    0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 eth0
    192.168.1.0     0.0.0.0         255.255.255.0   U     100    0        0 eth0
    ```
      * **Interpretation:** The `0.0.0.0` destination (default) uses gateway `192.168.1.1`.

### 6\. `nslookup google.com`

  * **Use:** Queries DNS to find the IP address for a name.
  * **Example Output:**
    ```
    Server:		127.0.0.53
    Address:	127.0.0.53#53

    Non-authoritative answer:
    Name:	google.com
    Address: 142.250.196.14
    Name:	google.com
    Address: 2404:6800:4009:80c::200e
    ```

### 7\. `dig google.com`

  * **Use:** A more detailed DNS lookup tool.
  * **Example Output (shortened):**
    ```
    ; <<>> DiG 9.16.1-Ubuntu <<>> google.com
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53120
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

    ;; QUESTION SECTION:
    ;google.com.			IN	A

    ;; ANSWER SECTION:
    google.com.		181	IN	A	142.250.196.14

    ;; Query time: 4 ms
    ;; SERVER: 127.0.0.53#53(127.0.0.53)
    ;; WHEN: Fri Oct 31 03:10:11 IST 2025
    ;; MSG SIZE  rcvd: 55
    ```

### 8\. `host google.com`

  * **Use:** A simple, quick tool for DNS lookups.
  * **Example Output:**
    ```
    google.com has address 142.250.196.14
    google.com has IPv6 address 2404:6800:4009:80c::200e
    google.com mail is handled by 10 smtp.google.com.
    ```

### 9\. `ss -tulpn`

  * **Use:** Shows all **T**CP and **U**DP ports that are **L**istening, with **N**umeric IPs/ports, and the **P**rocess using them.
  * **Example Output:**
    ```
    Proto Recv-Q Send-Q Local Address:Port    Peer Address:Port  State    PID/Program name
    tcp   0      0      0.0.0.0:22        0.0.0.0:* LISTEN   1089/sshd
    tcp   0      0      127.0.0.1:631     0.0.0.0:* LISTEN   1045/cupsd
    udp   0      0      127.0.0.53:53     0.0.0.0:* 672/systemd-resolv
    ```

### 10\. `netstat -tulpn`

  * **Use:** The **older** command to show listening ports (same flags as `ss` above).
  * **Example Output:**
    ```
    Active Internet connections (only servers)
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
    tcp        0      0 0.0.0.0:22              0.0.0.0:* LISTEN      1089/sshd
    tcp        0      0 127.0.0.1:631           0.0.0.0:* LISTEN      1045/cupsd
    udp        0      0 127.0.0.53:53           0.0.0.0:* 672/systemd-resolv
    ```

### 11\. `arp -a`

  * **Use:** Shows the ARP cache, which maps local IP addresses to hardware (MAC) addresses.
  * **Example Output:**
    ```
    ? (192.168.1.1) at 00:3a:9d:f4:c8:22 [ether] on eth0
    ? (192.168.1.105) at 9c:b6:d0:f8:33:a1 [ether] on eth0
    ```

### 12\. `hostname`

  * **Use:** Shows your computer's network name.
  * **Example Output:**
    ```
    my-linux-desktop
    ```

### 13\. `traceroute google.com`

  * **Use:** Traces the path (the sequence of routers or "hops") packets take to a destination.
  * **Example Output (shortened):**
    ```
    traceroute to google.com (142.250.196.14), 30 hops max, 60 byte packets
     1  my-router (192.168.1.1)  0.350 ms  0.285 ms  0.270 ms
     2  isp-gateway (10.0.0.1)  1.204 ms  1.385 ms  1.564 ms
     3  * * *
     4  142.251.226.110 (142.251.226.110)  4.305 ms  4.115 ms  4.001 ms
     5  142.250.196.14 (142.250.196.14)  4.512 ms  4.701 ms  4.685 ms
    ```

### 14\. `curl -I http://google.com`

  * **Use:** Fetches just the HTTP **Headers** from a web server. Good for checking if a site is up.
  * **Example Output:**
    ```
    HTTP/1.1 301 Moved Permanently
    Location: https://www.google.com/
    Content-Type: text/html; charset=UTF-8
    Date: Fri, 31 Oct 2025 03:12:00 GMT
    Server: gws
    Content-Length: 220
    X-XSS-Protection: 0
    ```

### 15\. `wget http://example.com/file.iso`

  * **Use:** Downloads a file from the web.
  * **Example Output (during download):**
    ```
    --2025-10-31 03:13:00--  http://example.com/file.iso
    Resolving example.com (example.com)... 93.184.216.34
    Connecting to example.com (example.com)|93.184.216.34|:80... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 123456789 (118M) [application/octet-stream]
    Saving to: ‘file.iso’

    file.iso           15%[==>                 ]  18.00M  12.5MB/s    eta 8s
    ```

### 16\. `tcpdump -i eth0 -c 5`

  * **Use:** A packet sniffer. Captures 5 packets (`-c 5`) on the `eth0` interface. (Requires `sudo`).
  * **Example Output:**
    ```
    tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
    listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes
    03:14:01.123456 IP my-desktop.ssh > 192.168.1.50.34567: Flags [P.], seq 1:52, ack 1, win 502, length 52
    03:14:01.123500 IP 192.168.1.50.34567 > my-desktop.ssh: Flags [.], ack 53, win 237, length 0
    03:14:01.456789 IP 1.1.1.1.domain > my-desktop.54321: 52185 NXDomain 0/1/0 (110)
    03:14:02.789012 ARP, Request who-has 192.168.1.1 tell 192.168.1.101, length 28
    03:14:02.789100 ARP, Reply 192.168.1.1 is-at 00:3a:9d:f4:c8:22, length 28
    5 packets captured
    ```

### 17\. `nmap 192.168.1.1`

  * **Use:** A network scanner. Scans a host to find open ports and services. (Requires `sudo` for best results).
  * **Example Output:**
    ```
    Starting Nmap 7.80 ( https://nmap.org ) at 2025-10-31 03:15 IST
    Nmap scan report for 192.168.1.1
    Host is up (0.00032s latency).
    Not shown: 997 closed ports
    PORT   STATE SERVICE
    53/tcp OPEN  domain
    80/tcp OPEN  http
    443/tcp OPEN https
    Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds
    ```

### 18\. `whois google.com`

  * **Use:** Looks up the public registration details for a domain name.
  * **Example Output (snippet):**
    ```
    Domain Name: google.com
    Registry Domain ID: 2138514_DOMAIN_COM-VRSN
    Registrar WHOIS Server: whois.markmonitor.com
    Registrar URL: http://www.markmonitor.com
    Updated Date: 2024-09-09T09:39:04Z
    Creation Date: 1997-09-15T04:00:00Z
    Registrar: MarkMonitor, Inc.
    Registrant Organization: Google LLC
    Registrant State/Province: CA
    Registrant Country: US
    Name Server: ns1.google.com
    Name Server: ns2.google.com
    ```

### 19\. `ethtool eth0`

  * **Use:** Shows low-level driver and hardware settings for your Ethernet interface.
  * **Example Output (snippet):**
    ```
    Settings for eth0:
            Supported ports: [ TP ]
            Supported link modes:   10baseT/Half 10baseT/Full 
                                    100baseT/Half 100baseT/Full 
                                    1000baseT/Full 
            Advertised link modes:  10baseT/Half 10baseT/Full 
                                    100baseT/Half 100baseT/Full 
                                    1000baseT/Full 
            Speed: 1000Mb/s
            Duplex: Full
            Port: Twisted Pair
            Link detected: yes
    ```

-----

### Wi-Fi Specific Commands

### 20\. `iwconfig`

  * **Use:** The **older** command for showing Wi-Fi connection details.
  * **Example Output:**
    ```
    wlan0     IEEE 802.11  ESSID:"MyHomeWiFi"  
              Mode:Managed  Frequency:5.24 GHz  Access Point: 00:1A:2B:3C:4D:5E   
              Bit Rate=526.5 Mb/s   Tx-Power=22 dBm   
              Retry short limit:7   RTS thr:off   Fragment thr:off
              Link Quality=70/70  Signal level=-40 dBm  
              Rx invalid nwid:0  Rx invalid crypt:0  Rx invalid frag:0
              Tx excessive retries:0  Invalid misc:7   Missed beacon:0
    ```

### 21\. `iwlist wlan0 scan`

  * **Use:** Scans for all available Wi-Fi networks in your area. (Requires `sudo`).
  * **Example Output (snippet for one network):**
    ```
    Cell 01 - Address: 00:1A:2B:3C:4D:5E
                Channel:48
                Frequency:5.24 GHz (Channel 48)
                Quality=70/70  Signal level=-40 dBm  
                Encryption key:on
                ESSID:"MyHomeWiFi"
                Bit Rates:54 Mb/s
                Mode:Master
                IE: WPA2 Version 1
                ...
    ```

### 22\. `nmcli dev wifi list`

  * **Use:** A modern, easy way to list visible Wi-Fi networks (if using NetworkManager).
  * **Example Output:**
    ```
    IN-USE  SSID              MODE   CHAN  RATE        SIGNAL  BARS  SECURITY 
    * MyHomeWiFi        Infra  48    526 Mbit/s  90      ▂▄▆█  WPA2 
            AnotherNetwork    Infra  6     130 Mbit/s  60      ▂▄▆_  WPA2 
            Neighbors_Wifi    Infra  11    195 Mbit/s  35      ▂▄__  WPA2
    ```
