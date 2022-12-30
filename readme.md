## Description
udphp is UDP protocol hole punching tool, main goal to establish direct connection between two sides behind GCNAT or inaccessible NAT servers. Main reason for it's creation was to connect 2 home networks via Wireguard VPN, as our ISP providers use CGNAT and no way you can open ports (you don't have true IP address at all).

If you launch udphp-client simulateonsely on two your computers, they build direct connection between them, for such task they use udphp-server (you can use our **garsoftware.com:7867**, but it have limited resources and not guaranteed to work at all, or you can launch your own one), udphp-server is signaling server for connection establishing only, after connection creation it's not used anymore. udphp-client find counterpart by given unique uuid, it replaces dynamic dns creation and registration.

---
## udphp-client command arguments:

    udphp-client [uuid] [server_ip:server_port] [OPTIONS]
    
    OPTIONS:
    -i,   --ip [value]        ip binding
    -p,   --port [value]      port binding
    -n,   --attempts [value]  send attempts, 0 - unlimited (default: 10)
    -1,   --client1           send request as client#1 (default)
    -2,   --client2           send request as client#2
    -b,   --bombardment [n]   bombardment mode

some clarification:

**uuid** is your unique uuid, it's must be same on 2 sides for connection establishment, just generate some for distint your connection pair, you can use https://www.uuidgenerator.net/

use **-1** for distinct request from first client, and **-2** for second one.

each connection attempt takes 4-6 seconds, and multiplying attemps (-n) to 4-6 you have approximate maximum connection time.

**bombardment** is experimental mode for breaking througth some specific [Endpoint-Dependent Mapping](https://www.ietf.org/rfc/rfc5128.txt) NAT servers, udphp-client not just connect to specific port, but to range of ports [port - bombardment, port + bombardment]

---
## udphp-server command arguments:

    udphp-server [OPTIONS]

    OPTIONS:
    -i, --ip [value]        listen ip
    -p, --port [value]      listen port
    -d, --daemon            daemon mode

---
## Example #1
Just prepare binding and connection address + port.

On computer#1 launch:

    udphp-client 95a14e53-57a4-4bd8-be04-ac310ba6e0ee garsoftware.com:7867 -1

On computer#2 launch:

    udphp-client 95a14e53-57a4-4bd8-be04-ac310ba6e0ee garsoftware.com:7867 -2

**95a14e53-57a4-4bd8-be04-ac310ba6e0ee** is your unique uuid. **garsoftware.com:7867** address of signaling udphp-server

You see results like this on each computer (with different IP/ports):

    ...
    BIND: 0.0.0.0:36372
    CLIENT: 176.53.44.33:60994

**BIND** is port and IP you need to bind your application and **CLIENT** is IP and port you need to connect to, udphp-client already prepared "hole" via your NAT and ISP's NAT.

***Your have around 2 minutes (depends on your ISP) to use this ports and IP's, unused "holes" closed by you ISP NAT server shortly***

---
## Example #2
Establish connection on already opened port (ex. Wireguard)

On computer#1 launch:

    udphp-client 95a14e53-57a4-4bd8-be04-ac310ba6e0ee garsoftware.com:7867 -1 -p 51820

On computer#2 launch:

    udphp-client 95a14e53-57a4-4bd8-be04-ac310ba6e0ee garsoftware.com:7867 -2 -p 31820

**95a14e53-57a4-4bd8-be04-ac310ba6e0ee** is your unique uuid. **garsoftware.com:7867** address of signaling udphp-server. **-p 51820** is port you want to bind to (can be different on each side), in most cases this port already used by some application (it's not a problem, udphp-client can simulateonesly use port with other application).

You see results like this on each computer (with different IP/ports):

    ...
    BIND: 0.0.0.0:51820
    CLIENT: 176.53.44.33:60994

**BIND** is not important, because it shows same port from command line, **CLIENT** is IP and port you need to connect to, udphp-client already prepared "hole" via your NAT and ISP's NAT.

***udphp-client need to have root rights to do such port binding because it supposes what your port alrady used by other application and it's need to use raw sockets. You also can give [application permission](https://stackoverflow.com/questions/46466543/linux-raw-socket-permissions-issue) without root, but it's more complicated.***

***Your have around 2 minutes (depends on your ISP) to use this ports and IP's, unused "holes" closed by you ISP NAT server shortly***

---
## Example #3
Real example for Wireguard, you need to have already set up Wiregueard (one server without endpoint set, and other client with endpoint to server, any ip,port, you don't know them yet)

On server Wireguard add to crontab this shell script (/root/wgcheck.sh):

    #!/bin/sh

    IFACE=vpn
    UUID=95a14e53-57a4-4bd8-be04-ac310ba6e0ee
    UDPHP_ADDR=garsoftware.com:7867
    WG_PORT=51820
    
    LAST_HANDSHAKE=`wg show ${IFACE} latest-handshakes | awk '{print $2}'`

    [ -z ${LAST_HANDSHAKE} ] && return 0;
    IDLE_SECONDS=$((`date +%s`-${LAST_HANDSHAKE}))
    [ ${IDLE_SECONDS} -lt 150 ] && return 0;
    logger -t "wg_check" "${IFACE} reconnecting..."

    OUT=$(udphp-client ${UUID} ${UDPHP_ADDR} -p ${WG_PORT} -1 -n 9
    if [ $? -ne 0 ]; then
    logger -t "wg_check" "${IFACE} reconnecting failed"
    exit 1
    fi

    CONNECT_ADDR=$(echo "$OUT" | grep '^CLIENT:' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+')
    logger -t "wg_check" "${IFACE} reconnecting succeded, client: ${CONNECT_ADDR}"


Set **IFACE** to your Wireguard interface name, **UUID** to your unique uuid, **WG_PORT** you Wireguard used port

On client Wireguard add to crontab this shell script (/root/wgcheck.sh):

    #!/bin/sh

    IFACE=vpn
    UUID=95a14e53-57a4-4bd8-be04-ac310ba6e0ee
    UDPHP_ADDR=garsoftware.com:7867
    WG_PORT=51820
    CLIENT_PUBKEY=K7X5715/55cJb2rJhlB78CWvoz890SByyyJ+eaOfhWY=

    LAST_HANDSHAKE=`wg show ${IFACE} latest-handshakes | awk '{print $2}'`

    [ -z ${LAST_HANDSHAKE} ] && return 0;
    IDLE_SECONDS=$((`date +%s`-${LAST_HANDSHAKE}))
    [ ${IDLE_SECONDS} -lt 150 ] && return 0;
    logger -t "wg_check" "${IFACE} reconnecting..."

    out=$(udphp-client ${UUID} ${UDPHP_ADDR} -p ${WG_PORT} -2 -n 9)
    if [ $? -ne 0 ]; then
    logger -t "wg_check" "${IFACE} reconnecting failed"
    exit 1
    fi

    CONNECT_ADDR=$(echo "$out" | grep '^CLIENT:' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+')
    wg set ${IFACE} peer ${CLIENT_PUBKEY} endpoint ${CONNECT_ADDR}
    logger -t "wg_check" "${IFACE} reconnecting succeded, client: ${CONNECT_ADDR}"

Set **IFACE** to your Wireguard interface name, **UUID** to your unique uuid, **WG_PORT** you Wireguard used port, **CLIENT_PUBKEY** your server Wireguard public key

Set one each side such crontab

    */1 * * * * /root/wgcheck.sh
