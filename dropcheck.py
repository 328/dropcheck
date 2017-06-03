# coding=utf-8

# usage: ./dropcheck.py vlan-id


import os
import socket
import sys
import dns.resolver

def ping4(address):
    return not os.system("ping -D -c 4 -s 1472 %s" % (address))


def ping6(address):
    return not os.system("sudo ping6 -c 4 -m -D -s 1232 -I en8 %s" % (address))


def traceroute4(address):
    return not os.system("traceroute -n %s" % (address))


def traceroute6(address):
    return not os.system("traceroute6 -n -I -w 1 %s" % (address))


def get_ipv4addr():
    try:
        addr = [(s.connect(('8.8.8.8', 80)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
        return addr
    except:
        return None


def get_ipv6addr():
    try:
        addr = [(s.connect(('2001:2408:2408::8888', 80)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)]][0][1]
        return addr
    except:
        return None


def check_a_record(addr):
    try:
        answer = dns.resolver.query(addr, "A")
        print("A record %s" % (answer[0]))
        return True
    except dns.resolver.NoAnswer:
        print("No A record")
        return False
    except dns.resolver.NXDOMAIN:
        print("No such domain")
        return False


def check_aaaa_record(addr):
    try:
        answer = dns.resolver.query(addr, "AAAA")
        print("AAAA record: %s" % (answer[0]))
        return True
    except dns.resolver.NoAnswer:
        print("No AAAA record")
        return False
    except dns.resolver.NXDOMAIN:
        print("No such domain")
        return False


def v4gw(vlan_id):
    ipv4 = get_ipv4addr()
    ipv4 = ipv4.split(".")
    ipv4[2] = int(vlan_id) - 2000
    if ipv4[2] <= 0 or ipv4[2] > 255:
        return None
    ipv4[3] = 1
    ipv4 = map(str, ipv4)
    ipv4 = ".".join(ipv4)
    print("Gateway Addr (v4): %s" % (ipv4))


def v6gw(vlan_id):
    addr = "fe80::" + str(vlan_id) + ":1"
    print("Gateway Addr (v6): %s" % (addr))
    return "fe80::" + str(vlan_id) + ":1"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: %s vlan_id" % sys.argv[0])
        sys.exit()

    vlan_id = sys.argv[1]

    v4result = {}
    v6result = {}

    ipv4 = get_ipv4addr()
    ipv6 = get_ipv6addr()

    v4result.update({"ping4-gateway":ping4(v4gw(vlan_id))})
    v4result.update({"ping4-external":ping4("8.8.8.8")})
    v4result.update({"dnsv4":check_a_record("www.wide.ad.jp")})
    v4result.update({"traceroute4":traceroute4("8.8.8.8")})

    os.system("osascript openbrowser.script")

    v6result.update({"ping6-external":ping6("2001:4860:4860::8888")})
    v6result.update({"ping6-gateway":ping6(v6gw(vlan_id))})
    v6result.update({"dnsv6":check_aaaa_record("www.wide.ad.jp")})
    v6result.update({"traceroute6":traceroute6("2001:4860:4860::8888")})

    print("IPv4 Address:\t%s" % (ipv4))
    print("IPv6 Address:\t%s" % (ipv6))

    print(v4result)
    print(v6result)
