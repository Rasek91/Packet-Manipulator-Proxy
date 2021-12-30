# Packet-Manipulator-Proxy

A proxy to manipulate egress packets, uses iptables *REDIRECT*.

## Usage

1. Add a redirect rule to your iptables chains:

```
iptables -t nat -I OUTPUT -p tcp -m owner --uid-owner test -j REDIRECT --to-ports 7777
iptables -t nat -I OUTPUT -p udp -m owner --uid-owner test -j REDIRECT --to-ports 7777
ip6tables -t nat -I OUTPUT -p tcp -m owner --uid-owner test -j REDIRECT --to-ports 7777
ip6tables -t nat -I OUTPUT -p udp -m owner --uid-owner test -j REDIRECT --to-ports 7777
```

2. Run the the code:

```
go run .
```

3. Run program which match with the rule:

```
sudo -u test curl -4 -k --http1.1 https://172.217.19.110
```

## Current features: **v0.2.0**

- Print the received message with Debug loglevel to the screen
- IPv4 and IPv6 support
- TCP and UDP support
- TLS interception with self-signed certification for localhost IP addresses
- DTLS interception with self-signed certification for localhost IP addresses
