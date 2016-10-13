### TCP Traffic:
Generates an TCP SYN packet from client to a random external host.

Check two packets:

1. TCP SYN packet sent from NAT external interface to the external host.
2. TCP SYN-ACK packet sent from NAT internal interface to the client.

### TCP Endpoint Independent Filtering:
Client sends a TCP SYN packet to one of the external host(exho1).
Get a new mapping (internal port#, internal IP) <=> (external port#, external IP) (Let’s call the external pair Pext).
After that, another external host(exho2) sends a TCP SYN packet using Pext as destination (port#, IP) pair.

Check that TCP packet is sent out via NAT internal interface with correct destination port#.

### TCP Simultaneous Open:
The NAT must support the following sequence of TCP packet exchanges.

```sequence
Alice->Bob: SYN
Bob->Alice: SYN
Alice->Bob: SYN/ACK
Bob->Alice: SYN/ACK
```

### TCP Unsolicited Syn:
- Send unsolicited SYN from one of the external hosts to the NAT external interface.
  It should generate an ICMP port unreachable after 6s ONLY if the destination port to which the packet is sent to is >= 1024.
- TCP Unsolicited Syn to restricted external port#(22).
  It should generate an ICMP port unreachable message too.
- Send unsolicited SYN from internal host to the NAT internal interface.
  It should generate an ICMP port unreachable message too.