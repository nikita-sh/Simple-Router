# CSC458 Assignment 1: Simple Router
## Authors: Nick Perrin and Nikita Shumeiko
----

## Code Structure

The overall structure of the code is fairly simple. When the router receives packets, `sr_handle_packet` is called. This function checks the ethernet packet for minimum length and then checks the ethertype. Here the structure diverges into two branches:

### If the packet is an ARP packet:

The function `handle_arp` is called. This method verifies the packet and then checks if it is a request or reply. If the packet is a request, it prepares an ARP reply packet framed in an Ethernet packet addressed to the broadcast address. If it is an ARP reply, the function walks through the list of packets waiting on this reply, sets their destination MAC address to be the source MAC address of the reply packet, and sends them.

### If the packet is an IP packet:

The function `handle_ip` is called. This function first verifies the IP packets checksum and length and then checks if the packet is addressed to the router. If it is, it checks the type of the IP packet. If it is an ICMP packet, it ensures that the type is 8, and sends an echo reply. If the type is not 8, or the ICMP checksum is not verified, the packet is dropped. If the packet is a TCP/UDP packet, the packet is dropped and an ICMP error is sent (type 3, code 3). If the packet is not destined to the router, the function `forward_ip` is called. 

`forward_ip` decrements the TTL of the packet and ensures it is still greater than 0, sending an ICMP error if it is not (type 11, code 0). It then finds a longest prefix match for the destination IP in the routing table, sending an ICMP error if one is not found (type 3, code 0). Once a match is found, the function goes through the ARP cache to see if there is a match against the destination IP address. If there is one, the packet to be forwarded has its source and destination MAC addresses updated and it is sent. If no ARP cache request exists, it is queued and the method `handle_arpreq` is called.

### ARP Cache

The function `sr_arpcache_sweepreqs` is called every second. It sweeps all requests and sees if the request should have another request packet sent out, or if it should be destroyed and an ICMP error sent. It calls the function `handle_arpreq`. This function first checks if more than a second has passed since the last ARP request was sent, and sends another if it has. If any request has been sent more than 5 times, it is discarded and an ICMP error is sent to all packets waiting on it (type 3, code 1). 

## Design Decisions

We tried to use encapsulation to make our code more modular as oppposed to stuffing everything into `handle_packet`. This allowed us to test easier, as whenever something went wrong, we had a better idea of where exactly it did go wrong.

In terms of ambiguities, we were initially quite confused with how the ARP cache worked, and how it was to be implemented. After some time, we came to understand it was a simple linked list that we would traverse to access the necessary information to handle ARP requests and replies. The structure for many of the headers was also confusing at first, this was resolved by diligent reading of the Network Sorcery pages for the relevant protocols.