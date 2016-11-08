# Mininet Router
A simple IP router for CS4390 (Computer Networks) using mininet. For setup, use https://github.com/mininet/mininet/wiki/Simple-Router

##Tasks


| Item                                                                                	| Points 	|
|-------------------------------------------------------------------------------------	|--------	|
| 1. Followed submission instructions                                                 	| 1      	|
| 2. Handle ARP request - Task 3                                                      	| 2      	|
| 3. Drop IP packet with wrong checksum - Task 1                                      	| 2      	|
| 4. Forwarded UDP packet reaches server1 - Task 3 & 4                                	| 2      	|
| 5. Forwarded UDP packet has decreased TTL - Task 2                                  	| 2      	|
| 6. Forwarded UDP packet has re-calculated checksum - Task 2                         	| 2      	|
| 7. Ping packet is forwarded to the server - Task 3 & 4                              	| 2      	|
| 8. Ping 192.168.2.2 from client succeeds - Task 1                                   	| 2      	|
| 9. Ping 172.64.3.10 from server1 succeeds - Task 1                                  	| 2      	|
| 10. wget 192.168.2.2 from client succeeds - Task 3 & 4                              	| 2      	|
| 11. Time exceeded message is generated when TTL=1 - Task 1                          	| 2      	|
| 12. Network unreachable message is generated when no routing entry matches - Task 2 	| 2      	|
| 13. Host unreachable message is generated when ARP resolution fails - Task 4        	| 2      	|
| 14. Packets are forwarded when they match a subnet routing entry - Task 3 & 4       	| 2      	|
| 15. Packets are forwarded to the gateway - Task 3 & 4                               	| 1      	|
| 16. Route lookups perform a longest prefix match - Task 2                           	| 1      	|
| 17. Traceroute succeeds - Task 1                                                    	| 1      	|
| Total                                                                               	| 30     	|

###Task 1 (9 Points): 
In sr_handlepacket function's 'TODO: Handle packets': Sanity Check and Router IP Match
(Sanity Check) First validate the IP packets length meets the minimum for an IP packet and that the packet has the correct checksum, drop if too short or incorrect checksum (Item 3). If packet is sane but TTL is 1 then send an ICMP time exceeded (type 11, code 0) message back to the host (Item 11).

(Router IP Match) If the packet is destined for an IP address that belongs to this router AND its type is: A) an ICMP Echo Request then send an ICMP Echo Reply back to the source (Item 8 & 9) | B) a TCP or UDP payload then send an ICMP port unreachable (type 3, code 3) back to the sending host.

###Task 2 (7 Points): 
In sr_handlepacket function's 'TODO: Handle packets': Modify TTL + Recalculate Checksum and Routing IP Lookup 
Note: The code for task two appears after the code for task 1, and can assume that the IP address does not belong to an interface of the router.

(Modify TTL + Recalculate Checksum) Examine packet header, decrement TTL by 1 and recompute the checksum over the modified header (decremented TTL is change to header) and change the packets checksum to this new one (Item 5 & 6).

(Routing Lookup) Examine the packets header then search for the next-HOP address's interface in the routing table (Populated in the (struct sr_instance* sr) parameter; accessed with sr->mask for the longest prefix matching comparison, and whose interface is found with sr->interface[1]; once the proper interface is found for the IP mask that matched the packets next-HOP IP (using longest prefix matching) use that in the ARP calls (Item 16). Respond with an ICMP network unreachable if no routing table match is found (Item 12). 

###Task 3 (6.5 Points): 
In sr_handlepacket function's 'TODO: Handle packets': ARP Cache Check and Prepare to Send on Hit, and ARP Queue for MAC lookup on Miss

(ARP Cache Check and Prepare to Send) Examine the packet type: A) if it is an ARP packet then call sr_handlepacket_arp using the interface found in the previous step (Routing Lookup) (Item 2) | B) if it is not an ARP packet then call sr_arpcache_lookup using the cache (which you must initialize and manage the cache) to make sure that the destination has not been looked up already, this returns an sr_arpentry struct that allows access to the MAC address of the IP (free the struct when done), or null if the ip was not in the cache. If the IP was in the cache and a MAC address was returned then leave the packet to be sent to the MAC by task 4 (Quarter of Items 4,7,14,15).

(ARP Queue for MAC) If the IP does not exist in the cache then request the MAC address using sr_waitforarp and the interface found in the previous step (Routing Lookup), this adds the packet to the queue and will be sent automatically when the MAC returns from the ARP request(Quarter of Items 4,7,14,15).

###Task 4 (6.5 Points): 
In sr_handlepacket function's 'TODO: Handle packets': Send Packet | In sr_handlepacket_arp function's 'TODO': Send Queued Packets | In sr_handle_arpreq function's 'TODO': Send ICMP Host Unreachable

(Send Packet) Send the packet whose MAC address was in the cache in Task 3 to that MAC
(Quarter of Items 4,7,14,15).

(Send Queued Packets) Iterate through the linked list whose head is stored in req->packets and send them all to the MAC address that was in the received ARP packet that is stored in arphdr->ar_sha (sha = Sender Hardware Address) (Quarter of Items 4,7,14,15).

(Send ICMP Host Unreachable) For each packet associated with the request that timed out, reply to its sender with ICMP host unreachable (type 3, code 1) (Item 13).
