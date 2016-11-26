/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
    unsigned int orig_len, struct sr_if *src_iface)
{
  /* Allocate space for packet */
  unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
  if (NULL == reply_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
  sr_arp_hdr_t *orig_arphdr = 
      (sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arphdr = 
      (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
  reply_ethhdr->ether_type = orig_ethhdr->ether_type;

  /* Populate ARP header */
  memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
  reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
  reply_arphdr->ar_pro = orig_arphdr->ar_pro;
  reply_arphdr->ar_hln = orig_arphdr->ar_hln;
  reply_arphdr->ar_pln = orig_arphdr->ar_pln;
  reply_arphdr->ar_op = htons(arp_op_reply); 
  memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
  reply_arphdr->ar_tip = orig_arphdr->ar_sip;
  memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
  reply_arphdr->ar_sip = src_iface->ip;

  /* Send ARP reply */
  printf("Send ARP reply\n");
  print_hdrs(reply_pkt, reply_len);
  sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
  free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr, 
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  /* Allocate space for ARP request packet */
  unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
  if (NULL == reqst_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
  sr_arp_hdr_t *reqst_arphdr = 
      (sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  reqst_ethhdr->ether_type = htons(ethertype_arp);

  /* Populate ARP header */
  reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
  reqst_arphdr->ar_pro = htons(ethertype_ip);
  reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
  reqst_arphdr->ar_pln = sizeof(uint32_t);
  reqst_arphdr->ar_op = htons(arp_op_request); 
  memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  reqst_arphdr->ar_sip = out_iface->ip;
  memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  reqst_arphdr->ar_tip = req->ip;

  /* Send ARP request */
  printf("Send ARP request\n");
  print_hdrs(reqst_pkt, reqst_len);
  sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
  free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr, 
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or  
 * or generate an ARP request packet 
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
      /*********************************************************************/
      /* TODO: send ICMP host uncreachable to the source address of all    */
      /* packets waiting on this request                                   */
      
/****** Begin Task 4-pt3  ******/
      size_t eth_hdr_size = sizeof(sr_ethernet_hdr_t);
      size_t ip_hdr_size = sizeof(sr_ip_hdr_t);
      size_t icmp_hdr_size = sizeof(sr_icmp_t3_hdr_t);

      size_t total_hdr_size = eth_hdr_size + ip_hdr_size + icmp_hdr_size;

      /*  Iterate through list of packets */
      struct sr_packet *packet;
      for (packet = req->packets; packet != NULL; packet = packet->next) 
      {
          
          /*  Grab packet buffer from this packet in the queue */
          uint8_t *buf = packet->buf;

          /*  Create the packet buffer to hold ICMP Host Unreachable message */
          uint8_t *pkt = (uint8_t *) malloc(total_hdr_size);

          /* Identify ethernet and ip headers of packet from the queue */
          sr_ethernet_hdr_t *old_eth_hdr = (sr_ethernet_hdr_t  *) buf;
          sr_ip_hdr_t *old_ip_hdr = (sr_ip_hdr_t *)(buf + eth_hdr_size);

          /*  Popoulate ethernet header */
          sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) pkt;
          eth_hdr->ether_type = htons(ethertype_ip);
          memcpy(eth_hdr->ether_shost, old_eth_hdr->ether_dhost, ETHER_ADDR_LEN);
          memcpy(eth_hdr->ether_dhost, old_eth_hdr->ether_shost, ETHER_ADDR_LEN);

          /*  Populate ip header */
          sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + eth_hdr_size);
          ip_hdr->ip_v = 4;
          ip_hdr->ip_hl = 5;
          ip_hdr->tos = 0;
          ip_hdr->ip_len =0;
          ip_hdr->ip_id = 0;
          ip_hdr->ip_off = htons(IP_DF);          //0x4000
          ip_hdr->ip_ttl = 255;               //INIT_TTL
          ip_hdr->ip_p = ip_protocol_icmp;        //1
          ip_hdr->ip_sum = 0;               //compute after filling in ICMP header
          ip_hdr->ip_src = old_ip_hdr->ip_dst;
          ip_hdr->ip_dst = old_ip_hdr->ip_src;

          /*  Populate ICMP header */
          sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(pkt + eth_hdr_size + ip_hdr_size);
          icmp_hdr->icmp_type = 3;
          icmp_hdr->icmp_code = 1;
          //icmp_hdr->unused =;
          //icmp_hdr->next_mtu =;
          // IP header plus first 64 bits (8 bytes) of original packet's data  
          memcpy(icmp_hdr->data, buf + eth_hdr_size, ip_hdr->ip_hdr*4 + 8);
          icmp_hdr->icmp_sum = cksum(pkt + eth_hdr_size + ip_hdr_size, icmp_hdr_size);
          // no IP options -> 20 byte IP header
          ip_hdr->ip_len = htons((ip_hl * 4) + icmp_hdr_size);
          id_hdr->ip_sum = cksum(pkt + eth_hdr_size, ip_hdr_size);

          /* Send ICMP packet */
          printf("Send ICMP Host Unreachable\n");
          print_hdrs(pkt, total_hdr_size);
          sr_send_packet(sr, pkt, total_hdr_size, packet->iface)
          free(pkt);
      }
/****** End Task 4-pt3  ******/
        
      /*********************************************************************/

      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    { 
      /* Send ARP request packet */
      sr_send_arprequest(sr, req, out_iface);
       
      /* Update ARP request entry to indicate ARP request packet was sent */ 
      req->sent = now;
      req->times_sent++;
    }
  }
} /* -- sr_handle_arpreq -- */

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip, 
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, 
            pkt, len, out_iface->name);
    sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, struct sr_if *src_iface)
{
  /* Drop packet if it is less than the size of Ethernet and ARP headers */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Packet is too short => drop packet\n");
    return;
  }

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  switch (ntohs(arphdr->ar_op))
  {
  case arp_op_request:
  {
    /* Check if request is for one of my interfaces */
    if (arphdr->ar_tip == src_iface->ip)
    { sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { break; }

    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);

    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
        
      /*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */
     
/****** Begin Task 4-pt2  ******/
      size_t eth_hdr_size = sizeof(sr_ethernet_hdr_t);

      //arphdr->ar_sha;
      for (packet = req->packets; packet != NULL; packet = packet->next) 
      {
        /*  Grab packet buffer from this packet in the queue */
          uint8_t *buf = packet->buf;

          /* Identify ethernet header of packet from the queue */
          sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t  *) buf;

          /*  Update destination MAC address to that from the ARP reply
           *  message */
          memcpy(eth_hdr->ether_dhost, arphdr->sha, ETHER_ADDR_LEN);
          
          /*  Update source MAC address to that of this device */
          struct sr_if *sender_if = sr_get_interface(sr, interface);
          memcpy(eth_hdr->ether_shost, sender_if, ETHER_ADDR_LEN);

          /* Update IP header checksum and ttl */
          sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + eth_hdr_size);
          ip_hdr->ip_sum=0;
          ip_hdr->ip_ttl -= 1;
          ip_hdr->sum = cksum(pkt + eth_hdr_size, ip_hdr_size);

           /* Send packet */
          printf("Send packet\n");
          print_hdrs(pkt, total_hdr_size);
          sr_send_packet(sr, buf, packet->len, src_iface);
          
      }
/****** End Task 4-pt2  ******/
      /*********************************************************************/
        
      /* Release ARP request entry */
      sr_arpreq_destroy(&(sr->cache), req);
    }
    break;
  }    
  default:
    printf("Unknown ARP opcode => drop packet\n");
    return;
  }
} /* -- sr_handlepacket_arp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /*************************************************************************/
  /* TODO: Handle packets                                                  */


  /****** Begin Task 2 - Patrick ******/
  /* 
     Part 1
     Decrement Time to Live (TTL) and update checksum
  */
  size_t eth_hdr_size = sizeof(sr_ethernet_hdr_t);
  size_t ip_hdr_size = sizeof(sr_ip_hdr_t);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + eth_hdr_size);
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_ttl -= 1;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_size);
  /************************************* 
    Task 2
    Part 2
  **************************************
    Find the longest prefix match (LPM) in the routing table. 
    Fortunately, all the masks provided in the routing table are 255.255.255.255.
    The "next hop" address is the gateway address of the LMP row on the routing table.
    If the gateways were anything but 255.255.255.255, we'd have to check specific bits to find LPM.
    We might still have to do that. For now, I'm checking if the addresses are completely equal.
    - Pat
  */
  struct sr_rt *rt_row = sr->routing_table; // Routing table first row (linked list first node)
  uint32_t ip_dst = ip_hdr->ip_dst;         // Destination addr of our IP packet
  struct sr_rt *rt_bestrow = NULL;          // Tentative best match
  // Loop through each row and find the longest prefix match.
  while(rt_row != NULL) {
    uint32_t rt_row_dest = (uint32_t)(rt_row->dest);
    uint32_t rt_row_mask = (uint32_t)(rt_row->mask);
    if ((ip_dst & rt_row_mask) == rt_row_dest) {
      // Found a prefix match. Is it the longest?
      if (rt_row_mask > (rt_bestrow == NULL ? 0 : rt_bestrow->mask)) {
        rt_bestrow = rt_row;
      }
    }
    rt_row = rt_row->next;
  }
  // Validate our results and find the destination MAC address in the arp cache
  struct sr_arpentry *lookup;
  bool fail = rt_bestrow == NULL;
  if (!fail)
    lookup = sr_arpcache_lookup(&sr_instance->cache, (uint32_t)rt_bestrow->dest);
  fail |= lookup == NULL;
  if (fail) {
    /* 
      Task 12 - send an ICMP Host Unreachable message because we never found it
    */
    // Create a packet buffer
    size_t icmp_hdr_size = sizeof(sr_icmp_t3_hdr_t);
    size_t total_hdr_size = eth_hdr_size + ip_hdr_size + icmp_hdr_size;
    uint8_t *newpkt = (uint8_t *)malloc(total_hdr_size);
    // Copy the ethernet header to the new buffer
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)pkt;
    eth_hdr->ether_type = htons(ethertype_ip);
    memcpy(eth_hdr->ether_shost, ((sr_ethernet_hdr_t *)packet)->ether_dhost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, ((sr_ethernet_hdr_t *)packet)->ether_shost, ETHER_ADDR_LEN);
    // Populate new IP header
    sr_ip_hdr_t *newip_hdr = (sr_ip_hdr_t *)(pkt + eth_hdr_size);
    newip_hdr->ip_v = 4;
    newip_hdr->ip_hl = 5;
    newip_hdr->tos = 0;
    newip_hdr->ip_len =0;
    newip_hdr->ip_id = 0;
    newip_hdr->ip_off = htons(IP_DF);     // Don't fragment me
    newip_hdr->ip_ttl = 255;              // INIT_TTL
    newip_hdr->ip_p = ip_protocol_icmp;   // 1
    newip_hdr->ip_sum = 0;                // Compute after filling in ICMP header
    newip_hdr->ip_src = ip_hdr->ip_dst;
    newip_hdr->ip_dst = ip_hdr->ip_src;
    // Populate ICMP header
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(pkt + eth_hdr_size + ip_hdr_size);
    icmp_hdr->icmp_type = 3;
    icmp_hdr->icmp_code = 1;
    // IP header plus first 64 bits (8 bytes) of original packet's data 
    memcpy(&icmp_hdr->data, packet + eth_hdr_size, ip_hdr_size + 8);
    icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_hdr_size);
    // No IP options means 20 byte IP header
    newip_hdr->ip_len = htons((newip_hdr->ip_hl * 4) + icmp_hdr_size);
    newip_hdr->ip_sum = cksum(newip_hdr, ip_hdr_size);
    // Done! Send
    printf("Send ICMP Host Unreachable\n");
    print_hdrs(pkt, total_hdr_size);
    sr_send_packet(sr, pkt, total_hdr_size, packet->iface);
    free(packet);
  }
  else {
    // Success
    sr_fwd_packet(sr, packet, len, rt_bestrow->interface, lookup->mac);
    free(lookup);
  }
  /******  End Task 2 - Patrick   ******/


  /*************************************************************************/

}/* end sr_ForwardPacket */

/****** Begin Task 4-pt1  ******/
/*---------------------------------------------------------------------
 * Method: sr_fwd_packet(struct sr_instance* sr,
          uint8_t * packet,
          unsigned int len,
          char* interface,
          unsigned char mac[6])
 *
 * Scope:  Global
 *
 * This method is called in sr_handlepacket() each time the router receives 
 * an ip packet on the interface.  The packet buffer, the packet length the 
 * receiving interface, and the MAC address determined in Task 3 are passed 
 * in as parameters. The packet is sent to the MAC address passed in.
 *
 * Note: The call should look like:
 * sr_fwd_packet(sr, packet, len, sr_rt(node)->interface, sr_arpentry->mac)
 * Where:
 *      * the sr_rt node is the node in the routing table whose destination
 *        ip address matches the destination ip address of the packet. 
 *      * sr_arpentry is returned by sr_arpcache_lookup in Task 3.
 *
 *---------------------------------------------------------------------*/

  void sr_fwd_packet(struct sr_instance* sr,
          uint8_t * packet,
          unsigned int len,
          char* interface,
          unsigned char mac[6])
  {
          /* Identify ethernet header of packet from the queue */
          sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t  *) packet;

          /*  Update destination MAC address to that passed in
           *  (Retrieved in Task 3) */
          memcpy(eth_hdr->ether_dhost, mac, ETHER_ADDR_LEN);

          /* Update IP header checksum and ttl */
          sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + eth_hdr_size);
          ip_hdr->ip_sum=0;
          ip_hdr->ip_ttl -= 1;
          ip_hdr->sum = = cksum(pkt + eth_hdr_size, ip_hdr_size);

           /* Send packet */
          printf("Send packet using MAC address in the cache.\n");
          //print_hdrs(pkt, total_hdr_size);
          sr_send_packet(sr, packet, len, src_iface);

  } /* End sr_sendpacket */
/****** End Task 4-pt1  ******/
