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

int check_eth_packet(uint8_t *packet, unsigned int len);
void handle_arp(struct sr_instance *sr, uint8_t *pkt);
void handle_ip(struct sr_instance *sr, uint8_t *pkt, unsigned int len, char *interface);

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

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  struct sr_if *myInt = sr_get_interface_by_MAC(sr, eth_hdr->ether_dhost);

  if (myInt) {

    if (check_eth_packet(packet, len)) {

      if (ethertype(packet) == ethertype_arp) {

        printf("Received ARP packet.\n");
        handle_arp(sr, packet);

      } else if (ethertype(packet) == ethertype_ip) {

        printf("Received IP packet.\n");
        handle_ip(sr, packet, len, interface);

      } else {

        printf("Unknown packet received. Dropping.\n");
        return;

      }
    } else {

      printf("Packet invalid.\n");

    }
  } else {

    printf("Packet not addressed to router. Dropping.\n");

  }
}/* end sr_ForwardPacket */

int check_eth_packet(uint8_t *packet, unsigned int len) {
  if (len < 64) {
    return 0;
  }
  return 1;
}

int check_arp_packet(uint8_t *pkt) {
  return 1;
}

void handle_arp(struct sr_instance *sr, uint8_t *pkt) {
  ;
}

int check_ip_packet(uint8_t *pkt, unsigned int len) {
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return 0;
  }

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  uint16_t old_cksm = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  if (old_cksm != cksum(ip_hdr, len - sizeof(sr_ethernet_hdr_t))) {
    return 0;
  }
  ip_hdr->ip_sum = old_cksm;

  return 1;
}

void handle_ip(struct sr_instance *sr, uint8_t *pkt, unsigned int len, char *interface) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
  
  struct sr_if *my_int = sr_get_interface_by_IP(sr, ip_hdr->ip_dst);

  if (my_int) {
    if (ip_hdr->ip_p == 1) {

      /* ICMP */
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t)(ip_hdr + sizeof(sr_ip_hdr_t));
      if (icmp_hdr->icmp_type != 0) {
        /* Unsupported type, drop */
        return ;
      }
      send_icmp_echo_reply(sr, pkt, interface, len);

    } else if (ip_hdr->ip_p == 0x0006 || ip_hdr->ip_p == 0x0011) {
      /* TCP/UDP */
      
    } else {
      /* Unsupported Protocol */
      return ;
    }
  } else {
    /* Destined elsewhere, forward */
    ;
  }

  // sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt);
  // sr_ip_hdr_t *ip_hdr = (sr_ip_hdr *)(pkt + sizeof(sr_ethernet_hdr_t));

  // /* is it for me? */
  // struct sr_if *dest_if = sr_get_interface_by_MAC(sr, ip_hdr->ip_dst);
  
  // if (dest_if) {
  //   /* packet destined to router */
  //   /* check if packet is icmp */
    
  //   if (ip_hdr->ip_p == ip_protocol_icmp) {
  //     /* packet is an ICMP message respond accordingly */
  //     sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + sizeof(sr_ip_hdr_t));
  //     if (icmp_hdr->icmp_code != 8) {
  //       /* only need to handle type 0 (echo) messages, drop packet */
  //       return;
  //     }
  //     icmp_hdr->icmp_type = 0;
  //     icmp_hdr->icmp_code = 0;
  //     icmp_hdr->sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));

  //     struct sr_if *sr_int = sr_get_interface(sr, interface);
  //     ip_hdr->ip_dst = ip_hdr->ip_src;
  //     ip_hdr->ip_src = sr_int->ip;
  //     ip_hdr->ip_sum = 0;
  //     ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  //     uint8_t dst_temp[ETHER_ADDR_LEN];
  //     memcpy(dst_temp, eth_hdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  //     memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  //     memcpy(eth_hdr->ether_shost, dst_temp, sizeof(uint8_t) * ETHER_ADDR_LEN);

  //     sr_send_packet(sr, pkt, len, interface);
  //   } else if (ip_hdr->ip_p == 0x0006 || ip_hdr->ip_p == 0x0011) {
  //     /* packet is TCP/UDP, send ICMP port unreachable and drop */
  //     uint8_t *packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

  //   } 
  //   else {
  //     /* uncrecognized or unsupported protocol, drop packet */
  //     return;
  //   }
  // } else {
  //   /* packet destined elsewhere */
  //   /* decrement TTL by 1 and recompute checksum */
  //   ip_hdr->ip_sum -= 1;
  //   if (ip_hdr->ip_sum <= 0) {
  //     /* TODO Send ICMP time exceeded here */
  //     return ;
  //   }
  //   ip_hdr->ip_sum = cksum(ip_hdr, len - sizeof(sr_ethernet_hdr_t));
  //   /* forward packet */
  // }
  // /* find out which entry in the routing table has longest prefix match w destination IP */
  // /* check ARP cache for next hop MAC addr corresponding to next hop IP */
  //   /* if its there, send it */
  //   /* else, send ARP request for next hop IP (if one hasnt been sent in past second) and add to ARP Q */
}

void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *pkt, char *interface, int len) {
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + sizeof(sr_ip_hdr_t));

  /* Prepare ICMP header */
  icmp_hdr->type = 3;
  icmp_hdr->code = 3;
  icmp_hdr->sum = 0;
  icmp_hdr->sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));

  /* Prepare IP header */
  struct sr_if *my_int = sr_get_interface(sr, interface);
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = my_int->ip;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  /* Prepare Ethernet Frame */
  uint8_t temp_src[ETHER_ADDR_LEN];
  memcpy(temp_src, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_dhost, temp_src, sizeof(uint8_t) * ETHER_ADDR_LEN);

  sr_send_packet(sr, pkt, len, interface);
}

void send_icmp3_error(int type, int code, struct sr_isntance *sr, uint32_t src_ip, uint32_t dst_ip, uint8_t *orig_pkt, unsigned int len, char *interface) {
  unsigned int plen = sizeof(sr_ethernet_hdr_t) +_ sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t);
  uint8_t *ret_pkt = malloc(plen);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(ret_pkt + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(ip_hdr + sizeof(sr_ip_hdr_t));
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t)(ret_pkt);

  /* Construct ICMP Header */
  icmp_hdr->type = type;
  icmp_hdr->code = code;
  icmp_hdr->sum = 0;
  icmp_hdr->sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  memcpy(icmp_hdr->data, orig_pkt + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t) + 8);

  /* Construct IP Header */
  ip_hdr->ip_tos = 4;
  ip_hdr->ip_len = 5;
  ip_hdr->id_id = 0;
  ip_hdr->ip_off = IP_DF;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->sum = 0;
  ip_hdr->ip_dst = ((sr_ip_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t)))->ip_src; /* Already net. byte order */

  /* Find LPM for dest. IP */
  struct sr_rt *dst_rt = longest_prefix_match(sr, ip_hdr->ip_dst);
  if (dst_rt) {
    /* Match found in RT */
    struct sr_if *my_if = sr_get_interface(sr, dst_rt->interface);
    ip_hdr->src_ip = my_if->ip;
    memcpy(eth_hdr->ether_shost, my_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);

    /* Consult ARP cache for previous dest. IP MAC */
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(sr->cache, ip_hdr->src_ip);
    if (arp_entry) {
      /* Match found, prepare Ethernet frame and send */
      memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
      eth_hdr->ether_type = htonl(ethertype_ip);

      /* Compute IP checksum and send */
      ip_hdr->sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      sr_send_packet()
    } else {
      /* No match exists, send ARP request and queue packet */
      ;
    }
  } else {
    ;
  }
}

struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t dest_addr) {
  struct sr_rt *walker = 0;

  /* REQUIRES */
  assert(sr);
  assert(dest_addr);

  walker = sr->routing_table;
  struct sr_rt *longest = 0;

  while (walker) {
    if (walker->dest.s_addr == (dest_addr & walker->mask.s_addr)) {
      if (walker->dest.s_addr > longest->dest.s_addr) {
        longest = walker;
      }
    }
    walker = walker->next;
  }

  return longest;
}

