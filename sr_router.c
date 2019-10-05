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
        handle_arp(sr, packet, interface, len);

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

int check_arp_packet(uint8_t *pkt, unsigned int len) {
  return 1;
}

void handle_arp(struct sr_instance *sr, uint8_t *pkt, char *interface, unsigned int len) {
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt);
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  if (!check_arp_packet(pkt, len)) {
    /* Send error? */
    return;
  }

  struct sr_if *my_if = sr_get_interface_by_IP(sr, arp_hdr->ar_tip);

  if (my_if) {
    if (arp_hdr->ar_op == arp_op_request) {
    uint8_t *ret_pkt = malloc(len);
    memcpy(ret_pkt, pkt, len);

    sr_ethernet_hdr_t *ret_eth_hdr = (sr_ethernet_hdr_t *)(ret_pkt);
    sr_arp_hdr_t *ret_arp_hdr = (sr_arp_hdr_t *)(ret_pkt + sizeof(sr_ethernet_hdr_t));

    memcpy(ret_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(ret_eth_hdr->ether_shost, my_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    ret_eth_hdr->ether_type = ethertype_arp;

    ret_arp_hdr->ar_op = arp_op_reply;
    memcpy(ret_arp_hdr->ar_sha, my_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    ret_arp_hdr->ar_sip = my_if->ip;
    memcpy(ret_arp_hdr->ar_tha, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    ret_arp_hdr->ar_tip = arp_hdr->ar_sip;

    sr_send_packet(sr, ret_pkt, len, interface);
    free(ret_pkt);
    } else if (arp_hdr->ar_op == arp_op_reply) {
      struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

      if (req) {
        struct sr_packet *walker = req->packets;

        while (walker) {
          sr_ethernet_hdr_t *w_eth = (sr_ethernet_hdr_t *)(walker->buf);
          memcpy(w_eth, arp_hdr->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);

          sr_send_packet(sr, walker->buf, walker->len, walker->iface);
        }
        sr_arpreq_destroy(&sr->cache, req);
      }
    } else {
      printf("Unrecognized ARP Opcode. Dropping.\n");
      return;
    }
  }
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

  if (!check_ip_packet(pkt, len)) {
    printf("Packet is not valid. Dropping.\n");
    return;
  }

  struct sr_if *my_int = sr_get_interface_by_IP(sr, ip_hdr->ip_dst);

  if (my_int) {
    if (ip_hdr->ip_p == 1) {

      /* ICMP */
      sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + sizeof(sr_ip_hdr_t));
      if (icmp_hdr->icmp_type != 0) {
        /* Unsupported type, drop */
        return ;
      }
      send_icmp_echo_reply(sr, pkt, interface, len);

    } else if (ip_hdr->ip_p == 0x0006 || ip_hdr->ip_p == 0x0011) {
      /* TCP/UDP */
      send_icmp3_error(3, 3, sr, pkt);
      return;
    } else {
      /* Unsupported Protocol */
      return ;
    }
  } else {
    /* Destined elsewhere, forward */
    forward_ip(sr, pkt, len, interface);
  }

}

void forward_ip(struct sr_instance *sr, uint8_t *pkt, unsigned int len, char *interface) {
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  if (!check_ip_packet(pkt, len)) {
    printf("Received invalid packet. Dropping.\n");
    return;
  }

  ip_hdr->ip_ttl--;
  if (ip_hdr <= 0) {
    /* send icmp time exceeded */
    send_icmp3_error(11, 0, sr, pkt);
  }
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  /* Find longest prefix match */
  struct sr_rt *my_int = longest_prefix_match(sr, ip_hdr->ip_dst);
  if (my_int) {
    /* Check ARP cache for next-hop MAC */
    struct sr_if *my_if = sr_get_interface(sr, my_int->interface);
    memcpy(eth_hdr->ether_shost, my_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_src);
    if (arp_entry) {
      /* Match found, reconfigure Ethernet frame and forward. */
      memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
      sr_send_packet(sr, pkt, len, my_if->name);
    } else {
      /* Queue packet for ARP */
      sr_arpcache_queuereq(&sr->cache, my_if->ip, pkt, len, my_if->name);
    }
  } else {
    /* Match not found, send icmp error */
    send_icmp3_error(3, 0, sr, pkt);
  }
}

void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *pkt, char *interface, int len) {
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + sizeof(sr_ip_hdr_t));

  /* Prepare ICMP header */
  icmp_hdr->icmp_type = 0;
  icmp_hdr->icmp_code = 0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));

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

  sr_send_packet(sr, pkt, len, my_int->name);
}

void send_icmp3_error(int type, int code, struct sr_instance *sr, uint8_t *orig_pkt) {
  unsigned int plen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t);
  uint8_t *ret_pkt = malloc(plen);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(ret_pkt + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(ip_hdr + sizeof(sr_ip_hdr_t));
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(ret_pkt);

  /* Construct ICMP Header */
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  memcpy(icmp_hdr->data, orig_pkt + sizeof(sr_ethernet_hdr_t), sizeof(sr_icmp_t3_hdr_t));

  /* Construct IP Header */
  ip_hdr->ip_tos = 4;
  ip_hdr->ip_len = 5;
  ip_hdr->ip_id = 0;
  ip_hdr->ip_off = IP_DF;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_dst = ((sr_ip_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t)))->ip_src; /* Already net. byte order */

  /* Find LPM for dest. IP */
  struct sr_rt *dst_rt = longest_prefix_match(sr, ip_hdr->ip_dst);
  if (dst_rt) {
    /* Match found in RT */
    struct sr_if *my_if = sr_get_interface(sr, dst_rt->interface);
    ip_hdr->ip_src = my_if->ip;
    memcpy(eth_hdr->ether_shost, my_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);

    /* Consult ARP cache for previous dest. IP MAC */
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_src);
    if (arp_entry) {
      /* Match found, prepare Ethernet frame and send */
      memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
      eth_hdr->ether_type = htons(ethertype_ip);

      /* Compute IP checksum and send */
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      sr_send_packet(sr, ret_pkt, plen, my_if->name);

      free(ret_pkt);
      free(arp_entry);
    } else {
      /* No match exists, add packet to ARP queue */
      struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, my_if->ip, ret_pkt, plen, my_if->name);
      handle_arpreq(req, &sr->cache);
    }
  } else {
    fprintf(stderr, "IP not found in routing table for sending ICMP type 3. Check IP.\n");
    return;
  }
}

/*----------------------------------------------------------------------------------------------------------------------
 * NOTE: This is gonna be done in arpcache.c. We throw packets on the queue and send ARP requests there. Once we get one,
 * we send all the packets on the queue in there.
 *-----------------------------------------------------------------------------------------------------------------------*/
void send_arp_request(struct sr_instance *sr, uint32_t src_ip, uint8_t src_mac[ETHER_ADDR_LEN], uint32_t dst_ip, char *interface) {
  sr_arp_hdr_t *arp_req;

  arp_req->ar_hrd = arp_hrd_ethernet;
  arp_req->ar_pro = htons(0x800);
  arp_req->ar_hln = 6;
  arp_req->ar_pln = 4;
  arp_req->ar_op = arp_op_request;
  memcpy(arp_req->ar_sha, src_mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
  arp_req->ar_sip = src_ip;
  arp_req->ar_tip = dst_ip;

  /* Search routing table for longest prefix match for dst IP */
  struct sr_rt *lpm = longest_prefix_match(sr, dst_ip);
  if (!lpm) {
    /* somethings wrong, shouldnt get here */
    return;
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

