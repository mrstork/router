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
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"
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

void sr_handlepacket(
    struct sr_instance* sr,
    uint8_t* packet,
    unsigned int len,
    char* interface
) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    /* Ensure packet meets minimum length */
    if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "Sanity Error: Ethernet packet has insufficient length\n");
        return;
    }

    print_hdrs(packet, len);

    switch (ethertype(packet)) {
        case ethertype_arp:
            sr_handle_arp_packet(sr, packet, len, interface);
            break;
        case ethertype_ip:
            sr_handle_ip_packet(sr, packet, len, interface);
            break;
    }
}/* end sr_handlepacket */

void sr_handle_arp_packet(
    struct sr_instance* sr,
    uint8_t* packet,
    unsigned int len,
    char* interface
) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if* if_in = sr_has_ip(sr, arp_hdr->ar_tip);

    if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
        fprintf(stderr, "Fatal Error: Unknown hardware type\n");
        return;
    }

    if (len - sizeof(sr_ethernet_hdr_t) < sizeof(sr_arp_hdr_t)) {
        fprintf(stderr, "Sanity Error: ARP packet has insufficient length\n");
        return;
    }

    if (!if_in) {
        fprintf(stderr, "Error: ARP Request/Reply not for us\n");
        return;
    }

    switch (ntohs(arp_hdr->ar_op)) {
        case arp_op_request: {
            printf("Received ARP Request \n");
            /* ARP Request - Send an ARP Reply back */
            populate_arp_header(packet, if_in->addr, arp_hdr->ar_sha, if_in->ip, arp_hdr->ar_sip, arp_op_reply);
            populate_ethernet_header(packet, if_in->addr, eth_hdr->ether_shost, ethertype_arp);
            sr_send_packet(sr, packet, len, interface);
            break;
        }
        case arp_op_reply: {
            printf("Received ARP Reply \n");
            /* ARP Reply - Cache ARP Reply, Go through request queue and send outstanding packets */
            struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
            if (req) {
                printf("Sending waiting packets \n");
                struct sr_packet *p;
                for (p = req->packets; p != NULL; p = p->next) {
                    populate_ethernet_header(p->buf, if_in->addr, arp_hdr->ar_sha, ethertype_ip);
                    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(p->buf + sizeof(sr_ethernet_hdr_t));
                    struct sr_rt *lpm = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
                    sr_send_packet(sr, p->buf, p->len, lpm->interface);
                }
                sr_arpreq_destroy(&sr->cache, req);
            }
            break;
        }
    }
}

void sr_handle_ip_packet(
    struct sr_instance* sr,
    uint8_t* packet,
    unsigned int len,
    char* interface
) {

    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* Ensure packet meets minimum length */
    if (ntohs(ip_hdr->ip_hl) < sizeof(sr_ip_hdr_t)) {
        fprintf(stderr, "Sanity Error: Ethernet packet has insufficient length\n");
        return;
    }

    /* Ensure packet has correct checksum */
    uint16_t received_sum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = (uint16_t) 0;
    if (received_sum != cksum(ip_hdr, sizeof(sr_ip_hdr_t))) {
        printf("Sanity Error: Invalid checksum. \n");
        return;
    }
    ip_hdr->ip_sum = received_sum;

    if (sr->nat != NULL) {
        sr_handle_nat_packet(sr, packet, len, interface);
    }

    if (sr_has_ip(sr, ip_hdr->ip_dst)) {
        sr_handle_router_packet(sr, packet, len, interface);
    } else {
        struct sr_if* if_in = sr_get_interface(sr, interface);
        struct sr_rt *lpm = sr_longest_prefix_match(sr, ip_hdr->ip_dst);

        /* Check non-existent IP */
        if (lpm == NULL) {
            printf("No match. Dropping Packet\n");
            send_icmp_t3_packet(sr, if_in->ip, packet, interface, icmp_t3_dest_unreachable, net_unreachable);
            return;
        }

        /* Check if TTL expired */
        if (ip_hdr->ip_ttl <= 1) {
            printf("Received Expired Packet - Sending Time Exceeded\n");
            send_icmp_t3_packet(sr, if_in->ip, packet, interface, icmp_t3_time_exceeded, 0x0000);
            return;
        }

        printf("Forwarding IP Packet \n");
        sr_forward_ip_packet(sr, packet, len, interface);
    }
}

void sr_handle_nat_packet(
    struct sr_instance* sr,
    uint8_t* packet,
    unsigned int len,
    char* interface
) {
    struct sr_if* if_in = sr_get_interface(sr, interface);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    struct sr_nat_mapping *mapping;
    sr_nat_mapping_type protocol_type;
    uint16_t port;

    switch (ip_hdr->ip_p) {
        case ip_protocol_icmp:
            protocol_type = nat_mapping_icmp;
            port = icmp_hdr->icmp_id;
            break;
        case ip_protocol_tcp:
            protocol_type = nat_mapping_tcp;
            port = tcp_hdr->tcp_dst_port;
            break;
    }

    /* Check if TTL expired */
    if (ip_hdr->ip_ttl <= 1) {
        printf("Received Expired Packet - Sending Time Exceeded\n");
        send_icmp_t3_packet(sr, if_in->ip, packet, interface, icmp_t3_time_exceeded, 0x0000);
        return;
    }

    if (ip_hdr->ip_p == ip_protocol_icmp || ip_hdr->ip_p == ip_protocol_tcp) {
        if (strcmp(interface, INTERNAL_INTERFACE) == 0) {

            /* Check non-existent IP */
            struct sr_rt *lpm = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
            if (lpm == NULL) {
                send_icmp_t3_packet(sr, if_in->ip, packet, interface, icmp_t3_dest_unreachable, net_unreachable);
                return;
            }

            mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, port, protocol_type);
            if (mapping == NULL) {
                if ((ip_hdr->ip_p == ip_protocol_tcp) && (htons(tcp_hdr->control) && TCP_SYN)) {
                    if (strcmp(lpm->interface, INTERNAL_INTERFACE) == 0) return;
                }
                mapping = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, port, protocol_type);
            }

            struct sr_if* if_out = sr_get_interface(sr, EXTERNAL_INTERFACE);
            ip_hdr->ip_src = if_out->ip;

            if (protocol_type == nat_mapping_icmp) {
                icmp_hdr->icmp_id = mapping->aux_ext;
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            } else if (protocol_type == nat_mapping_tcp) {
                tcp_hdr->tcp_src_port = mapping->aux_ext;
            }

            free(mapping);
        } else if (strcmp(interface, EXTERNAL_INTERFACE) == 0) {
            mapping = sr_nat_lookup_external(sr->nat, port, protocol_type);
            if (mapping == NULL) {
                send_icmp_t3_packet(sr, if_in->ip, packet, interface, icmp_t3_dest_unreachable, port_unreachable);
                return;
            }

            ip_hdr->ip_dst = mapping->ip_int;

            if (protocol_type == nat_mapping_icmp) {
                icmp_hdr->icmp_id = mapping->aux_int;
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            } else if (protocol_type == nat_mapping_tcp) {
                tcp_hdr->tcp_dst_port = mapping->aux_int;
                if (ntohs(tcp_hdr->control) && TCP_SYN) {
                    tcp_hdr->control = htons(TCP_SYN_ACK);
                }

            }

            print_hdrs(packet, len);
            free(mapping);
        }

        if (protocol_type == nat_mapping_tcp) {
            /* Recalculate TCP checksum */
            tcp_hdr->tcp_sum = 0;

            /* Generate TCP Pseudo Header */
            int tcp_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
            int cksum_hdr_len = tcp_len + sizeof(sr_tcp_psdo_hdr_t);
            uint8_t *cksum_hdr = malloc(cksum_hdr_len * sizeof(uint8_t));

            /* Populate TCP Pseudo Header */
            sr_tcp_psdo_hdr_t *tcp_psdo_hdr = (sr_tcp_psdo_hdr_t *)(cksum_hdr);
            tcp_psdo_hdr->ip_src = ip_hdr->ip_src;
            tcp_psdo_hdr->ip_dst = ip_hdr->ip_dst;
            tcp_psdo_hdr->reserved = 0;
            tcp_psdo_hdr->protocol = ip_protocol_tcp;
            tcp_psdo_hdr->tcp_length = htons(tcp_len);

            /* Copy in original TCP Header */
            sr_tcp_hdr_t *tcp_seg = (sr_tcp_hdr_t *)(cksum_hdr + sizeof(sr_tcp_psdo_hdr_t));
            memcpy(tcp_seg, tcp_hdr, tcp_len);

            tcp_hdr->tcp_sum = cksum(cksum_hdr, cksum_hdr_len);
            free(tcp_psdo_hdr);
        }
    }
}

void sr_handle_router_packet(
    struct sr_instance* sr,
    uint8_t* packet,
    unsigned int len,
    char* interface
) {
    struct sr_if* if_in = sr_get_interface(sr, interface);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    switch (ip_hdr->ip_p) {
        case ip_protocol_icmp: {
            printf("Received ICMP Packet\n");
            print_hdrs(packet, len);
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            if (icmp_hdr->icmp_type == icmp_echo_request) {
                populate_icmp_header(packet, icmp_echo_reply, len);
                populate_ip_header(
                    packet,
                    ip_hdr->ip_id,
                    ip_hdr->ip_dst,
                    ip_hdr->ip_src,
                    len - sizeof(sr_ip_hdr_t) - sizeof(sr_ethernet_hdr_t));
                populate_ethernet_header(packet, if_in->addr, eth_hdr->ether_shost, ethertype_ip);

                struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
                if (entry) {
                    printf("ARP Cache Hit\n");
                    populate_ethernet_header(packet, if_in->addr, entry->mac, ethertype_ip);
                    print_hdrs(packet, len);
                    sr_send_packet(sr, packet, len, interface);
                    free(entry);
                } else {
                    printf("ARP Cache Miss\n");
                    struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, interface);
                    sr_handle_arpreq(sr, req);
                }
            }
            break;
        }
        case ip_protocol_tcp:
        case ip_protocol_udp: {
            printf("Received TCP/UDP Packet - Sending Port Unreachable\n");
            send_icmp_t3_packet(sr, ip_hdr->ip_dst, packet, interface, icmp_t3_dest_unreachable, port_unreachable);
            break;
        }
    }
}

void sr_forward_ip_packet(
    struct sr_instance* sr,
    uint8_t* packet,
    unsigned int len,
    char* interface
) {
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_rt *lpm = sr_longest_prefix_match(sr, ip_hdr->ip_dst);

    /* Decrement the TTL by 1, and recompute the packet checksum over the modified header. */
    ip_hdr->ip_ttl -= 1;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
    if (entry) {
        printf("ARP Cache Hit\n");
        /* Modify Ethernet Header */
        struct sr_if* if_out = sr_get_interface(sr, lpm->interface);
        populate_ethernet_header(packet, if_out->addr, entry->mac, ethertype_ip);
        print_hdrs(packet, len);
        sr_send_packet(sr, packet, len, lpm->interface);
        free(entry);
    } else {
        printf("ARP Cache Miss\n");
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, interface);
        sr_handle_arpreq(sr, req);
    }
}

void send_icmp_t3_packet (
    struct sr_instance* sr,
    uint32_t ip_src,
    uint8_t* rcvd_pckt,
    char* interface,
    enum sr_icmp_t3_type type,
    enum sr_icmp_t3_code code
) {
    struct sr_if* if_in = sr_get_interface(sr, interface);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) rcvd_pckt;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(rcvd_pckt + sizeof(sr_ethernet_hdr_t));

    /* Create packet */
    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *icmp_pckt = malloc(len * sizeof(uint8_t));

    /* Populate packet */
    populate_icmp_t3_header(icmp_pckt, ip_hdr, type, code);
    populate_ip_header(icmp_pckt, 0, ip_src, ip_hdr->ip_src, sizeof(sr_icmp_t3_hdr_t));
    populate_ethernet_header(icmp_pckt, if_in->addr, eth_hdr->ether_shost, ethertype_ip);

    /* New Header */
    ip_hdr = (sr_ip_hdr_t *)(icmp_pckt + sizeof(sr_ethernet_hdr_t));
    /* Send packet */
    if (! sr_has_ip(sr, ip_hdr->ip_dst)) {
        struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
        if (entry) {
            populate_ethernet_header(icmp_pckt, if_in->addr, entry->mac, ethertype_ip);
            print_hdrs(icmp_pckt, len);
            sr_send_packet(sr, icmp_pckt, len, interface);
            free(entry);
        } else {
            print_hdrs(icmp_pckt, len);
            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, icmp_pckt, len, interface);
            sr_handle_arpreq(sr, req);
        }
    }

    free(icmp_pckt);
}

void populate_arp_header (
    uint8_t* packet,
    uint8_t *eth_src,
    uint8_t *eth_dst,
    uint32_t ip_src,
    uint32_t ip_dst,
    unsigned int ar_op
) {
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 4;
    arp_hdr->ar_op = htons(ar_op);

    uint8_t temp_eth[ETHER_ADDR_LEN];
    memcpy(temp_eth, eth_dst, ETHER_ADDR_LEN);
    memcpy(arp_hdr->ar_sha, eth_src, ETHER_ADDR_LEN);
    memcpy(arp_hdr->ar_tha, temp_eth, ETHER_ADDR_LEN);

    uint32_t temp_ip = ip_dst;
    arp_hdr->ar_sip = ip_src;
    arp_hdr->ar_tip = temp_ip;
}

void populate_icmp_header (
    uint8_t* packet,
    enum sr_icmp_type type,
    unsigned int len
) {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
}

void populate_icmp_t3_header (
    uint8_t* packet,
    sr_ip_hdr_t *rcvd_ip_hdr,
    enum sr_icmp_t3_type type,
    enum sr_icmp_t3_code code
) {
    sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->unused = 0;
    icmp_hdr->next_mtu = 0;
    memcpy(icmp_hdr->data, rcvd_ip_hdr, ICMP_DATA_SIZE);
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
}

void populate_ip_header (
    uint8_t* packet,
    uint16_t ip_id,
    uint32_t ip_src,
    uint32_t ip_dst,
    unsigned int len
) {
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + len);
    ip_hdr->ip_id = ip_id;
    ip_hdr->ip_off = htons(IP_DF);
    ip_hdr->ip_p = ip_protocol_icmp;
    ip_hdr->ip_ttl = INIT_TTL;

    uint32_t temp = ip_dst;
    ip_hdr->ip_src = ip_src;
    ip_hdr->ip_dst = temp;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}

void populate_ethernet_header (
    uint8_t* packet,
    uint8_t *eth_src,
    uint8_t *eth_dst,
    uint16_t type
) {
    uint8_t temp[ETHER_ADDR_LEN];
    memcpy(temp, eth_dst, ETHER_ADDR_LEN);
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(packet);
    memcpy(eth_hdr->ether_shost, eth_src, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_dhost, temp, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(type);
}
