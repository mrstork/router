/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance {
    int  sockfd;                 /* socket to server */
    char user[32];               /* user name */
    char host[32];               /* host name */
    char template_name[30];      /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr;  /* address to server */
    struct sr_if* if_list;       /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;    /* ARP cache */
    struct sr_nat* nat;          /* NAT mappings */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );

void populate_arp_header (uint8_t* packet, uint8_t *eth_src, uint8_t *eth_dest, uint32_t ip_src, uint32_t ip_dest, unsigned int ar_op);
void populate_icmp_header (uint8_t* packet, enum sr_icmp_type type, unsigned int len);
void populate_icmp_t3_header (uint8_t* packet, sr_ip_hdr_t *rcvd_ip_hdr, enum sr_icmp_t3_type type, enum sr_icmp_t3_code code);
void populate_ip_header (uint8_t* packet, uint16_t ip_id, uint32_t ip_src, uint32_t ip_dst, unsigned int len);
void populate_ethernet_header (uint8_t* packet, uint8_t *eth_src, uint8_t *eth_dest, uint16_t type);

void send_icmp_t3_packet (struct sr_instance* sr, uint32_t ip_src, uint8_t* rcvd_pckt, char* interface, enum sr_icmp_t3_type type, enum sr_icmp_t3_code code);

void sr_handle_arp_packet(struct sr_instance* sr, uint8_t * , unsigned int , char* );
void sr_handle_router_packet(struct sr_instance* sr, uint8_t * , unsigned int , char* );
void sr_forward_ip_packet(struct sr_instance* sr, uint8_t * , unsigned int , char* );
void sr_handle_nat_packet(struct sr_instance* sr, uint8_t * , unsigned int , char* );
void sr_handle_ip_packet(struct sr_instance* sr, uint8_t * , unsigned int , char* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
