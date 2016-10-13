
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#define INTERNAL_INTERFACE "eth1"
#define EXTERNAL_INTERFACE "eth2"

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
} sr_nat_mapping_type;

struct sr_nat_connection {
  /* add TCP connection state data members here */

  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  int valid; /* marks expired mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  struct sr_nat_mapping *mappings;
  unsigned int icmp_qt; /* ICMP Query Timeout */
  unsigned int tcp_eit; /* TCP Established Idle Timeout */
  unsigned int tcp_tit; /* TCP Transitory Idle Timeout */

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};

void sr_nat_remove_mapping (
  struct sr_nat *nat,
  struct sr_nat_mapping* mapping
);

int sr_nat_init (struct sr_nat *nat);  /* Initializes the nat */
void sr_nat_init_timings(
  struct sr_nat *nat,
  unsigned int icmp_qt,
  unsigned int tcp_eit,
  unsigned int tcp_tit);
int sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );


#endif
