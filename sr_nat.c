
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int sr_nat_init (struct sr_nat *nat) { /* Initializes the nat */
  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;

  return success;
}

void sr_nat_init_timings (
  struct sr_nat *nat,
  unsigned int icmp_qt,
  unsigned int tcp_eit,
  unsigned int tcp_tit
) {
  nat->icmp_qt = icmp_qt;
  nat->tcp_eit = tcp_eit;
  nat->tcp_tit = tcp_tit;
}

/* Destroys the nat (free memory) */
int sr_nat_destroy (struct sr_nat *nat) {

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  while (nat->mappings) {
    /* pthread_mutex_unlock(&(nat->lock)); */
    sr_nat_remove_mapping(nat, nat->mappings);
    /* pthread_mutex_lock(&(nat->lock)); */
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

/* Periodic Timout handling */
void *sr_nat_timeout (void *nat_ptr) {
  struct sr_nat *nat = (struct sr_nat *) nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);
    struct sr_nat_mapping* m_walker = nat->mappings;
    while (m_walker) {
      if (m_walker->type == nat_mapping_icmp
        && difftime(curtime, m_walker->last_updated) > nat->icmp_qt) {
          m_walker->valid = 0;
      }

      /* TODO: Established vs. Transitory */
      if (m_walker->type == nat_mapping_tcp
        && difftime(curtime, m_walker->last_updated) > nat->tcp_tit) {
          m_walker->valid = 0;
      }

      m_walker = m_walker->next;
    }
    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external (
  struct sr_nat *nat,
  uint16_t aux_ext,
  sr_nat_mapping_type type
) {

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *m_walker = nat->mappings, *copy = NULL;
  while (m_walker) {
    if ((m_walker->aux_ext == aux_ext) &&
      (m_walker->type == type) && m_walker->valid) {
      break;
    }
    m_walker = m_walker->next;
  }

  if (m_walker) {
    copy = malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, m_walker, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal (
  struct sr_nat *nat,
  uint32_t ip_int,
  uint16_t aux_int,
  sr_nat_mapping_type type
) {

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *m_walker = nat->mappings, *copy = NULL;
  while (m_walker) {
    if ((m_walker->ip_int == ip_int) &&
      (m_walker->aux_int == aux_int) &&
      (m_walker->type == type) && m_walker->valid) {
      break;
    }
    m_walker = m_walker->next;
  }

  if (m_walker) {
    copy = malloc(sizeof(struct sr_nat_mapping));
    memcpy(copy, m_walker, sizeof(struct sr_nat_mapping));
  }

  pthread_mutex_unlock(&(nat->lock));

  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping (
  struct sr_nat *nat,
  uint32_t ip_int,
  uint16_t aux_int,
  sr_nat_mapping_type type
) {

  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping)),
                           *copy = malloc(sizeof(struct sr_nat_mapping));
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->aux_int = aux_int;
  mapping->aux_ext = (rand() % (UINT16_MAX - 1024)) + 1025; /* Don't use ports (0-1024) */
  mapping->last_updated = time(NULL);
  mapping->valid = 1;
  mapping->conns = NULL;
  mapping->next = nat->mappings;
  nat->mappings = mapping;
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));

  return copy;
}

/* Remove a mapping in the nat mapping table */
void sr_nat_remove_mapping (
  struct sr_nat *nat,
  struct sr_nat_mapping* mapping
) {

  pthread_mutex_lock(&(nat->lock));
  if (mapping) {
    struct sr_nat_mapping *curr, *prev = NULL, *next = NULL;
    for (curr = nat->mappings; curr != NULL; curr = curr->next) {
      if (curr == mapping) {
        if (prev) {
          next = curr->next;
          prev->next = next;
        } else {
          next = curr->next;
          mapping = next;
        }
        break;
      }
      prev = curr;
    }
    free(mapping);
  }

  pthread_mutex_unlock(&(nat->lock));
}
