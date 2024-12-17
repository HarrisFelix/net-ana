// Copyright 2024 Felix Harris Ndiaye

#ifndef SRC_PROTOCOLS_TRANSPORT_TCP_TCP_H_
#define SRC_PROTOCOLS_TRANSPORT_TCP_TCP_H_

#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __linux__
#define TH_ECE 0x40
#define TH_CWR 0x80
#endif

/* For relative sequence and ack number purposes
 * TODO: Make it a dynamically allocated, a linked list would be good */
#define MAX_N_TCP_SESSIONS 100

/* https://stackoverflow.com/questions/40693548/relative-sequence-ack-number-in-jnetpcap
 * We want to keep track of relative sequence and acknowledgement numbers,
 * we are doing something simplified here */
struct tcp_session_info {
  uint32_t session_id; /* to recognize the session */
  tcp_seq seq_offset;  /* absolute sequence number */
  tcp_seq ack_offset;  /* absolute acknowledgement number */
};
extern struct tcp_session_info tcp_sessions[MAX_N_TCP_SESSIONS];

void print_tcp_frame(const struct tcphdr *tcp, bool is_ipv6);
void print_tcp_flags(uint8_t flags);
inline bool tcp_is_session_start(uint8_t flags);
inline uint32_t tcp_get_session_id(const struct tcphdr *tcp, bool is_ipv6);
void get_session_info(const struct tcphdr *tcp,
                      struct tcp_session_info *session, bool is_ipv6);
void print_seq_ack_numbers(const struct tcphdr *tcp, bool is_ipv6);
void print_tcp_cksum(const struct tcphdr *tcp, bool is_ipv6);

#endif  // SRC_PROTOCOLS_TRANSPORT_TCP_TCP_H_
