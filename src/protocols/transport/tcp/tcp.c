#include "../../../capture/capture_utils.h"
#include "../../../capture/packet_utils.h"
#include "../../network/ip/ip.h"
#include "../../network/ip6/ip6.h"
#include "tcp.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

extern enum verbosity_level verbosity;
extern u_int payload_length;
struct tcp_session_info tcp_sessions[MAX_N_TCP_SESSIONS] = {0};

/* https://datatracker.ietf.org/doc/html/rfc9293 */
void print_tcp_frame(const struct tcphdr *tcp, bool is_ipv6) {
  printf(": TCP");
  printf(", ports [src:%d, dst:%d]", htons(tcp->th_sport),
         htons(tcp->th_dport));

  if (verbosity <= LOW)
    return;

  print_seq_ack_numbers(tcp, is_ipv6);
  printf(", offset %d", tcp->th_off);
  printf(", reserved 0x%x", tcp->th_x2);

  printf(", flags ");
  print_tcp_flags(tcp->th_flags);

  printf(", win %d", htons(tcp->th_win));
  print_tcp_cksum(tcp, is_ipv6);

  /* Update the payload length */
  payload_length -= tcp->th_off * 4;
}

void print_tcp_flags(uint8_t flags) {
  printf("[");
  const char *delimiter = "";

  if (!flags) {
    printf("none");
  } else {
    if (flags & TH_FIN) {
      printf("%sFIN", delimiter);
      delimiter = ", ";
    }
    if (flags & TH_SYN) {
      printf("%sSYN", delimiter);
      delimiter = ", ";
    }
    if (flags & TH_RST) {
      printf("%sRST", delimiter);
      delimiter = ", ";
    }
    if (flags & TH_PUSH) {
      printf("%sPSH", delimiter);
      delimiter = ", ";
    }
    if (flags & TH_ACK) {
      printf("%sACK", delimiter);
      delimiter = ", ";
    }
    if (flags & TH_URG) {
      printf("%sURG", delimiter);
      delimiter = ", ";
    }
    if (flags & TH_ECE) {
      printf("%sECE", delimiter);
      delimiter = ", ";
    }
    if (flags & TH_CWR) {
      printf("%sCWR", delimiter);
    }
  }

  printf("]");
}

inline bool tcp_is_session_start(uint8_t flags) {
  return flags == (TH_SYN | TH_ACK) || flags == TH_SYN;
}

void print_seq_ack_numbers(const struct tcphdr *tcp, bool is_ipv6) {
  struct tcp_session_info session;
  get_session_info(tcp, &session, is_ipv6);

  if (!session.session_id) {
    printf(", seq %u", htonl(tcp->th_seq));
    printf(", ack %u", htonl(tcp->th_ack));
  } else {
    printf(", relative seq %u",
           htonl(tcp->th_seq) - (htonl(session.seq_offset)));
    if (verbosity == HIGH)
      printf(" (%u)", htonl(tcp->th_seq));

    printf(", relative ack %u",
           htonl(tcp->th_ack) - (htonl(session.ack_offset)) + 1);
    if (verbosity == HIGH)
      printf(" (%u)", htonl(tcp->th_ack));
  }
}

/* Simplest possible method to get a sort of "hash", a semi-unique identifier */
inline uint32_t tcp_get_session_id(const struct tcphdr *tcp, bool is_ipv6) {
  if (is_ipv6) {
    struct ip6_hdr *ip6 =
        (struct ip6_hdr *)((char *)tcp - sizeof(struct ip6_hdr));
    return tcp->th_sport ^ tcp->th_dport ^
           ip6->ip6_src.__u6_addr.__u6_addr32[0] ^
           ip6->ip6_src.__u6_addr.__u6_addr32[1] ^
           ip6->ip6_src.__u6_addr.__u6_addr32[2] ^
           ip6->ip6_src.__u6_addr.__u6_addr32[3] ^
           ip6->ip6_dst.__u6_addr.__u6_addr32[0] ^
           ip6->ip6_dst.__u6_addr.__u6_addr32[1] ^
           ip6->ip6_dst.__u6_addr.__u6_addr32[2] ^
           ip6->ip6_dst.__u6_addr.__u6_addr32[3] - tcp->th_sport;
  } else {
    struct ip *ip = (struct ip *)((char *)tcp - sizeof(struct ip));
    return tcp->th_sport ^ tcp->th_dport ^ ip->ip_src.s_addr ^
           ip->ip_dst.s_addr - tcp->th_sport;
  }
}

void get_session_info(const struct tcphdr *tcp,
                      struct tcp_session_info *session, bool is_ipv6) {
  session->session_id = tcp_get_session_id(tcp, is_ipv6);

  size_t i;
  bool found = false;
  /* We look for the session in the list of sessions if we're not a session
   * start */
  for (i = 0; i < MAX_N_TCP_SESSIONS && !found; i++)
    if (tcp_sessions[i].session_id == session->session_id)
      found = true;

  /* We decrement i because we incremented it one too many times */
  if (found)
    i--;

  /* If we're not the start of a session, and haven't found anything, we set the
   * session ID to 0 as a warning to the parent functions, if we did find
   * something we set the ISN (as offsets) */
  if (!tcp_is_session_start(tcp->th_flags)) {
    if (!found) {
      session->session_id = 0;
    } else {
      session->seq_offset = tcp_sessions[i].seq_offset;
      session->ack_offset = tcp_sessions[i].ack_offset;
    }

    return;
  }

  /* If we're here, it means this is the beginning of a connection, if there was
   * a session with the same ID, we replace it, if there wasn't we just add a
   * new session at the end */
  session->seq_offset = tcp->th_seq;
  session->ack_offset = tcp->th_ack;
  tcp_sessions[i % MAX_N_TCP_SESSIONS].session_id = session->session_id;
  tcp_sessions[i % MAX_N_TCP_SESSIONS].seq_offset = tcp->th_seq;
  tcp_sessions[i % MAX_N_TCP_SESSIONS].ack_offset = tcp->th_ack;
}

/* FIX: The checksum is not calculated correctly */
void print_tcp_cksum(const struct tcphdr *tcp, bool is_ipv6) {
  /* We calculate the checksum so we have to use a different header depending on
   * if we're working with IPv4 or IPv6 */
  if (is_ipv6) {
    struct pseudo_ip6_hdr pseudo_ip6;
    struct ip6_hdr *ip6 =
        (struct ip6_hdr *)((char *)tcp - sizeof(struct ip6_hdr));
    set_pseudo_ip6_hdr(&pseudo_ip6, ip6->ip6_src, ip6->ip6_dst, ip6->ip6_plen,
                       ip6->ip6_nxt);

    printf(", tcp cksum 0x%04x (%s)", htons(tcp->th_sum),
           validate_checksum(
               (const void *)&pseudo_ip6, is_ipv6, tcp,
               LITTLE_ENDIAN_INT_TO_32_BIT_WORDS(htons(ip6->ip6_plen)))
               ? "incorrect"
               : "correct");

  } else {
    struct pseudo_ip_hdr pseudo_ip;
    struct ip *ip = (struct ip *)((char *)tcp - sizeof(struct ip));
    set_pseudo_ip_hdr(&pseudo_ip, ip->ip_src, ip->ip_dst, ip->ip_p,
                      htons(ip->ip_len));

    printf(", tcp cksum 0x%04x (%s)", htons(tcp->th_sum),
           validate_checksum((const void *)&pseudo_ip, is_ipv6, tcp,
                             (payload_length))
               ? "incorrect"
               : "correct");
  }
}
