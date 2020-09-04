/*
------------------------------------------------------------------------------------------------------------------------
context_cc.c
Copyright (C) 2019-20 - NFStream Developers
This file is part of NFStream, a Flexible Network Data Analysis Framework (https://www.nfstream.org/).
NFStream is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
version.
NFStream is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
You should have received a copy of the GNU Lesser General Public License along with NFStream.
If not, see <http://www.gnu.org/licenses/>.
------------------------------------------------------------------------------------------------------------------------
*/

#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <math.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <machine/endian.h>
#endif
#ifdef __OpenBSD__
#include <endian.h>
#define __BYTE_ORDER BYTE_ORDER
#if BYTE_ORDER == LITTLE_ENDIAN
#define __LITTLE_ENDIAN__
#else
#define __BIG_ENDIAN__
#endif/* BYTE_ORDER */
#endif/* __OPENBSD__ */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#endif
#else
#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__
#endif
#endif
#if !(defined(__LITTLE_ENDIAN__) || defined(__BIG_ENDIAN__))
#if defined(__mips__)
#undef __LITTLE_ENDIAN__
#undef __LITTLE_ENDIAN
#define __BIG_ENDIAN__
#endif
#if (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#else
#define __BIG_ENDIAN__
#endif
#endif
#endif

#define PACK_ON
#define PACK_OFF  __attribute__((packed))


/*
------------------------------------------------------------------------------------------------------------------------
                                           Observer Layer
------------------------------------------------------------------------------------------------------------------------
*/

#define TICK_RESOLUTION          1000
#define	IPVERSION	4
#ifndef ETH_P_IP
#define ETH_P_IP               0x0800 	/* IPv4 */
#endif
#ifndef ETH_P_IPv6
#define ETH_P_IPV6	       0x86dd	/* IPv6 */
#endif
#define SLARP                  0x8035   /* Cisco Slarp */
#define CISCO_D_PROTO          0x2000	/* Cisco Discovery Protocol */
#define VLAN                   0x8100
#define MPLS_UNI               0x8847
#define MPLS_MULTI             0x8848
#define PPPoE                  0x8864
#define SNAP                   0xaa
#define BSTP                   0x42     /* Bridge Spanning Tree Protocol */
#define	WIFI_DATA                        0x2    /* 0000 0010 */
#define FCF_TYPE(fc)     (((fc) >> 2) & 0x3)    /* 0000 0011 = 0x3 */
#define FCF_SUBTYPE(fc)  (((fc) >> 4) & 0xF)    /* 0000 1111 = 0xF */
#define FCF_TO_DS(fc)        ((fc) & 0x0100)
#define FCF_FROM_DS(fc)      ((fc) & 0x0200)
#define nfstream_min(a,b)   ((a < b) ? a : b)
#define nfstream_max(a,b)   ((a > b) ? a : b)
#define BAD_FCS                         0x50    /* 0101 0000 */
#define GTP_U_V1_PORT                  2152
#define NFSTREAM_CAPWAP_DATA_PORT          5247
#define TZSP_PORT                      37008
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL  113
#endif

typedef enum {
  nfstream_no_tunnel = 0,
  nfstream_gtp_tunnel,
  nfstream_capwap_tunnel,
  nfstream_tzsp_tunnel,
  nfstream_l2tp_tunnel,
} nfstream_packet_tunnel;


PACK_ON
struct nfstream_chdlc
{
  uint8_t addr;          /* 0x0F (Unicast) - 0x8F (Broadcast) */
  uint8_t ctrl;          /* always 0x00                       */
  uint16_t proto_code;   /* protocol type (e.g. 0x0800 IP)    */
} PACK_OFF;


PACK_ON
struct nfstream_slarp
{
  /* address requests (0x00)
     address replies  (0x01)
     keep-alive       (0x02)
  */
  uint32_t slarp_type;
  uint32_t addr_1;
  uint32_t addr_2;
} PACK_OFF;


PACK_ON
struct nfstream_cdp
{
  uint8_t version;
  uint8_t ttl;
  uint16_t checksum;
  uint16_t type;
  uint16_t length;
} PACK_OFF;


PACK_ON
struct nfstream_ethhdr
{
  uint8_t h_dest[6];       /* destination eth addr */
  uint8_t h_source[6];     /* source ether addr    */
  uint16_t h_proto;      /* data length (<= 1500) or type ID proto (>=1536) */
} PACK_OFF;


PACK_ON
struct nfstream_arphdr {
  uint16_t ar_hrd;/* Format of hardware address.  */
  uint16_t ar_pro;/* Format of protocol address.  */
  uint8_t  ar_hln;/* Length of hardware address.  */
  uint8_t  ar_pln;/* Length of protocol address.  */
  uint16_t ar_op;/* ARP opcode (command).  */
  uint8_t arp_sha[6];/* sender hardware address */
  uint32_t arp_spa;/* sender protocol address */
  uint8_t arp_tha[6];/* target hardware address */
  uint32_t arp_tpa;/* target protocol address */
} PACK_OFF;


PACK_ON
struct nfstream_dhcphdr {
  uint8_t      msgType;
  uint8_t      htype;
  uint8_t      hlen;
  uint8_t      hops;
  uint32_t     xid;/* 4 */
  uint16_t     secs;/* 8 */
  uint16_t     flags;
  uint32_t     ciaddr;/* 12 */
  uint32_t     yiaddr;/* 16 */
  uint32_t     siaddr;/* 20 */
  uint32_t     giaddr;/* 24 */
  uint8_t      chaddr[16]; /* 28 */
  uint8_t      sname[64]; /* 44 */
  uint8_t      file[128]; /* 108 */
  uint32_t     magic; /* 236 */
  uint8_t      options[308];
} PACK_OFF;


PACK_ON
struct nfstream_mdns_rsp_entry {
  uint16_t rsp_type, rsp_class;
  uint32_t ttl;
  uint16_t data_len;
} PACK_OFF;


PACK_ON
struct nfstream_snap_extension
{
  uint16_t   oui;
  uint8_t    oui2;
  uint16_t   proto_ID;
} PACK_OFF;


PACK_ON
struct nfstream_llc_header_snap
{
  uint8_t    dsap;
  uint8_t    ssap;
  uint8_t    ctrl;
  struct nfstream_snap_extension snap;
} PACK_OFF;


PACK_ON
struct nfstream_radiotap_header
{
  uint8_t  version;         /* set to 0 */
  uint8_t  pad;
  uint16_t len;
  uint32_t present;
  uint64_t MAC_timestamp;
  uint8_t flags;
} PACK_OFF;


PACK_ON
struct nfstream_wifi_header
{
  uint16_t fc;
  uint16_t duration;
  uint8_t rcvr[6];
  uint8_t trsm[6];
  uint8_t dest[6];
  uint16_t seq_ctrl;
  /* uint64_t ccmp - for data encryption only - check fc.flag */
} PACK_OFF;


PACK_ON
struct nfstream_mpls_header
{
  /* Before using this strcut to parse an MPLS header, you will need to convert
   * the 4-byte data to the correct endianess with ntohl(). */
#if defined(__LITTLE_ENDIAN__)
  uint32_t ttl:8, s:1, exp:3, label:20;
#elif defined(__BIG_ENDIAN__)
  uint32_t label:20, exp:3, s:1, ttl:8;
#else
# error "Byte order must be defined"
#endif
} PACK_OFF;


PACK_ON
struct nfstream_iphdr {
#if defined(__LITTLE_ENDIAN__)
  uint8_t ihl:4, version:4;
#elif defined(__BIG_ENDIAN__)
  uint8_t version:4, ihl:4;
#else
# error "Byte order must be defined"
#endif
  uint8_t tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
} PACK_OFF;


PACK_ON
struct nfstream_in6_addr {
  union {
    uint8_t   u6_addr8[16];
    uint16_t  u6_addr16[8];
    uint32_t  u6_addr32[4];
    uint64_t  u6_addr64[2];
  } u6_addr;  /* 128-bit IP6 address */
} PACK_OFF;


PACK_ON
struct nfstream_ip6_hdrctl {
  uint32_t ip6_un1_flow;
  uint16_t ip6_un1_plen;
  uint8_t ip6_un1_nxt;
  uint8_t ip6_un1_hlim;
} PACK_OFF;


PACK_ON
struct nfstream_ipv6hdr {
  struct nfstream_ip6_hdrctl ip6_hdr;
  struct nfstream_in6_addr ip6_src;
  struct nfstream_in6_addr ip6_dst;
} PACK_OFF;


PACK_ON
struct nfstream_tcphdr
{
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
#if defined(__LITTLE_ENDIAN__)
  uint16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif defined(__BIG_ENDIAN__)
  uint16_t doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#else
# error "Byte order must be defined"
#endif
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
} PACK_OFF;


PACK_ON
struct nfstream_udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
} PACK_OFF;

PACK_ON
struct nfstream_dns_packet_header {
  uint16_t tr_id;
  uint16_t flags;
  uint16_t num_queries;
  uint16_t num_answers;
  uint16_t authority_rrs;
  uint16_t additional_rrs;
} PACK_OFF;

typedef union
{
  uint32_t ipv4;
  uint8_t ipv4_uint8_t[4];
  struct nfstream_in6_addr ipv6;
} nfstream_ip_addr_t;


PACK_ON
struct nfstream_icmphdr {
  uint8_t type;/* message type */
  uint8_t code;/* type sub-code */
  uint16_t checksum;
  union {
    struct {
      uint16_t id;
      uint16_t sequence;
    } echo; /* echo datagram */

    uint32_t gateway; /* gateway address */
    struct {
      uint16_t _unused;
      uint16_t mtu;
    } frag;/* path mtu discovery */
  } un;
} PACK_OFF;


PACK_ON
struct nfstream_icmp6hdr {
  uint8_t     icmp6_type;   /* type field */
  uint8_t     icmp6_code;   /* code field */
  uint16_t    icmp6_cksum;  /* checksum field */
  union {
    uint32_t  icmp6_un_data32[1]; /* type-specific field */
    uint16_t  icmp6_un_data16[2]; /* type-specific field */
    uint8_t   icmp6_un_data8[4];  /* type-specific field */
  } icmp6_dataun;
} PACK_OFF;


PACK_ON
struct nfstream_vxlanhdr {
  uint16_t flags;
  uint16_t groupPolicy;
  uint32_t vni;
} PACK_OFF;


typedef struct nf_packet {
  uint8_t direction;
  uint64_t time;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
  uint16_t vlan_id;
  char src_name[48], dst_name[48];
  uint8_t ip_version;
  uint16_t fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1; /* TCP Flags */
  uint16_t raw_size;
  uint16_t ip_size;
  uint16_t transport_size;
  uint16_t payload_size;
  uint16_t ip_content_len;
  uint8_t *ip_content;
} nf_packet_t;


/**
 * nfstream_handle_ipv6_extension_headers: Handle IPv6 extensions header.
 */
int nfstream_handle_ipv6_extension_headers(const uint8_t **l4ptr, uint16_t *l4len, uint8_t *nxt_hdr)
{
    while ((*nxt_hdr == 0 || *nxt_hdr == 43 || *nxt_hdr == 44 || *nxt_hdr == 60 || *nxt_hdr == 135 || *nxt_hdr == 59)) {
        uint16_t ehdr_len;
        // no next header
        if (*nxt_hdr == 59) {
            return (1);
        }
        // fragment extension header has fixed size of 8 bytes and the first byte is the next header type
        if (*nxt_hdr == 44) {
            if (*l4len < 8) {
                return (1);
            }
            *nxt_hdr = (*l4ptr)[0];
            *l4len -= 8;
            (*l4ptr) += 8;
            continue;
        }
        // the other extension headers have one byte for the next header type
        // and one byte for the extension header length in 8 byte steps minus the first 8 bytes
        if (*l4len < 2) {
            return (1);
        }
        ehdr_len = (*l4ptr)[1];
        ehdr_len *= 8;
        ehdr_len += 8;

        if (*l4len < ehdr_len) {
            return (1);
        }
        *nxt_hdr = (*l4ptr)[0];
        *l4len -= ehdr_len;
        (*l4ptr) += ehdr_len;
    }
    return (0);
}


/**
 * get_nf_packet_info: Build nf_packet structure.
 */
int get_nf_packet_info(const uint8_t version,
                       uint16_t vlan_id,
                       nfstream_packet_tunnel tunnel_type,
                       const struct nfstream_iphdr *iph,
                       const struct nfstream_ipv6hdr *iph6,
                       uint16_t ip_offset,
                       uint16_t ipsize,
                       uint16_t l4_packet_len,
                       struct nfstream_tcphdr **tcph,
                       struct nfstream_udphdr **udph,
                       uint16_t *sport, uint16_t *dport,
                       uint8_t *proto,
                       uint8_t **payload,
                       uint16_t *payload_len,
                       struct timeval when, struct nf_packet *nf_pkt, int n_roots, int root_idx) {
  uint32_t l4_offset;
  const uint8_t *l3, *l4;
  uint32_t l4_data_len = 0XFEEDFACE;

  if(version == IPVERSION) {
    if(ipsize < 20) {
      return 0;
    }


    if((iph->ihl * 4) > ipsize) {
         return 0;
       }

    l4_offset = iph->ihl * 4;
    l3 = (const uint8_t*)iph;
  } else {
    l4_offset = sizeof(struct nfstream_ipv6hdr);
    if(sizeof(struct nfstream_ipv6hdr) > ipsize) {
      return 0;
    }


    l3 = (const uint8_t*)iph6;
  }
  if(nfstream_max(ntohs(iph->tot_len) , ipsize)< l4_offset + l4_packet_len) {
    return 0;
  }


  *proto = iph->protocol;

  l4 =& ((const uint8_t *) l3)[l4_offset];

  if(*proto == IPPROTO_TCP && l4_packet_len >= sizeof(struct nfstream_tcphdr)) {
    unsigned tcp_len;
    *tcph = (struct nfstream_tcphdr *)l4;
    *sport = (*tcph)->source, *dport = (*tcph)->dest;
    tcp_len = nfstream_min(4*(*tcph)->doff, l4_packet_len);
    *payload = (uint8_t*)&l4[tcp_len];
    *payload_len = nfstream_max(0, l4_packet_len-4*(*tcph)->doff);
    l4_data_len = l4_packet_len - sizeof(struct nfstream_tcphdr);
    nf_pkt->fin = (*tcph)->fin;
    nf_pkt->syn = (*tcph)->syn;
    nf_pkt->rst = (*tcph)->rst;
    nf_pkt->psh = (*tcph)->psh;
    nf_pkt->ack = (*tcph)->ack;
    nf_pkt->urg = (*tcph)->urg;
    nf_pkt->ece = (*tcph)->ece;
    nf_pkt->cwr = (*tcph)->cwr;
  } else if(*proto == IPPROTO_UDP && l4_packet_len >= sizeof(struct nfstream_udphdr)) {
    *udph = (struct nfstream_udphdr *)l4;
    *sport = (*udph)->source, *dport = (*udph)->dest;
    *payload = (uint8_t*)&l4[sizeof(struct nfstream_udphdr)];
    *payload_len = (l4_packet_len > sizeof(struct nfstream_udphdr)) ? l4_packet_len-sizeof(struct nfstream_udphdr) : 0;
    l4_data_len = l4_packet_len - sizeof(struct nfstream_udphdr);
    nf_pkt->fin = nf_pkt->syn = nf_pkt->rst = nf_pkt->psh = nf_pkt->ack = nf_pkt->urg = nf_pkt->ece = nf_pkt->cwr = 0;
  } else if(*proto == IPPROTO_ICMP) {
    *payload = (uint8_t*)&l4[sizeof(struct nfstream_icmphdr )];
    *payload_len = (l4_packet_len > sizeof(struct nfstream_icmphdr)) ? l4_packet_len-sizeof(struct nfstream_icmphdr) : 0;
    l4_data_len = l4_packet_len - sizeof(struct nfstream_icmphdr);
    *sport = *dport = 0;
    nf_pkt->fin = nf_pkt->syn = nf_pkt->rst = nf_pkt->psh = nf_pkt->ack = nf_pkt->urg = nf_pkt->ece = nf_pkt->cwr = 0;
  } else if(*proto == IPPROTO_ICMPV6) {
    *payload = (uint8_t*)&l4[sizeof(struct nfstream_icmp6hdr)];
    *payload_len = (l4_packet_len > sizeof(struct nfstream_icmp6hdr)) ? l4_packet_len-sizeof(struct nfstream_icmp6hdr) : 0;
    l4_data_len = l4_packet_len - sizeof(struct nfstream_icmp6hdr);
    *sport = *dport = 0;
    nf_pkt->fin = nf_pkt->syn = nf_pkt->rst = nf_pkt->psh = nf_pkt->ack = nf_pkt->urg = nf_pkt->ece = nf_pkt->cwr = 0;
  } else {
    // non tcp/udp protocols
    *sport = *dport = 0;
    l4_data_len = 0;
    nf_pkt->fin = nf_pkt->syn = nf_pkt->rst = nf_pkt->psh = nf_pkt->ack = nf_pkt->urg = nf_pkt->ece = nf_pkt->cwr = 0;
  }

  nf_pkt->protocol = iph->protocol;
  nf_pkt->vlan_id = vlan_id;
  nf_pkt->src_port = htons(*sport);
  nf_pkt->dst_port = htons(*dport);
  nf_pkt->ip_version = version;
  nf_pkt->transport_size = l4_data_len;
  nf_pkt->payload_size = *payload_len;
  nf_pkt->ip_content_len = ipsize;
  uint64_t hashval = 0;
  hashval = nf_pkt->protocol + nf_pkt->vlan_id + iph->saddr + iph->daddr + nf_pkt->src_port + nf_pkt->dst_port;

  if(version == IPVERSION) {
	inet_ntop(AF_INET, &iph->saddr, nf_pkt->src_name, sizeof(nf_pkt->src_name));
	inet_ntop(AF_INET, &iph->daddr, nf_pkt->dst_name, sizeof(nf_pkt->dst_name));
	nf_pkt->ip_size= ntohs(iph->tot_len);
	nf_pkt->ip_content = (uint8_t *)iph;
  } else {
	inet_ntop(AF_INET6, &iph6->ip6_src, nf_pkt->src_name, sizeof(nf_pkt->src_name));
	inet_ntop(AF_INET6, &iph6->ip6_dst, nf_pkt->dst_name, sizeof(nf_pkt->dst_name));
	nf_pkt->ip_size = ntohs(iph->tot_len);
	nf_pkt->ip_content = (uint8_t *)iph6;
  }
  if ((hashval % n_roots) == root_idx) {
      return 1;
  } else {
     return 2;
  }
}


/**
 * get_nf_packet_info6: Convert IPv6 headers to IPv4.
 */
static int get_nf_packet_info6(uint16_t vlan_id,
                               nfstream_packet_tunnel tunnel_type,
                               const struct nfstream_ipv6hdr *iph6,
                               uint16_t ip_offset,
                               uint16_t ipsize,
                               struct nfstream_tcphdr **tcph,
                               struct nfstream_udphdr **udph,
                               uint16_t *sport, uint16_t *dport,
                               uint8_t *proto,
                               uint8_t **payload,
                               uint16_t *payload_len,
                               struct timeval when, struct nf_packet *nf_pkt, int n_roots, int root_idx) {
  struct nfstream_iphdr iph;
  memset(&iph, 0, sizeof(iph));
  iph.version = IPVERSION;
  iph.saddr = iph6->ip6_src.u6_addr.u6_addr32[2] + iph6->ip6_src.u6_addr.u6_addr32[3];
  iph.daddr = iph6->ip6_dst.u6_addr.u6_addr32[2] + iph6->ip6_dst.u6_addr.u6_addr32[3];
  uint8_t l4proto = iph6->ip6_hdr.ip6_un1_nxt;
  uint16_t ip_len = ntohs(iph6->ip6_hdr.ip6_un1_plen);
  const uint8_t *l4ptr = (((const uint8_t *) iph6) + sizeof(struct nfstream_ipv6hdr));
  if(nfstream_handle_ipv6_extension_headers(&l4ptr, &ip_len, &l4proto) != 0) {
    return 0;
  }
  iph.protocol = l4proto;
  iph.tot_len = iph6->ip6_hdr.ip6_un1_plen;
  return(get_nf_packet_info(6, vlan_id, tunnel_type,
			    &iph, iph6, ip_offset, ipsize,
			    ntohs(iph6->ip6_hdr.ip6_un1_plen),
			    tcph, udph, sport, dport, proto, payload,
			    payload_len, when, nf_pkt, n_roots, root_idx));
}


/**
 * process_packet: Packet information parsing function..
 */
int parse_packet(const uint64_t time,
                 uint16_t vlan_id,
                 nfstream_packet_tunnel tunnel_type,
                 const struct nfstream_iphdr *iph,
                 struct nfstream_ipv6hdr *iph6,
                 uint16_t ip_offset,
                 uint16_t ipsize,
                 uint16_t rawsize,
                 const struct pcap_pkthdr *header,
                 const uint8_t *packet,
                 struct timeval when,
                 struct nf_packet *nf_pkt,
                 int n_roots,
                 int root_idx) {
  uint8_t proto;
  struct nfstream_tcphdr *tcph = NULL;
  struct nfstream_udphdr *udph = NULL;
  uint16_t sport, dport, payload_len = 0;
  uint8_t *payload;
  nf_pkt->direction = 0;
  nf_pkt->time = time;
  nf_pkt->raw_size = rawsize;

  if(iph)
    return get_nf_packet_info(IPVERSION, vlan_id, tunnel_type, iph, NULL, ip_offset, ipsize, ntohs(iph->tot_len) - (iph->ihl * 4),
			      &tcph, &udph, &sport, &dport, &proto, &payload, &payload_len, when, nf_pkt, n_roots, root_idx);
  else
    return get_nf_packet_info6(vlan_id, tunnel_type, iph6, ip_offset, ipsize, &tcph, &udph, &sport, &dport, &proto,
                        &payload, &payload_len, when, nf_pkt, n_roots, root_idx);
}


/**
 * process_packet: Main packet processing function.
 */
int process_packet(pcap_t * pcap_handle, const struct pcap_pkthdr *header, const uint8_t *packet, int decode_tunnels,
                   struct nf_packet *nf_pkt, int n_roots, int root_idx) {
  /* --- Ethernet header --- */
  const struct nfstream_ethhdr *ethernet;
  /* --- LLC header --- */
  const struct nfstream_llc_header_snap *llc;
  /* --- Cisco HDLC header --- */
  const struct nfstream_chdlc *chdlc;
  /* --- Radio Tap header --- */
  const struct nfstream_radiotap_header *radiotap;
  /* --- Wifi header --- */
  const struct nfstream_wifi_header *wifi;
  /* --- MPLS header --- */
  union mpls {
    uint32_t u32;
    struct nfstream_mpls_header mpls;
  } mpls;
  /** --- IP header --- **/
  struct nfstream_iphdr *iph;
  /** --- IPv6 header --- **/
  struct nfstream_ipv6hdr *iph6;
  nfstream_packet_tunnel tunnel_type = nfstream_no_tunnel;
  /* lengths and offsets */
  uint16_t eth_offset = 0;
  uint16_t radio_len;
  uint16_t fc;
  uint16_t type = 0;
  int wifi_len = 0;
  int pyld_eth_len = 0;
  int check;
  uint64_t time;
  uint16_t ip_offset = 0, ip_len;
  uint16_t frag_off = 0, vlan_id = 0;
  uint8_t proto = 0, recheck_type;

  /* setting time */
  time = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);

  /*** check Data Link type ***/
  int datalink_type;
  datalink_type = (int)pcap_datalink(pcap_handle);


 datalink_check:
  if(header->caplen < eth_offset + 40) {
    return 0;
  }
  switch(datalink_type) {
  case DLT_NULL:
    if(ntohl(*((uint32_t*)&packet[eth_offset])) == 2)
      type = ETH_P_IP;
    else
      type = ETH_P_IPV6;

    ip_offset = 4 + eth_offset;
    break;

    /* Cisco PPP in HDLC-like framing - 50 */
  case DLT_PPP_SERIAL:
    chdlc = (struct nfstream_chdlc *) &packet[eth_offset];
    ip_offset = sizeof(struct nfstream_chdlc); /* CHDLC_OFF = 4 */
    type = ntohs(chdlc->proto_code);
    break;

    /* Cisco PPP - 9 or 104 */
  case DLT_C_HDLC:
  case DLT_PPP:
    chdlc = (struct nfstream_chdlc *) &packet[eth_offset];
    ip_offset = sizeof(struct nfstream_chdlc); /* CHDLC_OFF = 4 */
    type = ntohs(chdlc->proto_code);
    break;

    /* IEEE 802.3 Ethernet - 1 */
  case DLT_EN10MB:
    ethernet = (struct nfstream_ethhdr *) &packet[eth_offset];
    ip_offset = sizeof(struct nfstream_ethhdr) + eth_offset;
    check = ntohs(ethernet->h_proto);

    if(check <= 1500)
      pyld_eth_len = check;
    else if(check >= 1536)
      type = check;

    if(pyld_eth_len != 0) {
      llc = (struct nfstream_llc_header_snap *)(&packet[ip_offset]);
      /* check for LLC layer with SNAP extension */
      if(llc->dsap == SNAP || llc->ssap == SNAP) {
	type = llc->snap.proto_ID;
	ip_offset += + 8;
      }
      /* No SNAP extension - Spanning Tree pkt must be discarted */
      else if(llc->dsap == BSTP || llc->ssap == BSTP) {
	goto v4_warning;
      }
    }
    break;

    /* Linux Cooked Capture - 113 */
  case DLT_LINUX_SLL:
    type = (packet[eth_offset+14] << 8) + packet[eth_offset+15];
    ip_offset = 16 + eth_offset;
    break;

    /* Radiotap link-layer - 127 */
  case DLT_IEEE802_11_RADIO:
    radiotap = (struct nfstream_radiotap_header *) &packet[eth_offset];
    radio_len = radiotap->len;

    /* Check Bad FCS presence */
    if((radiotap->flags & BAD_FCS) == BAD_FCS) {
      return 0;
    }

    if(header->caplen < (eth_offset + radio_len + sizeof(struct nfstream_wifi_header))) {
      return 0;
    }

    /* Calculate 802.11 header length (variable) */
    wifi = (struct nfstream_wifi_header*)( packet + eth_offset + radio_len);
    fc = wifi->fc;

    /* check wifi data presence */
    if(FCF_TYPE(fc) == WIFI_DATA) {
      if((FCF_TO_DS(fc) && FCF_FROM_DS(fc) == 0x0) ||
	 (FCF_TO_DS(fc) == 0x0 && FCF_FROM_DS(fc)))
	wifi_len = 26; /* + 4 byte fcs */
    } else   /* no data frames */
      break;

    /* Check ether_type from LLC */
    if(header->caplen < (eth_offset + wifi_len + radio_len + sizeof(struct nfstream_llc_header_snap))) {
      return 0;
    }
    llc = (struct nfstream_llc_header_snap*)(packet + eth_offset + wifi_len + radio_len);
    if(llc->dsap == SNAP)
      type = ntohs(llc->snap.proto_ID);

    /* Set IP header offset */
    ip_offset = wifi_len + radio_len + sizeof(struct nfstream_llc_header_snap) + eth_offset;
    break;

  case DLT_RAW:
    ip_offset = eth_offset = 0;
    break;

  default:
    return 0;
  }

 ether_type_check:
  recheck_type = 0;

  /* check ether type */
  switch(type) {
  case VLAN:
    vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
    type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
    ip_offset += 4;

    // double tagging for 802.1Q
    while((type == 0x8100) && (((bpf_u_int32)ip_offset) < header->caplen)) {
      vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
      type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
      ip_offset += 4;
    }
    recheck_type = 1;
    break;

  case MPLS_UNI:
  case MPLS_MULTI:
    mpls.u32 = *((uint32_t *) &packet[ip_offset]);
    mpls.u32 = ntohl(mpls.u32);
    type = ETH_P_IP, ip_offset += 4;

    while(!mpls.mpls.s && (((bpf_u_int32)ip_offset) + 4 < header->caplen)) {
      mpls.u32 = *((uint32_t *) &packet[ip_offset]);
      mpls.u32 = ntohl(mpls.u32);
      ip_offset += 4;
    }
    recheck_type = 1;
    break;

  case PPPoE:
    type = ETH_P_IP;
    ip_offset += 8;
    recheck_type = 1;
    break;

  default:
    break;
  }

  if(recheck_type)
    goto ether_type_check;


 iph_check:
  /* Check and set IP header size and total packet length */
  if(header->caplen < ip_offset + sizeof(struct nfstream_iphdr)) {
    return 0;
  }

  iph = (struct nfstream_iphdr *) &packet[ip_offset];

  /* just work on Ethernet packets that contain IP */
  if(type == ETH_P_IP && header->caplen >= ip_offset) {
    frag_off = ntohs(iph->frag_off);

    proto = iph->protocol;
  }

  if(iph->version == IPVERSION) {
    ip_len = ((uint16_t)iph->ihl * 4);
    iph6 = NULL;

    if(iph->protocol == IPPROTO_IPV6 || iph->protocol == IPPROTO_IPIP) {
      ip_offset += ip_len;
      if(ip_len > 0)
        goto iph_check;
    }

    if((frag_off & 0x1FFF) != 0) {
      return 0;
    }
  } else if(iph->version == 6) {
    if(header->caplen < ip_offset + sizeof(struct nfstream_ipv6hdr)) {
      return 0;
    }
    iph6 = (struct nfstream_ipv6hdr *)&packet[ip_offset];
    proto = iph6->ip6_hdr.ip6_un1_nxt;
    ip_len = ntohs(iph6->ip6_hdr.ip6_un1_plen);
    if(header->caplen < (ip_offset + sizeof(struct nfstream_ipv6hdr) + ntohs(iph6->ip6_hdr.ip6_un1_plen))) {
      return 0;
    }

    const uint8_t *l4ptr = (((const uint8_t *) iph6) + sizeof(struct nfstream_ipv6hdr));
    if(nfstream_handle_ipv6_extension_headers(&l4ptr, &ip_len, &proto) != 0) {
      return 0;
    }
    if(proto == IPPROTO_IPV6 || proto == IPPROTO_IPIP) {
      if(l4ptr > packet) { /* Better safe than sorry */
        ip_offset = (l4ptr - packet);
        goto iph_check;
      }
    }

    iph = NULL;
  } else {
  v4_warning:
    return 0;
  }

  if(decode_tunnels && (proto == IPPROTO_UDP)) {
    if(header->caplen < ip_offset + ip_len + sizeof(struct nfstream_udphdr)) {
      return 0;/* Too short for UDP header*/
    } else {
      struct nfstream_udphdr *udp = (struct nfstream_udphdr *)&packet[ip_offset+ip_len];
      uint16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

      if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
	/* Check if it's GTPv1 */
	unsigned offset = ip_offset+ip_len+sizeof(struct nfstream_udphdr);
	uint8_t flags = packet[offset];
	uint8_t message_type = packet[offset+1];

	tunnel_type = nfstream_gtp_tunnel;

	if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) &&
	   (message_type == 0xFF /* T-PDU */)) {

	  ip_offset = ip_offset+ip_len+sizeof(struct nfstream_udphdr)+8; /* GTPv1 header len */
	  if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
	  if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
	  if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

	  if(ip_offset < header->caplen) {
	    iph = (struct nfstream_iphdr *)&packet[ip_offset];
	    if(iph->version == 6) {
	      iph6 = (struct nfstream_ipv6hdr *)&packet[ip_offset];
	      iph = NULL;
	    } else if(iph->version != IPVERSION) {
	      goto v4_warning;
	    }
	  }
	}
      } else if((sport == TZSP_PORT) || (dport == TZSP_PORT)) {
	/* https://en.wikipedia.org/wiki/TZSP */
	if(header->caplen < ip_offset + ip_len + sizeof(struct nfstream_udphdr) + 4) {
      return 0;
	}

	unsigned offset           = ip_offset+ip_len+sizeof(struct nfstream_udphdr);
	uint8_t version       = packet[offset];
	uint8_t ts_type       = packet[offset+1];
	uint16_t encapsulates = ntohs(*((uint16_t*)&packet[offset+2]));

	tunnel_type = nfstream_tzsp_tunnel;

	if((version == 1) && (ts_type == 0) && (encapsulates == 1)) {
	  uint8_t stop = 0;

	  offset += 4;

	  while((!stop) && (offset < header->caplen)) {
	    uint8_t tag_type = packet[offset];
	    uint8_t tag_len;

	    switch(tag_type) {
	    case 0: /* PADDING Tag */
	      tag_len = 1;
	      break;
	    case 1: /* END Tag */
	      tag_len = 1, stop = 1;
	      break;
	    default:
	      tag_len = packet[offset+1];
	      break;
	    }

	    offset += tag_len;

	    if(offset >= header->caplen) {
          return 0;
	    }
	    else {
	      eth_offset = offset;
	      goto datalink_check;
	    }
	  }
	}
      } else if(sport == NFSTREAM_CAPWAP_DATA_PORT) {
	/* We dissect ONLY CAPWAP traffic */
	unsigned offset           = ip_offset+ip_len+sizeof(struct nfstream_udphdr);

	if((offset+1) < header->caplen) {
	  uint8_t preamble = packet[offset];

	  if((preamble & 0x0F) == 0) { /* CAPWAP header */
	    uint16_t msg_len = (packet[offset+1] & 0xF8) >> 1;

	    offset += msg_len;

	    if((offset + 32 < header->caplen) && (packet[offset] == 0x02)) {
	      /* IEEE 802.11 Data */

	      offset += 24;
	      /* LLC header is 8 bytes */
	      type = ntohs((uint16_t)*((uint16_t*)&packet[offset+6]));

	      ip_offset = offset + 8;

	      tunnel_type = nfstream_capwap_tunnel;
	      goto iph_check;
	    }
	  }
	}
      }
    }
  }
  return parse_packet(time, vlan_id, tunnel_type, iph, iph6, ip_offset, header->caplen - ip_offset, header->len,
                      header, packet, header->ts, nf_pkt, n_roots, root_idx);
}


/**
 * observer_open: Open a pcap file or a specified device.
 */
pcap_t * observer_open(const uint8_t * pcap_file, unsigned snaplen, int promisc, char *err_open, char *err_set, int mode) {
  pcap_t * pcap_handle = NULL;
  int set = 0;
  if (mode == 0) {
    pcap_handle = pcap_open_offline((char*)pcap_file, err_open);
  }
  if (mode == 1) {
    pcap_handle = pcap_open_live((char*)pcap_file, snaplen, promisc, 1000, err_open);
    if (pcap_handle != NULL) set = pcap_setnonblock(pcap_handle, 1, err_set);
  }
  if (set == 0) {
    return pcap_handle;
  } else {
    pcap_close(pcap_handle);
    return NULL;
  }
}


/**
 * observer_configure: Configure pcap_t with specified bpf_filter.
 */
int observer_configure(pcap_t * pcap_handle, char * bpf_filter) {
  if(bpf_filter != NULL) {
    struct bpf_program fcode;
    if(pcap_compile(pcap_handle, &fcode, bpf_filter, 1, 0xFFFFFF00) < 0) {
      return 1;
    } else {
      if(pcap_setfilter(pcap_handle, &fcode) < 0) {
	return 2;
      } else
	return 0;
    }
  }
  else {
    return 0;
  }
}

/**
 * observer_next: Get next packet informations from pcap handle.
 */
int observer_next(pcap_t * pcap_handle, struct nf_packet *nf_pkt, int decode_tunnels, int n_roots, int root_idx) {
  struct pcap_pkthdr *hdr;
  const uint8_t *data;
  int rv_handle = pcap_next_ex(pcap_handle, &hdr, &data);
  if (rv_handle == 1) {
    int rv_processor = process_packet(pcap_handle, hdr, data, decode_tunnels, nf_pkt, n_roots, root_idx);
    if (rv_processor == 0) {
        return 0; // Packet ignored due to parsing
    } else if (rv_processor == 1) { // Packet parsed correctly and match root_idx
        return 1;
    } else { // Packet parsed correctly and do not match root_idx, will use it as time ticker
        return 2;
    }
  } else {
    if (rv_handle == 0) { // Buffer timeout, fill packet as ticker.
        struct timeval tick;
        gettimeofday(&tick, NULL);
        nf_pkt->time = ((uint64_t) tick.tv_sec) * TICK_RESOLUTION + tick.tv_usec / (1000000 / TICK_RESOLUTION);
        return 3;
    }
    if (rv_handle == -2) {
        return -2; // End of file
    }
  }
  return -1;
}


/**
 * observer_close: Close observer handle.
 */
void observer_close(pcap_t * pcap_handle) {
  pcap_breakloop(pcap_handle);
  pcap_close(pcap_handle);
}
/*
------------------------------------------------------------------------------------------------------------------------
                                           Dissector Layer
------------------------------------------------------------------------------------------------------------------------
*/


typedef struct dissector_checker {
uint32_t flow_size;
uint32_t id_size;
uint32_t flow_tcp_size;
uint32_t flow_udp_size;
} dissector_checker_t;

/**
 * dissector_init: Dissector initializer.
 */
struct ndpi_detection_module_struct *dissector_init(struct dissector_checker *checker) {
  ndpi_init_prefs init_prefs = ndpi_no_prefs;
  if (checker->flow_size != ndpi_detection_get_sizeof_ndpi_flow_struct()) return NULL;
  if (checker->id_size != ndpi_detection_get_sizeof_ndpi_id_struct()) return NULL;
  if (checker->flow_tcp_size != ndpi_detection_get_sizeof_ndpi_flow_tcp_struct()) return NULL;
  if (checker->flow_udp_size != ndpi_detection_get_sizeof_ndpi_flow_udp_struct()) return NULL;
  return ndpi_init_detection_module(init_prefs);
}

/**
 * dissector_configure: Dissector initializer.
 */
void dissector_configure(struct ndpi_detection_module_struct *dissector) {
    if (dissector == NULL) {
      return;
    } else {
      NDPI_PROTOCOL_BITMASK protos;
      NDPI_BITMASK_SET_ALL(protos);
      ndpi_set_protocol_detection_bitmask2(dissector, &protos);
      ndpi_finalize_initalization(dissector);
    }
}

/**
 * dissector_cleanup: Dissector cleaner.
 */
void dissector_cleanup(struct ndpi_detection_module_struct *dissector) {
  if (dissector == NULL) return;
  else return ndpi_exit_detection_module(dissector);
}


/*
------------------------------------------------------------------------------------------------------------------------
                                           Meter Layer
------------------------------------------------------------------------------------------------------------------------
*/

typedef struct nf_entry {
  char src_ip[48];
  uint16_t src_port;
  char dst_ip[48];
  uint16_t dst_port;
  uint8_t protocol;
  uint8_t ip_version;
  uint16_t vlan_id;
  uint64_t bidirectional_first_seen_ms;
  uint64_t bidirectional_last_seen_ms;
  uint64_t bidirectional_duration_ms;
  uint64_t bidirectional_packets;
  uint64_t bidirectional_bytes;
  uint64_t src2dst_first_seen_ms;
  uint64_t src2dst_last_seen_ms;
  uint64_t src2dst_duration_ms;
  uint64_t src2dst_packets;
  uint64_t src2dst_bytes;
  uint64_t dst2src_first_seen_ms;
  uint64_t dst2src_last_seen_ms;
  uint64_t dst2src_duration_ms;
  uint64_t dst2src_packets;
  uint64_t dst2src_bytes;
  uint16_t bidirectional_min_ps;
  double bidirectional_mean_ps;
  double bidirectional_stddev_ps;
  uint16_t bidirectional_max_ps;
  uint16_t src2dst_min_ps;
  double src2dst_mean_ps;
  double src2dst_stddev_ps;
  uint16_t src2dst_max_ps;
  uint16_t dst2src_min_ps;
  double dst2src_mean_ps;
  double dst2src_stddev_ps;
  uint16_t dst2src_max_ps;
  uint64_t bidirectional_min_piat_ms;
  double bidirectional_mean_piat_ms;
  double bidirectional_stddev_piat_ms;
  uint64_t bidirectional_max_piat_ms;
  uint64_t src2dst_min_piat_ms;
  double src2dst_mean_piat_ms;
  double src2dst_stddev_piat_ms;
  uint64_t src2dst_max_piat_ms;
  uint64_t dst2src_min_piat_ms;
  double dst2src_mean_piat_ms;
  double dst2src_stddev_piat_ms;
  uint64_t dst2src_max_piat_ms;
  uint64_t bidirectional_syn_packets;
  uint64_t bidirectional_cwr_packets;
  uint64_t bidirectional_ece_packets;
  uint64_t bidirectional_urg_packets;
  uint64_t bidirectional_ack_packets;
  uint64_t bidirectional_psh_packets;
  uint64_t bidirectional_rst_packets;
  uint64_t bidirectional_fin_packets;
  uint64_t src2dst_syn_packets;
  uint64_t src2dst_cwr_packets;
  uint64_t src2dst_ece_packets;
  uint64_t src2dst_urg_packets;
  uint64_t src2dst_ack_packets;
  uint64_t src2dst_psh_packets;
  uint64_t src2dst_rst_packets;
  uint64_t src2dst_fin_packets;
  uint64_t dst2src_syn_packets;
  uint64_t dst2src_cwr_packets;
  uint64_t dst2src_ece_packets;
  uint64_t dst2src_urg_packets;
  uint64_t dst2src_ack_packets;
  uint64_t dst2src_psh_packets;
  uint64_t dst2src_rst_packets;
  uint64_t dst2src_fin_packets;
  char application_name[32];
  char category_name[24];
  char requested_server_name[240];
  char c_hash[48];
  char s_hash[48];
  char content_type[64];
  char user_agent[128];
  struct ndpi_flow_struct *ndpi_flow;
  struct ndpi_id_struct *ndpi_src;
  struct ndpi_id_struct *ndpi_dst;
  ndpi_protocol detected_protocol;
  uint8_t guessed;
  uint8_t detection_completed;
} nf_entry_t;


/**
 * meter_account_packet: Return packet_size according to configured accounting mode.
 */
uint16_t meter_account_packet(struct nf_packet *packet, uint8_t accounting_mode) {
  if (accounting_mode == 0) return packet->raw_size;
  else if (accounting_mode == 1) return packet->ip_size;
  else if (accounting_mode == 2) return packet->transport_size;
  else return packet->payload_size;
}

uint8_t is_ndpi_proto(struct nf_entry *entry, uint16_t id) {
  if ((entry->detected_protocol.master_protocol == id)|| (entry->detected_protocol.app_protocol == id)) return 1;
  else return 0;
}

void dissector_process_info(struct ndpi_detection_module_struct *dissector, struct nf_entry *entry) {
  if (!entry->ndpi_flow) return;
  ndpi_protocol2name(dissector, entry->detected_protocol, entry->application_name, sizeof(entry->application_name));
  memcpy(entry->category_name, ndpi_category_get_name(dissector, entry->detected_protocol.category), 24);
  snprintf(entry->requested_server_name, sizeof(entry->requested_server_name), "%s", entry->ndpi_flow->host_server_name);
  /* DHCP */
  if (is_ndpi_proto(entry, NDPI_PROTOCOL_DHCP)) {
    snprintf(entry->c_hash, sizeof(entry->c_hash), "%s", entry->ndpi_flow->protos.dhcp.fingerprint);
  }
  /* HTTP */
  else if (is_ndpi_proto(entry, NDPI_PROTOCOL_HTTP)) {
      snprintf(entry->content_type, sizeof(entry->content_type), "%s",
               entry->ndpi_flow->http.content_type ? entry->ndpi_flow->http.content_type : "");
      snprintf(entry->user_agent, sizeof(entry->user_agent), "%s",
               entry->ndpi_flow->http.user_agent ? entry->ndpi_flow->http.user_agent : "");
  /* SSH */
  } else if (is_ndpi_proto(entry, NDPI_PROTOCOL_SSH)) {
    snprintf(entry->c_hash, sizeof(entry->c_hash), "%s", entry->ndpi_flow->protos.ssh.hassh_client);
    snprintf(entry->s_hash, sizeof(entry->s_hash), "%s", entry->ndpi_flow->protos.ssh.hassh_server);
  }
  /* TLS */
  else if ((is_ndpi_proto(entry, NDPI_PROTOCOL_TLS)) || (entry->ndpi_flow->protos.stun_ssl.ssl.ja3_client[0] != '\0')) {
    snprintf(entry->requested_server_name, sizeof(entry->requested_server_name), "%s",
             entry->ndpi_flow->protos.stun_ssl.ssl.client_requested_server_name);
    snprintf(entry->c_hash, sizeof(entry->c_hash), "%s",
             entry->ndpi_flow->protos.stun_ssl.ssl.ja3_client);
    snprintf(entry->s_hash, sizeof(entry->s_hash), "%s",
             entry->ndpi_flow->protos.stun_ssl.ssl.ja3_server);
  }
}


void free_ndpi_data(struct nf_entry *entry) {
  if(entry->ndpi_flow) { ndpi_flow_free(entry->ndpi_flow); entry->ndpi_flow = NULL; }
  if(entry->ndpi_src) { ndpi_free(entry->ndpi_src); entry->ndpi_src = NULL; }
  if(entry->ndpi_dst) { ndpi_free(entry->ndpi_dst); entry->ndpi_dst = NULL; }
}


/**
 * meter_initialize_entry: Initialize entry based on packet values and set packet direction.
 */
struct nf_entry *meter_initialize_entry(struct nf_packet *packet, uint8_t accounting_mode,
                                        uint8_t statistics, uint8_t dissect, uint64_t max_tcp_dissections,
                                        uint64_t max_udp_dissections, uint8_t enable_guess,
                                        struct ndpi_detection_module_struct *dissector) {

  struct nf_entry *entry = (struct nf_entry*)ndpi_malloc(sizeof(struct nf_entry));
  if(entry == NULL) return NULL;
  memset(entry, 0, sizeof(struct nf_entry));

  if (dissect == 1) {
    entry->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);

    if (entry->ndpi_flow == NULL) {
      ndpi_free(entry);
      return NULL;
    } else {
      memset(entry->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
    }
    entry->ndpi_src = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
    if (entry->ndpi_src == NULL)  {
      ndpi_free(entry);
      return NULL;
    }
    entry->ndpi_dst = (struct ndpi_id_struct *)ndpi_calloc(1, SIZEOF_ID_STRUCT);
    if (entry->ndpi_dst == NULL) {
      ndpi_free(entry);
      return NULL;
    }
    entry->detected_protocol = ndpi_detection_process_packet(dissector,
                                                             entry->ndpi_flow,
                                                             packet->ip_content,
                                                             packet->ip_content_len,
                                                             packet->time,
                                                             entry->ndpi_src,
                                                             entry->ndpi_dst);
    dissector_process_info(dissector, entry);
    uint8_t tcp_stop = (packet->protocol == 6) && (max_tcp_dissections == 1);
    uint8_t udp_stop = (packet->protocol == 17) && (max_udp_dissections == 1);
    if ((entry->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) && (tcp_stop || udp_stop)) {
      // not identified and we are limited to 1, we try to guess.
      entry->detected_protocol = ndpi_detection_giveup(dissector,
                                                       entry->ndpi_flow,
                                                       enable_guess,
                                                       &entry->guessed);
      dissector_process_info(dissector, entry);
      entry->detection_completed = 1;
      free_ndpi_data(entry);
    } else {
      dissector_process_info(dissector, entry);
    }
  }
  entry->bidirectional_first_seen_ms = packet->time;
  entry->bidirectional_last_seen_ms = packet->time;
  entry->src2dst_first_seen_ms = packet->time;
  entry->src2dst_last_seen_ms = packet->time;
  memcpy(entry->src_ip, packet->src_name, 48);
  entry->src_port = packet->src_port;
  memcpy(entry->dst_ip, packet->dst_name, 48);
  entry->dst_port = packet->dst_port;
  entry->protocol = packet->protocol;
  entry->ip_version = packet->ip_version;
  entry->vlan_id = packet->vlan_id;
  entry->bidirectional_packets = 1;
  entry->src2dst_packets = 1;
  uint16_t packet_size = meter_account_packet(packet, accounting_mode);

  // Already zero. (https://cffi.readthedocs.io/en/latest/using.html#working-with-pointers-structures-and-arrays)
  entry->bidirectional_bytes += packet_size;
  entry->src2dst_bytes += packet_size;
  if (statistics == 1) {
    entry->bidirectional_min_ps += packet_size;
    entry->bidirectional_mean_ps += packet_size;
    entry->bidirectional_max_ps += packet_size;
    entry->src2dst_min_ps += packet_size;
    entry->src2dst_mean_ps += packet_size;
    entry->src2dst_max_ps += packet_size;
    if (packet->syn) {
      entry->bidirectional_syn_packets++;
      entry->src2dst_syn_packets++;
    }
    if (packet->cwr) {
      entry->bidirectional_cwr_packets++;
      entry->src2dst_cwr_packets++;
    }
    if (packet->ece) {
      entry->bidirectional_ece_packets++;
      entry->src2dst_ece_packets++;
    }
    if (packet->urg) {
      entry->bidirectional_urg_packets++;
      entry->src2dst_urg_packets++;
    }
    if (packet->ack) {
      entry->bidirectional_ack_packets++;
      entry->src2dst_ack_packets++;
    }
    if (packet->psh) {
      entry->bidirectional_psh_packets++;
      entry->src2dst_psh_packets++;
    }
    if (packet->rst) {
      entry->bidirectional_rst_packets++;
      entry->src2dst_rst_packets++;
    }
    if (packet->fin) {
      entry->bidirectional_fin_packets++;
      entry->src2dst_fin_packets++;
    }
  }
  return entry;
}

/**
 * meter_update_entry: Check expiration state, and update entry based on packet values if case of active one.
 */
uint8_t meter_update_entry(struct nf_entry *entry, struct nf_packet *packet, uint64_t idle_timeout,
                           uint64_t active_timeout, uint8_t accounting_mode, uint8_t statistics, uint8_t dissect,
                           uint64_t max_tcp_dissections, uint64_t max_udp_dissections, uint8_t enable_guess,
                           struct ndpi_detection_module_struct *dissector) {
  if ((packet->time - entry->bidirectional_last_seen_ms) >= idle_timeout) {
    return 1; // Inactive expiration
  }
  if ((packet->time - entry->bidirectional_first_seen_ms) >= active_timeout) {
    return 2; // active expiration
  }

  // We first check ports to determine direction.
  if ((entry->src_port != packet->src_port) || (entry->src_port != packet->src_port)) {
    packet->direction = 1;
  // Then IPs
  } else {
    if ((memcmp(entry->src_ip, packet->src_name, 48) != 0) || (memcmp(entry->dst_ip, packet->dst_name, 48) != 0)) {
      packet->direction = 1;
    }
  }
  // --------------------------------------- bidirectional processing --------------------------------------------------
  uint64_t bidirectional_piat_ms = packet->time - entry->bidirectional_last_seen_ms;
  entry->bidirectional_last_seen_ms = packet->time;
  entry->bidirectional_duration_ms = entry->bidirectional_last_seen_ms - entry->bidirectional_first_seen_ms;
  entry->bidirectional_packets++;

  if (dissect == 1) {
    uint8_t tcp_stop = (packet->protocol == 6) && (max_tcp_dissections == entry->bidirectional_packets);
    uint8_t udp_stop = (packet->protocol == 17) && (max_udp_dissections == entry->bidirectional_packets);
    if (entry->detection_completed == 0) { // application not detected yet.
      if (packet->direction == 0) {
        entry->detected_protocol = ndpi_detection_process_packet(dissector,
                                                                 entry->ndpi_flow,
                                                                 packet->ip_content,
                                                                 packet->ip_content_len,
                                                                 packet->time,
                                                                 entry->ndpi_src,
                                                                 entry->ndpi_dst);
      } else {
        entry->detected_protocol = ndpi_detection_process_packet(dissector,
                                                                 entry->ndpi_flow,
                                                                 packet->ip_content,
                                                                 packet->ip_content_len,
                                                                 packet->time,
                                                                 entry->ndpi_dst,
                                                                 entry->ndpi_src);
      }
      dissector_process_info(dissector, entry);
      uint8_t enough_packets = (tcp_stop || udp_stop);
      if (enough_packets || (entry->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)) {
        if ((!enough_packets) && ndpi_extra_dissection_possible(dissector, entry->ndpi_flow));
        /* Pass as we will wait for certificate fingerprint */
        else {
          if (entry->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
            entry->detected_protocol = ndpi_detection_giveup(dissector,
                                                             entry->ndpi_flow,
                                                             enable_guess,
                                                             &entry->guessed);
          }
          dissector_process_info(dissector, entry);
          free_ndpi_data(entry);
          entry->detection_completed = 1;
        }
      }
    }
  }

  uint16_t packet_size = meter_account_packet(packet, accounting_mode);

  entry->bidirectional_bytes += packet_size;
  if (statistics == 1) {
    if (packet_size > entry->bidirectional_max_ps) {
      entry->bidirectional_max_ps = packet_size;
    }
    if (packet_size < entry->bidirectional_min_ps) {
      entry->bidirectional_min_ps = packet_size;
    }
    double bidirectional_mean_ps = entry->bidirectional_mean_ps;
    entry->bidirectional_mean_ps += (packet_size - bidirectional_mean_ps)/entry->bidirectional_packets;
    entry->bidirectional_stddev_ps += (packet_size - bidirectional_mean_ps)*(packet_size - entry->bidirectional_mean_ps);

    if (packet->syn) entry->bidirectional_syn_packets++;
    if (packet->cwr) entry->bidirectional_cwr_packets++;
    if (packet->ece) entry->bidirectional_ece_packets++;
    if (packet->urg) entry->bidirectional_urg_packets++;
    if (packet->ack) entry->bidirectional_ack_packets++;
    if (packet->psh) entry->bidirectional_psh_packets++;
    if (packet->rst) entry->bidirectional_rst_packets++;
    if (packet->fin) entry->bidirectional_fin_packets++;

    if (entry->bidirectional_packets == 2) {
      entry->bidirectional_min_piat_ms += bidirectional_piat_ms;
      entry->bidirectional_mean_piat_ms += bidirectional_piat_ms;
      entry->bidirectional_max_piat_ms += bidirectional_piat_ms;
    } else {
      if (bidirectional_piat_ms > entry->bidirectional_max_piat_ms) {
        entry->bidirectional_max_piat_ms = bidirectional_piat_ms;
      }
      if (bidirectional_piat_ms < entry->bidirectional_min_piat_ms) {
        entry->bidirectional_min_piat_ms = bidirectional_piat_ms;
      }
      double bidirectional_mean_piat_ms = entry->bidirectional_mean_piat_ms;
      entry->bidirectional_mean_piat_ms += (bidirectional_piat_ms - bidirectional_mean_piat_ms)/(entry->bidirectional_packets-1);
      entry->bidirectional_stddev_piat_ms += (bidirectional_piat_ms - bidirectional_mean_piat_ms)*(bidirectional_piat_ms - entry->bidirectional_mean_piat_ms);
    }
  }

  if (packet->direction == 0) { // ------------------ src2dst processing -----------------------------------------------
    entry->src2dst_packets++;
    uint64_t src2dst_piat_ms = packet->time - entry->src2dst_last_seen_ms;
    entry->src2dst_last_seen_ms = packet->time;
    entry->src2dst_duration_ms = entry->src2dst_last_seen_ms - entry->src2dst_first_seen_ms;
    entry->src2dst_bytes += packet_size;
    if (statistics == 1) {
      if (packet_size > entry->src2dst_max_ps) {
        entry->src2dst_max_ps = packet_size;
      }
      if (packet_size < entry->src2dst_min_ps) {
        entry->src2dst_min_ps = packet_size;
      }

      double src2dst_mean_ps = entry->src2dst_mean_ps;
      entry->src2dst_mean_ps += (packet_size - src2dst_mean_ps)/entry->src2dst_packets;
      entry->src2dst_stddev_ps += (packet_size - src2dst_mean_ps)*(packet_size - entry->src2dst_mean_ps);

      if (packet->syn) entry->src2dst_syn_packets++;
      if (packet->cwr) entry->src2dst_cwr_packets++;
      if (packet->ece) entry->src2dst_ece_packets++;
      if (packet->urg) entry->src2dst_urg_packets++;
      if (packet->ack) entry->src2dst_ack_packets++;
      if (packet->psh) entry->src2dst_psh_packets++;
      if (packet->rst) entry->src2dst_rst_packets++;
      if (packet->fin) entry->src2dst_fin_packets++;

      if (entry->src2dst_packets == 2) {
        entry->src2dst_min_piat_ms += src2dst_piat_ms;
        entry->src2dst_mean_piat_ms += src2dst_piat_ms;
        entry->src2dst_max_piat_ms += src2dst_piat_ms;
      } else {
        if (src2dst_piat_ms > entry->src2dst_max_piat_ms) {
          entry->src2dst_max_piat_ms = src2dst_piat_ms;
        }
        if (src2dst_piat_ms < entry->src2dst_min_piat_ms) {
          entry->src2dst_min_piat_ms = src2dst_piat_ms;
        }
        double src2dst_mean_piat_ms = entry->src2dst_mean_piat_ms;
        entry->src2dst_mean_piat_ms += (src2dst_piat_ms - src2dst_mean_piat_ms)/(entry->src2dst_packets-1);
        entry->src2dst_stddev_piat_ms += (src2dst_piat_ms - src2dst_mean_piat_ms)*(src2dst_piat_ms - entry->src2dst_mean_piat_ms);
      }
    }
  } else { // --------------------------------------- dst2src processing -----------------------------------------------
    entry->dst2src_packets++;
    entry->dst2src_bytes += packet_size;
    if (entry->dst2src_packets == 1) { // First packet in this direction
      entry->dst2src_first_seen_ms = packet->time;
      entry->dst2src_last_seen_ms = packet->time;
      if (statistics == 1) {
        entry->dst2src_min_ps += packet_size;
        entry->dst2src_mean_ps += packet_size;
        entry->dst2src_max_ps += packet_size;
        if (packet->syn) entry->dst2src_syn_packets++;
        if (packet->cwr) entry->dst2src_cwr_packets++;
        if (packet->ece) entry->dst2src_ece_packets++;
        if (packet->urg) entry->dst2src_urg_packets++;
        if (packet->ack) entry->dst2src_ack_packets++;
        if (packet->psh) entry->dst2src_psh_packets++;
        if (packet->rst) entry->dst2src_rst_packets++;
        if (packet->fin) entry->dst2src_fin_packets++;
      }
    } else {
      uint64_t dst2src_piat_ms = packet->time - entry->dst2src_last_seen_ms;
      entry->dst2src_last_seen_ms = packet->time;
      entry->dst2src_duration_ms = entry->dst2src_last_seen_ms - entry->dst2src_first_seen_ms;
      if (statistics == 1) {
        if (packet_size > entry->dst2src_max_ps) {
          entry->dst2src_max_ps = packet_size;
        }
        if (packet_size < entry->dst2src_min_ps) {
          entry->dst2src_min_ps = packet_size;
        }
        double dst2src_mean_ps = entry->dst2src_mean_ps;
        entry->dst2src_mean_ps += (packet_size - dst2src_mean_ps)/entry->dst2src_packets;
        entry->dst2src_stddev_ps += (packet_size - dst2src_mean_ps)*(packet_size - entry->dst2src_mean_ps);

        if (packet->syn) entry->dst2src_syn_packets++;
        if (packet->cwr) entry->dst2src_cwr_packets++;
        if (packet->ece) entry->dst2src_ece_packets++;
        if (packet->urg) entry->dst2src_urg_packets++;
        if (packet->ack) entry->dst2src_ack_packets++;
        if (packet->psh) entry->dst2src_psh_packets++;
        if (packet->rst) entry->dst2src_rst_packets++;
        if (packet->fin) entry->dst2src_fin_packets++;

        if (entry->dst2src_packets == 2) {
          entry->dst2src_min_piat_ms += dst2src_piat_ms;
          entry->dst2src_mean_piat_ms += dst2src_piat_ms;
          entry->dst2src_max_piat_ms += dst2src_piat_ms;
        } else {
          if (dst2src_piat_ms > entry->dst2src_max_piat_ms) {
            entry->dst2src_max_piat_ms = dst2src_piat_ms;
          }
          if (dst2src_piat_ms < entry->dst2src_min_piat_ms) {
            entry->dst2src_min_piat_ms = dst2src_piat_ms;
          }
          double dst2src_mean_piat_ms = entry->dst2src_mean_piat_ms;
          entry->dst2src_mean_piat_ms += (dst2src_piat_ms - dst2src_mean_piat_ms)/(entry->dst2src_packets-1);
          entry->dst2src_stddev_piat_ms += (dst2src_piat_ms - dst2src_mean_piat_ms)*(dst2src_piat_ms - entry->dst2src_mean_piat_ms);
        }
      }
    }
  }
  return 0; // Update done
}


void meter_expire_entry(struct nf_entry *entry, uint8_t dissect, uint8_t enable_guess,
                        struct ndpi_detection_module_struct *dissector) {
  if (dissect == 1) {
    if ((entry->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) && (entry->detection_completed == 0)) {
      entry->detected_protocol = ndpi_detection_giveup(dissector,
                                                       entry->ndpi_flow,
                                                       enable_guess,
                                                       &entry->guessed);
      dissector_process_info(dissector, entry);
    }
  }
}


void meter_free_entry(struct nf_entry *entry, uint8_t dissect) {
  if (dissect == 1) {
    free_ndpi_data(entry);
  }
  ndpi_free(entry);
  entry = NULL;
}