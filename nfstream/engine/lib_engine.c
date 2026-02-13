/*
------------------------------------------------------------------------------------------------------------------------
lib_engine.c
Copyright (C) 2019-22 - NFStream Developers
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

#define TICK_RESOLUTION          1000
#define	IPVERSION	4
#ifndef ETH_P_IP
#define ETH_P_IP               0x0800 	// IPv4
#endif
#ifndef ETH_P_IPv6
#define ETH_P_IPV6	       0x86dd	// IPv6
#endif
#define SLARP                  0x8035   // Cisco Slarp
#define CISCO_D_PROTO          0x2000	// Cisco Discovery Protocol
#define VLAN                   0x8100
#define MPLS_UNI               0x8847
#define MPLS_MULTI             0x8848
#define PPPoE                  0x8864
#define SNAP                   0xaa
#define BSTP                   0x42     // Bridge Spanning Tree Protocol
#define	WIFI_DATA                        0x2    // 0000 0010
#define FCF_TYPE(fc)     (((fc) >> 2) & 0x3)    // 0000 0011 = 0x3
#define FCF_SUBTYPE(fc)  (((fc) >> 4) & 0xF)    // 0000 1111 = 0xF
#define FCF_TO_DS(fc)        ((fc) & 0x0100)
#define FCF_FROM_DS(fc)      ((fc) & 0x0200)
#define BAD_FCS                         0x50  // 0101 0000
#define GTP_U_V1_PORT                  2152
#define NFSTREAM_CAPWAP_DATA_PORT          5247
#define TZSP_PORT                      37008
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL  113
#endif
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP  4
#endif
#ifdef WIN32
#define DLT_NULL  0
#define DLT_PPP_SERIAL  50
#define DLT_C_HDLC  104
#define DLT_PPP  9
#define DLT_IPV4  228
#define DLT_IPV6  229
#define DLT_EN10MB  1
#define DLT_IEEE802_11_RADIO  127
#define DLT_RAW  12
#endif
#define MODE_SINGLE_FILE 0
#define MODE_INTERFACE 1
#define MODE_MULTIPLE_FILES 2

//CFFI_SHARED_STRUCTURES
typedef struct dissector_checker {
  uint32_t flow_size;
  uint32_t id_size;
  uint32_t flow_tcp_size;
  uint32_t flow_udp_size;
} dissector_checker_t;

typedef struct nf_stat {
  unsigned received;
  unsigned dropped;
  unsigned dropped_by_interface;
} nf_stat_t;

// Flow main structure.
typedef struct nf_flow {
  uint64_t src_ip[2];
  uint64_t dst_ip[2];
  uint8_t src_mac[6];
  char src_mac_str[18];
  char src_oui[9];
  uint8_t dst_mac[6];
  char dst_mac_str[18];
  char dst_oui[9];
  char src_ip_str[48];
  uint16_t src_port;
  char dst_ip_str[48];
  uint16_t dst_port;
  uint8_t protocol;
  uint8_t ip_version;
  uint16_t vlan_id;
  unsigned tunnel_id;
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
  int8_t *splt_direction;
  int32_t *splt_ps;
  int64_t *splt_piat_ms;
  uint8_t splt_closed;
  char application_name[40];
  char category_name[40];
  char requested_server_name[80];
  char c_hash[48];
  char s_hash[48];
  char content_type[64];
  char user_agent[256];
  struct ndpi_flow_struct *ndpi_flow;
  uint8_t guessed;
  ndpi_protocol detected_protocol;
  uint8_t detection_completed;
  ndpi_confidence_t confidence;
} nf_flow_t;

// Main structure for packet information.
typedef struct nf_packet {
  uint8_t direction;
  uint64_t time;
  uint64_t delta_time;
  uint64_t src_ip[2];
  uint64_t dst_ip[2];
  uint16_t src_port;
  uint8_t src_mac[6];
  uint8_t dst_mac[6];
  uint16_t dst_port;
  uint8_t ip_version;
  uint8_t protocol;
  uint16_t vlan_id;
  uint16_t fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1; // TCP Flags
  uint16_t raw_size;
  uint16_t ip_size;
  uint16_t transport_size;
  uint16_t payload_size;
  uint16_t ip_content_len;
  uint8_t *ip_content;
  unsigned tunnel_id;
} nf_packet_t;
//CFFI_SHARED_STRUCTURES

/***************************************** Packet layer ***************************************************************/

/**
 * packet_get_tcp_info: TCP transport infos processing.
 */
static void packet_get_tcp_info(const uint8_t *l4, uint16_t l4_packet_len, struct nf_packet *nf_pkt,
                         struct ndpi_tcphdr **tcph, uint16_t *sport, uint16_t *dport,
                         uint32_t *l4_data_len, uint8_t **payload, uint16_t *payload_len) {
  unsigned tcp_len;
  *tcph = (struct ndpi_tcphdr *)l4;
  *sport = (*tcph)->source, *dport = (*tcph)->dest;
  tcp_len = ndpi_min(4*(*tcph)->doff, l4_packet_len);
  *payload = (uint8_t*)&l4[tcp_len];
  *payload_len = ndpi_max(0, l4_packet_len-4*(*tcph)->doff);
  *l4_data_len = l4_packet_len;
  nf_pkt->fin = (*tcph)->fin;
  nf_pkt->syn = (*tcph)->syn;
  nf_pkt->rst = (*tcph)->rst;
  nf_pkt->psh = (*tcph)->psh;
  nf_pkt->ack = (*tcph)->ack;
  nf_pkt->urg = (*tcph)->urg;
  nf_pkt->ece = (*tcph)->ece;
  nf_pkt->cwr = (*tcph)->cwr;
}

/**
 * packet_get_udp_info: UDP transport info processing.
 */
static void packet_get_udp_info(const uint8_t *l4, uint16_t l4_packet_len, struct nf_packet *nf_pkt,
                         struct ndpi_udphdr **udph, uint16_t *sport, uint16_t *dport,
                         uint32_t *l4_data_len, uint8_t **payload, uint16_t *payload_len) {
  *udph = (struct ndpi_udphdr *)l4;
  *sport = (*udph)->source, *dport = (*udph)->dest;
  *payload = (uint8_t*)&l4[sizeof(struct ndpi_udphdr)];
  *payload_len = (l4_packet_len > sizeof(struct ndpi_udphdr)) ? l4_packet_len-sizeof(struct ndpi_udphdr) : 0;
  *l4_data_len = l4_packet_len;
  nf_pkt->fin = nf_pkt->syn = nf_pkt->rst = nf_pkt->psh = nf_pkt->ack = nf_pkt->urg = nf_pkt->ece = nf_pkt->cwr = 0;
}

/**
 * packet_get_icmp_info: ICMP transport info processing.
 */
static void packet_get_icmp_info(const uint8_t *l4, uint16_t l4_packet_len, struct nf_packet *nf_pkt, uint16_t *sport,
                          uint16_t *dport, uint32_t *l4_data_len, uint8_t **payload, uint16_t *payload_len) {
  *payload = (uint8_t*)&l4[sizeof(struct ndpi_icmphdr )];
  *payload_len = (l4_packet_len > sizeof(struct ndpi_icmphdr)) ? l4_packet_len-sizeof(struct ndpi_icmphdr) : 0;
  *l4_data_len = l4_packet_len;
  *sport = *dport = 0;
  nf_pkt->fin = nf_pkt->syn = nf_pkt->rst = nf_pkt->psh = nf_pkt->ack = nf_pkt->urg = nf_pkt->ece = nf_pkt->cwr = 0;
}

/**
 * packet_get_icmp6_info: ICMPv6 transport infos processing.
 */
static void packet_get_icmp6_info(const uint8_t *l4, uint16_t l4_packet_len, struct nf_packet *nf_pkt, uint16_t *sport,
                           uint16_t *dport, uint32_t *l4_data_len, uint8_t **payload, uint16_t *payload_len) {
  *payload = (uint8_t*)&l4[sizeof(struct ndpi_icmp6hdr)];
  *payload_len = (l4_packet_len > sizeof(struct ndpi_icmp6hdr)) ? l4_packet_len-sizeof(struct ndpi_icmp6hdr) : 0;
  *l4_data_len = l4_packet_len;
  *sport = *dport = 0;
  nf_pkt->fin = nf_pkt->syn = nf_pkt->rst = nf_pkt->psh = nf_pkt->ack = nf_pkt->urg = nf_pkt->ece = nf_pkt->cwr = 0;
}

/**
 * packet_get_unknown_transport_info: Non TCP/UDP/ICMP/ICMPv6 infos processing.
 */
static void packet_get_unknown_transport_info(struct nf_packet *nf_pkt, uint16_t *sport, uint16_t *dport,
                                       uint32_t *l4_data_len) {
  *sport = *dport = 0;
  *l4_data_len = 0;
  nf_pkt->fin = nf_pkt->syn = nf_pkt->rst = nf_pkt->psh = nf_pkt->ack = nf_pkt->urg = nf_pkt->ece = nf_pkt->cwr = 0;
}

/**
 * packet_get_info: Fill required nf packet information.
 */
static void packet_get_info(struct nf_packet *nf_pkt, uint16_t *sport, uint16_t *dport, uint32_t *l4_data_len,
                     uint16_t *payload_len, const struct ndpi_iphdr *iph, const struct ndpi_ipv6hdr *iph6,
                     uint16_t ipsize, const uint8_t version, uint16_t vlan_id) {
  nf_pkt->protocol = iph->protocol;
  nf_pkt->vlan_id = vlan_id;
  nf_pkt->src_port = htons(*sport);
  nf_pkt->dst_port = htons(*dport);
  nf_pkt->ip_version = version;
  nf_pkt->transport_size = *l4_data_len;
  nf_pkt->payload_size = *payload_len;
  nf_pkt->ip_content_len = ipsize;
  nf_pkt->delta_time = 0; // This will be filled by meter.
  nf_pkt->ip_size = ntohs(iph->tot_len);
  if (version == IPVERSION) {
	nf_pkt->ip_content = (uint8_t *)iph;
	nf_pkt->src_ip[0] = iph->saddr;
	nf_pkt->dst_ip[0] = iph->daddr;
  } else {
	nf_pkt->ip_content = (uint8_t *)iph6;
	nf_pkt->src_ip[0] = iph6->ip6_src.u6_addr.u6_addr64[0];
	nf_pkt->src_ip[1] = iph6->ip6_src.u6_addr.u6_addr64[1];
	nf_pkt->dst_ip[0] = iph6->ip6_dst.u6_addr.u6_addr64[0];
	nf_pkt->dst_ip[1] = iph6->ip6_dst.u6_addr.u6_addr64[1];
  }
}

/**
 * packet_fanout: Network flow packet fanout.
 */
static int packet_fanout(int mode, uint64_t hashval, int n_roots, uint64_t root_idx) {
  if (mode == MODE_SINGLE_FILE || mode == MODE_MULTIPLE_FILES) { // Offline, we perform fanout like strategy
    if ((hashval % n_roots) == root_idx) { // If packet match meter idx, he will consume it and process it.
      return 1;
    } else {
      return 2; // Else it will be used as time ticker to ensure synchro across meters.
    }
  } else { // Live mode
#ifdef __linux__
    return 1; // Fanout already done by kernel on Linux
#else // Macos do not provide kernel fanout, so we do it ourselves.
    if ((hashval % n_roots) == root_idx) { // If packet match meter idx, he will consume it and process it.
      return 1;
    } else {
      return 2; // Else it will be used as time ticker to ensure synchro across meters.
    }
#endif
  }
}

/**
 * packet_get_ip_info: nf_packet structure filler.
 */
static int packet_get_ip_info(const uint8_t version, uint16_t vlan_id, ndpi_packet_tunnel tunnel_id,
                              const struct ndpi_iphdr *iph, const struct ndpi_ipv6hdr *iph6,
                              uint16_t ipsize, uint16_t l4_packet_len, uint16_t l4_offset, struct ndpi_tcphdr **tcph,
                              struct ndpi_udphdr **udph, uint16_t *sport, uint16_t *dport, uint8_t *proto,
                              uint8_t **payload, uint16_t *payload_len, struct nf_packet *nf_pkt,
                              int n_roots, uint64_t root_idx, int mode) {
  const uint8_t *l3, *l4;
  uint32_t l4_data_len = 0XFEEDFACE;
  if (version == IPVERSION) {
    if (ipsize < 20) return 0;
    if ((iph->ihl * 4) > ipsize) return 0;
    l3 = (const uint8_t*)iph;
  } else {
    if (l4_offset > ipsize) return 0;
    l3 = (const uint8_t*)iph6;
  }
  if (ndpi_max(ntohs(iph->tot_len) , ipsize)< l4_offset + l4_packet_len) return 0;
  *proto = iph->protocol;
  l4 =& ((const uint8_t *) l3)[l4_offset];
  if (*proto == IPPROTO_TCP && l4_packet_len >= sizeof(struct ndpi_tcphdr)) { // TCP Processing
    packet_get_tcp_info(l4, l4_packet_len, nf_pkt, tcph, sport, dport, &l4_data_len, payload, payload_len);
  } else if (*proto == IPPROTO_UDP && l4_packet_len >= sizeof(struct ndpi_udphdr)) { // UDP Processing
    packet_get_udp_info(l4, l4_packet_len, nf_pkt, udph, sport, dport, &l4_data_len, payload, payload_len);
  } else if (*proto == IPPROTO_ICMP) { // ICMP Processing
    packet_get_icmp_info(l4, l4_packet_len, nf_pkt, sport, dport, &l4_data_len, payload, payload_len);
  } else if (*proto == IPPROTO_ICMPV6) { // ICMPV6 Processing
    packet_get_icmp6_info(l4, l4_packet_len, nf_pkt, sport, dport, &l4_data_len, payload, payload_len);
  } else {
    packet_get_unknown_transport_info(nf_pkt, sport, dport, &l4_data_len);
  }
  packet_get_info(nf_pkt, sport, dport, &l4_data_len, payload_len, iph, iph6, ipsize, version, vlan_id);
  uint64_t hashval = 0; // Compute hashval as the sum of 6-tuple fields.
  hashval = nf_pkt->protocol + nf_pkt->vlan_id + iph->saddr + iph->daddr + nf_pkt->src_port + nf_pkt->dst_port +
            tunnel_id;
  nf_pkt->tunnel_id = tunnel_id;
  return packet_fanout(mode, hashval, n_roots, root_idx);
}

/**
 * packet_get_ipv6_info: Convert IPv6 headers to IPv4.
 */
static int packet_get_ipv6_info(uint16_t vlan_id, ndpi_packet_tunnel tunnel_id,
                                const struct ndpi_ipv6hdr *iph6, uint16_t ipsize,
                                struct ndpi_tcphdr **tcph, struct ndpi_udphdr **udph,
                                uint16_t *sport, uint16_t *dport, uint8_t *proto, uint8_t **payload,
                                uint16_t *payload_len, struct nf_packet *nf_pkt, int n_roots,
                                uint64_t root_idx, int mode) {
  // We move field to iph to treat it by the same function for IPV4
  struct ndpi_iphdr iph;
  if (ipsize < 40) return 0;
  memset(&iph, 0, sizeof(iph));
  iph.version = IPVERSION;
  iph.saddr = iph6->ip6_src.u6_addr.u6_addr32[2] + iph6->ip6_src.u6_addr.u6_addr32[3];
  iph.daddr = iph6->ip6_dst.u6_addr.u6_addr32[2] + iph6->ip6_dst.u6_addr.u6_addr32[3];
  uint8_t l4proto = iph6->ip6_hdr.ip6_un1_nxt;
  uint16_t ip_len = ntohs(iph6->ip6_hdr.ip6_un1_plen);
  const uint8_t *l4ptr = (((const uint8_t *) iph6) + sizeof(struct ndpi_ipv6hdr));
  if (ipsize < sizeof(struct ndpi_ipv6hdr) + ip_len) return 0;
  if (ndpi_handle_ipv6_extension_headers(ipsize - sizeof(struct ndpi_ipv6hdr), &l4ptr, &ip_len, &l4proto) != 0) {
    return 0;
  }
  iph.protocol = l4proto;
  iph.tot_len = htons(sizeof(struct ndpi_ipv6hdr) + ntohs(iph6->ip6_hdr.ip6_un1_plen));
  return(packet_get_ip_info(6, vlan_id, tunnel_id, &iph, iph6, ipsize, ip_len, l4ptr - (const uint8_t *)iph6,
	     tcph, udph, sport, dport, proto, payload, payload_len, nf_pkt, n_roots, root_idx, mode));
}

/**
 * packet_parse: Packet information parsing function.
 */
static int packet_parse(const uint64_t time,
                 uint16_t vlan_id,
                 ndpi_packet_tunnel tunnel_id,
                 const struct ndpi_iphdr *iph,
                 struct ndpi_ipv6hdr *iph6,
                 uint16_t ipsize,
                 uint16_t rawsize,
                 struct nf_packet *nf_pkt,
                 int n_roots,
                 uint64_t root_idx,
                 int mode) {
  uint8_t proto;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  uint16_t sport, dport, payload_len = 0;
  uint8_t *payload;
  nf_pkt->direction = 0;
  nf_pkt->time = time;
  nf_pkt->raw_size = rawsize;
  // According to IPVERSION, we extract required information for metering layer.
  if (iph)
    return packet_get_ip_info(IPVERSION, vlan_id, tunnel_id, iph, NULL, ipsize,
                              ntohs(iph->tot_len) - (iph->ihl * 4), iph->ihl * 4,
                              &tcph, &udph, &sport, &dport, &proto, &payload,
                              &payload_len, nf_pkt, n_roots, root_idx, mode);
  else
    return packet_get_ipv6_info(vlan_id, tunnel_id, iph6, ipsize, &tcph, &udph, &sport, &dport, &proto,
                                &payload, &payload_len, nf_pkt, n_roots, root_idx, mode);
}

/**
 * packet_dlt_null: null datatype processing
 */
static void packet_dlt_null(const uint8_t *packet, uint16_t eth_offset, uint16_t *type, uint16_t *ip_offset) {
  if (ntohl(*((uint32_t*)&packet[eth_offset])) == 2) (*type) = ETH_P_IP;
  else (*type) = ETH_P_IPV6;
  (*ip_offset) = 4 + eth_offset;
}

/**
 * packet_dlt_ppp_serial: cisco ppp processing
 */
static void packet_dlt_ppp_serial(const uint8_t *packet, uint16_t eth_offset, uint16_t *type, uint16_t *ip_offset) {
  const struct ndpi_chdlc *chdlc;
  chdlc = (struct ndpi_chdlc *) &packet[eth_offset];
  (*ip_offset) = eth_offset + sizeof(struct ndpi_chdlc); // CHDLC_OFF = 4
  (*type) = ntohs(chdlc->proto_code);
}

/**
 * packet_dlt_ppp: ppp processing
 */
static void packet_dlt_ppp(const uint8_t *packet, uint16_t eth_offset, uint16_t *type, uint16_t *ip_offset) {
  const struct ndpi_chdlc *chdlc;
  if(packet[0] == 0x0f || packet[0] == 0x8f) {
    chdlc = (struct ndpi_chdlc *) &packet[eth_offset];
    (*ip_offset) = eth_offset + sizeof(struct ndpi_chdlc); /* CHDLC_OFF = 4 */
    (*type) = ntohs(chdlc->proto_code);
  } else {
    (*ip_offset) = eth_offset + 2;
    (*type) = ntohs(*((u_int16_t*)&packet[eth_offset]));
  }
}


/**
 * packet_dlt_en10mb: Ethernet processing
 */
static int packet_dlt_en10mb(const uint8_t *packet, uint16_t eth_offset, uint16_t *type, uint16_t *ip_offset,
               int *pyld_eth_len, struct nf_packet *nf_pkt) {
  const struct ndpi_ethhdr *ethernet;
  const struct ndpi_llc_header_snap *llc;
  int check = 0;
  ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
  nf_pkt->src_mac[0] = ethernet->h_source[0];
  nf_pkt->src_mac[1] = ethernet->h_source[1];
  nf_pkt->src_mac[2] = ethernet->h_source[2];
  nf_pkt->src_mac[3] = ethernet->h_source[3];
  nf_pkt->src_mac[4] = ethernet->h_source[4];
  nf_pkt->src_mac[5] = ethernet->h_source[5];
  nf_pkt->dst_mac[0] = ethernet->h_dest[0];
  nf_pkt->dst_mac[1] = ethernet->h_dest[1];
  nf_pkt->dst_mac[2] = ethernet->h_dest[2];
  nf_pkt->dst_mac[3] = ethernet->h_dest[3];
  nf_pkt->dst_mac[4] = ethernet->h_dest[4];
  nf_pkt->dst_mac[5] = ethernet->h_dest[5];
  (*ip_offset) = sizeof(struct ndpi_ethhdr) + eth_offset;
  check = ntohs(ethernet->h_proto);
  if (check <= 1500) (*pyld_eth_len) = check;
  else if (check >= 1536) (*type) = check;

  if ((*pyld_eth_len) != 0) {
    llc = (struct ndpi_llc_header_snap *)(&packet[(*ip_offset)]);
    // check for LLC layer with SNAP extension */
    if (llc->dsap == SNAP || llc->ssap == SNAP) {
      (*type) = llc->snap.proto_ID;
      (*ip_offset) += + 8;
    } else if (llc->dsap == BSTP || llc->ssap == BSTP) {
      return 0;
    }
  }
  return 1;
}


/**
 * packet_dlt_radiotap: Radiotap link-layer processing
 */
static int packet_dlt_radiotap(const uint8_t *packet, uint32_t caplen, uint16_t eth_offset, uint16_t *type,
                        uint16_t *ip_offset, uint16_t *radio_len, uint16_t *fc, int *wifi_len,
                        struct nf_packet *nf_pkt) {
  const struct ndpi_radiotap_header *radiotap;
  const struct ndpi_wifi_header *wifi;
  const struct ndpi_llc_header_snap *llc;
  radiotap = (struct ndpi_radiotap_header *) &packet[eth_offset];
  (*radio_len) = radiotap->len;
  if ((radiotap->flags & BAD_FCS) == BAD_FCS) return 0;
  if (caplen < (eth_offset + (*radio_len) + sizeof(struct ndpi_wifi_header))) return 0;
  // Calculate 802.11 header length (variable)
  wifi = (struct ndpi_wifi_header*)( packet + eth_offset + (*radio_len));
  (*fc) = wifi->fc;
  // Check wifi data presence
  if (FCF_TYPE((*fc)) == WIFI_DATA) {
    if ((FCF_TO_DS((*fc)) && FCF_FROM_DS((*fc)) == 0x0)
        || (FCF_TO_DS((*fc)) == 0x0 && FCF_FROM_DS((*fc)))) (*wifi_len) = 26; // +4 byte fcs
  } else return 0;
  nf_pkt->src_mac[0] = wifi->trsm[0];
  nf_pkt->src_mac[1] = wifi->trsm[1];
  nf_pkt->src_mac[2] = wifi->trsm[2];
  nf_pkt->src_mac[3] = wifi->trsm[3];
  nf_pkt->src_mac[4] = wifi->trsm[4];
  nf_pkt->src_mac[5] = wifi->trsm[5];
  nf_pkt->dst_mac[0] = wifi->dest[0];
  nf_pkt->dst_mac[1] = wifi->dest[1];
  nf_pkt->dst_mac[2] = wifi->dest[2];
  nf_pkt->dst_mac[3] = wifi->dest[3];
  nf_pkt->dst_mac[4] = wifi->dest[4];
  nf_pkt->dst_mac[5] = wifi->dest[5];
  // Check ether_type from LLC
  if (caplen < (eth_offset + (*wifi_len) + (*radio_len) + sizeof(struct ndpi_llc_header_snap))) return 0;
  llc = (struct ndpi_llc_header_snap*)(packet + eth_offset + (*wifi_len) + (*radio_len));
  if (llc->dsap == SNAP) (*type) = ntohs(llc->snap.proto_ID);
  (*ip_offset) = (*wifi_len) + (*radio_len) + sizeof(struct ndpi_llc_header_snap) + eth_offset;
  return 1;
}


/**
 * packet_dlt_linux_ssl: Linux cooked capture processing
 */
static void packet_dlt_linux_ssl(const uint8_t *packet, uint16_t eth_offset, uint16_t *type, uint16_t *ip_offset) {
  (*type) = (packet[eth_offset+14] << 8) + packet[eth_offset+15];
  (*ip_offset) = 16 + eth_offset;
}


/**
 * packet_dlt_ipv4: Raw IPv4
 */
static void packet_dlt_ipv4(uint16_t *type, uint16_t eth_offset, uint16_t *ip_offset) {
  (*type) = ETH_P_IP;
  (*ip_offset) = eth_offset;
}


/**
 * packet_dlt_ipv6: Raw IPv6
 */
static void packet_dlt_ipv6(uint16_t *type, uint16_t eth_offset, uint16_t *ip_offset) {
  (*type) = ETH_P_IPV6;
  (*ip_offset) = eth_offset;
}


/**
 * packet_datalink_checker: Compute offsets based on datalink type.
 */
static int packet_datalink_checker(uint32_t caplen, const uint8_t *packet, uint16_t eth_offset, uint16_t *type,
                            int datalink_type, uint16_t *ip_offset, int *pyld_eth_len, uint16_t *radio_len, uint16_t *fc,
                            int *wifi_len, struct nf_packet *nf_pkt) {
  if (caplen < (eth_offset + 28)) return 0; /* 28 = min IP + min UDP */
  switch(datalink_type) {
  case DLT_NULL:
    packet_dlt_null(packet, eth_offset, type, ip_offset);
    break;
  case DLT_PPP_SERIAL: // Cisco PPP in HDLC-like framing: 50
    packet_dlt_ppp_serial(packet, eth_offset, type, ip_offset);
    break;
  case DLT_C_HDLC:
  case DLT_PPP: // Cisco PPP: 9 or 104
    packet_dlt_ppp(packet, eth_offset, type, ip_offset);
    break;
  case DLT_IPV4:
    packet_dlt_ipv4(type, eth_offset, ip_offset);
    break;
  case DLT_IPV6:
    packet_dlt_ipv6(type, eth_offset, ip_offset);
    break;
  case DLT_EN10MB: // IEEE 802.3 Ethernet: 1
    if (!packet_dlt_en10mb(packet, eth_offset, type, ip_offset, pyld_eth_len, nf_pkt)) return 0;
    break;
  case DLT_LINUX_SLL: // Linux Cooked Capture: 113
    packet_dlt_linux_ssl(packet, eth_offset, type, ip_offset);
    break;
  case DLT_IEEE802_11_RADIO: // Radiotap link-layer: 127
    if (!packet_dlt_radiotap(packet, caplen, eth_offset, type, ip_offset, radio_len, fc, wifi_len, nf_pkt)) return 0;
    break;
  case DLT_RAW:
    (*ip_offset) = eth_offset;
    if (caplen > eth_offset) { // Raw IP (DLT_RAW) can carry either IPv4 or IPv6 packets, so let's check it 
      uint8_t ip_version = packet[eth_offset] >> 4;
      if (ip_version == 4) *type = ETH_P_IP;
      if (ip_version == 6) *type = ETH_P_IPV6;
    }
    break;
  default:
    return 0;
  }
  return 1;
}


/**
 * packet_ether_type_checker: Check ether type.
 */
static int packet_ether_type_checker(uint32_t caplen, const uint8_t *packet, uint16_t *type,
                               uint16_t *vlan_id, uint16_t *ip_offset, uint8_t *recheck_type) {
  // MPLS header
  union mpls {
    uint32_t u32;
    struct ndpi_mpls_header mpls;
  } mpls;
  switch((*type)) {
  case VLAN:
    if (*ip_offset + 4 >= (int) caplen) return 0;
    (*vlan_id) = ((packet[(*ip_offset)] << 8) + packet[(*ip_offset)+1]) & 0xFFF;
    (*type) = (packet[(*ip_offset)+2] << 8) + packet[(*ip_offset)+3];
    (*ip_offset) += 4;
    // double tagging for 802.1Q
    while(((*type) == 0x8100) && (((uint32_t)(*ip_offset + 4)) < caplen)) {
      (*vlan_id) = ((packet[(*ip_offset)] << 8) + packet[(*ip_offset)+1]) & 0xFFF;
      (*type) = (packet[(*ip_offset)+2] << 8) + packet[(*ip_offset)+3];
      (*ip_offset) += 4;
    }
    (*recheck_type) = 1;
    break;
  case MPLS_UNI:
  case MPLS_MULTI:
    if (*ip_offset + 4 >= (int) caplen) return 0;
    mpls.u32 = *((uint32_t *) &packet[(*ip_offset)]);
    mpls.u32 = ntohl(mpls.u32);
    (*type) = ETH_P_IP, (*ip_offset) += 4;
    while(!mpls.mpls.s && (((uint32_t)(*ip_offset)) + 4 < caplen)) {
      mpls.u32 = *((uint32_t *) &packet[(*ip_offset)]);
      mpls.u32 = ntohl(mpls.u32);
      (*ip_offset) += 4;
    }
    (*recheck_type) = 1;
    break;
  case PPPoE:
    (*type) = ETH_P_IP;
    (*ip_offset) += 8;
    (*recheck_type) = 1;
    break;
  default:
    break;
  }
  return 1;
}

/**
 * packet_process: Main packet processing function.
 */
static int packet_process(int datalink_type, uint32_t caplen, uint32_t len, const uint8_t *packet, int decode_tunnels,
                   struct nf_packet *nf_pkt, int n_roots, uint64_t root_idx, int mode, uint64_t time) {
  // IP header
  struct ndpi_iphdr *iph;
  // IPv6 header
  struct ndpi_ipv6hdr *iph6;
  ndpi_packet_tunnel tunnel_id = ndpi_no_tunnel;
  uint32_t eth_offset = 0;
  uint16_t radio_len = 0, fc = 0, type = 0, ip_offset = 0, ip_len = 0, frag_off = 0, vlan_id = 0;
  int wifi_len = 0, pyld_eth_len = 0;
  uint8_t proto = 0, recheck_type = 0;

 datalink_check:
   if (!packet_datalink_checker(caplen, packet, eth_offset, &type, datalink_type, &ip_offset, &pyld_eth_len, &radio_len,
                                &fc, &wifi_len, nf_pkt)) return 0;

 ether_type_check:
  recheck_type = 0;
  if (!packet_ether_type_checker(caplen, packet, &type, &vlan_id, &ip_offset, &recheck_type)) return 0;
  if (recheck_type)
    goto ether_type_check;


 iph_check:
  // Check and set IP header size and total packet length
  if (caplen < ip_offset + sizeof(struct ndpi_iphdr)) return 0;
  iph = (struct ndpi_iphdr *) &packet[ip_offset];

  // just work on Ethernet packets that contain IP */
  if (type == ETH_P_IP && caplen >= ip_offset) {
    frag_off = ntohs(iph->frag_off);
    proto = iph->protocol;
  }

  if (iph->version == IPVERSION) {
    ip_len = ((uint16_t)iph->ihl * 4);
    iph6 = NULL;

    if (iph->protocol == IPPROTO_IPV6 || iph->protocol == IPPROTO_IPIP) {
      ip_offset += ip_len;
      if (ip_len > 0) goto iph_check;
    }

    if ((frag_off & 0x1FFF) != 0) return 0;

  } else if (iph->version == 6) {
    if (caplen < ip_offset + sizeof(struct ndpi_ipv6hdr)) return 0;
    iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    proto = iph6->ip6_hdr.ip6_un1_nxt;
    ip_len = ntohs(iph6->ip6_hdr.ip6_un1_plen);
    if (caplen < (ip_offset + sizeof(struct ndpi_ipv6hdr) + ntohs(iph6->ip6_hdr.ip6_un1_plen))) return 0;

    const uint8_t *l4ptr = (((const uint8_t *) iph6) + sizeof(struct ndpi_ipv6hdr));
    uint16_t ipsize = caplen - ip_offset;
    if (ndpi_handle_ipv6_extension_headers(ipsize - sizeof(struct ndpi_ipv6hdr), &l4ptr, &ip_len, &proto) != 0) return 0;

    if (proto == IPPROTO_IPV6 || proto == IPPROTO_IPIP) {
      if (l4ptr > packet) { // Better safe than sorry
        ip_offset = (l4ptr - packet);
        goto iph_check;
      }
    }
    iph = NULL;
  } else {
    return 0;
  }

  if (decode_tunnels && (proto == IPPROTO_UDP)) { // Tunnel decoding if configured by the user.
    if (caplen < ip_offset + ip_len + sizeof(struct ndpi_udphdr)) return 0; // Too short for UDP header
    else {
      struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
      uint16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);
      if (((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) && ((ip_offset + ip_len +
                                                                      sizeof(struct ndpi_udphdr) + 8)
                                                                      < caplen)
                                                                      ) {
        // Check if it's GTPv1
        unsigned offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
        uint8_t flags = packet[offset];
        uint8_t message_type = packet[offset+1];
        uint8_t exts_parsing_error = 0;

        if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) && (message_type == 0xFF /* T-PDU */)) {
          offset += 8; /* GTPv1 header len */
          if (flags & 0x07) offset += 4; /* sequence_number + pdu_number + next_ext_header fields */
          /* Extensions parsing */
          if (flags & 0x04) {
            unsigned int ext_length = 0;
            while (offset < caplen) {
              ext_length = packet[offset] << 2;
              offset += ext_length;
              if (offset >= caplen || ext_length == 0) {
                exts_parsing_error = 1;
                break;
              }
              if (packet[offset - 1] == 0) break;
            }
          }

          if (offset < caplen && !exts_parsing_error) {
	        /* Ok, valid GTP-U */
	        tunnel_id = ndpi_gtp_tunnel;
	        ip_offset = offset;
	        iph = (struct ndpi_iphdr *)&packet[ip_offset];
	        if (iph->version == 6) {
	          iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
	          iph = NULL;
	          if (caplen < ip_offset + sizeof(struct ndpi_ipv6hdr)) return 0;
	        } else if (iph->version != IPVERSION) {
	            return 0;
	        } else {
	            if (caplen < ip_offset + sizeof(struct ndpi_iphdr)) return 0;
	        }
	      }
	    }
      } else if ((sport == TZSP_PORT) || (dport == TZSP_PORT)) {
        // https://en.wikipedia.org/wiki/TZSP
        if (caplen < ip_offset + ip_len + sizeof(struct ndpi_udphdr) + 4) return 0;
        unsigned offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
        uint8_t version = packet[offset];
        uint8_t ts_type = packet[offset+1];
        uint16_t encapsulates = ntohs(*((uint16_t*)&packet[offset+2]));
        tunnel_id = ndpi_tzsp_tunnel;
        if ((version == 1) && (ts_type == 0) && (encapsulates == 1)) {
          uint8_t stop = 0;
          offset += 4;
          while((!stop) && (offset < caplen)) {
            uint8_t tag_type = packet[offset];
            uint8_t tag_len;
            switch (tag_type) {
            case 0: // PADDING Tag
              tag_len = 1;
              break;
            case 1: // END Tag
              tag_len = 1, stop = 1;
              break;
            default:
              if (offset + 1 >= caplen) return 0;
              tag_len = packet[offset+1];
              break;
            }
            offset += tag_len;
            if (offset >= caplen) return 0;
            else {
              eth_offset = offset;
              goto datalink_check;
            }
          }
	    }
      } else if ((sport == NFSTREAM_CAPWAP_DATA_PORT) || (dport == NFSTREAM_CAPWAP_DATA_PORT)) {
	    // We decode CAPWAP DATA
	    unsigned offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
	    if ((offset+1) < caplen) {
	      uint8_t preamble = packet[offset];
	      if ((preamble & 0x0F) == 0) { // CAPWAP header
	        uint16_t msg_len = (packet[offset+1] & 0xF8) >> 1;
	        offset += msg_len;
	        if (offset + 32 < caplen) {
	          const struct ndpi_wifi_header *wifi_hdr;
              wifi_hdr = (struct ndpi_wifi_header*)(packet + offset);
              nf_pkt->src_mac[0] = wifi_hdr->trsm[0];
              nf_pkt->src_mac[1] = wifi_hdr->trsm[1];
              nf_pkt->src_mac[2] = wifi_hdr->trsm[2];
              nf_pkt->src_mac[3] = wifi_hdr->trsm[3];
              nf_pkt->src_mac[4] = wifi_hdr->trsm[4];
              nf_pkt->src_mac[5] = wifi_hdr->trsm[5];
              nf_pkt->dst_mac[0] = wifi_hdr->dest[0];
              nf_pkt->dst_mac[1] = wifi_hdr->dest[1];
              nf_pkt->dst_mac[2] = wifi_hdr->dest[2];
              nf_pkt->dst_mac[3] = wifi_hdr->dest[3];
              nf_pkt->dst_mac[4] = wifi_hdr->dest[4];
              nf_pkt->dst_mac[5] = wifi_hdr->dest[5];
	          offset += 24;
	          // LLC header is 8 bytes
	          type = ntohs((uint16_t)*((uint16_t*)&packet[offset+6]));
	          ip_offset = offset + 8;
	          tunnel_id = ndpi_capwap_tunnel;
	          goto iph_check;
	        }
	      }
	    }
      }
    }
  }
  return packet_parse(time, vlan_id, tunnel_id, iph, iph6, caplen - ip_offset, len, nf_pkt, n_roots, root_idx, mode);
}
/***************************************** Flow layer *****************************************************************/

/**
 * flow_get_packet_size: Return packet_size according to configured accounting mode.
 */
static uint16_t flow_get_packet_size(struct nf_packet *packet, uint8_t accounting_mode) {
  if (accounting_mode == 0) return packet->raw_size;
  else if (accounting_mode == 1) return packet->ip_size;
  else if (accounting_mode == 2) return packet->transport_size;
  else return packet->payload_size;
}


/**
 * flow_is_ndpi_proto: helper to check is flow protocol equal to an id.
 */
static uint8_t flow_is_ndpi_proto(struct nf_flow *flow, uint16_t id) {
  if ((flow->detected_protocol.master_protocol == id)|| (flow->detected_protocol.app_protocol == id)) return 1;
  else return 0;
}

/**
 * flow_bidirectional_dissection_collect_info: Dissection info collector.
 */
static void flow_bidirectional_dissection_collect_info(struct ndpi_detection_module_struct *dissector, struct nf_flow *flow) {
  // We copy useful information to fileds in our flow structure in order to release dissector references at early stage.
  if (!flow->ndpi_flow) return;
  flow->confidence = flow->ndpi_flow->confidence;
  // Application name (STUN.WhatsApp, TLS.Netflix, etc.).
  ndpi_protocol2name(dissector, flow->detected_protocol, flow->application_name, sizeof(flow->application_name));
  // Application category name (Streaming, SocialNetwork, etc.).
  memcpy(flow->category_name, ndpi_category_get_name(dissector, flow->detected_protocol.category), 24);
  // Requested server name: HTTP server, DNS, etc.
  memcpy(flow->requested_server_name, flow->ndpi_flow->host_server_name, sizeof(flow->requested_server_name));
  // DHCP: We put DHCP fingerprint in client side: this can be helpful for device identification approaches.
  if (flow_is_ndpi_proto(flow, NDPI_PROTOCOL_DHCP)) {
    memcpy(flow->c_hash, flow->ndpi_flow->protos.dhcp.fingerprint, sizeof(flow->c_hash));
  }
  // HTTP: UserAgent and ContentType. With server name this is sufficient. (at least for now)
  else if (flow_is_ndpi_proto(flow, NDPI_PROTOCOL_HTTP)) {
    ndpi_snprintf(flow->content_type, sizeof(flow->content_type), "%s", flow->ndpi_flow->http.content_type ? flow->ndpi_flow->http.content_type : "");
    ndpi_snprintf(flow->user_agent, sizeof(flow->user_agent), "%s", (flow->ndpi_flow->http.user_agent ? flow->ndpi_flow->http.user_agent : ""));
  // SSH: https://github.com/salesforce/hassh
  //      We extract both client and server fingerprints hassh fingerprints for SSH.
  } else if (flow_is_ndpi_proto(flow, NDPI_PROTOCOL_SSH)) {
    memcpy(flow->c_hash, flow->ndpi_flow->protos.ssh.hassh_client, sizeof(flow->c_hash));
    memcpy(flow->s_hash, flow->ndpi_flow->protos.ssh.hassh_server, sizeof(flow->s_hash));
  }
  // TLS: We populate requested server name with the server name identifier extracted in client hello.
  //      Then we add JA3 fingerprints for both client and server: https://github.com/salesforce/ja3
  // We also add QUIC user Agent ID in case of QUIC protocol.


  else if (flow_is_ndpi_proto(flow, NDPI_PROTOCOL_TLS) || flow_is_ndpi_proto(flow, NDPI_PROTOCOL_DTLS) ||
           flow_is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_SMTPS) || flow_is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_IMAPS) ||
           flow_is_ndpi_proto(flow, NDPI_PROTOCOL_MAIL_POPS) || flow_is_ndpi_proto(flow, NDPI_PROTOCOL_QUIC)) {
    memcpy(flow->requested_server_name, flow->ndpi_flow->host_server_name, sizeof(flow->requested_server_name));
    ndpi_snprintf(flow->user_agent, sizeof(flow->user_agent), "%s", (flow->ndpi_flow->http.user_agent ? flow->ndpi_flow->http.user_agent : ""));
    memcpy(flow->c_hash, flow->ndpi_flow->protos.tls_quic.ja3_client, sizeof(flow->c_hash));
    memcpy(flow->s_hash, flow->ndpi_flow->protos.tls_quic.ja3_server, sizeof(flow->s_hash));
  }
}

/**
 * flow_free_ndpi_data: nDPI references freer.
 */
static void flow_free_ndpi_data(struct nf_flow *flow) {
  if (flow->ndpi_flow) { ndpi_flow_free(flow->ndpi_flow); flow->ndpi_flow = NULL; }
}

/**
 * flow_free_splt_data: SPLT fields freer.
 */
static void flow_free_splt_data(struct nf_flow *flow) {
  if (flow->splt_direction) { ndpi_free(flow->splt_direction); flow->splt_direction = NULL; }
  if (flow->splt_ps) { ndpi_free(flow->splt_ps); flow->splt_ps = NULL; }
  if (flow->splt_piat_ms) { ndpi_free(flow->splt_piat_ms); flow->splt_piat_ms = NULL; }
  flow->splt_closed = 1;
}

/**
 * flow_update_bidirectional_tcp_flags: Update bidirectional tcp flags flow counters.
 */
static void flow_update_bidirectional_tcp_flags(struct nf_flow *flow, struct nf_packet *packet) {
  flow->bidirectional_syn_packets += packet->syn;
  flow->bidirectional_cwr_packets += packet->cwr;
  flow->bidirectional_ece_packets += packet->ece;
  flow->bidirectional_urg_packets += packet->urg;
  flow->bidirectional_ack_packets += packet->ack;
  flow->bidirectional_psh_packets += packet->psh;
  flow->bidirectional_rst_packets += packet->rst;
  flow->bidirectional_fin_packets += packet->fin;
}

/**
 * flow_update_src2dst_tcp_flags: Update src2dst tcp flags flow counters.
 */
static void flow_update_src2dst_tcp_flags(struct nf_flow *flow, struct nf_packet *packet) {
  flow->src2dst_syn_packets += packet->syn;
  flow->src2dst_cwr_packets += packet->cwr;
  flow->src2dst_ece_packets += packet->ece;
  flow->src2dst_urg_packets += packet->urg;
  flow->src2dst_ack_packets += packet->ack;
  flow->src2dst_psh_packets += packet->psh;
  flow->src2dst_rst_packets += packet->rst;
  flow->src2dst_fin_packets += packet->fin;
}

/**
 * flow_update_dst2src_tcp_flags: Update dst2src tcp flags flow counters.
 */
static void flow_update_dst2src_tcp_flags(struct nf_flow *flow, struct nf_packet *packet) {
  flow->dst2src_syn_packets += packet->syn;
  flow->dst2src_cwr_packets += packet->cwr;
  flow->dst2src_ece_packets += packet->ece;
  flow->dst2src_urg_packets += packet->urg;
  flow->dst2src_ack_packets += packet->ack;
  flow->dst2src_psh_packets += packet->psh;
  flow->dst2src_rst_packets += packet->rst;
  flow->dst2src_fin_packets += packet->fin;
}

/**
 * flow_expiration_handler: Flow expiration handler.
 */
static uint8_t flow_expiration_handler(struct nf_flow *flow, struct nf_packet *packet,
                           uint64_t idle_timeout, uint64_t active_timeout) {
  if ((packet->time - flow->bidirectional_last_seen_ms) >= idle_timeout) return 1; // Inactive expiration
  if ((packet->time - flow->bidirectional_first_seen_ms) >= active_timeout) return 2; // active expiration
  // TCP natural expiration with id 3?
  return 0;
}

/**
 * flow_init_splt: Flow SPLT structure initializer.
 */
static uint8_t flow_init_splt(struct nf_flow *flow, uint16_t splt, uint16_t packet_size) {
  flow->splt_direction = (int8_t*)ndpi_malloc(sizeof(int8_t) * splt); // direction on int8 is more than sufficient.
  if (flow->splt_direction == NULL) {
    ndpi_free(flow);
    return 0;
  }
  memset(flow->splt_direction, -1, sizeof(int8_t) * splt); // Fill it with -1 as missing data value.
  // ps array allocation.
  flow->splt_ps = (int32_t*)ndpi_malloc(sizeof(int32_t) * splt);
  if (flow->splt_ps == NULL) {
    ndpi_free(flow);
    return 0;
  }
  memset(flow->splt_ps, -1, sizeof(int32_t) * splt); //-1 for missing values
  // piat_ms array allocation
  flow->splt_piat_ms = (int64_t*)ndpi_malloc(sizeof(int64_t) * splt); // int64 as time diff between two uint64.
  if (flow->splt_piat_ms == NULL) {
    ndpi_free(flow);
    return 0;
  }
  memset(flow->splt_piat_ms, -1, sizeof(int64_t) * splt); // -1 for missing values
  // SPLT values initialization
  flow->splt_direction[0] = 0; // First packet always src->dst
  flow->splt_ps[0] = packet_size;
  flow->splt_piat_ms[0] = 0; // We set first piat to zero.
  return 1;
}

/**
 * flow_update_splt: Flow SPLT structure updater.
 */
static void flow_update_splt(uint16_t splt, struct nf_flow *flow, struct nf_packet *packet, uint16_t packet_size,
                             uint64_t bidirectional_piat_ms) {
  if ((flow->bidirectional_packets - 1) < splt) {
      flow->splt_direction[flow->bidirectional_packets - 1] = packet->direction;
      flow->splt_ps[flow->bidirectional_packets - 1] = packet_size;
      flow->splt_piat_ms[flow->bidirectional_packets - 1] = bidirectional_piat_ms;
  }
}

/**
 * ip_src_eq: Compare packet-flow IP source
 */
static int ip_src_eq(struct nf_flow *flow, struct nf_packet *packet) {
  if (packet->ip_version == 6) {
    if(packet->src_ip[0] == flow->src_ip[0] &&
       packet->src_ip[1] == flow->src_ip[1])
       return 1;
    return 0;
  }
  if (packet->src_ip[0] == flow->src_ip[0]) return 1;
  return 0;
}

/**
 * ip_dst_eq: Compare packet-flow IP destination
 */
static int ip_dst_eq(struct nf_flow *flow, struct nf_packet *packet) {
  if (packet->ip_version == 6) {
    if(packet->dst_ip[0] == flow->dst_ip[0] &&
       packet->dst_ip[1] == flow->dst_ip[1])
       return 1;
    return 0;
  }
  if (packet->dst_ip[0] == flow->dst_ip[0]) return 1;
  return 0;
}

/**
 * flow_set_packet_direction: Compute flow packet direction.
 */
static void flow_set_packet_direction(struct nf_flow *flow, struct nf_packet *packet) {
  // We first check ports to determine direction.
  if ((flow->src_port != packet->src_port) || (flow->dst_port != packet->dst_port)) {
    packet->direction = 1;
  // Then IPs
  } else {
    if (!ip_src_eq(flow, packet) || !ip_dst_eq(flow, packet)) {
      packet->direction = 1;
    }
  }
}

/**
 * flow_init_bidirectional_dissection: Flow bidirectional dissection initialization.
 */
static uint8_t flow_init_bidirectional_dissection(struct ndpi_detection_module_struct *dissector, uint8_t n_dissections,
                                           struct nf_flow *flow, struct nf_packet *packet, uint8_t sync) {
  flow->ndpi_flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(SIZEOF_FLOW_STRUCT);
  if (flow->ndpi_flow == NULL) {
    ndpi_free(flow);
    return 0;
  } else {
    memset(flow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);
  }
  // First packet are dissected.
  flow->detected_protocol = ndpi_detection_process_packet(dissector, flow->ndpi_flow, packet->ip_content,
                                                          packet->ip_content_len, packet->time, NULL);
  if (sync) flow_bidirectional_dissection_collect_info(dissector, flow); // Then we collect possible infos.
  if ((flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) && (n_dissections == 1)) {
    // Not identified and we are limited to 1, we try to guess.
    flow->detected_protocol = ndpi_detection_giveup(dissector, flow->ndpi_flow, 1, &flow->guessed);
    if (sync) flow_bidirectional_dissection_collect_info(dissector, flow); // Collect potentially guessed infos.
    flow->detection_completed = 1; // Close it.
  }
  return 1;
}

/**
 * flow_update_bidirectional_dissection: Flow bidirectional dissection updater.
 */
static void flow_update_bidirectional_dissection(struct ndpi_detection_module_struct *dissector, uint8_t n_dissections,
                                          struct nf_flow *flow, struct nf_packet *packet, uint8_t sync) {
  if (flow->detection_completed == 0) { // application not detected yet.
    // We dissect only if still unknown or known and we didn't dissect all possible information yet.
    uint8_t still_dissect = (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) ||
                             ((flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
                               && ndpi_extra_dissection_possible(dissector, flow->ndpi_flow));
    if (still_dissect) { // Go for it.
      flow->detected_protocol = ndpi_detection_process_packet(dissector, flow->ndpi_flow, packet->ip_content,
                                                              packet->ip_content_len, packet->time, NULL);
      if (sync) flow_bidirectional_dissection_collect_info(dissector, flow); // Collect information to flow structure.
    } else { // We are done -> Known and no extra dissection possible.
      flow->detection_completed = 1; // Detection end. (detection_completed is used to trigger copy on sync mode)
      // Note we didn't collect information as this is already done in previous loop.
    }

    if (n_dissections == flow->bidirectional_packets) { // if we reach user defined limit and application is unknown
      if (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
        flow->detected_protocol = ndpi_detection_giveup(dissector, flow->ndpi_flow, 1, &flow->guessed);
        if (sync) flow_bidirectional_dissection_collect_info(dissector, flow); // copy guessed infos if present.
      } // We reach it.
      flow->detection_completed = 1;
    }
  } else {
    if (flow->detection_completed == 1) flow->detection_completed = 2; // trigger the copy only once on sync mode.
  }
}

/**
 * flow_init_bidirectional_ps: Flow bidirectional packet sizes statistics initializer.
 */
static void flow_init_bidirectional_ps(struct nf_flow *flow, uint16_t packet_size) {
  flow->bidirectional_min_ps += packet_size;
  flow->bidirectional_mean_ps += packet_size;
  flow->bidirectional_max_ps += packet_size;
}

/**
 * flow_update_bidirectional_ps: Flow bidirectional packet sizes statistics updater.
 */
static void flow_update_bidirectional_ps(struct nf_flow *flow, uint16_t packet_size) {
  if (packet_size > flow->bidirectional_max_ps) flow->bidirectional_max_ps = packet_size;
  if (packet_size < flow->bidirectional_min_ps) flow->bidirectional_min_ps = packet_size;
  double bidirectional_mean_ps = flow->bidirectional_mean_ps;
  flow->bidirectional_mean_ps += (packet_size - bidirectional_mean_ps) / flow->bidirectional_packets;
  flow->bidirectional_stddev_ps += (packet_size - bidirectional_mean_ps) * (packet_size - flow->bidirectional_mean_ps);
}

/**
 * flow_init_bidirectional_piat_ms: Flow bidirectional piat statistics initializer.
 */
static void flow_init_bidirectional_piat_ms(struct nf_flow *flow, uint64_t bidirectional_piat_ms) {
  flow->bidirectional_min_piat_ms += bidirectional_piat_ms;
  flow->bidirectional_mean_piat_ms += bidirectional_piat_ms;
  flow->bidirectional_max_piat_ms += bidirectional_piat_ms;
}

/**
 * flow_update_bidirectional_piat_ms: Flow bidirectional piat statistics updater.
 */
static void flow_update_bidirectional_piat_ms(struct nf_flow *flow, uint64_t bidirectional_piat_ms) {
  if (bidirectional_piat_ms > flow->bidirectional_max_piat_ms) flow->bidirectional_max_piat_ms = bidirectional_piat_ms;
  if (bidirectional_piat_ms < flow->bidirectional_min_piat_ms) flow->bidirectional_min_piat_ms = bidirectional_piat_ms;
  double bidirectional_mean_piat_ms = flow->bidirectional_mean_piat_ms;
  flow->bidirectional_mean_piat_ms += (bidirectional_piat_ms - bidirectional_mean_piat_ms)
                                      / (flow->bidirectional_packets-1);
  flow->bidirectional_stddev_piat_ms += (bidirectional_piat_ms - bidirectional_mean_piat_ms)
                                        * (bidirectional_piat_ms - flow->bidirectional_mean_piat_ms);
}

/**
 * flow_init_src2dst_ps: Flow src2dst packet sizes statistics initializer.
 */
static void flow_init_src2dst_ps(struct nf_flow *flow, uint16_t packet_size) {
  flow->src2dst_min_ps += packet_size;
  flow->src2dst_mean_ps += packet_size;
  flow->src2dst_max_ps += packet_size;
}

/**
 * flow_update_src2dst_ps: Flow src2dst packet sizes statistics updater.
 */
static void flow_update_src2dst_ps(struct nf_flow *flow, uint16_t packet_size) {
  if (packet_size > flow->src2dst_max_ps) flow->src2dst_max_ps = packet_size;
  if (packet_size < flow->src2dst_min_ps) flow->src2dst_min_ps = packet_size;
  double src2dst_mean_ps = flow->src2dst_mean_ps;
  flow->src2dst_mean_ps += (packet_size - src2dst_mean_ps)/flow->src2dst_packets;
  flow->src2dst_stddev_ps += (packet_size - src2dst_mean_ps)*(packet_size - flow->src2dst_mean_ps);
}

/**
 * flow_init_src2dst_piat_ms: Flow src2dst piat statistics initializer.
 */
static void flow_init_src2dst_piat_ms(struct nf_flow *flow, uint64_t src2dst_piat_ms) {
  flow->src2dst_min_piat_ms += src2dst_piat_ms;
  flow->src2dst_mean_piat_ms += src2dst_piat_ms;
  flow->src2dst_max_piat_ms += src2dst_piat_ms;
}

/**
 * flow_update_src2dst_piat_ms: Flow src2dst piat statistics updater.
 */
static void flow_update_src2dst_piat_ms(struct nf_flow *flow, uint64_t src2dst_piat_ms) {
  if (src2dst_piat_ms > flow->src2dst_max_piat_ms) flow->src2dst_max_piat_ms = src2dst_piat_ms;
  if (src2dst_piat_ms < flow->src2dst_min_piat_ms) flow->src2dst_min_piat_ms = src2dst_piat_ms;
  double src2dst_mean_piat_ms = flow->src2dst_mean_piat_ms;
  flow->src2dst_mean_piat_ms += (src2dst_piat_ms - src2dst_mean_piat_ms)/(flow->src2dst_packets-1);
  flow->src2dst_stddev_piat_ms += (src2dst_piat_ms - src2dst_mean_piat_ms)
                                  * (src2dst_piat_ms - flow->src2dst_mean_piat_ms);
}

/**
 * flow_init_dst2src_ps: Flow dst2src packet sizes statistics initializer.
 */
static void flow_init_dst2src_ps(struct nf_flow *flow, uint16_t packet_size) {
  flow->dst2src_min_ps += packet_size;
  flow->dst2src_mean_ps += packet_size;
  flow->dst2src_max_ps += packet_size;
}

/**
 * flow_update_dst2src_ps: Flow dst2src packet sizes statistics updater.
 */
static void flow_update_dst2src_ps(struct nf_flow *flow, uint16_t packet_size) {
  if (packet_size > flow->dst2src_max_ps) flow->dst2src_max_ps = packet_size;
  if (packet_size < flow->dst2src_min_ps) flow->dst2src_min_ps = packet_size;
  double dst2src_mean_ps = flow->dst2src_mean_ps;
  flow->dst2src_mean_ps += (packet_size - dst2src_mean_ps)/flow->dst2src_packets;
  flow->dst2src_stddev_ps += (packet_size - dst2src_mean_ps)*(packet_size - flow->dst2src_mean_ps);
}

/**
 * flow_init_dst2src_piat_ms: Flow dst2src piat statistics initializer.
 */
static void flow_init_dst2src_piat_ms(struct nf_flow *flow, uint64_t dst2src_piat_ms) {
  flow->dst2src_min_piat_ms += dst2src_piat_ms;
  flow->dst2src_mean_piat_ms += dst2src_piat_ms;
  flow->dst2src_max_piat_ms += dst2src_piat_ms;
}

/**
 * flow_update_dst2src_piat_ms: Flow dst2src piat statistics updater.
 */
static void flow_update_dst2src_piat_ms(struct nf_flow *flow, uint64_t dst2src_piat_ms) {
  if (dst2src_piat_ms > flow->dst2src_max_piat_ms) flow->dst2src_max_piat_ms = dst2src_piat_ms;
  if (dst2src_piat_ms < flow->dst2src_min_piat_ms) flow->dst2src_min_piat_ms = dst2src_piat_ms;
  double dst2src_mean_piat_ms = flow->dst2src_mean_piat_ms;
  flow->dst2src_mean_piat_ms += (dst2src_piat_ms - dst2src_mean_piat_ms)/(flow->dst2src_packets-1);
  flow->dst2src_stddev_piat_ms += (dst2src_piat_ms - dst2src_mean_piat_ms) *
                                  (dst2src_piat_ms - flow->dst2src_mean_piat_ms);
}

/**
 * flow_init_bidirectional: Flow bidirectional initializer.
 */
static uint8_t flow_init_bidirectional(struct ndpi_detection_module_struct *dissector, uint8_t n_dissections,
                                       uint16_t splt, uint8_t statistics, uint16_t packet_size, struct nf_flow *flow,
                                       struct nf_packet *packet, uint8_t sync) {
  if (splt) {
    uint8_t splt_init_success = flow_init_splt(flow, splt, packet_size);
    if (!splt_init_success) return 0;
  }

  if (n_dissections) { // we are configured to dissect
    uint8_t init_bidirectional_dissection_success = flow_init_bidirectional_dissection(dissector, n_dissections,
                                                                                       flow, packet, sync);
    if (!init_bidirectional_dissection_success) return 0;
  }
  // Classical flow initialization.
  flow->bidirectional_first_seen_ms = packet->time;
  flow->bidirectional_last_seen_ms = packet->time;
  flow->tunnel_id = packet->tunnel_id;
  flow->ip_version = packet->ip_version;
  if (flow->ip_version == 4) {
	inet_ntop(AF_INET, (uint32_t *)&packet->src_ip[0], flow->src_ip_str, sizeof(flow->src_ip_str));
	inet_ntop(AF_INET, (uint32_t *)&packet->dst_ip[0], flow->dst_ip_str, sizeof(flow->dst_ip_str));
  } else {
	inet_ntop(AF_INET6, (struct sockaddr_in6 *)&packet->src_ip[0], flow->src_ip_str, sizeof(flow->src_ip_str));
	inet_ntop(AF_INET6, (struct sockaddr_in6 *)&packet->dst_ip[0], flow->dst_ip_str, sizeof(flow->dst_ip_str));
  }
  flow->src_ip[0] = packet->src_ip[0];
  flow->src_ip[1] = packet->src_ip[1];
  flow->src_mac[0] = packet->src_mac[0];
  flow->src_mac[1] = packet->src_mac[1];
  flow->src_mac[2] = packet->src_mac[2];
  flow->src_mac[3] = packet->src_mac[3];
  flow->src_mac[4] = packet->src_mac[4];
  flow->src_mac[5] = packet->src_mac[5];
  ndpi_snprintf(flow->src_mac_str, sizeof(flow->src_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                packet->src_mac[0], packet->src_mac[1], packet->src_mac[2],
                packet->src_mac[3], packet->src_mac[4], packet->src_mac[5]);
  memcpy(flow->src_oui, flow->src_mac_str, 8);
  flow->src_port = packet->src_port;
  flow->dst_ip[0] = packet->dst_ip[0];
  flow->dst_ip[1] = packet->dst_ip[1];
  flow->dst_mac[0] = packet->dst_mac[0];
  flow->dst_mac[1] = packet->dst_mac[1];
  flow->dst_mac[2] = packet->dst_mac[2];
  flow->dst_mac[3] = packet->dst_mac[3];
  flow->dst_mac[4] = packet->dst_mac[4];
  flow->dst_mac[5] = packet->dst_mac[5];
  ndpi_snprintf(flow->dst_mac_str, sizeof(flow->dst_mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                packet->dst_mac[0], packet->dst_mac[1], packet->dst_mac[2],
                packet->dst_mac[3], packet->dst_mac[4], packet->dst_mac[5]);
  memcpy(flow->dst_oui, flow->dst_mac_str, 8);
  flow->dst_port = packet->dst_port;
  flow->protocol = packet->protocol;
  flow->vlan_id = packet->vlan_id;
  flow->bidirectional_packets = 1;
  flow->bidirectional_bytes += packet_size;
  if (statistics == 1) {
    flow_init_bidirectional_ps(flow, packet_size);
    flow_update_bidirectional_tcp_flags(flow, packet);
  }
  return 1;
}

/**
 * flow_update_bidirectional: Flow bidirectional updater.
 */
static void flow_update_bidirectional(struct ndpi_detection_module_struct *dissector, uint8_t n_dissections, uint16_t splt,
                               uint8_t statistics, uint16_t packet_size, struct nf_flow *flow,
                               struct nf_packet *packet, uint8_t sync) {
  uint64_t bidirectional_piat_ms = packet->time - flow->bidirectional_last_seen_ms;
  packet->delta_time = bidirectional_piat_ms; // This will be exposed as NFPacket feature.
  flow->bidirectional_packets++;
  flow_update_splt(splt, flow, packet, packet_size, bidirectional_piat_ms);
  flow->bidirectional_last_seen_ms = packet->time;
  flow->bidirectional_duration_ms = flow->bidirectional_last_seen_ms - flow->bidirectional_first_seen_ms;
  if (n_dissections) flow_update_bidirectional_dissection(dissector, n_dissections, flow, packet, sync);
  flow->bidirectional_bytes += packet_size;
  if (statistics == 1) {
    flow_update_bidirectional_tcp_flags(flow, packet);
    flow_update_bidirectional_ps(flow, packet_size);
    // Packet interarrival time need at least 2 packets.
    if (flow->bidirectional_packets == 2) flow_init_bidirectional_piat_ms(flow, bidirectional_piat_ms);
    else flow_update_bidirectional_piat_ms(flow, bidirectional_piat_ms);
  }
}

/**
 * flow_init_src2dst: Flow src2dst initializer.
 */
static void flow_init_src2dst(uint8_t statistics, uint16_t packet_size, struct nf_flow *flow, struct nf_packet *packet) {
  flow->src2dst_first_seen_ms = packet->time;
  flow->src2dst_last_seen_ms = packet->time;
  flow->src2dst_packets = 1;
  flow->src2dst_bytes += packet_size;
  if (statistics == 1) {
    flow_init_src2dst_ps(flow, packet_size);
    flow_update_src2dst_tcp_flags(flow, packet);
  }
}

/**
 * flow_update_src2dst: Flow src2dst updater.
 */
static void flow_update_src2dst(uint8_t statistics, uint16_t packet_size, struct nf_flow *flow, struct nf_packet *packet) {
  flow->src2dst_packets++;
  uint64_t src2dst_piat_ms = packet->time - flow->src2dst_last_seen_ms;
  flow->src2dst_last_seen_ms = packet->time;
  flow->src2dst_duration_ms = flow->src2dst_last_seen_ms - flow->src2dst_first_seen_ms;
  flow->src2dst_bytes += packet_size;
  if (statistics == 1) {
    flow_update_src2dst_ps(flow, packet_size);
    flow_update_src2dst_tcp_flags(flow, packet);
    if (flow->src2dst_packets == 2) flow_init_src2dst_piat_ms(flow, src2dst_piat_ms);
    else flow_update_src2dst_piat_ms(flow, src2dst_piat_ms);
  }
}

/**
 * flow_update_dst2src: Flow dst2src updater.
 */
static void flow_update_dst2src(uint8_t statistics, uint16_t packet_size, struct nf_flow *flow, struct nf_packet *packet) {
  flow->dst2src_packets++;
  flow->dst2src_bytes += packet_size;
  if (flow->dst2src_packets == 1) {
    flow->dst2src_first_seen_ms = packet->time;
    flow->dst2src_last_seen_ms = packet->time;
    if (statistics == 1) {
      flow_init_dst2src_ps(flow, packet_size);
      flow_update_dst2src_tcp_flags(flow, packet);
    }
  } else {
    uint64_t dst2src_piat_ms = packet->time - flow->dst2src_last_seen_ms;
    flow->dst2src_last_seen_ms = packet->time;
    flow->dst2src_duration_ms = flow->dst2src_last_seen_ms - flow->dst2src_first_seen_ms;
    if (statistics == 1) {
      flow_update_dst2src_ps(flow, packet_size);
      flow_update_dst2src_tcp_flags(flow, packet);
      if (flow->dst2src_packets == 2) flow_init_dst2src_piat_ms(flow, dst2src_piat_ms);
      else flow_update_dst2src_piat_ms(flow, dst2src_piat_ms);
    }
  }
}


/*
------------------------------------------------------------------------------------------------------------------------
                                           Engine APIs
------------------------------------------------------------------------------------------------------------------------
*/

/***************************************** Capture APIs ***************************************************************/


/**
 * capture_get_interface: load available interface
 */
char * capture_get_interface(char * intf_name) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldev = NULL;
  pcap_if_t *dev = NULL;
  char * if_name;
  if (pcap_findalldevs(&alldev, errbuf) != 0) return NULL;
  dev = alldev;
  while (dev != NULL && (strcmp(dev->name, intf_name) != 0)) {
      if (dev->description != NULL) {
         if (strcmp(dev->description, intf_name) == 0) break; // helper for windows interface name
      }
      dev=dev->next;
  }
  if (dev == NULL) {
    pcap_freealldevs(alldev);
    return NULL;
  } else {
    if_name = strdup(dev->name);
    pcap_freealldevs(alldev);
    return if_name;
  }
}


/**
 * capture_open: Open a pcap file or a specified device.
 */
pcap_t * capture_open(const char * pcap_file, int mode, char * child_error, int socket_buffer_size) {
  pcap_t * pcap_handle = NULL;
  int status; // pcap_set_buffer_size return status
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];
  if (mode == MODE_SINGLE_FILE || mode == MODE_MULTIPLE_FILES) {
    pcap_handle = pcap_open_offline(pcap_file, pcap_error_buffer);
  }
  if (mode == MODE_INTERFACE) {
    pcap_handle = pcap_create(pcap_file, pcap_error_buffer);
    // If the pcap_handle is created successfully and the socket buffer size is greater than 0, set the buffer size.
    if (pcap_handle != NULL && socket_buffer_size > 0){
      status = pcap_set_buffer_size(pcap_handle, socket_buffer_size);
      if (status != 0) {
        ndpi_snprintf(child_error, 256, "%s: %s", pcap_file, pcap_statustostr(status));
        return NULL;
      }
    }
  }
  if (pcap_handle != NULL) {
    return pcap_handle;
  } else {
    ndpi_snprintf(child_error, 256, "%s", pcap_error_buffer);
    return NULL;
  }
}

/**
 * capture_set_fanout: Set fanout mode.
 */
int capture_set_fanout(pcap_t * pcap_handle, int mode, char * child_error, int group_id) {
  int set_fanout = 0;
  if (mode == MODE_SINGLE_FILE || mode == MODE_MULTIPLE_FILES) return set_fanout;
  else {
#ifdef __linux__
    set_fanout = pcap_set_fanout_linux(pcap_handle, 1, 0x8000, (uint16_t) group_id);
    if (set_fanout != 0) {
      pcap_close(pcap_handle);
      ndpi_snprintf(child_error, 256, "%s", "Unable to setup fanout mode.");
    }
#endif
  return set_fanout;
  }
}

/**
 * capture_activate: Activate capture.
 */
int capture_activate(pcap_t * pcap_handle, int mode, char * child_error) {
  int set_activate = 0;
  if (mode == MODE_SINGLE_FILE || mode == MODE_MULTIPLE_FILES) return set_activate;
  else {
    set_activate = pcap_activate(pcap_handle);
    if (set_activate != 0) {
      pcap_close(pcap_handle);
      ndpi_snprintf(child_error, 256, "%s", "Unable to activate source.");
    }
  return set_activate;
  }
}

/**
 * capture_set_timeout: Set buffer timeout.
 */
int capture_set_timeout(pcap_t * pcap_handle, int mode, char * child_error) {
  int set_timeout = 0;
  if (mode == MODE_SINGLE_FILE || mode == MODE_MULTIPLE_FILES) return set_timeout;
  else {
    set_timeout = pcap_set_timeout(pcap_handle, 1000);
    if (set_timeout != 0) {
      pcap_close(pcap_handle);
      ndpi_snprintf(child_error, 256, "Unable to set buffer timeout.");
    }
  return set_timeout;
  }
}

/**
 * capture_set_promisc: Set promisc mode.
 */
int capture_set_promisc(pcap_t * pcap_handle, int mode, char * child_error, int promisc) {
  int set_promisc = 0;
  if (mode == MODE_SINGLE_FILE || mode == MODE_MULTIPLE_FILES) return set_promisc;
  else {
    set_promisc = pcap_set_promisc(pcap_handle, promisc);
    if (set_promisc != 0) {
      pcap_close(pcap_handle);
      ndpi_snprintf(child_error, 256, "Unable to set promisc mode.");
    }
  return set_promisc;
  }
}

/**
 * capture_set_snaplen: Set snaplen.
 */
int capture_set_snaplen(pcap_t * pcap_handle, int mode, char * child_error, unsigned snaplen) {
  int set_snaplen = 0;
  if (mode == MODE_SINGLE_FILE || mode == MODE_MULTIPLE_FILES) return set_snaplen;
  else {
    set_snaplen = pcap_set_snaplen(pcap_handle, snaplen);
    if (set_snaplen != 0) {
      pcap_close(pcap_handle);
      ndpi_snprintf(child_error, 256, "Unable to set snaplen.");
    }
  return set_snaplen;
  }
}

/**
 * capture_set_filter: Configure pcap_t with specified bpf_filter.
 */
int capture_set_filter(pcap_t * pcap_handle, char * bpf_filter, char * child_error) {
  if (bpf_filter != NULL) {
    struct bpf_program fcode;
    if (pcap_compile(pcap_handle, &fcode, bpf_filter, 1, 0xFFFFFF00) < 0) {
      ndpi_snprintf(child_error, 256, "Unable to compile BPF filter.");
      pcap_close(pcap_handle);
      return 1;
    } else {
      if (pcap_setfilter(pcap_handle, &fcode) < 0) {
	    ndpi_snprintf(child_error, 256, "Unable to compile BPF filter.");
	    pcap_close(pcap_handle);
	    return 1;
      } else {
	    return 0;
	  }
    }
  } else {
    return 0;
  }
}

/**
 * capture_next: Get next packet information from pcap handle.
 */
int capture_next(pcap_t * pcap_handle, struct nf_packet *nf_pkt, int decode_tunnels, int n_roots, uint64_t root_idx,
                 int mode) {
  struct pcap_pkthdr *hdr = NULL;
  const uint8_t *data = NULL;
  int rv_handle = pcap_next_ex(pcap_handle, &hdr, &data);
  if (rv_handle == 1) { // Everything is OK.
    // Check Data Link type
    uint64_t time = ((uint64_t) hdr->ts.tv_sec) * TICK_RESOLUTION + hdr->ts.tv_usec / (1000000 / TICK_RESOLUTION);
    int rv_processor = packet_process((int)pcap_datalink(pcap_handle), hdr->caplen, hdr->len, data, decode_tunnels, nf_pkt, n_roots, root_idx, mode, time);
    if (rv_processor == 0) {
        return 0; // Packet ignored due to parsing
    } else if (rv_processor == 1) { // Packet parsed correctly and match root_idx
        return 1;
    } else { // Packet parsed correctly and do not match root_idx, will use it as time ticker
        return 2;
    }
  } else {
    if (rv_handle == 0) {
    // See the following for full explanation:
    // https://github.com/the-tcpdump-group/libpcap/issues/572#issuecomment-576039197
    // We are using blocking mode and a timeout. So libpcap behavior will depend on used capture mechanism
      if ((hdr == NULL) || (data == NULL)) { // Timeout with no packet
        return -1;
      } else { // packet read at buffer timeout
        uint64_t time = ((uint64_t) hdr->ts.tv_sec) * TICK_RESOLUTION + hdr->ts.tv_usec / (1000000 / TICK_RESOLUTION);
        int rv_processor = packet_process((int)pcap_datalink(pcap_handle), hdr->caplen, hdr->len, data, decode_tunnels, nf_pkt, n_roots, root_idx, mode, time);
        if (rv_processor == 0) {
          return 0; // Packet ignored due to parsing
        } else if (rv_processor == 1) { // Packet parsed correctly and match root_idx
          return 1;
        } else { // Packet parsed correctly and do not match root_idx, will use it as time ticker
          return 2;
        }
      }
    }
    if (rv_handle == -2) {
        return -2; // End of file
    }
  }
  return -1;
}

/**
 * capture_stats: Get capture stats.
 */
void capture_stats(pcap_t * pcap_handle, struct nf_stat *nf_statistics, unsigned mode) {
  if (mode == MODE_SINGLE_FILE || mode == MODE_MULTIPLE_FILES) return;
  else {
    struct pcap_stat statistics;
    int ret = pcap_stats(pcap_handle, &statistics);
    if (ret == 0) {
      nf_statistics->received = statistics.ps_recv;
      nf_statistics->dropped = statistics.ps_drop;
      nf_statistics->dropped_by_interface = statistics.ps_ifdrop;
    } else {
      printf("Warning: Error while reading interface performance statistics.");
    }
  }
}

/**
 * capture_close: Close capture handle.
 */
void capture_close(pcap_t * pcap_handle) {
  pcap_breakloop(pcap_handle);
  pcap_close(pcap_handle);
}


/***************************************** Dissector APIs *************************************************************/

/**
 * dissector_init: Dissector initializer.
 */
struct ndpi_detection_module_struct *dissector_init(struct dissector_checker *checker) {
  // Check if headers match the ffi declarations and initialize dissector.
  ndpi_init_prefs init_prefs = ndpi_no_prefs;
  if (checker->flow_size != ndpi_detection_get_sizeof_ndpi_flow_struct()) return NULL;
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
      NDPI_BITMASK_SET_ALL(protos); // Set bitmask for ALL protocols
      ndpi_set_protocol_detection_bitmask2(dissector, &protos);
      ndpi_finalize_initialization(dissector);
    }
}

/**
 * dissector_cleanup: Dissector cleaner.
 */
void dissector_cleanup(struct ndpi_detection_module_struct *dissector) {
  if (dissector != NULL) ndpi_exit_detection_module(dissector);
}


/***************************************** Meter APIs *****************************************************************/

/**
 * meter_initialize_flow: Initialize flow based on packet values and set packet direction.
 */
struct nf_flow *meter_initialize_flow(struct nf_packet *packet, uint8_t accounting_mode, uint8_t statistics,
                                      uint16_t splt, uint8_t n_dissections,
                                      struct ndpi_detection_module_struct *dissector, uint8_t sync) {
  struct nf_flow *flow = (struct nf_flow*)ndpi_malloc(sizeof(struct nf_flow));
  if (flow == NULL) return NULL; // not enough memory for flow.
  memset(flow, 0, sizeof(struct nf_flow));
  // All packet sizes and bytes related metrics are reported according to user specified mode.
  // This will allow us to provide a flexible choice without duplicating unnecessary information.
  uint16_t packet_size = flow_get_packet_size(packet, accounting_mode);
  uint8_t flow_init_bidirectional_success = flow_init_bidirectional(dissector, n_dissections, splt, statistics,
                                                                    packet_size, flow, packet, sync);
  if (!flow_init_bidirectional_success) return NULL;
  flow_init_src2dst(statistics, packet_size, flow, packet);
  return flow; // we return a pointer to the created flow in order to be cached by Python side.
}

/**
 * meter_update_flow: Check expiration state, and update flow based on packet values if case of active one.
 */
uint8_t meter_update_flow(struct nf_flow *flow, struct nf_packet *packet, uint64_t idle_timeout, uint64_t active_timeout,
                          uint8_t accounting_mode, uint8_t statistics, uint16_t splt, uint8_t n_dissections,
                          struct ndpi_detection_module_struct *dissector, uint8_t sync) {
  uint8_t expired = flow_expiration_handler(flow, packet, idle_timeout, active_timeout);
  if (expired) return expired;
  flow_set_packet_direction(flow, packet);
  uint16_t packet_size = flow_get_packet_size(packet, accounting_mode);
  flow_update_bidirectional(dissector, n_dissections, splt, statistics, packet_size, flow, packet, sync);
  if (packet->direction == 0) flow_update_src2dst(statistics, packet_size, flow, packet);
  else flow_update_dst2src(statistics, packet_size, flow, packet);
  return 0; // Update done, we return 0.
}

/**
 * meter_expire_flow: Flow expiration. Mainly to guess idle flows that were not detected.
 */
void meter_expire_flow(struct nf_flow *flow, uint8_t n_dissections, struct ndpi_detection_module_struct *dissector) {
  if (n_dissections) {
    if ((flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) && (flow->detection_completed == 0)) {
      flow->detected_protocol = ndpi_detection_giveup(dissector, flow->ndpi_flow, 1, &flow->guessed);
    }
    flow_bidirectional_dissection_collect_info(dissector, flow);
    flow->detection_completed = 1; // IMPORTANT: This will force copy on non sync mode.
  }
}

/**
 * meter_free_flow: Flow structure freer.
 */
void meter_free_flow(struct nf_flow *flow, uint8_t n_dissections, uint16_t splt, uint8_t full) {
  if (full) {
    if (n_dissections) flow_free_ndpi_data(flow);
    if (splt) flow_free_splt_data(flow);
    ndpi_free(flow);
    flow = NULL;
  } else { // SPLT only
    flow_free_splt_data(flow);
  }
}

/**
 * engine_version: return engine library version.
 */
const char *engine_lib_version(void) {
  return "6.5.4";
}

/**
 * engine_version: return engine ndpi library version.
 */
const char *engine_lib_ndpi_version(void) {
  return ndpi_revision();
}

/**
 * engine_version: return engine libpcap version.
 */
const char *engine_lib_pcap_version(void) {
  return pcap_lib_version();
}