/*
------------------------------------------------------------------------------------------------------------------------
engine_cc.h
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

//CFFI_ENGINE_EXCLUDE
#ifndef __ENGINE_CC_H__
#define __ENGINE_CC_H__
//CFFI_ENGINE_EXCLUDE

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

pcap_t * capture_open(const uint8_t * pcap_file, int mode, char * child_error);
int capture_activate(pcap_t * pcap_handle, int mode, char * child_error);
int capture_next(pcap_t * pcap_handle, struct nf_packet *nf_pkt, int decode_tunnels, int n_roots, uint64_t root_idx,
                 int mode);
void capture_close(pcap_t * pcap_handle);
void capture_stats(pcap_t * pcap_handle, struct nf_stat *nf_statistics, unsigned mode);
int capture_set_fanout(pcap_t * pcap_handle, int mode, char * child_error, int group_id);
int capture_set_timeout(pcap_t * pcap_handle, int mode, char * child_error);
int capture_set_promisc(pcap_t * pcap_handle, int mode, char * child_error, int promisc);
int capture_set_snaplen(pcap_t * pcap_handle, int mode, char * child_error, unsigned snaplen);
int capture_set_filter(pcap_t * pcap_handle, char * bpf_filter, char * child_error);

struct ndpi_detection_module_struct *dissector_init(struct dissector_checker *checker);
void dissector_configure(struct ndpi_detection_module_struct *dissector);
void dissector_cleanup(struct ndpi_detection_module_struct *dissector);

struct nf_flow *meter_initialize_flow(struct nf_packet *packet, uint8_t accounting_mode, uint8_t statistics,
                                      uint8_t splt, uint8_t n_dissections,
                                      struct ndpi_detection_module_struct *dissector, uint8_t sync);
uint8_t meter_update_flow(struct nf_flow *flow, struct nf_packet *packet, uint64_t idle_timeout, uint64_t active_timeout,
                          uint8_t accounting_mode, uint8_t statistics, uint8_t splt, uint8_t n_dissections,
                          struct ndpi_detection_module_struct *dissector, uint8_t sync);
void meter_expire_flow(struct nf_flow *flow, uint8_t n_dissections, struct ndpi_detection_module_struct *dissector);
void meter_free_flow(struct nf_flow *flow, uint8_t n_dissections, uint8_t splt, uint8_t full);
//CFFI_ENGINE_EXCLUDE
#endif // __ENGINE_CC_H__
//CFFI_ENGINE_EXCLUDE
