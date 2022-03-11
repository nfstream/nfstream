"""
------------------------------------------------------------------------------------------------------------------------
engine.py
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
"""

from os.path import abspath, dirname
from psutil import net_if_addrs
import cffi

ENGINE_PATH = dirname(abspath(__file__)) + '/engine_cc.so'
NPCAP_PATH = "C:\\Windows\\System32\\Npcap\\wpcap.dll"

# We declare here all headers and APIs of native nfstream, This will include:
#   - headers and APIs for capture stage (packet capture and processing).
#   - headers and APIs for nDPI (the dissection part).
#   - headers and APIs for Metering stage (flow intialization, update, expiration and cleaning)

# We group it in an "engine" initialized by meter as start in order to share the same ffi instance between stages.

# For windows platform, nfstream is based on npcap library. As npcap do not allow redistribution without having a valid
# redistribution licence, we cannot link it statically to the nfstream engine lib as we do for UNIX based system with
# libpcap.
# Consequently, our approach is as follows:
# - We still link statically nDPI and its dependencies to the engine lib.
# - For capture part (capture API), we move to a pure Python interface in ABI mode with the npcap dll
#   installed by the user.

cc_capture_headers = """
struct pcap;

typedef struct pcap pcap_t;

struct bpf_insn;
struct bpf_program {
  unsigned int bf_len;
  struct bpf_insn *bf_insns;
};

struct pcap_addr {
  struct pcap_addr *next;
  struct sockaddr *addr;
  struct sockaddr *netmask;
  struct sockaddr *broadaddr;
  struct sockaddr *dstaddr;
};

typedef struct pcap_addr pcap_addr_t;

struct pcap_if {
  struct pcap_if *next;
  char *name;
  char *description;
  pcap_addr_t *addresses;
  int flags;
};

struct pcap_stat {
  unsigned int recv;
  unsigned int drop;
  unsigned int ifdrop;
};

typedef struct pcap_if pcap_if_t;

struct pcap_pkthdr {
  long tv_sec;
  long tv_usec;
  unsigned int caplen;
  unsigned int len;
};

typedef struct nf_packet {
  uint8_t direction;
  uint64_t time;
  uint64_t delta_time;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
  uint16_t vlan_id;
  char src_ip_str[48], dst_ip_str[48], src_mac[18], src_oui[9], dst_mac[18], dst_oui[9];
  uint8_t ip_version;
  uint16_t fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1; /* TCP Flags */
  uint16_t raw_size;
  uint16_t ip_size;
  uint16_t transport_size;
  uint16_t payload_size;
  uint16_t ip_content_len;
  uint8_t *ip_content;
  unsigned tunnel_id;
} nf_packet_t;

typedef struct nf_stat {
  unsigned received;
  unsigned dropped;
  unsigned dropped_by_interface;
} nf_stat_t;
"""

cc_dissector_headers_packed = """
struct ndpi_iphdr {
  uint8_t ihl:4, version:4;
  uint8_t tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
};

struct ndpi_in6_addr {
  union {
    uint8_t   u6_addr8[16];
    uint16_t  u6_addr16[8];
    uint32_t  u6_addr32[4];
    uint64_t  u6_addr64[2];
  } u6_addr;
};

struct ndpi_ip6_hdrctl {
  uint32_t ip6_un1_flow;
  uint16_t ip6_un1_plen;
  uint8_t ip6_un1_nxt;
  uint8_t ip6_un1_hlim;
};

struct ndpi_ipv6hdr {
  struct ndpi_ip6_hdrctl ip6_hdr;
  struct ndpi_in6_addr ip6_src;
  struct ndpi_in6_addr ip6_dst;
};

struct ndpi_tcphdr
{
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
};

struct ndpi_udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
};

struct tinc_cache_entry {
  uint32_t src_address;
  uint32_t dst_address;
  uint16_t dst_port;
};
"""

cc_dissector_headers = """
#define NDPI_MAX_NUM_TLS_APPL_BLOCKS            8
#define NDPI_PROTOCOL_IRC_MAXPORT               8
#define JABBER_MAX_STUN_PORTS                   6
#define NUM_CUSTOM_CATEGORIES                   5
#define CUSTOM_CATEGORY_LABEL_LEN               32
#define NDPI_CIPHER_SAFE                        0
#define NDPI_CIPHER_WEAK                        1
#define NDPI_CIPHER_INSECURE                    2
#define MAX_NUM_TLS_SIGNATURE_ALGORITHMS        16

typedef enum {
  NDPI_LOG_ERROR,
  NDPI_LOG_TRACE,
  NDPI_LOG_DEBUG,
  NDPI_LOG_DEBUG_EXTRA
} ndpi_log_level_t;

typedef enum {
  NDPI_NO_RISK = 0,
  NDPI_URL_POSSIBLE_XSS,
  NDPI_URL_POSSIBLE_SQL_INJECTION,
  NDPI_URL_POSSIBLE_RCE_INJECTION,
  NDPI_BINARY_APPLICATION_TRANSFER,
  NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT,
  NDPI_TLS_SELFSIGNED_CERTIFICATE,
  NDPI_TLS_OBSOLETE_VERSION,
  NDPI_TLS_WEAK_CIPHER,
  NDPI_TLS_CERTIFICATE_EXPIRED,
  NDPI_TLS_CERTIFICATE_MISMATCH,
  NDPI_HTTP_SUSPICIOUS_USER_AGENT,
  NDPI_HTTP_NUMERIC_IP_HOST,
  NDPI_HTTP_SUSPICIOUS_URL,
  NDPI_HTTP_SUSPICIOUS_HEADER,
  NDPI_TLS_NOT_CARRYING_HTTPS,
  NDPI_SUSPICIOUS_DGA_DOMAIN,
  NDPI_MALFORMED_PACKET,
  NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER,
  NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER,
  NDPI_SMB_INSECURE_VERSION,
  NDPI_TLS_SUSPICIOUS_ESNI_USAGE,
  NDPI_UNSAFE_PROTOCOL,
  NDPI_DNS_SUSPICIOUS_TRAFFIC,
  NDPI_TLS_MISSING_SNI,
  NDPI_HTTP_SUSPICIOUS_CONTENT,
  NDPI_RISKY_ASN,
  NDPI_RISKY_DOMAIN,
  NDPI_MALICIOUS_JA3,
  NDPI_MALICIOUS_SHA1_CERTIFICATE,
  NDPI_DESKTOP_OR_FILE_SHARING_SESSION,
  NDPI_TLS_UNCOMMON_ALPN,
  NDPI_TLS_CERT_VALIDITY_TOO_LONG,
  NDPI_TLS_SUSPICIOUS_EXTENSION,
  NDPI_TLS_FATAL_ALERT,
  NDPI_SUSPICIOUS_ENTROPY,
  NDPI_CLEAR_TEXT_CREDENTIALS,
  NDPI_DNS_LARGE_PACKET,
  NDPI_DNS_FRAGMENTED,
  NDPI_INVALID_CHARACTERS,
  NDPI_POSSIBLE_EXPLOIT,
  NDPI_TLS_CERTIFICATE_ABOUT_TO_EXPIRE,
  NDPI_PUNYCODE_IDN,
  NDPI_ERROR_CODE_DETECTED,
  NDPI_HTTP_CRAWLER_BOT,
  NDPI_ANONYMOUS_SUBSCRIBER,
  NDPI_MAX_RISK
} ndpi_risk_enum;

typedef uint64_t ndpi_risk;

typedef enum {
  ndpi_preorder,
  ndpi_postorder,
  ndpi_endorder,
  ndpi_leaf
} ndpi_VISIT;

typedef struct node_t {
  char *key;
  struct node_t *left, *right;
} ndpi_node;

typedef uint32_t ndpi_ndpi_mask;

typedef struct ndpi_protocol_bitmask_struct {
  ndpi_ndpi_mask fds_bits[16];
} NDPI_PROTOCOL_BITMASK;

typedef long int time_t;

typedef enum {
  NDPI_HTTP_METHOD_UNKNOWN = 0,
  NDPI_HTTP_METHOD_OPTIONS,
  NDPI_HTTP_METHOD_GET,
  NDPI_HTTP_METHOD_HEAD,
  NDPI_HTTP_METHOD_PATCH,
  NDPI_HTTP_METHOD_POST,
  NDPI_HTTP_METHOD_PUT,
  NDPI_HTTP_METHOD_DELETE,
  NDPI_HTTP_METHOD_TRACE,
  NDPI_HTTP_METHOD_CONNECT,
  NDPI_HTTP_METHOD_RPC_IN_DATA,
  NDPI_HTTP_METHOD_RPC_OUT_DATA,
} ndpi_http_method;

struct ndpi_lru_cache_entry {
  uint32_t key; /* Store the whole key to avoid ambiguities */
  uint32_t is_full:1, value:16, pad:15;
};

struct ndpi_lru_cache {
  uint32_t num_entries;
  struct ndpi_lru_cache_entry *entries;
};

typedef union
{
  uint32_t ipv4;
  struct ndpi_in6_addr ipv6;
} ndpi_ip_addr_t;

typedef struct message {
  uint8_t *buffer;
  unsigned buffer_len, buffer_used;
  uint32_t next_seq[2];
} message_t;
    
struct ndpi_flow_tcp_struct {
  struct {
    uint8_t auth_found:1, auth_failed:1, auth_tls:1, auth_done:1, _pad:4;
    char username[32], password[16];
  } ftp_imap_pop_smtp;
  uint16_t smtp_command_bitmask;
  uint16_t pop_command_bitmask;
  uint8_t wa_matched_so_far;
  uint8_t irc_stage;
  uint8_t h323_valid_packets;
  uint8_t gnutella_msg_id[3];
  uint32_t irc_3a_counter:3;
  uint32_t irc_stage2:5;
  uint32_t irc_direction:2;
  uint32_t irc_0x1000_full:1;
  uint32_t usenet_stage:2;
  uint32_t http_stage:2;
  uint32_t http_empty_line_seen:1;
  uint32_t gnutella_stage:2;
  uint32_t ssh_stage:3;
  uint32_t vnc_stage:2;
  uint32_t telnet_stage:2;
  struct {
    message_t message;
    uint8_t certificate_processed:1, fingerprint_set:1, _pad:6;
    uint8_t num_tls_blocks;
    int16_t tls_application_blocks_len[NDPI_MAX_NUM_TLS_APPL_BLOCKS];
  } tls;
  uint32_t postgres_stage:3;
  uint32_t seen_syn:1;
  uint32_t seen_syn_ack:1;
  uint32_t seen_ack:1;
  uint32_t icecast_stage:1;
  uint32_t dofus_stage:1;
  uint32_t fiesta_stage:2;
  uint32_t wow_stage:2;
  uint32_t shoutcast_stage:2;
  uint32_t rtp_special_packets_seen:1;
  uint32_t mail_pop_stage:2;
  uint32_t mail_imap_stage:3, mail_imap_starttls:2;
  uint32_t soap_stage:1;
  uint8_t skype_packet_id;
  uint8_t lotus_notes_packet_id;
  uint8_t teamviewer_stage;
  uint8_t prev_zmq_pkt_len;
  uint8_t prev_zmq_pkt[10];
  uint32_t ppstream_stage:3;
  uint8_t memcached_matches;
  uint8_t nest_log_sink_matches;
};

struct ndpi_flow_udp_struct {
  uint32_t ppstream_stage:3;
  uint32_t halflife2_stage:2;
  uint32_t tftp_stage:2;
  uint32_t aimini_stage:5;
  uint32_t xbox_stage:1;
  uint8_t skype_packet_id;
  uint8_t skype_crc[4];
  uint8_t teamviewer_stage;
  uint8_t eaq_pkt_id;
  uint32_t eaq_sequence;
  uint32_t rx_conn_epoch;
  uint32_t rx_conn_id;
  uint8_t memcached_matches;
  uint8_t wireguard_stage;
  uint32_t wireguard_peer_index[2];
  uint8_t *quic_reasm_buf;
  uint32_t quic_reasm_buf_len;
  uint8_t csgo_strid[18], csgo_state, csgo_s2;
  uint32_t csgo_id2;
  uint8_t rdp_to_srv[3], rdp_from_srv[3], rdp_to_srv_pkts, rdp_from_srv_pkts;
  uint8_t imo_last_one_byte_pkt, imo_last_bytes;
};

struct ndpi_int_one_line_struct {
  const uint8_t *ptr;
  uint16_t len;
};

struct ndpi_packet_struct {
  const struct ndpi_iphdr *iph;
  const struct ndpi_ipv6hdr *iphv6;
  const struct ndpi_tcphdr *tcp;
  const struct ndpi_udphdr *udp;
  const uint8_t *generic_l4_ptr;
  const uint8_t *payload;
  uint64_t current_time_ms;
  struct ndpi_int_one_line_struct line[64];
  struct ndpi_int_one_line_struct host_line;
  struct ndpi_int_one_line_struct forwarded_line;
  struct ndpi_int_one_line_struct referer_line;
  struct ndpi_int_one_line_struct content_line;
  struct ndpi_int_one_line_struct content_disposition_line;
  struct ndpi_int_one_line_struct accept_line;
  struct ndpi_int_one_line_struct authorization_line;
  struct ndpi_int_one_line_struct user_agent_line;
  struct ndpi_int_one_line_struct http_url_name;
  struct ndpi_int_one_line_struct http_encoding;
  struct ndpi_int_one_line_struct http_transfer_encoding;
  struct ndpi_int_one_line_struct http_contentlen;
  struct ndpi_int_one_line_struct http_cookie;
  struct ndpi_int_one_line_struct http_origin;
  struct ndpi_int_one_line_struct http_x_session_type;
  struct ndpi_int_one_line_struct server_line;
  struct ndpi_int_one_line_struct http_method;
  struct ndpi_int_one_line_struct http_response;
  uint8_t http_num_headers;
  uint16_t l3_packet_len;
  uint16_t payload_packet_len;
  uint16_t parsed_lines;
  uint16_t empty_line_position;
  uint8_t tcp_retransmission;
  uint8_t packet_lines_parsed_complete:1,
  packet_direction:1, empty_line_position_set:1, http_check_content:1, pad:4;
};

struct ndpi_detection_module_struct;
struct ndpi_flow_struct;

struct ndpi_call_function_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;
  void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
  uint32_t ndpi_selection_bitmask;
  uint16_t ndpi_protocol_id;
  uint8_t detection_feature;
};

struct ndpi_subprotocol_conf_struct {
  void (*func) (struct ndpi_detection_module_struct *, char *attr, char *value, int protocol_id);
};

typedef enum {
  NDPI_PROTOCOL_SAFE = 0,
  NDPI_PROTOCOL_ACCEPTABLE,
  NDPI_PROTOCOL_FUN,
  NDPI_PROTOCOL_UNSAFE, 
  NDPI_PROTOCOL_POTENTIALLY_DANGEROUS,
  NDPI_PROTOCOL_DANGEROUS,
  NDPI_PROTOCOL_TRACKER_ADS,
  NDPI_PROTOCOL_UNRATED
} ndpi_protocol_breed_t;

typedef enum {
  NDPI_PROTOCOL_CATEGORY_UNSPECIFIED = 0,
  NDPI_PROTOCOL_CATEGORY_MEDIA,
  NDPI_PROTOCOL_CATEGORY_VPN,
  NDPI_PROTOCOL_CATEGORY_MAIL,
  NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,
  NDPI_PROTOCOL_CATEGORY_WEB,
  NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,
  NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,
  NDPI_PROTOCOL_CATEGORY_GAME,
  NDPI_PROTOCOL_CATEGORY_CHAT,
  NDPI_PROTOCOL_CATEGORY_VOIP,
  NDPI_PROTOCOL_CATEGORY_DATABASE,
  NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,
  NDPI_PROTOCOL_CATEGORY_CLOUD,
  NDPI_PROTOCOL_CATEGORY_NETWORK,
  NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,
  NDPI_PROTOCOL_CATEGORY_RPC,
  NDPI_PROTOCOL_CATEGORY_STREAMING,
  NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,
  NDPI_PROTOCOL_CATEGORY_SW_UPDATE,
  NDPI_PROTOCOL_CATEGORY_CUSTOM_1,
  NDPI_PROTOCOL_CATEGORY_CUSTOM_2,
  NDPI_PROTOCOL_CATEGORY_CUSTOM_3,
  NDPI_PROTOCOL_CATEGORY_CUSTOM_4,
  NDPI_PROTOCOL_CATEGORY_CUSTOM_5,
  NDPI_PROTOCOL_CATEGORY_MUSIC,
  NDPI_PROTOCOL_CATEGORY_VIDEO,
  NDPI_PROTOCOL_CATEGORY_SHOPPING,
  NDPI_PROTOCOL_CATEGORY_PRODUCTIVITY,
  NDPI_PROTOCOL_CATEGORY_FILE_SHARING,
  NDPI_PROTOCOL_CATEGORY_CONNECTIVITY_CHECK,
  NDPI_PROTOCOL_CATEGORY_IOT_SCADA,
  CUSTOM_CATEGORY_MINING           = 99,
  CUSTOM_CATEGORY_MALWARE          = 100,
  CUSTOM_CATEGORY_ADVERTISEMENT    = 101,
  CUSTOM_CATEGORY_BANNED_SITE      = 102,
  CUSTOM_CATEGORY_SITE_UNAVAILABLE = 103,
  CUSTOM_CATEGORY_ALLOWED_SITE     = 104,
  CUSTOM_CATEGORY_ANTIMALWARE      = 105,
  NDPI_PROTOCOL_NUM_CATEGORIES,
  NDPI_PROTOCOL_ANY_CATEGORY
} ndpi_protocol_category_t;

typedef struct ndpi_proto_defaults {
  char *protoName;
  ndpi_protocol_category_t protoCategory;
  uint8_t isClearTextProto;
  uint16_t *subprotocols;
  uint32_t subprotocol_count;
  uint16_t protoId, protoIdx;
  uint16_t tcp_default_ports[5], udp_default_ports[5];
  ndpi_protocol_breed_t protoBreed;
  void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
} ndpi_proto_defaults_t;

typedef struct ndpi_default_ports_tree_node {
  ndpi_proto_defaults_t *proto;
  uint8_t customUserProto;
  uint16_t default_port;
} ndpi_default_ports_tree_node_t;

typedef struct _ndpi_automa {
  void *ac_automa;
} ndpi_automa;

typedef struct ndpi_proto {
  uint16_t master_protocol;
  ndpi_protocol_category_t category;
} ndpi_protocol;

typedef enum {
  ndpi_stun_cache,
  ndpi_hangout_cache
} ndpi_lru_cache_type;

struct ndpi_detection_module_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  uint32_t current_ts;
  uint16_t max_packets_to_process;
  uint16_t num_tls_blocks_to_follow;
  uint8_t skip_tls_blocks_until_change_cipher:1, enable_ja3_plus:1, _notused:6;
  char custom_category_labels[NUM_CUSTOM_CATEGORIES][CUSTOM_CATEGORY_LABEL_LEN];
  struct ndpi_call_function_struct callback_buffer[250];
  uint32_t callback_buffer_size;
  struct ndpi_call_function_struct callback_buffer_tcp_no_payload[250];
  uint32_t callback_buffer_size_tcp_no_payload;
  struct ndpi_call_function_struct callback_buffer_tcp_payload[250];
  uint32_t callback_buffer_size_tcp_payload;
  struct ndpi_call_function_struct callback_buffer_udp[250];
  uint32_t callback_buffer_size_udp;
  struct ndpi_call_function_struct callback_buffer_non_tcp_udp[250];
  uint32_t callback_buffer_size_non_tcp_udp;
  ndpi_default_ports_tree_node_t *tcpRoot, *udpRoot;
  ndpi_log_level_t ndpi_log_level;
  uint32_t tcp_max_retransmission_window_size;
  struct ndpi_subprotocol_conf_struct subprotocol_conf[250];
  unsigned ndpi_num_supported_protocols;
  unsigned ndpi_num_custom_protocols;
  int ac_automa_finalized;
  ndpi_automa host_automa,
  risky_domain_automa, tls_cert_subject_automa,
  malicious_ja3_automa, malicious_sha1_automa,
  host_risk_mask_automa, common_alpns_automa;
  void *ip_risk_mask_ptree;
  void *ip_risk_ptree;
  struct {
    ndpi_automa hostnames, hostnames_shadow;
    void *ipAddresses, *ipAddresses_shadow;
    uint8_t categories_loaded;
  } custom_categories;
  void *protocols_ptree;
  uint8_t ip_version_limit;
  struct ndpi_lru_cache *ookla_cache;
  struct cache *tinc_cache;
  struct ndpi_lru_cache *bittorrent_cache;
  struct ndpi_lru_cache *zoom_cache;
  struct ndpi_lru_cache *stun_cache;  
  struct ndpi_lru_cache *tls_cert_cache;
  struct ndpi_lru_cache *mining_cache;
  struct ndpi_lru_cache *msteams_cache;
  ndpi_proto_defaults_t proto_defaults[512];
  uint8_t direction_detect_disable:1, /* disable internal detection of packet direction */ _pad:7;
  void (*ndpi_notify_lru_add_handler_ptr)(ndpi_lru_cache_type cache_type, uint32_t proto, uint32_t app_proto);
  void *mmdb_city, *mmdb_as;
  uint8_t mmdb_city_loaded, mmdb_as_loaded;
  struct ndpi_packet_struct packet;
};

typedef enum {
  ndpi_cipher_safe = NDPI_CIPHER_SAFE,
  ndpi_cipher_weak = NDPI_CIPHER_WEAK,
  ndpi_cipher_insecure = NDPI_CIPHER_INSECURE
} ndpi_cipher_weakness;

struct tls_heuristics {
  uint8_t is_safari_tls:1, is_firefox_tls:1, is_chrome_tls:1, notused:5;
};

typedef enum {
  NDPI_CONFIDENCE_UNKNOWN = 0,
  NDPI_CONFIDENCE_MATCH_BY_PORT,
  NDPI_CONFIDENCE_MATCH_BY_IP,
  NDPI_CONFIDENCE_DPI_CACHE,
  NDPI_CONFIDENCE_DPI,
  NDPI_CONFIDENCE_MAX,
} ndpi_confidence_t;

struct ndpi_flow_struct {
  uint16_t detected_protocol_stack[2];
  uint16_t guessed_protocol_id, guessed_host_protocol_id, guessed_category, guessed_header_category;
  uint8_t l4_proto, protocol_id_already_guessed:1, host_already_guessed:1, fail_with_unknown:1,
  init_finished:1, setup_packet_direction:1, packet_direction:1, check_extra_packets:1, is_ipv6:1;
  ndpi_confidence_t confidence;
  uint32_t next_tcp_seq_nr[2];
  uint32_t saddr, daddr;
  uint16_t sport, dport;
  uint8_t max_extra_packets_to_check;
  uint8_t num_extra_packets_checked;
  uint16_t num_processed_pkts; /* <= WARNING it can wrap but we do expect people to giveup earlier */
  int (*extra_packets_func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
  uint64_t last_packet_time_ms;
  union {
    struct ndpi_flow_tcp_struct tcp;
    struct ndpi_flow_udp_struct udp;
  } l4;
  float entropy;
  char flow_extra_info[16];
  uint8_t host_server_name[80];
  uint8_t initial_binary_bytes[8], initial_binary_bytes_len;
  uint8_t risk_checked:1, ip_risk_mask_evaluated:1, host_risk_mask_evaluated:1, tree_risk_checked:1, _notused:4;
  ndpi_risk risk_mask; /* Stores the flow risk mask for flow peers */
  ndpi_risk risk; /* Issues found with this flow [bitmask of ndpi_risk] */
  struct {
    ndpi_http_method method;
    uint8_t request_version;
    uint16_t response_status_code;
    char *url, *content_type, *request_content_type, *user_agent;
    char *detected_os;
    char *nat_ip;
  } http;
  struct {    
    char *pktbuf;
    uint16_t pktbuf_maxlen, pktbuf_currlen;
  } kerberos_buf;
    struct {
    uint8_t num_udp_pkts, num_binding_requests;
    uint16_t num_processed_pkts;
  } stun;
  union {
    struct {
      uint8_t num_queries, num_answers, reply_code, is_query;
      uint16_t query_type, query_class, rsp_type;
      ndpi_ip_addr_t rsp_addr; /* The first address in a DNS response packet */
    } dns;
    struct {
      uint8_t request_code;
      uint8_t version;
    } ntp;
    struct {
      char hostname[48], domain[48], username[48];
    } kerberos;
    struct {
      char *server_names, *alpn, *tls_supported_versions, *issuerDN, *subjectDN;
      uint32_t notBefore, notAfter;
      char ja3_client[33], ja3_server[33];
      uint16_t server_cipher;
      uint8_t sha1_certificate_fingerprint[20];
      uint8_t hello_processed:1, subprotocol_detected:1, _pad:6;
      struct tls_heuristics browser_heuristics;
      uint16_t ssl_version, server_names_len;
      struct {
        uint16_t cipher_suite;
        char *esni;
      } encrypted_sni;
      ndpi_cipher_weakness server_unsafe_cipher;
      } tls_quic;
    struct {
      char client_signature[48], server_signature[48];
      char hassh_client[33], hassh_server[33];
    } ssh;
    struct {
      uint8_t username_detected:1, username_found:1, password_detected:1, password_found:1, pad:4;
      uint8_t character_id;
      char username[32], password[32];
    } telnet;
    struct {
      char version[32];
    } ubntac2;
    struct {
      uint8_t hash[20];
    } bittorrent;
    struct {
      uint8_t nat_ip[24];
    } http;
    struct {
      char fingerprint[48];
      char class_ident[48];
    } dhcp;
  } protos;
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;
  ndpi_protocol_category_t category;
  uint8_t redis_s2d_first_char, redis_d2s_first_char;
  uint16_t packet_counter;
  uint16_t packet_direction_counter[2];
  uint16_t byte_counter[2];
  uint8_t bittorrent_stage;
  uint8_t bt_check_performed:1;
  uint8_t directconnect_stage:2;
  uint8_t http_detected:1;
  uint8_t rtsprdt_stage:2;
  uint8_t zattoo_stage:3;
  uint8_t thunder_stage:2;
  uint8_t florensia_stage:1;
  uint8_t socks5_stage:2, socks4_stage:2;
  uint8_t edonkey_stage:2;
  uint8_t ftp_control_stage:2;
  uint8_t rtmp_stage:2;
  uint16_t steam_stage:3, steam_stage1:3, steam_stage2:2, steam_stage3:2;
  uint8_t starcraft_udp_stage : 3;	// 0-7
  uint8_t z3950_stage : 2; // 0-3
  uint8_t ovpn_session_id[8];
  uint8_t ovpn_counter;
  uint8_t tinc_state;
  struct tinc_cache_entry tinc_cache_entry;
};

typedef struct dissector_checker {
  uint32_t flow_size;
  uint32_t id_size;
  uint32_t flow_tcp_size;
  uint32_t flow_udp_size;
} dissector_checker_t;
"""

cc_meter_headers = """
typedef struct nf_flow {
  char src_ip[48], src_mac[18], src_oui[9];
  uint16_t src_port;
  char dst_ip[48], dst_mac[18], dst_oui[9];
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
"""

cc_capture_apis = """
int pcap_findalldevs(pcap_if_t **, char *);
void pcap_freealldevs(pcap_if_t *);
pcap_t * capture_open(const uint8_t * pcap_file, int mode, char * child_error);
int capture_set_fanout(pcap_t * pcap_handle, int mode, char * child_error, int group_id);
int capture_set_timeout(pcap_t * pcap_handle, int mode, char * child_error);
int capture_set_promisc(pcap_t * pcap_handle, int mode, char * child_error, int promisc);
int capture_set_snaplen(pcap_t * pcap_handle, int mode, char * child_error, unsigned snaplen);
int capture_set_filter(pcap_t * pcap_handle, char * bpf_filter, char * child_error);
int capture_next(pcap_t * pcap_handle, struct nf_packet *nf_pkt, int decode_tunnels, int n_roots, uint64_t root_idx, 
                 int mode);
void capture_stats(pcap_t * pcap_handle, struct nf_stat *nf_statistics, unsigned mode);
void capture_close(pcap_t * pcap_handle);
int capture_activate(pcap_t * pcap_handle, int mode, char * child_error);
int pcap_set_promisc(pcap_t *, int);
int pcap_set_snaplen(pcap_t *, int);
int pcap_set_timeout(pcap_t *, int);
int pcap_activate(pcap_t *);
pcap_t *pcap_create(const char *, char *); 
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
int pcap_setfilter(pcap_t *, struct bpf_program *);
int pcap_compile(pcap_t *, struct bpf_program *, const char *, int, unsigned int);
int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
int pcap_datalink(pcap_t *);
int packet_process(int datalink_type, uint32_t caplen, uint32_t len, const uint8_t *packet, int decode_tunnels, 
                   struct nf_packet *nf_pkt, int n_roots, uint64_t root_idx, int mode, uint64_t time);
void pcap_breakloop(pcap_t *);
void pcap_close(pcap_t *);
char *pcap_geterr(pcap_t *);
int pcap_stats(pcap_t *, struct pcap_stat *);
"""

cc_dissector_apis = """
struct ndpi_detection_module_struct *dissector_init(struct dissector_checker *checker);
void dissector_configure(struct ndpi_detection_module_struct *dissector);
void dissector_cleanup(struct ndpi_detection_module_struct *dissector);
"""

cc_meter_apis = """
struct nf_flow *meter_initialize_flow(struct nf_packet *packet, uint8_t accounting_mode, uint8_t statistics, 
                                      uint8_t splt, uint8_t n_dissections, 
                                      struct ndpi_detection_module_struct *dissector);
uint8_t meter_update_flow(struct nf_flow *flow, struct nf_packet *packet, uint64_t idle_timeout, 
                          uint64_t active_timeout, uint8_t accounting_mode, uint8_t statistics, uint8_t splt,
                          uint8_t n_dissections, struct ndpi_detection_module_struct *dissector);
void meter_expire_flow(struct nf_flow *flow, uint8_t n_dissections, struct ndpi_detection_module_struct *dissector);
void meter_free_flow(struct nf_flow *flow, uint8_t n_dissections, uint8_t splt, uint8_t full);
"""


def capture_open(ffi, npcap, pcap_file, mode, error_child):
    pcap_handle = ffi.NULL
    if mode == 0:
        pcap_handle = npcap.pcap_open_offline(pcap_file, error_child)
    if mode == 1:
        pcap_handle = npcap.pcap_create(pcap_file, error_child)
    return pcap_handle


def capture_set_timeout(npcap, pcap_handle, mode):
    set_timeout = 0
    if mode != 0:
        set_timeout = npcap.pcap_set_timeout(pcap_handle, 1000)
        if set_timeout != 0:
            npcap.pcap_close(pcap_handle)
    return set_timeout


def capture_set_promisc(npcap, pcap_handle, mode, promisc):
    set_promisc = 0
    if mode != 0:
        set_promisc = npcap.pcap_set_promisc(pcap_handle, promisc)
        if set_promisc != 0:
            npcap.pcap_close(pcap_handle)
    return set_promisc


def capture_set_snaplen(npcap, pcap_handle, mode, snaplen):
    set_snaplen = 0
    if mode != 0:
        set_snaplen = npcap.pcap_set_snaplen(pcap_handle, snaplen)
        if set_snaplen != 0:
            npcap.pcap_close(pcap_handle)
    return set_snaplen


def setup_capture_unix(ffi, lib, source, snaplen, promisc, mode, error_child, group_id):
    capture = lib.capture_open(bytes(source, 'utf-8'), mode, error_child)
    if capture == ffi.NULL:
        return
    fanout_set_failed = lib.capture_set_fanout(capture, mode, error_child, group_id)
    if fanout_set_failed:
        return
    timeout_set_failed = lib.capture_set_timeout(capture, mode, error_child)
    if timeout_set_failed:
        return
    promisc_set_failed = lib.capture_set_promisc(capture, mode, error_child, int(promisc))
    if promisc_set_failed:
        return
    snaplen_set_failed = lib.capture_set_snaplen(capture, mode, error_child, snaplen)
    if snaplen_set_failed:
        return
    return capture


def setup_capture_windows(ffi, npcap, source, snaplen, promisc, mode, error_child):
    capture = capture_open(ffi, npcap, bytes(source, 'utf-8'), mode, error_child)
    if capture == ffi.NULL:
        return
    timeout_set_failed = capture_set_timeout(npcap, capture, mode)
    if timeout_set_failed:
        ffi.memmove(error_child, b'Unable to set buffer timeout.', 256)
        return
    promisc_set_failed = capture_set_promisc(npcap, capture, mode, int(promisc))
    if promisc_set_failed:
        ffi.memmove(error_child, b'Unable to set promisc mode.', 256)
        return
    snaplen_set_failed = capture_set_snaplen(npcap, capture, mode, snaplen)
    if snaplen_set_failed:
        ffi.memmove(error_child, b'Unable to set snaplen.', 256)
        return
    return capture


def setup_capture(is_windows, ffi, lib, npcap, source, snaplen, promisc, mode, error_child, group_id):
    """ Setup capture """
    if is_windows:  # We move to pure Python API
        return setup_capture_windows(ffi, npcap, source, snaplen, promisc, mode, error_child)
    # We use APIs defined within the engine.
    return setup_capture_unix(ffi, lib, source, snaplen, promisc, mode, error_child, group_id)


def capture_set_filter(npcap, ffi, pcap_handle, bpf_filter, child_error):
    set_filter = 0
    if bpf_filter != ffi.NULL:
        fcode = ffi.new("struct bpf_program *")
        if npcap.pcap_compile(pcap_handle, fcode, bpf_filter, 1, 0xFFFFFF00) < 0:
            ffi.memmove(child_error, b'Unable to compile BPF filter.', 256)
            npcap.pcap_close(pcap_handle)
            set_filter = 1
        else:
            if npcap.pcap_setfilter(pcap_handle, fcode) < 0:
                ffi.memmove(child_error, b'Unable to compile BPF filter.', 256)
                npcap.pcap_close(pcap_handle)
                set_filter = 1
    return set_filter


def setup_filter_windows(npcap, ffi, capture, error_child, bpf_filter):
    """ Compile and setup BPF filter on Windows """
    if bpf_filter is not None:
        filter_set_failed = capture_set_filter(npcap, ffi, capture, bytes(bpf_filter, 'utf-8'), error_child)
        if filter_set_failed:
            return False
    return True


def setup_filter_unix(capture, lib, error_child, bpf_filter):
    """ Compile and setup BPF filter on Unix """
    if bpf_filter is not None:
        filter_set_failed = lib.capture_set_filter(capture, bytes(bpf_filter, 'utf-8'), error_child)
        if filter_set_failed:
            return False
    return True


def capture_activate(ffi, npcap, pcap_handle, mode, error_child):
    set_activate = 0
    if mode != 0:
        set_activate = npcap.pcap_activate(pcap_handle)
        if set_activate != 0:
            npcap.pcap_close(pcap_handle)
            ffi.memmove(error_child, b'Unable to activate source.', 256)
    return set_activate


def activate_capture_windows(npcap, ffi, capture, error_child, bpf_filter, mode):
    """ Capture activation function for Windows """
    activation_failed = capture_activate(ffi, npcap, capture, mode, error_child)
    if activation_failed:
        return False
    return setup_filter_windows(npcap, ffi, capture, error_child, bpf_filter)


def activate_capture_unix(capture, lib, error_child, bpf_filter, mode):
    """ Capture activation function for UNIX"""
    activation_failed = lib.capture_activate(capture, mode, error_child)
    if activation_failed:
        return False
    return setup_filter_unix(capture, lib, error_child, bpf_filter)


def activate_capture(is_windows, npcap, ffi, capture, lib, error_child, bpf_filter, mode):
    """ Capture activation function """
    if is_windows:
        return activate_capture_windows(npcap, ffi, capture, error_child, bpf_filter, mode)
    return activate_capture_unix(capture, lib, error_child, bpf_filter, mode)


def packet_process(npcap, lib, pcap_handle, hdr, data, decode_tunnels, nf_pkt, n_roots, root_idx, mode):
    time = int(hdr.tv_sec * 1000 + hdr.tv_usec / (1000000 / 1000))
    rv_processor = lib.packet_process(npcap.pcap_datalink(pcap_handle), hdr.caplen, hdr.len, data,
                                      decode_tunnels, nf_pkt, n_roots, root_idx, mode, time)
    if (rv_processor == 0) or (rv_processor == 1):
        return rv_processor
    return 2


def capture_next(ffi, npcap, lib, pcap_handle, nf_pkt, decode_tunnels, n_roots, root_idx, mode):
    """ Get next packet information from pcap handle """
    phdr = ffi.new("struct pcap_pkthdr **", ffi.NULL)
    pdata = ffi.new("uint8_t **", ffi.NULL)
    rv_handle = npcap.pcap_next_ex(pcap_handle, phdr, ffi.cast("unsigned char **", pdata))
    hdr = phdr[0]
    data = pdata[0]
    if rv_handle == 1:
        return packet_process(npcap, lib, pcap_handle, hdr, data, decode_tunnels, nf_pkt, n_roots, root_idx, mode)
    if rv_handle == 0:
        if hdr == ffi.NULL or data == ffi.NULL:
            return -1
        return packet_process(npcap, lib, pcap_handle, hdr, data, decode_tunnels, nf_pkt, n_roots, root_idx, mode)
    if rv_handle == -2:
        return -2
    return -1


def capture_close(is_windows, npcap, lib, pcap_handle):
    """ Capture close function """
    if is_windows:
        npcap.pcap_breakloop(pcap_handle)
        npcap.pcap_close(pcap_handle)
    else:
        lib.capture_close(pcap_handle)


def setup_dissector(ffi, lib, n_dissections):
    """ Setup dissector according to n_dissections value """
    if n_dissections:  # Dissection activated
        # Check that headers and loaded library match and initiate dissector.
        checker = ffi.new("struct dissector_checker *")
        checker.flow_size = ffi.sizeof("struct ndpi_flow_struct")
        checker.flow_tcp_size = ffi.sizeof("struct ndpi_flow_tcp_struct")
        checker.flow_udp_size = ffi.sizeof("struct ndpi_flow_udp_struct")
        dissector = lib.dissector_init(checker)
        if dissector == ffi.NULL:
            return ffi.NULL
        # Configure it (activate bitmask to all protocols)
        lib.dissector_configure(dissector)
        return dissector
    return ffi.NULL


def capture_stats(ffi, npcap, pcap_handle, nf_statistics, mode):
    if mode == 0:
        return
    statistics = ffi.new("struct pcap_stat *")
    ret = npcap.pcap_stats(pcap_handle, statistics)
    if ret == 0:
        nf_statistics.received = statistics[0].recv
        nf_statistics.dropped = statistics[0].drop
        nf_statistics.dropped_by_interface = statistics[0].ifdrop
    else:
        print("Warning: Error while reading interface performance statistics.")
    return


def discover_iterfaces():
    """ Interfaces discovery utility for windows """
    interfaces = {}
    ffi = cffi.FFI()
    try:
        npcap = ffi.dlopen(NPCAP_PATH)
    except OSError:
        return interfaces
    ffi.cdef(cc_capture_headers)
    ffi.cdef(cc_capture_apis)
    ppintf = ffi.new("pcap_if_t * *")
    errbuf = ffi.new("char []", 128)
    rv = npcap.pcap_findalldevs(ppintf, errbuf)
    if rv:
        return interfaces
    pintf = ppintf[0]
    tmp = pintf
    while tmp != ffi.NULL:
        name = ffi.string(tmp.name).decode('ascii', 'ignore')
        if tmp.description != ffi.NULL:
            interfaces[name] = ffi.string(tmp.description).decode('ascii', 'ignore')
        else:
            interfaces[name] = ""
        tmp = tmp.next
    npcap.pcap_freealldevs(pintf)
    ffi.dlclose(npcap)
    return interfaces


def is_interface(val, is_windows):
    """ Check if val is a valid interface name and return it if true else None """
    # On windows if the user give a description instead of network device name, we comply with it.
    if is_windows:
        interfaces_map = discover_iterfaces()
    else:
        interfaces_map = dict.fromkeys(net_if_addrs().keys(), "")
    for k, v in interfaces_map.items():
        if val == k or val == v:
            return k
    return None


def create_engine(is_windows):
    """ engine creation function, return the loaded native nfstream engine and it's ffi interface"""
    ffi = cffi.FFI()
    npcap = None
    lib = None
    try:
        lib = ffi.dlopen(ENGINE_PATH)
    except OSError:
        pass
    ffi.cdef(cc_capture_headers)
    ffi.cdef(cc_dissector_headers_packed, packed=True, override=True)
    ffi.cdef(cc_dissector_headers, override=True)
    ffi.cdef(cc_meter_headers, override=True)
    ffi.cdef(cc_capture_apis, override=True)
    if is_windows:
        try:
            npcap = ffi.dlopen(NPCAP_PATH)
        except OSError:
            ffi.dlclose(lib)
    ffi.cdef(cc_dissector_apis, override=True)
    ffi.cdef(cc_meter_apis, override=True)
    return ffi, lib, npcap
