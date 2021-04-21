"""
------------------------------------------------------------------------------------------------------------------------
engine.py
Copyright (C) 2019-21 - NFStream Developers
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
import cffi

# We declare here all headers and APIs of native nfstream, This will include:
#   - headers and APIs for capture stage (packet capture and processing).
#   - headers and APIs for nDPI (the dissection part).
#   - headers and APIs for Metering stage (flow intialization, update, expiration and cleaning)
# We group it in an "engine" initialized by meter as start in order to share the same ffi instance between stages.

cc_capture_headers = """
struct pcap;
typedef struct pcap pcap_t;
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
/* ++++++++++++++++++++++++ IP header ++++++++++++++++++++++++ */
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

/* +++++++++++++++++++++++ IPv6 header +++++++++++++++++++++++ */
/* rfc3542 */
struct ndpi_in6_addr {
  union {
    uint8_t   u6_addr8[16];
    uint16_t  u6_addr16[8];
    uint32_t  u6_addr32[4];
    uint64_t  u6_addr64[2];
  } u6_addr;  /* 128-bit IP6 address */
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

/* +++++++++++++++++++++++ TCP header +++++++++++++++++++++++ */
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

/* +++++++++++++++++++++++ UDP header +++++++++++++++++++++++ */
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
#define NDPI_MAX_NUM_TLS_APPL_BLOCKS      8

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
  NDPI_TLS_CERTIFICATE_MISMATCH, /* 10 */
  NDPI_HTTP_SUSPICIOUS_USER_AGENT,
  NDPI_HTTP_NUMERIC_IP_HOST,
  NDPI_HTTP_SUSPICIOUS_URL,
  NDPI_HTTP_SUSPICIOUS_HEADER,
  NDPI_TLS_NOT_CARRYING_HTTPS,
  NDPI_SUSPICIOUS_DGA_DOMAIN,
  NDPI_MALFORMED_PACKET,
  NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER,
  NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER,
  NDPI_SMB_INSECURE_VERSION, /* 20 */
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
  /* Leave this as last member */
  NDPI_MAX_RISK /* must be <= 31 due to (**) */
} ndpi_risk_enum;

typedef uint32_t ndpi_risk;

/* NDPI_VISIT */
typedef enum {
  ndpi_preorder,
  ndpi_postorder,
  ndpi_endorder,
  ndpi_leaf
} ndpi_VISIT;

/* NDPI_NODE */
typedef struct node_t {
  char *key;
  struct node_t *left, *right;
} ndpi_node;

/* NDPI_MASK_SIZE */
typedef uint32_t ndpi_ndpi_mask;

/* NDPI_PROTO_BITMASK_STRUCT */
typedef struct ndpi_protocol_bitmask_struct {
  ndpi_ndpi_mask fds_bits[16];
} NDPI_PROTOCOL_BITMASK;

/* NDPI_PROTOCOL_BITTORRENT */
typedef struct spinlock {
  volatile int    val;
} spinlock_t;

typedef struct atomic {
  volatile int counter;
} atomic_t;

typedef long int time_t;

struct hash_ip4p_node {
  struct hash_ip4p_node *next, *prev;
  time_t                  lchg;
  uint16_t               port,count:12,flag:4;
  uint32_t               ip;
};

struct hash_ip4p {
  struct hash_ip4p_node   *top;
  spinlock_t              lock;
  size_t                  len;
};

struct hash_ip4p_table {
  size_t                  size;
  int			  ipv6;
  spinlock_t              lock;
  atomic_t                count;
  struct hash_ip4p        tbl;
};

struct bt_announce {              // 192 bytes
  uint32_t		hash[5];
  uint32_t		ip[4];
  uint32_t		time;
  uint16_t		port;
  uint8_t		name_len,
    name[149];     // 149 bytes
};

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
  NDPI_HTTP_METHOD_CONNECT
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

struct ndpi_id_struct {
  /**
     detected_protocol_bitmask:
     access this bitmask to find out whether an id has used skype or not
     if a flag is set here, it will not be reset
     to compare this, use:
  **/
  NDPI_PROTOCOL_BITMASK detected_protocol_bitmask;
  /* NDPI_PROTOCOL_RTSP */
  ndpi_ip_addr_t rtsp_ip_address;

  /* NDPI_PROTOCOL_YAHOO */
  uint32_t yahoo_video_lan_timer;

  /* NDPI_PROTOCOL_IRC_MAXPORT % 2 must be 0 */
  /* NDPI_PROTOCOL_IRC */
#define NDPI_PROTOCOL_IRC_MAXPORT 8
  uint16_t irc_port[NDPI_PROTOCOL_IRC_MAXPORT];
  uint32_t last_time_port_used[NDPI_PROTOCOL_IRC_MAXPORT];
  uint32_t irc_ts;

  /* NDPI_PROTOCOL_GNUTELLA */
  uint32_t gnutella_ts;

  /* NDPI_PROTOCOL_THUNDER */
  uint32_t thunder_ts;

  /* NDPI_PROTOCOL_RTSP */
  uint32_t rtsp_timer;

  /* NDPI_PROTOCOL_ZATTOO */
  uint32_t zattoo_ts;

  /* NDPI_PROTOCOL_JABBER */
  uint32_t jabber_stun_or_ft_ts;

  /* NDPI_PROTOCOL_DIRECTCONNECT */
  uint32_t directconnect_last_safe_access_time;

  /* NDPI_PROTOCOL_SOULSEEK */
  uint32_t soulseek_last_safe_access_time;

  /* NDPI_PROTOCOL_DIRECTCONNECT */
  uint16_t detected_directconnect_port;
  uint16_t detected_directconnect_udp_port;
  uint16_t detected_directconnect_ssl_port;

  /* NDPI_PROTOCOL_BITTORRENT */
#define NDPI_BT_PORTS 8
  uint16_t bt_port_t[NDPI_BT_PORTS];
  uint16_t bt_port_u[NDPI_BT_PORTS];

  /* NDPI_PROTOCOL_JABBER */
#define JABBER_MAX_STUN_PORTS 6
  uint16_t jabber_voice_stun_port[JABBER_MAX_STUN_PORTS];
  uint16_t jabber_file_transfer_port[2];

  /* NDPI_PROTOCOL_GNUTELLA */
  uint16_t detected_gnutella_port;

  /* NDPI_PROTOCOL_GNUTELLA */
  uint16_t detected_gnutella_udp_port1;
  uint16_t detected_gnutella_udp_port2;

  /* NDPI_PROTOCOL_SOULSEEK */
  uint16_t soulseek_listen_port;

  /* NDPI_PROTOCOL_IRC */
  uint8_t irc_number_of_port;

  /* NDPI_PROTOCOL_JABBER */
  uint8_t jabber_voice_stun_used_ports;

  /* NDPI_PROTOCOL_SIP */
  /* NDPI_PROTOCOL_YAHOO */
  uint32_t yahoo_video_lan_dir:1;

  /* NDPI_PROTOCOL_YAHOO */
  uint32_t yahoo_conf_logged_in:1;
  uint32_t yahoo_voice_conf_logged_in:1;

  /* NDPI_PROTOCOL_RTSP */
  uint32_t rtsp_ts_set:1;
};


typedef struct message {
  uint8_t *buffer;
  unsigned buffer_len, buffer_used, max_expected;
  uint32_t next_seq[2]; /* Directions */
} message_t;
    
    
struct ndpi_flow_tcp_struct {
  /* NDPI_PROTOCOL_MAIL_SMTP */
  uint16_t smtp_command_bitmask;

  /* NDPI_PROTOCOL_MAIL_POP */
  uint16_t pop_command_bitmask;

  /* NDPI_PROTOCOL_QQ */
  uint16_t qq_nxt_len;

  /* NDPI_PROTOCOL_WHATSAPP */
  uint8_t wa_matched_so_far;

  /* NDPI_PROTOCOL_TDS */
  uint8_t tds_login_version;

  /* NDPI_PROTOCOL_IRC */
  uint8_t irc_stage;
  uint8_t irc_port;

  /* NDPI_PROTOCOL_H323 */
  uint8_t h323_valid_packets;

  /* NDPI_PROTOCOL_GNUTELLA */
  uint8_t gnutella_msg_id[3];

  /* NDPI_PROTOCOL_IRC */
  uint32_t irc_3a_counter:3;
  uint32_t irc_stage2:5;
  uint32_t irc_direction:2;
  uint32_t irc_0x1000_full:1;

  /* NDPI_PROTOCOL_SOULSEEK */
  uint32_t soulseek_stage:2;

  /* NDPI_PROTOCOL_TDS */
  uint32_t tds_stage:3;

  /* NDPI_PROTOCOL_USENET */
  uint32_t usenet_stage:2;

  /* NDPI_PROTOCOL_IMESH */
  uint32_t imesh_stage:4;

  /* NDPI_PROTOCOL_HTTP */
  uint32_t http_setup_dir:2;
  uint32_t http_stage:2;
  uint32_t http_empty_line_seen:1;
  uint32_t http_wait_for_retransmission:1;

  /* NDPI_PROTOCOL_GNUTELLA */
  uint32_t gnutella_stage:2;		       // 0 - 2

  /* NDPI_CONTENT_MMS */
  uint32_t mms_stage:2;

  /* NDPI_PROTOCOL_YAHOO */
  uint32_t yahoo_sip_comm:1;
  uint32_t yahoo_http_proxy_stage:2;

  /* NDPI_PROTOCOL_MSN */
  uint32_t msn_stage:3;
  uint32_t msn_ssl_ft:2;

  /* NDPI_PROTOCOL_SSH */
  uint32_t ssh_stage:3;

  /* NDPI_PROTOCOL_VNC */
  uint32_t vnc_stage:2;			// 0 - 3

  /* NDPI_PROTOCOL_TELNET */
  uint32_t telnet_stage:2;			// 0 - 2

  struct {
    message_t message;
    void* srv_cert_fingerprint_ctx; /* SHA-1 */
    /* NDPI_PROTOCOL_TLS */
    uint8_t hello_processed:1, certificate_processed:1, subprotocol_detected:1, fingerprint_set:1, _pad:4; 
    uint8_t num_tls_blocks;
    int16_t tls_application_blocks_len[NDPI_MAX_NUM_TLS_APPL_BLOCKS];
  } tls;

  /* NDPI_PROTOCOL_POSTGRES */
  uint32_t postgres_stage:3;

  /* NDPI_PROTOCOL_DIRECT_DOWNLOAD_LINK */
  uint32_t ddlink_server_direction:1;
  uint32_t seen_syn:1;
  uint32_t seen_syn_ack:1;
  uint32_t seen_ack:1;

  /* NDPI_PROTOCOL_ICECAST */
  uint32_t icecast_stage:1;

  /* NDPI_PROTOCOL_DOFUS */
  uint32_t dofus_stage:1;

  /* NDPI_PROTOCOL_FIESTA */
  uint32_t fiesta_stage:2;

  /* NDPI_PROTOCOL_WORLDOFWARCRAFT */
  uint32_t wow_stage:2;

  /* NDPI_PROTOCOL_HTTP_APPLICATION_VEOHTV */
  uint32_t veoh_tv_stage:2;

  /* NDPI_PROTOCOL_SHOUTCAST */
  uint32_t shoutcast_stage:2;

  /* NDPI_PROTOCOL_RTP */
  uint32_t rtp_special_packets_seen:1;

  /* NDPI_PROTOCOL_MAIL_POP */
  uint32_t mail_pop_stage:2;

  /* NDPI_PROTOCOL_MAIL_IMAP */
  uint32_t mail_imap_stage:3, mail_imap_starttls:2;

  /* NDPI_PROTOCOL_SOAP */
  uint32_t soap_stage:1;

  /* NDPI_PROTOCOL_SKYPE */
  uint8_t skype_packet_id;

  /* NDPI_PROTOCOL_CITRIX */
  uint8_t citrix_packet_id;

  /* NDPI_PROTOCOL_LOTUS_NOTES */
  uint8_t lotus_notes_packet_id;

  /* NDPI_PROTOCOL_TEAMVIEWER */
  uint8_t teamviewer_stage;

  /* NDPI_PROTOCOL_ZMQ */
  uint8_t prev_zmq_pkt_len;
  uint8_t prev_zmq_pkt[10];

  /* NDPI_PROTOCOL_PPSTREAM */
  uint32_t ppstream_stage:3;

  /* NDPI_PROTOCOL_MEMCACHED */
  uint8_t memcached_matches;

  /* NDPI_PROTOCOL_NEST_LOG_SINK */
  uint8_t nest_log_sink_matches;
};

struct ndpi_flow_udp_struct {
  /* NDPI_PROTOCOL_SNMP */
  uint32_t snmp_msg_id;

  /* NDPI_PROTOCOL_SNMP */
  uint32_t snmp_stage:2;

  /* NDPI_PROTOCOL_PPSTREAM */
  uint32_t ppstream_stage:3;		  // 0 - 7

  /* NDPI_PROTOCOL_HALFLIFE2 */
  uint32_t halflife2_stage:2;		  // 0 - 2

  /* NDPI_PROTOCOL_TFTP */
  uint32_t tftp_stage:1;

  /* NDPI_PROTOCOL_AIMINI */
  uint32_t aimini_stage:5;

  /* NDPI_PROTOCOL_XBOX */
  uint32_t xbox_stage:1;

  /* NDPI_PROTOCOL_WINDOWS_UPDATE */
  uint32_t wsus_stage:1;

  /* NDPI_PROTOCOL_SKYPE */
  uint8_t skype_packet_id;
  uint8_t skype_crc[4];

  /* NDPI_PROTOCOL_TEAMVIEWER */
  uint8_t teamviewer_stage;

  /* NDPI_PROTOCOL_EAQ */
  uint8_t eaq_pkt_id;
  uint32_t eaq_sequence;

  /* NDPI_PROTOCOL_RX */
  uint32_t rx_conn_epoch;
  uint32_t rx_conn_id;

  /* NDPI_PROTOCOL_MEMCACHED */
  uint8_t memcached_matches;

  /* NDPI_PROTOCOL_WIREGUARD */
  uint8_t wireguard_stage;
  uint32_t wireguard_peer_index[2];
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
  const uint8_t *generic_l4_ptr;	/* is set only for non tcp-udp traffic */
  const uint8_t *payload;
  uint64_t current_time_ms;
  uint16_t detected_protocol_stack[2];
  uint16_t protocol_stack_info;

  struct ndpi_int_one_line_struct line[64];
  /* HTTP headers */
  struct ndpi_int_one_line_struct host_line;
  struct ndpi_int_one_line_struct forwarded_line;
  struct ndpi_int_one_line_struct referer_line;
  struct ndpi_int_one_line_struct content_line;
  struct ndpi_int_one_line_struct content_disposition_line;
  struct ndpi_int_one_line_struct accept_line;
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
  uint8_t http_num_headers; /* number of found (valid) header lines in HTTP request or response */

  uint16_t l3_packet_len;
  uint16_t l4_packet_len;
  uint16_t payload_packet_len;
  uint16_t actual_payload_len;
  uint16_t num_retried_bytes;
  uint16_t parsed_lines;
  uint16_t parsed_unix_lines;
  uint16_t empty_line_position;
  uint8_t tcp_retransmission;
  uint8_t l4_protocol;

  uint8_t tls_certificate_detected:4, tls_certificate_num_checks:4;
  uint8_t packet_lines_parsed_complete:1,
  packet_direction:1, empty_line_position_set:1, http_check_content:1, pad:4;
};

struct ndpi_detection_module_struct;
struct ndpi_flow_struct;

struct ndpi_call_function_struct {
  uint16_t ndpi_protocol_id;
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;
  uint32_t ndpi_selection_bitmask;
  void (*func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
  uint8_t detection_feature;
};

struct ndpi_subprotocol_conf_struct {
  void (*func) (struct ndpi_detection_module_struct *, char *attr, char *value, int protocol_id);
};

typedef enum {
  NDPI_PROTOCOL_SAFE = 0,              /* Surely doesn't provide risks for the network. (e.g., a news site) */
  NDPI_PROTOCOL_ACCEPTABLE,            /* Probably doesn't provide risks, but could be malicious (e.g., Dropbox) */
  NDPI_PROTOCOL_FUN,                   /* Pure fun protocol, which may be prohibited by the user policy */
  NDPI_PROTOCOL_UNSAFE,                /* Probably provides risks, but could be a normal traffic. Unencrypted protocols 
                                          with clear pass should be here (e.g., telnet) */
  NDPI_PROTOCOL_POTENTIALLY_DANGEROUS, /* Possibly dangerous (ex. Tor). */
  NDPI_PROTOCOL_DANGEROUS,             /* Surely is dangerous (ex. smbv1). Be prepared to troubles */
  NDPI_PROTOCOL_TRACKER_ADS,           /* Trackers, Advertisements... */
  NDPI_PROTOCOL_UNRATED                /* No idea, not implemented or impossible to classify */
} ndpi_protocol_breed_t;

/* Abstract categories to group the protocols. */
typedef enum {
  NDPI_PROTOCOL_CATEGORY_UNSPECIFIED = 0,   /* For general services and unknown protocols */
  NDPI_PROTOCOL_CATEGORY_MEDIA,             /* Multimedia and streaming */
  NDPI_PROTOCOL_CATEGORY_VPN,               /* Virtual Private Networks */
  NDPI_PROTOCOL_CATEGORY_MAIL,              /* Protocols to send/receive/sync emails */
  NDPI_PROTOCOL_CATEGORY_DATA_TRANSFER,     /* AFS/NFS and similar protocols */
  NDPI_PROTOCOL_CATEGORY_WEB,               /* Web/mobile protocols and services */
  NDPI_PROTOCOL_CATEGORY_SOCIAL_NETWORK,    /* Social networks */
  NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT,       /* Download, FTP, file transfer/sharing */
  NDPI_PROTOCOL_CATEGORY_GAME,              /* Online games */
  NDPI_PROTOCOL_CATEGORY_CHAT,              /* Instant messaging */
  NDPI_PROTOCOL_CATEGORY_VOIP,              /* Real-time communications and conferencing */
  NDPI_PROTOCOL_CATEGORY_DATABASE,          /* Protocols for database communication */
  NDPI_PROTOCOL_CATEGORY_REMOTE_ACCESS,     /* Remote access and control */
  NDPI_PROTOCOL_CATEGORY_CLOUD,             /* Online cloud services */
  NDPI_PROTOCOL_CATEGORY_NETWORK,           /* Network infrastructure protocols */
  NDPI_PROTOCOL_CATEGORY_COLLABORATIVE,     /* Software for collaborative development, including Webmail */
  NDPI_PROTOCOL_CATEGORY_RPC,               /* High level network communication protocols */
  NDPI_PROTOCOL_CATEGORY_STREAMING,         /* Streaming protocols */
  NDPI_PROTOCOL_CATEGORY_SYSTEM_OS,         /* System/Operating System level applications */
  NDPI_PROTOCOL_CATEGORY_SW_UPDATE,         /* Software update */

  /* See #define NUM_CUSTOM_CATEGORIES */
  NDPI_PROTOCOL_CATEGORY_CUSTOM_1,          /* User custom category 1 */
  NDPI_PROTOCOL_CATEGORY_CUSTOM_2,          /* User custom category 2 */
  NDPI_PROTOCOL_CATEGORY_CUSTOM_3,          /* User custom category 3 */
  NDPI_PROTOCOL_CATEGORY_CUSTOM_4,          /* User custom category 4 */
  NDPI_PROTOCOL_CATEGORY_CUSTOM_5,          /* User custom category 5 */

  /* Further categories... */
  NDPI_PROTOCOL_CATEGORY_MUSIC,
  NDPI_PROTOCOL_CATEGORY_VIDEO,
  NDPI_PROTOCOL_CATEGORY_SHOPPING,
  NDPI_PROTOCOL_CATEGORY_PRODUCTIVITY,
  NDPI_PROTOCOL_CATEGORY_FILE_SHARING,

  /*
  The category below is used by sites who are used
  to test connectivity 
  */
  NDPI_PROTOCOL_CATEGORY_CONNECTIVITY_CHECK,
  NDPI_PROTOCOL_CATEGORY_IOT_SCADA,

  /* Some custom categories */
  CUSTOM_CATEGORY_MINING           = 99,
  CUSTOM_CATEGORY_MALWARE          = 100,
  CUSTOM_CATEGORY_ADVERTISEMENT    = 101,
  CUSTOM_CATEGORY_BANNED_SITE      = 102,
  CUSTOM_CATEGORY_SITE_UNAVAILABLE = 103,
  CUSTOM_CATEGORY_ALLOWED_SITE     = 104,
  /*
    The category below is used to track communications made by
    security applications (e.g. sophosxl.net, spamhaus.org)
    to track malware, spam etc.
    */
  CUSTOM_CATEGORY_ANTIMALWARE      = 105,

  /*
    IMPORTANT
    Please keep in sync with
    static const char* categories[] = { ..}
    in ndpi_main.c
  */

  NDPI_PROTOCOL_NUM_CATEGORIES,
  /*
    NOTE: Keep this as last member
    Unused as value but useful to getting the number of elements
    in this datastructure
  */
  NDPI_PROTOCOL_ANY_CATEGORY /* Used to handle wildcards */
} ndpi_protocol_category_t;

typedef struct ndpi_proto_defaults {
  char *protoName;
  ndpi_protocol_category_t protoCategory;
  uint16_t * subprotocols;
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
  void *ac_automa; /* Real type is AC_AUTOMATA_t */
  uint8_t ac_automa_finalized;
} ndpi_automa;

typedef struct ndpi_proto {
  /*
    Note
    below we do not use ndpi_protocol_id_t as users can define their own
    custom protocols and thus the typedef could be too short in size.
  */
  uint16_t master_protocol /* e.g. HTTP */, app_protocol /* e.g. FaceBook */;
  ndpi_protocol_category_t category;
} ndpi_protocol;

#define NUM_CUSTOM_CATEGORIES      5
#define CUSTOM_CATEGORY_LABEL_LEN 32

typedef enum {
  ndpi_stun_cache,
  ndpi_hangout_cache
} ndpi_lru_cache_type;

struct ndpi_detection_module_struct {
  NDPI_PROTOCOL_BITMASK detection_bitmask;
  NDPI_PROTOCOL_BITMASK generic_http_packet_bitmask;

  uint32_t current_ts;

  uint32_t ticks_per_second;

  uint16_t num_tls_blocks_to_follow;
  uint8_t skip_tls_blocks_until_change_cipher:1, enable_ja3_plus:1, _notused:6;

  char custom_category_labels[NUM_CUSTOM_CATEGORIES][CUSTOM_CATEGORY_LABEL_LEN];
  /* callback function buffer */
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

  ndpi_log_level_t ndpi_log_level; /* default error */

  /* misc parameters */
  uint32_t tcp_max_retransmission_window_size;

  uint32_t directconnect_connection_ip_tick_timeout;

  /* subprotocol registration handler */
  struct ndpi_subprotocol_conf_struct subprotocol_conf[250];

  unsigned ndpi_num_supported_protocols;
  unsigned ndpi_num_custom_protocols;

  /* HTTP/DNS/HTTPS/QUIC host matching */
  ndpi_automa host_automa,                     /* Used for DNS/HTTPS */
    content_automa,                            /* Used for HTTP subprotocol_detection */
    subprotocol_automa,                        /* Used for HTTP subprotocol_detection */
    bigrams_automa, trigrams_automa, impossible_bigrams_automa, /* TOR */
    risky_domain_automa, tls_cert_subject_automa,
    malicious_ja3_automa, malicious_sha1_automa;
  /* IMPORTANT: please update ndpi_finalize_initialization() whenever you add a new automa */

  struct {
    ndpi_automa hostnames, hostnames_shadow;
    void *ipAddresses, *ipAddresses_shadow; /* Patricia */
    uint8_t categories_loaded;
  } custom_categories;

  /* IP-based protocol detection */
  void *protocols_ptree;

  /* irc parameters */
  uint32_t irc_timeout;
  /* gnutella parameters */
  uint32_t gnutella_timeout;
  /* thunder parameters */
  uint32_t thunder_timeout;
  /* SoulSeek parameters */
  uint32_t soulseek_connection_ip_tick_timeout;
  /* rtsp parameters */
  uint32_t rtsp_connection_timeout;
  /* rstp */
  uint32_t orb_rstp_ts_timeout;
  /* yahoo */
  uint8_t yahoo_detect_http_connections;
  uint32_t yahoo_lan_video_timeout;
  uint32_t zattoo_connection_timeout;
  uint32_t jabber_stun_timeout;
  uint32_t jabber_file_transfer_timeout;
  uint8_t ip_version_limit;
  /* NDPI_PROTOCOL_BITTORRENT */
  struct hash_ip4p_table *bt_ht, *bt6_ht;
  /* BT_ANNOUNCE */
  struct bt_announce *bt_ann;
  int    bt_ann_len;

  /* NDPI_PROTOCOL_OOKLA */
  struct ndpi_lru_cache *ookla_cache;

  /* NDPI_PROTOCOL_TINC */
  struct cache *tinc_cache;

  /* NDPI_PROTOCOL_STUN and subprotocols */
  struct ndpi_lru_cache *stun_cache;
  
  struct ndpi_lru_cache *mining_cache;

  /* NDPI_PROTOCOL_MSTEAMS */
  struct ndpi_lru_cache *msteams_cache;

  ndpi_proto_defaults_t proto_defaults[512];
  uint8_t direction_detect_disable:1, /* disable internal detection of packet direction */ _pad:7;
  void (*ndpi_notify_lru_add_handler_ptr)(ndpi_lru_cache_type cache_type, uint32_t proto, uint32_t app_proto);
};

#define NDPI_CIPHER_SAFE                        0
#define NDPI_CIPHER_WEAK                        1
#define NDPI_CIPHER_INSECURE                    2

typedef enum {
  ndpi_cipher_safe = NDPI_CIPHER_SAFE,
  ndpi_cipher_weak = NDPI_CIPHER_WEAK,
  ndpi_cipher_insecure = NDPI_CIPHER_INSECURE
} ndpi_cipher_weakness;

struct ndpi_flow_struct {
  uint16_t detected_protocol_stack[2];
  uint16_t protocol_stack_info;
  /* init parameter, internal used to set up timestamp,... */
  uint16_t guessed_protocol_id, guessed_host_protocol_id, guessed_category, guessed_header_category;
  uint8_t l4_proto, protocol_id_already_guessed:1, host_already_guessed:1, fail_with_unknown:1,
    init_finished:1, setup_packet_direction:1, packet_direction:1, check_extra_packets:1;
  /*
    if ndpi_struct->direction_detect_disable == 1
    tcp sequence number connection tracking
  */
  uint32_t next_tcp_seq_nr[2];
  uint8_t max_extra_packets_to_check;
  uint8_t num_extra_packets_checked;
  uint16_t num_processed_pkts; /* <= WARNING it can wrap but we do expect people to giveup earlier */

  int (*extra_packets_func) (struct ndpi_detection_module_struct *, struct ndpi_flow_struct *flow);
  /*
    the tcp / udp / other l4 value union
    used to reduce the number of bytes for tcp or udp protocol states
  */
  union {
    struct ndpi_flow_tcp_struct tcp;
    struct ndpi_flow_udp_struct udp;
  } l4;

  /* Place textual flow info here */
  char flow_extra_info[16];

  /*
    Pointer to src or dst that identifies the
    server of this connection
  */
  struct ndpi_id_struct *server_id;
  /* HTTP host or DNS query */
  uint8_t host_server_name[240];
  uint8_t initial_binary_bytes[8], initial_binary_bytes_len;
  uint8_t risk_checked;
  ndpi_risk risk; /* Issues found with this flow [bitmask of ndpi_risk] */

  /*
    This structure below will not stay inside the protos
    structure below as HTTP is used by many subprotocols
    such as Facebook, Google... so it is hard to know
    when to use it or not. Thus we leave it outside for the
    time being.
  */
  struct {
    ndpi_http_method method;
    char *url, *content_type /* response */, *request_content_type /* e.g. for POST */, *user_agent;
    uint8_t num_request_headers, num_response_headers;
    uint8_t request_version; /* 0=1.0 and 1=1.1. Create an enum for this? */
    uint16_t response_status_code; /* 200, 404, etc. */
    uint8_t detected_os[32]; /* Via HTTP/QUIC User-Agent */
  } http;

  /* 
     Put outside of the union to avoid issues in case the protocol
     is remapped to somethign pther than Kerberos due to a faulty
     dissector
  */
  struct {    
    char *pktbuf;
    uint16_t pktbuf_maxlen, pktbuf_currlen;
  } kerberos_buf;
  union {
    /* the only fields useful for nDPI and ntopng */
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
      struct {
      char ssl_version_str[12];
      uint16_t ssl_version, server_names_len;
      char client_requested_server_name[256], *server_names,
      *alpn, *tls_supported_versions, *issuerDN, *subjectDN;
      uint32_t notBefore, notAfter;
      char ja3_client[33], ja3_server[33];
      uint16_t server_cipher;
      uint8_t sha1_certificate_fingerprint[20];
      struct {
        uint16_t cipher_suite;
        char *esni;
      } encrypted_sni;
      ndpi_cipher_weakness server_unsafe_cipher;
      } tls_quic;

      struct {
        uint8_t num_udp_pkts, num_binding_requests;
        uint16_t num_processed_pkts;
      } stun;

      /* We can have STUN over SSL/TLS thus they need to live together */
    } tls_quic_stun;

    struct {
      char client_signature[48], server_signature[48];
      char hassh_client[33], hassh_server[33];
    } ssh;

    struct {
      uint8_t last_one_byte_pkt, last_byte;
    } imo;

    struct {
      uint8_t username_detected:1, username_found:1,
      password_detected:1, password_found:1,
      pad:4;
      uint8_t character_id;
      char username[32], password[32];
    } telnet;

    struct {
      char version[32];
    } ubntac2;

    struct {
      /* Via HTTP X-Forwarded-For */
      uint8_t nat_ip[24];
    } http;

    struct {
      uint8_t auth_found:1, auth_failed:1, _pad:5;
      char username[16], password[16];
    } ftp_imap_pop_smtp;

    struct {
      /* Bittorrent hash */
      uint8_t hash[20];
    } bittorrent;

    struct {
      char fingerprint[48];
      char class_ident[48];
    } dhcp;
  } protos;

  /*** ALL protocol specific 64 bit variables here ***/

  /* protocols which have marked a connection as this connection cannot be protocol XXX, multiple uint64_t */
  NDPI_PROTOCOL_BITMASK excluded_protocol_bitmask;

  ndpi_protocol_category_t category;

  /* NDPI_PROTOCOL_REDIS */
  uint8_t redis_s2d_first_char, redis_d2s_first_char;

  uint16_t packet_counter;		      // can be 0 - 65000
  uint16_t packet_direction_counter[2];
  uint16_t byte_counter[2];
  /* NDPI_PROTOCOL_BITTORRENT */
  uint8_t bittorrent_stage;		      // can be 0 - 255

  /* NDPI_PROTOCOL_DIRECTCONNECT */
  uint8_t directconnect_stage:2;	      // 0 - 1

  /* NDPI_PROTOCOL_HTTP */
  uint8_t http_detected:1;

  /* NDPI_PROTOCOL_RTSP */
  uint8_t rtsprdt_stage:2, rtsp_control_flow:1;

  /* NDPI_PROTOCOL_YAHOO */
  uint8_t yahoo_detection_finished:2;

  /* NDPI_PROTOCOL_ZATTOO */
  uint8_t zattoo_stage:3;

  /* NDPI_PROTOCOL_QQ */
  uint8_t qq_stage:3;

  /* NDPI_PROTOCOL_THUNDER */
  uint8_t thunder_stage:2;		        // 0 - 3

  /* NDPI_PROTOCOL_FLORENSIA */
  uint8_t florensia_stage:1;

  /* NDPI_PROTOCOL_SOCKS */
  uint8_t socks5_stage:2, socks4_stage:2;      // 0 - 3

  /* NDPI_PROTOCOL_EDONKEY */
  uint8_t edonkey_stage:2;	                // 0 - 3

  /* NDPI_PROTOCOL_FTP_CONTROL */
  uint8_t ftp_control_stage:2;

  /* NDPI_PROTOCOL_RTMP */
  uint8_t rtmp_stage:2;

  /* NDPI_PROTOCOL_STEAM */
  uint16_t steam_stage:3, steam_stage1:3, steam_stage2:2, steam_stage3:2;

  /* NDPI_PROTOCOL_STARCRAFT */
  uint8_t starcraft_udp_stage : 3;	// 0-7

  /* NDPI_PROTOCOL_OPENVPN */
  uint8_t ovpn_session_id[8];
  uint8_t ovpn_counter;

  /* NDPI_PROTOCOL_TINC */
  uint8_t tinc_state;
  struct tinc_cache_entry tinc_cache_entry;

  /* NDPI_PROTOCOL_CSGO */
  uint8_t csgo_strid[18],csgo_state,csgo_s2;
  uint32_t csgo_id2;
  /* internal structures to save functions calls */
  struct ndpi_packet_struct packet;
  struct ndpi_flow_struct *flow;
  struct ndpi_id_struct *src;
  struct ndpi_id_struct *dst;
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
  char requested_server_name[256];
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
} nf_flow_t;
"""

cc_capture_apis = """
pcap_t * capture_open(const uint8_t * pcap_file, int mode, char * child_error);
int capture_set_fanout(pcap_t * pcap_handle, int mode, char * child_error);
int capture_set_timeout(pcap_t * pcap_handle, int mode, char * child_error);
int capture_set_promisc(pcap_t * pcap_handle, int mode, char * child_error, int promisc);
int capture_set_snaplen(pcap_t * pcap_handle, int mode, char * child_error, unsigned snaplen);
int capture_set_filter(pcap_t * pcap_handle, char * bpf_filter, char * child_error);
int capture_next(pcap_t * pcap_handle, struct nf_packet *nf_pkt, int decode_tunnels, int n_roots, int root_idx, int mode);
void capture_stats(pcap_t * pcap_handle, struct nf_stat *nf_statistics, unsigned mode);
void capture_close(pcap_t * pcap_handle);
int capture_activate(pcap_t * pcap_handle, int mode, char * child_error);
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


def create_engine():
    """ engine creation function, return the loaded native nfstream engine and it's ffi interface"""
    ffi = cffi.FFI()
    lib = ffi.dlopen(dirname(abspath(__file__)) + '/engine_cc.so')
    ffi.cdef(cc_capture_headers)
    ffi.cdef(cc_dissector_headers_packed, packed=True, override=True)
    ffi.cdef(cc_dissector_headers, override=True)
    ffi.cdef(cc_meter_headers, override=True)
    ffi.cdef(cc_capture_apis, override=True)
    ffi.cdef(cc_dissector_apis, override=True)
    ffi.cdef(cc_meter_apis, override=True)
    return ffi, lib
