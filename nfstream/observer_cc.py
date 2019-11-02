cc = """
typedef uint8_t u_char;
struct pcap;
typedef struct pcap pcap_t;
struct pcap_dumper;
typedef struct pcap_dumper pcap_dumper_t;
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
typedef struct pcap_if pcap_if_t;
int pcap_findalldevs(pcap_if_t **, char *);
void pcap_freealldevs(pcap_if_t *);
struct pcap_pkthdr {
    long tv_sec;
    long tv_usec;
    unsigned int caplen;
    unsigned int len;
};

struct pcap_stat {
    unsigned int recv;
    unsigned int drop;
    unsigned int ifdrop;
};

typedef void (*pcap_handler)(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);

pcap_t *pcap_open_dead(int, int);
pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);
void pcap_dump_close(pcap_dumper_t *);
void pcap_dump(pcap_dumper_t *, struct pcap_pkthdr *, unsigned char *);

// live capture
pcap_t *pcap_create(const char *, char *); 
pcap_t *pcap_open_live(const char *, int, int, int, char *);
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
int pcap_set_snaplen(pcap_t *, int);
int pcap_snapshot(pcap_t *);
int pcap_set_promisc(pcap_t *, int);

int pcap_set_timeout(pcap_t *, int);
int pcap_set_buffer_size(pcap_t *, int);

int pcap_set_tstamp_precision(pcap_t *, int);
int pcap_get_tstamp_precision(pcap_t *);
int pcap_set_tstamp_type(pcap_t *, int);
int pcap_list_tstamp_types(pcap_t *, int **);
void pcap_free_tstamp_types(int *);

int pcap_setdirection(pcap_t *, int); 
int pcap_datalink(pcap_t *);
int pcap_setnonblock(pcap_t *, int, char *); 
int pcap_getnonblock(pcap_t *, char *); 
int pcap_set_immediate_mode(pcap_t *, int);
int pcap_next_ex(pcap_t *, struct pcap_pkthdr **, const unsigned char **);
int pcap_dispatch(pcap_t *, int, pcap_handler, unsigned char *);
int pcap_loop(pcap_t *, int, pcap_handler, unsigned char *);
void pcap_breakloop(pcap_t *);
int pcap_activate(pcap_t *);
void pcap_close(pcap_t *);
int pcap_get_selectable_fd(pcap_t *);
int pcap_sendpacket(pcap_t *, const unsigned char *, int);
char *pcap_geterr(pcap_t *);
char *pcap_lib_version();
int pcap_stats(pcap_t *, struct pcap_stat *);

struct bpf_insn;
struct bpf_program {
    unsigned int bf_len;
    struct bpf_insn *bf_insns;
};
int pcap_setfilter(pcap_t *, struct bpf_program *);
int pcap_compile(pcap_t *, struct bpf_program *, const char *, int, unsigned int);
void pcap_freecode(struct bpf_program *);

struct nfstream_ethhdr
{
  u_char h_dest[6];
  u_char h_source[6];
  uint16_t h_proto;
};

struct nfstream_snap_extension
{
  uint16_t oui;
  uint8_t oui2;
  uint16_t proto_ID;
};
struct nfstream_llc_header_snap
{
  uint8_t dsap;
  uint8_t ssap;
  uint8_t ctrl;
  struct nfstream_snap_extension snap;
};
struct nfstream_chdlc
{
  uint8_t addr;
  uint8_t ctrl;
  uint16_t proto_code;
};
struct nfstream_radiotap_header
{
  uint8_t version;
  uint8_t pad;
  uint16_t len;
  uint32_t present;
  uint64_t MAC_timestamp;
  uint8_t flags;
};
struct nfstream_wifi_header
{
  uint16_t fc;
  uint16_t duration;
  u_char rcvr[6];
  u_char trsm[6];
  u_char dest[6];
  uint16_t seq_ctrl;
};
struct nfstream_mpls_header
{
  uint32_t ttl:8, s:1, exp:3, label:20;
};
extern union mpls {
  uint32_t u32;
  struct nfstream_mpls_header mpls;
} mpls;
struct nfstream_iphdr {
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
struct nfstream_in6_addr {
  union {
    uint8_t u6_addr8[16];
    uint16_t u6_addr16[8];
    uint32_t u6_addr32[4];
  } u6_addr;
};
struct nfstream_ip6_hdrctl {
  uint32_t ip6_un1_flow;
  uint16_t ip6_un1_plen;
  uint8_t ip6_un1_nxt;
  uint8_t ip6_un1_hlim;
};
struct nfstream_ipv6hdr {
  struct nfstream_ip6_hdrctl ip6_hdr;
  struct nfstream_in6_addr ip6_src;
  struct nfstream_in6_addr ip6_dst;
};
struct nfstream_udphdr
{
  uint16_t source;
  uint16_t dest;
  uint16_t len;
  uint16_t check;
};
struct pp_32 {
    uint32_t value;
};
struct nfstream_tcphdr
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
"""