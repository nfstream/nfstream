/* $Id$ */

#ifndef PCAP_EX_H
#define PCAP_EX_H

int   pcap_ex_immediate(pcap_t *pcap);
char *pcap_ex_name(char *name);
char *pcap_ex_lookupdev(char *ebuf);
int   pcap_ex_fileno(pcap_t *pcap);
void  pcap_ex_setup(pcap_t *pcap);
void  pcap_ex_setnonblock(pcap_t *pcap, int nonblock, char *ebuf);
int   pcap_ex_getnonblock(pcap_t *pcap, char *ebuf);
int   pcap_ex_next(pcap_t *pcap, struct pcap_pkthdr *hdr, u_char **pkt);
int   pcap_ex_setdirection(pcap_t *pcap, int direction);
int   pcap_ex_compile_nopcap(int snaplen, int dlt, struct bpf_program *fp,
          char *str, int optimize, unsigned int netmask);
int   pcap_ex_get_tstamp_precision(pcap_t *pcap);
int   pcap_ex_set_tstamp_precision(pcap_t *pcap, int tstamp_precision);
pcap_t *pcap_ex_open_offline_with_tstamp_precision(char *fname,
          unsigned int precision, char *errbuf);

#endif /* PCAP_EX_H */
