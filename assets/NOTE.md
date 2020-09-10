To avoid misinterpretation of performance summary on live interface, Please keep in mind the following
notes:
* Please find [**here**](https://linux.die.net/man/3/pcap_stats), detailed implementation of dropped by kernel and 
dropped by interface metrics and how reported value may vary from platform to another.
* Also, **dropped/filtered by kernel** include packets not yet read from the kernel by libpcap, and thus not yet seen 
by NFStream at the the time you interrupt it. This is based on the following 
[**source**](https://github.com/the-tcpdump-group/libpcap/blob/5905a7b75298fd87d7aef5d2db04191f1a4e8e88/pcap-linux.c#L1329).