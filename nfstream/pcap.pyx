import sys
import struct

from cython cimport view
from libc.stdlib cimport free
from libc.string cimport strdup

cdef extern from "Python.h":
    int    PyObject_AsCharBuffer(object obj, char **buffer, Py_ssize_t *buffer_len)

ctypedef unsigned int u_int
ctypedef unsigned char u_char

cdef extern from "pcap.h":
    struct bpf_insn:
        int __xxx
    struct bpf_program:
        bpf_insn *bf_insns
    struct bpf_timeval:
        unsigned int tv_sec
        unsigned int tv_usec
    struct pcap_stat:
        unsigned int ps_recv
        unsigned int ps_drop
        unsigned int ps_ifdrop
    struct pcap_pkthdr:
        bpf_timeval ts
        u_int caplen
    ctypedef struct pcap_t:
        int __xxx
    ctypedef struct pcap_if_t # hack for win32
    ctypedef struct pcap_if_t:
        pcap_if_t *next
        char *name

ctypedef void (*pcap_handler)(u_char *arg, const pcap_pkthdr *hdr, const u_char *pkt)

cdef extern from "pcap.h":
    pcap_t *pcap_open_live(char *device, int snaplen, int promisc,
                           int to_ms, char *errbuf)
    pcap_t *pcap_open_offline(char *fname, char *errbuf)
    pcap_t *pcap_create(char *source, char *errbuf)
    int     pcap_set_snaplen(pcap_t *p, int snaplen)
    int     pcap_set_promisc(pcap_t *p, int promisc)
    int     pcap_set_timeout(pcap_t *p, int to_ms)
    int     pcap_set_immediate_mode(pcap_t *p, int immediate_mode)
    int     pcap_set_rfmon(pcap_t *p, int rfmon)
    int     pcap_activate(pcap_t *p)
    int     pcap_compile(pcap_t *p, bpf_program *fp, char *str, int optimize,
                         unsigned int netmask)
    int     pcap_setfilter(pcap_t *p, bpf_program *fp)
    void    pcap_freecode(bpf_program *fp)
    int     pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback,
                          unsigned char *arg)
    unsigned char *pcap_next(pcap_t *p, pcap_pkthdr *hdr)
    int     pcap_datalink(pcap_t *p)
    int     pcap_snapshot(pcap_t *p)
    int     pcap_stats(pcap_t *p, pcap_stat *ps)
    char   *pcap_geterr(pcap_t *p)
    void    pcap_close(pcap_t *p)
    int     bpf_filter(bpf_insn *insns, const u_char *buf, u_int len, u_int caplen)
    int     pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
    void    pcap_freealldevs(pcap_if_t *alldevs)
    int     pcap_lookupnet(char *device,
                           unsigned int *netp,
                           unsigned int *maskp,
                           char *errbuf)
    int     pcap_sendpacket(pcap_t *p, const u_char *buf, int size)

cdef extern from "pcap_ex.h":
    # XXX - hrr, sync with libdnet and libevent
    int     pcap_ex_immediate(pcap_t *p)
    char   *pcap_ex_name(char *name)
    char   *pcap_ex_lookupdev(char *ebuf)
    int     pcap_ex_fileno(pcap_t *p)
    void    pcap_ex_setup(pcap_t *p)
    void    pcap_ex_setnonblock(pcap_t *p, int nonblock, char *ebuf)
    int     pcap_ex_getnonblock(pcap_t *p, char *ebuf)
    int    pcap_ex_setdirection(pcap_t *p, int direction)
    int     pcap_ex_next(pcap_t *p, pcap_pkthdr *hdr, u_char **pkt) nogil
    int     pcap_ex_compile_nopcap(int snaplen, int dlt,
                                   bpf_program *fp, char *str,
                                   int optimize, unsigned int netmask)
    int     pcap_ex_get_tstamp_precision(pcap_t *p)
    int     pcap_ex_set_tstamp_precision(pcap_t *p, int tstamp_precision)
    pcap_t *pcap_ex_open_offline_with_tstamp_precision(char *fname,
                                                       unsigned int precision,
                                                       char *errbuf)

cdef class pcap_handler_ctx:
    cdef:
        double scale
        long long scale_ns
        bint timestamp_in_ns
        void *callback
        void *args
        object exc


cdef object get_buffer(const u_char *pkt, u_int len):
    cdef bytes pkt_view = (<char *>pkt)[:len]
    return pkt_view


cdef void __pcap_handler(u_char *arg, const pcap_pkthdr *hdr, const u_char *pkt) with gil:
    cdef pcap_handler_ctx ctx = <pcap_handler_ctx><void*>arg
    try:
        if ctx.timestamp_in_ns:
            (<object>ctx.callback)(
                (hdr.ts.tv_sec * 1000000000LL) + (hdr.ts.tv_usec * ctx.scale_ns),
                get_buffer(pkt, hdr.caplen),
                *(<object>ctx.args)
            )
        else:
            (<object>ctx.callback)(
                hdr.ts.tv_sec + (hdr.ts.tv_usec * ctx.scale),
                get_buffer(pkt, hdr.caplen),
                *(<object>ctx.args)
            )
    except:
        ctx.exc = sys.exc_info()

DLT_NULL =	0
DLT_EN10MB =	1
DLT_EN3MB =	2
DLT_AX25 =	3
DLT_PRONET =	4
DLT_CHAOS =	5
DLT_IEEE802 =	6
DLT_ARCNET =	7
DLT_SLIP =	8
DLT_PPP =	9
DLT_FDDI =	10
# XXX - Linux
DLT_LINUX_SLL =	113
# XXX - OpenBSD
DLT_PFLOG =	117
DLT_PFSYNC =	18
if sys.platform.find('openbsd') != -1:
    DLT_LOOP =		12
    DLT_RAW =		14
else:
    DLT_LOOP =		108
    DLT_RAW =		12

PCAP_D_INOUT = 0
PCAP_D_IN = 1
PCAP_D_OUT = 2

PCAP_TSTAMP_PRECISION_MICRO = 0
PCAP_TSTAMP_PRECISION_NANO = 1

dltoff = { DLT_NULL:4, DLT_EN10MB:14, DLT_IEEE802:22, DLT_ARCNET:6,
          DLT_SLIP:16, DLT_PPP:4, DLT_FDDI:21, DLT_PFLOG:48, DLT_PFSYNC:4,
          DLT_LOOP:4, DLT_RAW:0, DLT_LINUX_SLL:16 }


cdef class bpf:
    """bpf(filter, dlt=DLT_RAW) -> BPF filter object"""

    cdef bpf_program fcode

    def __init__(self, char *filter, dlt=DLT_RAW):
        if pcap_ex_compile_nopcap(65535, dlt, &self.fcode, filter, 1, 0) < 0:
            raise IOError, 'bad filter'

    def filter(self, buf):
        """Return boolean match for buf against our filter."""
        cdef u_char *p
        cdef Py_ssize_t n
        if PyObject_AsCharBuffer(buf, <const char**>&p, &n) < 0:
            raise TypeError
        return bpf_filter(self.fcode.bf_insns, p, <u_int>n, <u_int>n) != 0

    def __dealloc__(self):
        pcap_freecode(&self.fcode)


cdef class pcap:
    """pcap(name=None, snaplen=65535, promisc=True, timeout_ms=None, immediate=False, timestamp_in_ns=False)  -> packet capture object

    Open a handle to a packet capture descriptor.

    Keyword arguments:
    name      -- name of a network interface or dumpfile to open,
                 or None to open the first available up interface
    snaplen   -- maximum number of bytes to capture for each packet
    promisc   -- boolean to specify promiscuous mode sniffing
    timeout_ms -- requests for the next packet will return None if the timeout
                  (in milliseconds) is reached and no packets were received
                  (Default: no timeout)
    immediate -- disable buffering, if possible
    timestamp_in_ns -- report timestamps in integer nanoseconds
    """
    cdef pcap_t *__pcap
    cdef char *__name
    cdef char *__filter
    cdef char __ebuf[256]
    cdef int __dloff
    cdef double __precision_scale
    cdef long long __precision_scale_ns
    cdef bint __timestamp_in_ns

    def __init__(self, name=None, snaplen=65535, promisc=True,
                 timeout_ms=0, immediate=False, rfmon=False,
                 timestamp_in_ns=False):
        global dltoff
        cdef char *p

        if not name:
            p = pcap_ex_lookupdev(self.__ebuf)
            if p == NULL:
                raise OSError, self.__ebuf
        else:
            py_byte_name = name.encode('UTF-8')
            p = py_byte_name

        self.__pcap = pcap_ex_open_offline_with_tstamp_precision(
            p, PCAP_TSTAMP_PRECISION_NANO, self.__ebuf)
        if not self.__pcap:
            self.__pcap = pcap_create(pcap_ex_name(p), self.__ebuf)
            passing = True
            def check_return(ret, descrip):
                if ret != 0:
                    raise OSError, "%s failed to execute" % descrip
            check_return(pcap_set_snaplen(self.__pcap, snaplen),
                         "Set snaplength")
            check_return(pcap_set_promisc(self.__pcap, promisc),
                         "Set promiscuous mode")
            check_return(pcap_set_timeout(self.__pcap, timeout_ms),
                         "Set timeout")
            check_return(pcap_set_immediate_mode(self.__pcap, immediate),
                         "Set immediate mode")
            check_return(pcap_set_rfmon(self.__pcap, rfmon),
                         "Set monitor mode")
            # Ask for nano-second precision, but don't fail if not available.
            pcap_ex_set_tstamp_precision(self.__pcap, PCAP_TSTAMP_PRECISION_NANO)
            if pcap_activate(self.__pcap) != 0:
                raise OSError, ("Activateing packet capture failed. "
                                "Error returned by packet capture library "
                                "was %s" % pcap_geterr(self.__pcap))

        if not self.__pcap:
            raise OSError, self.__ebuf

        self.__name = strdup(p)
        self.__filter = strdup("")
        self.__timestamp_in_ns = timestamp_in_ns
        precision = pcap_ex_get_tstamp_precision(self.__pcap)
        if precision == PCAP_TSTAMP_PRECISION_MICRO:
            self.__precision_scale = 1e-6
            self.__precision_scale_ns = 1000
        elif precision == PCAP_TSTAMP_PRECISION_NANO:
            self.__precision_scale = 1e-9
            self.__precision_scale_ns = 1
        else:
            raise OSError, "couldn't determine timestamp precision"
        try:
            self.__dloff = dltoff[pcap_datalink(self.__pcap)]
        except KeyError:
            pass
        if immediate and pcap_ex_immediate(self.__pcap) < 0:
            raise OSError, "couldn't enable immediate mode"

    property name:
        """Network interface or dumpfile name."""
        def __get__(self):
            return str(self.__name.decode('UTF-8'))

    property snaplen:
        """Maximum number of bytes to capture for each packet."""
        def __get__(self):
            return pcap_snapshot(self.__pcap)

    property dloff:
        """Datalink offset (length of layer-2 frame header)."""
        def __get__(self):
            return self.__dloff

    property filter:
        """Current packet capture filter."""
        def __get__(self):
            return str(self.__filter.decode('UTF-8'))

    property fd:
        """File descriptor (or Win32 HANDLE) for capture handle."""
        def __get__(self):
            return pcap_ex_fileno(self.__pcap)

    property precision:
        """Precision of timestamps"""
        def __get__(self):
            return pcap_ex_get_tstamp_precision(self.__pcap)

    property timestamp_in_ns:
        """Whether timestamps are returned in nanosecond units"""
        def __get__(self):
            return self.__timestamp_in_ns

    def fileno(self):
        """Return file descriptor (or Win32 HANDLE) for capture handle."""
        return pcap_ex_fileno(self.__pcap)

    def close(self):
        """Explicitly close the underlying pcap handle"""
        pcap_close(self.__pcap)
        self.__pcap = NULL

    def setfilter(self, value, optimize=1):
        """Set BPF-format packet capture filter."""
        cdef bpf_program fcode
        free(self.__filter)
        py_byte_value = value.encode('UTF-8')
        self.__filter = strdup(py_byte_value)
        if pcap_compile(self.__pcap, &fcode, self.__filter, optimize, 0) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        if pcap_setfilter(self.__pcap, &fcode) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        pcap_freecode(&fcode)

    def setdirection(self, direction):
        """Set capture direction."""
        return pcap_ex_setdirection(self.__pcap, direction) == 0

    def setnonblock(self, nonblock=True):
        """Set non-blocking capture mode."""
        pcap_ex_setnonblock(self.__pcap, nonblock, self.__ebuf)

    def getnonblock(self):
        """Return non-blocking capture mode as boolean."""
        ret = pcap_ex_getnonblock(self.__pcap, self.__ebuf)
        if ret < 0:
            raise OSError, self.__ebuf
        return ret != 0

    def datalink(self):
        """Return datalink type (DLT_* values)."""
        return pcap_datalink(self.__pcap)

    def __add_pkts(self, ts, pkt, pkts):
        pkts.append((ts, pkt))

    def readpkts(self):
        """Return a list of (timestamp, packet) tuples received in one buffer."""
        pkts = []
        self.dispatch(-1, self.__add_pkts, pkts)
        return pkts

    def dispatch(self, cnt, callback, *args):
        """Collect and process packets with a user callback,
        return the number of packets processed, or 0 for a savefile.

        Arguments:

        cnt      -- number of packets to process;
                    or 0 to process all packets until an error occurs,
                    EOF is reached, or the read times out;
                    or -1 to process all packets received in one buffer
        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        cdef pcap_handler_ctx ctx = pcap_handler_ctx()
        cdef int n

        ctx.scale = self.__precision_scale
        ctx.scale_ns = self.__precision_scale_ns
        ctx.timestamp_in_ns = self.__timestamp_in_ns
        ctx.callback = <void *>callback
        ctx.args = <void *>args
        n = pcap_dispatch(self.__pcap, cnt, __pcap_handler, <u_char *><void*>ctx)
        if ctx.exc:
            raise ctx.exc[0], ctx.exc[1], ctx.exc[2]
        return n

    def loop(self, cnt, callback, *args):
        """Processing packets with a user callback during a loop.
        The loop can be exited when cnt value is reached
        or with an exception, including KeyboardInterrupt.

        Arguments:

        cnt      -- number of packets to process;
                    0 or -1 to process all packets until an error occurs,
                    EOF is reached;
        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        cdef pcap_pkthdr hdr
        cdef u_char *pkt
        cdef int n
        cdef int i = 1
        cdef double scale = self.__precision_scale
        cdef long long scale_ns = self.__precision_scale_ns
        cdef bint timestamp_in_ns = self.__timestamp_in_ns
        pcap_ex_setup(self.__pcap)
        while 1:
            with nogil:
                n = pcap_ex_next(self.__pcap, &hdr, &pkt)
            if n == 1:
                if timestamp_in_ns:
                    callback(
                        (hdr.ts.tv_sec * 1000000000LL) + (hdr.ts.tv_usec * scale_ns),
                        get_buffer(pkt, hdr.caplen),
                        *args
                    )
                else:
                    callback(
                        hdr.ts.tv_sec + (hdr.ts.tv_usec * scale),
                        get_buffer(pkt, hdr.caplen),
                        *args
                    )
            elif n == 0:
                continue
            elif n == -1:
                raise KeyboardInterrupt
            elif n == -2:
                break
            if i == cnt:
                break
            i = i + 1

    def sendpacket(self, buf):
        """Send a raw network packet on the interface."""
        ret = pcap_sendpacket(self.__pcap, buf, <int>len(buf))
        if ret == -1:
            raise OSError, pcap_geterr(self.__pcap)
        return len(buf)

    def geterr(self):
        """Return the last error message associated with this handle."""
        return pcap_geterr(self.__pcap)

    def stats(self):
        """Return a 3-tuple of the total number of packets received,
        dropped, and dropped by the interface."""
        cdef pcap_stat pstat
        if pcap_stats(self.__pcap, &pstat) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        return (pstat.ps_recv, pstat.ps_drop, pstat.ps_ifdrop)

    def __iter__(self):
        pcap_ex_setup(self.__pcap)
        return self

    def __next__(self):
        cdef pcap_pkthdr hdr
        cdef u_char *pkt
        cdef int n
        cdef double scale = self.__precision_scale
        cdef long long scale_ns = self.__precision_scale_ns
        cdef bint timestamp_in_ns = self.__timestamp_in_ns
        cdef double timestamp
        cdef long long timestamp_ns
        while 1:
            with nogil:
                n = pcap_ex_next(self.__pcap, &hdr, &pkt)
            if n == 1:
                if timestamp_in_ns:
                    timestamp_ns = (hdr.ts.tv_sec * 1000000000LL) + (hdr.ts.tv_usec * scale_ns)
                    return (timestamp_ns, get_buffer(pkt, hdr.caplen))
                else:
                    timestamp = hdr.ts.tv_sec + (hdr.ts.tv_usec * scale)
                    return (timestamp, get_buffer(pkt, hdr.caplen))
            elif n == 0:
                continue
            elif n == -1:
                raise KeyboardInterrupt
            elif n == -2:
                raise StopIteration

    def __dealloc__(self):
        if self.__name:
            free(self.__name)
        if self.__filter:
            free(self.__filter)
        if self.__pcap:
            pcap_close(self.__pcap)

def ex_name(char *foo):
    return pcap_ex_name(foo)

def lookupdev():
    """Return the name of a network device suitable for sniffing."""
    cdef char *p
    cdef char ebuf[256]
    p = pcap_ex_lookupdev(ebuf)
    if p == NULL:
        raise OSError, ebuf
    return str(p.decode('UTF-8'))

def findalldevs():
    """Return a list of capture devices."""
    cdef pcap_if_t *devs
    cdef pcap_if_t *curr
    cdef char ebuf[256]

    status = pcap_findalldevs(&devs, ebuf)
    if status:
        raise OSError(ebuf)
    retval = []
    if not devs:
        return retval
    curr = devs
    while 1:
        retval.append(str(curr.name.decode('UTF-8')))
        if not curr.next:
            break
        curr = curr.next
    pcap_freealldevs(devs)
    return retval

def lookupnet(char *dev):
    """
    Return the address and the netmask of a given device
    as network-byteorder integers.
    """
    cdef unsigned int netp
    cdef unsigned int maskp
    cdef char ebuf[256]

    status = pcap_lookupnet(dev, &netp, &maskp, ebuf)
    if status:
        raise OSError(ebuf)
    return struct.pack('I', netp), struct.pack('I', maskp)
