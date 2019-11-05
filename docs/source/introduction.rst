Introduction
============

.. image:: asset/simplified_architecture.png
  :scale: 100%
  :align: center


A step by step walk through each process involved when performing flow monitoring is
developed in the this section. Our aim is to provide you with a reminder about how
things works in theory. Consequently, an easier understanding of nfstream features
and implementation is possible.

Packet observation
------------------
Packet observation is a key stage in a flow monitoring architecture as it is the
starting point. Consequently, we detail in the following each step involved at this
phase:

**Packet capture:**: This step is performed on the Network Interface Card (NIC) level.
After passing various checks such as checksum error, packets stored in on-card
reception buffers are moved to the hosting device memory. Several libraries are
available to capture network traffic such as libpcap for UNIX based operating systems
Winpcap for Windows. These libraries are running on the top of the operating system
stack which may reduce performances passing through several layers.
To overcome such limitation in a high speed network context, software optimization
technique are proposed and could be considered (e.g. Intel DPDK, PF-RING, netmap).

**Timestamping:** As packets may come from several observation points, reordering
process is based on packet’s timestamp. While hardware timestamping provides a high
accuracy up to 100 nanoseconds in case of the IEEE 1588 protocol, it’s not supported
by most of commodity NIC. Software timestamping is widely used to outcome this lack
providing an accuracy up to 100 microseconds.

**Truncation (optional):** Defining a snapshot length, the process selects precise
bytes from the packet. It is performed in some cases to reduce the amount of data
captured by the probe and therefore CPU and bus bandwidth load.

**Packet sampling (optional):** is generally performed to reduce load on subsequent
stages. It can be systematic (periodic sampling scheme) or random. The latter is
recommended as periodic scheme may introduce unwanted correlation in the observed
network data.

**Packet filtering (optional):** performs filtering of packets to separate packets
having specific properties from those not having them. A packet is selected if
some specific fields are equal or in the range of given values. Another technique is
a hash based filtering, applying a hash function on a portion of the packet,
the result is compared to a value or a range of values.