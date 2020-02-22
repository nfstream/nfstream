#########################
Get started with nfstream
#########################


Dealing with a big pcap file and just want to aggregate it as network flows?
nfstream make this path easier in few lines:

.. code-block:: python

   from nfstream import NFStreamer
   my_capture_streamer = NFStreamer(source="facebook.pcap",
                                    snaplen=65535,
                                    idle_timeout=30,
                                    active_timeout=300,
                                    plugins=(),
                                    dissect=True,
                                    max_tcp_dissections=10,
                                    max_udp_dissections=16)

   my_live_streamer = NFStreamer(source="eth1")  # or capture from a network interface
   for flow in my_capture_streamer:  # or for flow in my_live_streamer
       print(flow)  # print, append to pandas Dataframe or whatever you want :)!


*****************
NFStreamer object
*****************
* ``source`` [default= ``None`` ]

  - Source of packets. Can be ``live_interface_name`` or  ``pcap_file_path``.

* ``snaplen`` [default= ``65535`` ]

  - Packet capture length.

* ``idle_timeout`` [default= ``30`` ]

  - Flows that are inactive for more than this value in seconds will be exported.

* ``active_timeout`` [default= ``300`` ]

  - Flows that are active for more than this value in seconds will be exported.

* ``plugins`` [default= ``()`` ]

  - Set of user defined NFPlugins.

* ``dissect`` [default= ``True`` ]

  - Enable nDPI deep packet inspection library for Layer 7 visibility.

* ``max_tcp_dissections`` [default= ``10`` ]

  - Maximum per flow TCP packets to dissect (ignored when dissect=False).

* ``max_udp_dissections`` [default= ``16`` ]

  - Maximum per flow UDP packets to dissect (ignored when dissect=False).

NFStreamer returns an iterator of **NFEntry** object.

**************
NFEntry object
**************

.. list-table:: NFEntry object
   :widths: 25 25 50
   :header-rows: 1

   * - attribute name
     - attribute type
     - attribute description
   * - id
     - int
     - Flow identifier.
   * - first_seen
     - int
     - First packet timestamp in milliseconds.
   * - last_seen
     - int
     - Last packet timestamp in milliseconds.
   * - version
     - int
     - IP version.
   * - src_port
     - int
     - Transport layer source port.
   * - dst_port
     - int
     - Transport layer destination port.
   * - protocol
     - int
     - Transport layer protocol.
   * - vlan_id
     - int
     - Virtual LAN identifier.
   * - src_ip
     - str
     - Source IP address string representation.
   * - dst_ip
     - str
     - Destination IP address string representation.
   * - ip_src
     - int
     - Source IP address int value. [``volatile``]
   * - ip_dst
     - int
     - Destination IP address int value. [``volatile``]
   * - total_packets
     - int
     - Flow packets accumulator.
   * - total_bytes
     - int
     - Flow bytes (full packet lentgh) accumulator.
   * - duration
     - int
     - Flow duration in milliseconds.
   * - src2dst_packets
     - int
     - Flow packets accumulator (source->destination).
   * - src2dst_bytes
     - int
     - Flow bytes (full packet lentgh) accumulator (source->destination).
   * - dst2src_packets
     - int
     - Flow packets accumulator (destination->source).
   * - dst2src_bytes
     - int
     - Flow bytes (full packet lentgh) accumulator (destination->source).
   * - expiration_id
     - int
     - Identifier of flow expiration trigger. Can be ``0`` for idle_timeout, ``1`` for active_timeout or 'negative' for custom expiration.
   * - master_protocol
     - int
     - nDPI master protocol identifier.
   * - app_protocol
     - int
     - nDPI app protocol identifier.
   * - application_name
     - str
     - nDPI application name.
   * - category_name
     - str
     - nDPI application category name.
   * - client_info
     - str
     - Dissected client informations. Can be ``http_detected_os`` for HTTP, ``client_signature`` for SSH or ``client_requested_server_name`` for SSL.
   * - server_info
     - str
     - Dissected server informations. Can be ``host_server_name`` for HTTP or DNS, ``server_signature`` for SSH or ``server_names`` for SSL.
   * - j3a_client
     - str
     - J3A_ client fingerprint.
   * - j3a_server
     - str
     - J3A_ server fingerprint.

**NFEntry** is an aggregation of **NFPacket** objects.

***************
NFPacket object
***************

.. list-table:: NFPacket object
   :widths: 25 25 50
   :header-rows: 1

   * - attribute name
     - attribute type
     - attribute description
   * - time
     - int
     - Packet timestamp in milliseconds.
   * - capture_length
     - int
     - Packet capture length.
   * - length
     - int
     - Packet size.
   * - ip_src
     - int
     - Source IP address int value.
   * - ip_dst
     - int
     - Destination IP address int value.
   * - src_port
     - int
     - Transport layer source port.
   * - dst_port
     - int
     - Transport layer destination port.
   * - protocol
     - int
     - Transport layer protocol.
   * - vlan_id
     - int
     - Virtual LAN identifier.
   * - version
     - int
     - IP version.
   * - tcp_flags
     - int
     - Packet observed TCP flags.
   * - raw
     - bytes
     - Raw content starting from IP Header.
   * - direction
     - int
     - Packet direction: ``0`` for src_to_dst and  ``1`` for dst_to_src.


.. _J3A: https://github.com/salesforce/ja3
