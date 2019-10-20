Tutorials
=========

Reading a pcap file ot network interface
----------------------------------------


Dealing with a big pcap file and just want to see flow informations stored in as a csv file or pandas Dataframe?
nfstream make this path easier in few lines:

.. code-block:: python

   from nfstream.streamer import Streamer
   my_capture_streamer = Streamer(source="instagram.pcap",
                                  capacity=128000,
                                  active_timeout=120,
                                  inactive_timeout=60)
   my_live_streamer = Streamer(source="eth1")  # or capture from a network interface
   for flow in my_capture_streamer:  # or for flow in my_live_streamer
       print(flow)  # print, append to pandas Dataframe or whatever you want :)!

.. note::
   **Streamer arguments**

   * source: source od packets. Network interface or pcap file path.

   * capacity: maximum streamer real-time capacity. When this capacity is reached, least recently used flows will be dropped. (Default: 128000)

   * active_timeout: flows that are active for more than this value in seconds will be exported. (Default: 120)

   * inactive_timeout: flows that are inactive for more than this value in seconds will be exported. (Default: 120)

   * user_metrics: dict with metric_name as key ans callback as value. (Default {})


This will print a json representation of nfstream flow object:

.. code-block:: json

 {"ip_src": "192.168.122.121", # IP source address
  "src_port": 43277, # Transport source port
  "ip_dst": "186.102.189.33", # IP destination address
  "dst_port": 443, # Transport destination port
  "ip_protocol": 6, # Transport protocol (TCP, UDP, etc.)
  "src_to_dst_pkts": 6, # Count of packets sent src -> dst direction
  "dst_to_src_pkts": 5, # Count of packets sent dst -> src direction
  "src_to_dst_bytes": 1456, #  Bytes sent src -> dst direction
  "dst_to_src_bytes": 477, # Bytes sent dst -> src direction
  "application_name": "TLS.Instagram", # Detected application name (master.app)
  "category_name": "SocialNetwork", # Detected application category name
  "start_time": 1555969081636, # Flow start time in ms
  "end_time": 1555969082020, # Flow end time in ms
  "export_reason": 2} # export_reason: 0 for inactive, 1 for active and 2 for termination


Create your own flow metric
---------------------------

Didn't find a specific flow feature? add it to Streamer as a plugin in few lines:

.. code-block:: python

   from nfstream.streamer import Streamer

   def my_awesome_plugin(packet_information, flow):
       if packet_information.size > 666:
          flow.metrics['count_pkts_gt_666'] += 1
       return flow

   streamer_awesome = Streamer(source='devil.pcap',
                               user_metrics={'count_pkts_gt_666': my_awesome_plugin})
   for flow in streamer_awesome:
      # now you will see your created metric in generated flows
      print(flow.metrics['count_pkts_gt_666'])

.. warning::
   **Plugin signature**
   Your nfstream plugin must always update the received flow and **return the flow**.