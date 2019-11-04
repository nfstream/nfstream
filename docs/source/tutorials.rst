Tutorials
=========

Reading a pcap file ot network interface
----------------------------------------


Dealing with a big pcap file and just want to aggregate it as network flows? nfstream make this path easier in few lines:

.. code-block:: python

   from nfstream.streamer import Streamer
   my_capture_streamer = Streamer(source="instagram.pcap",
                                  capacity=128000,
                                  active_timeout=120,
                                  inactive_timeout=60,
                                  user_metrics=None,
                                  user_classifiers=None,
                                  enable_ndpi=True,
                                  bpf_filter=None,
                                  snaplen=65535)

   my_live_streamer = Streamer(source="eth1")  # or capture from a network interface
   for flow in my_capture_streamer:  # or for flow in my_live_streamer
       print(flow)  # print, append to pandas Dataframe or whatever you want :)!

.. note:: **Streamer arguments**

   **source** source od packets. Network interface or pcap file path.

   **capacity** maximum streamer real-time capacity. When this capacity is reached, least recently used flows will be dropped. (Default: 128000)

   **active_timeout** flows that are active for more than this value in seconds will be exported. (Default: 120)

   **inactive_timeout** flows that are inactive for more than this value in seconds will be exported. (Default: 120)

   **user_metrics** dict with metric_name as key ans callback as value. (Default None)

   **user_classifiers** NFStream Classifier or list of NFStream Classifiers. (Default None)

   **enable_ndpi** enable nDPI classifier a Layer 7 visibility. (Default True)

   **bpf_filter** BPF filter string. Example: "tcp src port 44614". (Default None)

   **snaplen** packet capture length. (Default 65535)


This will print a dict representation of nfstream flow object:

.. code-block:: json

   {"ip_src": "192.168.122.121", "src_port": 43277, "ip_dst": "186.102.189.33", "dst_port": 443, "ip_protocol": 6, "src_to_dst_pkts": 6, "dst_to_src_pkts": 5, "src_to_dst_bytes": 1456, "dst_to_src_bytes": 477, "application_name": "TLS.Instagram", "category_name": "SocialNetwork", "start_time": 1555969081636, "end_time": 1555969082020, "export_reason": 2}

.. note:: **Streamer arguments**

   **ip_src** IP source address.

   **src_port** Transport source port.

   **ip_dst** IP destination address.

   **dst_port** Transport destination port.

   **ip_protocol** Transport protocol (TCP, UDP, etc.).

   **src_to_dst_pkts** Count of packets sent src -> dst direction.

   **dst_to_src_pkts** Count of packets sent dst -> src direction.

   **src_to_dst_bytes** Bytes sent src -> dst direction.

   **dst_to_src_bytes** Bytes sent dst -> src direction.

   **application_name** Detected application name (master.app).

   **category_name** Detected application category name.

   **start_time** Flow start time in ms.

   **end_time** Flow end time in ms.

   **export_reason** Flow export reason: 0 for inactive, 1 for active and 2 for termination.

Create your own flow metric
---------------------------

Didn't find a specific flow feature? add a plugin to the Streamer in few lines:

.. code-block:: python

   from nfstream.streamer import Streamer

   def my_awesome_plugin(packet_information, flow, direction):
    old_value = flow.metrics['count_pkts_gt_666']
    if packet_information.length > 999:
        old_value = flow.metrics['count_pkts_gt_666']
        new_value =  old_value + 1
        return new_value
    else:
        return old_value

   streamer_awesome = Streamer(source='devil.pcap',
                               user_metrics={'count_pkts_gt_666': my_awesome_plugin})
   for export in streamer_awesome:
      # now you will see your created metric in generated flows
      print(export.metrics['count_pkts_gt_666'])

.. warning::
   **Plugin signature**

   * Your nfstream plugin must always **return the new value**.
   * nfstream always set metrics to 0 (Default value).

How if I want to log the size of the fourth packet from src -> dst ?

.. code-block:: python

   from nfstream.streamer import Streamer

   def my_awesome_plugin(packet_information, flow, direction):
    if flow.src_to_dst_pkts == 4 and direction == 0:
        return packet_information.length
    else:
        return 0

   streamer_awesome = Streamer(source='devil.pcap',
                               user_metrics={'fourth_src_to_dst_pkt_size': my_awesome_plugin})
   for export in streamer_awesome:
      # now you will see your created metric in generated flows
      print(export.metrics['fourth_src_to_dst_pkt_size'])

Create your own Classifier
--------------------------

If you want to add one or many classifiers to nfstream, you must create your classifier inheriting from
NFStreamClassifier.
Example, let's say that you have a trained Machine Learning Model and you want to use it to classify real traffic.
We suppose that your model takes as features the packet size of 3 first packets of a flow.

.. code-block:: python

    class DummyClassifier(NFStreamClassifier)
        def __init__(self, name):
            NFStreamClassifier.__init__(self, name)
            self.dummy_classifier = pickle.load(open('your_trained_model_file', "rb"))

        def on_flow_init(self, flow): # Initialize your flow features if needed
            flow.classifiers[self.name]['1'] = 0
            flow.classifiers[self.name]['2'] = 0
            flow.classifiers[self.name]['3'] = 0

        def on_flow_update(self, packet_information, flow, direction):
            number_packets = flow.src_to_dst_pkts + flow.dst_to_src_pkts
            if number_packets == 1:
                flow.classifiers[self.name]['1'] = packet_information.length
            elif number_packets == 2:
                flow.classifiers[self.name]['2'] = packet_information.length
            elif number_packets == 3:
                flow.classifiers[self.name]['3'] = packet_information.length
                flow.metrics[self.name]['prediction'] = self.dummy_classifier.predict(flow.classifiers[self.name]['1'],
                                                                                      flow.classifiers[self.name]['2'],
                                                                                      flow.classifiers[self.name]['3'])
                # Optionally, you can force the flow export by nfstream
                # flow.export_reason = 3
    def on_flow_terminate(self, flow):
        # Will be called when flow is expired by nfstream
        return

    def on_exit(self):
        # Will be called when nfstream is cleaning up.
        return

    my_capture_streamer = Streamer(source="instagram.pcap", user_classifiers=DummyClassifier("my_dummy_classifier"))