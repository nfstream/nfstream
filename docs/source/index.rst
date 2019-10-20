.. nfstream documentation master file, created by
   sphinx-quickstart on Sat Oct 19 16:26:59 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

========================
|nfstream_logo| nfstream
========================

|release| |build| |coverage| |quality| |python| |license|

nfstream is a flexible and lightweight network data analysis library.

**nfstream main features**

* **Performance:** nfstream was designed to be fast, CPU savvy and small memory fingerprint.
* **Layer-7 visibility:** nfstream dissection is based on nDPI_ (~300 applications including Tor, Messenger, WhatsApp, etc.).
* **Flexibility:** add a flow metric in 2 lines of code using nfstream plugins method.

**examples of use**

* Dealing with a big pcap file and just want to see flow informations stored in as a csv file or pandas Dataframe? nfstream make this path easier in few lines:

.. code-block:: python

   from nfstream.streamer import Streamer
   my_capture_streamer = Streamer(source="instagram.pcap",
                                  capacity=128000,
                                  active_timeout=120,
                                  inactive_timeout=60)
   my_live_streamer = Streamer(source="eth1")  # or capture from a network interface
   for flow in my_capture_streamer:  # or for flow in my_live_streamer
       print(flow)  # print, append to pandas Dataframe or whatever you want :)!
.. code-block:: json

 {"ip_src": "192.168.122.121",
  "src_port": 43277,
  "ip_dst": "186.102.189.33",
  "dst_port": 443,
  "ip_protocol": 6,
  "src_to_dst_pkts": 6,
  "dst_to_src_pkts": 5,
  "src_to_dst_bytes": 1456,
  "dst_to_src_bytes": 477,
  "application_name": "TLS.Instagram",
  "category_name": "SocialNetwork",
  "start_time": 1555969081636,
  "end_time": 1555969082020,
  "export_reason": 2}

* Didn't find a specific flow feature? add it to Streamer as a plugin in few lines:

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


.. toctree::
   :maxdepth: 2
   :caption: Contents:


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. |release| image:: https://img.shields.io/pypi/v/nfstream.svg
              :target: https://pypi.python.org/pypi/nfstream
.. |nfstream_logo| image:: https://github.com/aouinizied/nfstream/blob/master/docs/nfstream_logo.png
.. |build| image:: https://travis-ci.org/aouinizied/nfstream.svg?branch=master
               :target: https://travis-ci.org/aouinizied/nfstream
.. |coverage| image:: https://codecov.io/gh/aouinizied/nfstream/branch/master/graph/badge.svg
               :target: https://codecov.io/gh/aouinizied/nfstream/
.. |quality| image:: https://img.shields.io/lgtm/grade/python/github/aouinizied/nfstream.svg?logo=lgtm&logoWidth=18)
               :target: https://lgtm.com/projects/g/aouinizied/nfstream/context:python
.. |python| image:: https://img.shields.io/badge/python-3.x-blue.svg
               :target: https://travis-ci.org/aouinizied/nfstream
.. |license| image:: https://img.shields.io/badge/license-LGPLv3-blue.svg
               :target: LICENSE

.. _nDPI: https://www.ntop.org/products/deep-packet-inspection/ndpi/
