========================
|nfstream_logo| nfstream
========================

|build| |coverage| |quality| |doc| |download| |release| |python| |platform| |license|

nfstream is a flexible and lightweight network data analysis library.

**nfstream main features**

* **Performance:** nfstream was designed to be fast with a small CPU and memory footprint.
* **Layer-7 visibility:** nfstream dissection is based on nDPI_ (~300 applications including Tor, Messenger, WhatsApp, etc.).
* **Flexibility:** add a flow metric in 2 lines of code using nfstream plugins method.
* **Machine Learning oriented:** add your trained model as an NFStreamClassifier_.

**Use**

* Dealing with a big pcap file and just want to aggregate it as network flows? nfstream make this path easier in few lines:

.. code-block:: python

   from nfstream.streamer import Streamer
   my_capture_streamer = Streamer(source="instagram.pcap") # or capture from a network interface
   for flow in my_capture_streamer:  # or for flow in my_live_streamer
       print(flow)  # print, append to pandas Dataframe or whatever you want :)!


.. code-block:: json

    {"ip_src": "192.168.43.18",
     "src_port": 52066,
     "ip_dst": "66.220.156.68",
     "dst_port": 443,
     "ip_protocol": 6,
     "vlan_id": 0,
     "src_to_dst_pkts": 9,
     "dst_to_src_pkts": 10,
     "src_to_dst_bytes": 1345,
     "dst_to_src_bytes": 4400,
     "syn_count": [1, 1],
     "cwr_count": [0, 0],
     "ece_count": [0, 0],
     "urg_count": [0, 0],
     "ack_count": [8, 10],
     "psh_count": [4, 5],
     "rst_count": [0, 0],
     "fin_count": [0, 0],
     "start_time": 1472393122365.661,
     "end_time": 1472393123665.163,
     "export_reason": 2,
     "metrics": {"application_name": "TLS.Facebook",
                 "category_name": "SocialNetwork",
                 "http_dns_server_host_name": "",
                 "tls_client_certificate": "facebook.com",
                 "tls_server_certificate": "*.facebook.com",
                 "tls_version": "TLSv1.2",
                 "tls_not_before": "2014-08-28 00:00:00+00:00",
                 "tls_not_after": "2016-12-30 12:00:00+00:00"
                 }
     }

* Didn't find a specific flow feature? add a plugin to the Streamer in few lines:

.. code-block:: python

   def my_awesome_plugin(packet_information, flow, direction):
    if packet_information.length > 666:
        return flow.metrics['count_pkts_gt_666'] + 1

   streamer_awesome = Streamer(source='devil.pcap', user_metrics={'count_pkts_gt_666': my_awesome_plugin})
   for export in streamer_awesome:
      print(export.metrics['count_pkts_gt_666']) # now you will see your created metric in generated flows


* More example and details are provided on the official Documentation_.

Getting Started
===============

Prerequisites
-------------

.. code-block:: bash

    apt-get install libpcap-dev

Installation
------------

using pip
^^^^^^^^^

Binary installers for the latest released version are available:

.. code-block:: bash

    pip3 install nfstream


from source
^^^^^^^^^^^

If you want to build nfstream on your local machine:

.. code-block:: bash

    apt-get install autogen
    git clone https://github.com/aouinizied/nfstream.git
    # move to nfstream directory and run
    python3 setup.py install


Contributing
============

Please read Contributing_ for details on our code of conduct, and the process for submitting pull
requests to us.


Authors
=======

`Zied Aouini`_  (`aouinizied`_) created nfstream and `these fine people`_
have contributed.


License
=======

This project is licensed under the GPLv3 License - see the License_ file for details

.. |coverage| image:: https://codecov.io/gh/aouinizied/nfstream/branch/master/graph/badge.svg
               :target: https://codecov.io/gh/aouinizied/nfstream/
.. |release| image:: https://img.shields.io/pypi/v/nfstream.svg
              :target: https://pypi.python.org/pypi/nfstream
.. |nfstream_logo| image:: https://github.com/aouinizied/nfstream/blob/master/docs/nfstream_logo.png
.. |build| image:: https://travis-ci.org/aouinizied/nfstream.svg?branch=master
               :target: https://travis-ci.org/aouinizied/nfstream
.. |quality| image:: https://img.shields.io/lgtm/grade/python/github/aouinizied/nfstream.svg?logo=lgtm&logoWidth=18)
               :target: https://lgtm.com/projects/g/aouinizied/nfstream/context:python
.. |python| image:: https://img.shields.io/badge/python-3.6+-blue.svg
               :target: https://travis-ci.org/aouinizied/nfstream
.. |doc| image:: https://readthedocs.org/projects/nfstream/badge/?version=latest
               :target: https://nfstream.readthedocs.io/en/latest/?badge=latest
.. |license| image:: https://img.shields.io/badge/license-LGPLv3-blue.svg
               :target: LICENSE
.. |platform| image:: https://img.shields.io/badge/platform-linux%20%7C%20macos-blue
               :target: https://travis-ci.org/aouinizied/nfstream
.. |download| image:: https://img.shields.io/pypi/dm/nfstream.svg
               :target: https://pypistats.org/packages/nfstream

.. _License: https://github.com/aouinizied/nfstream/blob/master/LICENSE
.. _Contributing: https://github.com/aouinizied/nfstream/blob/master/CONTRIBUTING.rst
.. _these fine people: https://github.com/aouinizied/nfstream/graphs/contributors
.. _Zied Aouini: https://www.linkedin.com/in/dr-zied-aouini
.. _aouinizied: https://github.com/aouinizied
.. _Documentation: https://nfstream.readthedocs.io/en/latest/
.. _nDPI: https://www.ntop.org/products/deep-packet-inspection/ndpi/
.. _NFStreamClassifier: https://nfstream.readthedocs.io/en/latest/tutorials.html#create-your-own-classifier


