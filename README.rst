========================
|nfstream_logo| nfstream
========================

|release| |build| |coverage| |quality| |doc| |python| |license|

nfstream is a flexible and lightweight network data analysis library.

**nfstream main features**

* **Performance:** nfstream was designed to be fast, CPU savvy and small memory fingerprint.
* **Layer-7 visibility:** nfstream dissection is based on nDPI_ (~300 applications including Tor, Messenger, WhatsApp, etc.).
* **Flexibility:** add a flow metric in 2 lines of code using nfstream plugins method.
* **Machine Learning oriented:** add your trained model as an NFStreamClassifier_.

**examples of use**

* Dealing with a big pcap file and just want to see flow informations stored in as a csv file or pandas Dataframe? nfstream make this path easier in few lines:

.. code-block:: python

   from nfstream.streamer import Streamer
   my_capture_streamer = Streamer(source="instagram.pcap",
                                  capacity=128000,
                                  active_timeout=120,
                                  inactive_timeout=60,
                                  user_metrics=None,
                                  user_classifiers=None,
                                  enable_ndpi=True)

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
    old_value = flow.metrics['count_pkts_gt_666']
    if packet_information.size > 999:
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

* More example and details are provided on the official Documentation_.

Getting Started
===============

Prerequisites
-------------

.. code-block:: bash

    apt-get install python-dev libpcap-dev autogen

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

    apt-get autogen
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
.. |doc| image:: https://readthedocs.org/projects/nfstream/badge/?version=latest
               :target: https://nfstream.readthedocs.io/en/latest/?badge=latest
.. |license| image:: https://img.shields.io/badge/license-LGPLv3-blue.svg
               :target: LICENSE

.. _License: https://github.com/aouinizied/nfstream/blob/master/LICENSE
.. _Contributing: https://github.com/aouinizied/nfstream/blob/master/CONTRIBUTING.rst
.. _these fine people: https://github.com/aouinizied/nfstream/graphs/contributors
.. _Zied Aouini: https://www.linkedin.com/in/dr-zied-aouini
.. _aouinizied: https://github.com/aouinizied
.. _Documentation: https://nfstream.readthedocs.io/en/latest/
.. _nDPI: https://www.ntop.org/products/deep-packet-inspection/ndpi/
.. _NFStreamClassifier: https://nfstream.readthedocs.io/en/latest/tutorials.html#create-your-own-classifier


