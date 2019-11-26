========================
|nfstream_logo| nfstream
========================

|build| |doc| |download| |release| |python| |pypy| |platform| |license|

nfstream is a flexible and lightweight network data analysis framework.

**nfstream main features**

* **Performance:** nfstream was designed to be fast with a small CPU and memory footprint.
* **Layer-7 visibility:** nfstream dissection is based on nDPI_ (~300 applications including Tor, Messenger, WhatsApp, etc.).
* **Flexibility:** add a flow feature in 2 lines as an NFPlugin_.
* **Machine Learning oriented:** add your trained model as an NFPlugin_.

**Use**

* Dealing with a big pcap file and just want to aggregate it as network flows? nfstream make this path easier in few lines:

.. code-block:: python

   from nfstream import NFStreamer
   my_awesome_streamer = Streamer(source="instagram.pcap") # or capture from a network interface (source="eth0")
   for flow in my_awesome_streamer:
       print(flow)  # print, append to pandas Dataframe or whatever you want :)!


.. code-block:: python

    NFFlow(
        flow_id=0,
        first_seen=1472393122365,
        last_seen=1472393123665,
        nfhash=1456034341,
        version=4,
        src_port=52066,
        dst_port=443,
        protocol=6,
        vlan_id=0,
        src_ip='192.168.43.18',
        dst_ip='66.220.156.68',
        total_packets=19,
        total_bytes=5745,
        duration=1300,
        src2dst_packets=9,
        src2dst_bytes=1345,
        dst2src_packets=10,
        dst2src_bytes=4400,
        expiration_id=0,
        master_protocol=91,
        app_protocol=119,
        application_name='TLS.Facebook',
        category_name='SocialNetwork',
        client_info='facebook.com',
        server_info='*.facebook.com',
        j3a_client='bfcc1a3891601edb4f137ab7ab25b840',
        j3a_server='2d1eb5817ece335c24904f516ad5da12'
    )

* Didn't find a specific flow feature? add a plugin to NFStreamer in few lines:

.. code-block:: python

    from nfstream import NFPlugin

    class my_awesome_plugin(NFPlugin):
        def process(self, pkt, flow):
            if pkt.length >= 666:
                flow.my_awesome_plugin += 1

   streamer_awesome = NFStreamer(source='devil.pcap', plugins=[my_awesome_plugin()])
   for flow in streamer_awesome:
      print(flow.my_awesome_plugin) # now you will see your dynamically created metric in generated flows


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

Ethics
=======

nfstream is intended for network data research and forensics.
Researchers and network data scientists can use these framework to build reliable datasets, train and evaluate
network applied machine learning models.
As with any packet monitoring tool, nfstream could potentially be misused.
**Do not run it on any network of which you are not the owner or the administrator**.

License
=======

This project is licensed under the GPLv3 License - see the License_ file for details


.. |release| image:: https://img.shields.io/pypi/v/nfstream.svg
              :target: https://pypi.python.org/pypi/nfstream
.. |nfstream_logo| image:: https://github.com/aouinizied/nfstream/blob/master/docs/nfstream_logo.png
.. |build| image:: https://travis-ci.org/aouinizied/nfstream.svg?branch=master
               :target: https://travis-ci.org/aouinizied/nfstream
.. |python| image:: https://img.shields.io/badge/python-3.6+-blue.svg
               :target: https://travis-ci.org/aouinizied/nfstream
.. |pypy| image:: https://img.shields.io/badge/pypy-7.1+-blue.svg
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
.. _NFPlugin: https://nfstream.readthedocs.io/en/latest/plugins.html


