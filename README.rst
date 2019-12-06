.. image:: https://github.com/aouinizied/nfstream/blob/master/docs/source/asset/nfstream_logo.png
     :scale: 100%
     :align: left

=================================================================
nfstream: a flexible and powerful network data analysis framework
=================================================================

.. list-table::
   :widths: 25 25
   :header-rows: 0

   * - Latest Release
     - |release|
   * - Supported Versions
     - |python|
   * -
     - |pypy|
   * - Supported Platforms
     - |linux|
   * -
     - |macos|
   * - Build Status
     - |build|
   * - Documentation Status
     - |doc|
   * - Code Coverage
     - |coverage|
   * - Code Quality
     - |quality|
   * - Discussions Channel
     - |gitter|

Main Features
=============

* **Performance:** **nfstream** is designed to be fast (pypy3 support) with a small CPU and memory footprint.
* **Layer-7 visibility:** **nfstream** deep packet inspection engine is based on nDPI_ library. It allows nfstream to perform reliable_ encrypted applications identification and metadata extraction (e.g. TLS, SSH, DNS, HTTP).
* **Flexibility:** add a flow feature in 2 lines as an NFPlugin_.
* **Machine Learning oriented:** add your trained model as an NFPlugin_.

How to use it?
==============

* Dealing with a big pcap file and just want to aggregate it as network flows? **nfstream** make this path easier in few lines:

.. code-block:: python

   from nfstream import NFStreamer
   my_awesome_streamer = NFStreamer(source="facebook.pcap") # or capture from a network interface (source="eth0")
   for flow in my_awesome_streamer:
       print(flow)  # print, append to pandas Dataframe or whatever you want :)!


.. code-block:: python

    NFEntry(
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

* Didn't find a specific flow feature? add a plugin to **nfstream** in few lines:

.. code-block:: python

    from nfstream import NFPlugin

    class my_awesome_plugin(NFPlugin):
        def on_update(self, obs, entry):
            if obs.length >= 666:
                entry.my_awesome_plugin += 1

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

If you want to build **nfstream** on your local machine:

.. code-block:: bash

    apt-get install autogen
    git clone https://github.com/aouinizied/nfstream.git
    cd nfstream
    python3 setup.py install


Contributing
============

Please read Contributing_ for details on our code of conduct, and the process for submitting pull
requests to us.


Authors
=======

`Zied Aouini`_  (`aouinizied`_) created **nfstream** and `these fine people`_
have contributed.

Ethics
=======

**nfstream** is intended for network data research and forensics.
Researchers and network data scientists can use these framework to build reliable datasets, train and evaluate
network applied machine learning models.
As with any packet monitoring tool, **nfstream** could potentially be misused.
**Do not run it on any network of which you are not the owner or the administrator**.

License
=======

This project is licensed under the GPLv3 License - see the License_ file for details


.. |release| image:: https://img.shields.io/pypi/v/nfstream.svg
              :target: https://pypi.python.org/pypi/nfstream
.. |gitter| image:: https://badges.gitter.im/gitterHQ/gitter.png
              :target: https://gitter.im/nfstream/community
.. |build| image:: https://travis-ci.org/aouinizied/nfstream.svg?branch=master
               :target: https://travis-ci.org/aouinizied/nfstream
.. |python| image:: https://img.shields.io/badge/python-%3E%3D3.6-blue
               :target: https://travis-ci.org/aouinizied/nfstream
.. |pypy| image:: https://img.shields.io/badge/pypy-3-blue
            :target: https://travis-ci.org/aouinizied/nfstream
.. |doc| image:: https://readthedocs.org/projects/nfstream/badge/?version=latest
               :target: https://nfstream.readthedocs.io/en/latest/?badge=latest
.. |linux| image:: https://img.shields.io/badge/linux-x86__64-blue
            :target: https://travis-ci.org/aouinizied/nfstream
.. |macos| image:: https://img.shields.io/badge/%09macOS-%3E%3D10.13-blue
            :target: https://travis-ci.org/aouinizied/nfstream
.. |coverage| image:: https://codecov.io/gh/aouinizied/nfstream/branch/master/graph/badge.svg
               :target: https://codecov.io/gh/aouinizied/nfstream/
.. |quality| image:: https://img.shields.io/lgtm/grade/python/github/aouinizied/nfstream.svg?logo=lgtm&logoWidth=18)
               :target: https://lgtm.com/projects/g/aouinizied/nfstream/context:python

.. _License: https://github.com/aouinizied/nfstream/blob/master/LICENSE
.. _Contributing: https://nfstream.readthedocs.io/en/latest/contributing.html
.. _these fine people: https://github.com/aouinizied/nfstream/graphs/contributors
.. _Zied Aouini: https://www.linkedin.com/in/dr-zied-aouini
.. _aouinizied: https://github.com/aouinizied
.. _Documentation: https://nfstream.readthedocs.io/en/latest/
.. _nDPI: https://www.ntop.org/products/deep-packet-inspection/ndpi/
.. _NFPlugin: https://nfstream.readthedocs.io/en/latest/plugins.html
.. _reliable: http://people.ac.upc.edu/pbarlet/papers/ground-truth.pam2014.pdf


