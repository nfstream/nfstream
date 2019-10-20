========================
|nfstream_logo| nfstream
========================

|release| |build| |coverage| |quality| |doc| |python| |license|

nfstream is a flexible and lightweight network data analysis library.

**nfstream main features**

* **Performance:** nfstream was designed to be fast, CPU savvy and small memory fingerprint.
* **Layer-7 visibility:** (250+ applications including Tor, Messenger, WhatsApp, etc.).
* **Flexibility:** Missing metric? You can add a metric in 2 lines of code using nfstream User Defined Metrics.

**examples of use**

Dealing with a big pcap file and just want to see flow informations stored in as a csv file or
pandas Dataframe? nfstream make this path easier in few lines:

.. image:: https://github.com/aouinizied/nfstream/blob/master/docs/streamer_example.png
  :align: center


.. code-block:: json

    {"ip_src": "192.168.43.18", "src_port": 52066, "ip_dst": "66.220.156.68", "dst_port": 443, "ip_protocol": 6, "src_to_dst_pkts": 9, "dst_to_src_pkts": 10, "src_to_dst_bytes": 1345, "dst_to_src_bytes": 4400, "application_name": "TLS.Facebook", "start_time": 1472393122365, "end_time": 1472393123665, "export_reason": 2}


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



