Installing nfstream
===================

Prerequisites
-------------

.. code-block:: bash

    apt-get install python-dev pypy3-dev libpcap-dev

Installation
------------

**using pip**

Binary installers for the latest released version are available:

.. code-block:: bash

    pip3 install nfstream


**from source**

If you want to build nfstream on your local machine:

.. code-block:: bash

    apt-get install autogen
    git clone https://github.com/aouinizied/nfstream.git
    # move to nfstream directory and run
    python3 setup.py install
