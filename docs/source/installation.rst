###################
Installing NFStream
###################

*************
Prerequisites
*************

.. code-block:: bash

    apt-get install libpcap-dev

************
Installation
************

**using pip**

Binary installers for the latest released version are available:

.. code-block:: bash

    pip3 install nfstream


**from source**

If you want to build NFStream on your local machine:

.. code-block:: bash

    apt-get install autogen
    git clone https://github.com/aouinizied/nfstream.git
    cd nfstream
    python3 setup.py install
