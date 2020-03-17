###################
Installing nfstream
###################

************
Installation
************

**using pip**

Binary installers for the latest released version are available:

.. code-block:: bash

    python3 -m pip install nfstream


**from source: linux**

.. code-block:: bash

    sudo apt-get install autoconf automake libtool pkg-config libpcap-dev
    git clone https://github.com/aouinizied/nfstream.git
    cd nfstream
    python3 -m pip install -r requirements.txt
    python3 setup.py bdist_wheel

**from source: macos**

.. code-block:: bash

    brew install autoconf automake libtool pkg-config
    git clone https://github.com/aouinizied/nfstream.git
    cd nfstream
    python3 -m pip install -r requirements.txt
    python3 setup.py bdist_wheel
