.. nfstream documentation master file, created by
   sphinx-quickstart on Sat Oct 19 16:26:59 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

######################
nfstream Documentation
######################
.. image:: asset/nfstream_logo.png
  :scale: 100%
  :align: left

**nfstream**

|release| |python| |pypy| |platform| |license|

nfstream is a flexible and lightweight network data analysis framework.

**nfstream main features**

* **Performance:** nfstream was designed to be fast with a small CPU and memory footprint.
* **Layer-7 visibility:** nfstream dissection is based on nDPI_ (~300 applications including Tor, Messenger, WhatsApp, etc.).
* **Flexibility:** add a flow feature in 2 lines as an NFPlugin_.
* **Machine Learning oriented:** add your trained model as an NFPlugin_.


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   installation
   architecture
   nfstream
   plugins
   contributing
   changelog


.. |release| image:: https://img.shields.io/pypi/v/nfstream.svg
              :target: https://pypi.python.org/pypi/nfstream
.. |python| image:: https://img.shields.io/badge/python-3.6+-blue.svg
               :target: https://travis-ci.org/aouinizied/nfstream
.. |pypy| image:: https://img.shields.io/badge/pypy-7.1+-blue.svg
            :target: https://travis-ci.org/aouinizied/nfstream
.. |license| image:: https://img.shields.io/badge/license-LGPLv3-blue.svg
               :target: LICENSE
.. |platform| image:: https://img.shields.io/badge/platform-linux%20%7C%20macos-blue
               :target: https://travis-ci.org/aouinizied/nfstream

.. _nDPI: https://www.ntop.org/products/deep-packet-inspection/ndpi/
.. _NFPlugin: https://nfstream.readthedocs.io/en/latest/plugins.html

