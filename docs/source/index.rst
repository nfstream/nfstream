.. nfstream documentation master file, created by
   sphinx-quickstart on Sat Oct 19 16:26:59 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.


.. image:: asset/nfstream_logo.png
  :scale: 100%
  :align: left

########
nfstream
########
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
   usage
   plugins
   contributing
   changelog


.. _nDPI: https://www.ntop.org/products/deep-packet-inspection/ndpi/
.. _NFPlugin: https://nfstream.readthedocs.io/en/latest/plugins.html

