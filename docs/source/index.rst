.. nfstream documentation master file, created by
   sphinx-quickstart on Sat Oct 19 16:26:59 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

####################################################
nfstream: a flexible network data analysis framework
####################################################

.. image:: asset/logo_main.png
  :width: 140
  :height: 140
  :align: right

**nfstream** is a Python package providing fast, flexible, and expressive data structures designed to make working with **online** or **offline** network data both easy and intuitive. It aims to be the fundamental high-level building block for
doing practical, **real world** network data analysis in Python. Additionally, it has
the broader goal of becoming **a common network data processing framework for researchers** providing data reproducibility across experiments.

**Main Features**

* **Performance:** **nfstream** is designed to be fast (x10 faster with pypy3 support) with a small CPU and memory footprint.
* **Layer-7 visibility:** **nfstream** deep packet inspection engine is based on nDPI_ library. It allows nfstream to perform reliable_ encrypted applications identification and metadata extraction (e.g. TLS, SSH, DNS, HTTP).
* **Flexibility:** add a flow feature in 2 lines as an NFPlugin_.
* **Machine Learning oriented:** add your trained model as an NFPlugin_.



.. toctree::
   :maxdepth: 2
   :caption: Table of Contents:

   installation
   architecture
   get_started
   plugins
   contributing
   changelog


.. _nDPI: https://www.ntop.org/products/deep-packet-inspection/ndpi/
.. _NFPlugin: https://nfstream.readthedocs.io/en/latest/plugins.html
.. _reliable: http://people.ac.upc.edu/pbarlet/papers/ground-truth.pam2014.pdf
