.. nfstream documentation master file, created by
   sphinx-quickstart on Sat Oct 19 16:26:59 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

======================
nfstream documentation
======================

|build| |quality| |release| |python| |license|

**nfstream** is a flexible and lightweight network data analysis library.

**nfstream main features**

* **Performance:** nfstream was designed to be fast with a small CPU and memory footprint.
* **Layer-7 visibility:** nfstream dissection is based on nDPI_ (~300 applications including Tor, Messenger, WhatsApp, etc.).
* **Flexibility:** add a flow metric in 2 lines of code using nfstream plugins method.
* **Machine Learning oriented:** add your trained model as an NFStreamClassifier.


.. toctree::
   :maxdepth: 3
   :caption: Contents:

   installation
   tutorials
   contributing
   changelog


.. |release| image:: https://img.shields.io/pypi/v/nfstream.svg
              :target: https://pypi.python.org/pypi/nfstream
.. |build| image:: https://travis-ci.org/aouinizied/nfstream.svg?branch=master
               :target: https://travis-ci.org/aouinizied/nfstream
.. |quality| image:: https://img.shields.io/lgtm/grade/python/github/aouinizied/nfstream.svg?logo=lgtm&logoWidth=18)
               :target: https://lgtm.com/projects/g/aouinizied/nfstream/context:python
.. |python| image:: https://img.shields.io/badge/python-3.x-blue.svg
               :target: https://travis-ci.org/aouinizied/nfstream
.. |license| image:: https://img.shields.io/badge/license-LGPLv3-blue.svg
               :target: LICENSE

.. _nDPI: https://www.ntop.org/products/deep-packet-inspection/ndpi/
