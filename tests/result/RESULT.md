Result repository
-----------------

This repository contains results files generated after nDPI build step.
We run ndpiReader example and compare its generated classification results to nfstream ones.
This steps include flows/bytes and packets comparison per classification result and ensure 
a correct nDPI integration.
See ``nfstream/tests/build_results.sh`` and ``setup.py``
 for more informations about how we perform this step.