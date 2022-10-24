# NFStream browser extensions (experimental feature)

This repository contains nfstream browser extensions prototypes (Chrome and Firefox).
Each extension can be loaded as part of the browser. 
It will mainly extract per request attributes (tab url for instance) and export it as a JSON POST.
NFStream (set with system visibility mode == 2) is able to start a HTTP server that will listen to
these exports on a specific port ans try to enrich flow entries with such an information 
based on naive remote IP matching heuristic.

This feature is an exploratory work and thus, not part of the official documentation.


