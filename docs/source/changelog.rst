#########
Changelog
#########

**3.1.0 (2019-12-29)**

* Initial support for nDPI3.1 (commit: 73c7ccdb65a1e13e3fb1726af7882dd34534906f).
* Add wrapping for pandas.
* pypy7.2 support.
* Add py36, py38 for macOS wheels.
* Move continous integration to GitHub Actions.

**3.0.4 (2019-12-18)**

* Fix pypi description rendering.

**3.0.3 (2019-12-18)**

* MacOS Catalina support.
* Implement random port selection for zmq.

**3.0.2 (2019-12-06)**

* ether type double stacking implementation.
* Minor fixes.

**3.0.1 (2019-12-04)**

* Fix macOS wheels 10.14

**3.0.0 (2019-12-04)**

* Sync with nDPI major.minor versions.
* New NFPlugin API definition.
* Fix macOS wheels for 10.13 and 10.14

**2.0.1 (2019-11-29)**

* Fix pypy3 wheel.

**2.0.0 (2019-11-28)**

* Pypy support.
* Major performances improvements.
* NFPlugin as main extension API.
* nDPI memory usage improved.
* nDPI implemented using cffi.
* tcp_max_dissections, udp_max_dissections options.
* NFFlow dynamic attributes creation.
* HTTP, SSH, DNS client and server informations extraction.
* FlowCache management implemented in pure Python.

**1.2.1 (2019-11-15)**

* Fix ndpi padding and alignement issues.
* nDPI3.1 compatibility.

**1.2.0 (2019-11-14)**

* Fix ndpi bindings.
* Add TLS dissection features (server sni, client sni, version, organization, expiration dates)
* Improve documentation.

**1.1.8 (2019-11-07)**

* Fix ndpi wrap missing fields.
* Add host_server_name metric.
* Update doc.

**1.1.7 (2019-11-07)**

* Fix minor bugs.

**1.1.6 (2019-11-03)**

* TCP flags extraction.
* Minor bug fixes.

**1.1.5 (2019-11-02)**

* Add BPF filtering feature.
* Fix radiotap parsing.

**1.1.2-3-4 (2019-11-01)**

* Fix broken macos wheels on pypi.

**1.1.1 (2019-11-01)**

* Fix broken linux wheels on pypi.
* Py38 compatibility.

**1.1.0 (2019-11-01)**

* Add OSX support.

**1.0.1-2-3 (2019-10-31)**

* Fix deployment CI


**1.0.0 (2019-10-30)**

* cffi based packet capture.
* fast parsing mechanism.
* Minor bug fixes.
* auto-generate binaries.

**0.5.0 (2019-10-21)**

* Classifier mechanism introduced.
* Custom export_reason.
* Fix minor bugs.
* Improve documentation.

**0.4.0 (2019-10-20)**

* Pypi package description readable.

**0.3.1 (2019-10-20)**

* Add category_name as flow feature.

**0.3.0 (2019-10-20)**

* Add user defined callbacks feature.
* Fix live capture handling.
* Fix library loading path.
* Json support for flow printing.
* Add examples.

**0.2.0 (2019-10-19)**

* Add nDPI bindings as part of the released package
* Documentation improvement

**0.1.0 (2019-10-19)**

* First release on PyPI.
