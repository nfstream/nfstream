# nfstream: a flexible network data analysis framework
<img align="right" src="https://raw.githubusercontent.com/aouinizied/nfstream/master/docs/source/asset/logo_main.png" width="140" height="122"> 

**nfstream** is a Python package providing fast, flexible, and expressive data structures designed to make working with **online** or **offline** network data both easy and intuitive. It aims to be the fundamental high-level building block for
doing practical, **real world** network data analysis in Python. Additionally, it has
the broader goal of becoming **a common network data processing framework for researchers** providing data reproducibility across experiments.

<table>
<tr>
  <td>Latest Release</td>
  <td>
    <a href="https://pypi.python.org/pypi/nfstream">
    <img src="https://img.shields.io/pypi/v/nfstream.svg" alt="latest release" />
    </a>
  </td>
</tr>
<tr>
  <td>Supported Platforms</td>
  <td>
    <a href="https://github.com/aouinizied/nfstream/actions?query=workflow%3Abuild">
    <img src="https://raw.githubusercontent.com/wiki/ryanoasis/nerd-fonts/screenshots/v1.0.x/linux-pass-sm.png" alt="Linux" />
    </a>
    <a href="https://github.com/aouinizied/nfstream/actions?query=workflow%3Abuild">
    <img src="https://raw.githubusercontent.com/wiki/ryanoasis/nerd-fonts/screenshots/v1.0.x/mac-pass-sm.png" alt="MacOS" />
  </td>
</tr>
<tr>
  <td>Supported Versions</td>
  <td>
    <a href="https://github.com/aouinizied/nfstream/actions?query=workflow%3Abuild">
    <img src="https://img.shields.io/badge/python3-%3E%3D3.6-blue" alt="python3" />
    </a>
    <a href="https://github.com/aouinizied/nfstream/actions?query=workflow%3Abuild">
    <img src="https://img.shields.io/badge/pypy3-%3E%3D7.1-blue" alt="pypy3" />
    </a>
  </td>
</tr>
<tr>
  <td>Build Status</td>
  <td>
    <a href="https://github.com/aouinizied/nfstream/actions?query=workflow%3Abuild">
    <img src="https://github.com/aouinizied/nfstream/workflows/build/badge.svg" alt="Github WorkFlows" />
    </a>
  </td>
</tr>
<tr>
  <td>Documentation Status</td>
  <td>
    <a href="https://nfstream.readthedocs.io/en/latest/?badge=latest">
    <img src="https://readthedocs.org/projects/nfstream/badge/?version=latest" alt="ReadTheDocs" />
    </a>
  </td>
</tr>
<tr>
  <td>Code Quality</td>
  <td>
    <a href="https://lgtm.com/projects/g/aouinizied/nfstream/context:python">
    <img src="https://img.shields.io/lgtm/grade/python/github/aouinizied/nfstream.svg?logo=lgtm&logoWidth=18)" alt="Quality" />
    </a>
  </td>
</tr>
<tr>
  <td>Code Coverage</td>
  <td>
    <a href="https://codecov.io/gh/aouinizied/nfstream/">
    <img src="https://codecov.io/gh/aouinizied/nfstream/branch/master/graph/badge.svg" alt="Coverage" />
    </a>
  </td>
</tr>
<tr>
  <td>Discussion Channel</td>
  <td>
    <a href="https://gitter.im/nfstream/community">
    <img src="https://badges.gitter.im/gitterHQ/gitter.png" alt="Gitter" />
    </a>
  </td>
</tr>	
</table>

## Main Features

* **Performance:** **nfstream** is designed to be fast (x10 faster with pypy3 support) with a small CPU and memory footprint.
* **Layer-7 visibility:** **nfstream** deep packet inspection engine is based on [**nDPI**][ndpi]. It allows nfstream to perform [**reliable**][reliable] encrypted applications identification and metadata extraction (e.g. TLS, QUIC, TOR, HTTP, SSH, DNS).
* **Flexibility:** add a flow feature in 2 lines as an [**NFPlugin**][nfplugin].
* **Machine Learning oriented:** add your trained model as an [**NFPlugin**][nfplugin]. 

## How to use it?

* Dealing with a big pcap file and just want to aggregate it as network flows? **nfstream** make this path easier in few lines:

```python
   from nfstream import NFStreamer
   my_awesome_streamer = NFStreamer(source="facebook.pcap") # or network interface (source="eth0")
   for flow in my_awesome_streamer:
       print(flow)  # print it, append to pandas Dataframe or whatever you want :)!
```

```python
    NFEntry(
        flow_id=0,
        first_seen=1472393122365,
        last_seen=1472393123665,
        version=4,
        src_port=52066,
        dst_port=443,
        protocol=6,
        vlan_id=0,
        src_ip='192.168.43.18',
        dst_ip='66.220.156.68',
        total_packets=19,
        total_bytes=5745,
        duration=1300,
        src2dst_packets=9,
        src2dst_bytes=1345,
        dst2src_packets=10,
        dst2src_bytes=4400,
        expiration_id=0,
        master_protocol=91,
        app_protocol=119,
        application_name='TLS.Facebook',
        category_name='SocialNetwork',
        client_info='facebook.com',
        server_info='*.facebook.com',
        j3a_client='bfcc1a3891601edb4f137ab7ab25b840',
        j3a_server='2d1eb5817ece335c24904f516ad5da12'
    )
 ```
* From pcap to Pandas DataFrame?

```python
    import pandas as pd	
    streamer_awesome = NFStreamer(source='devil.pcap')
    data = []
    for flow in streamer_awesome:
       data.append(flow.to_namedtuple())
    my_df = pd.DataFrame(data=data)
    my_df.head(5) # Enjoy!
```
* Didn't find a specific flow feature? add a plugin to **nfstream** in few lines:

```python
    from nfstream import NFPlugin

    class my_awesome_plugin(NFPlugin):
        def on_update(self, obs, entry):
            if obs.length >= 666:
                entry.my_awesome_plugin += 1
		
   streamer_awesome = NFStreamer(source='devil.pcap', plugins=[my_awesome_plugin()])
   for flow in streamer_awesome:
      print(flow.my_awesome_plugin) # see your dynamically created metric in generated flows
```

* More example and details are provided on the official [**documentation**][documentation].

## Prerequisites
```bash
    apt-get install libpcap-dev
```
## Installation

### Using pip

Binary installers for the latest released version are available:
```bash
    pip3 install nfstream
```

### Build from source

If you want to build **nfstream** on your local machine:

```bash
    git clone https://github.com/aouinizied/nfstream.git
    cd nfstream
    python3 setup.py install
```

## Contributing

Please read [**Contributing**][contribute] for details on our code of conduct, and the process for submitting pull
requests to us.


## Authors

[**Zied Aouini**][linkedin] created **nfstream** and [**these fine people**][contributors] have contributed.

## Ethics

**nfstream** is intended for network data research and forensics.
Researchers and network data scientists can use these framework to build reliable datasets, train and evaluate
network applied machine learning models.
As with any packet monitoring tool, **nfstream** could potentially be misused.
**Do not run it on any network of which you are not the owner or the administrator**.

## License

This project is licensed under the GPLv3 License - see the [**License**][license] file for details

[license]: https://github.com/aouinizied/nfstream/blob/master/LICENSE
[contribute]: https://nfstream.readthedocs.io/en/latest/contributing.html
[contributors]: https://github.com/aouinizied/nfstream/graphs/contributors
[linkedin]: https://www.linkedin.com/in/dr-zied-aouini
[github]: https://github.com/aouinizied
[documentation]: https://readthedocs.org/projects/nfstream/downloads/pdf/latest/
[ndpi]: https://github.com/ntop/nDPI
[nfplugin]: https://nfstream.readthedocs.io/en/latest/plugins.html
[reliable]: http://people.ac.upc.edu/pbarlet/papers/ground-truth.pam2014.pdf
