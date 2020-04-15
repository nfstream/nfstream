<p align="center"><a href="https://nfstream.github.io/"><img width=35% alt="" src="https://raw.githubusercontent.com/aouinizied/nfstream/master/logo_main.png?raw=true"></a></p>
<h1 align="center">nfstream: a flexible network data analysis framework</h1>

[**nfstream**][repo] is a Python package providing fast, flexible, and expressive data structures designed to make working with **online** or **offline** network data both easy and intuitive. It aims to be the fundamental high-level building block for
doing practical, **real world** network data analysis in Python. Additionally, it has
the broader goal of becoming **a common network data processing framework for researchers** providing data reproducibility across experiments.

<table>
<tr>
  <td><b>Live Demo Notebook</b></td>
  <td>
    <a href="https://mybinder.org/v2/gh/aouinizied/nfstream-tutorials/master?filepath=demo_notebook.ipynb">
    <img src="https://mybinder.org/badge_logo.svg" alt="live notebook" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Project Website</b></td>
  <td>
    <a href="https://nfstream.github.io">
    <img src="https://img.shields.io/badge/website-nfstream.github.io-blue" alt="website" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Latest Release</b></td>
  <td>
    <a href="https://pypi.python.org/pypi/nfstream">
    <img src="https://img.shields.io/pypi/v/nfstream.svg" alt="latest release" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Citation</b></td>
  <td>
    <a href="https://zenodo.org/badge/latestdoi/216051909">
    <img src="https://zenodo.org/badge/216051909.svg" alt="DOI" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Downloads</b></td>
  <td>
    <a href="https://pepy.tech/project/nfstream">
    <img src="https://pepy.tech/badge/nfstream" alt="downloads" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Supported Platforms</b></td>
  <td>
    <a href="https://github.com/aouinizied/nfstream/actions?query=workflow%3Abuild">
    <img src="https://raw.githubusercontent.com/wiki/ryanoasis/nerd-fonts/screenshots/v1.0.x/linux-pass-sm.png" alt="Linux" />
    </a>
    <a href="https://github.com/aouinizied/nfstream/actions?query=workflow%3Abuild">
    <img src="https://raw.githubusercontent.com/wiki/ryanoasis/nerd-fonts/screenshots/v1.0.x/mac-pass-sm.png" alt="MacOS" />
  </td>
</tr>
<tr>
  <td><b>Supported Versions</b></td>
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
  <td><b>Build Status</b></td>
  <td>
    <a href="https://github.com/aouinizied/nfstream/actions?query=workflow%3Abuild">
    <img src="https://github.com/aouinizied/nfstream/workflows/build/badge.svg" alt="Github WorkFlows" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Code Quality</b></td>
  <td>
    <a href="https://lgtm.com/projects/g/aouinizied/nfstream/context:python">
    <img src="https://img.shields.io/lgtm/grade/python/github/aouinizied/nfstream.svg?logo=lgtm&logoWidth=18)" alt="Quality" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Code Coverage</b></td>
  <td>
    <a href="https://codecov.io/gh/aouinizied/nfstream/">
    <img src="https://codecov.io/gh/aouinizied/nfstream/branch/master/graph/badge.svg" alt="Coverage" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Discussion Channel</b></td>
  <td>
    <a href="https://gitter.im/nfstream/community">
    <img src="https://badges.gitter.im/gitterHQ/gitter.png" alt="Gitter" />
    </a>
  </td>
</tr>	
</table>

## Main Features

* **Performance:** **nfstream** is designed to be fast (x10 faster with pypy3 support) with a small CPU and memory footprint.
* **Layer-7 visibility:** **nfstream** deep packet inspection engine is based on [**nDPI**][ndpi]. It allows nfstream to perform [**reliable**][reliable] encrypted applications identification and metadata extraction (e.g. TLS, QUIC, TOR, HTTP, SSH, DNS, etc.).
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
    id=0,
    bidirectional_first_seen_ms=1472393122365.661,
    bidirectional_last_seen_ms=1472393123665.163,
    src2dst_first_seen_ms=1472393122365.661,
    src2dst_last_seen_ms=1472393123408.152,
    dst2src_first_seen_ms=1472393122668.038,
    dst2src_last_seen_ms=1472393123665.163,
    version=4,
    src_port=52066,
    dst_port=443,
    protocol=6,
    vlan_id=4,
    src_ip='192.168.43.18',
    dst_ip='66.220.156.68',
    bidirectional_packets=19,
    bidirectional_raw_bytes=5745,
    bidirectional_ip_bytes=5479,
    bidirectional_duration_ms=1299.502197265625,
    src2dst_packets=9, src2dst_raw_bytes=1345,
    src2dst_ip_bytes=1219,
    src2dst_duration_ms=1299.502197265625,
    dst2src_packets=10,
    dst2src_raw_bytes=4400,
    dst2src_ip_bytes=4260,
    dst2src_duration_ms=997.125,
    expiration_id=0,
    master_protocol=91,
    app_protocol=119,
    application_name='TLS.Facebook',
    category_name='SocialNetwork',
    client_info='facebook.com',
    server_info='*.facebook.com,*.facebook.net,*.fb.com,*.fbcdn.net,\
                *.fbsbx.com,*.m.facebook.com,*.messenger.com,*.xx.fbcdn.net,\
                *.xy.fbcdn.net,*.xz.fbcdn.net,facebook.com,fb.com,messenger.com',
    j3a_client='bfcc1a3891601edb4f137ab7ab25b840',
    j3a_server='2d1eb5817ece335c24904f516ad5da12'
)

 ```
* nfstream also extracts [**60+ flow statistical features**][stat_feat]

```python
from nfstream import NFStreamer
my_awesome_streamer = NFStreamer(source="facebook.pcap", statistics=True)
for flow in my_awesome_streamer:
    print(flow)
```

```python
NFEntry(
    id=0,
    bidirectional_first_seen_ms=1472393122365.661,
    bidirectional_last_seen_ms=1472393123665.163,
    src2dst_first_seen_ms=1472393122365.661,
    src2dst_last_seen_ms=1472393123408.152,
    dst2src_first_seen_ms=1472393122668.038,
    dst2src_last_seen_ms=1472393123665.163,
    version=4,
    src_port=52066,
    dst_port=443,
    protocol=6,
    vlan_id=4,
    src_ip='192.168.43.18',
    dst_ip='66.220.156.68',
    bidirectional_packets=19,
    bidirectional_raw_bytes=5745,
    bidirectional_ip_bytes=5479,
    bidirectional_duration_ms=1299.502197265625,
    src2dst_packets=9,
    src2dst_raw_bytes=1345,
    src2dst_ip_bytes=1219,
    src2dst_duration_ms=1299.502197265625,
    dst2src_packets=10,
    dst2src_raw_bytes=4400,
    dst2src_ip_bytes=4260,
    dst2src_duration_ms=997.125,
    expiration_id=0,
    bidirectional_min_raw_ps=66,
    bidirectional_mean_raw_ps=302.36842105263156,
    bidirectional_stdev_raw_ps=425.53315715259754,
    bidirectional_max_raw_ps=1454,
    src2dst_min_raw_ps=66,
    src2dst_mean_raw_ps=149.44444444444446,
    src2dst_stdev_raw_ps=132.20354676701294,
    src2dst_max_raw_ps=449,
    dst2src_min_raw_ps=66,
    dst2src_mean_raw_ps=440.0,
    dst2src_stdev_raw_ps=549.7164925870628,
    dst2src_max_raw_ps=1454,
    bidirectional_min_ip_ps=52,
    bidirectional_mean_ip_ps=288.36842105263156,
    bidirectional_stdev_ip_ps=425.53315715259754,
    bidirectional_max_ip_ps=1440,
    src2dst_min_ip_ps=52,
    src2dst_mean_ip_ps=135.44444444444446,
    src2dst_stdev_ip_ps=132.20354676701294,
    src2dst_max_ip_ps=435,
    dst2src_min_ip_ps=52,
    dst2src_mean_ip_ps=426.0,
    dst2src_stdev_ip_ps=549.7164925870628,
    dst2src_max_ip_ps=1440,
    bidirectional_min_piat_ms=0.0029296875,
    bidirectional_mean_piat_ms=72.19456651475694,
    bidirectional_stdev_piat_ms=137.32250609970072,
    bidirectional_max_piat_ms=397.63720703125,
    src2dst_min_piat_ms=0.008056640625,
    src2dst_mean_piat_ms=130.3114013671875,
    src2dst_stdev_piat_ms=179.64644832489174,
    src2dst_max_piat_ms=414.4921875,
    dst2src_min_piat_ms=0.006103515625,
    dst2src_mean_piat_ms=110.79166666666669,
    dst2src_stdev_piat_ms=169.61844149451002,
    dst2src_max_piat_ms=0.531005859375,
    bidirectional_syn_packets=2,
    bidirectional_cwr_packets=0,
    bidirectional_ece_packets=0,
    bidirectional_urg_packets=0,
    bidirectional_ack_packets=18,
    bidirectional_psh_packets=9,
    bidirectional_rst_packets=0,
    bidirectional_fin_packets=0,
    src2dst_syn_packets=1,
    src2dst_cwr_packets=0,
    src2dst_ece_packets=0,
    src2dst_urg_packets=0,
    src2dst_ack_packets=8,
    src2dst_psh_packets=4,
    src2dst_rst_packets=0,
    src2dst_fin_packets=0,
    dst2src_syn_packets=1,
    dst2src_cwr_packets=0,
    dst2src_ece_packets=0,
    dst2src_urg_packets=0,
    dst2src_ack_packets=10,
    dst2src_psh_packets=5,
    dst2src_rst_packets=0,
    dst2src_fin_packets=0, 
    master_protocol=91,
    app_protocol=119,
    application_name='TLS.Facebook',
    category_name='SocialNetwork',
    client_info='facebook.com',
    server_info='*.facebook.com,*.facebook.net,*.fb.com,*.fbcdn.net,\
                *.fbsbx.com,*.m.facebook.com,*.messenger.com,*.xx.fbcdn.net,\
                *.xy.fbcdn.net,*.xz.fbcdn.net,facebook.com,fb.com,messenger.com',
    j3a_client='bfcc1a3891601edb4f137ab7ab25b840',
    j3a_server='2d1eb5817ece335c24904f516ad5da12'
)
```

* From pcap to Pandas DataFrame?

```python
my_dataframe = NFStreamer(source='devil.pcap').to_pandas()
my_dataframe.head(5)
```
* Didn't find a specific flow feature? add a plugin to **nfstream** in few lines:

```python
from nfstream import NFPlugin
    
class packet_with_666_size(NFPlugin):
    def on_init(self, pkt): # flow creation with the first packet
        if pkt.raw_size == 666:
            return 1
        else:
            return 0
	
    def on_update(self, pkt, flow): # flow update with each packet belonging to the flow
        if pkt.pkt.raw_size == 666:
            flow.packet_with_666_size += 1
		
streamer_awesome = NFStreamer(source='devil.pcap', plugins=[packet_with_666_size()])
for flow in streamer_awesome:
    print(flow.packet_with_666_size) # see your dynamically created metric in generated flows
```

* More example and details are provided on the official [**documentation**][documentation].
* You can test nfstream without installation using our [**live demo notebook**][demo].

## Installation


### Using pip

Binary installers for the latest released version are available:
```bash
python3 -m pip install nfstream
```

### Build from sources

If you want to build **nfstream** from sources on your local machine:

#### On Linux

```bash
sudo apt-get install autoconf automake libtool pkg-config libpcap-dev
git clone https://github.com/aouinizied/nfstream.git
cd nfstream
python3 -m pip install -r requirements.txt
python3 setup.py bdist_wheel
```

#### On MacOS

```bash
brew install autoconf automake libtool pkg-config
git clone https://github.com/aouinizied/nfstream.git
cd nfstream
python3 -m pip install -r requirements.txt
python3 setup.py bdist_wheel
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
[contribute]: https://nfstream.github.io/docs/community
[contributors]: https://github.com/aouinizied/nfstream/graphs/contributors
[linkedin]: https://www.linkedin.com/in/dr-zied-aouini
[github]: https://github.com/aouinizied
[documentation]: https://nfstream.github.io/
[ndpi]: https://nfstream.github.io/docs/visibility
[nfplugin]: https://nfstream.github.io/docs/api#nfplugin
[reliable]: http://people.ac.upc.edu/pbarlet/papers/ground-truth.pam2014.pdf
[repo]: https://nfstream.github.io/
[demo]: https://mybinder.org/v2/gh/aouinizied/nfstream-tutorials/master?filepath=demo_notebook.ipynb
[stat_feat]: https://nfstream.github.io/docs/api#statistical-features