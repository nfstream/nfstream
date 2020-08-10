![NFStream Logo](https://raw.githubusercontent.com/nfstream/nfstream/master/nfstream_logo_dark.png?raw=true)

--------------------------------------------------------------------------------
[**NFStream**][repo] is a Python package providing fast, flexible, and expressive data structures designed to make working with **online** or **offline** network data both easy and intuitive. It aims to be the fundamental high-level building block for
doing practical, **real world** network data analysis in Python. Additionally, it has
the broader goal of becoming **a common network data processing framework for researchers** providing data reproducibility across experiments.

<table>
<tr>
  <td><b>Live Notebook</b></td>
  <td>
    <a href="https://mybinder.org/v2/gh/nfstream/nfstream-tutorials/master?filepath=demo_notebook.ipynb">
    <img src="https://img.shields.io/badge/notebook-launch-blue?logo=jupyter&style=for-the-badge" alt="live notebook" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Project Website</b></td>
  <td>
    <a href="https://www.nfstream.org/">
    <img src="https://img.shields.io/website?down_color=red&down_message=down&label=nfstream.org&logo=github&up_color=blue&up_message=up&url=https%3A%2F%2Fnfstream.org%2F&style=for-the-badge" alt="website" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Discussion Channel</b></td>
  <td>
    <a href="https://gitter.im/nfstream/community">
    <img src="https://img.shields.io/badge/chat-on%20gitter-blue?color=blue&logo=gitter&style=for-the-badge" alt="Gitter" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Latest Release</b></td>
  <td>
    <a href="https://pypi.python.org/pypi/nfstream">
    <img src="https://img.shields.io/pypi/v/nfstream.svg?logo=pypi&style=for-the-badge" alt="latest release" />
    </a>
  </td>
</tr>

<tr>
  <td><b>Supported Versions</b></td>
  <td>
    <a href="https://github.com/nfstream/nfstream/actions?query=workflow%3Abuild">
    <img src="https://img.shields.io/pypi/pyversions/nfstream?logo=python&style=for-the-badge" alt="python3" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Project License</b></td>
  <td>
    <a href="https://github.com/nfstream/nfstream/blob/master/LICENSE">
    <img src="https://img.shields.io/pypi/l/nfstream?logo=gnu&style=for-the-badge&color=blue" alt="License" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Build Status</b></td>
  <td>
    <a href="https://github.com/nfstream/nfstream/actions?query=workflow%3Abuild">
    <img src="https://img.shields.io/github/workflow/status/nfstream/nfstream/build/master?logo=github&style=for-the-badge" alt="Github WorkFlows" />
    </a>
    <a href="https://travis-ci.org/github/nfstream/nfstream">
    <img src="https://img.shields.io/travis/nfstream/nfstream?logo=travis&style=for-the-badge" alt="Travis CI" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Code Quality</b></td>
  <td>
    <a href="https://lgtm.com/projects/g/nfstream/nfstream/context:python">
    <img src="https://img.shields.io/lgtm/grade/python/github/nfstream/nfstream.svg?logo=lgtm&style=for-the-badge&logoWidth=18)" alt="Quality" />
    </a>
  </td>
</tr>
<tr>
  <td><b>Code Coverage</b></td>
  <td>
    <a href="https://codecov.io/gh/nfstream/nfstream/">
    <img src="https://img.shields.io/codecov/c/github/nfstream/nfstream?color=brightgreen&logo=codecov&style=for-the-badge" alt="Coverage" />
    </a>
  </td>
</tr>
</table>

## Main Features

* **Performance:** **NFStream** is designed to be fast (with native [**PyPy**][pypy] support) with a small CPU and memory footprint.
* **Layer-7 visibility:** **NFStream** deep packet inspection engine is based on [**nDPI**][ndpi]. It allows NFStream to perform [**reliable**][reliable] encrypted applications identification and metadata extraction (e.g. TLS, QUIC, TOR, HTTP, SSH, DNS, etc.).
* **Flexibility:** add a flow feature in 2 lines as an [**NFPlugin**][nfplugin].
* **Machine Learning oriented:** add your trained model as an [**NFPlugin**][nfplugin]. 

## How to use it?

* Dealing with a big pcap file and just want to aggregate it as network flows? **NFStream** make this path easier in few lines:

```python
from nfstream import NFStreamer
my_awesome_streamer = NFStreamer(source="facebook.pcap", # or network interface
                                 snaplen=65535,
                                 idle_timeout=30,
                                 active_timeout=300,
                                 plugins=(),
                                 dissect=True,
                                 max_tcp_dissections=80,
                                 max_udp_dissections=16,
                                 statistics=False,
                                 enable_guess=True,
                                 decode_tunnels=True,
                                 bpf_filter=None,
                                 promisc=True
)

for flow in my_awesome_streamer:
    print(flow)  # print it.
    print(flow.to_namedtuple()) # convert it to a namedtuple.
    print(flow.to_json()) # convert it to json.
    print(flow.keys()) # get flow keys.
    print(flow.values()) # get flow values.
```

```python
NFEntry(id=0,
        bidirectional_first_seen_ms=1472393122365,
        bidirectional_last_seen_ms=1472393123665,
        src2dst_first_seen_ms=1472393122365,
        src2dst_last_seen_ms=1472393123408,
        dst2src_first_seen_ms=1472393122668,
        dst2src_last_seen_ms=1472393123665,
        src_ip='192.168.43.18',
        src_ip_type=1,
        dst_ip='66.220.156.68',
        dst_ip_type=0,
        version=4,
        src_port=52066,
        dst_port=443,
        protocol=6,
        vlan_id=4,
        bidirectional_packets=19,
        bidirectional_raw_bytes=5745,
        bidirectional_ip_bytes=5479,
        bidirectional_duration_ms=1300,
        src2dst_packets=9,
        src2dst_raw_bytes=1345,
        src2dst_ip_bytes=1219,
        src2dst_duration_ms=1300,
        dst2src_packets=10,
        dst2src_raw_bytes=4400,
        dst2src_ip_bytes=4260,
        dst2src_duration_ms=997,
        expiration_id=0,
        master_protocol=91,
        app_protocol=119,
        application_name='TLS.Facebook',
        category_name='SocialNetwork',
        client_info='facebook.com',
        server_info='*.facebook.com,*.facebook.net,*.fb.com,\
                     *.fbcdn.net,*.fbsbx.com,*.m.facebook.com,\
                     *.messenger.com,*.xx.fbcdn.net,*.xy.fbcdn.net,\
                     *.xz.fbcdn.net,facebook.com,fb.com,messenger.com',
        ja3_client='bfcc1a3891601edb4f137ab7ab25b840',
        ja3_server='2d1eb5817ece335c24904f516ad5da12')

 ```
* NFStream also extracts [**60+ flow statistical features**][stat_feat]

```python
from nfstream import NFStreamer
my_awesome_streamer = NFStreamer(source="facebook.pcap", statistics=True)
for flow in my_awesome_streamer:
    print(flow)
```

```python
NFEntry(id=0,      
        bidirectional_first_seen_ms=1472393122365,
        bidirectional_last_seen_ms=1472393123665,
        src2dst_first_seen_ms=1472393122365,
        src2dst_last_seen_ms=1472393123408,
        dst2src_first_seen_ms=1472393122668,
        dst2src_last_seen_ms=1472393123665,
        src_ip='192.168.43.18',
        src_ip_type=1,
        dst_ip='66.220.156.68',
        dst_ip_type=0,
        version=4,
        src_port=52066,
        dst_port=443,
        protocol=6,
        vlan_id=4,
        bidirectional_packets=19,
        bidirectional_raw_bytes=5745,
        bidirectional_ip_bytes=5479,
        bidirectional_duration_ms=1300,
        src2dst_packets=9,
        src2dst_raw_bytes=1345,
        src2dst_ip_bytes=1219,
        src2dst_duration_ms=1300,
        dst2src_packets=10,
        dst2src_raw_bytes=4400,
        dst2src_ip_bytes=4260,
        dst2src_duration_ms=997,
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
        bidirectional_min_piat_ms=0,
        bidirectional_mean_piat_ms=72.22222222222223,
        bidirectional_stdev_piat_ms=137.34994188549086,
        bidirectional_max_piat_ms=398,
        src2dst_min_piat_ms=0,
        src2dst_mean_piat_ms=130.375,
        src2dst_stdev_piat_ms=179.72036811192467,
        src2dst_max_piat_ms=415,
        dst2src_min_piat_ms=0,
        dst2src_mean_piat_ms=110.77777777777777,
        dst2src_stdev_piat_ms=169.51458475436397,
        dst2src_max_piat_ms=1,
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
        server_info='*.facebook.com,*.facebook.net,*.fb.com,\
                     *.fbcdn.net,*.fbsbx.com,*.m.facebook.com,\
                     *.messenger.com,*.xx.fbcdn.net,*.xy.fbcdn.net,\
                     *.xz.fbcdn.net,facebook.com,fb.com,messenger.com',
        j3a_client='bfcc1a3891601edb4f137ab7ab25b840',
        j3a_server='2d1eb5817ece335c24904f516ad5da12')
```

* From pcap to Pandas DataFrame?

```python
my_dataframe = NFStreamer(source='devil.pcap').to_pandas(ip_anonymization=False)
my_dataframe.head(5)
```

* From pcap to csv file?

```python
flows_rows_count = NFStreamer(source='devil.pcap').to_csv(path="devil.pcap.csv",
                                                          sep="|",
                                                          ip_anonymization=False)
```
* Didn't find a specific flow feature? add a plugin to **NFStream** in few lines:

```python
from nfstream import NFPlugin
    
class packet_with_666_size(NFPlugin):
    def on_init(self, pkt): # flow creation with the first packet
        if pkt.raw_size == 666:
            return 1
        else:
            return 0
	
    def on_update(self, pkt, flow): # flow update with each packet belonging to the flow
        if pkt.raw_size == 666:
            flow.packet_with_666_size += 1
		
streamer_awesome = NFStreamer(source='devil.pcap', plugins=[packet_with_666_size()])
for flow in streamer_awesome:
    print(flow.packet_with_666_size) # see your dynamically created metric in generated flows
```

### Run your Machine Learning models

In the following, we want to run an early classification of flows based on a trained machine learning model than takes 
as features the 3 first packets size of a flow.

#### Computing required features

```python
from nfstream import NFPlugin

class feat_1(NFPlugin):
    def on_init(self, obs):
        return obs.raw_size

class feat_2(NFPlugin):
    def on_update(self, obs, entry):
        if entry.bidirectional_packets == 2:
            entry.feat_2 = obs.raw_size

class feat_3(NFPlugin):
    def on_update(self, obs, entry):
        if entry.bidirectional_packets == 3:
            entry.feat_3 = obs.raw_size
```

#### Trained model prediction

```python
class model_prediction(NFPlugin):
    def on_update(self, obs, entry):
        if entry.bidirectional_packets == 3:
            entry.model_prediction = self.user_data.predict_proba([entry.feat_1,
                                                                   entry.feat_2,
                                                                   entry.feat_3])
            # optionally we can trigger NFStreamer to immediately expires the flow
            # entry.expiration_id = -1
```

#### Start your ML powered streamer

```python
my_model = function_to_load_your_model() # or whatever
ml_streamer = NFStreamer(source='devil.pcap',
                         plugins=[feat_1(volatile=True),
                                  feat_2(volatile=True),
                                  feat_3(volatile=True),
                                  model_prediction(user_data=my_model)
                                  ])
for flow in ml_streamer:
     print(flow.model_prediction) # now you will see your trained model prediction.
```
* More example and details are provided on the official [**documentation**][documentation].
* You can test NFStream without installation using our [**live demo notebook**][demo].

## Installation


### Using pip

Binary installers for the latest released version are available:
```bash
python3 -m pip install nfstream
```

### Build from sources

If you want to build **NFStream** from sources on your local machine:

#### ![linux](https://raw.githubusercontent.com/wiki/ryanoasis/nerd-fonts/screenshots/v1.0.x/linux-pass-sm.png) Linux

```bash
sudo apt-get update
sudo apt-get install autoconf automake libtool pkg-config libpcap-dev flex bison
sudo apt-get install libusb-1.0-0-dev libdbus-glib-1-dev libbluetooth-dev libnl-genl-3-dev
git clone https://github.com/nfstream/nfstream.git
cd nfstream
python3 -m pip install -r requirements.txt
python3 setup.py bdist_wheel
```

#### ![osx](https://raw.githubusercontent.com/wiki/ryanoasis/nerd-fonts/screenshots/v1.0.x/mac-pass-sm.png) MacOS

```bash
brew install autoconf automake libtool pkg-config
git clone https://github.com/nfstream/nfstream.git
cd nfstream
python3 -m pip install -r requirements.txt
python3 setup.py bdist_wheel
```

## Contributing

Please read [**Contributing**][contribute] for details on our code of conduct, and the process for submitting pull
requests to us.

## Ethics

**NFStream** is intended for network data research and forensics.
Researchers and network data scientists can use these framework to build reliable datasets, train and evaluate
network applied machine learning models.
As with any packet monitoring tool, **NFStream** could potentially be misused.
**Do not run it on any network of which you are not the owner or the administrator**.

## License

This project is licensed under the LGPLv3 License - see the [**License**][license] file for details

[license]: https://github.com/nfstream/nfstream/blob/master/LICENSE
[contribute]: https://nfstream.org/docs/community
[contributors]: https://github.com/nfstream/nfstream/graphs/contributors
[documentation]: https://nfstream.org/
[ndpi]: https://nfstream.org/docs/visibility
[nfplugin]: https://nfstream.org/docs/api#nfplugin
[reliable]: http://people.ac.upc.edu/pbarlet/papers/ground-truth.pam2014.pdf
[repo]: https://nfstream.org/
[demo]: https://mybinder.org/v2/gh/nfstream/nfstream/master?filepath=demo_notebook.ipynb
[stat_feat]: https://nfstream.org/docs/api#statistical-features
[pypy]: https://www.pypy.org/
