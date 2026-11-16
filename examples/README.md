# Example Applications

We provide some simple examples to demonstrate how **NFStream** can be integrated within your Python application.

## Setup your environment

``` bash
python3 -m pip install --upgrade pip
virtualenv venv-py -p /usr/bin/python3
source venv-py/bin/activate
pip install --upgrade nfstream
```

## flow_printer

```
usage: python3 flow_printer.py input

positional arguments:
  input                 input pcap file or network interface (root privileges required)
```

## csv_generator

```
usage: python3 csv_generator.py input

positional arguments:
  input                 input pcap file or network interface (root privileges required)

Generated CSV will be stored in the same directory and named input.csv.
```

> **Live Capture Notes**: For live interface capture, root privileges.
> Example:
> 
> sudo venv-py/bin/python3 flow_printer.py eth0
>
> sudo venv-py/bin/python3 csv_generator.py eth0

[csv_generator]: https://github.com/nfstream/nfstream/blob/master/examples/csv_generator.py
## Directional bursts for flow classification

```python
from nfstream import NFStreamer
from nfstream.plugins import BurstSequence

for flow in NFStreamer(source="capture.pcap", udps=BurstSequence(sequence_length=8)):
    print(flow.udps.burst_bytes, flow.udps.burst_packets)
```

The two vectors summarize consecutive payload-carrying packets travelling in the same direction. Byte totals are signed by direction, and zero padding keeps a fixed input width for classifiers. Only packet metadata is used.
