# Example Applications

We provide some simple examples to demonstrate how **NFStream** can be integrated within your Python application.

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

[csv_generator]: https://github.com/nfstream/nfstream/blob/master/examples/csv_generator.py