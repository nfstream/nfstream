# NFStream Browser Extensions (experimental)

This repository contains NFStream browser extensions (Chrome and Firefox) that was implemented
as part of a exploratory work for end-host ground truth generation.
The main idea was to explore what could be extracted from a browser context data (tab_id, tab_url, 
etc.) to enrich end-host visibility when the process generating the traffic is a browser.

This implementation was first ([**this commit**][commit]) introduced in NFStream as experimental/draft code 
(not officially documented), we decided for clarity purposes to isolate it and provide it in this separate repository.

Feel free to use it or extend it as part of your research experiments.

## How it works?

NFStream browser extension is simply a listener on `onResponseStarted` of [**webRequest**][webrequest] browser API that
perform the following actions:

* extract features such as timestamp, tab identifier, request identifier, tab is active, server IP address and URL.
* export it as HTTP POST it a JSON format to **localhost:export_port**.

`export_port` is configurable by the user in the nfstream extension options menu and is set by default to `28314`.

## How to use it?

### Setup your environment

``` bash
python3 -m pip install --upgrade pip
virtualenv venv-py -p /usr/bin/python3
source venv-py/bin/activate
```

### Load the extensions

#### On Chrome

* Open: chrome://extensions
* Enable `Developer Mode`.
* Click on `Load unpacked`.
* Select `nfstream/browser/chrome` folder.
* Now NFStream extension is loaded, you can navigate to details menu and then select extension options to configure 
a specific export port.

#### On Firefox

* Open `about:debugging`
* Click `This Firefox`
* Click `Load Temporary Add-on`
* Open the `nfstream/browser/firefox` and select any file inside the extension,
* Now NFStream extension is loaded, you can navigate to `about:addons` and then select extension preferences
to configure specific export port.


### extension_server

```
usage: python3 extension_server.py listening_port_number

positional arguments:
  listening_port_number    port number to listen to (default 28314).
```

The script will display exported data from the extensions. That's it!

[webrequest]: https://developer.chrome.com/docs/extensions/reference/webRequest/
[commit]: https://github.com/nfstream/nfstream/commit/729e69d97bac69c12609b28271d32542e9f5dc45


