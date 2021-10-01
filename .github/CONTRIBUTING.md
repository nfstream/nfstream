# Contributing

Contributions are welcome, and they are greatly appreciated! Every little bit helps, and credit will always be given.

You can contribute in many ways.

## Types of contribution

### Report bugs

Report bugs at https://github.com/nfstream/nfstream/issues.

If you are reporting a bug, please include:

* Your operating system name and version.
* Any details about your local setup that might be helpful in troubleshooting.
* Detailed steps to reproduce the bug.
* pcap file if you are reporting a bug on offline mode

### Fix bugs

Look through the GitHub issues for bugs. Anything tagged with "bug" and "help
wanted" is open to whoever wants to implement it.

### Implement features

Look through the GitHub issues for features. Anything tagged with "enhancement"
and "help wanted" is open to whoever wants to implement it.

### Write documentation

NFStream could always use more documentation, whether as part of the
official NFStream docs, in docstrings, or even on the web in blog posts,
articles, and such.

### Submit feedback

The best way to send feedback is to file an issue at https://github.com/nfstream/nfstream/issues.

If you are proposing a feature:

* Explain in detail how it would work.
* Keep the scope as narrow as possible, to make it easier to implement.
* Remember that this is a volunteer-driven project, and that contributions are welcome.


## Get started

Ready to contribute? Here's how to set up NFStream for local development.

* Fork the NFStream repo on GitHub.
* Clone your fork locally::

```shell
git clone git@github.com:your_name_here/nfstream.git
```

* Install NFStream prerequisites:

**On Linux**

```bash
sudo apt-get update
sudo apt-get install autoconf automake libtool pkg-config gettext libjson-c-dev libpcap-dev
sudo apt-get install libusb-1.0-0-dev libdbus-glib-1-dev libbluetooth-dev libnl-genl-3-dev flex bison
```

**On OSX**

```bash
brew install autoconf automake libtool pkg-config gettext json-c
```

* Build NFStream development dependencies:

[**libgpg-error**](https://github.com/gpg/libgpg-error)

```bash
git clone --branch libgpg-error-1.42 https://github.com/gpg/libgpg-error
cd libgpg-error
./autogen.sh
./configure -enable-maintainer-mode --enable-static --enable-shared --with-pic --disable-doc --disable-nls
make
sudo make install
cd ..
rm -rf libgpg-error
```

[**libgcrypt**](https://github.com/gpg/libgcrypt)

```bash
git clone --branch libgcrypt-1.8.8 https://github.com/gpg/libgcrypt
cd libgcrypt
./autogen.sh
./configure -enable-maintainer-mode --enable-static --enable-shared --with-pic --disable-doc
make
sudo make install
cd ..
rm -rf libgcrypt
```

[**libpcap**](https://github.com/the-tcpdump-group/libpcap)

```bash
git clone --branch fanout https://github.com/tsnoam/libpcap
cd libpcap
./configure --enable-ipv6 --disable-universal --enable-dbus=no --without-libnl
make
sudo make install
cd ..
rm -rf libpcap
```

[**nDPI**](https://github.com/ntop/nDPI)

```bash
git clone --branch dev https://github.com/ntop/nDPI.git
cd nDPI
./autogen.sh
./configure
make
sudo mkdir /usr/local/include/ndpi
sudo cp -a src/include/. /usr/local/include/ndpi/
sudo cp example/ndpiReader /usr/local/bin/ndpiReader
sudo cp src/lib/libndpi.a /usr/local/lib/libndpi.a
cd ..
rm -rf nDPI
```


* Install your local copy into a virtualenv. This is an example how you set up your fork for local development 
for Python3.6:

```shell
cd nfstream
virtualenv venv-nfstream-py36 -p /usr/bin/python3.6
source venv-nfstream-py36/bin/activate
pip install wheel twine setuptools codecov
pip install -r requirements.txt
MACOSX_DEPLOYMENT_TARGET=10.14 python setup.py bdist_wheel
```

* Create a branch for local development:

```shell
git checkout -b name-of-your-bugfix-or-feature
```

* When you're done making changes, check that your changes pass the tests:

``` shell
python tests.py
```

* Commit your changes and push your branch to GitHub:

``` shell
git add .
git commit -m "Your detailed description of your changes."
git push origin name-of-your-bugfix-or-feature
```

7. Submit a pull request through the GitHub website.

## Pull request guidelines


Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests.
2. If the pull request adds functionality, the docs should be updated. Put
   your new functionality into a function with a docstring, and add the
   feature to the examples in README.md.
3. The pull request should work for 3.6 and 3.7 and 3.8 and 3.9 and PyPy3 Check Github Actions and Travis CIs and 
make sure all testing jobs are OK.


## Deploying

A reminder for the maintainers on how to deploy.
Make sure all your changes are committed.
Then run:

``` shell
bumpversion patch
git push
git push --tags
```

Github Actions and Travis will then automatically deploy to PyPI if tests pass.
