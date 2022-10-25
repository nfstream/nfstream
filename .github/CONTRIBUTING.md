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

Ready to contribute? Here's a typical contribution workflow.

### Setup your working NFStream environment

### Fork NFStream and clone your fork:

```shell
git clone --recurse-submodules git@github.com:your_name_here/nfstream.git
```

### Create a branch for local development:

```shell
git checkout -b name-of-your-bugfix-or-feature
```

### Build NFStream from sources

#### Linux Prerequisites

```bash
sudo apt-get update
sudo apt-get install python3-dev autoconf automake libtool pkg-config flex bison gettext libjson-c-dev
sudo apt-get install libusb-1.0-0-dev libdbus-glib-1-dev libbluetooth-dev libnl-genl-3-dev
```

#### MacOS Prerequisites

```bash
brew install autoconf automake libtool pkg-config gettext json-c
```

### Windows Prerequisites

On Windows, NFStream build system is based MSYS2. Please follow [**msys2 installation guide**][msys2] before moving to 
the next steps.

```bash
pacman -S git unzip mingw-w64-x86_64-toolchain automake1.16 automake-wrapper autoconf libtool make mingw-w64-x86_64-json-c mingw-w64-x86_64-crt-git
```

Note that you will also need to have npcap installed according to [**these instructions**][npcap].

### Build

```bash
git clone --recurse-submodules https://github.com/nfstream/nfstream.git
cd nfstream
python3 -m pip install --upgrade pip
python3 -m pip install -r dev_requirements.txt
python3 -m pip install .
```

### Test it

When you're done making changes, check that your changes pass the tests and add a test if needed:

``` shell
python tests.py
```

### Commit your changes and push your branch to GitHub:

``` shell
git add .
git commit -m "Your detailed description of your changes."
git push origin name-of-your-bugfix-or-feature
```

### Submit a pull request through the GitHub website.

## Pull request guidelines

Before you submit a pull request, check that it meets these guidelines:

* The pull request should include tests. 
* If the pull request adds functionality, the docs should be updated. Put your new 
functionality into a function with a docstring, and add the feature to the examples in README.md. 
* The pull request should work for 3.6 and 3.7 and 3.8 and 3.9 and PyPy3 Check Github Actions and Travis CIs and 
make sure all testing jobs are OK.


## Deploy

A reminder for the maintainers on how to deploy. Make sure all your changes are committed.
Then run:

``` shell
bumpversion patch
git push
git push --tags
```

Github Actions will then automatically deploy to PyPI if tests pass.

[msys2]: https://www.msys2.org/
[npcap]: https://npcap.com/guide/npcap-users-guide.html
