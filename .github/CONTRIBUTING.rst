############
Contributing
############

Contributions are welcome, and they are greatly appreciated! Every little bit
helps, and credit will always be given.

You can contribute in many ways:

*********************
Types of contribution
*********************

**Report bugs**

Report bugs at https://github.com/nfstream/nfstream/issues.

If you are reporting a bug, please include:

* Your operating system name and version.
* Any details about your local setup that might be helpful in troubleshooting.
* Detailed steps to reproduce the bug.
* pcap file if you are reporting a bug on offline mode

**Fix bugs**

Look through the GitHub issues for bugs. Anything tagged with "bug" and "help
wanted" is open to whoever wants to implement it.

**Implement features**

Look through the GitHub issues for features. Anything tagged with "enhancement"
and "help wanted" is open to whoever wants to implement it.

**Write documentation**

nfstream could always use more documentation, whether as part of the
official nfstream docs, in docstrings, or even on the web in blog posts,
articles, and such.

**Submit feedback**

The best way to send feedback is to file an issue at https://github.com/nfstream/nfstream/issues.

If you are proposing a feature:

* Explain in detail how it would work.
* Keep the scope as narrow as possible, to make it easier to implement.
* Remember that this is a volunteer-driven project, and that contributions
  are welcome.

***********
Get started
***********

Ready to contribute? Here's how to set up nfstream for local development.

1. Fork the nfstream repo on GitHub.
2. Clone your fork locally::

    $ git clone git@github.com:your_name_here/nfstream.git

3. Install your local copy into a virtualenv. This is an example how you set up your fork for local development for Python3.6::

    $ cd nfstream
    $ virtualenv venv-nfstream-py36 -p /usr/bin/python3.6
    $ source venv-nfstream-py36/bin/activate
    $ python setup.py bdist_wheel

4. Create a branch for local development::

    $ git checkout -b name-of-your-bugfix-or-feature

5. When you're done making changes, check that your changes pass the
   tests (run it as root to trigger live capture testing)::

    $ python tests.py

6. Commit your changes and push your branch to GitHub::

    $ git add .
    $ git commit -m "Your detailed description of your changes."
    $ git push origin name-of-your-bugfix-or-feature

7. Submit a pull request through the GitHub website.

***********************
Pull request guidelines
***********************

Before you submit a pull request, check that it meets these guidelines:

1. The pull request should include tests.
2. If the pull request adds functionality, the docs should be updated. Put
   your new functionality into a function with a docstring, and add the
   feature to the list in README.rst.
3. The pull request should work for 3.6 and 3.7 and 3.8 Check
   https://travis-ci.org/nfstream/nfstream/pull_requests
   and make sure that the tests pass for all supported Python versions.

*********
Deploying
*********

A reminder for the maintainers on how to deploy.
Make sure all your changes are committed (including an entry in /docs/source/changelog.rst).
Then run::

$ bumpversion patch
$ git push
$ git push --tags

Travis will then deploy to PyPI if tests pass.
