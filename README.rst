.. image:: https://raw.githubusercontent.com/dowjones/tokendito/master/docs/tokendito.png
   :align: center

Generate temporary AWS credentials via Okta.

.. image:: https://github.com/dowjones/tokendito/workflows/Lint%20and%20Test/badge.svg
    :target: https://github.com/dowjones/tokendito/actions

.. image:: https://img.shields.io/badge/python-2.7%2C%203.5%2C%203.6%2C%203.7%2C%203.8-blueviolet
    :target: https://pypi.org/project/tokendito/

.. image:: https://github.com/dowjones/tokendito/workflows/Woke/badge.svg
    :target: https://github.com/dowjones/tokendito/actions

.. image:: https://img.shields.io/badge/license-Apache%202.0-ff69b4
    :target: https://github.com/dowjones/tokendito/blob/master/LICENSE.txt

.. image:: https://img.shields.io/badge/OS-Mac%2C%20Windows%2C%20Linux-9cf
    :target: https://github.com/dowjones/tokendito/

|
|

.. image:: https://raw.githubusercontent.com/dowjones/tokendito/master/docs/tokendito-scaled.gif


**WARNING: Python2.7 and Python3.5 support will be dropped in a near time, pin tokendito version to current if you want to keep it working in automation.**

NOTE: Advanced users may shorten the tokendito interaction to a `single command <https://github.com/dowjones/tokendito/tree/master/docs#single-command-usage>`_.

.. _STS: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html

Use tokendito to generate temporary AWS credentials via Okta for programmatic authentication to AWS. Tokendito signs you in to Okta and uses your existing AWS integration to broker your SAML assertion into your AWS accounts, returning STS_ tokens into your local ``~/.aws/credentials`` file.

Requirements
------------

* Python 2.7.10+
* Your AWS account is federated in Okta

tokendito is compatible with both python 2 and 3, and can be installed with either pip or pip3.

Getting started
---------------

#. Install (via PyPi): ``pip install tokendito``

#. Run ``tokendito --configure``.

#. Run ``tokendito``.

Have multiple Okta tiles to switch between? View our `multi-tile guide <https://github.com/dowjones/tokendito/tree/master/docs#multi-tile-guide>`_.

=====================================================================================================================================================================================================================================================
Tips, tricks, troubleshooting, examples, and more docs are `here <https://github.com/dowjones/tokendito/blob/master/docs/README.rst>`_! Also, `contributions are welcome <https://github.com/dowjones/tokendito/blob/master/docs/CONTRIBUTING.rst>`_!
=====================================================================================================================================================================================================================================================
