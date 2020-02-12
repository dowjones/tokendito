=========
Terraform
=========

Use these files to create basic infrastructure in an AWS account federated to Okta. The roles
can then be used for ``py.test`` functional tests. Requires Terraform 0.12.x

Example
-------
.. code-block:: sh

  AWS_PROFILE=tokendito-tests-profile terraform plan
  AWS_PROFILE=tokendito-tests-profile terraform apply

If you need to configure more than one IdP, use the format:

.. code-block:: sh

  AWS_PROFILE=tokendito-tests-profile terraform plan -var 'idp=["primary_IdP","secondary_IdP"]'
  AWS_PROFILE=tokendito-tests-profile terraform apply -var 'idp=["primary_IdP","secondary_IdP"]'
