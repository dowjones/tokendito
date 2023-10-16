# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Simulatie okta reponses."""

with_mfa = {
    "status": "MFA_REQUIRED",
    "_embedded": {
        "user": {
            "profile": {
                "login": "First.Last@acme.org",
            },
        },
        "factors": [
            {
                "id": "opfrar9yi4bKJNH2WEW",
                "factorType": "push",
                "provider": "OKTA",
                "profile": {"name": "Redmi 6 Pro"},
            },
            {
                "id": "FfdskljfdsS1ljUT0r8",
                "factorType": "token:software:totp",
                "provider": "GOOGLE",
                "profile": {"credentialId": "First.Last@acme.org"},
            },
            {
                "id": "fdsfsd6ewREr8",
                "factorType": "token:software:totp",
                "provider": "OKTA",
                "profile": {"credentialId": "First.Last@acme.org"},
            },
            {
                "id": "fdsfsd6ewREr0",
                "factorType": "pytest_dupe",
                "provider": "GOOGLE",
                "profile": {"credentialId": "First.Last@acme.org"},
            },
            {
                "id": "fdsfsd6ewREr1",
                "factorType": "pytest_dupe",
                "provider": "OKTA",
                "profile": {"credentialId": "First.Last@acme.org"},
            },
        ],
    },
}
no_mfa_no_session_token = {"status": "SUCCESS", "sessionToken": None}
no_mfa = {"status": "SUCCESS", "sessionToken": 345}
error_dict = {"errorCode": "E0000004"}
empty_dict = {}
no_auth_methods = {"status": "MFA_REQUIRED"}
