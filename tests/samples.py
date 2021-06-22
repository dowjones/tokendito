# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""This module handles samples."""


def primary_auth(
    last_name="Lastname",
    first_name="Firstname",
    email="Firstname.Lastname@acme.org",
    timestamp=None,
    time_zone=None,
    locale=None,
):
    """Generate template for simalation okta reply.

    :param first_name: User first name
    :param last_name: User last name
    :param email: User email
    :param timestamp: localtime in user location
    :param time_zone: user's time zone
    :param locale: user's locale
    :return: simulated okta reply

    """
    return {
        "stateToken": "xfmktlTe4ksl593klssER",
        "expiresAt": timestamp,
        "status": "MFA_REQUIRED",
        "factorResult": "SUCCESS",
        "_embedded": {
            "user": {
                "id": "44urdfsafdse3Ib0x8",
                "profile": {
                    "login": email,
                    "firstName": first_name,
                    "lastName": last_name,
                    "locale": locale,
                    "timeZone": time_zone,
                },
            },
            "factors": [
                {
                    "id": "opfrar9yi4bKJNH2WEWQ0x8",
                    "factorType": "push",
                    "provider": "OKTA",
                    "vendorName": "OKTA",
                    "profile": {
                        "credentialId": email,
                        "deviceType": "SmartPhone_Android",
                        "keys": [
                            {
                                "kty": "RSA",
                                "use": "sig",
                                "kid": "default",
                                "e": "AQAB",
                                "n": "FDSAKLJFDSALElkdfjsklj3424lkdsfjlkKLDJSF",
                            }
                        ],
                        "name": "Redmi 6 Pro",
                        "platform": "ANDROID",
                        "version": "28",
                    },
                    "_links": {
                        "verify": {
                            "href": "https://www.acme.org",
                            "hints": {"allow": ["POST"]},
                        }
                    },
                },
                {
                    "id": "FfdskljfdsS1ljUT0r8",
                    "factorType": "token:software:totp",
                    "provider": "GOOGLE",
                    "vendorName": "GOOGLE",
                    "profile": {"credentialId": email},
                    "_links": {
                        "verify": {
                            "href": "https://www.acme.org",
                            "hints": {"allow": ["POST"]},
                        }
                    },
                },
                {
                    "id": "fdsfsd6ewREr8",
                    "factorType": "token:software:totp",
                    "provider": "OKTA",
                    "vendorName": "OKTA",
                    "profile": {"credentialId": email},
                    "_links": {
                        "verify": {
                            "href": "https://www.acme.org",
                            "hints": {"allow": ["POST"]},
                        }
                    },
                },
            ],
            "policy": {
                "allowRememberDevice": True,
                "rememberDeviceLifetimeInMinutes": 82200,
                "rememberDeviceByDefault": False,
                "factorsPolicyInfo": {
                    "opfrar9yi4bRM2NHV0x7": {"autoPushEnabled": False}
                },
            },
        },
        "_links": {
            "cancel": {"href": "https://www.acme.org", "hints": {"allow": ["POST"]}}
        },
    }
