#
# SPDX-License-Identifier: EUPL-1.2
#
import pytest
import requests
from datetime import date, timedelta
from unittest import TestCase
from sectxt import Parser, SecurityTXT
from requests_mock.mocker import Mocker

_signed_example = f"""-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

# Canonical URI
Canonical: https://example.com/.well-known/security.txt

# Our security address
Contact: mailto:security@example.com

# Our OpenPGP key
Encryption: https://example.com/pgp-key.txt

# Our security policy
Policy: https://example.com/security-policy.html

# Our security acknowledgments page
Acknowledgments: https://example.com/hall-of-fame.html

# CSAF link
CSAF: https://example.com/.well-known/csaf/provider-metadata.json

Expires: {(date.today() + timedelta(days=10)).isoformat()}T18:37:07z
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2.2

wpwEAQEIABAFAmTHcawJEDs4gPMoG10dAACN5wP/UozhFqHcUWRNhg4KwfY4
HHXU8bf222naeYJHgaHadLTJJ8YQIQ9N5fYF7K4BM0jPZc48aaUPaBdhNxw+
KDtQJWPzVREIbbGLRQ5WNYrLR6/7v1LHTI8RvgY22QZD9EAkFQwgdG8paIP4
2APWewNf8e01t1oh4n5bDBtr4IaQoj0=
=DHXw
-----END PGP SIGNATURE-----
"""


class SecTxtTestCase(TestCase):
    def test_future_expires(self):
        content = f"Expires: {date.today().year + 3}-01-01T12:00:00Z\n"
        p = Parser(content)
        self.assertEqual(p._recommendations[0]["code"], "long_expiry")

    def test_invalid_expires(self):
        content = "Expires: Nonsense\n"
        p = Parser(content)
        self.assertEqual(p._errors[0]["code"], "invalid_expiry")
        content = "Expires: Thu, 15 Sep 2022 06:03:46 -0700\n"
        p = Parser(content)
        self.assertEqual(p._errors[0]["code"], "invalid_expiry")

    def test_expired(self):
        content = "Expires: 2020-01-01T12:00:00Z\n"
        p = Parser(content)
        self.assertEqual(p._errors[0]["code"], "expired")

    def test_long_expiry(self):
        content = "Expires: 2030-01-01T12:00:00Z\n# Wow"
        p = Parser(content)
        line_info = p._line_info[1]
        self.assertEqual(line_info["type"], "comment")
        self.assertEqual(line_info["value"], "# Wow")

    def test_preferred_languages(self):
        # Define content for a valid security.txt.
        static_content = (
            f"Expires: {(date.today() + timedelta(days=10)).isoformat()}"
            "T18:37:07z\n"
            "Contact: mailto:security@example.com\n"
        )

        # Single invalid value.
        content = static_content + "Preferred-Languages: English"
        p = Parser(content)
        self.assertEqual(p._errors[0]["code"], "invalid_lang")

        # Mix of valid and invalid value.
        content = static_content + "Preferred-Languages: nl, Invalid"
        p = Parser(content)
        self.assertEqual(p._errors[0]["code"], "invalid_lang")

        # Both ISO 639-1 (2 char) and ISO 639-2 (3 char) should be valid.
        # Case should be ignored.
        content = static_content + "Preferred-Languages: En, dUT"
        p = Parser(content)
        self.assertFalse(any(error["code"] == "invalid_lang" for error in p._errors))

    def test_prec_ws(self):
        content = "Contact : mailto:me@example.com\n# Wow"
        p = Parser(content)
        self.assertEqual(p._errors[0]["code"], "prec_ws")

    def test_empty_key(self):
        content = ": mailto:me@example.com\n# Wow"
        p = Parser(content)
        self.assertEqual(p._errors[0]["code"], "empty_key")

    def test_empty_key2(self):
        content = " : mailto:me@example.com\n# Wow"
        p = Parser(content)
        self.assertEqual(p._errors[1]["code"], "empty_key")

    def test_missing_space(self):
        content = "Contact:mailto:me@example.com\n# Wow"
        p = Parser(content)
        self.assertEqual(p._errors[0]["code"], "no_space")

    def test_missing_value(self):
        content = "Contact: \n# Wow"
        p = Parser(content)
        self.assertEqual(p._errors[0]["code"], "empty_value")

    def test_no_https(self):
        content = "Contact: http://example.com/contact\n# Wow"
        p = Parser(content)
        self.assertEqual(p._errors[0]["code"], "no_https")

    def test_no_uri(self):
        content = "Contact: me@example.com\n# Wow"
        p = Parser(content)
        self.assertEqual(p._errors[0]["code"], "no_uri")

    def test_signed(self):
        p = Parser(_signed_example)
        self.assertTrue(p.is_valid())

    def test_signed_invalid_pgp(self):
        # Remove required pgp signature header for pgp data error
        content = _signed_example.replace(
            "-----BEGIN PGP SIGNATURE-----", ""
        )
        p1 = Parser(content)
        self.assertFalse(p1.is_valid())
        self.assertEqual(
            len([1 for r in p1._errors if r["code"] == "pgp_data_error"]), 1
        )
        # Add dash escaping within the pgp signature for pgp data error
        content = _signed_example.replace(
            "-----BEGIN PGP SIGNATURE-----", "-----BEGIN PGP SIGNATURE-----\n- \n"
        )
        p2 = Parser(content)
        self.assertFalse(p2.is_valid())
        self.assertEqual(
            len([1 for r in p2._errors if r["code"] == "pgp_data_error"]), 1
        )
        # create an error in the pgp message by invalidating the base64 encoding of the signature
        content = _signed_example.replace(
            "wpwEAQEIABAFAmTHcawJEDs4gPMoG10dAACN5wP/UozhFqHcUWRNhg4KwfY4", "wpwEAQEIABAFAmTH"
        ).replace(
            "HHXU8bf222naeYJHgaHadLTJJ8YQIQ9N5fYF7K4BM0jPZc48aaUPaBdhNxw+", "HHXU8bf222naeYJHga"
        )
        p3 = Parser(content)
        self.assertFalse(p3.is_valid())
        self.assertEqual(
            len([1 for r in p3._errors if r["code"] == "pgp_error"]), 1
        )

    def test_signed_no_canonical(self):
        content = _signed_example.replace(
            "Canonical: https://example.com/.well-known/security.txt", ""
        )
        p = Parser(content)
        self.assertEqual(p._recommendations[0]["code"], "no_canonical")

    def test_signed_dash_escaped(self):
        content = _signed_example.replace("Expires", "- Expires")
        p = Parser(content)
        self.assertTrue(p.is_valid())

    def test_pgp_signed_formatting(self):
        content = "\r\n" + _signed_example
        p = Parser(content)
        self.assertFalse(p.is_valid())
        self.assertTrue(any(d["code"] == "signed_format_issue" for d in p.errors))

    def test_unknown_fields(self):
        # Define a security.txt that contains unknown fields (but is valid).
        # The fields Last-updated and Unknown, should be marked as unknown.
        content = (
            f"Expires: {(date.today() + timedelta(days=10)).isoformat()}"
            "T18:37:07z\n"
            "Contact: mailto:security@example.com\n"
            "Last-updated: {date.today().isoformat()}T12:00:00z\n"
            "Unknown: value\n"
            "Encryption: https://example.com/pgp-key.txt\n"
        )

        # By default, recommend that there are unknown fields.
        p = Parser(content)
        self.assertTrue(p.is_valid())
        self.assertEqual(
            len([1 for r in p._notifications if r["code"] == "unknown_field"]), 2
        )

        # When turned off, there should be no unknown_field recommendations.
        p = Parser(content, recommend_unknown_fields=False)
        self.assertTrue(p.is_valid())
        self.assertEqual(
            len([1 for r in p._notifications if r["code"] == "unknown_field"]), 0
        )

    def test_no_line_separators(self):
        expire_date = (date.today() + timedelta(days=10)).isoformat()
        single_line_security_txt = (
            "Contact: mailto:security@example.com  Expires: "
            f"{expire_date}T18:37:07z  # All on a single line"
        )
        p_line_separator = Parser(single_line_security_txt)
        self.assertFalse(p_line_separator.is_valid())
        self.assertEqual(
            len([1 for r in p_line_separator._errors if r["code"] == "no_line_separators"]), 1
        )
        line_length_4_no_carriage_feed = (
            "line 1\n"
            "line 2\n"
            "line 3\n"
            "Contact: mailto:security@example.com  Expires"
        )
        p_length_4 = Parser(line_length_4_no_carriage_feed)
        self.assertFalse(p_length_4.is_valid())
        self.assertEqual(
            len([1 for r in p_length_4._errors if r["code"] == "no_line_separators"]), 1
        )
        self.assertEqual(
            [r["line"] for r in p_length_4._errors if r["code"] == "no_line_separators"], [4]
        )

    def test_csaf_https_uri(self):
        content = _signed_example.replace(
            "CSAF: https://example.com/.well-known/csaf/provider-metadata.json",
            "CSAF: http://example.com/.well-known/csaf/provider-metadata.json",
        )
        p = Parser(content)
        self.assertFalse(p.is_valid())
        self.assertEqual(len([1 for r in p._errors if r["code"] == "no_https"]), 1)

    def test_csaf_provider_file(self):
        content = _signed_example.replace(
            "CSAF: https://example.com/.well-known/csaf/provider-metadata.json",
            "CSAF: https://example.com/.well-known/csaf/other_provider_name.json",
        )
        p = Parser(content)
        self.assertFalse(p.is_valid())
        self.assertEqual(len([1 for r in p._errors if r["code"] == "no_csaf_file"]), 1)

    def test_multiple_csaf_notification(self):
        content = _signed_example.replace(
            "# CSAF link",
            "# CSAF link\n"
            "CSAF: https://example2.com/.well-known/csaf/provider-metadata.json",
        )
        p = Parser(content)
        self.assertTrue(p.is_valid())
        self.assertEqual(
            len([1 for r in p._recommendations if r["code"] == "multiple_csaf_fields"]), 1
        )


def test_not_correct_path(requests_mock: Mocker):
    with Mocker() as m:
        m.get(
            "https://example.com/.well-known/security.txt",
            exc=requests.exceptions.ConnectTimeout,
        )
        m.get("https://example.com/security.txt", text=_signed_example)
        s = SecurityTXT("example.com")
        if not any(d["code"] == "location" for d in s.errors):
            pytest.fail("location error code should be given")


def test_invalid_uri_scheme(requests_mock: Mocker):
    with Mocker() as m:
        m.get(
            "https://example.com/.well-known/security.txt",
            exc=requests.exceptions.ConnectTimeout,
        )
        m.get(
            "https://example.com/security.txt", exc=requests.exceptions.ConnectTimeout
        )
        m.get("http://example.com/.well-known/security.txt", text=_signed_example)
        s = SecurityTXT("example.com")
        if not any(d["code"] == "invalid_uri_scheme" for d in s.errors):
            pytest.fail("invalid_uri_scheme error code should be given")


def test_byte_order_mark(requests_mock: Mocker):
    with Mocker() as m:
        byte_content_with_bom = b'\xef\xbb\xbf\xef\xbb\xbfContact: mailto:me@example.com\n' \
                                b'Expires: 2023-08-11T18:37:07z\n'
        m.get(
            "https://example.com/.well-known/security.txt",
            headers={"content-type": "text/plain"},
            content=byte_content_with_bom,
        )
        s = SecurityTXT("example.com")
        assert(s.is_valid())
