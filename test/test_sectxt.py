#
# SPDX-License-Identifier: EUPL-1.2
#

from datetime import date, timedelta
from unittest import TestCase

from sectxt import Parser


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

Expires: {(date.today() + timedelta(days=10)).isoformat()}T18:37:07z
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v2.2

[signature]
-----END PGP SIGNATURE-----
"""


class SecTxtTestCase(TestCase):

    def test_future_expires(self):
        content = f"Expires: {date.today().year + 3}-01-01T12:00Z\n"
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
        content = "Expires: 2030-01-01T12:00Z\n# Wow"
        p = Parser(content)
        line_info = p._line_info[1]
        self.assertEqual(line_info["type"], "comment")
        self.assertEqual(line_info["value"], "# Wow")
        
    def test_preferred_languages(self):
        # Define content for a valid security.txt.
        static_content = (
            f"Expires: {(date.today() + timedelta(days=10)).isoformat()}"
            "T18:37:07z\n"
            "Contact: mailto:security@example.com\n")
   
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
        self.assertFalse(
            any(
                error["code"] == "invalid_lang" 
                for error in p._errors
            )
        )

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

    def test_signed_no_canonical(self):
        content = _signed_example.replace(
            "Canonical: https://example.com/.well-known/security.txt", "")
        p = Parser(content)
        self.assertEqual(p._recommendations[0]['code'], "no_canonical")

    def test_signed_dash_escaped(self):
        content = _signed_example.replace("Expires", "- Expires")
        p = Parser(content)
        self.assertTrue(p.is_valid())

    def test_unknown_fields(self):
        # Define a security.txt that contains unknown fields (but is valid).
        # The fields Last-updated and Unknown, should be marked as unknown.
        content = (
            f"Expires: {(date.today() + timedelta(days=10)).isoformat()}"
            "T18:37:07z\n"
            "Contact: mailto:security@example.com\n"
            "Last-updated: {date.today().isoformat()}T12:00:00z\n"
            "Unknown: value\n"
            "Encryption: https://example.com/pgp-key.txt\n")
        
        # By default, recommend that there are unknown fields.
        p = Parser(content)
        self.assertTrue(p.is_valid())
        self.assertEqual(len([1 for r in p._recommendations if r["code"] == "unknown_field"]), 2)
        
        # When turned off, there should be no unknown_field recommendations.
        p = Parser(content, recommend_unknown_fields=False)
        self.assertTrue(p.is_valid())
        self.assertEqual(len([1 for r in p._recommendations if r["code"] == "unknown_field"]), 0)
       
