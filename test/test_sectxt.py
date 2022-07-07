from unittest import TestCase

from sectxt import Parser


class SecTxtTestCase(TestCase):

    def test_future_expires(self):
        content = "Expires: 2030-01-01T12:00Z\n"
        p = Parser(content)
        self.assertEqual(p._warnings[0]["code"], "long_expiry")

    def test_invalid_expires(self):
        content = "Expires: Nonsense\n"
        p = Parser(content)
        self.assertEqual(p._errors[0]["code"], "invalid_expiry")

    def test_long_expiry(self):
        content = "Expires: 2030-01-01T12:00Z\n# Wow"
        p = Parser(content)
        line_info = p._line_info[1]
        self.assertEqual(line_info["type"], "comment")
        self.assertEqual(line_info["value"], "# Wow")

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
