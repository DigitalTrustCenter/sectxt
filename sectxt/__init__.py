from collections import defaultdict
from datetime import datetime, timezone
import socket
from typing import Optional, Union, List
from urllib.parse import urlsplit, urlunsplit

import dateutil.parser
import requests
import urllib3.util.connection


__version__ = "0.1"

urllib3.util.connection.allowed_gai_family = lambda: socket.AF_INET

s = requests.Session()
# print(s.def)
class Parser:
    PREFERRED_LANGUAGES = "preferred-languages"

    uri_fields = [
        "acknowledgments", "canonical", "contact", "encryption", "hiring",
        "policy"]

    def __init__(self, content: str, url: Optional[str] = None):
        self._url = url
        self._line_info = []
        self._errors = []
        self._warnings = []
        self._recommendations = []
        self._values = defaultdict(list)
        self._langs = None
        lines = content.split("\n")
        for line_no, line in enumerate(lines):
            self.parse_line(line, line_no)
        self.validate_contents()

    def _add_error(self, code: str, message: str, line_no: Optional[int] = None):
        if line_no is not None:
            line_no += 1
        err_dict = {"code": code, "message": message, "line": line_no}
        self._errors.append(err_dict)

    def _add_warning(self, code: str, message: str, line_no: Optional[int] = None):
        if line_no is not None:
            line_no += 1
        err_dict = {"code": code, "message": message, "line": line_no}
        self._warnings.append(err_dict)

    def _add_recommendation(self, code: str, message: str, line_no: Optional[int] = None):
        if line_no is not None:
            line_no += 1
        err_dict = {"code": code, "message": message, "line": line_no}
        self._recommendations.append(err_dict)

    def parse_line(self, line: str, line_no: int):
        line = line.rstrip()
        if line.startswith("#"):
            self._line_info.append({"type": "comment", "value": line})
        elif ":" in line:
            self.parse_field(line, line_no)

    def parse_field(self, line: str, line_no: int):
        key, value = line.split(":", 1)
        key = key.lower()
        if key.rstrip() != key:
            self._add_error("prec_ws", "There should be no whitespace before the field separator (colon)", line_no)
            key = key.rstrip()
        if not key:
            self._add_error("empty_key", "Field key can not be empty", line_no)

        if value:
            if value[0] != " ":
                self._add_error("no_space", "The field separator (colon) must be followed by a space", line_no)
            value = value.lstrip()

        if not value:
            self._add_error("empty_value", "Field value can not be empty", line_no)
        else:
            if key in self.uri_fields:
                url_parts = urlsplit(value)
                if url_parts.scheme == "":
                    self._add_error("no_uri", "Field value must be an URI", line_no)
                elif url_parts.scheme == "http":
                    self._add_error("no_https", "A web URI must be https", line_no)
            elif key == "expires":
                value = self._parse_expires(value, line_no)
        self._values[key].append(value)
        self._line_info.append(
            {"type": "field", "field_name": key, "value": value})

    def _parse_expires(self, value, line_no):
        try:
            value = dateutil.parser.parse(value)
        except dateutil.parser.ParserError:
            self._add_error("invalid_expiry", "Date in Expires field is invalid")
        else:
            now = datetime.now(timezone.utc)
            max_value = now.replace(year=now.year + 1)
            if value > max_value:
                self._add_warning(
                    "long_expiry",
                    "Expiry date is more than one year in the future",
                    line_no,
                )
        return value

    def validate_contents(self):
        if "expires" not in self._values:
            self._add_error("no_expire", "Expires field is missing")
        elif len(self._values["expires"]) > 1:
            self._add_error(
                "multi_expire", "Expires field must appear only once")
        if self._url and "canonical" in self._values:
            if self._url not in self._values["canonical"]:
                self._add_error(
                    "no_canonical", "URL does not match with canonical URLs")
        if "contact" not in self._values:
            self._add_error(
                "no_contact", "Contact field must appear at least once")
        else:
            if (any(v.startswith("mailto:") for v in self._values['contact'])
                    and "encryption" not in self._values):
                self._add_recommendation(
                    "no_encryption",
                    "Contact missing encryption key for email communication")
        if self.PREFERRED_LANGUAGES in self._values:
            if len(self._values[self.PREFERRED_LANGUAGES]) > 1:
                self._add_error(
                    "multi_lang", "Multiple Preferred-Languages lines are not allowed")
            self._langs = [
                v.strip() for v in self._values[self.PREFERRED_LANGUAGES][0].split(",")]


class SecurityTXT:

    CORRECT_PATH = ".well-known/security.txt"

    def __init__(self, url: str):
        url_parts = urlsplit(url)
        if url_parts.scheme:
            if not url_parts.netloc:
                raise ValueError("Invalid URL")
            netloc = url_parts.netloc
        else:
            netloc = url
        self._netloc = netloc
        self._errors = []
        self._warnings = []
        self._recommendations = []
        self._path: Optional[str] = None
        self._url: Optional[str] = None
        self._lines = None
        self._langs = None
        self._contacts: Optional[List[str]] = None
        self.check()

    def check(self):
        self.retrieve()

    def _add_error(self, code: str, message: str, line_no: Optional[int] = None):
        if line_no is not None:
            line_no += 1
        err_dict = {"code": code, "message": message, "line": line_no}
        self._errors.append(err_dict)

    def _get_str(self, content: bytes):
        try:
            return content.decode()
        except UnicodeError:
            self._add_error("utf8", "Content is not utf-8 encoded", None)
        return content.decode(errors="replace")

    def retrieve(self):
        for path in [".well-known/security.txt", "security.txt"]:
            url = urlunsplit(("https", self._netloc, path, "", ""))
            try:
                print("yes")
                resp = requests.get(url, timeout=5)
                print("yes")
            except requests.ConnectionError:
                continue
            if resp.status_code == 200:
                self._path = path
                self._url = url
                if path != self.CORRECT_PATH:
                    self._add_error(
                        "location", "Security.txt must be located at .well-known/security.txt")
                p = Parser(self._get_str(resp.content), url)
                self._errors.extend(p._errors)
                self._warnings.extend(p._warnings)
                self._recommendations.extend(p._recommendations)
                self._lines = p._line_info
                self._langs = p._langs
                self._contacts = p._values["contact"] or None
                break
        else:
            self._add_error("no_security_txt", "Can not locate security.txt")

    def is_valid(self):
        return not self._errors

    @property
    def errors(self):
        return self._errors

    @property
    def recommendations(self):
        return self._recommendations

    @property
    def warnings(self):
        return self._warnings

    @property
    def lines(self):
        return self._lines

    @property
    def resolved_url(self) -> Optional[str]:
        return self._url

    @property
    def contacts(self):
        return self._contacts

    @property
    def contacts(self):
        return self._contacts

    @property
    def preferred_languages(self) -> Union[List[str], None]:
        return self._langs
