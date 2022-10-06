#
# SPDX-License-Identifier: EUPL-1.2
#

from cgi import parse_header
from collections import defaultdict
from datetime import datetime, timezone
import re
from typing import Optional, Union, List, DefaultDict
import sys
from urllib.parse import urlsplit, urlunsplit
import langcodes

if sys.version_info < (3, 8):
    from typing_extensions import TypedDict
else:
    from typing import TypedDict

import dateutil.parser
import requests


__version__ = "0.5"

s = requests.Session()


class ErrorDict(TypedDict):
    code: str
    message: str
    line: Optional[int]


class LineDict(TypedDict):
    type: str
    field_name: Optional[str]
    value: str


def strlist_from_arg(
        arg: Union[str, List[str], None]) -> Union[List[str], None]:
    if isinstance(arg, str):
        return [arg]
    return arg


PREFERRED_LANGUAGES = "preferred-languages"


class Parser:
    iso8601_re = re.compile(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[-+]\d{2}:\d{2})$",
        re.IGNORECASE | re.ASCII)

    uri_fields = [
        "acknowledgments", "canonical", "contact", "encryption", "hiring",
        "policy"]
        
    known_fields = uri_fields + [PREFERRED_LANGUAGES, "expires"]

    def __init__(
            self,
            content: str,
            urls: Optional[str] = None,
            recommend_unknown_fields: bool = True,
    ):
        self._urls = strlist_from_arg(urls)
        self._line_info: List[LineDict] = []
        self._errors: List[ErrorDict] = []
        self._recommendations: List[ErrorDict] = []
        self._values: DefaultDict[str, List[str]] = defaultdict(list)
        self._langs: Optional[List[str]] = None
        self._signed = False
        self._reading_sig = False
        self._finished_sig = False
        self._content = content
        self.recommend_unknown_fields = recommend_unknown_fields
        self._line_no: Optional[int] = None
        self._process()

    def _process(self) -> None:
        lines = self._content.split("\n")
        self._line_no = 1
        for line in lines:
            self._line_info.append(self._parse_line(line))
            self._line_no += 1
        self._line_no = None
        if self._line_info and self._line_info[-1]["type"] == "empty":
            del self._line_info[-1]
        self.validate_contents()

    def _add_error(
            self,
            code: str,
            message: str,
    ) -> None:
        err_dict: ErrorDict = {
            "code": code, "message": message, "line": self._line_no}
        self._errors.append(err_dict)

    def _add_recommendation(
            self,
            code: str,
            message: str,
    ) -> None:
        err_dict: ErrorDict = {
            "code": code, "message": message, "line": self._line_no}
        self._recommendations.append(err_dict)

    def _parse_line(self, line: str) -> LineDict:
        line = line.rstrip()

        if self._reading_sig:
            if line == "-----END PGP SIGNATURE-----":
                self._reading_sig = False
                self._finished_sig = True
            return {"type": "pgp_envelope", "field_name": None, "value": line}

        if line and self._finished_sig:
            self._add_error("data_after_sig", "Data exists after signature")
            return {"type": "error", "field_name": None, "value": line}

        # signed content might be dash escaped
        if self._signed and not self._reading_sig and line.startswith("- "):
            line = line[2:]

        if line == "-----BEGIN PGP SIGNED MESSAGE-----" and self._line_no == 1:
            self._signed = True
            return {"type": "pgp_envelope", "field_name": None, "value": line}

        if line == "-----BEGIN PGP SIGNATURE-----" and self._signed:
            self._reading_sig = True
            return {"type": "pgp_envelope", "field_name": None, "value": line}

        if line.startswith("#"):
            return {"type": "comment", "value": line, "field_name": None}

        if ":" in line:
            return self._parse_field(line)

        if line:
            self._add_error(
                "invalid_line", 
                "Line must contain a field name and value, "
                "unless the line is blank or contains a comment.")
            return {"type": "error", "value": line, "field_name": None}

        return {"type": "empty", "value": "", "field_name": None}

    def _parse_field(self, line: str) -> LineDict:
        key, value = line.split(":", 1)
        key = key.lower()
        if key.rstrip() != key:
            self._add_error(
                "prec_ws",
                "There must be no whitespace before the field separator "
                "(colon).")
            key = key.rstrip()

        if value:
            if value[0] != " ":
                self._add_error(
                    "no_space",
                    "Field separator (colon) must be followed by a space.")
            value = value.lstrip()

        if key == "hash" and self._signed:
            return {"type": "pgp_envelope", "field_name": None, "value": line}

        if not key:
            self._add_error("empty_key", "Field name must not be empty.")
            return {"type": "error", "value": line, "field_name": None}

        if not value:
            self._add_error(
                "empty_value", "Field value must not be empty.")
            return {"type": "error", "value": line, "field_name": None}

        if key in self.uri_fields:
            url_parts = urlsplit(value)
            if url_parts.scheme == "":
                self._add_error(
                    "no_uri", "Field value must be a URI "
                    "(e.g. beginning with 'mailto:').")
            elif url_parts.scheme == "http":
                self._add_error(
                    "no_https", 
                    "Web URI must begin with 'https://'.")
        elif key == "expires":
            self._parse_expires(value)
        elif key == PREFERRED_LANGUAGES:
            self._langs = [v.strip() for v in value.split(",")]
                
            # Check if all the languages are valid according to RFC5646.
            for lang in self._langs:
                if not langcodes.tag_is_valid(lang):
                    self._add_error(
                        "invalid_lang",
                        "Value in 'Preferred-Languages' field must match one "
                        "or more language tags as defined in RFC5646, "
                        "separated by commas.")
            
        if self.recommend_unknown_fields and not key in self.known_fields:
            self._add_recommendation(
                "unknown_field",
                f"Unknown field name '{key}'. "
                "Permitted, but not syntax checked and probably "
                "widely unsupported.")
        
        self._values[key].append(value)
        return {"type": "field", "field_name": key, "value": value}

    def _parse_expires(self, value: str) -> None:
        try:
            date_value = dateutil.parser.parse(value)
        except dateutil.parser.ParserError:
            self._add_error(
                "invalid_expiry", 
                "Date and time in 'Expires' field must be formatted "
                "according to ISO 8601.")
        else:
            self._expires_date = date_value
            if not self.iso8601_re.match(value):
                # dateutil parses more than just iso8601 format
                self._add_error(
                    "invalid_expiry", 
                    "Date and time in 'Expires' field must be formatted "
                    "according to ISO 8601.")
            now = datetime.now(timezone.utc)
            max_value = now.replace(year=now.year + 1)
            if date_value > max_value:
                self._add_recommendation(
                    "long_expiry",
                    "Date and time in 'Expires' field should be less than "
                    "a year into the future.")
            elif date_value < now:
                self._add_error(
                    "expired", 
                    "Date and time in 'Expires' field must not be in "
                    "the past.")

    def validate_contents(self) -> None:
        if "expires" not in self._values:
            self._add_error("no_expire", "'Expires' field must be present.")
        elif len(self._values["expires"]) > 1:
            self._add_error(
                "multi_expire", "'Expires' field must not appear more "
                "than once.")
        if self._urls and "canonical" in self._values:
            if all(url not in self._values["canonical"] for url in self._urls):
                self._add_error(
                    "no_canonical_match",
                    "Web URI where security.txt is located must match with a "
                    "'Canonical' field. In case of redirecting either the "
                    "first or last web URI of the redirect chain must match.")
        if "contact" not in self._values:
            self._add_error(
                "no_contact", "'Contact' field must appear at least once.")
        else:
            if (any(v.startswith("mailto:") for v in self._values['contact'])
                    and "encryption" not in self._values):
                self._add_recommendation(
                    "no_encryption",
                    "'Encryption' field should be present when 'Contact' "
                    "field contains an email address.")
        if PREFERRED_LANGUAGES in self._values:
            if len(self._values[PREFERRED_LANGUAGES]) > 1:
                self._add_error(
                    "multi_lang",
                    "'Preferred-Languages' field must not appear more "
                    "than once.")

        if not self._signed:
            self._add_recommendation(
                "not_signed", "File should be digitally signed.")
        if self._signed and not self._values.get("canonical"):
            self._add_recommendation(
                "no_canonical",
                "'Canonical' field should be present in a signed file.")

    def is_valid(self) -> bool:
        return not self._errors

    @property
    def errors(self) -> List[ErrorDict]:
        return self._errors

    @property
    def recommendations(self) -> List[ErrorDict]:
        return self._recommendations

    @property
    def lines(self) -> List[LineDict]:
        return self._line_info

    @property
    def preferred_languages(self) -> Union[List[str], None]:
        if PREFERRED_LANGUAGES in self._values:
            return [
                v.strip() for v in
                self._values[PREFERRED_LANGUAGES][0].split(",")]
        return None

    @property
    def contact_email(self) -> Union[None, str]:
        if "contact" in self._values:
            for value in self._values["contact"]:
                if value.startswith("mailto:"):
                    return value[7:]
                if ":" not in value and "@" in value:
                    return value
        return None

    @property
    def resolved_url(self) -> Optional[str]:
        if self._urls:
            return self._urls[-1]
        return None


CORRECT_PATH = ".well-known/security.txt"


class SecurityTXT(Parser):

    def __init__(self, url: str, recommend_unknown_fields: bool = True):
        url_parts = urlsplit(url)
        if url_parts.scheme:
            if not url_parts.netloc:
                raise ValueError("Invalid URL")
            netloc = url_parts.netloc
        else:
            netloc = url
        self._netloc = netloc
        self._path: Optional[str] = None
        self._url: Optional[str] = None
        super().__init__('', recommend_unknown_fields=recommend_unknown_fields)

    def _get_str(self, content: bytes) -> str:
        try:
            return content.decode()
        except UnicodeError:
            self._add_error("utf8", "Content must be utf-8 encoded.")
        return content.decode(errors="replace")

    def _process(self) -> None:
        for path in [".well-known/security.txt", "security.txt"]:
            url = urlunsplit(("https", self._netloc, path, None, None))
            try:
                resp = requests.get(url, timeout=5)
            except requests.exceptions.SSLError:
                self._add_error("invalid_cert", "Security.txt must be "
                    "served with a valid TLS certificate.")
                try:
                    resp = requests.get(url, timeout=5, verify=False)
                except:
                    continue
            except:
                continue
            if resp.status_code == 200:
                self._path = path
                self._url = url
                if path != CORRECT_PATH:
                    self._add_error(
                        "location",
                        "Security.txt was located on the top-level path "
                        "(legacy place), but must be placed under "
                        "the '/.well-known/' path.")
                if 'content-type' not in resp.headers:
                    self._add_error(
                        "no_content_type",
                        "HTTP Content-Type header must be sent.")
                else:
                    media_type, params = parse_header(
                        resp.headers["content-type"])
                    if media_type.lower() != "text/plain":
                        self._add_error(
                            "invalid_media",
                            "Media type in Content-Type header must be "
                            "'text/plain'.",
                        )
                    charset = params.get('charset', "utf-8").lower()
                    if charset != "utf-8" and charset != "csutf8":
                        # According to RFC9116, charset default is utf-8
                        self._add_error(
                            "invalid_charset",
                            "Charset parameter in Content-Type header must be "
                            "'utf-8' if present.",
                        )
                self._content = self._get_str(resp.content)
                if resp.history:
                    self._urls = [resp.history[0].url, resp.url]
                else:
                    self._urls = [url]
                super()._process()
                break
        else:
            self._add_error("no_security_txt", "Security.txt could not be located.")
