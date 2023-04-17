# SecTXT: Security.txt parser and validator

This package contains a security.txt ([RFC 9116](https://www.rfc-editor.org/info/rfc9116)) parser and validator.

When security risks in web services are discovered by independent security researchers who understand the severity of the risk, they often lack the channels to disclose them properly. As a result, security issues may be left unreported. security.txt defines a standard to help organizations define the process for security researchers to disclose security vulnerabilities securely.

## Installation

The package is available on pypi. It can be installed using pip:

```console
> python -m pip install sectxt
```

## Usage

```python

>>> from sectxt import SecurityTXT
>>> s = SecurityTXT("www.example.com")
>>> s.is_valid()
True

```

## Validation

```python

>>> from sectxt import SecurityTXT
>>> s = SecurityTXT("www.example.com")
>>> s.errors
[{'code': 'no_uri', 'message': 'The field value must be an URI', 'line': 2}, {'code': 'no_expire', 'message': 'The Expires field is missing', 'line': None}]
>>> s.recommendations
[{'code': 'long_expiry', 'message': 'Expiry date is more than one year in the future', 'line': 3}]
```

The "errors", "recommendations" and "notifications" attribute return a list of entries. An entry is
a dict with three keys:

| key     | value                                                                                                      |
|---------|------------------------------------------------------------------------------------------------------------|
| code    | A fixed error code string                                                                                  |
| message | A human readable error message in English                                                                  |
| line    | The 1 based integer line number where the error occurred or None when the error applies to the entire file |

### Possible errors

| code                  | message                                                                                                                                                                |
|-----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| "no_security_txt"     | "security.txt could not be located."                                                                                                                                   |
| "location"            | "security.txt was located on the top-level path (legacy place), but must be placed under the '/.well-known/' path."                                                    |
| "invalid_uri_scheme"  | "Insecure URI scheme HTTP is not allowed. The security.txt file access must use the HTTPS scheme"                                                                      |
| "invalid_cert"        | "security.txt must be served with a valid TLS certificate."                                                                                                            |
| "no_content_type"     | "HTTP Content-Type header must be sent."                                                                                                                               |
| "invalid_media"       | "Media type in Content-Type header must be 'text/plain'."                                                                                                              |
| "invalid_charset"     | "Charset parameter in Content-Type header must be 'utf-8' if present."                                                                                                 |
| "utf8"                | "Content must be utf-8 encoded."                                                                                                                                       |
| "no_expire"           | "'Expires' field must be present."                                                                                                                                     |
| "multi_expire"        | "'Expires' field must not appear more than once."                                                                                                                      |
| "invalid_expiry"      | "Date and time in 'Expires' field must be formatted according to ISO 8601."                                                                                            | 
| "expired"             | "Date and time in 'Expires' field must not be in the past."                                                                                                            |
| "no_contact"          | "'Contact' field must appear at least once."                                                                                                                           |
| "no_canonical_match"  | "Web URI where security.txt is located must match with a 'Canonical' field. In case of redirecting either the first or last web URI of the redirect chain must match." |
| "multi_lang"          | "'Preferred-Languages' field must not appear more than once."                                                                                                          |
| "invalid_lang"        | "Value in 'Preferred-Languages' field must match one or more language tags as defined in RFC5646, separated by commas."                                                |
| "no_uri"              | "Field value must be a URI (e.g. beginning with 'mailto:')."                                                                                                           |
| "no_https"            | "Web URI must begin with 'https://'."                                                                                                                                  |
| "prec_ws"             | "There must be no whitespace before the field separator (colon)."                                                                                                      |
| "no_space"            | "Field separator (colon) must be followed by a space."                                                                                                                 | 
| "empty_key"           | "Field name must not be empty."                                                                                                                                        |
| "empty_value"         | "Field value must not be empty."                                                                                                                                       |
| "invalid_line"        | "Line must contain a field name and value, unless the line is blank or contains a comment."                                                                            |
| "no_line_separators"  | "Every line must end with either a carriage return and line feed characters or just a line feed character"                                                             |
| "signed_format_issue" | "Signed security.txt must start with the header '-----BEGIN PGP SIGNED MESSAGE-----'. "                                                                                |
| "data_after_sig"      | "Signed security.txt must not contain data after the signature."                                                                                                       |
| "no_csaf_file"        | "All CSAF fields must point to a provider-metadata.json file."                                                                                                         |


### Possible recommendations

| code                       | message                                                                                        |
|----------------------------|------------------------------------------------------------------------------------------------|
| "long_expiry"              | "Date and time in 'Expires' field should be less than a year into the future."                 |
| "no_encryption"            | "'Encryption' field should be present when 'Contact' field contains an email address."         |
| "not_signed"<sup>[1]</sup> | "security.txt should be digitally signed."                                                     |
| "no_canonical"             | "'Canonical' field should be present in a signed file."                                        |
| "multiple_csaf_fields"     | "It is allowed to have more than one CSAF field, however this should be removed if possible."  |

### Possible notifications

| code                          | message                                                                                                                                                                     |
|-------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| "unknown_field"<sup>[2]</sup> | "Security.txt contains an unknown field. Field {unknown_field} is either a custom field which may not be widely supported, or there is a typo in a standardised field name. |


---

[1] The security.txt parser will check for the addition of the digital signature, but it will not verify the validity of the signature.

[2] Regarding code "unknown_field": According to RFC 9116 section 2.4, any fields that are not explicitly supported must be ignored. This parser does add a notification for unknown fields by default. This behaviour can be turned off using the parameter recommend_unknown_fields:
```python

>>> from sectxt import SecurityTXT
>>> s = SecurityTXT("www.example.com", recommend_unknown_fields=False)
```
