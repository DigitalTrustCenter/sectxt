# SecTXT: Security.txt parser and validator

This package contains a security.txt (RFC 9116) parser and validator.

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

The "errors" and "recommendations" attribute return a list of entries. An entry is
a dict with three keys:

| key     | value                                                                                                      |
|---------|------------------------------------------------------------------------------------------------------------|
| code    | A fixed error code string                                                                                  |
| message | A human readable error message in English                                                                  |
| line    | The 1 based integer line number where the error occurred or None when the error applies to the entire file |

### Possible errors

| code                 | message                                                                                                                 |
|----------------------|-------------------------------------------------------------------------------------------------------------------------|
| "no_security_txt"    | "Security.txt could not be located."                                                                                    |
| "location"           | "Security.txt was located on the top-level path (legacy place), but must be placed under the '/.well-known/' path."     |
| "invalid_cert"       | "Security.txt must be served with a valid TLS certificate."                                                             |
| "no_content_type"    | "HTTP Content-Type header must be sent."                                                                                |
| "invalid_media"      | "Media type in Content-Type header must be 'text/plain'."                                                               |
| "invalid_charset"    | "Charset parameter in Content-Type header must be 'utf-8' if present."                                                  |
| "utf8"               | "Content must be utf-8 encoded."                                                                                        |
| "no_expire"          | "'Expires' field must be present."                                                                                      |
| "multi_expire"       | "'Expires' field must not appear more than once."                                                                       |
| "invalid_expiry"     | "Date and time in 'Expires' field must be formatted according to ISO 8601."                                             | 
| "expired"            | "Date and time in 'Expires' field must not be in the past."                                                             |
| "no_contact"         | "'Contact' field must appear at least once."                                                                            |
| "no_canonical_match" | "Web URI where security.txt is located must match with a 'Canonical' field. In case of redirecting either the first or last web URI of the redirect chain must match." |
| "multi_lang"         | "'Preferred-Languages' field must not appear more than once."                                                           |
| "invalid_lang"       | "Value in 'Preferred-Languages' field must match one or more language tags as defined in RFC5646, separated by commas." |
| "no_uri"             | "Field value must be a URI (e.g. beginning with 'mailto:')."                                                            |
| "no_https"           | "Web URI must begin with 'https://'."                                                                                   |
| "prec_ws"            | "There must be no whitespace before the field separator (colon)."                                                       |
| "no_space"           | "Field separator (colon) must be followed by a space."                                                                  | 
| "empty_key"          | "Field name must not be empty."                                                                                         |
| "empty_value"        | "Field value must not be empty."                                                                                        |
| "invalid_line"       | "Line must contain a field name and value, unless the line is blank or contains a comment."                             |

### Possible recommendations

| code             | message                                                                                                  |
|------------------|----------------------------------------------------------------------------------------------------------|
| "long_expiry"    | "Date and time in 'Expires' field should be less than a year into the future."                           |
| "no_encryption"  | "'Encryption' field should be present when 'Contact' field contains an email address."                   |
| "not_signed"     | "File should be digitally signed."                                                                       |
| "no_canonical"   | "'Canonical' field should be present in a signed file."                                                  |
| "unknown_field"  | "Unknown field name '{name}'. Permitted, but not syntax checked and probably widely unsupported."        |

According to RFC 9116 section 2.4, any fields that are not explicitly supported should be ignored. This parser does add a recommendation for unknown fields by default. This behaviour can be turned off using the parameter recommend_unknown_fields:
```python

>>> from sectxt import SecurityTXT
>>> s = SecurityTXT("www.example.com", recommend_unknown_fields=False)
```
