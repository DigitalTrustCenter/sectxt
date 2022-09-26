# SecTXT: Security.txt parser and validator

This package contains a security.txt (RFC 9116) parser and validator.

Usage:

```python

>>> from sectxt import SecurityTXT
>>> s = SecurityTXT("www.example.com")
>>> s.is_valid()
True

```

# Validation

```python

>>> from sectxt import SecurityTXT
>>> s = SecurityTXT("www.example.com")
>>> s.errors
[{'code': 'no_uri', 'message': 'The field value must be an URI', 'line': 2}, {'code': 'no_expire', 'message': 'The Expires field is missing', 'line': None}]
>>> s.recommendations
[{'code': 'long_expiry', 'message': 'Expiry date is more than one year in the future', 'line': 3}]
```

The "errors" and "recommendations" attribute return a list of entries. An entry is
a dict with three keys

| key     | value                                                                                                      |
|---------|------------------------------------------------------------------------------------------------------------|
| code    | A fixed error code string                                                                                  |
| message | A human readable error message in English                                                                  |
| line    | The 1 based integer line number where the error occurred or None when the error applies to the entire file |

## Possible errors

| code                 | message                                                                |
|----------------------|------------------------------------------------------------------------|
| "no_expire"          | "Expires field is missing."                                            |
| "multi_expire"       | "Expires field must appear only once."                                 |
| "expired"            | "Expiry date has passed."                                              |
| "invalid_expiry"     | "Date in Expires field is invalid."                                    |
| "no_canonical_match" | "URL does not match with canonical URLs."                              |
| "no_contact"         | "Contact field must appear at least once."                             |
| "prec_ws"            | "There must be no whitespace before the field separator (colon)."      |
| "empty_key"          | "Field key can not be empty."                                          | 
| "no_space"           | "The field separator (colon) must be followed by a space."             |
| "empty_value"        | "Field value can not be empty."                                        |
| "no_uri"             | "Field value must be an URI."                                          |
| "no_https"           | "A web URI must be https."                                             |
| "utf8"               | "Content is not utf-8 encoded."                                        |
| "location"           | "Security.txt must be located at .well-known/security.txt."            |
| "no_security_txt"    | "Can not locate security.txt."                                         |
| "multi_lang"         | "Multiple Preferred-Languages lines are not allowed."                  |
| "invalid_line"       | "No key and value found."                                              |
| "invalid_cert"       | "Invalid certificate.                                                  |
| "no_content_type"    | "Missing HTTP content-type header."                                    |
| "invalid_media"      | "Media type in content-type header must be 'text/plain'.               |
| "invalid_charset"    | "Charset parameter in content-type header must be 'utf-8' if present." |


## Possible recommendations

| code             | message                                                    |
|------------------|------------------------------------------------------------|
| "long_expiry"    | "Expiry date is more than one year in the future."         |
| "no_encryption"  | "Contact missing encryption key for email communication.", |
| "not_signed"     | "The contents should be digitally signed."                 |
| "no_canonical"   | "Canonical field should be present in a signed file."      |
