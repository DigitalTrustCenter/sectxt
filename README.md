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
>>> s.warnings
[{'code': 'long_expiry', 'message': 'Expiry date is more than one year in the future', 'line': 3}]
```

The "errors" and "warnings" attribute return a list of entries. An entry is
a dict with three keys

| key     | value                                                                                                      |
|---------|------------------------------------------------------------------------------------------------------------|
| code    | A fixed error code string                                                                                  |
| message | A human readable error message in English                                                                  |
| line    | The 1 based integer line number where the error occurred or None when the error applies to the entire file |

## Possible erors

| code              | message                                                            |
|-------------------|--------------------------------------------------------------------|
| "no_expire"       | "The Expires field is missing"                                     |
| "multi_expire"    | "Expires field must appear only once"                              |
| "invalid_expiry"  | "Expiry date is invalid"                                           |
| "no_canonical"    | "URL does not match with canonical URLs"                           |
| "no_contact"      | "Contact field must appear at least once"                          |
| "prec_ws"         | "There should be no whitespace before the field separator (colon)" |
| "empty_key"       | "Key can not be empty"                                             | 
| "no_space"        | "The field separator (colon) must be followed by a space"          |
| "empty_value"     | "Value can not be empty"                                           |
| "no_uri"          | "The field value must be an URI"                                   |
| "no_https"        | "A web URI must be https"                                          |
| "utf8"            | "Content is not utf-8 encoded"                                     |
| "location"        | "Security.txt must be located at .well-known/security.txt"         |
| "no_security_txt" | "Can not locate security.txt"                                      |
| "multi_lang"      | "Multiple Preferred-Languages lines is not allowed"                |

## Possible warnings

| code          | message                                            |
|---------------|----------------------------------------------------|
| "long_expiry" | "Expiry date is more than one year in the future", |
