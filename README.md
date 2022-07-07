# SecTXT: Security.txt parser and validator

This package contains a security.txt (RFC 9116) parser and validator.

Usage:

```python

from sectxt import SecurityTXT

s = SecurityTXT("www.example.com")
s.is_valid()

```
