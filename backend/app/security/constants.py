"""
Security-related constants.

Only fixed, non-configurable values live here (token type labels, claim
names). Anything environment-dependent (secret key, algorithm, expiry)
belongs in config/settings.py and is passed into these helpers as arguments.
"""

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"
TOKEN_TYPE_PASSWORD_RESET = "password_reset"

CLAIM_SUBJECT = "sub"
CLAIM_TOKEN_TYPE = "type"
CLAIM_EXPIRES_AT = "exp"
CLAIM_ISSUED_AT = "iat"
CLAIM_JTI = "jti"
