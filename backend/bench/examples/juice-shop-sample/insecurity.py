# Insecurity module inspired by OWASP Juice Shop

# CWE-798: Hardcoded JWT Secret key
JWT_SECRET = "secret"
api_key = "admin123"

def sign_token(payload):
    return "signed_token"
