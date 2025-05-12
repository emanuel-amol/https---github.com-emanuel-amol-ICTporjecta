import jwt
import os
from datetime import datetime, timedelta
from security_protocols.monitoring.logger import log_activity

def generate_jwt(user_id, role, mfa_verified=False):
    payload = {
        "sub": user_id,
        "role": role,
        "mfa_verified": mfa_verified,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1),
        "aud": "authenticated"
    }
    secret = os.environ.get("JWT_SECRET")
    token = jwt.encode(payload, secret, algorithm="HS256")

    from security_protocols.monitoring.logger import log_activity

    return token
