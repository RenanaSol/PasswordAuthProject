import time
import secrets

class CaptchaManager:
    def __init__(self, threshold=3, token_ttl_seconds=120):
        self.threshold = threshold
        self.failed_attempts = {}
        self.valid_tokens = {}
        self.token_ttl_seconds = token_ttl_seconds  

    def register_failure(self, key):
        self.failed_attempts[key] = self.failed_attempts.get(key, 0) + 1
        return self.is_captcha_required(key)

    def is_captcha_required(self, key):
        return self.failed_attempts.get(key, 0) >= self.threshold
    
    def reset(self, key):
        self.failed_attempts.pop(key, None)

    def issue_token(self) -> str:
        """Create a one-time CAPTCHA token with TTL."""
        self._cleanup_expired_tokens()
        token = secrets.token_urlsafe(24)
        self.valid_tokens[token] = time.time() + self.token_ttl_seconds
        return token

    def validate_token(self, token: str) -> bool:
        """Check token exists and not expired (does NOT consume)."""
        self._cleanup_expired_tokens()
        exp = self.valid_tokens.get(token)
        return exp is not None and exp >= time.time()

    def consume_token(self, token: str) -> bool:
        """Validate + consume (one-time use)."""
        if not self.validate_token(token):
            return False
        self.valid_tokens.pop(token, None)
        return True

    def _cleanup_expired_tokens(self):
        now = time.time()
        expired = [t for t, exp in self.valid_tokens.items() if exp < now]
        for t in expired:
            self.valid_tokens.pop(t, None)
