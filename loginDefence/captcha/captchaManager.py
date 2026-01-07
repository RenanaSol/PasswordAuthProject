import time
import secrets

class CaptchaManager:
    def __init__(self, threshold=3, token_ttl_seconds=120):
        self.threshold = threshold
        
        self.failed_attempts_per_user = {}

        self.valid_tokens = {}
        self.token_ttl_seconds = token_ttl_seconds  


    def register_failure(self, username: str) -> bool:
        """Register login failure for specific user"""
        self.failed_attempts_per_user[username] = \
            self.failed_attempts_per_user.get(username, 0) + 1
        
        return self.is_captcha_required(username)


    def is_captcha_required(self, username: str) -> bool:
        return self.failed_attempts_per_user.get(username, 0) >= self.threshold


    def reset_user(self, username: str):
        self.failed_attempts_per_user.pop(username, None)


    def issue_token(self) -> str:
        self._cleanup_expired_tokens()
        token = secrets.token_urlsafe(24)
        self.valid_tokens[token] = time.time() + self.token_ttl_seconds
        return token


    def validate_token(self, token: str) -> bool:
        self._cleanup_expired_tokens()
        exp = self.valid_tokens.get(token)
        return exp is not None and exp >= time.time()


    def consume_token(self, token: str) -> bool:
        if not self.validate_token(token):
            return False
        self.valid_tokens.pop(token, None)
        return True


    # ---- ניקוי טוקנים שפג תוקפם ----
    def _cleanup_expired_tokens(self):
        now = time.time()
        expired = [t for t, exp in self.valid_tokens.items() if exp < now]
        for t in expired:
            self.valid_tokens.pop(t, None)
