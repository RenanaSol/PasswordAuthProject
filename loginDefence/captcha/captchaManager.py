# loginDefence/captcha/captchaManager.py
import time

class CaptchaManager:
    def __init__(self, threshold=3):
        self.threshold = threshold
        self.failed_attempts_captcha = {}  

    def register_failure(self, key):
        self.failed_attempts[key] = self.failed_attempts.get(key, 0) + 1

    def is_captcha_required(self, key):
        return self.failed_attempts.get(key, 0) >= self.threshold

    def reset(self, key):
        self.failed_attempts.pop(key, None)
