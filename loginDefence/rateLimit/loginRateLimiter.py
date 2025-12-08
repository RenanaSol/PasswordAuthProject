from collections import defaultdict
from loginDefence.rateLimit.tokenBucket import TokenBucket


# manages multiple token buckets for different keys (IP addresses)
class LoginRateLimiter:
    def __init__(self, capacity = 0.5 , refill_rate = 5.0/60):
        self.capacity = capacity #max tokens
        self.refill_rate = refill_rate #tokens added per second
        self._buckets = defaultdict(self._create_bucket) #buckets per key


    def _create_bucket(self):
        return TokenBucket(self.capacity, self.refill_rate) # create a new full token bucket
    
    def allow(self, key, cost = 1.0):
        # check if action is allowed for the given key
        bucket = self._buckets[key]
        return bucket.allow(cost)