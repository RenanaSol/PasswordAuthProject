import time
from collections import defaultdict, deque

class TokenBucket:
    def __init__(self,capacity ,refill_rate):
        self.capacity = float(capacity) #max tokens in the bucket
        self.tokens = float(capacity) #current tokens in the bucket
        self.refill_rate = float(refill_rate) #amount of tokens added per second
        self.last_refill = time.time() #when the bucket was last refilled

    def _refill(self):
        # calculate how much time has passed since last refill
        # and add tokens accordingly
        # add tokens up to the capacity

        # check how much time has passed since last refill
        now = time.time()
        elapsed = now - self.last_refill

        if elapsed <= 0: # if no time has passed, nothing to refill
            return  
        
        # calculate how many tokens to add based on elapsed time
        added_tokens = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + added_tokens)
        self.last_refill = now

    def allow(self, cost=1.0):
        # try to consume tokens for an action
        # if allowed - return True, else False
        self._refill()

        if self.tokens >= cost: # if there are enough tokens - take one and return True
            self.tokens -= cost
            return True
        else:
            return False # not enough tokens - return False and blocked action