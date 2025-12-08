import time

class AccountLockoutManager:

    # manage account lockout based on failed login attempts
    # if there are more than max_attempts failed attempts within lockout_window seconds,
    # the account is locked for lockout_duration seconds

    def __init__(self, max_failed_attempts, lockout_seconds):
        self.max_failed_attempts = max_failed_attempts # amount of failed attempts before lockout
        self.lockout_duration = lockout_seconds # duration of lockout in seconds
       
        # key -> {
        #   "failed_attempts": number of failed attempts,
        #   "lockout_until": until when the account is locked (timestamp)}
        self._state = {} 
    
    def _get_records(self, key):
        # initialize records for key if not present
        # if key present, return its records
        if key not in self._state:
            self._state[key] = {
                "failed_attempts": 0,
                "locked_until": 0
            }
        return self._state[key]
    
    def is_locked(self, key):
        # check if account is currently locked
        record = self._get_records(key)
        current_time = time.time()
        
        if record["locked_until"] > current_time:
            return True
        
        # if locked period has passed, reset failed attempts
        if record["locked_until"] != 0 and record["locked_until"] <= current_time:
            record["locked_until"] = 0
            record["failed_attempts"] = 0

        return False
    

    def register_failure(self, key):
        # register a failed login attempt for the given key
        record = self._get_records(key)
        current_time = time.time()
        
        record["failed_attempts"] += 1
        
        if record["failed_attempts"] >= self.max_failed_attempts:
            record["locked_until"] = current_time + self.lockout_duration
            
    def register_success(self, key):

        record = self._get_records(key)
        record["failed_attempts"] = 0
        record["locked_until"] = 0

    def get_remaining_lock_time(self, key):
        # return remaining lockout time in seconds, or 0 if not locked
        record = self._get_records(key)
        current_time = time.time()
        
        if record["locked_until"] > current_time:
            return record["locked_until"] - current_time
        return 0