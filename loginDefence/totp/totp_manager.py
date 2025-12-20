import time
import pyotp

class TOTPManager:
    def __init__(self, interval=30, digits=6):
        self.interval = interval  # TOTP time-step length in seconds 
        self.digits = digits # Number of digits in the generated TOTP code

    def verify(self, secret, token, server_time=None , valid_window=1):

        if server_time is None: # If no server_time provided, use current server time
            server_time = time.time()

        # Create a TOTP generator using the shared secret and configuration
        totp = pyotp.TOTP(secret, interval=self.interval, digits=self.digits)

        # Verify the token against the provided time
        # valid_window allows accepting neighboring time-steps
        return totp.verify(token, for_time=server_time, valid_window=valid_window)
    
    def estimate_offset_seconds(self, secret, token, server_time=None, max_abs_drift=120):

        if server_time is None: # If no server_time provided, use current server time
            server_time = time.time()

        # Create a TOTP generator using the shared secret and configuration
        totp = pyotp.TOTP(secret, interval=self.interval, digits=self.digits)

        # Search for a time offset (in seconds) that makes the token valid
        for delta in range(0, max_abs_drift + 1):
            for sign in (1, -1) if delta != 0 else (1,):
                offset = sign * delta
                candidate_time = server_time + offset # Candidate time is the server time shifted by the offset

                # valid_window=0 means the token must match exactly this time-step
                if totp.verify(token, for_time=candidate_time, valid_window=0):
                    return offset
        
         # If no matching offset was found within the allowed drift range
        return None