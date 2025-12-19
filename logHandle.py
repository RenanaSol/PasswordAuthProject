import logging
import json
from datetime import datetime

log_file = "attempts.log"
logger = logging.getLogger("login_logger")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(log_file)
handler.setLevel(logging.INFO)
logger.addHandler(handler)

def log_login_attempt(username, result, latency_ms, has_pepper, hash_mode, protection_flag, group_seed ):

    entry = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "result": result,
        "latency_ms": latency_ms,
        "has_pepper": has_pepper,
        "hash_mode": hash_mode,
        "protection_flag": protection_flag,
        "group_seed": group_seed
    }
    logger.info(json.dumps(entry))
