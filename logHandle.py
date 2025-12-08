import logging
import json
from datetime import datetime

log_file = "attempts.log"
logger = logging.getLogger("login_logger")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(log_file)
handler.setLevel(logging.INFO)
logger.addHandler(handler)

def log_login_attempt(username, success, group_seed):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "success": success,
        "group_seed": group_seed
    }
    logger.info(json.dumps(entry))
