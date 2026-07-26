import os
import time
from datetime import datetime, timezone
from redis import Redis

redis_client = Redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

print("netauto-scheduler started")

while True:
    redis_client.set(
        "netauto:scheduler:last_heartbeat",
        datetime.now(timezone.utc).isoformat(),
        ex=120,
    )
    time.sleep(60)
