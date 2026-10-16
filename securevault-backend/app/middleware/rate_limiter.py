import time
import logging
from fastapi import Request, HTTPException, status
import redis.asyncio as aioredis
from app.config import settings

logger = logging.getLogger("securevault.rate_limiter")

redis_client = None
redis_disabled = False

def get_redis():
    global redis_client, redis_disabled
    if redis_disabled:
        return None
    if redis_client is None and settings.REDIS_URL:
        try:
            redis_client = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=0.2,
                socket_timeout=0.2
            )
        except Exception as err:
            logger.warning(f"Could not connect to Redis at {settings.REDIS_URL}: {err}")
            redis_disabled = True
            redis_client = None
    return redis_client

# In-memory sliding window fallback for standalone development without Redis
in_memory_window = {}

async def check_rate_limit(request: Request):
    client_ip = "127.0.0.1"
    if request.client and request.client.host:
        client_ip = request.client.host
    
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()

    key = f"rate_limit:{client_ip}"
    current_time = time.time()
    window_start = current_time - settings.RATE_LIMIT_WINDOW_SECONDS

    r_client = get_redis()
    request_count = 0
    redis_success = False

    if r_client:
        try:
            async with r_client.pipeline(transaction=True) as pipe:
                pipe.zremrangebyscore(key, 0, window_start)
                pipe.zcard(key)
                pipe.zadd(key, {str(current_time): current_time})
                pipe.expire(key, settings.RATE_LIMIT_WINDOW_SECONDS)
                results = await pipe.execute()
                request_count = results[1]
                redis_success = True
        except Exception as e:
            logger.warning(f"Redis pipeline rate limiter exception (falling back to memory): {e}")
            redis_disabled = True
            redis_success = False

    if not redis_success:
        timestamps = in_memory_window.get(key, [])
        timestamps = [t for t in timestamps if t > window_start]
        timestamps.append(current_time)
        in_memory_window[key] = timestamps
        request_count = len(timestamps)

    if request_count >= settings.RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Security Copilot quota exceeded. Please wait before sending more prompts."
        )
