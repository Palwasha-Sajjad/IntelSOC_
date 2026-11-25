"""Redis-backed authentication rate limiting for IntelSOC."""

import hashlib
import ipaddress

import redis

from app.core.config import get_redis_config


LOGIN_WINDOW_SECONDS = 60
LOGIN_EMAIL_LIMIT = 5
LOGIN_IP_LIMIT = 20


class LoginRateLimitExceeded(Exception):
    """Login attempt limit exceeded."""

    def __init__(self, retry_after):
        self.retry_after = retry_after
        super().__init__("Too many login attempts")


class RateLimitUnavailable(Exception):
    """Authentication rate limiter unavailable."""


RATE_LIMIT_SCRIPT = """
local email_count = redis.call('INCR', KEYS[1])

if email_count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end

local ip_count = redis.call('INCR', KEYS[2])

if ip_count == 1 then
    redis.call('EXPIRE', KEYS[2], ARGV[1])
end

local retry_after = 0

if email_count > tonumber(ARGV[2]) then
    retry_after = math.max(
        retry_after,
        redis.call('TTL', KEYS[1])
    )
end

if ip_count > tonumber(ARGV[3]) then
    retry_after = math.max(
        retry_after,
        redis.call('TTL', KEYS[2])
    )
end

if email_count > tonumber(ARGV[2])
    or ip_count > tonumber(ARGV[3]) then
    return {0, math.max(1, retry_after)}
end

return {1, 0}
"""


def _digest(value):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def enforce_login_rate_limit(*, email, source_ip):
    """Check both account and source IP login attempt limits."""

    normalized_email = email.strip().lower()

    try:
        normalized_ip = str(
            ipaddress.ip_address(source_ip)
        )
    except (ValueError, TypeError):
        normalized_ip = "unknown"

    email_key = (
        "intelsoc:auth:login:email:"
        + _digest(normalized_email)
    )

    ip_key = (
        "intelsoc:auth:login:ip:"
        + _digest(normalized_ip)
    )

    try:
        with redis.Redis(**get_redis_config()) as client:
            allowed, retry_after = client.eval(
                RATE_LIMIT_SCRIPT,
                2,
                email_key,
                ip_key,
                LOGIN_WINDOW_SECONDS,
                LOGIN_EMAIL_LIMIT,
                LOGIN_IP_LIMIT,
            )

    except redis.RedisError as error:
        raise RateLimitUnavailable(
            "Authentication temporarily unavailable"
        ) from error

    if not allowed:
        raise LoginRateLimitExceeded(
            retry_after=int(retry_after)
        )
