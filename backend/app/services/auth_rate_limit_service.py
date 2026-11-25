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

# --------------------------------------------------
# Account provisioning and invitation rate limiting
# --------------------------------------------------

PROVISIONING_WINDOW_SECONDS = 3600
PROVISIONING_ADMIN_LIMIT = 20
INVITATION_ACCOUNT_LIMIT = 5
INVITATION_COOLDOWN_SECONDS = 60


class ProvisioningRateLimitExceeded(Exception):
    """Account provisioning request limit exceeded."""

    def __init__(self, retry_after):
        self.retry_after = retry_after
        super().__init__("Too many provisioning requests")


PROVISIONING_RATE_LIMIT_SCRIPT = """
local retry_after = 0

local admin_count = tonumber(
    redis.call('GET', KEYS[1]) or '0'
)

if ARGV[5] == '1'
    and admin_count >= tonumber(ARGV[2]) then
    retry_after = math.max(
        retry_after,
        redis.call('TTL', KEYS[1]),
        1
    )
end

if #KEYS == 3 then
    local account_count = tonumber(
        redis.call('GET', KEYS[2]) or '0'
    )

    if account_count >= tonumber(ARGV[3]) then
        retry_after = math.max(
            retry_after,
            redis.call('TTL', KEYS[2]),
            1
        )
    end

    if redis.call('EXISTS', KEYS[3]) == 1 then
        retry_after = math.max(
            retry_after,
            redis.call('TTL', KEYS[3]),
            1
        )
    end
end

if retry_after > 0 then
    return {0, retry_after}
end

if ARGV[5] == '1' then
    local new_admin_count = redis.call('INCR', KEYS[1])

    if new_admin_count == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
end

if #KEYS == 3 then
    local new_account_count = redis.call('INCR', KEYS[2])

    if new_account_count == 1 then
        redis.call('EXPIRE', KEYS[2], ARGV[1])
    end

    redis.call(
        'SET',
        KEYS[3],
        '1',
        'EX',
        ARGV[4]
    )
end

return {1, 0}
"""


def enforce_provisioning_rate_limit(
    *,
    actor_user_id,
    user_id=None,
    charge_admin=True,
):
    """Atomically reserve provisioning request capacity."""

    if not charge_admin and user_id is None:
        raise ValueError("Account reservation requires user ID")

    prefix = "intelsoc:auth:provisioning:"

    keys = [
        prefix + "admin:" + _digest(str(actor_user_id))
    ]

    if user_id is not None:
        account_digest = _digest(str(user_id))

        keys.extend([
            prefix + "account:" + account_digest,
            prefix + "cooldown:" + account_digest,
        ])

    try:
        with redis.Redis(**get_redis_config()) as client:

            allowed, retry_after = client.eval(
                PROVISIONING_RATE_LIMIT_SCRIPT,
                len(keys),
                *keys,
                PROVISIONING_WINDOW_SECONDS,
                PROVISIONING_ADMIN_LIMIT,
                INVITATION_ACCOUNT_LIMIT,
                INVITATION_COOLDOWN_SECONDS,
                int(charge_admin),
            )

    except (redis.RedisError, OSError, ValueError, KeyError):
        raise RateLimitUnavailable(
            "Account provisioning temporarily unavailable"
        ) from None

    if not allowed:
        raise ProvisioningRateLimitExceeded(
            retry_after=max(1, int(retry_after))
        )



# --------------------------------------------------
# Account activation rate limiting
# --------------------------------------------------

ACTIVATION_WINDOW_SECONDS = 60
ACTIVATION_TOKEN_LIMIT = 5
ACTIVATION_IP_LIMIT = 20


class ActivationRateLimitExceeded(Exception):
    """Account activation attempt limit exceeded."""

    def __init__(self, retry_after):
        self.retry_after = retry_after
        super().__init__("Too many activation attempts")


def enforce_activation_rate_limit(
    *,
    invitation_token,
    source_ip,
):
    """Limit activation requests by token and source IP."""

    try:
        normalized_ip = str(
            ipaddress.ip_address(source_ip)
        )
    except (ValueError, TypeError):
        normalized_ip = "unknown"

    token_key = (
        "intelsoc:auth:activation:token:"
        + _digest(invitation_token)
    )

    ip_key = (
        "intelsoc:auth:activation:ip:"
        + _digest(normalized_ip)
    )

    try:
        with redis.Redis(**get_redis_config()) as client:

            allowed, retry_after = client.eval(
                RATE_LIMIT_SCRIPT,
                2,
                token_key,
                ip_key,
                ACTIVATION_WINDOW_SECONDS,
                ACTIVATION_TOKEN_LIMIT,
                ACTIVATION_IP_LIMIT,
            )

    except (redis.RedisError, OSError, ValueError, KeyError):
        raise RateLimitUnavailable(
            "Account activation temporarily unavailable"
        ) from None

    if not allowed:
        raise ActivationRateLimitExceeded(
            retry_after=max(1, int(retry_after))
        )

# --------------------------------------------------
# Password recovery and reset rate limiting
# --------------------------------------------------

RECOVERY_WINDOW_SECONDS = 3600
RECOVERY_EMAIL_LIMIT = 5
RECOVERY_IP_LIMIT = 20
RECOVERY_COOLDOWN_SECONDS = 60

RESET_WINDOW_SECONDS = 60
RESET_TOKEN_LIMIT = 5
RESET_IP_LIMIT = 20


class RecoveryRateLimitExceeded(Exception):
    """Password recovery request limit exceeded."""

    def __init__(self, retry_after):
        self.retry_after = retry_after
        super().__init__("Too many password recovery requests")


class ResetRateLimitExceeded(Exception):
    """Password reset attempt limit exceeded."""

    def __init__(self, retry_after):
        self.retry_after = retry_after
        super().__init__("Too many password reset attempts")


RECOVERY_RATE_LIMIT_SCRIPT = """
local email_count = tonumber(
    redis.call('GET', KEYS[1]) or '0'
)

local ip_count = tonumber(
    redis.call('GET', KEYS[2]) or '0'
)

local retry_after = 0

if email_count >= tonumber(ARGV[2]) then
    retry_after = math.max(
        retry_after,
        redis.call('TTL', KEYS[1]),
        1
    )
end

if ip_count >= tonumber(ARGV[3]) then
    retry_after = math.max(
        retry_after,
        redis.call('TTL', KEYS[2]),
        1
    )
end

if redis.call('EXISTS', KEYS[3]) == 1 then
    retry_after = math.max(
        retry_after,
        redis.call('TTL', KEYS[3]),
        1
    )
end

if retry_after > 0 then
    return {0, retry_after}
end

local new_email_count = redis.call('INCR', KEYS[1])

if new_email_count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end

local new_ip_count = redis.call('INCR', KEYS[2])

if new_ip_count == 1 then
    redis.call('EXPIRE', KEYS[2], ARGV[1])
end

redis.call(
    'SET',
    KEYS[3],
    '1',
    'EX',
    ARGV[4]
)

return {1, 0}
"""


def _normalize_recovery_ip(source_ip):
    try:
        address = ipaddress.ip_address(source_ip)

        if isinstance(address, ipaddress.IPv6Address):
            if address.ipv4_mapped is not None:
                address = address.ipv4_mapped

        return str(address)

    except (ValueError, TypeError):
        return "unknown"


def enforce_password_recovery_rate_limit(
    *,
    email,
    source_ip,
):
    """Limit recovery requests independently of account existence."""

    normalized_email = email.strip().lower()
    normalized_ip = _normalize_recovery_ip(source_ip)

    prefix = "intelsoc:auth:recovery:"

    email_digest = _digest(normalized_email)
    ip_digest = _digest(normalized_ip)

    keys = [
        prefix + "email:" + email_digest,
        prefix + "ip:" + ip_digest,
        prefix + "cooldown:" + email_digest,
    ]

    try:
        with redis.Redis(**get_redis_config()) as client:

            allowed, retry_after = client.eval(
                RECOVERY_RATE_LIMIT_SCRIPT,
                len(keys),
                *keys,
                RECOVERY_WINDOW_SECONDS,
                RECOVERY_EMAIL_LIMIT,
                RECOVERY_IP_LIMIT,
                RECOVERY_COOLDOWN_SECONDS,
            )

    except (redis.RedisError, OSError, ValueError, KeyError):
        raise RateLimitUnavailable(
            "Password recovery temporarily unavailable"
        ) from None

    if not allowed:
        raise RecoveryRateLimitExceeded(
            retry_after=max(1, int(retry_after))
        )


def enforce_password_reset_rate_limit(
    *,
    reset_token,
    source_ip,
):
    """Limit password reset attempts by token and source IP."""

    normalized_ip = _normalize_recovery_ip(source_ip)

    token_key = (
        "intelsoc:auth:reset:token:"
        + _digest(reset_token)
    )

    ip_key = (
        "intelsoc:auth:reset:ip:"
        + _digest(normalized_ip)
    )

    try:
        with redis.Redis(**get_redis_config()) as client:

            allowed, retry_after = client.eval(
                RATE_LIMIT_SCRIPT,
                2,
                token_key,
                ip_key,
                RESET_WINDOW_SECONDS,
                RESET_TOKEN_LIMIT,
                RESET_IP_LIMIT,
            )

    except (redis.RedisError, OSError, ValueError, KeyError):
        raise RateLimitUnavailable(
            "Password reset temporarily unavailable"
        ) from None

    if not allowed:
        raise ResetRateLimitExceeded(
            retry_after=max(1, int(retry_after))
        )
