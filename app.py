import os
import sqlite3
import hashlib
import hmac
import json
import time
from urllib.parse import parse_qsl

from flask import Flask, request, jsonify, render_template

BOT_TOKEN = os.environ.get("BOT_TOKEN", "PUT_BOT_TOKEN_HERE")
# This must point to the SAME SQLite database used by limegram777.py.
DB = os.environ.get("BOT_DB_PATH", "tenx_gram.db")
IP_HASH_SALT = os.environ.get("IP_HASH_SALT", "CHANGE_THIS_SALT")
TRUST_PROXY = os.environ.get("TRUST_PROXY", "1") == "1"
MAX_INIT_DATA_AGE = int(os.environ.get("MAX_INIT_DATA_AGE", "86400"))

app = Flask(__name__)


def db():
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            referrer_id INTEGER,
            balance REAL NOT NULL DEFAULT 0,
            withdrawn REAL NOT NULL DEFAULT 0,
            total_earned REAL NOT NULL DEFAULT 0,
            referrals_count INTEGER NOT NULL DEFAULT 0,
            confirmed_referrals INTEGER NOT NULL DEFAULT 0,
            referral_credited INTEGER NOT NULL DEFAULT 0,
            gate_passed INTEGER NOT NULL DEFAULT 0,
            gate_sponsors_confirmed INTEGER NOT NULL DEFAULT 0,
            is_blocked INTEGER NOT NULL DEFAULT 0,
            ban_until TEXT,
            ban_reason TEXT,
            ip_hash TEXT,
            ip_checked_at TEXT,
            joined_at TEXT
        )
    """)
    existing = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    migrations = {
        "ban_until": "TEXT",
        "ban_reason": "TEXT",
        "ip_hash": "TEXT",
        "ip_checked_at": "TEXT",
        "joined_at": "TEXT",
        "username": "TEXT",
        "is_blocked": "INTEGER NOT NULL DEFAULT 0",
    }
    for name, definition in migrations.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
    conn.commit()
    return conn


def verify_telegram_init_data(init_data: str) -> dict:
    """Validate Telegram Web App initData on the server."""
    if not init_data or BOT_TOKEN == "PUT_BOT_TOKEN_HERE":
        raise ValueError("BOT_TOKEN is not configured")

    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = pairs.pop("hash", None)
    if not received_hash:
        raise ValueError("Missing Telegram hash")

    auth_date = pairs.get("auth_date")
    if auth_date:
        try:
            if int(time.time()) - int(auth_date) > MAX_INIT_DATA_AGE:
                raise ValueError("Telegram initData is expired")
        except ValueError as exc:
            if str(exc) == "Telegram initData is expired":
                raise
            raise ValueError("Invalid auth_date")

    data_check_string = "\n".join(
        f"{k}={v}" for k, v in sorted(pairs.items())
    )

    secret_key = hmac.new(
        b"WebAppData",
        BOT_TOKEN.encode(),
        hashlib.sha256
    ).digest()

    calculated_hash = hmac.new(
        secret_key,
        data_check_string.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(calculated_hash, received_hash):
        raise ValueError("Invalid Telegram initData")

    return pairs


def client_ip() -> str:
    if TRUST_PROXY:
        # Use proxy-provided client IP only when the deployment explicitly
        # trusts its reverse proxy. Otherwise X-Forwarded-For is spoofable.
        forwarded = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or ""


def hash_ip(ip: str) -> str:
    if not ip:
        raise ValueError("Unable to determine client IP")
    return hashlib.sha256((IP_HASH_SALT + ":" + ip).encode()).hexdigest()


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/check")
def check():
    try:
        payload = request.get_json(silent=True) or {}
        pairs = verify_telegram_init_data(payload.get("initData", ""))
        user = json.loads(pairs["user"])
        telegram_id = int(user["id"])
    except Exception as e:
        return jsonify({"ok": False, "blocked": True, "error": str(e)}), 400

    try:
        ip_h = hash_ip(client_ip())
        conn = db()

        # If the same IP was already recorded for another Telegram account,
        # block the current account in the bot's own users table.
        row = conn.execute(
            "SELECT user_id, is_blocked FROM users "
            "WHERE ip_hash=? AND user_id<>? LIMIT 1",
            (ip_h, telegram_id),
        ).fetchone()

        if row:
            conn.execute(
                "UPDATE users SET is_blocked=1, ban_until=NULL, "
                "ban_reason=? WHERE user_id=?",
                (f"Совпадение IP с аккаунтом {row[0]}", telegram_id),
            )
            conn.commit()
            conn.close()
            return jsonify({
                "ok": True,
                "blocked": True,
                "reason": "Этот IP уже использовался другим аккаунтом.",
            })

        # First visit for this account: save the salted IP hash.
        conn.execute(
            """INSERT INTO users(user_id, username, ip_hash, ip_checked_at)
               VALUES(?,?,?,CURRENT_TIMESTAMP)
               ON CONFLICT(user_id) DO UPDATE SET
                 username=excluded.username,
                 ip_hash=excluded.ip_hash,
                 ip_checked_at=excluded.ip_checked_at""",
            (telegram_id, user.get("username", ""), ip_h),
        )
        conn.commit()

        # Check once more after the upsert so a concurrent Web App request
        # cannot leave the account in an inconsistent state.
        row2 = conn.execute(
            "SELECT user_id FROM users WHERE ip_hash=? AND user_id<>? LIMIT 1",
            (ip_h, telegram_id),
        ).fetchone()
        if row2:
            conn.execute(
                "UPDATE users SET is_blocked=1, ban_until=NULL, "
                "ban_reason=? WHERE user_id=?",
                (f"Совпадение IP с аккаунтом {row2[0]}", telegram_id),
            )
            conn.commit()
            conn.close()
            return jsonify({
                "ok": True,
                "blocked": True,
                "reason": "Этот IP уже использовался другим аккаунтом.",
            })

        conn.close()
        return jsonify({"ok": True, "blocked": False})
    except Exception as e:
        app.logger.exception("IP check failed")
        return jsonify({"ok": False, "blocked": False, "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
