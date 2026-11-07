"""
AegisDPI — Middleware Client
Handles authentication with the Node.js middleware, token caching,
and automated blocklist rule enforcement (POST /api/rules) with retry on 401.
"""

import os
import requests
from typing import Optional
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(dotenv_path=os.path.join(BASE_DIR, ".env"))

class MiddlewareClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.base_url = (base_url or os.getenv("MIDDLEWARE_URL", "http://localhost:4000")).rstrip("/")
        self.username = username or os.getenv("ML_SERVICE_USERNAME", "ml-service")
        self.password = password or os.getenv("ML_SERVICE_PASSWORD", "")
        self._token: Optional[str] = None

    def login(self) -> bool:
        """Authenticates with middleware and caches JWT token."""
        url = f"{self.base_url}/api/auth/login"
        payload = {"username": self.username, "password": self.password}
        try:
            res = requests.post(url, json=payload, timeout=5)
            if res.status_code == 200:
                data = res.json()
                self._token = data.get("token")
                print(f"[MIDDLEWARE-CLIENT] Authenticated successfully as '{self.username}'")
                return True
            else:
                print(f"[MIDDLEWARE-CLIENT] Login failed ({res.status_code}): {res.text}")
                return False
        except Exception as e:
            print(f"[MIDDLEWARE-CLIENT] Exception during login: {e}")
            return False

    def post_rule(self, ip: str, reason: str = "") -> bool:
        """
        POST /api/rules with { "type": "ip", "value": ip, "source": "ml_auto", "reason": reason }
        Returns True on 201 (success), False otherwise.
        Automatically re-authenticates and retries once on 401 Unauthorized.
        """
        if not self._token:
            if not self.login():
                print("[MIDDLEWARE-CLIENT] Unable to post rule: Login failed.")
                return False

        url = f"{self.base_url}/api/rules"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }
        payload = {"type": "ip", "value": ip, "source": "ml_auto"}
        if reason:
            payload["reason"] = reason

        try:
            res = requests.post(url, json=payload, headers=headers, timeout=5)
            if res.status_code == 201:
                data = res.json() if res.headers.get("content-type", "").startswith("application/json") else {}
                ttl_s = data.get("ttl_s")
                expires_at = data.get("expires_at")
                print(f"[MIDDLEWARE-CLIENT] Successfully enforced block rule for IP: {ip} (ttl_s: {ttl_s}, expires_at: {expires_at})")
                return True
            elif res.status_code == 409:
                print(f"[MIDDLEWARE-CLIENT] Block rule suppressed: {ip} is allowlisted")
                return False
            elif res.status_code == 401:
                print("[MIDDLEWARE-CLIENT] Received 401 Unauthorized. Refreshing token and retrying...")
                if self.login():
                    headers["Authorization"] = f"Bearer {self._token}"
                    retry_res = requests.post(url, json=payload, headers=headers, timeout=5)
                    if retry_res.status_code == 201:
                        data = retry_res.json() if retry_res.headers.get("content-type", "").startswith("application/json") else {}
                        ttl_s = data.get("ttl_s")
                        expires_at = data.get("expires_at")
                        print(f"[MIDDLEWARE-CLIENT] Retry succeeded for IP: {ip} (ttl_s: {ttl_s}, expires_at: {expires_at})")
                        return True
                    elif retry_res.status_code == 409:
                        print(f"[MIDDLEWARE-CLIENT] Block rule suppressed: {ip} is allowlisted")
                        return False
                    else:
                        print(f"[MIDDLEWARE-CLIENT] Retry failed ({retry_res.status_code}): {retry_res.text}")
                        return False
                return False
            else:
                print(f"[MIDDLEWARE-CLIENT] Post rule failed ({res.status_code}): {res.text}")
                return False
        except Exception as e:
            print(f"[MIDDLEWARE-CLIENT] Exception while posting rule: {e}")
            return False
