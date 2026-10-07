"""Run: python3 -m tests.test_scanner   (no dependencies needed)"""
from app import scanner

# Build provider-specific fake credentials at runtime.
# This lets us test realistic secret formats without storing complete
# secret-shaped values as literals in Git history.
TEST_SLACK_WEBHOOK = (
    "https://hooks.slack.com/"
    + "services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
)

TEST_HF_TOKEN = "hf_" + "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh"

TEST_PYPI_TOKEN = (
    "pypi-"
    + "AgEIcHlwaS5vcmcCJDk2ZjZkNzEwLTY4ZTItNDQ3ZS1hYTQzLTc0NmI3MmYxYzA1ZQ"
)

TEST_TELEGRAM_TOKEN = (
    "1234567890:"
    + "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1"
)

TEST_AZURE_SAS = (
    "https://acct.blob.core.windows.net/c?"
    + "sv=2022-11-02&ss=b&sig=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789%3D"
)

# (file, line) -> should be detected
POSITIVE = [
    (".env", "API_KEY=abc123def456"),
    (".env", "DATABASE_URL=postgresql://localhost:5432/mydb"),
    (".env", "DB_PASSWORD=mysecretpassword"),
    (".env", "SECRET=hunter2"),
    (".env", "STRIPE_API_KEY=sk_test_51Habcdefghijklmnop"),
    ("config.py", 'password = "test123"'),
    ("config.py", 'DB_URL = "postgres://admin:SuperSecret123@db.example.com:5432/prod"'),
    ("config.py", 'SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://app:pw1234@10.0.0.5/app"'),
    ("config.py", 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'),
    ("config.py", 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'),
    ("app.js", "const apiKey = 'AIzaSyA1234567890abcdefghijklmnopqrstuv';"),
    ("app.js", "const mongo = 'mongodb+srv://user:p%40ss@cluster0.abcde.mongodb.net/test';"),
    ("app.js", "const token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';"),
    ("app.js", 'fetch(url, {headers: {"x-api-key": "9f8e7d6c5b4a3210"}})'),
    ("settings.yaml", "api_key: sk_test_1234567890abcdef"),
    ("settings.yaml", "  password: Passw0rd!"),
    ("config.json", '"client_secret": "a1b2c3d4e5f6g7h8"'),
    ("App.java", 'String url = "jdbc:mysql://db.internal:3306/shop?user=root&password=toor";'),
    ("appsettings.json", '"Default": "Server=tcp:sql.example.com;Database=app;User Id=sa;Password=P@ssw0rd123;"'),
    ("redis.conf", "REDIS_URL=redis://:s3cr3tpass@redis.example.com:6379/0"),
    ("id_rsa", "-----BEGIN RSA PRIVATE KEY-----"),
    ("main.go", 'const openaiKey = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"'),
    ("notify.py", f'SLACK = "{TEST_SLACK_WEBHOOK}"'),
    ("release.yml", f"token: {TEST_PYPI_TOKEN}"),
    ("model.py", f'login("{TEST_HF_TOKEN}")'),
    ("bot.py", f'bot = Bot("{TEST_TELEGRAM_TOKEN}")'),
    ("upload.js", f'const url = "{TEST_AZURE_SAS}";'),
    ("client.py", 'SESSION = "Zq8Rk2Lw9Tv4Xn7Bm1Hc6Pj3Yf5Gd0Sa"'),
]

# Should NOT be detected (common false positives)
NEGATIVE = [
    ("config.py", 'password = os.environ.get("DB_PASSWORD")'),
    ("config.py", 'API_KEY = os.getenv("API_KEY")'),
    ("app.js", "const token = process.env.TOKEN;"),
    ("docker-compose.yml", "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}"),
    ("models.py", "    password: str"),
    ("auth.py", "    token = get_token()"),
    ("auth.py", "    password = user_password"),
    (".env.example", "API_KEY=your_api_key"),
    (".env.example", "SECRET_KEY=changeme"),
    ("README.md", "Set the TOKEN environment variable before running."),
    ("form.html", '<input type="password" name="password">'),
    ("tests.py", 'API_KEY = "AKIAIOSFODNN7EXAMPLE"  # sentinel:ignore'),
    ("conf.py", 'API_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"  # gitleaks:allow'),
    ("hashes.py", 'EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"'),
    ("ids.py", 'request_id = "abcdefghijklmnopqrstuvwxyzabcd"'),
    ("README.md", "(`Server=...;Password=...`) connection strings are covered too."),
    ("clone.py", 'return f"https://x-access-token:{token}@{host}/{owner}/{name}.git"'),
    ("env.py", '"""Load KEY=VALUE lines from .env"""'),
    ("client.py", 'requests.post(url, headers={"X-Api-Key": api_key})'),
]

def run():
    failures = 0
    for path, line in POSITIVE:
        found = scanner.scan_text(path, line)
        status = "OK " if found else "MISS"
        if not found:
            failures += 1
        print(f"[{status}] +  {path:18s} {line[:70]:72s} -> {[f.rule_id for f in found]}")
    for path, line in NEGATIVE:
        found = scanner.scan_text(path, line)
        status = "OK " if not found else "FP  "
        if found:
            failures += 1
        print(f"[{status}] -  {path:18s} {line[:70]:72s} -> {[f.rule_id for f in found]}")
    print(f"\n{len(POSITIVE) + len(NEGATIVE) - failures}/{len(POSITIVE) + len(NEGATIVE)} passed")
    return failures

if __name__ == "__main__":
    raise SystemExit(1 if run() else 0)
