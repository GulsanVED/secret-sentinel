"""
Secret detection rules and scanning logic.

Rules are plain regexes (no external deps like gitleaks/trufflehog) so the
project stays dependency-light and easy to extend: append a Rule to RULES, or
list a team's own formats in a .sentinel-rules.json file (load_custom_rules).

Design notes
------------
* Vendor-specific rules (AWS, Stripe, GitHub...) run first. "Generic" rules
  (KEY=value style assignments) are skipped when they overlap a specific
  match on the same line, so one secret doesn't raise two alerts.
* Generic assignments work with or without quotes, with prefixed variable
  names (DB_PASSWORD, STRIPE_API_KEY...), and in .env / YAML / JSON / code.
* Obvious non-secrets (os.environ.get(...), ${VAR}, "changeme", type hints)
  are filtered out to keep noise down.
* Fingerprints use sha256, so they are stable across restarts. (Python's
  built-in hash() is randomized per process, which would make every finding
  look "removed" and "new" again after each restart.)
"""
import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple


@dataclass
class Rule:
    id: str
    description: str
    pattern: re.Pattern
    severity: str = "high"
    generic: bool = False  # generic rules yield to specific ones on overlap
    # Named group holding the secret value, if the regex has one; otherwise
    # the whole match is treated as the secret.
    group: str = "secret"
    # Optional extra test on the captured value (e.g. an entropy check).
    validator: Optional[Callable[[re.Match], bool]] = None
    # Restrict the rule to config-style files (.env/.yaml/.json/...).
    config_files_only: bool = False
    # Restrict the rule to files that are neither config nor docs (source code).
    source_files_only: bool = False


@dataclass
class Finding:
    rule_id: str
    description: str
    severity: str
    file_path: str
    line_number: int
    matched_text: str      # masked — the raw secret never leaves this module
    fingerprint: str       # stable id used to track "still present" vs "removed"


def _mask(value: str) -> str:
    """Keep enough of the secret to recognize it in an alert, hide the rest."""
    value = value.strip()
    if len(value) <= 4:
        return "*" * len(value)
    if len(value) <= 10:
        return value[:2] + "*" * (len(value) - 2)
    # Cap the run of asterisks: a 120-char connection string masked literally
    # becomes an unreadable wall in a table cell or email.
    stars = min(len(value) - 8, 12)
    ellipsis = "…" if len(value) - 8 > 12 else ""
    return f"{value[:4]}{'*' * stars}{ellipsis}{value[-4:]}"


def _fingerprint(rule_id: str, file_path: str, secret: str) -> str:
    digest = hashlib.sha256(f"{rule_id}\x00{file_path}\x00{secret}".encode("utf-8", "ignore")).hexdigest()
    return f"{rule_id}:{file_path}:{digest[:16]}"


# --------------------------------------------------------------------------
# Rule set
# --------------------------------------------------------------------------

_DB_SCHEMES = (
    r"postgres|postgresql|mysql|mariadb|mongodb|redis|rediss|amqp|amqps|"
    r"mssql|sqlserver|oracle|cockroachdb|clickhouse|cassandra|couchdb|neo4j|db2"
)

# Secret-ish words that, at the END of a variable/key name, mean "the value is sensitive".
# Matches e.g. API_KEY, stripeApiKey, DB_PASSWORD, "client_secret", auth-token, PWD.
_SECRET_KEY_WORDS = (
    r"api[_\-.]?keys?|apikey|api[_\-.]?secret|secret[_\-.]?keys?|secrets?|access[_\-.]?keys?|"
    r"access[_\-.]?token|auth[_\-.]?token|refresh[_\-.]?token|bearer[_\-.]?token|tokens?|"
    r"client[_\-.]?secret|app[_\-.]?secret|private[_\-.]?keys?|public[_\-.]?key|signing[_\-.]?key|"
    r"encryption[_\-.]?key|master[_\-.]?key|licen[cs]e[_\-.]?key|keys?|"
    r"passwords?|passwd|passphrase|pass|pwd|credentials?|creds|"
    r"conn[_\-.]?str(?:ing)?|connection[_\-.]?string|dsn|auth|authorization|sas[_\-.]?token"
)

# A key name is the secret word, optionally prefixed by dotted/underscored/dashed
# segments: AWS_KEY, stripe.api.key, x-api-key. The leading separator requirement
# is what stops "monkey" from matching "key".
_KEY_NAME = rf"(?:(?<![A-Za-z0-9])|(?<=[_\-.]))(?:[A-Za-z0-9]+[_\-.])*(?:{_SECRET_KEY_WORDS})"

RULES: List[Rule] = [
    # ---- Vendor / format specific ------------------------------------------
    Rule("aws-access-key-id", "AWS Access Key ID",
         re.compile(r"\b(?P<secret>(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16})\b"), "critical"),
    Rule("aws-secret-key", "AWS Secret Access Key",
         re.compile(r"(?i)aws.{0,20}?secret.{0,20}?['\"]?\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{40})\b"), "critical"),
    Rule("gcp-api-key", "Google API Key", re.compile(r"\b(?P<secret>AIza[0-9A-Za-z\-_]{35})\b")),
    Rule("gcp-service-account", "Google service account private key (JSON)",
         re.compile(r"\"private_key\"\s*:\s*\"(?P<secret>-----BEGIN PRIVATE KEY-----[^\"]{20,})"), "critical"),  # sentinel:ignore (the rule itself)
    Rule("github-token", "GitHub Token",
         re.compile(r"\b(?P<secret>gh[pousr]_[0-9A-Za-z]{30,255}|github_pat_[0-9A-Za-z_]{20,255})\b"), "critical"),
    Rule("gitlab-token", "GitLab Personal Access Token", re.compile(r"\b(?P<secret>glpat-[0-9A-Za-z\-_]{20})\b")),
    Rule("slack-token", "Slack Token", re.compile(r"\b(?P<secret>xox[baprs]-[0-9A-Za-z-]{10,72})\b")),
    Rule("slack-webhook", "Slack Webhook URL",
         re.compile(r"(?P<secret>https://hooks\.slack\.com/services/[A-Za-z0-9/_]{20,80})")),
    Rule("discord-webhook", "Discord Webhook URL",
         re.compile(r"(?P<secret>https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)")),
    Rule("stripe-key", "Stripe API Key", re.compile(r"\b(?P<secret>(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{10,99})\b")),
    Rule("openai-key", "OpenAI API Key", re.compile(r"\b(?P<secret>sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,200})\b")),
    Rule("anthropic-key", "Anthropic API Key", re.compile(r"\b(?P<secret>sk-ant-[A-Za-z0-9_\-]{20,200})\b"), "critical"),
    Rule("google-oauth-secret", "Google OAuth Client Secret", re.compile(r"\b(?P<secret>GOCSPX-[0-9A-Za-z\-_]{20,})")),
    Rule("twilio-key", "Twilio API Key", re.compile(r"\b(?P<secret>SK[0-9a-fA-F]{32})\b")),
    Rule("sendgrid-key", "SendGrid API Key", re.compile(r"\b(?P<secret>SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b")),
    Rule("mailgun-key", "Mailgun API Key", re.compile(r"\b(?P<secret>key-[0-9a-zA-Z]{32})\b")),
    Rule("npm-token", "npm Access Token", re.compile(r"\b(?P<secret>npm_[A-Za-z0-9]{36})\b")),
    Rule("azure-storage-key", "Azure Storage Account Key",
         re.compile(r"AccountKey=(?P<secret>[A-Za-z0-9+/=]{60,100})")),
    Rule("pypi-token", "PyPI Upload Token", re.compile(r"\b(?P<secret>pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})"), "critical"),
    Rule("huggingface-token", "Hugging Face Access Token", re.compile(r"\b(?P<secret>hf_[A-Za-z]{34})\b")),
    Rule("shopify-token", "Shopify Access Token", re.compile(r"\b(?P<secret>shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b")),
    Rule("digitalocean-token", "DigitalOcean Token", re.compile(r"\b(?P<secret>do[por]_v1_[a-f0-9]{64})\b"), "critical"),
    Rule("telegram-bot-token", "Telegram Bot Token", re.compile(r"\b(?P<secret>\d{8,10}:AA[0-9A-Za-z_\-]{33})\b")),
    Rule("azure-sas-token", "Azure Shared Access Signature",
         re.compile(r"(?P<secret>[?&]sv=\d{4}-\d{2}-\d{2}&[^\s'\"]*?sig=[A-Za-z0-9%+/=]{30,})")),
    Rule("jwt", "JSON Web Token",
         re.compile(r"\b(?P<secret>eyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,})"), "medium"),
    Rule("private-key-block", "Private Key Block",
         re.compile(r"(?P<secret>-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"), "critical"),

    # ---- Database connection strings / URLs --------------------------------
    # Order matters: the first rule to claim a span wins, so the most specific
    # (credentialed) forms come before the generic "a DB URL is exposed" ones.
    Rule("jdbc-with-password", "JDBC connection string with password",
         re.compile(r"(?i)(?P<secret>jdbc:[a-z0-9]+:[^\s'\"`]*?password=[^&\s'\"`;]+)"), "critical"),
    Rule("db-url-with-credentials", "Database connection URL with embedded credentials",
         re.compile(
             rf"(?i)(?P<secret>\b(?:{_DB_SCHEMES})(?:\+[a-z0-9]+)?://"
             r"(?:[^\s:@/'\"`]*:[^\s@'\"`]+@[^\s'\"`<>]+"          # user:pass@host   (user may be empty)
             r"|[^\s'\"`<>]*?[?&](?:password|pwd)=[^&\s'\"`<>]+))"),  # host/db?password=...
         "critical"),
    Rule("dotnet-conn-string", "Connection string with password (ADO.NET / ODBC style)",
         re.compile(r"(?i)(?:server|data source|host)\s*=[^;'\"]+;[^'\"\n]*?(?:password|pwd)\s*=\s*(?P<secret>[^;'\"\s]{3,})"),
         "critical", validator=lambda m: not _looks_like_placeholder(m.group("secret"))),
    Rule("jdbc-url", "JDBC connection string",
         re.compile(r"(?i)(?P<secret>jdbc:[a-z0-9]+:[^\s'\"`]{6,})"), "medium"),
    Rule("db-url", "Database connection URL (host/db exposed, no inline password)",
         re.compile(rf"(?i)(?P<secret>\b(?:{_DB_SCHEMES})(?:\+[a-z0-9]+)?://[^\s'\"`<>]{{3,}})"),
         "medium"),

    # ---- Generic assignments (KEY=value / key: value / "key": "value") -----
    Rule("generic-secret-assignment", "Hard-coded secret / password / API key",
         re.compile(
             rf"(?i)(?P<key>{_KEY_NAME})['\"`]?\s*(?:=|:=|=>|:)\s*"
             r"(?P<q>['\"`]?)(?P<secret>[^\s'\"`,;]{4,300})(?P=q)"),
         "high", generic=True),

    # Anything that simply LOOKS like a credential in a config file, whatever it
    # is called (catches names the list above doesn't know: SENTRY_DSN, TWILIO_SID...).
    Rule("high-entropy-value", "Possible secret (high-entropy value in a config file)",
         re.compile(r"""(?ix)^\s*(?:export\s+)?(?P<key>[A-Za-z0-9_.\-]{2,64})\s*[:=]\s*
                        (?P<q>['\"]?)(?P<secret>[A-Za-z0-9+/=_\-.~]{16,200})(?P=q)\s*(?:\#.*)?$"""),
         "medium", generic=True, config_files_only=True,
         validator=lambda m: _entropy_candidate(m.group("key"), m.group("secret"))),

    # Same idea for source code: a long, random-looking string literal assigned
    # to something. Low severity (reported, but does not fail a default build),
    # since code legitimately contains hashes and encoded blobs.
    Rule("high-entropy-string", "Possible secret (high-entropy string literal in code)",
         re.compile(r"""(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{1,64})['"]?\s*(?:=|:=|=>|:)\s*
                        (?P<q>['"`])(?P<secret>[A-Za-z0-9+/=_\-]{24,200})(?P=q)""", re.X),
         "low", generic=True, source_files_only=True,
         validator=lambda m: _entropy_candidate(m.group("key"), m.group("secret"), min_entropy=4.2, min_classes=3)),
]


# Keys whose values are routinely long and random but not secret.
_BENIGN_ENTROPY_KEYS = {
    "sha", "sha1", "sha256", "sha512", "md5", "hash", "integrity", "digest", "checksum", "etag",
    "version", "id", "uuid", "guid", "commit", "revision", "rev", "ref", "branch", "tag", "image",
    "url", "uri", "path", "file", "filename", "name", "host", "hostname", "port", "email", "user",
    "username", "region", "bucket", "zone", "locale", "timezone", "date", "time", "timestamp",
    "class", "style", "src", "href", "font", "color", "width", "height", "description", "comment",
}


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _entropy_candidate(key: str, value: str, min_entropy: float = 3.4, min_classes: int = 2) -> bool:
    """True when `key = value` looks like a real credential rather than config."""
    base_key = re.split(r"[_.\-]", key.strip().lower())[-1]
    if base_key in _BENIGN_ENTROPY_KEYS or key.strip().lower() in _BENIGN_ENTROPY_KEYS:
        return False
    if _looks_like_placeholder(value):
        return False
    if _shannon_entropy(value) < min_entropy:
        return False
    classes = sum([any(c.islower() for c in value), any(c.isupper() for c in value),
                   any(c.isdigit() for c in value)])
    if classes < min_classes:             # all-lowercase words etc. are usually not keys
        return False
    if re.fullmatch(r"[0-9.]+", value):   # version numbers
        return False
    if value.lower().startswith(("http://", "https://", "/", "./", "~/")):
        return False                      # plain URLs/paths (credentialed ones have their own rules)
    return True


# --------------------------------------------------------------------------
# Custom rules (a team's own token formats, without editing this file)
# --------------------------------------------------------------------------

CUSTOM_RULES: List[Rule] = []
_ACTIVE_RULES: List[Rule] = list(RULES)
_SEVERITIES = ("low", "medium", "high", "critical")
_RULE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")


class RulesFileError(ValueError):
    pass


def active_rules() -> List[Rule]:
    """Built-in specific rules, then custom rules, then the generic catch-alls,
    so a custom format claims its match before a generic rule can."""
    return _ACTIVE_RULES


def set_custom_rules(rules: List[Rule]) -> None:
    CUSTOM_RULES[:] = rules
    _ACTIVE_RULES[:] = ([r for r in RULES if not r.generic] + list(rules)
                        + [r for r in RULES if r.generic])


def load_custom_rules(path) -> List[Rule]:
    """Read a rules file such as .sentinel-rules.json:

        {"rules": [{"id": "acme-api-key", "description": "Acme API key",
                    "pattern": "\\b(?P<secret>acme_[A-Za-z0-9]{32})\\b",
                    "severity": "critical", "min_entropy": 3.0}]}

    `pattern` is a Python regex; a named group `secret` marks the secret part
    (else the whole match is the secret). `severity` defaults to high,
    `description` to the id, and `min_entropy` (optional) rejects matches whose
    secret is less random than that many bits per character."""
    import json
    from pathlib import Path

    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as e:
        raise RulesFileError(f"cannot read rules file {path}: {e}") from e
    except ValueError as e:
        raise RulesFileError(f"rules file {path} is not valid JSON: {e}") from e
    entries = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise RulesFileError(f"rules file {path} must be an object with a \"rules\" list")

    builtin_ids = {r.id for r in RULES}
    seen, out = set(), []
    for i, entry in enumerate(entries):
        where = f"{path}: rule #{i + 1}"
        if not isinstance(entry, dict):
            raise RulesFileError(f"{where} must be an object")
        rid = str(entry.get("id", ""))
        if not _RULE_ID.match(rid):
            raise RulesFileError(f"{where}: id {rid!r} must be 2-64 lowercase letters, digits or dashes")
        if rid in builtin_ids or rid in seen:
            raise RulesFileError(f"{where}: id {rid!r} is already used")
        seen.add(rid)
        severity = str(entry.get("severity", "high")).lower()
        if severity not in _SEVERITIES:
            raise RulesFileError(f"{where} ({rid}): severity must be one of {', '.join(_SEVERITIES)}")
        try:
            pattern = re.compile(str(entry.get("pattern", "")))
        except re.error as e:
            raise RulesFileError(f"{where} ({rid}): invalid regex: {e}") from e
        if not pattern.pattern:
            raise RulesFileError(f"{where} ({rid}): pattern is empty")
        validator = None
        if entry.get("min_entropy") is not None:
            try:
                floor = float(entry["min_entropy"])
            except (TypeError, ValueError) as e:
                raise RulesFileError(f"{where} ({rid}): min_entropy must be a number") from e
            validator = (lambda m, floor=floor:
                         _shannon_entropy(m.groupdict().get("secret") or m.group(0)) >= floor)
        out.append(Rule(rid, str(entry.get("description") or rid), pattern, severity,
                        validator=validator))
    return out


# --------------------------------------------------------------------------
# Noise filters for generic matches
# --------------------------------------------------------------------------

_PLACEHOLDER_VALUES = {
    "true", "false", "null", "none", "nil", "undefined", "empty", "string", "str", "int",
    "number", "bool", "boolean", "any", "object", "optional", "required", "secret", "password",
    "token", "changeme", "change_me", "change-me", "placeholder", "example", "sample", "redacted",
    "hidden", "xxxxxx", "******", "<password>", "your_password", "your-password", "yourpassword",
    "your_api_key", "your-api-key", "api_key", "apikey", "todo", "tbd", "n/a", "na", "default",
    "value", "values", "...", "....", "…",
}

_CODE_REF_PREFIXES = (
    "os.", "process.", "env.", "environ", "getenv", "self.", "this.", "config.", "settings.",
    "request.", "req.", "args.", "options.", "opts.", "props.", "params.", "context.", "ctx.",
    "secrets.", "vars.", "import", "require", "new ", "function", "lambda", "st.secrets",
    "system.getenv", "configuration[", "document.", "window.", "input", "form.", "data.",
    "user.", "credentials.", "auth.", "keyring", "vault", "boto", "none", "null",
)


def _looks_like_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"`").lower()
    if not v or len(v) < 4:
        return True
    if v in _PLACEHOLDER_VALUES:
        return True
    if v.startswith(_CODE_REF_PREFIXES):
        return True
    # Templating / interpolation / code: ${VAR}, {{ var }}, <VAR>, %(var)s, func(...), obj[...]
    if any(tok in v for tok in ("${", "{{", "}}", "<", ">", "%(", "(", ")", "[", "]")):
        return True
    if v.startswith("$"):  # $VAR / $(cmd) shell references
        return True
    if v.startswith("{") and "}" in v:  # f-string / str.format: {token}@{host}
        return True
    # Repeated filler characters: xxxxx, *****, 00000, .....
    if len(set(v)) <= 2:
        return True
    if v.startswith(("your", "insert", "enter", "replace", "put-", "put_", "add-", "add_")):
        return True
    return False


def _looks_like_code_identifier(value: str, quoted: bool) -> bool:
    """For UNQUOTED values in source code: `token = get_token` / `password = user.password`
    / `token: string` are references, not secrets. Unquoted values in .env / YAML files are
    still treated as literals."""
    if quoted:
        return False
    # Closing brackets belong to the surrounding code: {"X-Api-Key": api_key}
    value = value.rstrip(")]}")
    # A bare snake/camel-case identifier with no digits is very likely a variable name.
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z_]*", value)) and not value.isupper() and len(value) < 24


_CONFIG_EXTENSIONS = re.compile(
    r"(\.env(\..*)?|\.ini|\.cfg|\.conf|\.config|\.properties|\.ya?ml|\.toml|\.txt|\.json|\.xml|\.sh|\.bash|"
    r"\.zsh|\.envrc|\.npmrc|\.pypirc|\.netrc|\.tfvars|\.md)$|(^|/)\.env[^/]*$|(^|/)Dockerfile[^/]*$",
    re.IGNORECASE,
)

# The entropy rule only runs on these (not .md/.txt, where random-looking
# strings are usually examples).
_ENTROPY_FILE_EXTENSIONS = re.compile(
    r"(\.env(\..*)?|\.ini|\.cfg|\.conf|\.config|\.properties|\.ya?ml|\.toml|\.tfvars|"
    r"\.envrc|\.npmrc|\.netrc|\.json)$|(^|/)\.env[^/]*$", re.IGNORECASE)

# Skip binary / lock / vendored files.
SKIP_PATH_PATTERNS = [
    re.compile(r"(^|/)node_modules/"),
    re.compile(r"(^|/)vendor/"),
    re.compile(r"(^|/)\.git/"),
    re.compile(r"(^|/)(dist|build|\.next|__pycache__|\.venv|venv)/"),
    re.compile(r"\.(png|jpe?g|gif|webp|ico|bmp|tiff?|svg|woff2?|ttf|otf|eot|mp[34]|mov|avi|zip|gz|tgz|bz2|xz|7z|"
               r"tar|rar|jar|war|pdf|docx?|xlsx?|pptx?|exe|dll|so|dylib|bin|class|pyc|o|a|lock|min\.js|map)$",
               re.IGNORECASE),
    re.compile(r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|go\.sum|composer\.lock)$"),
    # Our own policy files hold fingerprints, which look like key=value secrets.
    re.compile(r"(^|/)(\.sentinelignore|\.sentinel-baseline\.json|\.sentinel-rules\.json)$"),
]

MAX_FILE_BYTES = 1_000_000  # don't bother scanning huge generated files


def should_skip_path(path: str) -> bool:
    return any(p.search(path) for p in SKIP_PATH_PATTERNS)


def _overlaps(span: Tuple[int, int], spans: List[Tuple[int, int]]) -> bool:
    return any(span[0] < e and s < span[1] for s, e in spans)


# A line carrying one of these markers is never reported, e.g. a documented
# test fixture:  API_KEY = "AKIA..."  # sentinel:ignore
# (gitleaks:allow / pragma: allowlist secret are honoured for compatibility.)
_INLINE_IGNORE = re.compile(r"sentinel:ignore|gitleaks:allow|pragma:\s*allowlist secret", re.IGNORECASE)


def scan_line(file_path: str, line: str, line_no: int) -> List[Finding]:
    if _INLINE_IGNORE.search(line):
        return []
    findings: List[Finding] = []
    claimed: List[Tuple[int, int]] = []   # spans already reported by an earlier (higher-priority) rule
    is_config_file = bool(_CONFIG_EXTENSIONS.search(file_path))

    is_entropy_file = bool(_ENTROPY_FILE_EXTENSIONS.search(file_path))
    for rule in _ACTIVE_RULES:
        if rule.config_files_only and not is_entropy_file:
            continue
        if rule.source_files_only and is_config_file:
            continue
        for m in rule.pattern.finditer(line):
            secret = m.groupdict().get(rule.group) or m.group(0)
            span = m.span(rule.group) if m.groupdict().get(rule.group) else m.span()

            if _overlaps(span, claimed):
                continue  # same secret already reported by a more specific rule
            if rule.validator and not rule.validator(m):
                continue
            if rule.generic:
                quoted = bool(m.groupdict().get("q"))
                if _looks_like_placeholder(secret):
                    continue
                if not is_config_file and _looks_like_code_identifier(secret, quoted):
                    continue
            claimed.append(span)

            findings.append(Finding(
                rule_id=rule.id,
                description=rule.description,
                severity=rule.severity,
                file_path=file_path,
                line_number=line_no,
                matched_text=_mask(secret),
                fingerprint=_fingerprint(rule.id, file_path, secret),
            ))
    return findings


def scan_text(file_path: str, content: str) -> List[Finding]:
    """Scan one file's full text and return all findings (deduplicated by fingerprint)."""
    if should_skip_path(file_path):
        return []
    if len(content) > MAX_FILE_BYTES:
        return []
    if "\x00" in content[:8000]:  # binary file that slipped past the extension filter
        return []

    findings: List[Finding] = []
    seen = set()
    for line_no, line in enumerate(content.splitlines(), start=1):
        if len(line) > 5000:  # minified blob; scan only the start to stay fast
            line = line[:5000]
        for f in scan_line(file_path, line, line_no):
            if f.fingerprint in seen:
                continue
            seen.add(f.fingerprint)
            findings.append(f)
    return findings
