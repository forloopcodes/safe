"""Synthesize malicious-class feature vectors for training — feature space only.

This module never writes, stores, or executes any script. It produces rows in the
exact numeric feature space emitted by `safe features` (see FEATURE_ORDER), so the
classifier trains on the same representation it will see at inference time.

Method: each malicious vector borrows its *structural* features (size, line counts,
comment ratio, interpreter kind, function count) from a real benign script, then has
one to three attack archetypes layered on. An archetype turns on the detection
indicators that a documented technique class exhibits and shifts the correlated
byte-statistics (entropy, base64 density, long-line ratio, hard-coded IP endpoints).
Archetypes are named after MITRE ATT&CK technique classes and describe *what a
detector observes*, not how to build the technique.

Because the structural features are inherited from genuine installers, the model
cannot separate the classes on length or interpreter alone; the signal lives in the
behavioral indicators, which the Rust extractor computes identically on real input.
The synthetic nature of the positive class is stated as a limitation in the report.
"""
from __future__ import annotations

import math
import random

# Canonical feature order emitted by `safe features` (features::names in Rust).
FEATURE_ORDER = [
    "rule_exec_downloaded", "rule_downloads", "rule_privilege", "rule_persistence",
    "rule_profile", "rule_chmod", "rule_registry", "rule_disable_security",
    "rule_encoded_exec", "rule_recursive_delete", "log_size", "log_lines",
    "avg_line_len", "log_max_line_len", "long_line_ratio", "entropy", "comment_ratio",
    "blank_ratio", "non_ascii_ratio", "symbol_ratio", "dollar_per_line", "url_count",
    "http_url_count", "ip_url_count", "ipv4_count", "distinct_hosts", "base64_tokens",
    "log_longest_token", "function_count", "hex_escapes", "char_codes", "string_concat",
    "backtick_obfuscation", "ps_iex", "ps_hidden_window", "ps_exec_bypass",
    "ps_download_cradle", "ps_reflection", "sh_reverse_shell", "sh_eval",
    "anti_forensics", "credential_access", "crypto_mining", "exfiltration",
    "tmp_exec_dir", "background_exec", "file_lock", "process_kill", "user_creation",
    "ssh_key_injection", "checksum_verify", "usage_help", "kind_bash",
    "kind_powershell", "kind_python", "kind_executable", "kind_text",
]

KIND_FEATURES = ["kind_bash", "kind_powershell", "kind_python", "kind_executable", "kind_text"]


def _ln1p_count(lo: int, hi: int, rng: random.Random) -> float:
    """A count feature stored as ln(1 + n), matching the Rust extractor."""
    return math.log1p(rng.randint(lo, hi))


def _set_kind(vec: dict, kind: str) -> None:
    for k in KIND_FEATURES:
        vec[k] = 1.0 if k == kind else 0.0


# Each archetype is a callable that mutates a feature dict in place. Indicator features
# are set to ln(1+count) for a small random count; correlated statistics are nudged.
def _reverse_shell(v, rng):  # T1059 / T1571 — interactive shell to a hard-coded endpoint
    v["sh_reverse_shell"] = _ln1p_count(1, 2, rng)
    v["tmp_exec_dir"] = _ln1p_count(1, 3, rng)
    v["ip_url_count"] = max(v["ip_url_count"], _ln1p_count(1, 2, rng))
    v["ipv4_count"] = max(v["ipv4_count"], _ln1p_count(1, 2, rng))
    v["background_exec"] = _ln1p_count(1, 2, rng)
    v["rule_chmod"] = 1.0
    _set_kind(v, "kind_bash")


def _miner(v, rng):  # T1496 — resource hijacking
    v["crypto_mining"] = _ln1p_count(1, 3, rng)
    v["ip_url_count"] = max(v["ip_url_count"], _ln1p_count(1, 2, rng))
    v["tmp_exec_dir"] = _ln1p_count(1, 3, rng)
    v["background_exec"] = _ln1p_count(1, 2, rng)
    v["process_kill"] = _ln1p_count(1, 3, rng)
    v["rule_chmod"] = 1.0
    v["rule_downloads"] = 1.0


def _cred_theft(v, rng):  # T1552 — unsecured credentials + T1041 exfil
    v["credential_access"] = _ln1p_count(1, 4, rng)
    v["exfiltration"] = _ln1p_count(1, 2, rng)
    v["ssh_key_injection"] = _ln1p_count(0, 2, rng)
    v["tmp_exec_dir"] = _ln1p_count(0, 2, rng)
    v["http_url_count"] = max(v["http_url_count"], _ln1p_count(1, 2, rng))


def _ps_cradle(v, rng):  # T1059.001 — obfuscated PowerShell download cradle
    _set_kind(v, "kind_powershell")
    v["ps_download_cradle"] = _ln1p_count(1, 2, rng)
    v["ps_hidden_window"] = 1.0
    v["ps_exec_bypass"] = _ln1p_count(1, 2, rng)
    v["ps_iex"] = _ln1p_count(1, 2, rng)
    v["ps_reflection"] = _ln1p_count(0, 2, rng)
    v["backtick_obfuscation"] = _ln1p_count(1, 6, rng)
    v["string_concat"] = _ln1p_count(1, 8, rng)
    v["entropy"] = max(v["entropy"], rng.uniform(5.2, 6.4))
    v["symbol_ratio"] = max(v["symbol_ratio"], rng.uniform(0.06, 0.16))
    v["dollar_per_line"] = max(v["dollar_per_line"], rng.uniform(1.5, 5.0))


def _encoded_stager(v, rng):  # T1027 — obfuscated / encoded payload
    v["rule_encoded_exec"] = 1.0
    v["base64_tokens"] = _ln1p_count(1, 4, rng)
    v["entropy"] = max(v["entropy"], rng.uniform(5.4, 6.6))
    v["log_longest_token"] = max(v["log_longest_token"], rng.uniform(5.5, 8.5))
    v["long_line_ratio"] = max(v["long_line_ratio"], rng.uniform(0.05, 0.4))
    v["char_codes"] = _ln1p_count(0, 3, rng)
    v["hex_escapes"] = _ln1p_count(0, 5, rng)
    v["sh_eval"] = float(rng.random() < 0.5) and _ln1p_count(1, 2, rng)


def _security_tamper(v, rng):  # T1562 / T1070 — impair defenses, remove traces
    v["rule_disable_security"] = 1.0
    v["anti_forensics"] = _ln1p_count(1, 3, rng)
    v["process_kill"] = _ln1p_count(1, 3, rng)
    v["rule_privilege"] = 1.0
    v["file_lock"] = _ln1p_count(0, 1, rng)


def _backdoor_account(v, rng):  # T1136 / T1098 — persistence via new account + keys
    v["user_creation"] = _ln1p_count(1, 2, rng)
    v["ssh_key_injection"] = _ln1p_count(1, 2, rng)
    v["rule_persistence"] = 1.0
    v["rule_privilege"] = 1.0
    v["rule_profile"] = float(rng.random() < 0.5)


def _wiper(v, rng):  # T1485 — data destruction
    v["rule_recursive_delete"] = 1.0
    v["process_kill"] = _ln1p_count(1, 2, rng)
    v["rule_privilege"] = 1.0


def _supply_chain(v, rng):  # T1195.002 — trojanized installer: mostly benign + one tell
    v["rule_downloads"] = 1.0
    v["rule_exec_downloaded"] = float(rng.random() < 0.7)
    v["rule_chmod"] = 1.0
    v["rule_persistence"] = float(rng.random() < 0.5)
    # A single stealthy indicator hidden inside an otherwise ordinary installer.
    tell = rng.choice(["exfiltration", "ip_url_count", "rule_encoded_exec",
                        "credential_access", "base64_tokens"])
    if tell in ("ip_url_count",):
        v[tell] = max(v[tell], _ln1p_count(1, 1, rng))
    elif tell == "rule_encoded_exec":
        v[tell] = 1.0
        v["base64_tokens"] = max(v["base64_tokens"], _ln1p_count(1, 2, rng))
    else:
        v[tell] = max(v.get(tell, 0.0), _ln1p_count(1, 2, rng))


ARCHETYPES = [
    _reverse_shell, _miner, _cred_theft, _ps_cradle, _encoded_stager,
    _security_tamper, _backdoor_account, _wiper, _supply_chain,
]
# Supply-chain trojans are the realistic majority and the hardest to catch, so weight them up.
WEIGHTS = [3, 3, 3, 4, 4, 3, 2, 2, 6]


def synthesize(benign_rows, count, seed=1706):
    """Return `count` malicious feature dicts built on bootstrapped benign structure."""
    rng = random.Random(seed)
    bases = [r for r in benign_rows]
    out = []
    for _ in range(count):
        base = dict(rng.choice(bases))
        # Droppers commonly fetch and pipe to an interpreter.
        base["rule_downloads"] = 1.0 if rng.random() < 0.85 else base["rule_downloads"]
        base["rule_privilege"] = 1.0 if rng.random() < 0.55 else base["rule_privilege"]
        # Malicious scripts tend to carry little explanatory prose.
        base["comment_ratio"] *= rng.uniform(0.1, 0.6)
        base["usage_help"] = 0.0 if rng.random() < 0.7 else base["usage_help"]
        base["checksum_verify"] = 0.0 if rng.random() < 0.85 else base["checksum_verify"]
        n = rng.choices([1, 2, 3], weights=[5, 4, 2])[0]
        for fn in rng.choices(ARCHETYPES, weights=WEIGHTS, k=n):
            fn(base, rng)
        # A dropper that fetches and runs remote code.
        if base.get("sh_reverse_shell") or base.get("crypto_mining"):
            base["rule_exec_downloaded"] = 1.0 if rng.random() < 0.6 else base["rule_exec_downloaded"]
        out.append({k: float(base.get(k, 0.0)) for k in FEATURE_ORDER})
    return out
