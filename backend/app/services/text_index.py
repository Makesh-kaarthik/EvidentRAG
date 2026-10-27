"""Shared normalization for local BM25 indexing and query retrieval."""

import re
import unicodedata
from collections import Counter


_TOKEN_PATTERN = re.compile(
    r"cve-\d{4}-\d{3,}|(?:t\d{4}(?:\.\d{3})?|m\d{4}|ta\d{4})|"
    r"[a-z0-9]+(?:[._:-][a-z0-9]+)*",
    re.IGNORECASE,
)

_STOP_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "been", "by", "can",
    "could", "did", "do", "does", "during", "for", "from", "had", "has",
    "have", "how", "i", "in", "into", "is", "it", "its", "may", "might",
    "of", "on", "or", "should", "that", "the", "their", "them", "there",
    "these", "this", "to", "was", "were", "what", "when", "where", "which",
    "who", "why", "will", "with", "would", "you", "your", "att", "ck",
    "use", "uses", "using", "sub-technique", "subtechnique", "execute",
    "adversary", "adversaries", "attacker", "attackers", "intruder", "intruders",
    "operator", "operators", "responder", "responders", "compromised", "compromise",
    "launch", "launches", "launched", "run", "runs", "running", "finds", "found",
    "reading", "extracting", "gaining", "gained", "after", "before", "another",
}

_QUERY_SYNONYMS = {
    "2fa": ("multifactor", "authentication"),
    "accounts": ("account",),
    "administrator": ("admin", "privileged", "account"),
    "administrators": ("administrator", "privileged"),
    "attachments": ("attachment",),
    "c2": ("command", "control"),
    "changing": ("change", "modify", "alter", "disable"),
    "changes": ("change", "modify", "alter", "disable"),
    "commands": ("command",),
    "hashes": ("hash",),
    "secrets": ("secret",),
    "details": ("information",),
    "disguise": ("obfuscation", "obfuscated"),
    "disguising": ("obfuscation", "obfuscated"),
    "enumerates": ("enumerate", "enumeration", "discovery"),
    "enumerating": ("enumerate", "enumeration", "discovery"),
    "cred": ("credential", "credentials"),
    "creds": ("credential", "credentials"),
    "ddos": ("distributed", "denial", "service"),
    "dos": ("denial", "service"),
    "hide": ("obfuscate", "obfuscated"),
    "hiding": ("obfuscate", "obfuscated"),
    "internet-facing": ("public-facing", "public", "facing"),
    "ioc": ("indicator", "compromise"),
    "mfa": ("multifactor", "authentication"),
    "mitm": ("man", "middle", "attack"),
    "operating-system": ("operating", "system"),
    "rdp": ("remote", "desktop", "protocol"),
    "separating": ("segment", "segmentation", "separate"),
    "services": ("service",),
    "rds": ("remote", "desktop", "services"),
    "sqli": ("sql", "injection"),
    "vuln": ("vulnerability", "vulnerabilities"),
    "zones": ("segment", "segmentation", "network"),
    "xss": ("cross", "site", "scripting"),
    "credentials": ("credential", "password", "secret", "authentication"),
    "theft": ("steal", "stealing", "dump", "dumping"),
    "steal": ("theft", "credential", "dumping"),
    "protect": ("protection", "defend", "mitigate", "credential"),
    "protecting": ("protection", "defend", "mitigate", "credential"),
    "mitigation": ("mitigate", "protection", "defense", "defence"),
    "mitigations": ("mitigate", "protection", "defense", "defence"),
    "lsass": ("credential", "dumping", "memory", "password", "hash"),
    "hashes": ("hash", "credential", "password"),
    "secrets": ("secret", "credential", "password"),
    "cached": ("cache", "credential", "logon"),
    "logons": ("logon", "credential", "account"),
    "powershell": ("shell", "scripting", "script", "command", "execution"),
    "weaponized": ("malicious", "exploit", "attachment"),
    "document": ("file", "attachment", "phishing"),
    "documents": ("file", "attachment"),
    "stolen": ("steal", "valid", "account", "credential"),
    "employee": ("user", "account", "valid"),
    "erase": ("clear", "delete", "remove", "log"),
    "erasing": ("clear", "delete", "remove", "log"),
    "disabled": ("disable", "impair", "defense", "antivirus"),
    "antivirus": ("security", "defender", "disable", "protection"),
    "disables": ("disable", "impair", "defense", "tool", "antivirus"),
    "records": ("record", "log", "event", "audit"),
    "wevtutil": ("event", "log", "clear", "windows", "audit"),
    "archive": ("compress", "compression", "utility", "7-zip", "file"),
    "archives": ("archive", "compress", "compression", "utility", "file"),
    "payload": ("malware", "tool", "execution"),
    "spearphishing": ("phishing", "email", "attachment"),
    "registers": ("create", "scheduled", "task", "persistence"),
    "installs": ("install", "create", "service", "persistence"),
    "bundles": ("archive", "compress", "7-zip", "collect"),
    "staging": ("stage", "archive", "collection"),
    "systeminfo": ("system", "information", "discovery", "version", "hardware"),
    "remote": ("rdp", "remote-desktop", "lateral", "movement"),
}

_IDENTIFIER_PATTERN = re.compile(
    r"\b(?:CVE-\d{4}-\d{3,}|T\d{4}(?:\.\d{3})?|M\d{4}|TA\d{4})\b",
    re.IGNORECASE,
)


def tokenize(text: str) -> list[str]:
    normalized = unicodedata.normalize("NFKC", text or "").casefold()
    return [
        token
        for token in _TOKEN_PATTERN.findall(normalized)
        if token not in _STOP_WORDS and len(token) > 1
    ]


def query_terms(text: str) -> list[str]:
    base = tokenize(text)
    expanded = list(base)
    for token in base:
        expanded.extend(_QUERY_SYNONYMS.get(token, ()))
    return list(dict.fromkeys(expanded))


def query_phrase_tokens(text: str) -> list[str]:
    """Return ordered query tokens with known plural forms normalized for title matching."""
    tokens = tokenize(text)
    normalized = []
    for token in tokens:
        if token == "operating-system":
            normalized.extend(("operating", "system"))
            continue
        if token == "active-directory":
            normalized.extend(("active", "directory"))
            continue
        aliases = _QUERY_SYNONYMS.get(token, ())
        if token == "internet-facing":
            normalized.append("public-facing")
        else:
            normalized.append(aliases[0] if token.endswith("s") and aliases else token)
    return normalized


def query_expansion_terms(text: str) -> list[str]:
    """Add domain-specific terms for a few unambiguous multiword concepts."""
    normalized = unicodedata.normalize("NFKC", text or "").casefold()
    additions = []
    phrase_expansions = (
        ("operating system", ("os", "platform", "host")),
        ("operating-system", ("os", "platform", "host")),
        ("host configuration", ("system", "information", "hardware")),
        ("system configuration", ("host", "information", "hardware")),
        ("active directory", ("domain", "account", "user")),
        ("active-directory", ("domain", "account", "user")),
        ("domain account", ("active", "directory", "user")),
        ("domain accounts", ("active", "directory", "user")),
        ("lists user accounts", ("listing", "domain", "discovery")),
        ("list user accounts", ("listing", "domain", "discovery")),
        ("enumerate domain", ("listing", "discovery", "account")),
        ("enumerates domain", ("listing", "discovery", "account")),
        ("protect credentials", ("credential", "protection", "password", "secret", "authentication", "access", "dumping")),
        ("credentials from theft", ("credential", "protection", "password", "secret", "authentication", "access", "dumping")),
        ("credential theft", ("credential", "protection", "password", "secret", "authentication", "access", "dumping")),
        ("credential dumping", ("credential", "password", "hash", "lsass", "memory", "secret", "authentication")),
        ("execute commands", ("command", "shell", "powershell", "scripting", "script", "execution")),
        ("powershell commands", ("command", "shell", "scripting", "script", "execution")),
        ("phishing attachment", ("spearphishing", "email", "malicious", "file")),
        ("targeted email", ("spearphishing", "phishing", "attachment", "email")),
        ("disable antivirus", ("disable", "security", "tool", "antivirus", "degrade", "tamper", "impair", "edr", "endpoint")),
        ("disables antivirus", ("disable", "security", "tool", "antivirus", "degrade", "tamper", "impair", "edr", "endpoint")),
        ("antivirus protection", ("disable", "security", "tool", "antivirus", "degrade", "tamper", "impair", "edr", "endpoint")),
        ("lateral movement", ("remote", "network", "account", "credential", "pivot")),
        ("remote desktop", ("rdp", "remote", "desktop", "protocol", "lateral", "movement")),
        ("detect malware", ("detection", "monitor", "logging", "telemetry", "malicious")),
        ("prevent malware", ("mitigation", "protection", "block", "malicious", "execution")),
    )
    for phrase, terms in phrase_expansions:
        if phrase in normalized:
            additions.extend(terms)
    technique_intent = any(
        phrase in normalized
        for phrase in (
            "which technique", "what technique", "which sub-technique",
            "what sub-technique", "which subtechnique", "what subtechnique",
        )
    )
    if technique_intent:
        additions.append("attack-pattern")
    return list(dict.fromkeys(additions))


def document_text(document: dict) -> str:
    return " ".join(
        str(document.get(field, ""))
        for field in ("title", "source", "upstream_id", "text")
    )


def term_frequencies(document: dict) -> dict[str, int]:
    return dict(Counter(tokenize(document_text(document))))


def extract_identifiers(text: str) -> list[str]:
    return list(dict.fromkeys(match.upper() for match in _IDENTIFIER_PATTERN.findall(text or "")))
