"""Convert downloaded ATT&CK and KEV JSON into source-linked RAG documents."""

from __future__ import annotations

import hashlib
import json
import io
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
ATTACK_PATH = ROOT / "raw" / "mitre_attack_enterprise_20.0.json"
KEV_PATH = ROOT / "raw" / "cisa_known_exploited_vulnerabilities.json"
STARTER_PATH = ROOT / "curated" / "mitre_starter.json"
OUTPUT_PATH = ROOT / "processed" / "index_documents.jsonl"
OUTPUT_MANIFEST = ROOT / "processed" / "processing-manifest.json"
ATTACK_RELEASE = "Enterprise ATT&CK 20.0"
NVD_DIR = ROOT / "raw" / "nvd"


def _iter_json_array_objects(path: Path, key: str):
    """Stream objects from a top-level JSON array without loading a large feed."""
    needle = f'"{key}"'.encode("ascii")
    with path.open("rb") as raw:
        tail = b""
        offset = 0
        found_at = None
        while chunk := raw.read(1024 * 1024):
            haystack = tail + chunk
            location = haystack.find(needle)
            if location >= 0:
                found_at = offset - len(tail) + location + len(needle)
                break
            offset += len(chunk)
            tail = haystack[-(len(needle) - 1):]
        if found_at is None:
            raise ValueError(f"JSON array {key!r} not found in {path.name}.")
        raw.seek(found_at)
        stream = io.TextIOWrapper(raw, encoding="utf-8")
        buffer = ""
        position = 0
        decoder = json.JSONDecoder()

        def next_char():
            nonlocal buffer, position
            while position >= len(buffer):
                buffer = stream.read(1024 * 1024)
                position = 0
                if not buffer:
                    return ""
            char = buffer[position]
            position += 1
            return char

        def skip_space():
            char = next_char()
            while char and char.isspace():
                char = next_char()
            return char

        if skip_space() != ":" or skip_space() != "[":
            raise ValueError(f"Invalid JSON array field {key!r} in {path.name}.")

        char = skip_space()
        if char == "]":
            return
        while char:
            # raw_decode needs a complete record; refill only when the current
            # buffer ends inside that record, keeping memory bounded by one CVE.
            start = position - 1
            while True:
                try:
                    item, end = decoder.raw_decode(buffer, start)
                    position = end
                    break
                except json.JSONDecodeError:
                    more = stream.read(1024 * 1024)
                    if not more:
                        raise
                    record_buffer = buffer[start:]
                    buffer = record_buffer + more
                    position = len(record_buffer)
                    start = 0
            yield item
            if position > 1024 * 1024:
                buffer = buffer[position:]
                position = 0
            char = skip_space()
            if char == ",":
                char = skip_space()
            elif char == "]":
                return
            else:
                raise ValueError(f"Invalid JSON array delimiter in {path.name}.")


def _external_id(obj: dict[str, Any]) -> str | None:
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return reference.get("external_id")
    return None


def _clean(value: Any) -> str:
    if isinstance(value, str):
        return " ".join(value.split())
    return ""


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _make_document(
    source_id: str,
    title: str,
    source: str,
    url: str,
    text: str,
    source_type: str,
    upstream_id: str,
    source_version: str,
) -> dict[str, Any]:
    normalized = "\n".join(line.strip() for line in text.splitlines() if line.strip())
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return {
        "source_id": source_id,
        "title": title,
        "source": source,
        "url": url,
        "text": normalized,
        "source_type": source_type,
        "upstream_id": upstream_id,
        "source_version": source_version,
        "content_sha256": digest,
    }


def _mitre_documents(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    objects = bundle.get("objects", [])
    active = {
        obj.get("id"): obj
        for obj in objects
        if obj.get("id") and not obj.get("revoked") and not obj.get("x_mitre_deprecated")
    }
    technique_names = {
        object_id: obj.get("name", "")
        for object_id, obj in active.items()
        if obj.get("type") == "attack-pattern"
    }
    mitigation_names = {
        object_id: obj.get("name", "")
        for object_id, obj in active.items()
        if obj.get("type") == "course-of-action"
    }
    techniques_by_mitigation: dict[str, list[str]] = defaultdict(list)
    mitigations_by_technique: dict[str, list[str]] = defaultdict(list)
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "mitigates":
            continue
        mitigation_id = obj.get("source_ref")
        technique_id = obj.get("target_ref")
        if mitigation_id in mitigation_names and technique_id in technique_names:
            mitigation_external_id = _external_id(active[mitigation_id]) or mitigation_id
            technique_external_id = _external_id(active[technique_id]) or technique_id
            techniques_by_mitigation[mitigation_id].append(
                f"{technique_external_id}: {technique_names[technique_id]}"
            )
            mitigations_by_technique[technique_id].append(
                f"{mitigation_external_id}: {mitigation_names[mitigation_id]}"
            )

    documents = []
    supported_types = {"attack-pattern", "course-of-action", "x-mitre-tactic"}
    for obj in active.values():
        kind = obj.get("type")
        if kind not in supported_types:
            continue
        external_id = _external_id(obj)
        name = _clean(obj.get("name"))
        if not external_id or not name:
            continue

        if kind == "attack-pattern":
            title = f"{name} ({external_id})"
            url = f"https://attack.mitre.org/techniques/{external_id}/"
            phases = _unique(
                [
                    _clean(phase.get("phase_name", "")).replace("-", " ").title()
                    for phase in obj.get("kill_chain_phases", [])
                ]
            )
            fields = [
                f"ATT&CK technique: {name} ({external_id}).",
                f"Description: {_clean(obj.get('description'))}",
                f"Tactics: {', '.join(phases)}" if phases else "",
                f"Platforms: {', '.join(_unique(obj.get('x_mitre_platforms', [])))}"
                if obj.get("x_mitre_platforms")
                else "",
                f"Detection: {_clean(obj.get('x_mitre_detection'))}"
                if obj.get("x_mitre_detection")
                else "",
                f"Mitigations: {'; '.join(_unique(mitigations_by_technique[obj['id']]))}"
                if mitigations_by_technique[obj["id"]]
                else "",
            ]
        elif kind == "course-of-action":
            title = f"{name} ({external_id})"
            url = f"https://attack.mitre.org/mitigations/{external_id}/"
            targets = _unique(techniques_by_mitigation[obj["id"]])
            fields = [
                f"ATT&CK mitigation: {name} ({external_id}).",
                f"Description: {_clean(obj.get('description'))}",
                f"Techniques addressed: {'; '.join(targets)}" if targets else "",
            ]
        else:
            title = f"{name} ({external_id})"
            url = f"https://attack.mitre.org/tactics/{external_id}/"
            fields = [
                f"ATT&CK tactic: {name} ({external_id}).",
                f"Description: {_clean(obj.get('description'))}",
            ]

        documents.append(
            _make_document(
                source_id=f"mitre-attack-{external_id}",
                title=title,
                source="MITRE ATT&CK",
                url=url,
                text="\n".join(field for field in fields if field),
                source_type=kind,
                upstream_id=external_id,
                source_version=ATTACK_RELEASE,
            )
        )
    return documents


def _kev_documents(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    version = catalog.get("catalogVersion", "unknown")
    documents = []
    for item in catalog.get("vulnerabilities", []):
        cve_id = _clean(item.get("cveID"))
        if not cve_id:
            continue
        vendor = _clean(item.get("vendorProject"))
        product = _clean(item.get("product"))
        name = _clean(item.get("vulnerabilityName"))
        cwes = _unique(item.get("cwes", []))
        fields = [
            f"CISA Known Exploited Vulnerability: {cve_id} — {name}.",
            f"Vendor/project: {vendor}. Product: {product}.",
            f"Description: {_clean(item.get('shortDescription'))}",
            f"Required action: {_clean(item.get('requiredAction'))}",
            f"Date added to KEV: {_clean(item.get('dateAdded'))}. Due date: {_clean(item.get('dueDate'))}.",
            f"Known ransomware campaign use: {_clean(item.get('knownRansomwareCampaignUse'))}.",
            f"Associated CWE identifiers: {', '.join(cwes)}." if cwes else "",
            f"Additional notes: {_clean(item.get('notes'))}" if item.get("notes") else "",
        ]
        documents.append(
            _make_document(
                source_id=f"cisa-kev-{cve_id}",
                title=f"{cve_id}: {name or product}",
                source="CISA Known Exploited Vulnerabilities Catalog",
                url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                text="\n".join(field for field in fields if field),
                source_type="cisa-kev",
                upstream_id=cve_id,
                source_version=f"CISA KEV {version}",
            )
        )
    return documents


def _nvd_documents(path: Path) -> list[dict[str, Any]]:
    documents = []
    version = path.stem.removeprefix("nvdcve-2.0-")
    for record in _iter_json_array_objects(path, "vulnerabilities"):
        cve = record.get("cve", {})
        cve_id = _clean(cve.get("id"))
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        description = next(
            (_clean(item.get("value")) for item in descriptions if item.get("lang") == "en"),
            _clean(descriptions[0].get("value")) if descriptions else "",
        )
        cwes = _unique([
            _clean(item.get("value"))
            for weakness in cve.get("weaknesses", [])
            for item in weakness.get("description", [])
            if _clean(item.get("value")).startswith("CWE-")
        ])
        score_lines = []
        for metric_key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(metric_key, [])
            if not metrics:
                continue
            cvss = metrics[0].get("cvssData", {})
            version_label = _clean(cvss.get("version")) or metric_key.removeprefix("cvssMetricV")
            score_lines.append(
                f"CVSS {version_label}: score {_clean(str(cvss.get('baseScore', '')))}, "
                f"severity {_clean(cvss.get('baseSeverity', metrics[0].get('baseSeverity', '')))}, "
                f"vector {_clean(cvss.get('vectorString', ''))}."
            )
        products = []
        for configuration in cve.get("configurations", []):
            for node in configuration.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criterion = _clean(match.get("criteria"))
                    if criterion:
                        products.append(criterion)
        products = _unique(products)[:30]
        refs = _unique([
            _clean(item.get("url"))
            for item in cve.get("references", [])
            if item.get("url")
        ])[:12]
        status = _clean(cve.get("vulnStatus"))
        fields = [
            f"NVD vulnerability: {cve_id}.",
            f"Description: {description}" if description else "",
            f"Published: {_clean(cve.get('published'))}. Last modified: {_clean(cve.get('lastModified'))}.",
            f"NVD status: {status}." if status else "",
            *score_lines,
            f"Weaknesses: {', '.join(cwes)}." if cwes else "",
            f"Affected product criteria: {'; '.join(products)}." if products else "",
            f"References: {'; '.join(refs)}" if refs else "",
        ]
        documents.append(_make_document(
            source_id=f"nvd-{cve_id}",
            title=f"{cve_id}: {description[:180] or 'NVD vulnerability record'}",
            source="NIST National Vulnerability Database",
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            text="\n".join(field for field in fields if field),
            source_type="nvd-cve",
            upstream_id=cve_id,
            source_version=f"NVD CVE feed {version}",
        ))
    return documents


def main() -> None:
    for required in (ATTACK_PATH, KEV_PATH, STARTER_PATH):
        if not required.exists():
            raise FileNotFoundError(f"Required dataset is missing: {required}")

    attack = json.loads(ATTACK_PATH.read_text(encoding="utf-8"))
    kev = json.loads(KEV_PATH.read_text(encoding="utf-8"))
    starter = json.loads(STARTER_PATH.read_text(encoding="utf-8"))
    nvd_files = sorted(NVD_DIR.glob("nvdcve-2.0-*.json")) if NVD_DIR.exists() else []
    documents = _mitre_documents(attack) + _kev_documents(kev)
    for nvd_file in nvd_files:
        documents.extend(_nvd_documents(nvd_file))

    # Keep any hand-curated starter records that are not represented in the
    # selected full ATT&CK types, while deduplicating by stable source ID.
    by_source_id = {document["source_id"]: document for document in documents}
    for item in starter:
        by_source_id.setdefault(
            item["source_id"],
            _make_document(
                source_id=item["source_id"],
                title=item["title"],
                source=item["source"],
                url=item["url"],
                text=item["text"],
                source_type="curated-starter",
                upstream_id=item["source_id"],
                source_version="curated starter corpus",
            ),
        )
    documents = sorted(by_source_id.values(), key=lambda item: item["source_id"])

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8", newline="\n") as stream:
        for document in documents:
            stream.write(json.dumps(document, ensure_ascii=False) + "\n")

    output_hash = hashlib.sha256(OUTPUT_PATH.read_bytes()).hexdigest()
    manifest = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "attack_file": ATTACK_PATH.name,
            "attack_release": ATTACK_RELEASE,
            "kev_file": KEV_PATH.name,
            "kev_version": kev.get("catalogVersion"),
            "nvd_files": [path.name for path in nvd_files],
        },
        "selection": ["attack-pattern", "course-of-action", "x-mitre-tactic", "cisa-kev", "nvd-cve"],
        "document_count": len(documents),
        "counts_by_source_type": dict(Counter(doc["source_type"] for doc in documents)),
        "output_file": OUTPUT_PATH.name,
        "output_sha256": output_hash,
    }
    OUTPUT_MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Prepared {len(documents)} unique index documents.")
    for kind, count in sorted(manifest["counts_by_source_type"].items()):
        print(f"  {kind}: {count}")
    print(f"Output: {OUTPUT_PATH}")
    print(f"Manifest: {OUTPUT_MANIFEST}")


if __name__ == "__main__":
    main()
