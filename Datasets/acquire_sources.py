"""Download pinned, first-party cybersecurity datasets into Datasets/raw."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
SOURCES = {
    "cisa-kev": {
        "path": Path("raw/cisa_known_exploited_vulnerabilities.json"),
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "license": "CC0 1.0; third-party references retain their own terms.",
        "license_file": "licenses/CISA-KEV-LICENSE.txt",
        "record_key": "vulnerabilities",
    },
    "mitre-enterprise": {
        "path": Path("raw/mitre_attack_enterprise_20.0.json"),
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json",
        "license": "MITRE ATT&CK license; reproduce the copyright designation and license with copies.",
        "license_file": "licenses/MITRE-ATTACK-LICENSE.txt",
        "record_key": "objects",
    },
}
NVD_YEAR = 2026
NVD_META_URL = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{NVD_YEAR}.meta"
NVD_ZIP_URL = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{NVD_YEAR}.json.zip"


def download_nvd_year() -> dict:
    """Download and verify an official NVD yearly CVE feed and extract its JSON."""
    target_dir = ROOT / "raw" / "nvd"
    target_dir.mkdir(parents=True, exist_ok=True)
    zip_target = target_dir / f"nvdcve-2.0-{NVD_YEAR}.json.zip"
    json_target = target_dir / f"nvdcve-2.0-{NVD_YEAR}.json"
    headers = {"User-Agent": "CyberEvidentRAG-Dataset-Acquirer/1.0"}
    if zip_target.exists() and zip_target.stat().st_size > 0:
        expected_zip = zip_target.stat().st_size
        meta = None
    else:
        with urlopen(Request(NVD_META_URL, headers=headers), timeout=60) as response:
            meta_text = response.read().decode("utf-8")
        meta = dict(line.split(":", 1) for line in meta_text.splitlines() if ":" in line)
        expected_zip = int(meta["zipSize"])
    expected_size = int(meta["size"]) if meta else None
    expected_sha = meta["sha256"].lower() if meta else None

    digest = hashlib.sha256()
    total_bytes = 0
    if zip_target.exists() and zip_target.stat().st_size == expected_zip:
        zip_temp = zip_target
        total_bytes = expected_zip
    else:
        with tempfile.NamedTemporaryFile(mode="wb", dir=target_dir, suffix=".part", delete=False) as temporary:
            zip_temp = Path(temporary.name)
    json_temp = target_dir / f".{json_target.name}.part"
    try:
        if zip_temp != zip_target:
            request = Request(NVD_ZIP_URL, headers=headers)
            with urlopen(request, timeout=180) as response, zip_temp.open("wb") as output:
                while block := response.read(1024 * 1024):
                    output.write(block)
                    digest.update(block)
                    total_bytes += len(block)
                output.flush()
                os.fsync(output.fileno())
        if total_bytes != expected_zip:
            raise ValueError(f"NVD ZIP size mismatch: expected {expected_zip}, received {total_bytes}.")

        with zipfile.ZipFile(zip_temp) as archive:
            member = f"nvdcve-2.0-{NVD_YEAR}.json"
            if member not in archive.namelist() or archive.testzip() is not None:
                raise ValueError("NVD archive failed its ZIP integrity check.")
            extracted_hash = hashlib.sha256()
            extracted_size = 0
            with archive.open(member) as source, json_temp.open("wb") as output:
                while block := source.read(1024 * 1024):
                    output.write(block)
                    extracted_hash.update(block)
                    extracted_size += len(block)
                output.flush()
                os.fsync(output.fileno())
        if expected_size is not None and (extracted_size != expected_size or extracted_hash.hexdigest().lower() != expected_sha):
            raise ValueError("NVD extracted feed failed the official size or SHA-256 check.")
        if zip_temp != zip_target:
            zip_temp.replace(zip_target)
        json_temp.replace(json_target)
    except Exception:
        if zip_temp != zip_target:
            zip_temp.unlink(missing_ok=True)
        json_temp.unlink(missing_ok=True)
        raise

    return {
        "id": f"nvd-cve-{NVD_YEAR}",
        "path": json_target.relative_to(ROOT).as_posix(),
        "archive_path": zip_target.relative_to(ROOT).as_posix(),
        "source_url": NVD_ZIP_URL,
        "metadata_url": NVD_META_URL,
        "license_summary": "NVD data is provided by NIST; check NIST terms and third-party reference rights.",
        "bytes": total_bytes,
        "uncompressed_bytes": extracted_size,
        "sha256": extracted_hash.hexdigest(),
        "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def download(name: str) -> dict:
    source = SOURCES[name]
    target = ROOT / source["path"]
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    total_bytes = 0

    request = Request(
        source["url"],
        headers={"User-Agent": "CyberEvidentRAG-Dataset-Acquirer/1.0"},
    )
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=target.parent, suffix=".part", delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with temporary_path.open("wb") as temporary:
            with urlopen(request, timeout=120) as response:
                while block := response.read(1024 * 1024):
                    temporary.write(block)
                    digest.update(block)
                    total_bytes += len(block)
            temporary.flush()
            os.fsync(temporary.fileno())
        with temporary_path.open("r", encoding="utf-8") as stream:
            payload = json.load(stream)
        records = payload.get(source["record_key"])
        if not isinstance(records, list):
            raise ValueError(f"Unexpected JSON structure for {name}.")
        temporary_path.replace(target)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise

    return {
        "id": name,
        "path": source["path"].as_posix(),
        "source_url": source["url"],
        "license_summary": source["license"],
        "license_file": source["license_file"],
        "bytes": total_bytes,
        "record_count": len(records),
        "sha256": digest.hexdigest(),
        "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        choices=[*SOURCES, "nvd-2026", "all"],
        default="all",
        help="Which first-party dataset to fetch (default: all).",
    )
    args = parser.parse_args()
    selected = [*SOURCES, "nvd-2026"] if args.source == "all" else [args.source]

    manifest_path = ROOT / "acquisition-manifest.json"
    manifest = {"entries": []}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = {entry["id"]: entry for entry in manifest.get("entries", [])}

    for name in selected:
        entry = download_nvd_year() if name == "nvd-2026" else download(name)
        entries[name] = entry
        print(
            f"{name}: {entry.get('record_count', 'records parsed during normalization')} records, "
            f"{entry['bytes']} downloaded bytes, {entry.get('uncompressed_bytes', entry['bytes'])} uncompressed bytes, "
            f"SHA-256 {entry['sha256']}"
        )

    manifest = {
        "manifest_version": 1,
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "entries": list(entries.values()),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Manifest updated: {manifest_path}")


if __name__ == "__main__":
    main()
