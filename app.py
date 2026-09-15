from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ocr_pipeline import (
    OCR_MAX_PASSES,
    OCR_MIN_CONFIDENCE,
    OCR_PREPROCESS_MODE,
    analyze_document,
    analyze_plain_text,
    build_audit_manifest,
    make_run_id,
    tesseract_diagnostics,
)
from storage import get_review_decisions, init_db, persist_analysis, set_review_decision


ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "runs"
STATIC = ROOT / "static"
HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8765"))


def parse_multipart(body: bytes, content_type: str) -> dict[str, tuple[str, bytes] | str]:
    boundary_token = "boundary="
    if boundary_token not in content_type:
        return {}
    boundary = ("--" + content_type.split(boundary_token, 1)[1].split(";", 1)[0]).encode()
    fields: dict[str, tuple[str, bytes] | str] = {}
    for part in body.split(boundary):
        part = part.strip(b"\r\n")
        if not part or part == b"--" or b"\r\n\r\n" not in part:
            continue
        raw_headers, payload = part.split(b"\r\n\r\n", 1)
        headers = raw_headers.decode("utf-8", "replace")
        name = None
        filename = None
        for item in headers.split(";"):
            item = item.strip()
            if item.startswith("name="):
                name = item.split("=", 1)[1].strip('"')
            elif item.startswith("filename="):
                filename = item.split("=", 1)[1].strip('"')
        if not name:
            continue
        if filename:
            fields[name] = (Path(filename).name, payload)
        else:
            fields[name] = payload.decode("utf-8", "replace")
    return fields


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_file(STATIC / "index.html", "text/html; charset=utf-8")
        elif parsed.path.startswith("/runs/"):
            self.send_file(ROOT / parsed.path.lstrip("/"), self.guess_type(parsed.path))
        elif parsed.path in {"/health", "/api/health"}:
            self.send_json({"ok": True, "service": "secure-ocr-lab"})
        elif parsed.path == "/api/config":
            self.send_json(
                {
                    "ok": True,
                    "ocr_lang": os.environ.get("OCR_LANG", "eng"),
                    "ocr_preprocess_mode": OCR_PREPROCESS_MODE,
                    "ocr_max_passes": OCR_MAX_PASSES,
                    "ocr_min_confidence": OCR_MIN_CONFIDENCE,
                    "tesseract": tesseract_diagnostics(),
                    "port": PORT,
                }
            )
        elif parsed.path == "/api/rag-export":
            self.handle_rag_export(parsed.query)
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if self.path == "/api/review":
            self.handle_review_decision()
            return
        if self.path != "/api/analyze":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        content_type = self.headers.get("content-type", "")
        run_id = make_run_id()
        run_dir = RUNS / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        try:
            if content_type.startswith("multipart/form-data"):
                fields = parse_multipart(body, content_type)
                text = str(fields.get("text", "")).strip()
                upload = fields.get("file")
                if isinstance(upload, tuple) and upload[1]:
                    filename, data = upload
                    source = run_dir / filename
                    source.write_bytes(data)
                    result = analyze_document(source, run_dir)
                elif text:
                    result = analyze_plain_text(text, run_dir)
                else:
                    raise ValueError("Ajoute un fichier ou colle un texte.")
            else:
                params = parse_qs(body.decode("utf-8", "replace"))
                text = params.get("text", [""])[0].strip()
                if not text:
                    raise ValueError("Texte vide.")
                result = analyze_plain_text(text, run_dir)

            (run_dir / "analysis.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            audit_manifest = build_audit_manifest(result)
            (run_dir / "audit_manifest.json").write_text(
                json.dumps(audit_manifest, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            with (run_dir / "rag_records.jsonl").open("w", encoding="utf-8") as handle:
                for record in result.get("rag_records", []):
                    handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            persist_analysis(result, audit_manifest)
            self.send_json(result)
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=400)

    def handle_review_decision(self) -> None:
        try:
            length = int(self.headers.get("content-length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            decision = set_review_decision(
                run_id=str(payload.get("run_id", "")),
                target_kind=str(payload.get("target_kind", "")),
                target_id=str(payload.get("target_id", "")),
                decision=str(payload.get("decision", "")),
                note=str(payload.get("note", "")),
            )
            self.send_json({"ok": True, "decision": decision})
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, status=400)

    def handle_rag_export(self, query: str) -> None:
        params = parse_qs(query)
        run_id = params.get("run_id", [""])[0]
        policy = params.get("policy", ["raw"])[0]
        analysis_path = RUNS / run_id / "analysis.json"
        if not run_id or not analysis_path.exists():
            self.send_json({"ok": False, "error": "run_id inconnu"}, status=404)
            return
        result = json.loads(analysis_path.read_text(encoding="utf-8"))
        decisions = get_review_decisions(run_id)
        records = apply_review_policy(result.get("rag_records", []), decisions, policy)
        data = "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records)
        self.send_text(data, "application/x-ndjson; charset=utf-8")

    def send_file(self, path: Path, content_type: str) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(404)
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_text(self, payload: str, content_type: str, status: int = 200) -> None:
        data = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    @staticmethod
    def guess_type(path: str) -> str:
        if path.endswith(".png"):
            return "image/png"
        if path.endswith(".json"):
            return "application/json; charset=utf-8"
        if path.endswith(".jsonl"):
            return "application/x-ndjson; charset=utf-8"
        return "application/octet-stream"

    def log_message(self, fmt: str, *args) -> None:
        print("%s - %s" % (self.address_string(), fmt % args))


def apply_review_policy(records: list[dict], decisions: dict[str, dict], policy: str) -> list[dict]:
    exported = []
    for record in records:
        metadata = record.get("metadata", {})
        chunk_id = metadata.get("chunk_id")
        block_ids = metadata.get("block_ids", [])
        chunk_decision = decisions.get(f"chunk:{chunk_id}", {}).get("decision")
        block_decisions = [decisions.get(f"block:{block_id}", {}).get("decision") for block_id in block_ids]
        blocked = chunk_decision in {"noise", "quarantine", "needs_reocr"} or any(
            item in {"noise", "quarantine", "needs_reocr"} for item in block_decisions
        )
        needs_review = record.get("index_status") == "needs_review"
        accepted = chunk_decision == "accepted" or any(item == "accepted" for item in block_decisions)

        if policy == "reviewed":
            if blocked:
                continue
            if needs_review and not accepted:
                continue
        elif policy == "accepted":
            if not accepted or blocked:
                continue

        patched = dict(record)
        patched["review_decision"] = chunk_decision or "implicit_candidate"
        patched["export_policy"] = policy
        exported.append(patched)
    return exported


if __name__ == "__main__":
    RUNS.mkdir(exist_ok=True)
    init_db()
    print(f"Secure OCR Lab: http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
