from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEFAULT_DB_PATH = ROOT / "secure_ocr_lab.sqlite3"
VALID_DECISIONS = {"pending", "accepted", "noise", "quarantine", "needs_reocr"}
VALID_TARGETS = {"block", "chunk", "layer_comparison", "document"}


def get_db_path(db_path: Path | None = None) -> Path:
    if db_path is not None:
        return db_path
    return Path(os.environ.get("OCR_DB_PATH", DEFAULT_DB_PATH))


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = get_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path | None = None) -> None:
    with connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                source_name TEXT NOT NULL,
                source_sha256 TEXT NOT NULL,
                ocr_lang TEXT NOT NULL,
                dpi INTEGER NOT NULL,
                page_count INTEGER NOT NULL,
                chunk_count INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                analysis_json TEXT NOT NULL,
                audit_manifest_json TEXT
            );
            CREATE TABLE IF NOT EXISTS pages (
                run_id TEXT NOT NULL,
                page INTEGER NOT NULL,
                page_image_sha256 TEXT NOT NULL,
                width INTEGER NOT NULL,
                height INTEGER NOT NULL,
                image_url TEXT,
                overlay_url TEXT,
                PRIMARY KEY (run_id, page),
                FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS blocks (
                run_id TEXT NOT NULL,
                block_id TEXT NOT NULL,
                page INTEGER NOT NULL,
                kind TEXT NOT NULL,
                bbox_json TEXT NOT NULL,
                grid_cell TEXT NOT NULL,
                confidence REAL,
                block_sha256 TEXT NOT NULL,
                security_flags_json TEXT NOT NULL,
                quality_flags_json TEXT NOT NULL,
                text TEXT NOT NULL,
                PRIMARY KEY (run_id, block_id),
                FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS chunks (
                run_id TEXT NOT NULL,
                chunk_id TEXT NOT NULL,
                page INTEGER NOT NULL,
                bbox_json TEXT NOT NULL,
                chunk_sha256 TEXT NOT NULL,
                text_sha256 TEXT NOT NULL,
                block_ids_json TEXT NOT NULL,
                security_flags_json TEXT NOT NULL,
                word_count INTEGER NOT NULL,
                text TEXT NOT NULL,
                PRIMARY KEY (run_id, chunk_id),
                FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS review_decisions (
                run_id TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                target_id TEXT NOT NULL,
                decision TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (run_id, target_kind, target_id),
                FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
            """
        )


def persist_analysis(result: dict, audit_manifest: dict | None = None, db_path: Path | None = None) -> None:
    init_db(db_path)
    run_id = result["run_id"]
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO runs
            (run_id, source_name, source_sha256, ocr_lang, dpi, page_count, chunk_count, created_at, analysis_json, audit_manifest_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                result["source_name"],
                result["source_sha256"],
                result["ocr_lang"],
                result["dpi"],
                result["page_count"],
                len(result.get("chunks", [])),
                int(time.time()),
                json.dumps(result, ensure_ascii=False, sort_keys=True),
                json.dumps(audit_manifest, ensure_ascii=False, sort_keys=True) if audit_manifest else None,
            ),
        )
        for page in result.get("pages", []):
            conn.execute(
                """
                INSERT OR REPLACE INTO pages
                (run_id, page, page_image_sha256, width, height, image_url, overlay_url)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, page["page"], page["page_image_sha256"], page["width"], page["height"], page.get("image_url"), page.get("overlay_url")),
            )
            for block in page.get("blocks", []):
                conn.execute(
                    """
                    INSERT OR REPLACE INTO blocks
                    (run_id, block_id, page, kind, bbox_json, grid_cell, confidence, block_sha256,
                     security_flags_json, quality_flags_json, text)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        block["block_id"],
                        page["page"],
                        block["kind"],
                        json.dumps(block["bbox"]),
                        block["grid_cell"],
                        block.get("confidence"),
                        block["block_sha256"],
                        json.dumps(block.get("security_flags", [])),
                        json.dumps(block.get("quality_flags", [])),
                        block["text"],
                    ),
                )
        for chunk in result.get("chunks", []):
            conn.execute(
                """
                INSERT OR REPLACE INTO chunks
                (run_id, chunk_id, page, bbox_json, chunk_sha256, text_sha256, block_ids_json,
                 security_flags_json, word_count, text)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    chunk["chunk_id"],
                    chunk["page"],
                    json.dumps(chunk["bbox"]),
                    chunk["chunk_sha256"],
                    chunk["text_sha256"],
                    json.dumps(chunk.get("block_ids", [])),
                    json.dumps(chunk.get("security_flags", [])),
                    chunk["word_count"],
                    chunk["text"],
                ),
            )


def set_review_decision(run_id: str, target_kind: str, target_id: str, decision: str, note: str = "", db_path: Path | None = None) -> dict:
    if target_kind not in VALID_TARGETS:
        raise ValueError(f"target_kind invalide: {target_kind}")
    if decision not in VALID_DECISIONS:
        raise ValueError(f"decision invalide: {decision}")
    init_db(db_path)
    updated_at = int(time.time())
    with connect(db_path) as conn:
        exists = conn.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not exists:
            raise ValueError(f"run inconnu: {run_id}")
        conn.execute(
            """
            INSERT INTO review_decisions (run_id, target_kind, target_id, decision, note, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id, target_kind, target_id)
            DO UPDATE SET decision = excluded.decision, note = excluded.note, updated_at = excluded.updated_at
            """,
            (run_id, target_kind, target_id, decision, note, updated_at),
        )
    return {"run_id": run_id, "target_kind": target_kind, "target_id": target_id, "decision": decision, "note": note, "updated_at": updated_at}


def get_review_decisions(run_id: str, db_path: Path | None = None) -> dict[str, dict]:
    init_db(db_path)
    with connect(db_path) as conn:
        rows = conn.execute(
            "SELECT target_kind, target_id, decision, note, updated_at FROM review_decisions WHERE run_id = ?",
            (run_id,),
        ).fetchall()
    return {f"{row['target_kind']}:{row['target_id']}": dict(row) for row in rows}
