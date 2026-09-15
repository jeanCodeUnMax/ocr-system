from __future__ import annotations

import csv
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from textwrap import wrap

import fitz
from PIL import Image, ImageDraw, ImageFilter, ImageFont, ImageOps


OCR_LANG_REQUESTED = os.environ.get("OCR_LANG", "eng")
OCR_LANG = OCR_LANG_REQUESTED
DPI = int(os.environ.get("OCR_DPI", "220"))
MAX_CHUNK_WORDS = int(os.environ.get("MAX_CHUNK_WORDS", "500"))
MIN_CHUNK_WORDS = int(os.environ.get("MIN_CHUNK_WORDS", "120"))
PIPELINE_VERSION = "0.5.1"
SCHEMA_VERSION = "secure-ocr-lab.analysis.v2"
OCR_PREPROCESS_MODE = os.environ.get("OCR_PREPROCESS_MODE", "auto")
BINARY_THRESHOLD = int(os.environ.get("OCR_BINARY_THRESHOLD", "180"))
OCR_MIN_CONFIDENCE = float(os.environ.get("OCR_MIN_CONFIDENCE", "65"))
OCR_MAX_PASSES = int(os.environ.get("OCR_MAX_PASSES", "4"))

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s*instructions?",
    r"system\s+prompt",
    r"developer\s+mode",
    r"reveal\s+(the\s+)?prompt",
    r"bypass\s+(safety|rules|guardrails)",
    r"base64",
    r"api[_\s-]?key",
]


@dataclass
class OcrLine:
    text: str
    bbox: tuple[int, int, int, int]
    confidence: float


def make_run_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + "-" + hashlib.sha1(os.urandom(8)).hexdigest()[:8]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_payload(payload: dict) -> str:
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def analyze_document(source: Path, run_dir: Path) -> dict:
    source_hash = sha256_file(source)
    native_pages = extract_native_text_layers(source)
    images = rasterize_source(source, run_dir)
    return analyze_images(images, source.name, run_dir, source_hash, native_pages)


def analyze_plain_text(text: str, run_dir: Path) -> dict:
    source = run_dir / "pasted_text.txt"
    source.write_text(text, encoding="utf-8")
    image = render_text_to_image(text, run_dir / "page-001.png")
    return analyze_images([image], source.name, run_dir, sha256_file(source), [text])


def extract_native_text_layers(source: Path) -> list[str]:
    suffix = source.suffix.lower()
    if suffix == ".pdf":
        try:
            doc = fitz.open(source)
            return [page.get_text("text") for page in doc]
        except Exception:
            return []
    if suffix in {".txt", ".md", ".csv", ".json", ".html", ".htm"}:
        return [source.read_text(encoding="utf-8", errors="replace")]
    return []


def rasterize_source(source: Path, run_dir: Path) -> list[Path]:
    suffix = source.suffix.lower()
    if suffix == ".pdf":
        return rasterize_pdf(source, run_dir)
    if suffix in {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"}:
        return [normalize_image(source, run_dir / "page-001.png")]
    if suffix in {".txt", ".md", ".csv", ".json", ".html", ".htm"}:
        return [render_text_to_image(source.read_text(encoding="utf-8", errors="replace"), run_dir / "page-001.png")]
    raise ValueError(f"Format non supporte pour la V1: {suffix or source.name}")


def rasterize_pdf(source: Path, run_dir: Path) -> list[Path]:
    doc = fitz.open(source)
    zoom = DPI / 72
    matrix = fitz.Matrix(zoom, zoom)
    images = []
    for index, page in enumerate(doc, start=1):
        pix = page.get_pixmap(matrix=matrix, alpha=False)
        out = run_dir / f"page-{index:03d}.png"
        pix.save(out)
        images.append(out)
    return images


def normalize_image(source: Path, target: Path) -> Path:
    img = Image.open(source).convert("RGB")
    white = Image.new("RGB", img.size, "white")
    white.paste(img)
    white.save(target)
    return target


def render_text_to_image(text: str, target: Path) -> Path:
    font = load_font(26)
    lines: list[str] = []
    for paragraph in text.splitlines() or [text]:
        wrapped = wrap(paragraph, width=78) or [""]
        lines.extend(wrapped + [""])
    width = 1400
    line_height = 38
    height = max(240, 80 + line_height * len(lines))
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    y = 40
    for line in lines:
        draw.text((40, y), line, fill=(20, 24, 32), font=font)
        y += line_height
    img.save(target)
    return target


def load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    ):
        if Path(path).exists():
            return ImageFont.truetype(path, size=size)
    return ImageFont.load_default()


def analyze_images(
    images: list[Path], source_name: str, run_dir: Path, source_hash: str, native_pages: list[str] | None = None
) -> dict:
    native_pages = native_pages or []
    pages = []
    all_chunks = []
    for page_num, image_path in enumerate(images, start=1):
        page_id = f"p{page_num:03d}"
        page_hash = sha256_file(image_path)
        ocr_attempt = run_best_ocr_attempt(image_path, run_dir, page_num)
        ocr_image_path = ocr_attempt["image_path"]
        preprocessing = ocr_attempt["preprocessing"]
        lines = ocr_attempt["lines"]
        ocr_report = ocr_attempt["ocr"]
        blocks = group_lines_into_blocks(lines, page_id, page_hash, source_hash)
        page_text = "\n".join(block["text"] for block in blocks)
        native_text = native_pages[page_num - 1] if page_num - 1 < len(native_pages) else ""
        layer_comparison = compare_text_layers(page_text, native_text)
        if layer_comparison["needs_human_review"]:
            for block in blocks:
                if "native_ocr_divergence" not in block["quality_flags"]:
                    block["quality_flags"].append("native_ocr_divergence")
        chunks = make_chunks(blocks, page_num, source_name, source_hash, page_hash)
        overlay_path = draw_overlay(image_path, blocks, run_dir / f"overlay-{page_num:03d}.png")
        for chunk in chunks:
            all_chunks.append(chunk)
        width, height = Image.open(image_path).size
        pages.append(
            {
                "page": page_num,
                "page_id": page_id,
                "image_url": f"/runs/{run_dir.name}/{image_path.name}",
                "ocr_image_url": f"/runs/{run_dir.name}/{ocr_image_path.name}",
                "overlay_url": f"/runs/{run_dir.name}/{overlay_path.name}",
                "page_image_sha256": page_hash,
                "ocr_image_sha256": sha256_file(ocr_image_path),
                "width": width,
                "height": height,
                "preprocessing": preprocessing,
                "ocr": ocr_report,
                "line_count": len(lines),
                "block_count": len(blocks),
                "layers": {
                    "visual_ocr": {
                        "role": "indexable_candidate",
                        "text_sha256": hashlib.sha256(page_text.encode("utf-8")).hexdigest(),
                        "char_count": len(page_text),
                    },
                    "native_text_shadow": {
                        "role": "control_only_not_indexed",
                        "text_sha256": hashlib.sha256(native_text.encode("utf-8")).hexdigest() if native_text else None,
                        "char_count": len(native_text),
                    },
                    "comparison": layer_comparison,
                },
                "blocks": blocks,
            }
        )

    repetition_summary = detect_repeated_blocks(pages)
    review_queue = build_review_queue(pages, all_chunks, repetition_summary)
    graph = build_graph_projection(pages)
    rag_records = build_rag_records(all_chunks, pages, source_name, source_hash)

    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "pipeline_version": PIPELINE_VERSION,
        "run_id": run_dir.name,
        "source_name": source_name,
        "source_sha256": source_hash,
        "ocr_lang": resolve_tesseract_languages()["effective_lang"],
        "ocr_lang_requested": OCR_LANG_REQUESTED,
        "dpi": DPI,
        "ocr_engine": "tesseract_cli",
        "ocr_diagnostics": tesseract_diagnostics(),
        "ocr_strategy": {
            "mode": OCR_PREPROCESS_MODE,
            "max_passes": OCR_MAX_PASSES,
            "min_confidence": OCR_MIN_CONFIDENCE,
            "rule": "try image variants, score OCR output, keep best auditable image",
        },
        "ingestion_manifest": {
            "schema": "secure-ocr-lab.ingestion.v1",
            "source_name": source_name,
            "source_sha256": source_hash,
            "raster_policy": "image_first_no_native_text_indexing",
            "native_text_policy": "shadow_control_only_requires_human_approval",
            "page_hashes": [
                {
                    "page": page["page"],
                    "sha256": page["page_image_sha256"],
                    "ocr_image_sha256": page["ocr_image_sha256"],
                }
                for page in pages
            ],
            "chunk_hashes": [{"chunk_id": chunk["chunk_id"], "sha256": chunk["chunk_sha256"]} for chunk in all_chunks],
        },
        "quality_report": {
            "repetition_summary": repetition_summary,
            "review_queue": review_queue,
        },
        "graph": graph,
        "rag_records": rag_records,
        "rag_jsonl_url": f"/runs/{run_dir.name}/rag_records.jsonl",
        "rag_reviewed_jsonl_url": f"/api/rag-export?run_id={run_dir.name}&policy=reviewed",
        "audit_manifest_url": f"/runs/{run_dir.name}/audit_manifest.json",
        "page_count": len(pages),
        "pages": pages,
        "chunks": all_chunks,
        "json_url": f"/runs/{run_dir.name}/analysis.json",
    }


def run_best_ocr_attempt(source: Path, run_dir: Path, page_num: int) -> dict:
    attempts = []
    candidates = prepare_ocr_candidates(source, run_dir, page_num)
    for candidate in candidates[: max(1, OCR_MAX_PASSES)]:
        try:
            lines, report = run_tesseract(candidate["path"])
        except Exception as exc:
            lines = []
            report = {
                "engine": "tesseract_cli",
                "requested_lang": OCR_LANG_REQUESTED,
                "effective_lang": None,
                "missing_langs": [],
                "available_langs": [],
                "returncode": 1,
                "stderr": str(exc)[:1000],
                "word_count": 0,
                "line_count": 0,
                "status": "ocr_error",
            }
        report["score"] = score_ocr_lines(lines)
        report["avg_confidence"] = average_confidence(lines)
        report["preprocessing_mode"] = candidate["preprocessing"]["mode"]
        attempts.append(
            {
                "image_path": candidate["path"],
                "preprocessing": candidate["preprocessing"],
                "lines": lines,
                "ocr": report,
            }
        )
        if report["status"] == "ok" and report["avg_confidence"] >= OCR_MIN_CONFIDENCE and report["word_count"] >= 8:
            break

    best = max(attempts, key=lambda item: item["ocr"]["score"])
    best["ocr"]["attempts"] = [
        {
            "mode": item["preprocessing"]["mode"],
            "steps": item["preprocessing"]["steps"],
            "image_sha256": item["preprocessing"].get("ocr_image_sha256"),
            "status": item["ocr"]["status"],
            "word_count": item["ocr"].get("word_count", 0),
            "line_count": item["ocr"].get("line_count", 0),
            "avg_confidence": item["ocr"].get("avg_confidence"),
            "score": item["ocr"].get("score"),
        }
        for item in attempts
    ]
    best["ocr"]["selected_mode"] = best["preprocessing"]["mode"]
    if best["ocr"].get("status") == "ocr_error":
        best["ocr"]["status"] = "ocr_error"
    elif best["ocr"]["word_count"] == 0:
        best["ocr"]["status"] = "empty_ocr_result"
    elif best["ocr"]["avg_confidence"] < OCR_MIN_CONFIDENCE:
        best["ocr"]["status"] = "low_confidence"
    else:
        best["ocr"]["status"] = "ok"
    return best


def prepare_ocr_candidates(source: Path, run_dir: Path, page_num: int) -> list[dict]:
    mode = OCR_PREPROCESS_MODE.lower().strip()
    canonical = run_dir / f"page-{page_num:03d}-ocr.png"
    if mode in {"off", "none", "raw", "binary", "threshold", "auto_light", "sharp"}:
        path, preprocessing = prepare_image_for_ocr(source, canonical, mode)
        return [{"path": path, "preprocessing": preprocessing}]

    specs = [
        ("auto", canonical),
        ("binary", run_dir / f"page-{page_num:03d}-ocr-binary.png"),
        ("auto_light", run_dir / f"page-{page_num:03d}-ocr-light.png"),
        ("sharp", run_dir / f"page-{page_num:03d}-ocr-sharp.png"),
    ]
    return [{"path": path, "preprocessing": preprocessing} for path, preprocessing in (
        prepare_image_for_ocr(source, target, item_mode) for item_mode, target in specs
    )]


def prepare_image_for_ocr(source: Path, target: Path, requested_mode: str | None = None) -> tuple[Path, dict]:
    mode = (requested_mode or OCR_PREPROCESS_MODE).lower().strip()
    if mode in {"off", "none", "raw"}:
        Image.open(source).convert("RGB").save(target)
        return target, {
            "mode": "off",
            "steps": ["rgb_copy"],
            "bbox_preserved": True,
            "source_image_sha256": sha256_file(source),
        }

    original = Image.open(source).convert("RGB")
    prepared = ImageOps.grayscale(original)
    prepared = ImageOps.autocontrast(prepared)
    steps = ["grayscale", "autocontrast"]

    if mode != "auto_light":
        prepared = prepared.filter(ImageFilter.MedianFilter(size=3))
        steps.append("median_filter_3")

    if mode in {"sharp", "auto"}:
        prepared = prepared.filter(ImageFilter.UnsharpMask(radius=1.4, percent=155, threshold=3))
        steps.append("unsharp_mask")

    if mode in {"binary", "threshold"}:
        prepared = prepared.filter(ImageFilter.UnsharpMask(radius=1.2, percent=130, threshold=3))
        prepared = prepared.point(lambda pixel: 255 if pixel >= BINARY_THRESHOLD else 0, mode="1").convert("L")
        steps.append("unsharp_mask")
        steps.append(f"binary_threshold_{BINARY_THRESHOLD}")

    prepared.convert("RGB").save(target)
    return target, {
        "mode": mode if mode else "auto",
        "steps": steps,
        "bbox_preserved": True,
        "source_image_sha256": sha256_file(source),
        "ocr_image_sha256": sha256_file(target),
        "note": "same pixel dimensions as source page, so OCR bbox can be projected on the displayed page",
    }


def average_confidence(lines: list[OcrLine]) -> float:
    if not lines:
        return 0.0
    return round(sum(line.confidence for line in lines) / len(lines), 2)


def score_ocr_lines(lines: list[OcrLine]) -> float:
    if not lines:
        return 0.0
    text = " ".join(line.text for line in lines)
    word_count = count_words(text)
    char_count = len(re.sub(r"\s+", "", text))
    avg_conf = average_confidence(lines)
    return round(avg_conf * 1.5 + min(word_count, 250) * 2 + min(char_count, 2000) * 0.05, 2)


def run_tesseract(image_path: Path) -> tuple[list[OcrLine], dict]:
    lang_info = resolve_tesseract_languages()
    cmd = ["tesseract", str(image_path), "stdout", "-l", lang_info["effective_lang"], "--psm", "6", "tsv"]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    report = {
        "engine": "tesseract_cli",
        "requested_lang": OCR_LANG_REQUESTED,
        "effective_lang": lang_info["effective_lang"],
        "missing_langs": lang_info["missing_langs"],
        "available_langs": lang_info["available_langs"],
        "command": " ".join(cmd),
        "returncode": proc.returncode,
        "stderr": proc.stderr.strip()[:1000],
    }
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Erreur Tesseract CLI")
    rows = csv.DictReader(proc.stdout.splitlines(), delimiter="\t")
    raw = []
    for row in rows:
        text = (row.get("text") or "").strip()
        conf = parse_conf(row.get("conf"))
        if not text or conf < 20:
            continue
        x, y, w, h = [int(float(row.get(k) or 0)) for k in ("left", "top", "width", "height")]
        raw.append(OcrLine(text=text, bbox=(x, y, x + w, y + h), confidence=conf))
    lines = merge_words_into_lines(raw)
    report["word_count"] = len(raw)
    report["line_count"] = len(lines)
    report["status"] = "ok" if lines else "empty_ocr_result"
    return lines, report


def tesseract_diagnostics() -> dict:
    executable = shutil.which("tesseract")
    if not executable:
        return {
            "engine": "tesseract_cli",
            "available": False,
            "error": "tesseract executable not found in PATH",
            "requested_lang": OCR_LANG_REQUESTED,
        }
    lang_info = resolve_tesseract_languages()
    return {
        "engine": "tesseract_cli",
        "available": True,
        "executable": executable,
        "requested_lang": OCR_LANG_REQUESTED,
        "effective_lang": lang_info["effective_lang"],
        "missing_langs": lang_info["missing_langs"],
        "available_langs": lang_info["available_langs"],
    }


def resolve_tesseract_languages() -> dict:
    requested = [item for item in re.split(r"[+,]", OCR_LANG_REQUESTED) if item]
    available = available_tesseract_languages()
    effective = [lang for lang in requested if lang in available]
    missing = [lang for lang in requested if lang not in available]
    if not effective:
        if "eng" in available:
            effective = ["eng"]
        elif available:
            effective = [available[0]]
        else:
            raise RuntimeError("Aucune langue Tesseract disponible.")
    return {
        "requested_langs": requested,
        "available_langs": available,
        "effective_lang": "+".join(effective),
        "missing_langs": missing,
    }


def available_tesseract_languages() -> list[str]:
    if not shutil.which("tesseract"):
        raise RuntimeError("Tesseract CLI introuvable. Installe tesseract-ocr puis relance le serveur.")
    proc = subprocess.run(["tesseract", "--list-langs"], text=True, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "Impossible de lister les langues Tesseract.")
    langs = []
    for line in proc.stdout.splitlines():
        value = line.strip()
        if not value or value.lower().startswith("list of available"):
            continue
        langs.append(value)
    return sorted(langs)


def parse_conf(value: str | None) -> float:
    try:
        return float(value or -1)
    except ValueError:
        return -1


def merge_words_into_lines(words: list[OcrLine]) -> list[OcrLine]:
    if not words:
        return []
    words = sorted(words, key=lambda item: (item.bbox[1], item.bbox[0]))
    lines: list[list[OcrLine]] = []
    for word in words:
        cy = (word.bbox[1] + word.bbox[3]) / 2
        placed = False
        for line in lines:
            ly = sum((w.bbox[1] + w.bbox[3]) / 2 for w in line) / len(line)
            if abs(cy - ly) <= max(10, (word.bbox[3] - word.bbox[1]) * 0.8):
                line.append(word)
                placed = True
                break
        if not placed:
            lines.append([word])

    merged = []
    for line in lines:
        line.sort(key=lambda item: item.bbox[0])
        merged.append(
            OcrLine(
                text=" ".join(w.text for w in line),
                bbox=union_bbox([w.bbox for w in line]),
                confidence=round(sum(w.confidence for w in line) / len(line), 2),
            )
        )
    return sorted(merged, key=lambda item: (item.bbox[1], item.bbox[0]))


def group_lines_into_blocks(lines: list[OcrLine], page_id: str, page_hash: str, source_hash: str) -> list[dict]:
    blocks: list[list[OcrLine]] = []
    for line in lines:
        if not blocks:
            blocks.append([line])
            continue
        prev = blocks[-1][-1]
        vertical_gap = line.bbox[1] - prev.bbox[3]
        same_column = horizontal_overlap(line.bbox, prev.bbox) > 0.18
        if vertical_gap <= max(28, (prev.bbox[3] - prev.bbox[1]) * 1.8) and same_column:
            blocks[-1].append(line)
        else:
            blocks.append([line])

    result = []
    for idx, block_lines in enumerate(blocks, start=1):
        block_id = f"{page_id}-b{idx:03d}"
        text = "\n".join(line.text for line in block_lines).strip()
        bbox = union_bbox([line.bbox for line in block_lines])
        block_hash = hash_payload(
            {
                "source_sha256": source_hash,
                "page_sha256": page_hash,
                "block_id": block_id,
                "bbox": bbox,
                "text": text,
            }
        )
        result.append(
            {
                "block_id": block_id,
                "kind": classify_block(text),
                "bbox": bbox,
                "grid_cell": grid_cell(bbox),
                "confidence": round(sum(line.confidence for line in block_lines) / len(block_lines), 2),
                "text": text,
                "block_sha256": block_hash,
                "security_flags": security_flags(text),
                "quality_flags": quality_flags(text, block_lines),
                "review_status": "pending",
                "source_ref": {
                    "source_sha256": source_hash,
                    "page_id": page_id,
                    "page_sha256": page_hash,
                    "bbox": bbox,
                    "grid_cell": grid_cell(bbox),
                },
                "lines": [
                    {"text": line.text, "bbox": line.bbox, "confidence": line.confidence}
                    for line in block_lines
                ],
            }
        )
    return result


def make_chunks(blocks: list[dict], page: int, source_name: str, source_hash: str, page_hash: str) -> list[dict]:
    chunks = []
    current: list[dict] = []
    current_words = 0
    for block in blocks:
        words = count_words(block["text"])
        if current and current_words + words > MAX_CHUNK_WORDS:
            chunks.append(build_chunk(current, page, source_name, source_hash, page_hash, len(chunks) + 1))
            current = []
            current_words = 0
        current.append(block)
        current_words += words
        if current_words >= MIN_CHUNK_WORDS and block["text"].rstrip().endswith((".", "!", "?", ":")):
            chunks.append(build_chunk(current, page, source_name, source_hash, page_hash, len(chunks) + 1))
            current = []
            current_words = 0
    if current:
        chunks.append(build_chunk(current, page, source_name, source_hash, page_hash, len(chunks) + 1))
    return chunks


def build_chunk(blocks: list[dict], page: int, source_name: str, source_hash: str, page_hash: str, index: int) -> dict:
    text = "\n\n".join(block["text"] for block in blocks)
    flags = sorted({flag for block in blocks for flag in block["security_flags"]})
    bbox = union_bbox([tuple(block["bbox"]) for block in blocks])
    chunk_id = f"p{page:03d}-c{index:03d}"
    block_hashes = [block["block_sha256"] for block in blocks]
    chunk_hash = hash_payload(
        {
            "source_sha256": source_hash,
            "page_sha256": page_hash,
            "chunk_id": chunk_id,
            "block_hashes": block_hashes,
            "bbox": bbox,
            "text": text,
        }
    )
    return {
        "chunk_id": chunk_id,
        "source_name": source_name,
        "source_sha256": source_hash,
        "page": page,
        "page_sha256": page_hash,
        "block_ids": [block["block_id"] for block in blocks],
        "block_hashes": block_hashes,
        "bbox": bbox,
        "grid_cells": sorted({block["grid_cell"] for block in blocks}),
        "word_count": count_words(text),
        "security_flags": flags,
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "chunk_sha256": chunk_hash,
        "source_ref": {
            "source_sha256": source_hash,
            "page_id": f"p{page:03d}",
            "page_sha256": page_hash,
            "bbox": bbox,
            "grid_cells": sorted({block["grid_cell"] for block in blocks}),
            "block_ids": [block["block_id"] for block in blocks],
            "block_hashes": block_hashes,
        },
        "evidence_chain": {
            "source_sha256": source_hash,
            "page_sha256": page_hash,
            "block_hashes": block_hashes,
            "chunk_sha256": chunk_hash,
        },
        "text": text,
    }


def draw_overlay(image_path: Path, blocks: list[dict], target: Path) -> Path:
    img = Image.open(image_path).convert("RGB")
    draw = ImageDraw.Draw(img, "RGBA")
    for block in blocks:
        x1, y1, x2, y2 = block["bbox"]
        color = (21, 120, 255, 60) if not block["security_flags"] else (230, 70, 40, 80)
        outline = (21, 120, 255, 230) if not block["security_flags"] else (230, 70, 40, 240)
        draw.rectangle((x1, y1, x2, y2), fill=color, outline=outline, width=3)
        draw.text((x1 + 4, max(0, y1 - 14)), block["block_id"], fill=outline)
    img.save(target)
    return target


def classify_block(text: str) -> str:
    if len(text) < 80 and text.endswith(":"):
        return "heading_or_label"
    if re.search(r"\b(if|then|else|condition|action|class|table|foreign key)\b", text, re.I):
        return "possible_logic_or_schema"
    return "paragraph"


def security_flags(text: str) -> list[str]:
    flags = []
    lowered = text.lower()
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, lowered, re.I):
            flags.append("possible_prompt_injection")
            break
    if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", text):
        flags.append("possible_encoded_payload")
    return flags


def quality_flags(text: str, lines: list[OcrLine]) -> list[str]:
    flags = []
    avg_conf = sum(line.confidence for line in lines) / max(1, len(lines))
    if avg_conf < 65:
        flags.append("low_ocr_confidence")
    if count_words(text) <= 2:
        flags.append("too_short_for_semantic_chunk")
    return flags


def compare_text_layers(ocr_text: str, native_text: str) -> dict:
    if not native_text.strip():
        return {
            "available": False,
            "similarity": None,
            "needs_human_review": False,
            "flags": [],
            "note": "no_native_text_layer",
        }
    ocr_norm = normalize_text_for_compare(ocr_text)
    native_norm = normalize_text_for_compare(native_text)
    similarity = round(difflib.SequenceMatcher(None, ocr_norm, native_norm).ratio(), 4)
    flags = []
    if similarity < 0.72:
        flags.append("native_ocr_divergence")
    if len(native_norm) > len(ocr_norm) * 1.35 and len(native_norm) - len(ocr_norm) > 80:
        flags.append("native_has_extra_text")
    if len(ocr_norm) > len(native_norm) * 1.35 and len(ocr_norm) - len(native_norm) > 80:
        flags.append("ocr_has_extra_text")
    return {
        "available": True,
        "similarity": similarity,
        "needs_human_review": bool(flags),
        "flags": flags,
        "native_preview": native_text.strip()[:500],
    }


def detect_repeated_blocks(pages: list[dict]) -> list[dict]:
    seen: dict[str, list[dict]] = {}
    for page in pages:
        for block in page["blocks"]:
            key = normalize_text_for_compare(block["text"])
            if len(key) < 20:
                continue
            seen.setdefault(key, []).append(
                {
                    "page": page["page"],
                    "block_id": block["block_id"],
                    "bbox": block["bbox"],
                    "grid_cell": block["grid_cell"],
                    "text": block["text"][:160],
                }
            )
    repeated = []
    for key, hits in seen.items():
        if len(hits) >= 3:
            repeated.append(
                {
                    "count": len(hits),
                    "candidate_kind": "repeated_header_footer_or_boilerplate",
                    "text_fingerprint": hashlib.sha256(key.encode("utf-8")).hexdigest(),
                    "sample": hits[0]["text"],
                    "hits": hits,
                }
            )
            hit_ids = {hit["block_id"] for hit in hits}
            for page in pages:
                for block in page["blocks"]:
                    if block["block_id"] in hit_ids and "repeated_boilerplate_candidate" not in block["quality_flags"]:
                        block["quality_flags"].append("repeated_boilerplate_candidate")
    return repeated


def build_review_queue(pages: list[dict], chunks: list[dict], repeated: list[dict]) -> list[dict]:
    queue = []
    repeated_ids = {hit["block_id"] for item in repeated for hit in item["hits"]}
    for page in pages:
        ocr_status = page.get("ocr", {}).get("status")
        if ocr_status in {"empty_ocr_result", "low_confidence", "ocr_error"}:
            reason_by_status = {
                "empty_ocr_result": "ocr_engine_returned_no_text",
                "low_confidence": "ocr_engine_low_confidence_after_image_retries",
                "ocr_error": "ocr_engine_failed",
            }
            queue.append(
                {
                    "review_id": f"{page['page_id']}-{ocr_status}",
                    "kind": "page",
                    "page": page["page"],
                    "reason": reason_by_status[ocr_status],
                    "flags": [ocr_status],
                    "suggested_action": "inspect_ocr_attempts_or_try_other_backend",
                }
            )
        comparison = page["layers"]["comparison"]
        if comparison["needs_human_review"]:
            queue.append(
                {
                    "review_id": f"{page['page_id']}-layer-diff",
                    "kind": "layer_comparison",
                    "page": page["page"],
                    "reason": "native_text_differs_from_visual_ocr",
                    "flags": comparison["flags"],
                    "suggested_action": "inspect_visual_page_before_indexing",
                }
            )
        for block in page["blocks"]:
            flags = block["security_flags"] + block["quality_flags"]
            if not flags and block["block_id"] not in repeated_ids:
                continue
            queue.append(
                {
                    "review_id": f"{block['block_id']}-review",
                    "kind": "block",
                    "page": page["page"],
                    "block_id": block["block_id"],
                    "bbox": block["bbox"],
                    "flags": flags,
                    "suggested_action": "accept_or_mark_noise",
                }
            )
    for chunk in chunks:
        if chunk["security_flags"]:
            queue.append(
                {
                    "review_id": f"{chunk['chunk_id']}-review",
                    "kind": "chunk",
                    "page": chunk["page"],
                    "chunk_id": chunk["chunk_id"],
                    "bbox": chunk["bbox"],
                    "flags": chunk["security_flags"],
                    "suggested_action": "quarantine_or_accept_after_human_review",
                }
            )
    return queue


def build_rag_records(chunks: list[dict], pages: list[dict], source_name: str, source_hash: str) -> list[dict]:
    page_by_num = {page["page"]: page for page in pages}
    records = []
    document_tags = infer_document_tags("\n".join(chunk["text"] for chunk in chunks), source_name)
    for chunk in chunks:
        page = page_by_num.get(chunk["page"], {})
        confidence = chunk_confidence(chunk, page)
        index_status = "needs_review" if chunk["security_flags"] else "candidate"
        records.append(
            {
                "id": f"{source_hash[:16]}:{chunk['chunk_id']}",
                "embedding_text": contextualize_for_embedding(chunk, document_tags),
                "raw_text": chunk["text"],
                "index_status": index_status,
                "tags": sorted(set(document_tags + chunk["grid_cells"] + chunk["security_flags"])),
                "metadata": {
                    "source_name": source_name,
                    "source_sha256": source_hash,
                    "page": chunk["page"],
                    "page_sha256": chunk["page_sha256"],
                    "chunk_id": chunk["chunk_id"],
                    "chunk_sha256": chunk["chunk_sha256"],
                    "text_sha256": chunk["text_sha256"],
                    "bbox": chunk["bbox"],
                    "grid_cells": chunk["grid_cells"],
                    "block_ids": chunk["block_ids"],
                    "block_hashes": chunk["block_hashes"],
                    "ocr_confidence": confidence,
                    "source_image_url": page.get("image_url"),
                    "source_overlay_url": page.get("overlay_url"),
                    "review_policy": "index_only_after_human_acceptance_when_flagged",
                },
            }
        )
    return records


def build_graph_projection(pages: list[dict]) -> dict:
    nodes = []
    edges = []
    by_label: dict[str, str] = {}
    for page in pages:
        for block in page.get("blocks", []):
            snippet = " ".join(block["text"].split())[:120]
            node_id = block["block_id"]
            label = normalize_relation_label(snippet)
            nodes.append(
                {
                    "node_id": node_id,
                    "page": page["page"],
                    "bbox": block["bbox"],
                    "grid_cell": block["grid_cell"],
                    "kind": block["kind"],
                    "text_preview": snippet,
                    "source_ref": block["source_ref"],
                }
            )
            if label:
                by_label.setdefault(label, node_id)

    for page in pages:
        for block in page.get("blocks", []):
            for source_label, relation, target_label in extract_text_relations(block["text"]):
                source_id = by_label.get(normalize_relation_label(source_label), block["block_id"])
                target_id = by_label.get(normalize_relation_label(target_label))
                edges.append(
                    {
                        "edge_id": f"e{len(edges) + 1:03d}",
                        "source_node_id": source_id,
                        "target_node_id": target_id,
                        "relation": relation,
                        "confidence": 0.45 if target_id else 0.25,
                        "evidence_text": f"{source_label} {relation} {target_label}",
                        "status": "candidate_text_relation" if target_id else "unresolved_target",
                        "page": page["page"],
                        "bbox": block["bbox"],
                    }
                )

    return {
        "schema": "secure-ocr-lab.graph.v1",
        "mode": "text_relation_projection",
        "status": "candidate",
        "nodes": nodes,
        "edges": edges,
        "limitations": [
            "Visual arrow and connector detection is intentionally a V4 skeleton.",
            "Use OpenCV or a vision-language model before trusting visual graph edges.",
        ],
    }


def extract_text_relations(text: str) -> list[tuple[str, str, str]]:
    relations = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        match = re.search(r"(.{1,60}?)(->|=>)(.{1,60})", line)
        if match:
            relations.append((match.group(1).strip(), match.group(2), match.group(3).strip()))
            continue
        match = re.search(r"\bif\s+(.{1,80}?)\s+then\s+(.{1,80})", line, re.I)
        if match:
            relations.append((match.group(1).strip(), "if_then", match.group(2).strip()))
    return relations


def normalize_relation_label(value: str) -> str:
    value = normalize_text_for_compare(value)
    words = value.split()
    return " ".join(words[:8])


def build_audit_manifest(result: dict) -> dict:
    review_queue = result.get("quality_report", {}).get("review_queue", [])
    return {
        "schema": "secure-ocr-lab.audit.v1",
        "analysis_schema_version": result.get("schema_version"),
        "pipeline_version": result.get("pipeline_version"),
        "run_id": result["run_id"],
        "source_name": result["source_name"],
        "source_sha256": result["source_sha256"],
        "ocr_lang": result["ocr_lang"],
        "dpi": result["dpi"],
        "raster_policy": result["ingestion_manifest"]["raster_policy"],
        "native_text_policy": result["ingestion_manifest"]["native_text_policy"],
        "page_hashes": result["ingestion_manifest"]["page_hashes"],
        "chunk_hashes": result["ingestion_manifest"]["chunk_hashes"],
        "preprocessing": [
            {
                "page": page["page"],
                "mode": page["preprocessing"]["mode"],
                "steps": page["preprocessing"]["steps"],
                "ocr_image_sha256": page["ocr_image_sha256"],
            }
            for page in result.get("pages", [])
        ],
        "review_required_count": len(review_queue),
        "rag_record_count": len(result.get("rag_records", [])),
        "graph_node_count": len(result.get("graph", {}).get("nodes", [])),
        "graph_edge_count": len(result.get("graph", {}).get("edges", [])),
        "evidence_model": {
            "parent": "source_sha256",
            "children": ["page_image_sha256", "block_sha256", "chunk_sha256"],
            "lookup_keys": ["run_id", "page", "bbox", "chunk_id", "block_ids"],
        },
    }


def contextualize_for_embedding(chunk: dict, document_tags: list[str]) -> str:
    context = [
        f"Document tags: {', '.join(document_tags) if document_tags else 'unknown'}",
        f"Source: {chunk['source_name']}",
        f"Page: {chunk['page']}",
        f"Grid: {', '.join(chunk['grid_cells'])}",
        "",
        chunk["text"],
    ]
    return "\n".join(context).strip()


def infer_document_tags(text: str, source_name: str) -> list[str]:
    haystack = f"{source_name}\n{text}".lower()
    tags = []
    if re.search(r"\b(receipt|ticket|total|tva|vat|cash|cb|euros?|€)\b", haystack):
        tags.append("document:receipt")
    if re.search(r"\b(invoice|facture|amount due|siret|iban)\b", haystack):
        tags.append("document:invoice")
    if re.search(r"\b(class|table|foreign key|primary key|schema|database)\b", haystack):
        tags.append("document:schema_or_database")
    if re.search(r"\b(condition|action|workflow|task|step|then|else)\b", haystack):
        tags.append("document:workflow_or_logic")
    if not tags:
        tags.append("document:unknown")
    return tags


def chunk_confidence(chunk: dict, page: dict) -> float | None:
    block_ids = set(chunk["block_ids"])
    values = [
        block["confidence"]
        for block in page.get("blocks", [])
        if block["block_id"] in block_ids and isinstance(block.get("confidence"), (int, float))
    ]
    if not values:
        return None
    return round(sum(values) / len(values), 2)


def normalize_text_for_compare(text: str) -> str:
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[^\w\s.,:;!?€$%-]", "", text, flags=re.UNICODE)
    return text.strip()


def grid_cell(bbox: tuple[int, int, int, int], cols: int = 8, rows: int = 8) -> str:
    x1, y1, x2, y2 = bbox
    cx = (x1 + x2) / 2
    cy = (y1 + y2) / 2
    col = min(cols, max(1, int(cx / 1400 * cols) + 1))
    row = min(rows, max(1, int(cy / 2000 * rows) + 1))
    return f"R{row}C{col}"


def count_words(text: str) -> int:
    return len(re.findall(r"\w+", text, flags=re.UNICODE))


def union_bbox(boxes: list[tuple[int, int, int, int]]) -> tuple[int, int, int, int]:
    return (
        min(box[0] for box in boxes),
        min(box[1] for box in boxes),
        max(box[2] for box in boxes),
        max(box[3] for box in boxes),
    )


def horizontal_overlap(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> float:
    overlap = max(0, min(a[2], b[2]) - max(a[0], b[0]))
    width = max(1, min(a[2] - a[0], b[2] - b[0]))
    return overlap / width
