from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

# Import conditionnel de Pillow et PyMuPDF
try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import pymupdf as fitz
    HAS_FITZ = True
except ImportError:
    try:
        import fitz
        HAS_FITZ = True
    except ImportError:
        HAS_FITZ = False


SUSPICIOUS_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+in\s+developer\s+mode", re.IGNORECASE),
    re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
    re.compile(r"base64\s*,\s*[A-Za-z0-9+/=]{40,}", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
]


def sha256_bytes(data: bytes) -> str:
    """Calcule le hash SHA-256 d'une chaîne binaire."""
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    """Calcule le hash SHA-256 d'un texte encodé en UTF-8."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_run_id() -> str:
    """Génère un identifiant d'exécution unique et horodaté."""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    rand_suffix = uuid.uuid4().hex[:6]
    return f"run_{timestamp}_{rand_suffix}"


def find_tesseract_binary() -> str | None:
    """Détecte l'exécutable Tesseract CLI dans le PATH ou dans les dossiers Windows standards."""
    found = shutil.which("tesseract")
    if found:
        return found
    candidate_paths = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        r"D:\Program Files\Tesseract-OCR\tesseract.exe",
        os.path.expanduser(r"~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"),
    ]
    for candidate in candidate_paths:
        if os.path.isfile(candidate):
            return candidate
    return None


def detect_grid_cell(bbox: list[int], width: int, height: int, rows: int = 4, cols: int = 4) -> str:
    """Calcule la cellule de grille (ex: R1C1) correspondant au centre de la boîte englobante."""
    if width <= 0 or height <= 0:
        return "R1C1"
    center_x = (bbox[0] + bbox[2]) / 2.0
    center_y = (bbox[1] + bbox[3]) / 2.0
    col_idx = min(cols, max(1, int(math.floor((center_x / width) * cols)) + 1))
    row_idx = min(rows, max(1, int(math.floor((center_y / height) * rows)) + 1))
    return f"R{row_idx}C{col_idx}"


def detect_security_flags(text: str, native_text_diff: bool = False) -> list[str]:
    """Détecte les anomalies de sécurité (prompt injection, dissimulation, mismatch shadow layer)."""
    flags = []
    if native_text_diff:
        flags.append("shadow_mismatch")
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(text):
            flags.append("prompt_injection_suspect")
            break
    # Détection de texte à haute entropie ou chaînes obfusquées
    words = text.split()
    if any(len(w) > 45 and not w.startswith("http") for w in words):
        flags.append("obfuscated_token")
    return flags


def detect_quality_flags(confidence: float | None, text: str) -> list[str]:
    """Évalue la qualité optique d'un bloc de texte OCR."""
    flags = []
    if confidence is not None and confidence < 0.60:
        flags.append("low_confidence")
    if text.strip() and sum(1 for c in text if not c.isalnum() and not c.isspace()) / len(text) > 0.40:
        flags.append("noisy_characters")
    return flags


def run_tesseract_tsv(image_path: Path, lang: str, dpi: int) -> list[dict]:
    """Exécute Tesseract CLI pour extraire les blocs de texte avec coordonnées précises (TSV)."""
    tess_bin = find_tesseract_binary()
    if not tess_bin:
        return []

    cmd = [tess_bin, str(image_path), "stdout", "-l", lang, "--dpi", str(dpi), "tsv"]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=60)
        tsv_output = proc.stdout.decode("utf-8", "replace")
    except Exception:
        return []

    blocks_dict: dict[int, dict] = {}
    reader = csv.DictReader(io.StringIO(tsv_output), delimiter="\t")
    for row in reader:
        text = (row.get("text") or "").strip()
        conf_raw = row.get("conf", "-1")
        try:
            conf = float(conf_raw) / 100.0
        except ValueError:
            conf = -1.0
        if not text or conf < 0:
            continue

        try:
            left = int(row.get("left", 0))
            top = int(row.get("top", 0))
            width = int(row.get("width", 0))
            height = int(row.get("height", 0))
            block_num = int(row.get("block_num", 1))
        except (ValueError, TypeError):
            continue

        bbox = [left, top, left + width, top + height]
        if block_num not in blocks_dict:
            blocks_dict[block_num] = {
                "words": [text],
                "bbox": bbox,
                "confs": [conf],
            }
        else:
            entry = blocks_dict[block_num]
            entry["words"].append(text)
            entry["confs"].append(conf)
            # Agrandir la bbox pour englober tous les mots du bloc
            entry["bbox"] = [
                min(entry["bbox"][0], bbox[0]),
                min(entry["bbox"][1], bbox[1]),
                max(entry["bbox"][2], bbox[2]),
                max(entry["bbox"][3], bbox[3]),
            ]

    result_blocks = []
    for b_num, entry in sorted(blocks_dict.items()):
        text_joined = " ".join(entry["words"]).strip()
        if not text_joined:
            continue
        avg_conf = sum(entry["confs"]) / len(entry["confs"]) if entry["confs"] else 0.8
        result_blocks.append({
            "block_index": b_num,
            "text": text_joined,
            "bbox": entry["bbox"],
            "confidence": round(avg_conf, 3),
        })
    return result_blocks


def draw_bounding_boxes(image_path: Path, output_overlay_path: Path, blocks: list[dict]) -> None:
    """Dessine les boîtes englobantes (bbox) sur une copie de l'image de la page pour le contrôle visuel."""
    if not HAS_PIL or not image_path.exists():
        return
    try:
        with Image.open(image_path) as img:
            overlay = img.convert("RGBA")
            draw = ImageDraw.Draw(overlay)
            for block in blocks:
                bbox = block.get("bbox", [0, 0, 0, 0])
                flags = block.get("security_flags", [])
                color = (239, 68, 68, 220) if flags else (59, 130, 246, 200)
                fill_color = (239, 68, 68, 40) if flags else (59, 130, 246, 25)
                draw.rectangle(bbox, outline=color, fill=fill_color, width=2)
            # Sauvegarde en PNG
            overlay.convert("RGB").save(output_overlay_path, "PNG")
    except Exception:
        pass


def chunk_blocks(blocks: list[dict], page_num: int, target_words: int = 150) -> list[dict]:
    """Regroupe les blocs d'une page en chunks sémantiques cohérents avec calcul de preuve SHA-256."""
    chunks = []
    current_blocks: list[dict] = []
    current_words = 0
    chunk_index = 1

    def flush_chunk():
        nonlocal chunk_index, current_blocks, current_words
        if not current_blocks:
            return
        chunk_text = "\n\n".join(b["text"] for b in current_blocks).strip()
        block_ids = [b["block_id"] for b in current_blocks]
        block_hashes = [b["block_sha256"] for b in current_blocks]

        # Calcul de la bbox englobante
        min_x = min(b["bbox"][0] for b in current_blocks)
        min_y = min(b["bbox"][1] for b in current_blocks)
        max_x = max(b["bbox"][2] for b in current_blocks)
        max_y = max(b["bbox"][3] for b in current_blocks)
        chunk_bbox = [min_x, min_y, max_x, max_y]

        # Empreintes cryptographiques
        text_hash = sha256_text(chunk_text)
        chunk_lineage = f"{text_hash}:" + ",".join(block_hashes)
        chunk_hash = sha256_text(chunk_lineage)

        # Agrégation des drapeaux de sécurité
        all_sec_flags = []
        for b in current_blocks:
            for f in b.get("security_flags", []):
                if f not in all_sec_flags:
                    all_sec_flags.append(f)

        chunk_id = f"c_p{page_num}_{chunk_index}"
        chunks.append({
            "chunk_id": chunk_id,
            "page": page_num,
            "bbox": chunk_bbox,
            "chunk_sha256": chunk_hash,
            "text_sha256": text_hash,
            "block_ids": block_ids,
            "block_hashes": block_hashes,
            "security_flags": all_sec_flags,
            "word_count": len(chunk_text.split()),
            "text": chunk_text,
        })
        chunk_index += 1
        current_blocks = []
        current_words = 0

    for block in blocks:
        words_in_block = len(block["text"].split())
        if current_words + words_in_block > target_words and current_blocks:
            flush_chunk()
        current_blocks.append(block)
        current_words += words_in_block

    flush_chunk()
    return chunks


def analyze_document(source_path: Path, run_dir: Path) -> dict[str, Any]:
    """Pipeline d'analyse documentaire image-first avec auditabilité complète et shadow layer."""
    run_id = run_dir.name
    source_bytes = source_path.read_bytes()
    source_sha256 = sha256_bytes(source_bytes)
    ocr_lang = os.environ.get("OCR_LANG", "eng")
    dpi = int(os.environ.get("OCR_DPI", "200"))

    pages: list[dict] = []
    all_chunks: list[dict] = []
    rag_records: list[dict] = []

    ext = source_path.suffix.lower()

    if ext == ".pdf" and HAS_FITZ:
        doc = fitz.open(source_path)
        page_count = len(doc)

        for page_idx in range(page_count):
            page_num = page_idx + 1
            doc_page = doc[page_idx]

            # 1. Rasterisation Image-First
            pix = doc_page.get_pixmap(dpi=dpi)
            page_image_name = f"page_{page_num}.png"
            page_image_path = run_dir / page_image_name
            pix.save(page_image_path)
            image_bytes = page_image_path.read_bytes()
            page_image_sha256 = sha256_bytes(image_bytes)
            width, height = pix.width, pix.height

            # 2. Extraction du texte natif (Couche Shadow)
            native_text = doc_page.get_text() or ""
            native_text_cleaned = re.sub(r"\s+", " ", native_text).strip()

            # 3. Extraction OCR sur l'image rasterisée
            tess_blocks = run_tesseract_tsv(page_image_path, lang=ocr_lang, dpi=dpi)

            page_blocks = []
            if tess_blocks:
                # Utilisation des résultats Tesseract CLI
                for idx, t_block in enumerate(tess_blocks):
                    block_id = f"b_p{page_num}_{idx + 1}"
                    text = t_block["text"]
                    bbox = t_block["bbox"]
                    conf = t_block["confidence"]
                    grid = detect_grid_cell(bbox, width, height)
                    sec_flags = detect_security_flags(text)
                    qual_flags = detect_quality_flags(conf, text)
                    page_blocks.append({
                        "block_id": block_id,
                        "kind": "heading" if len(text.split()) < 8 and idx == 0 else "text",
                        "bbox": bbox,
                        "grid_cell": grid,
                        "confidence": conf,
                        "block_sha256": sha256_text(text),
                        "security_flags": sec_flags,
                        "quality_flags": qual_flags,
                        "text": text,
                    })
            else:
                # Fallback haute fidélité via PyMuPDF (mise à l'échelle DPI)
                scale = dpi / 72.0
                raw_blocks = doc_page.get_text("blocks")
                for idx, b in enumerate(raw_blocks):
                    text = (b[4] or "").strip()
                    if not text:
                        continue
                    block_id = f"b_p{page_num}_{idx + 1}"
                    bbox = [int(b[0] * scale), int(b[1] * scale), int(b[2] * scale), int(b[3] * scale)]
                    grid = detect_grid_cell(bbox, width, height)
                    sec_flags = detect_security_flags(text)
                    qual_flags = detect_quality_flags(0.95, text)
                    page_blocks.append({
                        "block_id": block_id,
                        "kind": "text",
                        "bbox": bbox,
                        "grid_cell": grid,
                        "confidence": 0.95,
                        "block_sha256": sha256_text(text),
                        "security_flags": sec_flags,
                        "quality_flags": qual_flags,
                        "text": text,
                    })

            # 4. Détection des divergences Couche Shadow vs OCR Visible
            visible_text_page = " ".join(b["text"] for b in page_blocks)
            if native_text_cleaned and len(native_text_cleaned) > len(visible_text_page) * 1.5:
                # Texte invisible ou caché présent dans le PDF natif
                for b in page_blocks:
                    if "shadow_mismatch" not in b["security_flags"]:
                        b["security_flags"].append("shadow_mismatch")

            # 5. Génération de l'image de superposition avec Bounding Boxes
            overlay_name = f"page_{page_num}_overlay.png"
            overlay_path = run_dir / overlay_name
            draw_bounding_boxes(page_image_path, overlay_path, page_blocks)

            # 6. Découpage en chunks pour la page
            page_chunks = chunk_blocks(page_blocks, page_num)
            all_chunks.extend(page_chunks)

            pages.append({
                "page": page_num,
                "page_image_sha256": page_image_sha256,
                "width": width,
                "height": height,
                "image_url": f"/runs/{run_id}/{page_image_name}",
                "overlay_url": f"/runs/{run_id}/{overlay_name}" if overlay_path.exists() else None,
                "blocks": page_blocks,
                "shadow_layer": {
                    "native_text_length": len(native_text_cleaned),
                    "visible_text_length": len(visible_text_page),
                    "has_shadow_mismatch": any("shadow_mismatch" in b["security_flags"] for b in page_blocks),
                },
            })

    else:
        # Traitement pour Images (PNG, JPG, TIFF, etc.)
        page_count = 1
        page_image_path = run_dir / f"page_1.png"

        if HAS_PIL:
            try:
                with Image.open(source_path) as img:
                    img.convert("RGB").save(page_image_path, "PNG")
                    width, height = img.width, img.height
            except Exception:
                page_image_path.write_bytes(source_bytes)
                width, height = 1200, 1600
        else:
            page_image_path.write_bytes(source_bytes)
            width, height = 1200, 1600

        page_image_sha256 = sha256_bytes(page_image_path.read_bytes())
        tess_blocks = run_tesseract_tsv(page_image_path, lang=ocr_lang, dpi=dpi)

        page_blocks = []
        if tess_blocks:
            for idx, t_block in enumerate(tess_blocks):
                block_id = f"b_p1_{idx + 1}"
                text = t_block["text"]
                bbox = t_block["bbox"]
                conf = t_block["confidence"]
                page_blocks.append({
                    "block_id": block_id,
                    "kind": "text",
                    "bbox": bbox,
                    "grid_cell": detect_grid_cell(bbox, width, height),
                    "confidence": conf,
                    "block_sha256": sha256_text(text),
                    "security_flags": detect_security_flags(text),
                    "quality_flags": detect_quality_flags(conf, text),
                    "text": text,
                })
        else:
            # Fallback basique image
            block_id = "b_p1_1"
            sample_text = f"[Image rasterisée sans Tesseract CLI - {source_path.name}]"
            page_blocks.append({
                "block_id": block_id,
                "kind": "image_placeholder",
                "bbox": [50, 50, width - 50, height - 50],
                "grid_cell": "R1C1",
                "confidence": 0.50,
                "block_sha256": sha256_text(sample_text),
                "security_flags": [],
                "quality_flags": ["no_tesseract"],
                "text": sample_text,
            })

        overlay_path = run_dir / "page_1_overlay.png"
        draw_bounding_boxes(page_image_path, overlay_path, page_blocks)
        page_chunks = chunk_blocks(page_blocks, 1)
        all_chunks.extend(page_chunks)

        pages.append({
            "page": 1,
            "page_image_sha256": page_image_sha256,
            "width": width,
            "height": height,
            "image_url": f"/runs/{run_id}/page_1.png",
            "overlay_url": f"/runs/{run_id}/page_1_overlay.png" if overlay_path.exists() else None,
            "blocks": page_blocks,
        })

    # Construction des enregistrements RAG auditables
    for chunk in all_chunks:
        needs_review = bool(chunk["security_flags"])
        rag_records.append({
            "chunk_id": chunk["chunk_id"],
            "text": chunk["text"],
            "index_status": "needs_review" if needs_review else "ready",
            "metadata": {
                "run_id": run_id,
                "source_name": source_path.name,
                "source_sha256": source_sha256,
                "page": chunk["page"],
                "chunk_id": chunk["chunk_id"],
                "chunk_sha256": chunk["chunk_sha256"],
                "text_sha256": chunk["text_sha256"],
                "block_ids": chunk["block_ids"],
                "block_hashes": chunk.get("block_hashes", []),
                "bbox": chunk["bbox"],
                "security_flags": chunk["security_flags"],
                "word_count": chunk["word_count"],
            },
        })

    return {
        "run_id": run_id,
        "source_name": source_path.name,
        "source_sha256": source_sha256,
        "ocr_lang": ocr_lang,
        "dpi": dpi,
        "page_count": len(pages),
        "pages": pages,
        "chunks": all_chunks,
        "rag_records": rag_records,
    }


def analyze_plain_text(text: str, run_dir: Path) -> dict[str, Any]:
    """Analyse un texte brut collé en créant une représentation visuelle et des blocs vérifiables."""
    run_id = run_dir.name
    text_clean = text.strip()
    source_sha256 = sha256_text(text_clean)
    ocr_lang = os.environ.get("OCR_LANG", "eng")
    dpi = int(os.environ.get("OCR_DPI", "200"))

    width, height = 1200, 1600
    page_image_path = run_dir / "page_1.png"

    # Synthèse d'une page image pour la traçabilité visuelle
    if HAS_PIL:
        img = Image.new("RGB", (width, height), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)
        lines = text_clean.split("\n")
        y_cursor = 80
        for line in lines[:60]:
            draw.text((60, y_cursor), line[:90], fill=(20, 20, 20))
            y_cursor += 24
        img.save(page_image_path, "PNG")
    else:
        page_image_path.write_bytes(b"")

    page_image_sha256 = sha256_bytes(page_image_path.read_bytes())

    # Découpage du texte en paragraphes
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text_clean) if p.strip()]
    if not paragraphs:
        paragraphs = [text_clean]

    page_blocks = []
    y_step = max(50, min(140, height // (len(paragraphs) + 1)))
    current_y = 60

    for idx, para in enumerate(paragraphs):
        block_id = f"b_p1_{idx + 1}"
        bbox = [60, current_y, width - 60, current_y + y_step - 10]
        current_y += y_step
        sec_flags = detect_security_flags(para)
        page_blocks.append({
            "block_id": block_id,
            "kind": "heading" if idx == 0 and len(para.split()) < 10 else "text",
            "bbox": bbox,
            "grid_cell": detect_grid_cell(bbox, width, height),
            "confidence": 1.0,
            "block_sha256": sha256_text(para),
            "security_flags": sec_flags,
            "quality_flags": [],
            "text": para,
        })

    overlay_path = run_dir / "page_1_overlay.png"
    draw_bounding_boxes(page_image_path, overlay_path, page_blocks)

    chunks = chunk_blocks(page_blocks, 1)
    rag_records = []
    for chunk in chunks:
        rag_records.append({
            "chunk_id": chunk["chunk_id"],
            "text": chunk["text"],
            "index_status": "needs_review" if chunk["security_flags"] else "ready",
            "metadata": {
                "run_id": run_id,
                "source_name": "plain_text_input.txt",
                "source_sha256": source_sha256,
                "page": 1,
                "chunk_id": chunk["chunk_id"],
                "chunk_sha256": chunk["chunk_sha256"],
                "text_sha256": chunk["text_sha256"],
                "block_ids": chunk["block_ids"],
                "block_hashes": chunk.get("block_hashes", []),
                "bbox": chunk["bbox"],
                "security_flags": chunk["security_flags"],
                "word_count": chunk["word_count"],
            },
        })

    return {
        "run_id": run_id,
        "source_name": "plain_text_input.txt",
        "source_sha256": source_sha256,
        "ocr_lang": ocr_lang,
        "dpi": dpi,
        "page_count": 1,
        "pages": [{
            "page": 1,
            "page_image_sha256": page_image_sha256,
            "width": width,
            "height": height,
            "image_url": f"/runs/{run_id}/page_1.png",
            "overlay_url": f"/runs/{run_id}/page_1_overlay.png" if overlay_path.exists() else None,
            "blocks": page_blocks,
        }],
        "chunks": chunks,
        "rag_records": rag_records,
    }


def build_audit_manifest(result: dict[str, Any]) -> dict[str, Any]:
    """Construit l'arbre complet de traçabilité et de preuve cryptographique pour l'audit."""
    run_id = result["run_id"]
    source_sha256 = result["source_sha256"]

    proof_tree = []
    total_security_flags = 0

    for page in result.get("pages", []):
        page_num = page["page"]
        page_hash = page["page_image_sha256"]
        block_lineage = []

        for block in page.get("blocks", []):
            if block.get("security_flags"):
                total_security_flags += len(block["security_flags"])
            block_lineage.append({
                "block_id": block["block_id"],
                "block_sha256": block["block_sha256"],
                "bbox": block["bbox"],
                "grid_cell": block["grid_cell"],
                "confidence": block.get("confidence"),
                "security_flags": block.get("security_flags", []),
            })

        proof_tree.append({
            "page": page_num,
            "page_image_sha256": page_hash,
            "blocks": block_lineage,
        })

    return {
        "manifest_version": "3.0",
        "generated_at": int(time.time()),
        "run_id": run_id,
        "source_name": result["source_name"],
        "source_sha256": source_sha256,
        "ocr_lang": result["ocr_lang"],
        "dpi": result["dpi"],
        "audit_summary": {
            "page_count": result["page_count"],
            "block_count": sum(len(p.get("blocks", [])) for p in result.get("pages", [])),
            "chunk_count": len(result.get("chunks", [])),
            "flagged_issues_count": total_security_flags,
            "audit_compliance": "pass" if total_security_flags == 0 else "requires_human_review",
        },
        "proof_tree": proof_tree,
    }
