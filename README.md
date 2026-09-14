# Secure OCR Lab

Back-office local pour tester une boucle OCR auditable, securisee et orientee RAG.

## Capacites

- Upload PDF, image ou texte.
- Conversion image-first avant OCR pour reduire les injections cachees dans HTML, PDF, commentaires, metadonnees ou texte invisible.
- OCR Tesseract CLI sur images rasterisees.
- Detection de blocs, bbox pixel, cellules de grille, chunks semantiques.
- Hash de preuve: source, page image, bloc, chunk.
- Couche native shadow pour comparer texte technique vs texte visible sans l'indexer.
- File de revue humaine avec decisions persistantes SQLite.
- Export RAG brut et export RAG filtre par validation humaine.
- Manifeste d'audit pour retrouver la preuve source d'une reponse.
- Projection graphe candidate pour relations textuelles simples.

## Lancer

### Windows (PowerShell) :

```powershell
# Création et activation de l'environnement virtuel (recommandé)
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Lancement de l'application
py app.py
```

### Linux / macOS :

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Puis ouvrir dans votre navigateur :

```text
http://127.0.0.1:8788
```

## Versions implementees

| Version | Fonction | Etat |
| --- | --- | --- |
| V1 | OCR image-first, blocs, chunks, bbox, hash parent/enfant | Fonctionnel |
| V2 | Back-office de revue humaine + decisions SQLite | Fonctionnel |
| V3 | Manifeste d'audit avec chaines de preuve | Fonctionnel |
| V4 | Graphe candidat base sur relations textuelles | Squelette exploitable |
| V5 | Endpoints API `health`, `config`, `review`, `rag-export` | Fonctionnel |

## Langues

Par defaut, l'app utilise `OCR_LANG=eng`. Sur une machine avec les donnees Tesseract francaises:

```bash
OCR_LANG=fra+eng python3 app.py
```

## Audit et RAG

Chaque chunk contient `source_sha256`, `page_sha256`, `bbox`, `block_ids`, `block_hashes` et `chunk_sha256`. Une reponse RAG peut donc revenir au document source, afficher la page image et encadrer la zone exacte qui justifie la reponse.

Exports:

- `/runs/<run_id>/rag_records.jsonl`: export brut.
- `/api/rag-export?run_id=<run_id>&policy=reviewed`: export filtre, bloque les chunks en bruit, quarantaine ou non valides.

Endpoints:

| Endpoint | Role |
| --- | --- |
| `GET /api/health` | Controle de vie |
| `GET /api/config` | Configuration OCR active |
| `POST /api/analyze` | Analyse document ou texte |
| `POST /api/review` | Sauvegarde une decision humaine |
| `GET /api/rag-export?run_id=...&policy=reviewed` | Exporte les chunks autorises |

## Dependances

Python 3.11+, Pillow, PyMuPDF, Tesseract OCR CLI.
