# Secure OCR Lab

Petit back-office local pour tester une boucle OCR "image-first" :

- upload PDF, image ou texte ;
- conversion en images normalisees ;
- OCR via Tesseract CLI ;
- pretraitement image local multi-passes avant OCR : gris, contraste, filtre median, nettete, binarisation optionnelle ;
- regroupement des lignes en blocs de paragraphes ;
- overlay visuel des zones detectees ;
- export JSON des pages, blocs, lignes, chunks, positions et signaux de securite ;
- manifeste de preuve avec hash source, hash page-image, hash bloc et hash chunk.
- couche native "shadow" non indexee pour comparer texte technique vs OCR visuel ;
- file de revue humaine pour accepter, marquer comme bruit ou quarantainer les zones.
- decisions humaines persistantes en SQLite ;
- manifeste d'audit JSON pour remonter d'une reponse a la preuve source ;
- projection graphe candidate pour relations textuelles `A -> B`, `if ... then ...` ;
- export `rag_records.jsonl` pret pour embedding et indexation vectorielle.

## Lancer

```bash
python3 app.py
```

Puis ouvrir :

```text
http://127.0.0.1:8765
```

## Versions implementees

| Version | Fonction | Etat |
| --- | --- | --- |
| V1 | OCR image-first, blocs, chunks, bbox, hash parent/enfant | Fonctionnel |
| V2 | Back-office de revue humaine + decisions SQLite | Fonctionnel |
| V3 | Manifeste d'audit avec chaines de preuve | Fonctionnel |
| V4 | Graphe candidat base sur relations textuelles | Squelette exploitable |
| V5 | Endpoints API `health`, `config`, `review`, `rag-export` | Fonctionnel |
| V6 | OCR multi-passes score par confiance et volume de texte | Fonctionnel |

## Langues

Par defaut, l'app utilise `OCR_LANG=eng` car seules les donnees anglaises sont
presentes dans cet environnement. Sur ta machine, installe les paquets Tesseract
souhaites puis lance par exemple :

```bash
OCR_LANG=fra+eng python3 app.py
```

## Qualite image OCR

Le pipeline cree au minimum deux images par page :

- `page-XXX.png` : rendu visuel source conserve pour audit ;
- `page-XXX-ocr.png` : image nettoyee retenue pour OCR, meme taille en pixels pour garder les bbox projetables.

Par defaut :

```bash
OCR_PREPROCESS_MODE=auto python3 app.py
```

En mode `auto`, le pipeline essaye plusieurs variantes locales, lance Tesseract
sur chaque image, score les resultats, puis garde la meilleure image auditable.
Cela evite de rester bloque sur une seule photo trop floue, trop grise ou trop
bruitee.

Modes utiles :

- `auto` : gris + autocontrast + filtre median + nettete ;
- `auto_light` : gris + autocontrast, utile quand le filtre median mange les petits caracteres ;
- `binary` : ajoute une binarisation par seuil ;
- `sharp` : accentuation forte pour scans mous ;
- `off` : copie brute, utile pour comparer.

Seuils configurables :

```bash
OCR_PREPROCESS_MODE=auto OCR_MAX_PASSES=4 OCR_MIN_CONFIDENCE=65 python3 app.py
OCR_PREPROCESS_MODE=binary OCR_BINARY_THRESHOLD=180 python3 app.py
```

Chaque page expose `ocr.attempts`, `ocr.selected_mode`, `ocr.avg_confidence` et
`ocr.score`. Si toutes les passes restent faibles, la page passe en revue humaine
avec `low_confidence`, `empty_ocr_result` ou `ocr_error`.

## Diagnostic Tesseract

Le endpoint suivant dit si le serveur voit bien Tesseract et quelles langues sont
vraiment disponibles :

```text
http://127.0.0.1:8765/api/config
```

Si tu demandes `OCR_LANG=fra+eng` mais que `fra` n'est pas installe, le pipeline
utilise automatiquement la langue disponible, par exemple `eng`, et ajoute
`missing_langs: ["fra"]` dans le JSON. Sur Debian/Ubuntu :

```bash
sudo apt install tesseract-ocr tesseract-ocr-fra tesseract-ocr-eng
```

Un résultat du type "image rasterisee sans Tesseract CLI" n'est pas un OCR
valide : cela indique que tu fais tourner une ancienne version ou un fallback
qui invente un bloc technique. La version actuelle expose `ocr.status`,
`ocr.stderr`, `effective_lang` et `missing_langs` pour eviter ce faux positif.

## Etat de l'art local retenu

La pile actuelle reste volontairement legere pour reparer la boucle de base :
PyMuPDF rasterise toutes les pages PDF, Pillow ameliore les images, Tesseract
fait l'OCR et le back-office montre les bbox. Les recherches conduisent a cette
priorite pour les prochaines versions :

| Priorite | Candidat | Usage vise |
| --- | --- | --- |
| 1 | RapidOCR / ONNXRuntime | Backend OCR Python leger, facile a garder local CPU/GPU |
| 2 | PaddleOCR / PP-OCRv5 | Meilleure cible OCR locale multilingue pour RTX 8 Go |
| 3 | docTR ou Surya/Marker | Layout plus riche, paragraphes, tables, documents complexes |
| 4 | OpenCV | Formes, fleches, connecteurs, logos simples, diagrammes |
| 5 | DeepSeek-OCR, MinerU, olmOCR | Backend VLM/document AI plus lourd, seulement apres stabilisation |

Le manuscrit ne doit pas etre promis par Tesseract seul. Il faudra un backend
dedie, probablement PaddleOCR/PP-OCRv5 ou un modele type TrOCR/Surya selon les
tests locaux. Les formes et fleches ne sont pas de l'OCR pur : elles demandent
une couche vision separee.

## Principe

La source originale reste une piece d'audit, mais le texte indexable vient de la
page rendue en image. Cela reduit les injections cachees dans les formats natifs
comme les metadonnees PDF, HTML/CSS non visible, commentaires et calques.
Le texte natif peut etre extrait en couche de controle, mais il n'alimente pas le
RAG tant qu'une politique humaine explicite ne l'a pas autorise.

Chaque chunk contient une `source_ref` :

- `source_sha256` : empreinte du document injecte ;
- `page_sha256` : empreinte de la page rasterisee ;
- `bbox` : zone pixel exacte a encadrer ;
- `block_ids` / `block_hashes` : blocs OCR parents ;
- `chunk_sha256` : preuve du contenu indexable.

Ce schema permet de remonter d'une reponse RAG vers la photo/page source et
d'encadrer la zone qui justifie la reponse.

## Controle qualite

Le JSON contient aussi `pages[].layers` :

- `visual_ocr` : texte issu de l'image, candidat indexable ;
- `native_text_shadow` : texte technique/natif, uniquement pour controle ;
- `comparison` : score de similarite et flags comme `native_ocr_divergence`.

`quality_report.review_queue` liste les elements qui meritent une validation :
faible confiance OCR, divergence OCR/natif, injection probable ou boilerplate
repete type header/footer.

## Export RAG

Chaque analyse genere `rag_records.jsonl`. Une ligne correspond a un futur point
de base vectorielle :

- `id` : identifiant stable derive du hash source et du chunk ;
- `embedding_text` : texte contextualise a envoyer au modele d'embedding ;
- `index_status` : `candidate` ou `needs_review` ;
- `tags` : type document probable, cellules visuelles, flags securite ;
- `metadata` : hashes, page, bbox, blocs parents, URLs image/overlay.

Le connecteur vers Qdrant, Chroma, LanceDB ou SQLite/FAISS pourra lire ce JSONL
sans changer le pipeline OCR.

Deux exports coexistent :

- `/runs/<run_id>/rag_records.jsonl` : export brut avec statuts `candidate` ou `needs_review` ;
- `/api/rag-export?run_id=<run_id>&policy=reviewed` : export filtre qui exclut les zones en bruit, quarantaine ou necessitant revue non acceptee.

## API locale

| Endpoint | Role |
| --- | --- |
| `GET /api/health` | Controle de vie du service |
| `GET /api/config` | Configuration OCR active |
| `POST /api/analyze` | Analyse document/texte |
| `POST /api/review` | Sauvegarde une decision humaine |
| `GET /api/rag-export?run_id=...&policy=reviewed` | Exporte les chunks autorises pour RAG |

## Audit

Chaque run cree `audit_manifest.json`. Il contient le hash du document source,
les hashes des images rasterisees, le hash des images OCR nettoyees, les hashes
des chunks, la politique de rasterisation et les compteurs d'alerte. L'objectif est simple : quand le RAG
renvoie "50 euros", le back-office peut retrouver le `chunk_id`, afficher la
page source et encadrer la bbox qui justifie la reponse.

## Graphe V4

La V4 actuelle cree des noeuds a partir des blocs OCR et detecte les relations
textuelles simples comme `A -> B`, `A => B` ou `if A then B`. La detection de
fleches visuelles, connecteurs, cardinalites et schemas complexes est marquee
comme prochaine etape : il faudra ajouter OpenCV et/ou un modele vision-langage
pour ne pas pretendre deviner des liaisons invisibles.
