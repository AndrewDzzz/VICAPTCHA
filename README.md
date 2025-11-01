# VICAPTCHA (Vision-illusion CAPTCHA) (Python PoW)

A local image selection CAPTCHA system.
- Six image grid, questions from your three image directories.
- Validates selection correctness first, then performs lightweight PoW (Proof of Work).
- Pure Python implementation (`pycap.py`), no external services required.

## Directory Structure
- `server.py`: Flask server and API endpoints (challenge, precheck, verify).
- `pycap.py`: PoW module (issue challenge + verify nonce).
- `static/`: Frontend pages and scripts.
- `IllusionCAPTCHA-Source/`: Three image category directories.

## Getting Started
```bash
source /Volumes/Ants/runs/.venv/bin/activate   # If venv doesn't exist: python3 -m venv .venv
pip install -r requirements.txt
python server.py
# Open http://localhost:8000
```
If port is occupied:
```bash
lsof -nti tcp:8000 | xargs -I {} kill -9 {} 2>/dev/null || true
python server.py
```

## Frontend Flow
1) `GET /api/captcha` fetches challenge (includes `pow.challenge` and `pow.difficulty`).
2) Select images, click Submit.
3) `POST /api/check` prechecks if selection is correct; if yes, shows progress bar and starts computing PoW:
   Computes `sha256(f"{challenge}:{nonce}")` until hash starts with `difficulty` zeroes.
4) After computation, `POST /api/verify` submits; server recomputes and verifies, returns success/failure.

## Backend Principles
- Challenge generation: Randomly selects target category, picks 2-4 target images + remaining from other categories to total 6.
- Challenge issuance: `pycap.PyCap.issue()` generates `challenge`, `difficulty`, expiration time.
- Precheck: Compares selected image id set against correct set, returns PoW config.
- Verification: Recomputes SHA-256 from `challenge` and `nonce`, checks leading zeros, re-verifies selection; then invalidates `captcha_id` to prevent replay.

## API Examples
- `GET /api/captcha` →
```json
{
  "captcha_id": "...",
  "prompt": "Which 2 images contain apples?",
  "select_count": 2,
  "images": [{"id":"...","url":"/images/..."}],
  "pow": {"challenge": "hex", "difficulty": 4, "algo": "sha256-prefix-zeros"}
}
```
- `POST /api/check`: `{ captcha_id, selected_ids: [id1,id2] }` → `{ valid, correct, pow }`
- `POST /api/verify`: `{ captcha_id, selected_ids, pow: { nonce } }` → `{ success }`

## Configuration
- PoW difficulty: `DEFAULT_DIFFICULTY` in `server.py` (default 4). Higher = more computation.
- Image directory: `IllusionCAPTCHA-Source/<category>/*.(png|jpg|jpeg|webp)`.

## Common Issues
- Port occupied: `Address already in use` → Free port 8000 or change port.
- PoW failed: Challenge may have expired or page was refreshed → Click ⟳ to get a new challenge.
- Slow device: Lower `DEFAULT_DIFFICULTY` to 3 for demo.

## Security Notice
This is a demo implementation suitable for local/development use. For production, add: rate limiting, session binding, replay protection and risk controls, enable HTTPS and CSRF protection, and consider dynamic difficulty.
