import os
import random
import uuid
from typing import Dict, List, Tuple
from pycap import PyCap, Challenge

from flask import Flask, jsonify, request, send_from_directory, abort


WORKSPACE_ROOT = "/Volumes/Ants/runs"
IMAGES_ROOT = os.path.join(WORKSPACE_ROOT, "IllusionCAPTCHA-Source")


def _discover_categories(root_dir: str) -> Dict[str, List[str]]:
    """Return mapping of category -> list of image filenames.

    Only includes directories that contain at least one .png/.jpg/.jpeg.
    """
    categories: Dict[str, List[str]] = {}
    if not os.path.isdir(root_dir):
        return categories
    for entry in os.listdir(root_dir):
        category_path = os.path.join(root_dir, entry)
        if not os.path.isdir(category_path):
            continue
        files = [
            f for f in os.listdir(category_path)
            if os.path.splitext(f)[1].lower() in {".png", ".jpg", ".jpeg", ".webp"}
        ]
        if files:
            categories[entry] = files
    return categories


app = Flask(__name__, static_folder=os.path.join(WORKSPACE_ROOT, "static"), static_url_path="/static")

# In-memory store: captcha_id -> {correct_ids, pow_challenge, difficulty}
ACTIVE_CHALLENGES: Dict[str, Dict[str, object]] = {}

# Demo PoW difficulty (number of leading hex zeros required in SHA-256)
DEFAULT_DIFFICULTY = 5
PY_CAP = PyCap(difficulty=DEFAULT_DIFFICULTY, ttl_seconds=180)

# No external CAP; using local PyCap only

def _make_pow_challenge() -> Tuple[str, int]:
    ch = PY_CAP.issue()
    return ch.challenge, ch.difficulty


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/images/<category>/<path:filename>")
def serve_image(category: str, filename: str):
    safe_root = os.path.abspath(IMAGES_ROOT)
    target_dir = os.path.abspath(os.path.join(IMAGES_ROOT, category))
    if not target_dir.startswith(safe_root):
        abort(404)
    if not os.path.exists(os.path.join(target_dir, filename)):
        abort(404)
    return send_from_directory(target_dir, filename)


@app.route("/api/captcha", methods=["GET"])
def api_captcha():
    categories = _discover_categories(IMAGES_ROOT)
    if not categories:
        return jsonify({"error": "No categories with images found."}), 500

    category_names = list(categories.keys())
    # Pick the target category and normalize the display label
    target_category = random.choice(category_names)
    display_label = target_category.replace("_illusion", "").replace("_", " ")

    # Decide how many correct images are required (2-4, bounded by available images)
    max_correct_possible = min(4, len(categories[target_category]), 6)
    min_correct_required = 2 if max_correct_possible >= 2 else 1
    select_count = random.randint(min_correct_required, max_correct_possible)

    # Select images: select_count from target, remaining from others to total 6
    target_files = random.sample(
        categories[target_category],
        k=min(select_count, len(categories[target_category]))
    )

    # Collect non-target options
    non_target = []
    for cat, files in categories.items():
        if cat == target_category:
            continue
        for f in files:
            non_target.append((cat, f))

    needed_non_target = 6 - len(target_files)
    if len(non_target) < needed_non_target:
        # If not enough other images, just fill from target (still works for demo)
        extra = random.sample(
            [f for f in categories[target_category] if f not in target_files],
            k=min(needed_non_target, max(0, len(categories[target_category]) - len(target_files)))
        )
        fill = [(target_category, f) for f in extra]
    else:
        fill = random.sample(non_target, k=needed_non_target)

    images = []
    correct_ids = set()

    # Add target images first
    for f in target_files:
        img_id = str(uuid.uuid4())
        images.append({
            "id": img_id,
            "url": f"/images/{target_category}/{f}",
        })
        correct_ids.add(img_id)

    # Add filler images
    for cat, f in fill:
        img_id = str(uuid.uuid4())
        images.append({
            "id": img_id,
            "url": f"/images/{cat}/{f}",
        })

    random.shuffle(images)

    captcha_id = str(uuid.uuid4())
    pow_challenge, difficulty = _make_pow_challenge()
    ACTIVE_CHALLENGES[captcha_id] = {
        "correct_ids": correct_ids,
        "pow_challenge": pow_challenge,
        "difficulty": difficulty,
    }

    return jsonify({
        "captcha_id": captcha_id,
        "prompt": f"Which images contain {display_label}?",
        "select_count": len(target_files),
        "images": images,
        "pow": {
            "challenge": pow_challenge,
            "difficulty": difficulty,
            "algo": "sha256-prefix-zeros",
        },
    })


@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json(silent=True) or {}
    captcha_id = data.get("captcha_id")
    selected_ids = set(data.get("selected_ids") or [])
    if not captcha_id or captcha_id not in ACTIVE_CHALLENGES:
        return jsonify({"success": False, "error": "Invalid or expired captcha."}), 400

    record = ACTIVE_CHALLENGES.get(captcha_id)
    if not record:
        return jsonify({"success": False, "error": "Invalid or expired captcha."}), 400

    correct_ids = record["correct_ids"]
    pow_challenge = record["pow_challenge"]
    difficulty = int(record["difficulty"]) or DEFAULT_DIFFICULTY

    # Enforce: selection count must match requirement
    if len(selected_ids) != len(correct_ids):
        return jsonify({"success": False, "error": f"Must select exactly {len(correct_ids)} images, got {len(selected_ids)}."}), 400

    # Verify PoW (Python-only implementation via PyCap)
    pow_data = data.get("pow") or {}
    nonce = str(pow_data.get("nonce", ""))
    if not nonce:
        return jsonify({"success": False, "error": "Missing PoW nonce."}), 400

    ch = Challenge(challenge=pow_challenge, difficulty=difficulty, expires_at=9999999999.0)
    ok, err = PY_CAP.verify(ch, nonce)
    if not ok:
        return jsonify({"success": False, "error": err}), 400

    # Invalidate captcha after verification attempt
    ACTIVE_CHALLENGES.pop(captcha_id, None)

    success = selected_ids == correct_ids
    return jsonify({"success": success})


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    captcha_id = data.get("captcha_id")
    selected_ids = set(data.get("selected_ids") or [])
    if not captcha_id or captcha_id not in ACTIVE_CHALLENGES:
        return jsonify({
            "valid": False,
            "correct": False,
            "error": "Invalid or expired captcha."
        })

    record = ACTIVE_CHALLENGES[captcha_id]
    correct = selected_ids == record["correct_ids"]
    return jsonify({
        "valid": True,
        "correct": correct,
        "pow": {
            "challenge": record["pow_challenge"],
            "difficulty": record["difficulty"],
            "algo": "sha256-prefix-zeros",
        }
    })


def main():
    # Ensure static directory exists (for index and assets)
    static_dir = app.static_folder
    os.makedirs(static_dir, exist_ok=True)
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()


