"""Build data/features.csv: run `safe features` over the benign corpus, then add
synthesized malicious feature vectors. Only labels and numeric features are written;
no script contents are ever committed.

Usage:
    python ml/build_dataset.py [--ratio 1.0] [--seed 1706]
"""
import argparse
import csv
import json
import pathlib
import subprocess
import sys

from synth_malicious import FEATURE_ORDER, synthesize

ROOT = pathlib.Path(__file__).parent
REPO = ROOT.parent
CORPUS = ROOT / "corpus" / "benign"
DATA = REPO / "data"
BINARY = REPO / "target" / "release" / "safe"


def ensure_binary():
    if not BINARY.exists():
        print("building release binary...")
        subprocess.run(["cargo", "build", "--release"], cwd=REPO, check=True)


def extract_benign():
    files = sorted(p for p in CORPUS.rglob("*") if p.is_file())
    if not files:
        sys.exit("no benign corpus found; run: python ml/fetch_benign.py")
    rows = []
    batch = 200
    for i in range(0, len(files), batch):
        chunk = [str(p) for p in files[i:i + batch]]
        proc = subprocess.run([str(BINARY), "features", "--json", *chunk],
                              capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            rec = json.loads(line)
            feats = rec["features"]
            rows.append({k: float(feats[k]) for k in FEATURE_ORDER})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ratio", type=float, default=1.0,
                    help="malicious rows per benign row")
    ap.add_argument("--seed", type=int, default=1706)
    args = ap.parse_args()

    ensure_binary()
    DATA.mkdir(exist_ok=True)

    benign = extract_benign()
    malicious = synthesize(benign, int(len(benign) * args.ratio), seed=args.seed)
    print(f"benign: {len(benign)}   malicious (synthetic): {len(malicious)}")

    out = DATA / "features.csv"
    with out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["label", *FEATURE_ORDER])
        for r in benign:
            w.writerow([0, *(f"{r[k]:.6g}" for k in FEATURE_ORDER)])
        for r in malicious:
            w.writerow([1, *(f"{r[k]:.6g}" for k in FEATURE_ORDER)])
    print(f"wrote {out} ({len(benign) + len(malicious)} rows, {len(FEATURE_ORDER)} features)")

    meta = DATA / "dataset_meta.json"
    meta.write_text(json.dumps({
        "benign": len(benign),
        "malicious_synthetic": len(malicious),
        "features": len(FEATURE_ORDER),
        "feature_order": FEATURE_ORDER,
        "seed": args.seed,
        "note": "Benign rows are features of real installer scripts. Malicious rows are "
                "synthesized in feature space from documented ATT&CK indicator distributions; "
                "no malware is stored or executed.",
    }, indent=2))


if __name__ == "__main__":
    main()
