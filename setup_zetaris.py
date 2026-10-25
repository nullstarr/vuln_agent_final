"""
Registers our three sources in Zetaris (one statement at a time).

    python3 setup_zetaris.py              # dry run: prints the statements, changes nothing
    python3 setup_zetaris.py --run        # runs them against the instance in .env
    python3 setup_zetaris.py --run --skip-exists   # re-run: ignore 'already exists' errors

Needs ZETARIS_REST_URL, ZETARIS_ORG_ID, ZETARIS_API_KEY (see .env.example) and the data server running
(docker compose -f integrations/zetaris/docker-compose.data.yml up -d).
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agents.envfile import load_env
from agents.zetaris_client import ZetarisClient, ZetarisError
from integrations.zetaris.setup_statements import STATEMENTS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--skip-exists", action="store_true")
    args = ap.parse_args()
    if not args.run:
        for i, s in enumerate(STATEMENTS, 1):
            print(f"-- [{i}/{len(STATEMENTS)}]\n{s}\n")
        print("Dry run only. Add --run to execute.")
        return 0
    load_env()
    try:
        client = ZetarisClient()
        client.run_sql("SELECT 1")
    except ZetarisError as e:
        print("ERROR:", e)
        return 1
    for i, s in enumerate(STATEMENTS, 1):
        head = s.splitlines()[0][:70]
        try:
            client.run_sql(s)
            print(f"[{i}/{len(STATEMENTS)}] ok     {head}")
        except ZetarisError as e:
            if args.skip_exists and "exist" in str(e).lower():
                print(f"[{i}/{len(STATEMENTS)}] exists {head}")
                continue
            print(f"[{i}/{len(STATEMENTS)}] FAILED {head}\n    {e}")
            return 1
    print("Done. Check: python3 check_zetaris.py --live")
    return 0


if __name__ == "__main__":
    sys.exit(main())
