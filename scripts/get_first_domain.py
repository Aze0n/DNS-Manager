# datei scripts get_first_domain py
# decrypt erste domain aus db
import argparse
import base64
import sys
import pathlib

# Ensure project root is on sys.path so `import app` works when running the script
# directly from the repository root.
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

from sqlmodel import Session, select

from app.db import engine
from app.models import ApiKey, Domain
from app.core.security import derive_encryption_key, decrypt_secret


def get_first_domain(password: str) -> str:
    # return erste domain aus db
    with Session(engine) as session:
        api_entry = session.exec(select(ApiKey)).first()
        if not api_entry:
            raise SystemExit("No ApiKey row found in database.")
        if not api_entry.kek_salt_b64:
            raise SystemExit("ApiKey entry has no kek_salt_b64 stored; cannot derive KEK.")

        try:
            salt = base64.b64decode(api_entry.kek_salt_b64)
        except Exception as e:
            raise SystemExit(f"Failed to decode stored KEK salt: {e}")

        try:
            kek, _ = derive_encryption_key(password, salt)
        except Exception as e:
            raise SystemExit(f"Failed to derive KEK from password: {e}")

        domain_row = session.exec(select(Domain)).first()
        if not domain_row:
            raise SystemExit("No Domain rows found in database.")

        try:
            domain = decrypt_secret(kek, domain_row.domain_encrypted)
            return domain
        except Exception as e:
            raise SystemExit(f"Failed to decrypt domain: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Print first decrypted domain from DB")
    parser.add_argument("--password", required=True, help="master password used at setup")
    args = parser.parse_args()

    domain = get_first_domain(args.password)
    print(domain)


if __name__ == "__main__":
    main()
