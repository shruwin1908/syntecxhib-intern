import os
import sys
import json
import base64
import getpass
import argparse
from datetime import datetime
 
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
 
VAULT_FILE = "vault.enc"
SALT_SIZE = 16
KDF_ITERATIONS = 390_000
 
 
# ----------------------------------------------------------------------
# Key derivation & vault (de)serialization
# ----------------------------------------------------------------------
def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a 32-byte Fernet-compatible key from the master password + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)
 
 
def vault_exists() -> bool:
    return os.path.exists(VAULT_FILE)
 
 
def load_vault(master_password: str) -> dict:
    """Reads salt + ciphertext from disk, derives the key, decrypts, returns entries dict."""
    if not vault_exists():
        print(f"[ERROR] No vault found. Run 'init' first.")
        sys.exit(1)
 
    try:
        with open(VAULT_FILE, "rb") as f:
            raw = f.read()
        salt, token = raw[:SALT_SIZE], raw[SALT_SIZE:]
 
        key = derive_key(master_password, salt)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(token)
        return json.loads(decrypted.decode("utf-8"))
 
    except InvalidToken:
        print("[ERROR] Incorrect master password, or vault file is corrupted.")
        sys.exit(1)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[ERROR] Could not read vault: {e}")
        sys.exit(1)
 
 
def save_vault(entries: dict, master_password: str, salt: bytes = None) -> None:
    """Encrypts the entries dict and writes salt + ciphertext to disk."""
    try:
        if salt is None:
            # Reuse existing salt if vault already exists, else generate new
            if vault_exists():
                with open(VAULT_FILE, "rb") as f:
                    salt = f.read()[:SALT_SIZE]
            else:
                salt = os.urandom(SALT_SIZE)
 
        key = derive_key(master_password, salt)
        fernet = Fernet(key)
        token = fernet.encrypt(json.dumps(entries).encode("utf-8"))
 
        with open(VAULT_FILE, "wb") as f:
            f.write(salt + token)
 
    except OSError as e:
        print(f"[ERROR] Could not write vault: {e}")
        sys.exit(1)
 
 
# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------
def cmd_init(args):
    if vault_exists():
        confirm = input(f"'{VAULT_FILE}' already exists. Overwrite? (y/N): ")
        if confirm.lower() != "y":
            print("Aborted.")
            return
 
    pw1 = getpass.getpass("Set a master password: ")
    pw2 = getpass.getpass("Confirm master password: ")
    if pw1 != pw2:
        print("[ERROR] Passwords do not match.")
        sys.exit(1)
    if len(pw1) < 8:
        print("[ERROR] Master password should be at least 8 characters.")
        sys.exit(1)
 
    salt = os.urandom(SALT_SIZE)
    save_vault({}, pw1, salt=salt)
    print(f"[OK] New encrypted vault created: {VAULT_FILE}")
 
 
def cmd_add(args):
    master = getpass.getpass("Master password: ")
    entries = load_vault(master)
 
    service = args.service or input("Service (e.g. github.com): ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password to store: ")
 
    if service in entries:
        confirm = input(f"'{service}' already exists. Overwrite? (y/N): ")
        if confirm.lower() != "y":
            print("Aborted.")
            return
 
    entries[service] = {
        "username": username,
        "password": password,
        "updated": datetime.now().isoformat(timespec="seconds"),
    }
    save_vault(entries, master)
    print(f"[OK] Entry saved for '{service}'.")
 
 
def cmd_get(args):
    master = getpass.getpass("Master password: ")
    entries = load_vault(master)
 
    entry = entries.get(args.service)
    if not entry:
        print(f"[NOT FOUND] No entry for '{args.service}'.")
        return
 
    print(f"\nService:  {args.service}")
    print(f"Username: {entry['username']}")
    print(f"Password: {entry['password']}")
    print(f"Updated:  {entry['updated']}")
 
 
def cmd_delete(args):
    master = getpass.getpass("Master password: ")
    entries = load_vault(master)
 
    if args.service not in entries:
        print(f"[NOT FOUND] No entry for '{args.service}'.")
        return
 
    confirm = input(f"Delete entry for '{args.service}'? (y/N): ")
    if confirm.lower() != "y":
        print("Aborted.")
        return
 
    del entries[args.service]
    save_vault(entries, master)
    print(f"[OK] Entry deleted for '{args.service}'.")
 
 
def cmd_search(args):
    master = getpass.getpass("Master password: ")
    entries = load_vault(master)
 
    term = args.term.lower()
    matches = [
        s for s, e in entries.items()
        if term in s.lower() or term in e["username"].lower()
    ]
 
    if not matches:
        print(f"[NO MATCHES] Nothing found for '{args.term}'.")
        return
 
    print(f"\nFound {len(matches)} match(es):")
    for s in matches:
        print(f"  - {s}  (user: {entries[s]['username']})")
 
 
def cmd_list(args):
    master = getpass.getpass("Master password: ")
    entries = load_vault(master)
 
    if not entries:
        print("Vault is empty.")
        return
 
    print(f"\nStored services ({len(entries)}):")
    for s in sorted(entries):
        print(f"  - {s}")
 
 
# ----------------------------------------------------------------------
# Main / argument parsing
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="A local, AES-encrypted password manager (educational project)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
 
    subparsers.add_parser("init", help="Create a new encrypted vault")
 
    p_add = subparsers.add_parser("add", help="Add a new credential entry")
    p_add.add_argument("service", nargs="?", help="Service name (optional, will prompt if omitted)")
 
    p_get = subparsers.add_parser("get", help="Retrieve a credential entry")
    p_get.add_argument("service", help="Service name to look up")
 
    p_del = subparsers.add_parser("delete", help="Delete a credential entry")
    p_del.add_argument("service", help="Service name to delete")
 
    p_search = subparsers.add_parser("search", help="Search entries by service/username")
    p_search.add_argument("term", help="Search term")
 
    subparsers.add_parser("list", help="List all stored service names")
 
    args = parser.parse_args()
 
    commands = {
        "init": cmd_init,
        "add": cmd_add,
        "get": cmd_get,
        "delete": cmd_delete,
        "search": cmd_search,
        "list": cmd_list,
    }
    commands[args.command](args)
 
 
if __name__ == "__main__":
    main()
