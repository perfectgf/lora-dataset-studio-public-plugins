"""Renew authenticated metadata, without publishing or changing any target."""
from __future__ import annotations

import copy
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import serialization
from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Metadata, MetaFile, Root, Snapshot, Targets, Timestamp

ONLINE_ROLES = ("targets", "snapshot", "timestamp")
RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}


def plain_path(path: Path) -> None:
    """Reject aliases, including Windows junctions and hardlinked files."""
    for current in (path, *path.parents):
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Links are not repository storage")
        if stat.S_ISREG(info.st_mode):
            if current != path or info.st_nlink != 1:
                raise ValueError("Repository files must be ordinary unlinked files")
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError("Unsupported repository file type")


def safe_target(name: str) -> PurePosixPath:
    if not isinstance(name, str) or not 1 <= len(name) <= 400:
        raise ValueError("Invalid target path")
    parts = name.split("/")
    if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,179}", part)
           or part.endswith(".") or part.split(".")[0].upper() in RESERVED for part in parts):
        raise ValueError("Unsafe target path")
    return PurePosixPath(name)


def verify_repository(public: Path, now: datetime) -> dict[str, Metadata]:
    """Authenticate the existing generation before any private key is used.

    Online expiry is deliberately not a renewal prerequisite: the operator can
    recover from missed schedules. Clients still enforce all TUF expiration dates.
    Root rotation is a separate, offline operation.
    """
    plain_path(public)
    for folder, directories, files in os.walk(public, followlinks=False):
        for name in (*directories, *files):
            plain_path(Path(folder) / name)
    metadata_dir = public / "metadata"
    raw = {role: (metadata_dir / f"{role}.json").read_bytes()
           for role in ("root", *ONLINE_ROLES)}
    roles = {role: Metadata.from_bytes(data) for role, data in raw.items()}
    for role, cls in (("root", Root), ("targets", Targets), ("snapshot", Snapshot), ("timestamp", Timestamp)):
        if not isinstance(roles[role].signed, cls):
            raise ValueError("Metadata type does not match its role")
    root = roles["root"].signed
    if raw["root"] != (public / "bootstrap.root.json").read_bytes():
        raise ValueError("Root differs from the reviewed bootstrap; rotate offline")
    if raw["root"] != (metadata_dir / f"{root.version}.root.json").read_bytes():
        raise ValueError("Root differs from its immutable version")
    if root.is_expired(now) or not root.consistent_snapshot:
        raise ValueError("Root is expired or consistent snapshots are disabled")
    if root.roles["root"].threshold != 2 or len(set(root.roles["root"].keyids)) != 2:
        raise ValueError("Two offline root keys are required")
    root_keys = set(root.roles["root"].keyids)
    online_keys = set()
    for role in ONLINE_ROLES:
        config = root.roles[role]
        if config.threshold != 1 or len(config.keyids) != 1:
            raise ValueError("Each online role requires one dedicated key")
        if set(config.keyids) & (root_keys | online_keys):
            raise ValueError("Signing keys must be separated by role")
        online_keys.update(config.keyids)
    for role, value in roles.items():
        root.verify_delegate(role, value.signed_bytes, value.signatures)
    targets, snapshot, timestamp = (roles[role].signed for role in ONLINE_ROLES)
    if targets.delegations is not None or set(snapshot.meta) != {"targets.json"}:
        raise ValueError("Delegated targets are outside this renewal policy")
    for role, reference in (("targets", snapshot.meta["targets.json"]),
                            ("snapshot", timestamp.snapshot_meta)):
        if reference.version != roles[role].signed.version:
            raise ValueError("Metadata versions do not match")
        if reference.length is None or not reference.hashes or "sha256" not in reference.hashes:
            raise ValueError("Metadata requires SHA-256 and length")
        reference.verify_length_and_hashes(raw[role])
        if raw[role] != (metadata_dir / f"{reference.version}.{role}.json").read_bytes():
            raise ValueError("Metadata differs from its immutable version")
    if "catalog.json" not in targets.targets:
        raise ValueError("Signed catalog is required")
    for name, info in targets.targets.items():
        relative = safe_target(name)
        digest = info.hashes.get("sha256", "")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("A target requires a SHA-256 digest")
        physical = public / "targets" / relative.parent / f"{digest}.{relative.name}"
        plain_path(physical)
        with physical.open("rb") as stream:
            info.verify_length_and_hashes(stream)
    return roles


def atomic_write(path: Path, data: bytes, *, immutable: bool = False) -> None:
    plain_path(path)
    if immutable and path.exists():
        if path.read_bytes() != data:
            raise ValueError("Immutable metadata already exists")
        return
    handle, temporary = tempfile.mkstemp(prefix=".renew-", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if immutable:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def renew(public: Path, signers: dict[str, CryptoSigner], *, now: datetime | None = None) -> int:
    public = public.absolute()
    now = now or datetime.now(timezone.utc)
    existing = verify_repository(public, now)
    root = existing["root"].signed
    if set(signers) != set(ONLINE_ROLES):
        raise ValueError("Exactly the three online signers are required")
    for role, signer in signers.items():
        if signer.public_key.keyid not in root.roles[role].keyids:
            raise ValueError("Signer is not authorized for its role")
    metadata_dir = public / "metadata"
    versions = [value.signed.version for role, value in existing.items() if role != "root"]
    for path in metadata_dir.iterdir():
        match = re.fullmatch(r"([1-9][0-9]*)\.(targets|snapshot|timestamp)\.json", path.name)
        if match:
            versions.append(int(match.group(1)))
    version = max(versions) + 1
    targets = copy.deepcopy(existing["targets"])
    targets.signed.version = version
    targets.signed.expires = now + timedelta(days=30)
    targets.sign(signers["targets"])
    target_bytes = targets.to_bytes()
    snapshot = Metadata(Snapshot(version=version, expires=now + timedelta(days=7),
                                 meta={"targets.json": MetaFile.from_data(version, target_bytes, ["sha256"])}))
    snapshot.sign(signers["snapshot"])
    snapshot_bytes = snapshot.to_bytes()
    timestamp = Metadata(Timestamp(version=version, expires=now + timedelta(days=3),
                                   snapshot_meta=MetaFile.from_data(version, snapshot_bytes, ["sha256"])))
    timestamp.sign(signers["timestamp"])
    output = {"targets": target_bytes, "snapshot": snapshot_bytes, "timestamp": timestamp.to_bytes()}
    # Check every destination before writing the first one.
    for role, data in output.items():
        for path in (metadata_dir / f"{version}.{role}.json", metadata_dir / f"{role}.json"):
            plain_path(path)
            if path.exists() and not path.is_file():
                raise ValueError("Metadata destination is not a file")
        immutable = metadata_dir / f"{version}.{role}.json"
        if immutable.exists() and immutable.read_bytes() != data:
            raise ValueError("Immutable metadata cannot be replaced")
    for role, data in output.items():
        atomic_write(metadata_dir / f"{version}.{role}.json", data, immutable=True)
    # Clients keep using the preceding snapshot until the final timestamp.
    for role in ONLINE_ROLES:
        atomic_write(metadata_dir / f"{role}.json", output[role])
    return version


def main() -> int:
    try:
        public = Path(__file__).resolve().parent / "public"
        # Refuse a modified public tree before parsing any private key.
        verify_repository(public, datetime.now(timezone.utc))
        signers = {}
        for role in ONLINE_ROLES:
            pem = os.environ.pop(f"LDS_TUF_{role.upper()}_KEY")
            signers[role] = CryptoSigner(serialization.load_pem_private_key(pem.encode("ascii"), password=None))
        version = renew(public, signers)
    except Exception:
        # Exception text from cryptographic parsers or environment values must
        # never end up in a public Actions log.
        print("Renewal refused: metadata, targets, root validity or signing keys failed validation.", file=sys.stderr)
        return 1
    print(f"Renewed existing catalog metadata to version {version}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
