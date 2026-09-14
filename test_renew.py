"""Security contracts using only disposable keys and target bytes."""
from __future__ import annotations

import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from securesystemslib.signer import CryptoSigner
from tuf.api.exceptions import DownloadHTTPError
from tuf.api.metadata import Metadata, MetaFile, Root, Snapshot, TargetFile, Targets, Timestamp
from tuf.ngclient import Updater
from tuf.ngclient.fetcher import FetcherInterface

import renew


class LocalFetcher(FetcherInterface):
    def __init__(self, public):
        self.public = public

    def _fetch(self, url):
        path = self.public / urlsplit(url).path.removeprefix("/repository/")
        if not path.is_file():
            raise DownloadHTTPError("Missing fixture", 404)
        yield path.read_bytes()


class RenewalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lds-renewal-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.public = self.base / "public"
        self.metadata = self.public / "metadata"
        self.metadata.mkdir(parents=True)
        (self.public / "targets").mkdir()
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.signers = {role: CryptoSigner.generate_ed25519() for role in renew.ONLINE_ROLES}
        self.root_signers = [CryptoSigner.generate_ed25519(), CryptoSigner.generate_ed25519()]
        self.root = Metadata(Root(expires=self.now + timedelta(days=365)))
        for signer in self.root_signers:
            self.root.signed.add_key(signer.public_key, "root")
        self.root.signed.roles["root"].threshold = 2
        for role, signer in self.signers.items():
            self.root.signed.add_key(signer.public_key, role)
        self.write_root()
        self.targets = Metadata(Targets(expires=self.now + timedelta(days=30)))
        for name, data in (("catalog.json", b'{"schema_version":1,"products":[]}'),
                           ("plugins/example/1.0.0.ldsplugin", b"synthetic archive")):
            info = TargetFile.from_data(name, data, ["sha256"])
            self.targets.signed.targets[name] = info
            relative = Path(name)
            path = self.public / "targets" / relative.parent / f"{info.hashes['sha256']}.{relative.name}"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.write_generation()

    def write_root(self):
        for index, signer in enumerate(self.root_signers):
            self.root.sign(signer, append=index > 0)
        data = self.root.to_bytes()
        for path in (self.metadata / "root.json", self.metadata / "1.root.json", self.public / "bootstrap.root.json"):
            path.write_bytes(data)

    def write_generation(self, expired=False):
        expires = self.now + timedelta(days=-1 if expired else 3)
        if expired:
            self.targets.signed.expires = expires
        self.targets.sign(self.signers["targets"])
        target_bytes = self.targets.to_bytes()
        snapshot = Metadata(Snapshot(expires=expires,
                                     meta={"targets.json": MetaFile.from_data(1, target_bytes, ["sha256"])}))
        snapshot.sign(self.signers["snapshot"])
        snapshot_bytes = snapshot.to_bytes()
        timestamp = Metadata(Timestamp(expires=expires,
                                       snapshot_meta=MetaFile.from_data(1, snapshot_bytes, ["sha256"])))
        timestamp.sign(self.signers["timestamp"])
        for role, data in (("targets", target_bytes), ("snapshot", snapshot_bytes), ("timestamp", timestamp.to_bytes())):
            (self.metadata / f"{role}.json").write_bytes(data)
            if role != "timestamp":
                (self.metadata / f"1.{role}.json").write_bytes(data)

    def metadata_bytes(self):
        return {path.name: path.read_bytes() for path in self.metadata.iterdir()}

    def assert_refused_without_writes(self, signers=None):
        before = self.metadata_bytes()
        with self.assertRaises(Exception):
            renew.renew(self.public, self.signers if signers is None else signers, now=self.now)
        self.assertEqual(before, self.metadata_bytes())

    def updater(self):
        cache = self.base / "client"
        cache.mkdir(exist_ok=True)
        updater = Updater(str(cache), "https://fixture.invalid/repository/metadata/",
                          target_dir=str(self.base / "download"),
                          target_base_url="https://fixture.invalid/repository/targets/",
                          fetcher=LocalFetcher(self.public), bootstrap=self.root.to_bytes())
        updater.refresh()
        return updater

    def test_existing_tuf_client_accepts_renewal_and_targets_are_identical(self):
        old_targets = copy.deepcopy(self.targets.signed.targets)
        old_root = (self.public / "bootstrap.root.json").read_bytes()
        client = self.updater()
        before = client.get_targetinfo("plugins/example/1.0.0.ldsplugin")
        self.assertIsNotNone(before)
        target_bytes = {path.relative_to(self.public): path.read_bytes()
                        for path in (self.public / "targets").rglob("*") if path.is_file()}
        self.assertEqual(renew.renew(self.public, self.signers, now=self.now), 2)
        client = self.updater()
        after = client.get_targetinfo("plugins/example/1.0.0.ldsplugin")
        self.assertEqual(before.to_dict(), after.to_dict())
        destination = client.download_target(after)
        self.assertEqual(Path(destination).read_bytes(), b"synthetic archive")
        roles = renew.verify_repository(self.public, self.now)
        self.assertEqual({name: info.to_dict() for name, info in roles["targets"].signed.targets.items()},
                         {name: info.to_dict() for name, info in old_targets.items()})
        for role, days in (("targets", 30), ("snapshot", 7), ("timestamp", 3)):
            self.assertEqual(roles[role].signed.expires, self.now + timedelta(days=days))
        self.assertEqual(old_root, (self.public / "bootstrap.root.json").read_bytes())
        for relative, data in target_bytes.items():
            self.assertEqual(data, (self.public / relative).read_bytes())

    def test_target_tampering_refused(self):
        info = self.targets.signed.targets["catalog.json"]
        (self.public / "targets" / f"{info.hashes['sha256']}.catalog.json").write_bytes(b"tampered")
        self.assert_refused_without_writes()

    def test_signature_tampering_refused(self):
        raw = (self.metadata / "targets.json").read_bytes().replace(b'"version":1', b'"version":2')
        (self.metadata / "targets.json").write_bytes(raw)
        self.assert_refused_without_writes()

    def test_unapproved_signer_refused(self):
        wrong = {**self.signers, "targets": CryptoSigner.generate_ed25519()}
        self.assert_refused_without_writes(wrong)

    def test_signed_unsafe_target_refused(self):
        self.targets.signed.targets["../escape"] = TargetFile.from_data("../escape", b"escape", ["sha256"])
        self.write_generation()
        self.assert_refused_without_writes()

    def test_expired_root_refused_but_expired_online_metadata_can_recover(self):
        self.write_generation(expired=True)
        self.assertEqual(renew.renew(self.public, self.signers, now=self.now), 2)
        self.root.signed.expires = self.now - timedelta(seconds=1)
        self.write_root()
        self.assert_refused_without_writes()

    def test_root_threshold_must_stay_two(self):
        self.root.signed.roles["root"].threshold = 1
        self.write_root()
        self.assert_refused_without_writes()

    def test_bootstrap_replacement_refused(self):
        (self.public / "bootstrap.root.json").write_bytes(b"untrusted root")
        self.assert_refused_without_writes()

    def test_unversioned_metadata_cannot_disagree_with_immutable_file(self):
        (self.metadata / "1.targets.json").write_bytes(b"different immutable generation")
        self.assert_refused_without_writes()


if __name__ == "__main__":
    unittest.main()
