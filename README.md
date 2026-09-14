# LDS public plugin catalog

Signed distribution files for the 13 free public plugins in [LoRA Dataset Studio V2](https://github.com/perfectgf/lora-dataset-studio/tree/v2).

Install plugins from LDS → Plugins. This repository hosts the catalog, screenshots and immutable `.ldsplugin` archives used by the app. It is not a launcher or a separate app. Source and contributor documentation are in the LDS repository.

The app verifies TUF metadata against its pinned public bootstrap root, then verifies each downloaded archive's signed size and digest. Files are served directly from this repository's `main` branch under `public/`. The top-level `catalog.json` is an operator reference; the client consumes the authenticated catalog target.

`renew.py` only renews the already signed target set. It verifies root thresholds, all role signatures, metadata references and every target's bytes before signing. It never reads a new catalog or publishes new plugins. Target metadata expires after 30 days, snapshots after 7 days and timestamps after 3 days. GitHub Actions renews them every six hours and also supports manual dispatch. If scheduling stops, clients eventually refuse stale updates; existing installed plugins remain available. Check failed workflow runs promptly, since GitHub can delay or disable scheduled workflows.

Only the three online signing keys are configured as Actions secrets: `LDS_TUF_TARGETS_KEY`, `LDS_TUF_SNAPSHOT_KEY`, `LDS_TUF_TIMESTAMP_KEY`. Both root signing keys stay offline. No private keys belong in this repository. Changes to the target set and root rotation require a separate reviewed publication; renewal refuses an expired or changed bootstrap root. Renewing expired online metadata is supported after an outage.

For synthetic verification, install `requirements.txt` in an isolated Python environment and run `python -m unittest -v test_renew`. These tests generate disposable keys and do not alter the published files.
