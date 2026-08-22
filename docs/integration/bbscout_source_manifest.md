# bbscout integration source manifest

This manifest describes the external bbscout source tree included in the combined integration archive. The source is **not vendored or committed** in the WebPent Git repository; its archive copy is produced from the reviewed extraction tree at release time.

| Field | Value |
|---|---|
| Source tree | `webpent_bbscout_integration/bbscout` |
| Tree file count | 39 |
| Deterministic tree SHA-256 | `93422c48afc8443fa6d32b765c2eb3f38b0b317fefbd462fd84cedb7e4f15c3f` |
| Network behavior | Provider fixtures are offline-only; no live provider smoke was run |
| Secret policy | No private keys, provider credentials, cookies, `.env`, database, cache, or runtime state included |
| Verification | `ruff check src tests scripts`; `PYTHONPATH=src pytest -q`; offline provider registry smoke |

The tree contains the signing, package verification, ingestor trust-map enforcement, provider-neutral fixture registry, four provider fixture datasets, tests, and the offline registry check. Bugcrowd, Intigriti, and YesWeHack are fixture-only in this release; no live support or authorization is claimed for them.

The source hash is a release input and must be recomputed if any file in the external bbscout tree changes.
