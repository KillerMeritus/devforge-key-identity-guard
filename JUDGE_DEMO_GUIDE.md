# Five-minute judge demo guide

Use the baseline for the live judging path. Run from a clean checkout after
[the README setup](README.md). [Original repository](https://github.com/KillerMeritus/devforge-key-identity-guard)

| Time | Show | Evidence to point out |
|---|---|---|
| 0:00–0:40 | Start `python console.py` and open http://127.0.0.1:8080. | Two running workers and one local SQLite authority. |
| 0:40–2:10 | Ask the judge to choose a crash boundary and predict the version. Run it and inspect both node cards. | HTTP 200 teammate reads and HTTP 403 revoked-device denials. The recovered version is v1 before commit and v2 after commit. After commit, both workers reject v1. |
| 2:10–3:00 | Run the opposite boundary or open a captured result. Select a revocation or rotation event. | Process interruption, observed recovery time, authenticated audit event and per-node provenance. |
| 3:00–4:10 | Open Detection View. Contrast an approval finding with a related service path and the clock-overlap note. | The finding lists source receipts, services, the rule, and explanation. Path suspicion requires investigation. |
| 4:10–5:00 | Show the scope and fallback. Use the Time Machine only if there is time. | Stale archive reads are unavailable while historical archive evidence is separately accessible. Archive mode is experimental. |

## Terminal fallback

```sh
python demo_cli.py --kill-at pre
python demo_cli.py --kill-at post
PYTHONPATH=. python scripts/evaluate_detector.py --baseline 4f75ed2
```

Run the [README verification](README.md#release-verification) before judging.
Compare status labels with HTTP output. Use the [metrics](METRICS.md) for
rubric numbers and the [coverage matrix](OBJECTIVE_COVERAGE.md) for limits.

## Team-owned submission step

**FINAL PUBLIC VIDEO URL: [TEAM TO INSERT]**

The owner will make the original repository public near submission. After
that change, verify a signed-out Git clone or browser view, the exact commit
on `main`, and the signed-out five-minute video link before submission.
