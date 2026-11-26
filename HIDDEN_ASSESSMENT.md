# Adapter contract coverage

The checks below drive the repository root `track4_service.py` as a new
subprocess for every exchange, from an unrelated working directory. The driver
checks exit status, one JSON output line, and empty stderr. The function names
are in [tests/test_root_adapter_contract.py](tests/test_root_adapter_contract.py)
under `RootAdapterContract`. Results were observed with the pinned dependencies
and synthetic fixtures.

| Requested coverage | Exact test function | Executed result |
|---|---|---|
| Root adapter subprocess behavior | `test_root_subprocess_protocol` | Pass. Initialized temp state and returned the unsupported-operation response without stderr. |
| Multiple actors and assets | `test_multiple_actors_and_assets` | Pass. Six owner, peer and missing-asset cases matched. |
| Initially disabled identities | `test_initially_disabled_identity` | Pass. Disabled owner was denied and the active peer read its asset. |
| Repeated revocation | `test_repeated_revocation` | Pass. Three revocations acknowledged, each followed by denial. The peer still read its asset. |
| Fresh-process persistence | `test_persistence_across_fresh_processes` | Pass. Setup, revocation and both correlated decisions survived process boundaries. A second setup was refused. |
| Independent state-directory isolation | `test_state_directory_isolation` | Pass. Asset contents, revocation and request IDs stayed separate across two state directories. |
| Empty and Unicode content | `test_empty_and_unicode_content` | Pass. Empty text and multilingual text including a newline and emoji round-tripped exactly. |
| Malformed requests | `test_malformed_requests` | Pass. Nine malformed request inputs returned the protocol error. |
| Independent ML-KEM interoperability | `test_cross_implementation_ml_kem_proof` | Pass. The Cryptography client decapsulated the adapter's pqcrypto ciphertext and verified the challenge/content HMAC. A different challenge's HMAC differed. |
| Malformed cryptographic inputs | `test_malformed_cryptographic_inputs` | Pass. Invalid Base64, missing or wrong lengths/types and invalid or absent challenges produced denial without proof. |
| Unauthorized protected reads | `test_unauthorized_protected_reads` | Pass. Wrong owner, disabled owner, missing asset and revoked owner received denial without a proof. |
| Correlated audit decisions | `test_audit_correlates_and_preserves_original_decision` | Pass. Allow/deny results correlated by request ID. Conflicting reuse retained both original decisions. Unknown ID returned the protocol error. |
| Deterministic randomized reference-model sequences | `test_seeded_operation_sequences_against_reference_model` | Pass. All 96 read, revoke and audit steps matched the Python ownership, revocation and first-decision model across seeds 4127 and 5905. |

```sh
python -m unittest discover -s tests -p test_root_adapter_contract.py -v
```

This is observed contract coverage for the tested synthetic cases. Official
hidden assessment results are unavailable.
