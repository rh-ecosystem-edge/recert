# Integration tests

Containerized etcd + scenario suite for recert. Prefer this suite for etcd,
config CLI, CN/SAN, PKCS#8 EC input, dry-run/force-expire, multi-alg JWT, and
standalone `.key`/`.pub` coverage. The host-runner [e2e crypto smoke](../../e2e_test.sh)
stays a fast crypto-dir check without Docker/etcd — do not grow e2e into a
second integration suite.

## Run

```bash
make integration-test
# Run only scenarios matching test_<tag>_*:
make integration-test INTEGRATION_ARGS="--tag etcd_kubeadmin"
```

Builds `Dockerfile.integration`, seeds etcd, generates fixtures via
[`fixtures/generate.sh`](fixtures/generate.sh), then runs
[`run_tests.sh`](run_tests.sh). Crypto/config scenarios run in parallel;
`test_etcd_*` (except `test_etcd_bad_endpoint`) run serially against the shared
etcd.

Artifacts land in `.integration-artifacts/` (mounted into the container).

## Scenario index

| Scenario | What it covers |
|----------|----------------|
| `test_config_*` | Config CLI/env, mutual exclusion, unknown keys, IP-change-only, postprocess-only |
| `test_crypto_all_key_types` | RSA-2048/4096, P-256/P-384, cross-alg leaves in one run |
| `test_crypto_rsa2048` / `rsa4096` | Single-algo RSA regen + chain verify |
| `test_crypto_ecdsa_p256` / `ecdsa_p384` | ECDSA regen + chain verify (P-384 verify enabled post-#1941) |
| `test_crypto_ed25519` | Ed25519 CA+leaf regen + chain verify |
| `test_crypto_ec_pkcs8_input` | PKCS#8 EC input; asserts `PRIVATE KEY` PEM tag |
| `test_crypto_jwt_rs256` | RS256 JWT resign + verify |
| `test_crypto_jwt_es256` | ES256 JWT resign + verify |
| `test_crypto_jwt_es384` | ES384 JWT resign + verify |
| `test_crypto_jwt_eddsa` | EdDSA JWT resign + verify |
| `test_crypto_standalone_keys` | Standalone `.key`/`.pub` (RSA PUBLIC KEY + SPKI) regen |
| `test_crypto_use_key` / `use_cert` | `--use-key` / `--use-cert` rules (incl. colon CNs) |
| `test_crypto_cn_san_*` | CN/SAN replace (incl. IPv6) |
| `test_crypto_dry_run` / `force_expire` / `extend_expiration` | Expiration / dry-run behavior |
| `test_crypto_empty_dir_ignored` | empty-dir volumes skipped |
| `test_crypto_ip_change_only_prunes` | IP-change-only pruning |
| `test_crypto_kubeconfig_embedded` | Embedded kubeconfig certs |
| `test_crypto_summary_redaction` | Summary redaction |
| `test_crypto_ssh_host_keys` | `regenerate_server_ssh_keys` replaces every host key type; refused with `dry_run` |
| `test_etcd_connect` / `bad_endpoint` | etcd connectivity |
| `test_etcd_invalid_kubelet_pull_secret` | Invalid kubelet config.json is skipped with a warning while etcd and valid filesystem pull-secret updates continue |
| `test_etcd_cluster_rename` | `cluster_rename` rewrites domain, API URLs, apps domain and infra ID across the required objects ([`lib/cluster_rename_fixtures.py`](lib/cluster_rename_fixtures.py)) and on-disk kubeconfig / `apiserver-url.env`; malformed value rejected (re-seeds the baseline) |
| `test_etcd_install_config_cidr_chrony` | `install_config`, `machine_network_cidr` (runs after, so it wins) and `chrony_config`; missing `install-config` key is an error, not a panic |
| `test_etcd_ip_rename` | `ip` single- and dual-stack: etcd pod/scripts/endpoints/secrets, apiserver etcd-servers, OVN annotation, on-disk static pods; nodes/pods deleted; IP count mismatch rejected (re-seeds the baseline) |
| `test_etcd_kubeadmin_password` | kubeadmin hash: update, delete on empty, error when the Secret is missing |
| `test_etcd_postprocess_defaults` | Always-on postprocess: leases / node-kubeconfigs deleted, CVO Available=False, OLM `olmcahash`, apiserver dep-/spec-hash annotations (re-seeds the baseline first) |
| `test_etcd_proxy_rename` | `proxy` spec values go to the Proxy spec, status values to Proxy status, operator observedConfigs, workload env, MachineConfig and on-disk `proxy.env`; malformed value rejected |
| `test_etcd_pull_secret_rename` | Pull secret replaced in the Secret, kubelet MachineConfig, and on-disk `config.json` |
| `test_etcd_user_ca_bundle` | `user_ca_bundle` (+ `proxy_trusted_ca_bundle: "user-ca-bundle:"`) rewrites the user bundle, ControllerConfig/MachineConfig/anchor copies and every injected merged bundle; documented errors |
| `test_etcd_tls_secret_regen` | TLS Secret regen round-trip |
| `test_etcd_cert_manager` | cert-manager Certificate CR rename (spiffe / comma CN-SAN) |
| `test_etcd_pem_crlf` | Mixed/CRLF PEM line endings |
| `test_etcd_json_encode` | JSON-mode etcd write-back stays JSON (not protobuf) |
| `test_etcd_bytearray_utf8` | ByteArray decode preserves multi-byte UTF-8 |
| `test_etcd_z_encryption` | aesgcm encryption round-trip (sorts last; mutates shared keyspace) |
| `test_etcd_z_encryption_aescbc` | aescbc round-trip as a rotation from aesgcm key 1; ciphertext decrypted independently with `openssl` |

Helpers live in [`lib/helpers.sh`](lib/helpers.sh) (`run_crypto_algo_test`,
`run_jwt_algo_test`, `run_encryption_roundtrip`, `assert_jwt_verifies`, etcd helpers
such as `etcd_has`/`assert_etcd_has` for protobuf-encoded values and
`machineconfig_json`/`etcd_mc_file` for MachineConfig file contents).
