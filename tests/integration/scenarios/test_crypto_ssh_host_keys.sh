#!/usr/bin/env bash
# regenerate_server_ssh_keys: every existing host key type is replaced by a fresh key of
# the same type (so clusters cloned from one seed don't share host keys), and the option
# is rejected with dry_run because regeneration deletes the old keys.

set -euo pipefail

workdir=$(setup_test_workdir "crypto_ssh_host_keys")
crypto_dir=$(setup_crypto_dir "$workdir" ca.crt ca.key)
ssh_dir="${workdir}/ssh"
mkdir -p "$ssh_dir"

key_types=(rsa ecdsa ed25519)
declare -A fingerprints_before
for type in "${key_types[@]}"; do
    ssh-keygen -q -t "$type" -N '' -C seed -f "${ssh_dir}/ssh_host_${type}_key"
    fingerprints_before[$type]=$(ssh-keygen -l -f "${ssh_dir}/ssh_host_${type}_key" | awk '{print $2}')
done

ssh_dir_listing() {
    (cd "$ssh_dir" && ls | sort | tr '\n' ' ')
}
listing_before=$(ssh_dir_listing)
tree_hash_before=$(cat "$ssh_dir"/* | sha256sum)

write_config() {
    cat > "${workdir}/config.yaml" <<EOF
crypto_dirs:
  - ${crypto_dir}
regenerate_server_ssh_keys: ${ssh_dir}
summary_file: ${workdir}/summary.yaml
$1
EOF
}

# 1. dry_run must be refused before any key is touched.
write_config "dry_run: true"
output=$(RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_failure)
assert_contains "$output" "dry_run and regenerate_server_ssh_keys are mutually exclusive" \
    "dry_run with regenerate_server_ssh_keys should be rejected"
assert_eq "$(cat "$ssh_dir"/* | sha256sum)" "$tree_hash_before" "dry_run must leave the SSH host keys untouched"

# 2. A real run regenerates every key type and nothing else.
write_config "force_expire: true"
RECERT_CONFIG="${workdir}/config.yaml" run_recert_expect_success >/dev/null

assert_eq "$(ssh_dir_listing)" "$listing_before" "the same set of key files should exist after regeneration"
for type in "${key_types[@]}"; do
    key="${ssh_dir}/ssh_host_${type}_key"
    fingerprint=$(ssh-keygen -l -f "$key" | awk '{print $2}')
    assert_ne "$fingerprint" "${fingerprints_before[$type]}" "${type} host key should be regenerated"
    assert_eq "$(ssh-keygen -y -f "$key" | awk '{print $1, $2}')" "$(awk '{print $1, $2}' "${key}.pub")" \
        "${type} public key should match the regenerated private key"
done
