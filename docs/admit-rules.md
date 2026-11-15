# zipslip admit rules

## Signing input
`v1|{kid}|{archive}|{entry}|{target_root}|{size}|{mode}|{iat}|{nonce}`

## Path
target_root ∈ allowed_roots; archive endswith archive_suffixes;
reject entry deny substrings; if forbid_absolute_entry and entry startswith `/` => deny;
if forbid_symlink_mode and mode ∈ symlink_modes => deny; size <= size_max;
HMAC+revoke; time; nonce allow-only.
