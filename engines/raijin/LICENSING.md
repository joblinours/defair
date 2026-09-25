# Raijin in DEFAIR — licensing

Raijin (this directory) is distributed upstream under the GNU GPL v3.0 (see
`LICENSE`). DEFAIR vendors, modifies and redistributes it — in source form in
this repository and in binary form in the `ghcr.io/joblinours/defair` image —
under a separate permission granted by its author:

| | |
|---|---|
| Copyright holder(s) | **TODO — name(s) of every Raijin copyright holder** |
| Permission granted to | Lucas Joblin / the DEFAIR project |
| Scope | Integration, modification and redistribution of Raijin within DEFAIR without the GPL-3.0 obligations |
| Date | **TODO — date of the agreement** |
| Evidence | **TODO — reference to the written agreement (e-mail, signed letter…)** |

The permission covers Raijin's own code only. Its dependencies (including the
vendored `vendor/yara-x`, BSD-3-Clause) keep their own licenses, and so do the
detection rule sets DEFAIR installs (see `/opt/defair/rules/NOTICE` in the
image and `src/defair/rules/lock/rules.lock`).

## DEFAIR modifications

- Structured rule identity in the JSONL output (`reasons[].rule`: engine,
  name, id, namespace, file, tags, level) — `src/types.rs`,
  `src/helpers/unified_logger.rs`, `src/modules/*.rs`
- YARA sources loaded recursively per namespace, Sigma directories followed
  through symlinks — `src/main.rs`
- `raijin-util update` / `upgrade` disabled: rules come from
  `defair rules sync` (pinned + verified) and Raijin is built from this source
  in CI — `src/raijin_util/main.rs`
- Rust toolchain pinned — `rust-toolchain.toml`
