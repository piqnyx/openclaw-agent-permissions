# Exec policy audit notes for 2.0.14

This release is intentionally split into two layers:

1. Runtime parser correctness in `src/exec-paths.js`.
2. Operator policy tuning in `/home/openclaw/.openclaw/permissions.json`.

The plugin must not silently broaden operator policy. Scripts and runtime code do not rewrite the live permissions file.

## Parser invariants

- A bare command name is not a filesystem operand merely because it contains a dot (`mkfs.ext4`).
- Network-looking bare operands such as `1.1.1.1` and `example.com` are not guessed to be files.
- Commands that actually consume file operands detect bare relative names (`README`, `LEFT`, `SECRET`).
- File-bearing options such as `grep -f FILE`, `wc --files0-from FILE`, and `realpath --relative-to DIR` are path checked.
- Pattern/filter/format option values remain data, not filesystem targets.
- `find` roots are paths; matcher patterns are not paths; path-valued predicates such as `-newer FILE` remain protected.
- Implicit recursive cwd access (`rg PATTERN`, recursive `grep` without an explicit search path, `find` without a root, `du` without a target) remains ASK.
- Static globs remain ASK because host-side physical verification cannot prove the shell-expanded target set or symlink behavior before execution.
- Dynamic shell syntax, unsafe redirection, background execution, process substitution, and command substitution remain fail-closed.

## Policy classification target

The live policy should eventually classify commands into:

- silent read-only diagnostics;
- narrowly constrained read-only system/network diagnostics;
- ASK for active network, secret-bearing environment inspection, process/system mutation, containers, services, logs, or commands outside proven-safe forms;
- DENY for a small set of obviously catastrophic storage/power/root-destruction operations.

The final live acceptance matrix belongs after the parser release and manual policy edits, not inside release code that mutates operator configuration.
