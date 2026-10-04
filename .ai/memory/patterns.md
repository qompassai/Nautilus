# Patterns

## Repo hygiene

- Seed zero-commit repos via Contents API PUT (blob endpoint 409s on
  zero-commit repos).
- Remove `__pycache__` before `git add -A`.
- `push_via_api.py` cannot push repos with no local parent commit.

## Repomap (codebase map for agents)

One-shot generation:

```
nix run github:qompassai/nix?dir=repomap -- /path/to/repo --budget 15000 --out .repomap.txt
```

`.repomap.txt` is a derived artifact — gitignore it, never commit it.
Covers all text files: Rust gets full tree-sitter extraction with qualified-reference ranking; Markdown, Nix, Python, Lua, Ruby, TOML, YAML, JSON, shell and others get shallow structure extraction.
