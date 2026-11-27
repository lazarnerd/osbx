# Provenance and clean-room policy

`osbx` is an independent implementation of the *behavior* documented for Docker
Sandboxes (`sbx`). It is not affiliated with Docker, and must not use Docker's
names, logos, endpoints, or code.

## Allowed sources
1. Public documentation, blog posts and release notes (cite in code comments or docs).
2. The Apache-2.0 Kit specification (`docker/sandbox-kit-spec`).
3. Black-box observation of `sbx` on a machine we own: CLI output, files it writes,
   traffic of its own sandboxes.

## Decompilation / binary reverse engineering
Permitted by the project owner, but **not started**. Docker's EULA may prohibit it.
Before any decompilation: get a legal review, then use a two-role split: a "spec writer"
records behavior as prose in `docs/behavior/`; implementers read only that prose.
Never copy code, string tables, assets, or branding.

## Recording assumptions
Where the public docs are silent, the code states the assumption in a doc comment
tagged `ASSUMPTION:` and a test pins it, so a later black-box check against real `sbx`
can confirm or correct it. `grep -rn "ASSUMPTION:" crates/` lists them all.
