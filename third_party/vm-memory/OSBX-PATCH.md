# osbx patch to vm-memory 0.17.1

Upstream: https://github.com/rust-vmm/vm-memory (Apache-2.0 OR BSD-3-Clause, see LICENSE-*).

`vm-memory`'s default feature `rawfd` is a hard `compile_error!` on Windows, and `linux-loader`
and `virtio-queue` depend on `vm-memory` with default features, so a Windows build cannot turn
it off. This copy narrows every `feature = "rawfd"` gate to `all(feature = "rawfd", unix)` and
drops the `compile_error!`, so on Windows the feature is simply inert. Unix builds compile the
same code as upstream. Benchmarks and CI files were removed.

Wired in through `[patch.crates-io]` in the workspace `Cargo.toml`. Drop this directory once
upstream gates `rawfd` per platform.
