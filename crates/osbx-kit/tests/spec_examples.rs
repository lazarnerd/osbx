//! Differential check against the upstream example kits.
//!
//! Set `OSBX_SPEC_EXAMPLES` to the `examples/` directory of a checkout of
//! github.com/docker/sandbox-kit-spec. Every descriptor there must decode strictly and
//! validate cleanly. Skipped (passes) when the variable is unset.

use osbx_kit::{Descriptor, validate};
use std::path::{Path, PathBuf};

fn descriptors(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            descriptors(&p, out);
        } else if p.extension().is_some_and(|x| x == "yaml" || x == "yml") {
            out.push(p);
        }
    }
}

#[test]
fn upstream_examples_decode_and_validate() {
    let dir = std::env::var("OSBX_SPEC_EXAMPLES").unwrap_or_default();
    if dir.is_empty() || !Path::new(&dir).is_dir() {
        eprintln!("OSBX_SPEC_EXAMPLES unset or not a directory; skipping");
        return;
    }
    let mut files = Vec::new();
    descriptors(Path::new(&dir), &mut files);
    files.sort();
    let (mut checked, mut problems) = (0, Vec::new());
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        if !text.contains("schemaVersion: \"3\"")
            && !text.contains("schemaVersion: '3'")
            && !text.contains("schemaVersion: 3")
        {
            continue; // not a kit descriptor (e.g. an sbxenv or v2 file)
        }
        checked += 1;
        match Descriptor::from_yaml(&text) {
            Err(e) => problems.push(format!("{}: DECODE {e}", f.display())),
            Ok(d) => problems.extend(
                validate(&d)
                    .into_iter()
                    .map(|i| format!("{}: {i}", f.display())),
            ),
        }
    }
    eprintln!("checked {checked} descriptors");
    assert!(
        checked > 20,
        "expected to find the upstream examples, found {checked}"
    );
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}
