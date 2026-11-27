//! Reading OCI layer blobs: decompression (gzip, zstd or plain tar, detected from the data) and
//! whiteouts (`.wh.<name>` removes a lower path, `.wh..wh..opq` empties a lower directory).

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

/// Open a layer blob as an uncompressed tar stream.
pub fn open(blob: &Path, _media_type: &str) -> io::Result<Box<dyn Read + Send>> {
    let mut f = File::open(blob)?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    drop(f);
    let f = BufReader::with_capacity(1 << 20, File::open(blob)?);
    Ok(match &magic[..n] {
        [0x1f, 0x8b, ..] => Box::new(flate2::read::MultiGzDecoder::new(f)),
        [0x28, 0xb5, 0x2f, 0xfd] => Box::new(
            ruzstd::decoding::StreamingDecoder::new(f)
                .map_err(|e| io::Error::other(e.to_string()))?,
        ),
        _ => Box::new(f),
    })
}

/// What a layer removes from the layers below it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Whiteouts {
    /// Paths (relative, no leading `/`) to delete before extracting the layer.
    pub remove: Vec<String>,
    /// Directories whose existing contents are deleted before extracting the layer.
    pub opaque: Vec<String>,
    /// The marker files themselves (extracted as plain files; deleted afterwards).
    pub markers: Vec<String>,
}

impl Whiteouts {
    /// No whiteouts at all.
    pub fn is_empty(&self) -> bool {
        self.markers.is_empty()
    }
}

/// A relative path that stays inside the root (no `..`, not absolute after trimming).
fn clean(p: &str) -> Option<String> {
    let p = p
        .trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/');
    if p.is_empty() || p.split('/').any(|c| c == "..") {
        return None;
    }
    Some(p.to_owned())
}

/// Scan a layer for whiteouts.
pub fn whiteouts(blob: &Path, media_type: &str) -> io::Result<Whiteouts> {
    let mut w = Whiteouts::default();
    let mut ar = tar::Archive::new(open(blob, media_type)?);
    for e in ar.entries()? {
        let e = e?;
        let raw = e.path()?.to_string_lossy().into_owned();
        let Some(p) = clean(&raw) else { continue };
        let (dir, name) = p.rsplit_once('/').unwrap_or(("", p.as_str()));
        let Some(hidden) = name.strip_prefix(".wh.") else {
            continue;
        };
        if hidden == ".wh..opq" {
            if !dir.is_empty() {
                w.opaque.push(dir.to_owned());
            }
        } else if !hidden.is_empty() {
            w.remove.push(if dir.is_empty() {
                hidden.to_owned()
            } else {
                format!("{dir}/{hidden}")
            });
        }
        w.markers.push(p);
    }
    Ok(w)
}

/// The deletion script input for [`Whiteouts`]: one `R <path>` or `O <dir>` per line.
pub fn deletion_list(w: &Whiteouts) -> String {
    let mut s = String::new();
    for d in &w.opaque {
        s.push_str(&format!("O {d}\n"));
    }
    for p in &w.remove {
        s.push_str(&format!("R {p}\n"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(entries: &[(&str, &[u8])]) -> tempfile_like::TempFile {
        let mut b = tar::Builder::new(Vec::new());
        for (p, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, p, *data).unwrap();
        }
        let tar = b.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        tempfile_like::TempFile::with(&gz.finish().unwrap())
    }

    mod tempfile_like {
        pub struct TempFile(pub std::path::PathBuf);
        impl TempFile {
            pub fn with(data: &[u8]) -> Self {
                static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
                let p = std::env::temp_dir().join(format!(
                    "osbx-layer-test-{}-{}",
                    std::process::id(),
                    N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                ));
                std::fs::write(&p, data).unwrap();
                Self(p)
            }
        }
        impl Drop for TempFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
    }

    #[test]
    fn finds_whiteouts_and_decompresses() {
        let l = layer(&[
            ("etc/.wh.motd", b""),
            ("var/cache/.wh..wh..opq", b""),
            ("usr/bin/tool", b"x"),
            (".wh.opt", b""),
        ]);
        let w = whiteouts(&l.0, "").unwrap();
        assert_eq!(w.remove, ["etc/motd", "opt"]);
        assert_eq!(w.opaque, ["var/cache"]);
        assert_eq!(
            w.markers,
            ["etc/.wh.motd", "var/cache/.wh..wh..opq", ".wh.opt"]
        );
        assert_eq!(deletion_list(&w), "O var/cache\nR etc/motd\nR opt\n");
        let mut ar = tar::Archive::new(open(&l.0, "").unwrap());
        assert_eq!(ar.entries().unwrap().count(), 4);
        assert_eq!(clean("../etc"), None);
        assert_eq!(clean("./a/b/").as_deref(), Some("a/b"));
    }
}
