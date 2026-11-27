//! A small OCI distribution client: resolve `linux/amd64` images, cache blobs by digest, read
//! the image configuration and single files from the layers. No Docker needed.
//!
//! Registries: anonymous bearer-token auth (Docker Hub, GHCR, ...), or basic credentials from
//! `~/.docker/config.json` `auths` entries (credential helpers are not consulted). Proxies come
//! from `HTTPS_PROXY`/`ALL_PROXY`; TLS uses the platform's certificate store.
//!
//! Cache layout under the given root: `blobs/sha256/<hex>` (verified against their digest) and
//! `refs/<escaped reference>.json` (the resolved manifest digest, so later uses work offline).

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";

/// A parsed image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Registry host (`registry-1.docker.io` for Docker Hub).
    pub registry: String,
    /// Repository path (`library/ubuntu`).
    pub repository: String,
    /// Tag or digest (`24.04`, `sha256:...`).
    pub reference: String,
}

impl Reference {
    /// Parse `name[:tag][@digest]` with Docker's defaults (`docker.io`, `library/`, `latest`).
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() || s.contains(char::is_whitespace) {
            return Err(format!("invalid image reference {s:?}"));
        }
        let (name, reference) = if let Some((n, d)) = s.split_once('@') {
            (n, d.to_owned())
        } else {
            // a ':' after the last '/' is a tag (one before it is a registry port)
            match s.rfind(':') {
                Some(i) if !s[i..].contains('/') => (&s[..i], s[i + 1..].to_owned()),
                _ => (s, "latest".to_owned()),
            }
        };
        let (registry, repo) = match name.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_owned(), rest.to_owned())
            }
            _ => ("docker.io".to_owned(), name.to_owned()),
        };
        let (registry, repository) = if registry == "docker.io" || registry == "index.docker.io" {
            let repo = if repo.contains('/') {
                repo
            } else {
                format!("library/{repo}")
            };
            ("registry-1.docker.io".to_owned(), repo)
        } else {
            (registry, repo)
        };
        if repository.is_empty() || reference.is_empty() {
            return Err(format!("invalid image reference {s:?}"));
        }
        Ok(Self {
            registry,
            repository,
            reference,
        })
    }

    fn base(&self) -> String {
        let scheme = if self.registry.starts_with("localhost") || self.registry.starts_with("127.")
        {
            "http"
        } else {
            "https"
        };
        format!("{scheme}://{}/v2/{}", self.registry, self.repository)
    }
}

/// The parts of an image configuration a sandbox needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageConfig {
    /// Entrypoint followed by Cmd.
    pub argv: Vec<String>,
    /// `K=V` environment entries.
    pub env: Vec<String>,
    /// User to run as (empty = root).
    pub user: String,
    /// Working directory.
    pub workdir: String,
}

/// One layer blob.
#[derive(Debug, Clone)]
pub struct Layer {
    /// `sha256:...`.
    pub digest: String,
    /// Media type (gzip, zstd or plain tar).
    pub media_type: String,
    /// Compressed size.
    pub size: u64,
}

/// A resolved image.
#[derive(Debug, Clone)]
pub struct Image {
    /// Reference it was resolved from.
    pub reference: String,
    /// Digest of the image configuration (the image id).
    pub config_digest: String,
    /// Parsed configuration.
    pub config: ImageConfig,
    /// Layers, bottom first.
    pub layers: Vec<Layer>,
}

impl Image {
    /// A short stable id (first 16 hex digits of the config digest), for cache keys.
    pub fn short_id(&self) -> String {
        self.config_digest
            .trim_start_matches("sha256:")
            .chars()
            .take(16)
            .collect()
    }
}

/// Registry client with a local blob cache.
pub struct Client {
    root: PathBuf,
    agent: ureq::Agent,
    tokens: std::sync::Mutex<BTreeMap<String, String>>,
}

fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn hex_of(digest: &str) -> io::Result<&str> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| other(format!("unsupported digest {digest:?}")))?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(other(format!("malformed digest {digest:?}")));
    }
    Ok(hex)
}

/// `Bearer realm="...",service="...",scope="..."` -> parameters.
fn parse_challenge(h: &str) -> Option<BTreeMap<String, String>> {
    let rest = h
        .strip_prefix("Bearer ")
        .or_else(|| h.strip_prefix("bearer "))?;
    let mut out = BTreeMap::new();
    let mut s = rest;
    while !s.is_empty() {
        let (k, v) = s.split_once('=')?;
        let k = k.trim().trim_start_matches(',').trim().to_ascii_lowercase();
        let v = v.trim_start();
        let (val, tail) = if let Some(q) = v.strip_prefix('"') {
            let end = q.find('"')?;
            (&q[..end], &q[end + 1..])
        } else {
            let end = v.find(',').unwrap_or(v.len());
            (&v[..end], &v[end..])
        };
        out.insert(k, val.to_owned());
        s = tail.trim_start_matches(',').trim_start();
    }
    Some(out)
}

/// Basic credentials for `registry` from `~/.docker/config.json`, if any.
fn docker_config_auth(registry: &str) -> Option<String> {
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
    let path = std::env::var_os("DOCKER_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(home).join(".docker"))
        .join("config.json");
    let v: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    let keys: &[&str] = if registry == "registry-1.docker.io" {
        &[
            "https://index.docker.io/v1/",
            "index.docker.io",
            "docker.io",
            "registry-1.docker.io",
        ]
    } else {
        &[registry]
    };
    keys.iter()
        .find_map(|k| v["auths"][*k]["auth"].as_str().map(str::to_owned))
        .filter(|a| !a.is_empty())
}

impl Client {
    /// A client caching under `root`.
    pub fn new(root: &Path) -> Self {
        let tls = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .tls_config(tls)
            .proxy(ureq::Proxy::try_from_env())
            .timeout_connect(Some(std::time::Duration::from_secs(30)))
            .build()
            .into();
        Self {
            root: root.to_path_buf(),
            agent,
            tokens: Default::default(),
        }
    }

    fn token(&self, r: &Reference, challenge: &str) -> io::Result<String> {
        let p = parse_challenge(challenge)
            .ok_or_else(|| other(format!("unsupported auth challenge {challenge:?}")))?;
        let realm = p
            .get("realm")
            .ok_or_else(|| other("auth challenge without realm"))?;
        let scope = p
            .get("scope")
            .cloned()
            .unwrap_or_else(|| format!("repository:{}:pull", r.repository));
        let mut req = self.agent.get(realm).query("scope", &scope);
        if let Some(svc) = p.get("service") {
            req = req.query("service", svc);
        }
        if let Some(auth) = docker_config_auth(&r.registry) {
            req = req.header("Authorization", &format!("Basic {auth}"));
        }
        let mut resp = req.call().map_err(other)?;
        if !resp.status().is_success() {
            return Err(other(format!(
                "registry auth for {} failed: HTTP {}",
                r.repository,
                resp.status()
            )));
        }
        let v: Value = serde_json::from_slice(&resp.body_mut().read_to_vec().map_err(other)?)
            .map_err(other)?;
        v["token"]
            .as_str()
            .or_else(|| v["access_token"].as_str())
            .map(str::to_owned)
            .ok_or_else(|| other("registry auth response has no token"))
    }

    /// GET with registry auth; returns the response once it is not a 401.
    fn get(
        &self,
        r: &Reference,
        url: &str,
        accept: Option<&str>,
    ) -> io::Result<ureq::http::Response<ureq::Body>> {
        let key = format!("{}/{}", r.registry, r.repository);
        for attempt in 0..2 {
            let mut req = self.agent.get(url);
            if let Some(a) = accept {
                req = req.header("Accept", a);
            }
            if let Some(t) = self.tokens.lock().unwrap().get(&key) {
                req = req.header("Authorization", &format!("Bearer {t}"));
            } else if let Some(auth) = docker_config_auth(&r.registry) {
                req = req.header("Authorization", &format!("Basic {auth}"));
            }
            let resp = req.call().map_err(|e| other(format!("GET {url}: {e}")))?;
            if resp.status().as_u16() == 401 && attempt == 0 {
                let challenge = resp
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned();
                let t = self.token(r, &challenge)?;
                self.tokens.lock().unwrap().insert(key.clone(), t);
                continue;
            }
            if !resp.status().is_success() {
                return Err(other(format!("GET {url}: HTTP {}", resp.status())));
            }
            return Ok(resp);
        }
        Err(other(format!("GET {url}: unauthorized")))
    }

    fn blob_path(&self, digest: &str) -> io::Result<PathBuf> {
        Ok(self.root.join("blobs").join("sha256").join(hex_of(digest)?))
    }

    /// Fetch a blob into the cache (verified) unless it is there already; returns its path.
    pub fn blob(&self, r: &Reference, digest: &str) -> io::Result<PathBuf> {
        let path = self.blob_path(digest)?;
        if path.exists() {
            return Ok(path);
        }
        std::fs::create_dir_all(path.parent().unwrap())?;
        let mut resp = self.get(r, &format!("{}/blobs/{digest}", r.base()), None)?;
        let tmp = path.with_extension("part");
        let mut f = std::fs::File::create(&tmp)?;
        let mut h = Sha256::new();
        let mut rd = resp.body_mut().as_reader();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = rd.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            f.write_all(&buf[..n])?;
        }
        f.sync_all()?;
        drop(f);
        let got = format!("sha256:{:x}", h.finalize());
        if got != digest {
            let _ = std::fs::remove_file(&tmp);
            return Err(other(format!(
                "blob {digest} failed verification (got {got})"
            )));
        }
        std::fs::rename(&tmp, &path)?;
        Ok(path)
    }

    fn manifest(&self, r: &Reference, reference: &str) -> io::Result<(Value, String)> {
        // by digest: cached and verified like any blob
        if reference.starts_with("sha256:") {
            let path = self.blob_path(reference)?;
            if let Ok(data) = std::fs::read(&path) {
                return Ok((
                    serde_json::from_slice(&data).map_err(other)?,
                    reference.to_owned(),
                ));
            }
        }
        let mut resp = self.get(
            r,
            &format!("{}/manifests/{reference}", r.base()),
            Some(ACCEPT),
        )?;
        let data = resp
            .body_mut()
            .with_config()
            .limit(16 << 20)
            .read_to_vec()
            .map_err(other)?;
        let digest = format!("sha256:{:x}", Sha256::digest(&data));
        if reference.starts_with("sha256:") && digest != reference {
            return Err(other(format!("manifest {reference} failed verification")));
        }
        let path = self.blob_path(&digest)?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, &data)?;
        Ok((serde_json::from_slice(&data).map_err(other)?, digest))
    }

    fn ref_file(&self, image: &str) -> PathBuf {
        let safe: String = image
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || "._-".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.root.join("refs").join(format!("{safe}.json"))
    }

    /// Has `image` been resolved before (so [`Client::resolve`] works without the network)?
    pub fn has_ref(&self, image: &str) -> bool {
        self.ref_file(image).exists()
    }

    /// Resolve `image` for linux/amd64 and fetch its configuration (layers are fetched lazily
    /// by [`Client::layer_path`]). A reference resolved before is reused without the network
    /// unless `refresh`.
    pub fn resolve(&self, image: &str, refresh: bool) -> io::Result<Image> {
        let r = Reference::parse(image).map_err(other)?;
        let cached: Option<String> = (!refresh)
            .then(|| std::fs::read_to_string(self.ref_file(image)).ok())
            .flatten()
            .map(|s| s.trim().to_owned());
        let start = cached.unwrap_or_else(|| r.reference.clone());
        let (mut m, mut digest) = self.manifest(&r, &start)?;
        if m["manifests"].is_array() {
            let pick = m["manifests"]
                .as_array()
                .unwrap()
                .iter()
                .find(|d| {
                    d["platform"]["os"] == "linux"
                        && d["platform"]["architecture"] == "amd64"
                        && d["platform"]["variant"]
                            .as_str()
                            .is_none_or(|v| v.is_empty())
                })
                .and_then(|d| d["digest"].as_str())
                .ok_or_else(|| other(format!("{image} has no linux/amd64 variant")))?
                .to_owned();
            (m, digest) = self.manifest(&r, &pick)?;
        }
        let config_digest = m["config"]["digest"]
            .as_str()
            .ok_or_else(|| other(format!("{image}: manifest has no config")))?
            .to_owned();
        let layers = m["layers"]
            .as_array()
            .ok_or_else(|| other(format!("{image}: manifest has no layers")))?
            .iter()
            .map(|l| Layer {
                digest: l["digest"].as_str().unwrap_or_default().to_owned(),
                media_type: l["mediaType"].as_str().unwrap_or_default().to_owned(),
                size: l["size"].as_u64().unwrap_or(0),
            })
            .collect();
        let cfg_path = self.blob(&r, &config_digest)?;
        let cfg: Value = serde_json::from_slice(&std::fs::read(cfg_path)?).map_err(other)?;
        let c = &cfg["config"];
        let list = |v: &Value| -> Vec<String> {
            v.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut argv = list(&c["Entrypoint"]);
        argv.extend(list(&c["Cmd"]));
        let file = self.ref_file(image);
        std::fs::create_dir_all(file.parent().unwrap())?;
        std::fs::write(&file, &digest)?;
        Ok(Image {
            reference: image.to_owned(),
            config_digest,
            config: ImageConfig {
                argv,
                env: list(&c["Env"]),
                user: c["User"].as_str().unwrap_or("").to_owned(),
                workdir: c["WorkingDir"].as_str().unwrap_or("").to_owned(),
            },
            layers,
        })
    }

    /// The cached (fetched if needed) blob of `layer` of `image`.
    pub fn layer_path(&self, image: &Image, layer: &Layer) -> io::Result<PathBuf> {
        let r = Reference::parse(&image.reference).map_err(other)?;
        self.blob(&r, &layer.digest)
    }

    /// Read `path` (e.g. `/etc/passwd`) from the image's merged file system; `Ok(None)` if no
    /// layer has it (or a whiteout removed it).
    pub fn read_file(&self, image: &Image, path: &str) -> io::Result<Option<Vec<u8>>> {
        let want = path.trim_start_matches('/').to_owned();
        Ok(self.find_file(image, |p| p == want)?.map(|(_, d)| d))
    }

    /// The first regular file (top layer first) whose path (relative, no leading `/`)
    /// satisfies `want` and is not hidden by a whiteout in a higher layer: `(path, contents)`.
    pub fn find_file(
        &self,
        image: &Image,
        want: impl Fn(&str) -> bool,
    ) -> io::Result<Option<(String, Vec<u8>)>> {
        let mut hidden: Vec<String> = Vec::new(); // prefixes removed by higher layers
        for layer in image.layers.iter().rev() {
            let blob = self.layer_path(image, layer)?;
            let mut ar = tar::Archive::new(crate::layer::open(&blob, &layer.media_type)?);
            let mut here = Vec::new();
            for e in ar.entries()? {
                let mut e = e?;
                let p = e
                    .path()?
                    .to_string_lossy()
                    .trim_start_matches("./")
                    .to_owned();
                let (dir, name) = p.rsplit_once('/').unwrap_or(("", p.as_str()));
                if let Some(h) = name.strip_prefix(".wh.") {
                    here.push(match (h, dir.is_empty()) {
                        (".wh..opq", _) => format!("{dir}/"),
                        (_, true) => h.to_owned(),
                        (_, false) => format!("{dir}/{h}"),
                    });
                    continue;
                }
                let shadowed = hidden
                    .iter()
                    .any(|h| p == *h || p.starts_with(&format!("{}/", h.trim_end_matches('/'))));
                if e.header().entry_type().is_file() && !shadowed && want(&p) {
                    let mut data = Vec::new();
                    e.read_to_end(&mut data)?;
                    return Ok(Some((p, data)));
                }
            }
            hidden.extend(here);
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references() {
        let r = Reference::parse("ubuntu:24.04").unwrap();
        assert_eq!(
            (
                r.registry.as_str(),
                r.repository.as_str(),
                r.reference.as_str()
            ),
            ("registry-1.docker.io", "library/ubuntu", "24.04")
        );
        let r = Reference::parse("docker.io/sbx/claude").unwrap();
        assert_eq!(
            (r.repository.as_str(), r.reference.as_str()),
            ("sbx/claude", "latest")
        );
        let r = Reference::parse("ghcr.io/o/i:1.2").unwrap();
        assert_eq!(
            (r.registry.as_str(), r.repository.as_str()),
            ("ghcr.io", "o/i")
        );
        let r = Reference::parse("localhost:5000/x").unwrap();
        assert_eq!(
            (r.registry.as_str(), r.reference.as_str()),
            ("localhost:5000", "latest")
        );
        let d = format!("sha256:{}", "a".repeat(64));
        let r = Reference::parse(&format!("alpine@{d}")).unwrap();
        assert_eq!(r.reference, d);
        assert!(Reference::parse("").is_err());
    }

    #[test]
    fn challenges() {
        let p = parse_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/ubuntu:pull""#,
        )
        .unwrap();
        assert_eq!(p["realm"], "https://auth.docker.io/token");
        assert_eq!(p["scope"], "repository:library/ubuntu:pull");
        assert!(parse_challenge("Basic realm=x").is_none());
    }
}
