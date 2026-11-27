//! The `balanced` preset's baseline allow-list.
//!
//! ASSUMPTION: Docker documents the categories (AI provider APIs, package managers, OS
//! package repositories, code hosts, container registries, cloud services, certificate
//! validation) but not the exact list. The hosts below are our own representative set.
//! Compare with `sbx policy ls` on a real install and sync this list.

/// Hostname patterns allowed by the `balanced` preset.
pub fn balanced_baseline() -> &'static [&'static str] {
    &[
        // AI provider APIs
        "api.anthropic.com",
        "console.anthropic.com",
        "platform.claude.com",
        "api.openai.com",
        "auth.openai.com",
        "chatgpt.com",
        "api.groq.com",
        "api.mistral.ai",
        "api.x.ai",
        "openrouter.ai",
        "api.cursor.com",
        "*.googleapis.com", // documented as part of the default rules
        // package managers
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "index.crates.io",
        "static.crates.io",
        "crates.io",
        "static.rust-lang.org",
        "sh.rustup.rs",
        "proxy.golang.org",
        "sum.golang.org",
        "repo.maven.apache.org",
        "repo1.maven.org",
        "rubygems.org",
        "index.rubygems.org",
        // OS package repositories
        "deb.debian.org",
        "security.debian.org",
        "archive.ubuntu.com",
        "security.ubuntu.com",
        "dl-cdn.alpinelinux.org",
        // code hosts
        "github.com",
        "api.github.com",
        "codeload.github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "gitlab.com",
        "bitbucket.org",
        // container registries
        "registry-1.docker.io",
        "auth.docker.io",
        "production.cloudflare.docker.com",
        // Docker Hub redirects layer downloads to its CDN (observed: `docker pull` inside a sandbox)
        "production.cloudfront.docker.com",
        "docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com",
        "hub.docker.com",
        "dhi.io",
        "ghcr.io",
        "quay.io",
        "gcr.io",
        "mcr.microsoft.com",
        // certificate validation
        "ocsp.digicert.com",
        "crl.digicert.com",
        "ocsp.sectigo.com",
        "r3.o.lencr.org",
    ]
}
