//! Negative and positive cases pinned to spec rules (section numbers in comments).

use osbx_kit::{Descriptor, validate};

fn issues(src: &str) -> Vec<String> {
    match Descriptor::from_yaml(src) {
        Err(e) => vec![format!("DECODE: {e}")],
        Ok(d) => validate(&d).into_iter().map(|i| i.to_string()).collect(),
    }
}
fn has(src: &str, needle: &str) {
    let v = issues(src);
    assert!(
        v.iter().any(|m| m.contains(needle)),
        "expected {needle:?} in {v:#?}"
    );
}
const HEAD: &str = "schemaVersion: \"3\"\nkind: mixin\n";

#[test]
fn minimal_is_valid() {
    assert!(issues(HEAD).is_empty());
}

#[test]
fn strict_decoding() {
    // §1.2: unknown field anywhere is an error
    has(&format!("{HEAD}bogus: 1\n"), "DECODE");
    has(
        &format!("{HEAD}capabilities:\n  - type: com.docker.sandbox/lifecycle@1\n    nope: 1\n"),
        "DECODE",
    );
    has(&format!("{HEAD}args:\n  a:\n    nope: 1\n"), "DECODE");
    has(&format!("{HEAD}description: \"a\\0b\"\n"), "NUL");
}

#[test]
fn top_level_rules() {
    has("schemaVersion: \"2\"\nkind: mixin\n", "must be \"3\"");
    has("schemaVersion: \"3\"\nkind: sandbox\n", "pre-rename");
    has(
        &format!("{HEAD}build: x\ndockerfile: y\n"),
        "mutually exclusive",
    );
    has(
        &format!("{HEAD}dockerfile: ../x\n"),
        "inside the descriptor",
    );
    has("schemaVersion: \"3\"\nkind: set\n", "at least one kit");
    has(&format!("{HEAD}version: v1.2\n"), "invalid version");
    has(&format!("{HEAD}iconUrl: http://x/y.png\n"), "https");
    has(
        &format!("{HEAD}providesFrom: {{git: /usr/bin/git}}\n"),
        "workload only",
    );
}

#[test]
fn kit_lists() {
    has(
        &format!("{HEAD}requires: [\"node >= 20, < 19\"]\n"),
        "unsatisfiable",
    );
    has(
        &format!(
            "{HEAD}requires: [\"gh@${{{{ kit.args.v }}}}\"]\nargs: {{v: {{default: \"1\"}}}}\n"
        ),
        "literal",
    );
    has(
        &format!("{HEAD}provides: [\"deb/bash@5.2\"]\n"),
        "derived by publishing",
    );
    has(
        &format!("{HEAD}conflicts: [podman@1]\n"),
        "invalid capability name",
    );
    has(
        "schemaVersion: \"3\"\nkind: set\nkits:\n  - ref: ./local\n",
        "registry reference",
    );
    has(
        "schemaVersion: \"3\"\nkind: set\nkits:\n  - {ref: a/b:1, digest: sha256:abc}\n",
        "sha256",
    );
    has(
        "schemaVersion: \"3\"\nkind: set\nkits:\n  - {ref: a/b:1}\n  - {ref: a/b:1}\n",
        "twice",
    );
}

#[test]
fn args() {
    has(
        &format!("{HEAD}args:\n  a: {{default: x, required: true}}\n"),
        "mutually exclusive",
    );
    has(
        &format!("{HEAD}args:\n  a: {{enum: [x], pattern: x}}\n"),
        "mutually exclusive",
    );
    has(
        &format!("{HEAD}args:\n  a: {{env: A, buildArg: B}}\n"),
        "mutually exclusive",
    );
    has(
        &format!("{HEAD}args:\n  a: {{pattern: \"(\"}}\n"),
        "does not compile",
    );
    has(
        &format!("{HEAD}args:\n  a: {{pattern: '^[0-9]+$', default: x}}\n"),
        "own pattern",
    );
    has(
        &format!("{HEAD}args:\n  \"1a\": {{default: x}}\n"),
        "name must match",
    );
    // §6: every reference must be declared; build secrets cannot be referenced
    has(
        &format!("{HEAD}provides: [\"gh@${{{{ kit.args.nope }}}}\"]\n"),
        "undeclared arg",
    );
    has(
        &format!(
            "{HEAD}provides: [\"gh@${{{{ kit.args.s }}}}\"]\nargs: {{s: {{buildSecret: S}}}}\n"
        ),
        "cannot be referenced",
    );
    // a reference in provides is legal when declared
    assert!(issues(&format!("{HEAD}provides: [\"gh@${{{{ kit.args.v }}}}\"]\nargs: {{v: {{default: \"1.0\", buildArg: V}}}}\n")).is_empty());
}

#[test]
fn capability_grammar_and_arity() {
    let cap = |body: &str| format!("{HEAD}capabilities:\n{body}");
    has(
        &cap("  - type: Bad/type@1\n"),
        "not <namespace>/<name>@<version>",
    );
    has(
        &cap("  - type: com.docker.sandbox/lifecycle@0\n"),
        "not <namespace>/<name>@<version>",
    );
    // singleton + exact duplicate
    has(
        &cap("  - type: com.docker.sandbox/kvm@1\n  - type: com.docker.sandbox/kvm@1\n"),
        "singleton",
    );
    has(
        &cap("  - type: com.docker.sandbox/kvm@1\n    config: {a: 1}\n"),
        "takes no config",
    );
    has(
        &cap(
            "  - type: com.docker.sandbox/network-policy@1\n  - type: com.docker.sandbox/network-policy@2\n",
        ),
        "exclusive",
    );
    // same singleton in two different blocks is allowed
    assert!(issues(&cap("  - type: com.docker.sandbox/lifecycle@1\n  - group:\n      capabilities:\n        - type: com.docker.sandbox/lifecycle@1\n")).is_empty());
    // unknown types ride opaquely (§7.3)
    assert!(
        issues(&cap(
            "  - type: com.example/thing@3\n    config: {anything: [1,2]}\n"
        ))
        .is_empty()
    );
}

#[test]
fn credential_and_policy_cross_rules() {
    let np = "  - type: com.docker.sandbox/network-policy@1\n    config:\n      runtime:\n        allow: [\"*.github.com\"]\n";
    let cred = |dom: &str, phase: &str| {
        format!(
            "  - type: com.docker.sandbox/credential@1\n    config:\n      service: github\n      phase: {phase}\n      apiKey:\n        name: GH_TOKEN\n        inject:\n          - {{domain: {dom}, header: Authorization, format: \"Bearer %s\"}}\n"
        )
    };
    let doc = |body: String| format!("{HEAD}capabilities:\n{body}");
    assert!(issues(&doc(format!("{np}{}", cred("api.github.com", "runtime")))).is_empty());
    // not covered by the single-label wildcard
    has(
        &doc(format!("{np}{}", cred("a.b.github.com", "runtime"))),
        "allows no such host",
    );
    // install phase has no allow list at all
    has(
        &doc(format!(
            "{np}{}",
            cred("api.github.com", "[install, runtime]")
        )),
        "phase install",
    );
    // duplicate (service, phase)
    has(
        &doc(format!(
            "{}{}",
            cred("x.com", "runtime"),
            cred("x.com", "runtime")
        )),
        "declared twice",
    );
    // needs apiKey or oauth
    has(
        &doc(
            "  - type: com.docker.sandbox/credential@1\n    config: {service: s, phase: runtime}\n"
                .into(),
        ),
        "apiKey/oauth",
    );
    // unknown key in typed config
    has(&doc("  - type: com.docker.sandbox/credential@1\n    config: {service: s, phase: runtime, apiKey: {name: X}, wat: 1}\n".into()), "wat");
}

#[test]
fn storage_rules() {
    let cap = |body: &str| format!("{HEAD}capabilities:\n{body}");
    has(
        &cap("  - type: com.docker.sandbox/host-mount@1\n    config: {path: relative}\n"),
        "absolute and canonical",
    );
    has(
        &cap("  - type: com.docker.sandbox/host-mount@1\n    config: {path: /a/}\n"),
        "absolute and canonical",
    );
    has(
        &cap("  - type: com.docker.sandbox/host-mount@1\n    config: {path: /}\n"),
        "absolute and canonical",
    );
    has(
        &cap(
            "  - type: com.docker.sandbox/host-mount@1\n    config: {path: /a}\n  - type: com.docker.sandbox/volume@1\n    config: {path: /a}\n",
        ),
        "already declared",
    );
    has(
        &cap(
            "  - type: com.docker.sandbox/dockerd@1\n  - type: com.docker.sandbox/volume@1\n    config: {path: /var/lib/docker/x}\n",
        ),
        "owned by dockerd@1",
    );
    // a reference defers typed checks to the effective form
    assert!(issues(&format!("{HEAD}args: {{p: {{default: /a}}}}\ncapabilities:\n  - type: com.docker.sandbox/host-mount@1\n    config: {{path: \"${{{{ kit.args.p }}}}\"}}\n")).is_empty());
}

#[test]
fn published_descriptors_may_carry_derived_provides() {
    let src = format!("{HEAD}provides: [\"gh@2.1\", \"deb/bash@5.2\", \"apk/musl@1.2\"]\n");
    let d = Descriptor::from_yaml(&src).unwrap();
    assert!(!osbx_kit::validate(&d).is_empty(), "authored: refused");
    assert!(
        osbx_kit::validate_published(&d).is_empty(),
        "published: fine"
    );
    let set =
        Descriptor::from_yaml("schemaVersion: \"3\"\nkind: set\nkits: [{ref: a/b:1}]\n").unwrap();
    assert!(!osbx_kit::validate_published(&set).is_empty());
}
