use std::{env, fs, path::PathBuf};

fn assert_mirror(canonical: PathBuf, packaged: PathBuf) {
    println!("cargo:rerun-if-changed={}", canonical.display());
    println!("cargo:rerun-if-changed={}", packaged.display());

    // The repository-level files remain the operator-facing source of truth.
    // They are absent when crates.io builds the isolated package tarball.
    if !canonical.exists() {
        return;
    }

    let canonical_bytes = fs::read(&canonical)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", canonical.display()));
    let packaged_bytes = fs::read(&packaged)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", packaged.display()));
    let canonical_bytes = canonical_bytes
        .split(|byte| *byte == b'\r')
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    let packaged_bytes = packaged_bytes
        .split(|byte| *byte == b'\r')
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(
        canonical_bytes,
        packaged_bytes,
        "packaged settings asset {} drifted from canonical {}; update both in one commit",
        packaged.display(),
        canonical.display()
    );
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    assert_mirror(
        manifest.join("../../config/settings.defaults.json"),
        manifest.join("config/settings.defaults.json"),
    );
    assert_mirror(
        manifest.join("../../schemas/settings.schema.json"),
        manifest.join("schemas/settings.schema.json"),
    );
}
