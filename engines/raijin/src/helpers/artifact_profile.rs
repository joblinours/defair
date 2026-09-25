/// Detects the layout of a forensic artifact collection pointed to by `-f`
/// (a plain mount, a KAPE output folder, or an extracted Velociraptor
/// collection) and rewrites discovered artifact paths back into a clean
/// "original host path" for use in Sigma-scan alert output.
use std::fs;
use std::path::{Path, PathBuf};

/// One Velociraptor `uploads/` + `results/` pair found under the scan root,
/// with its accessor subdirectories (e.g. `ntfs`, `auto`, `file`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VelociraptorCollection {
    pub uploads_root: PathBuf,
    pub accessors: Vec<(String, PathBuf)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactProfile {
    /// KAPE output: source drive(s) mirrored under single-letter directories.
    Kape { drive_roots: Vec<(char, PathBuf)> },
    /// Extracted Velociraptor offline collection(s).
    Velociraptor { collections: Vec<VelociraptorCollection> },
    /// Plain mounted/extracted filesystem root. Also the fallback.
    Mount { root: PathBuf },
}

const KAPE_TARGET_EXTS: &[(&str, &str)] = &[("target_", ".tsv"), ("modules_", ".csv")];

fn velociraptor_collection_at(dir: &Path) -> Option<VelociraptorCollection> {
    let uploads = dir.join("uploads");
    let results = dir.join("results");
    if !uploads.is_dir() || !results.is_dir() {
        return None;
    }

    let mut accessors: Vec<(String, PathBuf)> = fs::read_dir(&uploads)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_string_lossy().into_owned();
            Some((name, path))
        })
        .collect();
    accessors.sort_by(|a, b| a.0.cmp(&b.0));

    Some(VelociraptorCollection { uploads_root: uploads, accessors })
}

/// Treats `dir` itself as an `uploads/` root when it's literally named
/// `uploads` and has at least one accessor subdirectory - handles `-f`
/// being pointed directly at the `uploads/` folder rather than its parent
/// (the collection root that normally also has a sibling `results/`). Without
/// this, that layout falls through to the `Mount` fallback and alert paths
/// come out as the raw, still-percent-encoded accessor path instead of a
/// reconstructed host path.
fn velociraptor_uploads_dir_itself(dir: &Path) -> Option<VelociraptorCollection> {
    let is_named_uploads = dir.file_name()?.to_str()?.eq_ignore_ascii_case("uploads");
    if !is_named_uploads {
        return None;
    }

    let accessors: Vec<(String, PathBuf)> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_string_lossy().into_owned();
            Some((name, path))
        })
        .collect();

    if accessors.is_empty() {
        return None;
    }

    let mut accessors = accessors;
    accessors.sort_by(|a, b| a.0.cmp(&b.0));
    Some(VelociraptorCollection { uploads_root: dir.to_path_buf(), accessors })
}

fn find_velociraptor_collections(root: &Path) -> Vec<VelociraptorCollection> {
    let mut collections: Vec<VelociraptorCollection> = Vec::new();

    if let Some(c) = velociraptor_collection_at(root) {
        collections.push(c);
    }

    for entry in fs::read_dir(root).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(c) = velociraptor_collection_at(&path) {
                collections.push(c);
            }
        }
    }

    if collections.is_empty() {
        if let Some(c) = velociraptor_uploads_dir_itself(root) {
            collections.push(c);
        }
    }

    collections
}

fn find_kape_drive_roots(root: &Path) -> Vec<(char, PathBuf)> {
    let mut roots: Vec<(char, PathBuf)> = fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?.to_string();
            let mut chars = name.chars();
            let c = chars.next()?;
            if chars.next().is_none() && c.is_ascii_uppercase() {
                Some((c, path))
            } else {
                None
            }
        })
        .collect();
    roots.sort_by_key(|(c, _)| *c);
    roots
}

fn has_kape_marker_file(root: &Path) -> bool {
    fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            let path = entry.path();
            if !path.is_file() {
                return false;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                return false;
            };
            let lower = name.to_lowercase();
            lower.ends_with("_kape.log")
                || lower.starts_with("!!!")
                || KAPE_TARGET_EXTS
                    .iter()
                    .any(|(prefix, suffix)| lower.starts_with(prefix) && lower.ends_with(suffix))
        })
}

/// Detects which of the three known artifact-collection layouts `root` is,
/// most structurally specific first. Falls back to `Mount` when neither
/// Velociraptor nor KAPE signatures are found — this covers both a genuine
/// plain mount and any unrecognized layout.
pub fn detect_artifact_profile(root: &Path) -> ArtifactProfile {
    let collections = find_velociraptor_collections(root);
    if !collections.is_empty() {
        return ArtifactProfile::Velociraptor { collections };
    }

    let drive_roots = find_kape_drive_roots(root);
    if !drive_roots.is_empty() || has_kape_marker_file(root) {
        return ArtifactProfile::Kape { drive_roots };
    }

    ArtifactProfile::Mount { root: root.to_path_buf() }
}

/// Best-effort percent-decode of a Velociraptor upload path segment,
/// verbatim on failure rather than erroring the whole scan.
fn decode_segment(raw: &str) -> String {
    urlencoding::decode(raw).map(|s| s.into_owned()).unwrap_or_else(|_| raw.to_string())
}

/// Reassembles a Velociraptor-escaped relative path into a clean host path,
/// recognizing a leading drive-letter / NTFS-device segment when present.
fn rewrite_velociraptor_rel(rel: &Path) -> String {
    let decoded: Vec<String> =
        rel.components().map(|c| decode_segment(&c.as_os_str().to_string_lossy())).collect();

    let Some(first) = decoded.first() else {
        return String::new();
    };

    let drive_letter = first
        .trim_start_matches('\\')
        .trim_start_matches('.')
        .trim_start_matches('\\')
        .chars()
        .next()
        .filter(|c| c.is_ascii_alphabetic() && first.contains(':'));

    match drive_letter {
        Some(letter) => {
            let rest = decoded[1..].join("\\");
            if rest.is_empty() {
                format!("{}:\\", letter.to_ascii_uppercase())
            } else {
                format!("{}:\\{}", letter.to_ascii_uppercase(), rest)
            }
        }
        None => decoded.join("/"),
    }
}

impl ArtifactProfile {
    /// The concrete directories the Sigma walker should recurse into.
    pub fn walk_roots(&self) -> Vec<PathBuf> {
        match self {
            ArtifactProfile::Kape { drive_roots } => {
                drive_roots.iter().map(|(_, p)| p.clone()).collect()
            }
            ArtifactProfile::Velociraptor { collections } => collections
                .iter()
                .flat_map(|c| c.accessors.iter().map(|(_, p)| p.clone()))
                .collect(),
            ArtifactProfile::Mount { root } => vec![root.clone()],
        }
    }

    /// Rewrites an on-disk discovered artifact path into a clean "original
    /// host path" string for alert display. Never fails — falls back to the
    /// raw discovered path when nothing recognizable can be reconstructed.
    pub fn rewrite_path(&self, discovered: &Path) -> String {
        match self {
            ArtifactProfile::Kape { drive_roots } => {
                for (letter, root) in drive_roots {
                    if let Ok(rel) = discovered.strip_prefix(root) {
                        let rel_str = rel.to_string_lossy().replace('/', "\\");
                        return format!("{}:\\{}", letter, rel_str);
                    }
                }
                discovered.to_string_lossy().into_owned()
            }
            ArtifactProfile::Velociraptor { collections } => {
                for c in collections {
                    for (_, accessor_root) in &c.accessors {
                        if let Ok(rel) = discovered.strip_prefix(accessor_root) {
                            return rewrite_velociraptor_rel(rel);
                        }
                    }
                }
                discovered.to_string_lossy().into_owned()
            }
            ArtifactProfile::Mount { root } => match discovered.strip_prefix(root) {
                Ok(rel) if rel.as_os_str().is_empty() => "/".to_string(),
                Ok(rel) => format!("/{}", rel.to_string_lossy().replace('\\', "/")),
                Err(_) => discovered.to_string_lossy().into_owned(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), nanos))
    }

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn make_temp_dir(prefix: &str) -> TempDir {
        let path = temp_path(prefix);
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    #[test]
    fn test_detects_kape_by_drive_letter_dir() {
        let tmp = make_temp_dir("raijin-sigma-kape-letter");
        fs::create_dir_all(tmp.0.join("C/Windows/System32/winevt/Logs")).unwrap();

        let profile = detect_artifact_profile(&tmp.0);
        match profile {
            ArtifactProfile::Kape { drive_roots } => {
                assert_eq!(drive_roots.len(), 1);
                assert_eq!(drive_roots[0].0, 'C');
                assert_eq!(drive_roots[0].1, tmp.0.join("C"));
            }
            other => panic!("expected Kape, got {:?}", other),
        }
    }

    #[test]
    fn test_detects_kape_by_marker_file_only() {
        let tmp = make_temp_dir("raijin-sigma-kape-marker");
        fs::write(tmp.0.join("!!!host_container_list.csv"), b"x").unwrap();

        let profile = detect_artifact_profile(&tmp.0);
        match profile {
            ArtifactProfile::Kape { drive_roots } => assert!(drive_roots.is_empty()),
            other => panic!("expected Kape, got {:?}", other),
        }
    }

    #[test]
    fn test_detects_velociraptor_at_root() {
        let tmp = make_temp_dir("raijin-sigma-velo-root");
        fs::create_dir_all(tmp.0.join("uploads/ntfs")).unwrap();
        fs::create_dir_all(tmp.0.join("results")).unwrap();

        let profile = detect_artifact_profile(&tmp.0);
        match profile {
            ArtifactProfile::Velociraptor { collections } => {
                assert_eq!(collections.len(), 1);
                assert_eq!(collections[0].accessors, vec![("ntfs".to_string(), tmp.0.join("uploads/ntfs"))]);
            }
            other => panic!("expected Velociraptor, got {:?}", other),
        }
    }

    #[test]
    fn test_detects_velociraptor_one_level_down() {
        let tmp = make_temp_dir("raijin-sigma-velo-nested");
        let collection_dir = tmp.0.join("Collection-HOST-2026");
        fs::create_dir_all(collection_dir.join("uploads/auto")).unwrap();
        fs::create_dir_all(collection_dir.join("results")).unwrap();

        let profile = detect_artifact_profile(&tmp.0);
        match profile {
            ArtifactProfile::Velociraptor { collections } => {
                assert_eq!(collections.len(), 1);
                assert_eq!(collections[0].uploads_root, collection_dir.join("uploads"));
            }
            other => panic!("expected Velociraptor, got {:?}", other),
        }
    }

    #[test]
    fn test_detects_velociraptor_when_f_points_at_uploads_dir_itself() {
        // Regression test: -f pointed directly at .../uploads (no sibling
        // results/ visible, since the user didn't point at its parent) must
        // still be recognized as Velociraptor, not fall through to Mount -
        // otherwise alert paths come out as the raw, still-percent-encoded
        // accessor path (e.g. "/auto/C%3A/Windows/...") instead of a
        // reconstructed host path.
        let tmp = make_temp_dir("raijin-sigma-velo-uploads-direct");
        let uploads_dir = tmp.0.join("uploads");
        fs::create_dir_all(uploads_dir.join("auto")).unwrap();

        let profile = detect_artifact_profile(&uploads_dir);
        match profile {
            ArtifactProfile::Velociraptor { collections } => {
                assert_eq!(collections.len(), 1);
                assert_eq!(collections[0].uploads_root, uploads_dir);
                assert_eq!(collections[0].accessors, vec![("auto".to_string(), uploads_dir.join("auto"))]);
            }
            other => panic!("expected Velociraptor, got {:?}", other),
        }
    }

    #[test]
    fn test_detects_mount_windows() {
        let tmp = make_temp_dir("raijin-sigma-mount-win");
        fs::create_dir_all(tmp.0.join("Windows/System32/winevt/Logs")).unwrap();

        assert_eq!(detect_artifact_profile(&tmp.0), ArtifactProfile::Mount { root: tmp.0.clone() });
    }

    #[test]
    fn test_detects_mount_linux() {
        let tmp = make_temp_dir("raijin-sigma-mount-linux");
        fs::create_dir_all(tmp.0.join("etc")).unwrap();
        fs::create_dir_all(tmp.0.join("var/log")).unwrap();

        assert_eq!(detect_artifact_profile(&tmp.0), ArtifactProfile::Mount { root: tmp.0.clone() });
    }

    #[test]
    fn test_detects_mount_as_fallback_when_ambiguous_empty_dir() {
        let tmp = make_temp_dir("raijin-sigma-mount-empty");
        assert_eq!(detect_artifact_profile(&tmp.0), ArtifactProfile::Mount { root: tmp.0.clone() });
    }

    #[test]
    fn test_rewrite_path_kape() {
        let root = PathBuf::from("/collections/case1");
        let profile = ArtifactProfile::Kape { drive_roots: vec![('C', root.join("C"))] };
        let discovered = root.join("C/Windows/System32/winevt/Logs/Security.evtx");
        assert_eq!(profile.rewrite_path(&discovered), "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx");
    }

    #[test]
    fn test_rewrite_path_velociraptor_percent_decoded() {
        let uploads_root = PathBuf::from("/collections/case1/uploads/ntfs");
        let profile = ArtifactProfile::Velociraptor {
            collections: vec![VelociraptorCollection {
                uploads_root: uploads_root.clone(),
                accessors: vec![("ntfs".to_string(), uploads_root.clone())],
            }],
        };
        let discovered = uploads_root.join("C%3A/Windows/System32/winevt/Logs/Security.evtx");
        assert_eq!(profile.rewrite_path(&discovered), "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx");
    }

    #[test]
    fn test_rewrite_path_mount() {
        let root = PathBuf::from("/mnt/evidence");
        let profile = ArtifactProfile::Mount { root: root.clone() };
        let discovered = root.join("var/log/auth.log");
        assert_eq!(profile.rewrite_path(&discovered), "/var/log/auth.log");
    }
}
