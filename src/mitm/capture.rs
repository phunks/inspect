use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use chrono::Utc;

#[derive(Clone, Debug)]
pub struct CapturePaths {
    pub root: PathBuf,
    pub db_path: PathBuf,
    pub flows_dir: PathBuf,
    pub filters_dir: PathBuf,
    pub generated_filters_dir: PathBuf,
    pub quarantine_filters_dir: PathBuf,
}

static CAPTURE_PATHS: OnceLock<CapturePaths> = OnceLock::new();

impl CapturePaths {
    fn build() -> std::io::Result<Self> {
        let base_dir = std::env::var("INSPECT_CAPTURE_DIR")
            .unwrap_or_else(|_| "./capture".to_string());
        let session = Utc::now().format("%Y%m%d%H%M%SZ").to_string();

        let root = PathBuf::from(base_dir).join(session);
        let db_path = root.join("index.sqlite");
        let flows_dir = root.join("flows");
        let filters_dir = root.join("filters");
        let generated_filters_dir = filters_dir.join("generated");
        let quarantine_filters_dir = filters_dir.join("quarantine");

        std::fs::create_dir_all(&flows_dir)?;
        std::fs::create_dir_all(&generated_filters_dir)?;
        std::fs::create_dir_all(&quarantine_filters_dir)?;

        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&db_path)?;

        Ok(Self {
            root,
            db_path,
            flows_dir,
            filters_dir,
            generated_filters_dir,
            quarantine_filters_dir,
        })
    }

    fn from_existing_root(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        let db_path = root.join("index.sqlite");
        let flows_dir = root.join("flows");
        let filters_dir = root.join("filters");
        let generated_filters_dir = filters_dir.join("generated");
        let quarantine_filters_dir = filters_dir.join("quarantine");

        if !db_path.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("capture database not found: {}", db_path.display()),
            ));
        }

        if !flows_dir.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("capture flows directory not found: {}", flows_dir.display()),
            ));
        }

        Ok(Self {
            root,
            db_path,
            flows_dir,
            filters_dir,
            generated_filters_dir,
            quarantine_filters_dir,
        })
    }

    pub fn write_generated_filter(
        &self,
        name: impl AsRef<str>,
        source: impl AsRef<str>,
    ) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(&self.generated_filters_dir)?;

        let file_name = generated_filter_file_name(name.as_ref());
        let path = unique_file_path(&self.generated_filters_dir, &file_name);

        std::fs::write(&path, source.as_ref())?;

        Ok(path)
    }

    pub fn quarantine_generated_filter(
        &self,
        path: impl AsRef<Path>,
    ) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(&self.quarantine_filters_dir)?;

        let path = path.as_ref();
        let file_name = path.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("generated filter path has no file name: {}", path.display()),
            )
        })?;

        let destination = unique_file_path(
            &self.quarantine_filters_dir,
            &file_name.to_string_lossy(),
        );

        std::fs::rename(path, &destination).or_else(|_| {
            std::fs::copy(path, &destination)?;
            std::fs::remove_file(path)
        })?;

        Ok(destination)
    }

    pub fn initialize_for_process() -> std::io::Result<&'static Self> {
        if let Some(existing) = CAPTURE_PATHS.get() {
            return Ok(existing);
        }

        let built = Self::build()?;
        let _ = CAPTURE_PATHS.set(built);
        Ok(CAPTURE_PATHS.get().expect("capture paths must be initialized"))
    }

    pub fn initialize_for_existing_capture(
        root: impl AsRef<Path>,
    ) -> std::io::Result<&'static Self> {
        if let Some(existing) = CAPTURE_PATHS.get() {
            return Ok(existing);
        }

        let built = Self::from_existing_root(root)?;
        let _ = CAPTURE_PATHS.set(built);
        Ok(CAPTURE_PATHS.get().expect("capture paths must be initialized"))
    }

    pub fn new() -> Self {
        CAPTURE_PATHS
            .get_or_init(|| {
                Self::build().expect("failed to initialize capture paths")
            })
            .clone()
    }
}

pub fn generated_filter_file_name(name: &str) -> String {
    let slug = slugify_filter_name(name);

    if slug.ends_with(".roto") {
        slug
    } else {
        format!("{slug}.roto")
    }
}

fn slugify_filter_name(name: &str) -> String {
    let mut out = String::new();
    let mut last_was_dash = false;

    for ch in name.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_was_dash = false;
            continue;
        }

        if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }
    }

    let slug = out.trim_matches('-');

    if slug.is_empty() {
        Utc::now().format("generated-%H%M%S").to_string()
    } else {
        slug.to_string()
    }
}

fn unique_file_path(dir: &Path, file_name: &str) -> PathBuf {
    let candidate = dir.join(file_name);

    if !candidate.exists() {
        return candidate;
    }

    let path = Path::new(file_name);
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("generated");
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("roto");

    for idx in 1.. {
        let candidate = dir.join(format!("{stem}-{idx}.{extension}"));

        if !candidate.exists() {
            return candidate;
        }
    }

    unreachable!("unbounded generated filter path search should always find a candidate")
}

impl Default for CapturePaths {
    fn default() -> Self {
        Self::new()
    }
}
