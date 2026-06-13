use std::path::PathBuf;
use std::sync::OnceLock;
use chrono::Utc;

#[derive(Clone, Debug)]
pub struct CapturePaths {
    pub root: PathBuf,
    pub db_path: PathBuf,
    pub flows_dir: PathBuf,
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

        std::fs::create_dir_all(&flows_dir)?;
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&db_path)?;

        Ok(Self { root, db_path, flows_dir })
    }

    pub fn initialize_for_process() -> std::io::Result<&'static Self> {
        if let Some(existing) = CAPTURE_PATHS.get() {
            return Ok(existing);
        }

        let built = Self::build()?;
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

impl Default for CapturePaths {
    fn default() -> Self {
        Self::new()
    }
}
