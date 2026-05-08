use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum LazyReconError {
    #[error("No injectable parameters found in URL")]
    NoParams,

    #[error("Target unreachable: {0}")]
    Unreachable(String),

    #[error("Scan module error: {0}")]
    ModuleError(String),
}
