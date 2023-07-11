#[allow(dead_code)]
use crate::error::Error;

pub const VAR_DIR: &'static str = "VESSEL_DIR";
pub const DB_EXTENSION: &'static str = ".veas";

#[cfg(target_os = "linux")]
pub fn check_token() -> Result<(), Error> {
    let mut dir = std::env::var("HOME")?;
    dir.push_str("/.local/share/vessel/");
    if std::env::var(VAR_DIR).is_err() {
        std::env::set_var(VAR_DIR, dir);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn check_token() -> Result<(), Error> {
    let mut dir = std::env::var("LOCALAPPDATA")?;
    dir.push_str("\\vessel\\");
    if std::env::var(VAR_DIR).is_err() {
        std::env::set_var(VAR_DIR, dir);
    }
    Ok(())
}
