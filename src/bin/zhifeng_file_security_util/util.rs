use std::{error::Error, fs, io::Write, path::Path};

/// Save some bytes to a file. This function will try to create its parent directories if they don't exist.
pub fn save_file<P: AsRef<Path>>(path: P, buf: &[u8]) -> Result<(), Box<dyn Error>> {
    if let Ok(exists) = path.as_ref().try_exists() {
        if !exists {
            if let Some(parent_dir) = path.as_ref().parent() {
                fs::create_dir_all(parent_dir)?;
            }
        }
    } else {
        return Err(format!(
            "An error has occurred when trying to save file \"{}\"",
            path.as_ref().to_string_lossy()
        )
        .into());
    };

    let mut file = fs::File::options().write(true).truncate(true).open(path)?;
    file.write_all(buf)?;
    Ok(())
}
