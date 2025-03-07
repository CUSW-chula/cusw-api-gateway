use crate::models::PermissionEntry;
use config::{Config, ConfigError, File};

pub fn load_config(config_files: &[String]) -> Result<Config, ConfigError> {
    let mut builder = Config::builder();
    for file in config_files {
        builder = builder.add_source(File::with_name(file));
    }
    builder.build()
}

pub fn load_permissions(config_files: &[String]) -> Result<Vec<PermissionEntry>, ConfigError> {
    let mut permissions = Vec::new();
    for file in config_files {
        let cfg = Config::builder()
            .add_source(File::with_name(file))
            .build()?;
        if let Ok(mut perms) = cfg.get::<Vec<PermissionEntry>>("permissions") {
            permissions.append(&mut perms);
        }
    }
    Ok(permissions)
}
