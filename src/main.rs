use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use std::collections::HashMap;
use std::fs;
use std::process::Command;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use rand::{RngCore, thread_rng};

#[derive(Parser)]
#[command(name = "envx")]
#[command(author, version, about = "Environment and secrets manager")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// List all environment variables for the current project
    List,
    /// Set an environment variable (encrypted)
    Set { pair: String },
    /// Run a command with loaded environment variables
    Inject { 
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String> 
    },
    /// Sync environment variables (stub)
    Sync,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let project_hash = get_project_hash()?;
    let storage_dir = get_storage_dir()?;
    let key = get_or_create_key(&storage_dir)?;

    match cli.command.unwrap_or(Commands::List) {
        Commands::List => {
            let envs = load_envs(&storage_dir, &project_hash, &key)?;
            for (k, v) in envs {
                println!("{}={}", k, v);
            }
        }
        Commands::Set { pair } => {
            let parts: Vec<&str> = pair.splitn(2, '=').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid format. Use KEY=VALUE"));
            }
            let key_name = parts[0];
            let value = parts[1];
            let mut envs = load_envs(&storage_dir, &project_hash, &key)?;
            envs.insert(key_name.to_string(), value.to_string());
            save_envs(&storage_dir, &project_hash, &key, &envs)?;
            println!("Set {} successfully.", key_name);
        }
        Commands::Inject { cmd } => {
            let envs = load_envs(&storage_dir, &project_hash, &key)?;
            let mut child = Command::new(&cmd[0])
                .args(&cmd[1..])
                .envs(envs)
                .spawn()
                .context("Failed to run command")?;
            child.wait()?;
        }
        Commands::Sync => {
            println!("Sync is not implemented yet (stub).");
        }
    }

    Ok(())
}

fn get_project_hash() -> Result<String> {
    let current_dir = std::env::current_dir()?;
    let path_str = current_dir.to_string_lossy();
    // A simple hash for the path
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    use std::hash::{Hash, Hasher};
    path_str.hash(&mut hasher);
    Ok(format!("{:x}", hasher.finish()))
}

fn get_storage_dir() -> Result<std::path::PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "eliott", "envx")
        .context("Could not find config directory")?;
    let dir = proj_dirs.config_dir().to_path_buf();
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn get_or_create_key(storage_dir: &std::path::Path) -> Result<[u8; 32]> {
    let key_file = storage_dir.join("master.key");
    if key_file.exists() {
        let content = fs::read(&key_file)?;
        if content.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&content);
            return Ok(key);
        }
    }
    let mut key = [0u8; 32];
    thread_rng().fill_bytes(&mut key);
    fs::write(&key_file, &key)?;
    Ok(key)
}

fn load_envs(storage_dir: &std::path::Path, hash: &str, key: &[u8; 32]) -> Result<HashMap<String, String>> {
    let env_file = storage_dir.join(format!("{}.envx", hash));
    if !env_file.exists() {
        return Ok(HashMap::new());
    }
    let content = fs::read_to_string(&env_file)?;
    if content.is_empty() {
        return Ok(HashMap::new());
    }

    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let decoded = general_purpose::STANDARD.decode(content.trim())
        .context("Failed to decode base64")?;
    
    if decoded.len() < 12 {
        return Err(anyhow::anyhow!("Invalid encrypted data"));
    }
    let (nonce_bytes, ciphertext) = decoded.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let decrypted = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
    
    let envs: HashMap<String, String> = serde_json::from_slice(&decrypted)?;
    Ok(envs)
}

fn save_envs(storage_dir: &std::path::Path, hash: &str, key: &[u8; 32], envs: &HashMap<String, String>) -> Result<()> {
    let env_file = storage_dir.join(format!("{}.envx", hash));
    let data = serde_json::to_vec(envs)?;
    
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data.as_slice())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
    
    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);
    
    let encoded = general_purpose::STANDARD.encode(combined);
    fs::write(env_file, encoded)?;
    Ok(())
}
