# envx - Environment and Secrets Manager

`envx` is a secure environment and secrets manager for your projects. It allows you to store project-specific environment variables encrypted locally using AES-256-GCM and inject them into commands.

## Installation

### One-liner (requires Rust/Cargo)
```bash
curl -fsSL https://raw.githubusercontent.com/kharonsec/envx/master/install.sh | bash
```

### Manual
```bash
git clone https://github.com/kharonsec/envx.git
cd envx
./install.sh
```

## Usage

### Set an environment variable (encrypted)
```bash
envx set KEY=VALUE
```

### List variables for the current project
```bash
envx list
```

### Inject variables into a command
```bash
envx inject cargo run
```

### Sync variables (stub)
```bash
envx sync
```
