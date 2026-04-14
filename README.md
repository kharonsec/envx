# envx

Environment and secrets manager. Stores project-specific environment variables encrypted locally.

## Installation

```bash
cargo install --path .
```

## Usage

```bash
envx [COMMAND]
```

### Commands:
- `envx`: List all environment variables for the current project.
- `envx set KEY=VALUE`: Set an environment variable (encrypted).
- `envx inject <command>`: Run a command with loaded environment variables.
- `envx sync`: Sync environment variables (stub).

Example:
```bash
envx set API_KEY=secret123
envx inject cargo run
```
