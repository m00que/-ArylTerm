# ArylTerm Backend

Rust SSH/tmux communication probe built on `russh`.

## Run

Password auth:

```powershell
$env:ARYLTERM_SSH_PASSWORD = "your-password"
cargo run -- --host example.com --user arya --tmux main --accept-any-host-key
```

Private key auth:

```powershell
cargo run -- --host example.com --user arya --key C:\Users\arya\.ssh\id_ed25519 --tmux main --accept-any-host-key
```

Use `--host-key-sha256 SHA256:...` instead of `--accept-any-host-key` once the server fingerprint is known.
