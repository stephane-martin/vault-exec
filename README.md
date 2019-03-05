# vault-exec

`vault-exec` is a helper tool for Hashicorp's Vault. It is similar to `envconsul`: `vault-exec`
reads some secrets from Vault, sets the corresponding environment variables, and executes
a command.

Differences from `envconsul`:

- `vault-exec` can not read key/values from consul. Only from Vault.
- `vault-exec` supports various Vault authentication schemes: token, userpass, approle, ldap.
- by default `vault-exec` does not prefix environment variable keys with the secret keys.

After authentication, `vault-exec` gets a token from Vault. `vault-exec` automatically renews
the token. When the token finally expires, the command is terminated and `vault-exec` stops.

If a secret read from Vault is renewable, `vault-exec` automatically renews the secret. When
a secret finally expires, `vault-exec` terminates the command, rereads the secrets from Vault,
and then restarts the command.

Please note that Vault does not support "watching" a secret, contrary to consul. If you
modify a secret in Vault, `vault-exec` won't be aware of the change before the end of the
expiration period.

# Compilation

`vault-exec` is written in pure Go. It uses `dep` as a dependency manager. The dependencies
are committed in git. There is provided `Makefile` to set the appropriate compilation options.
So do something like :

```bash
mkdir -p ~/go/src/github.com/stephane-martin
cd ~/go/src/github.com/stephane-martin
git clone https://github.com/stephane-martin/vault-exec
cd vault-exec
make release
```

# Installation

For Linux you van just grab the provided binary in the releases section. It is
compiled statically.

# Examples


