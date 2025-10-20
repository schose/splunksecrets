# schose.splunksecrets (Ansible Collection)

Manage encrypted passwords in Splunk INI configuration files (e.g. `authentication.conf`).
The module reads the current encrypted value from a stanza/key, decrypts it using `splunk.secret`, compares it with the desired cleartext password, and updates the file if needed.

- If current cleartext equals the desired password → no change (`changed: false`, `msg: ok`).
- Otherwise the new password is encrypted and written (`changed: true`, `msg: updated password`).

Supported formats: `$1$` (RC4) and `$7$` (AES‑GCM).

## Install

You can install this collection from Ansible Galaxy, from GitHub via requirements, or from a local build artifact.

### A) From Ansible Galaxy (recommended)

```bash
ansible-galaxy collection install git+https://github.com/schose/splunksecrets.git,main
```

### B) From GitHub (requirements.yml)

Create a `requirements.yml`:

```yaml
collections:
  - name: git+https://github.com/schose/splunksecrets.git
    type: git
    version: main   # or a tag, e.g. 1.0.0
```

Install:

```bash
ansible-galaxy collection install -r requirements.yml --force
```

### C) From a local build artifact

```bash
# in the collection root
ansible-galaxy collection build
ansible-galaxy collection install ./schose-splunksecrets-*.tar.gz --force
```

## Use in a playbook

Use the Fully Qualified Collection Name (FQCN) or declare the collection at the play level.

FQCN:

```yaml
- hosts: all
  tasks:
    - name: set passwords in authentication.conf
      schose.splunksecrets.splunksecrets:
        splunksecretfile: "/opt/splunk/etc/auth/splunk.secret"
        password: "MySecretPassword42!"
        path: "/opt/splunk/etc/apps/your_app/default/authentication.conf"
        stanza: "your.realm"
        key: "bindDNpassword"
```

With `collections:`:

```yaml
- hosts: all
  collections:
    - schose.splunksecrets
  tasks:
    - name: set passwords in authentication.conf
      splunksecrets:
        splunksecretfile: "/opt/splunk/etc/auth/splunk.secret"
        password: "MySecretPassword42!"
        path: "/opt/splunk/etc/apps/your_app/default/authentication.conf"
        stanza: "your.realm"
        key: "bindDNpassword"
```

Check-mode (dry-run):

```bash
ansible-playbook -i inventory.ini play.yml --check
```

## Module parameters

- `path` (str, required, alias `file`): path to the INI file
- `splunksecretfile` (str, default `/opt/splunk/etc/auth/splunk.secret`): path to `splunk.secret`
- `password` (str, required, no_log=True): desired cleartext password
- `stanza` (str, required, alias `section`): INI section (stanza)
- `key` (str, required): key within the stanza
- `fail_if_missing` (bool, default: true): fail if file/stanza/key are missing
- `encoding` (str, default: `utf-8`): file encoding for INI

## Requirements

- Python 3.x
- Ansible
- For `$7$` (AES‑GCM): Python package `cryptography` (for `$1$`, a pure‑Python RC4 fallback is used if needed)

Tip: If running on localhost, ensure Ansible uses your venv’s Python, e.g. via inventory:

```ini
[local]
localhost ansible_connection=local ansible_python_interpreter=/path/to/venv/bin/python3
```

## Troubleshooting

- `ModuleNotFoundError: No module named 'cryptography'`
  - Ensure Ansible uses your venv’s Python or install `cryptography`:
    ```bash
    python3 -m pip install cryptography
    ```

- Could not find module_utils
  - When using the collection, always reference the module via FQCN or add the collection under `collections:`. The collection ships its own `plugins/module_utils/splunk_crypto.py`.

## Security

- `password` is `no_log=True` and not shown in logs.
- The module does not return cleartext secrets. Ensure restrictive permissions on `authentication.conf` and `splunk.secret`.

## References / Credits

- Crypto implementation is based on Hurricane Labs’ project:
  - https://github.com/HurricaneLabs/splunksecrets (original `splunk.py`)
  - This collection adapts it as `plugins/module_utils/splunk_crypto.py` for Ansible usage.
