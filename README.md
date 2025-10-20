# Ansible module: splunksecrets

The `splunksecrets` module manages passwords in Splunk configuration files using INI format (e.g. `authentication.conf`).
It reads the current encrypted value from a stanza/key, decrypts it using `splunk.secret`, and compares it with the desired cleartext password.

- If the current cleartext equals the desired password: no change (`changed: false`, `msg: ok`).
- Otherwise the new password is encrypted and written to the INI file (`changed: true`, `msg: updated password`).

Supported formats: `$1$` (RC4) and `$7$` (AES‑GCM). The module takes a path to `splunk.secret`.

## Repository structure

- `library/splunksecrets.py` – Ansible module
- `module_utils/splunk_crypto.py` – crypto helpers (auto-shipped with module via Ansible)
- `inventory.ini` – local inventory (interpreter pinned to your venv)
- `ansible.cfg` – sets `library` and `module_utils` paths
- `test.yml` – example playbook for `splunksecrets`

Note: A prior demo module `hello_world` may still exist but is not required.

## Requirements

- Python 3.x
- Ansible
- For `$7$` (AES‑GCM): Python package `cryptography` (for `$1$`, a pure‑Python RC4 fallback is used if needed)

Install (optional):

```bash
python3 -m pip install --upgrade pip wheel
python3 -m pip install ansible cryptography
```

## Ansible configuration

`ansible.cfg` already contains:

```
[defaults]
library = ./library
module_utils = ./module_utils
```

`inventory.ini` pins the Python interpreter (adjust to your venv path):

```
[local]
localhost ansible_connection=local ansible_python_interpreter=/Users/andreas/venv-ansible/bin/python3
```

## Parameters (splunksecrets)

- `path` (str, required, alias `file`): path to INI file (e.g. `authentication.conf`)
- `splunksecretfile` (str, default `/opt/splunk/etc/auth/splunk.secret`): path to `splunk.secret`
- `password` (str, required, no_log=True): desired cleartext password
- `stanza` (str, required, alias `section`): INI section/stanza
- `key` (str, required): key within the stanza
- `fail_if_missing` (bool, default: true): fail if file/stanza/key are missing
- `encoding` (str, default: `utf-8`): file encoding for INI

## Behavior & idempotency

- Module decrypts the current value (if `$1$`/`$7$`).
- If cleartext equals `password` → `changed: false`, `msg: ok`.
- Otherwise it re-encrypts and writes → `changed: true`, `msg: updated password`.
- Scheme selection:
  - If old value is `$7$`: prefer `$7$` again (fallback `$1$` if AES‑GCM not available).
  - If old value is `$1$`: stay with `$1$`.
  - If no prefix: prefer `$7$`, fallback `$1$`.
- Check‑mode (`--check`) supported and shows what would change.

Return values (excerpt, no secrets):

- `changed` (bool)
- `msg` ("ok" | "updated password")
- `encryption_scheme` ("1" | "7", only on update/check‑mode)
- `path`, `stanza`, `key`

## Examples

Minimal task (adjust paths):

```yaml
- name: set passwords in authentication.conf
  splunksecrets:
    splunksecretfile: "/opt/splunk/etc/auth/splunk.secret"
    password: "MySecretPassword42!"
    path: "/opt/splunk/etc/apps/your_app/default/authentication.conf"
    stanza: "your.realm"
    key: "bindDNpassword"
```

Full example playbook (see `test.yml`):

```yaml
- name: "set splunksecrets encrypted values"
  hosts: all
  gather_facts: false
  tasks:
    - name: set passwords in authentication.conf
      splunksecrets:
        splunksecretfile: "/Users/andreas/splunk/etc/auth/splunk.secret"
        password: "Password02"
        path: "/Users/andreas/splunk/etc/apps/bw_cfg_auth-base/default/authentication.conf"
        stanza: "bwlab.loc"
        key: "bindDNpassword"

    # Check-mode example (show changes only)
    # ansible-playbook -i inventory.ini test.yml --check
```

## Run

```bash
ansible-playbook -i inventory.ini test.yml
```

## Troubleshooting

- `ModuleNotFoundError: No module named 'cryptography'`
  - Ensure Ansible uses your venv's Python (see `inventory.ini`), or install `cryptography`:
    ```bash
    python3 -m pip install cryptography
    ```

- `INI file not found` / `Stanza ... not found` / `Key ... not found`
  - Verify paths, stanza/key names, and file permissions.

- Local run uses wrong Python
  - Inspect interpreter:
    ```bash
    ansible all -i inventory.ini -m debug -a 'var=ansible_python_interpreter'
    ```

## Security

- `password` is `no_log=True` and not shown in logs.
- The module does not return cleartext secrets. Ensure restrictive permissions on `authentication.conf` and `splunk.secret`.

## References / Credits

- Crypto implementation is based on Hurricane Labs' project:
  - https://github.com/HurricaneLabs/splunksecrets (original `splunk.py`)
  - This repository adapts it as `module_utils/splunk_crypto.py` for Ansible usage.
