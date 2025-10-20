#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = r'''
---
module: splunksecrets
short_description: Manage Splunk encrypted passwords in INI files
description:
    - Read, decrypt and compare a password stored in a Splunk INI file and update it if necessary.
    - Supports both C($1$) (RC4) and C($7$) (AES-GCM) formats.
options:
    path:
        description:
            - Path to the INI file (e.g. C(authentication.conf)).
        required: true
        type: path
        aliases: [ file ]
    splunksecretfile:
        description:
            - Path to the Splunk secret file used for encryption and decryption.
        required: false
        type: str
        default: /opt/splunk/etc/auth/splunk.secret
    password:
        description:
            - Desired cleartext password to enforce.
        required: true
        type: str
        no_log: true
    stanza:
        description:
            - INI section (stanza) containing the key.
        required: true
        type: str
        aliases: [ section ]
    key:
        description:
            - INI key to manage within the stanza.
        required: true
        type: str
    fail_if_missing:
        description:
            - If true, fail when the file/stanza/key is missing; otherwise exit without changes.
        required: false
        type: bool
        default: true
    encoding:
        description:
            - File encoding used when reading/writing the INI file.
        required: false
        type: str
        default: utf-8
notes:
    - Supports check_mode.
    - C($7$) (AES-GCM) requires the Python package C(cryptography).
author:
    - Andreas (example)
'''

EXAMPLES = r'''
- name: Ensure bindDNpassword is set (keeping scheme)
    splunksecrets:
        splunksecretfile: "/opt/splunk/etc/auth/splunk.secret"
        path: "/opt/splunk/etc/apps/your_app/default/authentication.conf"
        stanza: "your.realm"
        key: "bindDNpassword"
        password: "MySecretPassword42!"

- name: Run in check mode (dry-run)
    hosts: all
    gather_facts: false
    tasks:
        - name: Show what would change
            splunksecrets:
                splunksecretfile: "/opt/splunk/etc/auth/splunk.secret"
                path: "/opt/splunk/etc/apps/your_app/default/authentication.conf"
                stanza: "your.realm"
                key: "bindDNpassword"
                password: "MySecretPassword42!"
            check_mode: yes
'''

RETURN = r'''
changed:
    description: Whether the INI file was updated.
    type: bool
    returned: always
msg:
    description: Result message (one of C(ok), C(updated password), C(would update password)).
    type: str
    returned: always
encryption_scheme:
    description: Encryption scheme used (C("1") for RC4, C("7") for AES-GCM).
    type: str
    returned: when changed or in check-mode
path:
    description: Absolute path to the INI file.
    type: str
    returned: always
stanza:
    description: INI stanza used.
    type: str
    returned: always
key:
    description: INI key used.
    type: str
    returned: always
found:
    description: Whether stanza/key existed.
    type: bool
    returned: always
'''

from ansible.module_utils.basic import AnsibleModule
from configparser import ConfigParser, MissingSectionHeaderError
import os

# Clean import via Ansible module_utils so the dependency is shipped with the module
from ansible_collections.schose.splunksecrets.plugins.module_utils.splunk_crypto import (  # type: ignore
    decrypt,
    encrypt,
    encrypt_new,
)

def main():
    module_args = dict(
        path=dict(type='path', required=True, aliases=['file']),
        splunksecretfile=dict(type='str', required=False, default='/opt/splunk/etc/auth/splunk.secret'),
    password=dict(type='str', required=True, no_log=True),
        stanza=dict(type='str', required=True, aliases=['section']),
        key=dict(type='str', required=True),
        default=dict(type='str', required=False, default=None),
        fail_if_missing=dict(type='bool', required=False, default=True),
        encoding=dict(type='str', required=False, default='utf-8'),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    path = module.params['path']
    stanza = module.params['stanza']
    key = module.params['key']
    default = module.params.get('default')
    fail_if_missing = module.params.get('fail_if_missing', False)
    encoding = module.params.get('encoding', 'utf-8')

    # Determine normalized path (for output)
    abs_path = os.path.abspath(path)

    result = {
        'changed': False,
        'path': abs_path,
        'stanza': stanza,
        'key': key,
        'found': False,
    }

    # Check mode: reading is safe, continue normally as no changes are performed until write

    # File exists?
    if not os.path.exists(path):
        if fail_if_missing:
            module.fail_json(msg=f"INI file not found: {abs_path}", **result)
        # Not found and allowed to continue: exit without value to avoid leaking defaults
        module.exit_json(**result)

    # Read INI
    # Preserve key case when reading/writing
    parser = ConfigParser()
    # By default, ConfigParser lower-cases option names. We need to preserve case.
    # Setting optionxform to str keeps the original casing intact.
    parser.optionxform = str  # type: ignore[attr-defined]
    try:
        # ConfigParser.read accepts encoding in Python 3
        read_ok = parser.read(path, encoding=encoding)
        if not read_ok:
            # File exists but could not be read (e.g., empty)
            if fail_if_missing:
                module.fail_json(msg=f"INI file could not be read or is empty: {abs_path}", **result)
            module.exit_json(**result)
    except MissingSectionHeaderError as e:
        # No sections – invalid INI
        if fail_if_missing:
            module.fail_json(msg=f"Invalid INI format: {e}", **result)
        module.exit_json(**result)
    except Exception as e:
        module.fail_json(msg=f"Error reading INI file: {e}", **result)

    # Section/Stanza present?
    if not parser.has_section(stanza) and stanza != parser.default_section:
        if fail_if_missing:
            module.fail_json(msg=f"Stanza/section '{stanza}' not found in {abs_path}", **result)
        module.exit_json(**result)

    # Key present? We want a case-insensitive check but preserve original case for write-back
    actual_key = None
    if parser.has_section(stanza) or stanza == parser.default_section:
        try:
            for existing_key in parser.options(stanza):
                if existing_key.lower() == key.lower():
                    actual_key = existing_key
                    break
        except Exception:
            pass

    if actual_key is None:
        if fail_if_missing:
            module.fail_json(msg=f"Key '{key}' in stanza '{stanza}' not found in {abs_path}", **result)
        module.exit_json(**result)

    # Read value
    try:
        value = parser.get(stanza, actual_key)
    except Exception as e:
        module.fail_json(msg=f"Error reading '{stanza}.{key}': {e}", **result)



    # Read Splunk secret file as bytes (decrypt expects bytes for $1$)
    try:
        with open(module.params['splunksecretfile'], 'rb') as f:
            secret = f.read()
    except Exception as e:
        module.fail_json(msg=f"Error reading Splunk secret file '{module.params['splunksecretfile']}': {e}", **result)

    # Decrypt; if decrypt returns None (e.g., no $1$/$7$ prefix), use original value
    try:
        decrypted = decrypt(secret, value, nosalt=False)
    except Exception as e:
        module.fail_json(msg=f"Error decrypting value from '{stanza}.{key}': {e}", **result)
    decrypted_pw = decrypted if decrypted is not None else value

    # Compare: if desired password equals current plain text -> ok
    desired_password = module.params['password']

    result['found'] = True

    if desired_password == decrypted_pw:
        result['changed'] = False
        result['msg'] = 'ok'
        module.exit_json(**result)

    # Otherwise: encrypt and write new password
    # Determine scheme: keep $7$ if present, else $1$; if none present prefer $7$
    try:
        if isinstance(value, str) and value.startswith('$7$'):
            try:
                new_encrypted = encrypt_new(secret, desired_password)
                scheme = '7'
            except Exception:
                # Fallback: if encrypt_new is not available, use RC4 ($1$)
                new_encrypted = encrypt(secret, desired_password, nosalt=False)
                scheme = '1'
        elif isinstance(value, str) and value.startswith('$1$'):
            new_encrypted = encrypt(secret, desired_password, nosalt=False)
            scheme = '1'
        else:
            # no prefix detected: prefer new $7$ schema
            try:
                new_encrypted = encrypt_new(secret, desired_password)
                scheme = '7'
            except Exception:
                new_encrypted = encrypt(secret, desired_password, nosalt=False)
                scheme = '1'
    except Exception as e:
        module.fail_json(msg=f"Error encrypting new password: {e}", **result)

    # honor check_mode
    if module.check_mode:
        result['changed'] = True
        result['msg'] = 'would update password'
        result['encryption_scheme'] = scheme
        module.exit_json(**result)

    # Update INI and write back
    try:
        # Write back using the original key spelling
        parser.set(stanza, actual_key, new_encrypted)
        with open(path, 'w', encoding=encoding) as fh:
            parser.write(fh)
    except Exception as e:
        module.fail_json(msg=f"Error writing INI file: {e}", **result)

    result['changed'] = True
    result['msg'] = 'updated password'
    result['encryption_scheme'] = scheme
    module.exit_json(**result)


if __name__ == '__main__':
    main()
