# 🔐 Ansible Bitwarden CLI Unofficial Wrapper

This project provides an **unofficial Ansible wrapper** around the [Bitwarden CLI](https://bitwarden.com/help/cli/) for use in self-hosted environments. It was originally created for personal use and is still in early development, so use with care.  
🧪 **Tested only on Linux. Not yet production-hardened.**

---

## 📦 Installation

```bash
ansible-galaxy collection install focshole.bitwarden_cli_wrapper
```

Make sure you preserve the directory structure so Ansible can locate it correctly.
Requires to have the [Bitwarden CLI](https://bitwarden.com/help/cli/) installed and reachable from `$PATH`

---

## 🚀 Getting Started

To access your Bitwarden vault, first **generate a client API key**. ⚠️ This script grants full access to your vault, so **avoid using it with personal vaults**—preferably, create a dedicated vault per environment or deployment.

### 1. Export required environment variables

Create a file like this and adjust the placeholders accordingly:

```bash
#!/bin/bash
export BW_SCOPE=api
export BW_GRANT_TYPE=client_credentials
export BW_CLIENT_ID=<your_client_id>
export BW_URL='https://<your.bitwarden.instance.url>'
export BW_CLIENTSECRET='<your_client_secret>'
```

Source it before running your Ansible playbooks.

---

### 2. Use in your Ansible playbook

Example playbook snippet:

```yaml
vars_prompt:
  - name: "vault_password"
    prompt: "Please enter the vault password"
    private: yes

vars:
  a_secret_from_bitwarden: "{{ lookup('focshole.ansible_bitwarden_cli_wrapper.lookup', 'password', '<secret_id>', vault_password) }}"

tasks:
  - name: Show the secret
    debug:
      var: a_secret_from_bitwarden
```

---

## 🛠️ How It Works

- Syncs the vault to a **temporary directory** on first lookup
- Opens the vault and caches the **session key**
- Reuses the session for subsequent lookups during the same execution
- Parameters passed to the lookup plugin:
  1. Bitwarden CLI `get` subcommand (e.g. `password`)
  2. ID or name of the secret
  3. Vault password (much better if prompted)

> 💡 Not intended for persistent background processes. Best used in interactive or CI environments.

---

## ⚠️ Known Limitations

- Not tested with multiple vaults
- Requires Bitwarden CLI to be installed and accessible
- Not audited for production security use

---

## ❓Why another Bitwarden-Ansible integration?

Because the official Bitwarden Secrets Manager doesn't support self-hosted deployments—and I needed a self-hosted option.  
Simple as that.
