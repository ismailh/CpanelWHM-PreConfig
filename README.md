# Cpanel & WHM-PreConfig v3.0

Automated, robust, and highly secure deployment script to install and configure cPanel/WHM along with essential server plugins like LiteSpeed, CloudLinux, and JetBackup 5. Designed to save significant time and ensure standard security baselines when provisioning new cPanel production servers.

> **Coded and developed by nx.lc & Bluedot Team**

---

## 🚀 How to run?

Simply execute the following command as the `root` user on a fresh operating system:

```bash
curl -Ls https://raw.githubusercontent.com/ismailh/CpanelWHM-PreConfig/refs/heads/main/2026nx.lc.sh | bash  
```

*Note: You will be prompted to enter a secret authorization phrase to execute the deployment.*

### 🗑️ Uninstalling Plugins
If you need to uninstall any of the plugins added by this script, you can run the standalone master uninstaller:

```bash
curl -Ls https://raw.githubusercontent.com/ismailh/CpanelWHM-PreConfig/refs/heads/main/uninstall_plugins.sh | bash
```

---

## 🔒 Base Hardening
- **Custom SSH Port:** `1337` (Root login allowed with Password Auth enabled)
- **Firewall:** IPTables / Firewalld replaced natively with **CSF (ConfigServer Security & Firewall)**.
- **Kernel Tuning:** Sysctl optimizations for network performance, swap reduced to 10.
- **Service Optimization:** Stops and disables unused background services (telnet, rsh, rlogin, rexec, finger, talk, ntalk, rpcbind).
- **CloudLinux Symlink Protection:** Configured with `fs.enforce_symlinksifowner` via `sysctl` dynamically based on the nobody user group (if CloudLinux is installed).
- **Compiler Access:** Completely restricted for security (`compilers off`).
- **Protection:** Shell Fork Bomb Protection enabled by default.

---

## 📦 Supported Environments & Operating Systems

**Hardware Support:**
- Fully supports **VPS (Virtual Private Servers)**
- Fully supports **Dedicated Servers / Bare Metal**

**Operating Systems (64-bit):**
- Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS
- Debian 11 / 12
- AlmaLinux 8.x / 9.x
- Rocky Linux 8.x / 9.x
- CentOS 7 / CentOS Stream 8 & 9
- CloudLinux 8 / 9

---

## 🔌 Included Software & Plugins
During the setup, the script intelligently asks if you'd like to install the following tools, fully configuring them to work together without conflicts:

- **LiteSpeed Web Server** *(Trial or Custom Serial)*
- **CloudLinux OS** *(License Activation Supported)*
- **CloudLinux CageFS** *(Automated setup & mount/unmount logic)*
- **JetBackup 5** *(Stable/Edge branch selection)*
- **Imunify360** *(Full, ImunifyAV+, or Free)*
- **Softaculous**
- **WP Toolkit**
- **ConfigServer Mail Queues (CMQ)**
- **ConfigServer ModSecurity Control (CMC)**
- **Account DNS Check**
- **CleanBackups**
- **WatchMySQL**
- **MailBaby Smarthost** *(Automated Exim routing integration)*
- **Redis & Memcached** *(Object Caching Daemons + EA4 PHP Extensions)*
- **cPanel Security Alerts To Telegram** *(CSF & WHM Contact Manager Integration)*

---

## ⚙️ Core Configurations

### Database
- **Default Installation:** MariaDB 11.4

### LiteSpeed Auto-Installer Fallback
If installed via the script fallback, the LiteSpeed WebAdmin is deployed with the following credentials:
- **User:** `admin`
- **Pass:** *(Randomly generated 12-character secure password)*

### Hardened PHP Settings (EA-PHP 7.4 to 8.4)
- **memory_limit:** `1024M`
- **post_max_size:** `100M`
- **upload_max_filesize:** `100M`
- **max_execution_time:** `200`
- **max_input_vars:** `3000`
- **date.timezone:** `UTC`
- **disable_functions:** Secured by disabling 28 high-risk functions (e.g., `exec`, `shell_exec`, `system`, `passthru`, `popen`, `proc_open`).

### WHM Tweak Settings Applied
- Background Process Killer enabled (BitchX, eggdrop, sniffers, etc.)
- Exim optimized (50MB message size limit, outbound spam detection)
- AutoSSL renewal & expiry notification spam disabled.
- Proxy Subdomains disabled.

---

## 📞 Support

If you encounter any issues or need further customization, please contact:
**Email:** ismail@bluedot.ltd  
**Website:** [https://me.ismail.info/](https://me.ismail.info/)
**Website:** [https://nx.lc/](https://nx.lc/)

---

## ☕ Donate

If this project saved you time, consider supporting the development:

[![Donate with PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg?logo=paypal)](https://www.paypal.com/donate/?hosted_button_id=YLMGDWTDQNDXW)

👉 **[Donate via PayPal](https://www.paypal.com/donate/?hosted_button_id=YLMGDWTDQNDXW)**
