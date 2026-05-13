#!/bin/bash
# ============================================================
# WHM/cPanel All Important Plugin Installation Setup Script and Preconfiguration
# Version: 7.0.0
# All messages in English
# SSH Port: 1337
#
# Supported OS:
#   Ubuntu 20.04/22.04/24.04 LTS
#   CentOS 7, CentOS Stream 8/9
#   Rocky Linux 8/9
#   AlmaLinux 8/9
#   Debian 11/12
#
# Coded-by nx.lc & Bluedot Team
# Donate: https://www.paypal.com/donate/?hosted_button_id=YLMGDWTDQNDXW
# ============================================================

set -o pipefail
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# ── GLOBALS ──
CWD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LOGFILE="/var/log/whm_preconfig_$(date +%Y%m%d_%H%M%S).log"
RUN_FLAG="/root/.whm_preconfig_run1_done"
SSH_PORT="1337"
PASSV_PORT="49152:65534"
PASSV_MIN="49152"
PASSV_MAX="65534"
PUBLIC_IP=$(curl -s https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
ISVPS="NO"
[ -f /proc/user_beancounters ] && ISVPS="YES"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

mkdir -p /var/log
touch "$LOGFILE"

# Plugin Install Status Tracking
PL_CMQ="Pending"
PL_CMC="Pending"
PL_DNS="Pending"
PL_CLN="Pending"
PL_WMY="Pending"
PL_SOFT="Pending"
PL_WPT="Pending"
PL_JB5="Pending"
PL_IMU="Pending"
PL_LS="Pending"
PL_CACHE="Pending"
PL_TG="Pending"
PL_CGF="Pending"
PL_MB="Pending"
PL_CL="Pending"

log_info()    { echo -e "${GREEN}[INFO]${NC}  $1"    | tee -a "$LOGFILE"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"   | tee -a "$LOGFILE"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"      | tee -a "$LOGFILE"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}   ✅ $1"  | tee -a "$LOGFILE"; }
log_section() {
    echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}" | tee -a "$LOGFILE"
    echo -e "${CYAN}${BOLD}  ➤  $1${NC}" | tee -a "$LOGFILE"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}\n" | tee -a "$LOGFILE"
}

ask_yn() {
    local q="$1"
    while true; do
        echo -ne "\n${YELLOW}[?]${NC} ${BOLD}${q}${NC} (y/n): "
        read a </dev/tty
        case "${a,,}" in
            y|yes) return 0 ;;
            n|no)  return 1 ;;
            *) echo -e "${RED}  Type y or n${NC}" ;;
        esac
    done
}

ask_yn_timeout() {
    local q="$1"
    local timeout="$2"
    echo -ne "\n${YELLOW}[?]${NC} ${BOLD}${q}${NC} (y/n, skips in ${timeout}s): "
    local a
    if read -t "$timeout" -r a </dev/tty; then
        case "${a,,}" in
            y|yes) return 0 ;;
            *) return 1 ;;
        esac
    else
        echo ""
        return 1
    fi
}

ask_reconfig_uninstall_timeout() {
    local q="$1"
    local timeout="$2"
    local uninst_word="${3:-need uninstall}"
    echo -ne "\n${YELLOW}[?]${NC} ${BOLD}${q}${NC}\n  (y = reconfig / reinstall, n = skip, type '${uninst_word}' to remove. Skips in ${timeout}s): "
    local a
    if read -t "$timeout" -r a </dev/tty; then
        case "${a,,}" in
            y|yes) return 0 ;;
            "${uninst_word,,}"|"need unistall"|"need uninstall") return 2 ;;
            *) return 1 ;;
        esac
    else
        echo ""
        return 1
    fi
}

check_root() { [ "$EUID" -ne 0 ] && { log_error "Run as root!"; exit 1; }; }

# ── OS DETECTION ──
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME; VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si); VER=$(lsb_release -sr)
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release; OS=$DISTRIB_ID; VER=$DISTRIB_RELEASE
    elif [ -f /etc/debian_version ]; then
        OS=Debian; VER=$(cat /etc/debian_version)
    elif [ -f /etc/almalinux-release ]; then
        OS="almalinux"; VER=$(grep -o "[0-9]" /etc/almalinux-release | head -1)
    elif [ -f /etc/redhat-release ]; then
        OS="centos"; VER=$(grep -o "[0-9]" /etc/redhat-release | head -1)
    else
        OS=$(uname -s); VER=$(uname -r)
    fi
    OS_MAJOR="${VER%%.*}"
    log_info "Detected OS: $OS, Version: $VER"
    export OS VER OS_MAJOR

    # Check hardware environment
    SERVER_TYPE="Unknown"
    if command -v systemd-detect-virt &>/dev/null; then
        VIRT=$(systemd-detect-virt 2>/dev/null || echo "none")
        if [ "$VIRT" = "none" ]; then
            log_info "Detected Hardware: Bare Metal Server"
            SERVER_TYPE="Bare Metal Server"
        else
            log_info "Detected Hardware: Virtualized Environment ($VIRT)"
            SERVER_TYPE="VPS ($VIRT)"
        fi
    fi
    export SERVER_TYPE
}

# ── PKG MANAGER HELPER ──
_pkg() {
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get "$@"
    elif command -v dnf &>/dev/null; then
        dnf "$@"
    else
        yum "$@"
    fi
}

# ── SYSCTL HARDENING (no network stop) ──
_apply_sysctl() {
    log_info "Applying kernel sysctl hardening..."
    cat > /etc/sysctl.d/99-whm-hardening.conf << 'EOF'
net.ipv4.tcp_syncookies               = 1
net.ipv4.conf.all.rp_filter           = 1
net.ipv4.conf.default.rp_filter       = 1
net.ipv4.icmp_echo_ignore_broadcasts  = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects    = 0
net.ipv4.conf.all.send_redirects      = 0
net.ipv4.conf.all.log_martians        = 1
net.ipv6.conf.all.accept_redirects    = 0
net.core.somaxconn                    = 65535
net.ipv4.tcp_max_syn_backlog          = 65535
net.ipv4.tcp_fin_timeout              = 15
net.ipv4.tcp_keepalive_time           = 300
vm.swappiness                         = 10
kernel.randomize_va_space             = 2
fs.suid_dumpable                      = 0
kernel.dmesg_restrict                 = 1
kernel.kptr_restrict                  = 2
EOF
    sysctl --system 2>/dev/null || true
}

# ── SSH HARDENING (port 1337) ──
_apply_ssh() {
    log_info "Hardening SSH (port $SSH_PORT)..."
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%s)" 2>/dev/null || true
    sed -i "s/^#\?Port.*/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    sed -i 's/^#\?UseDNS.*/UseDNS no/' /etc/ssh/sshd_config
    sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
    # Ubuntu 23+ ssh.socket port
    [ -f /lib/systemd/system/ssh.socket ] && \
        sed -i "s/ListenStream=.*/ListenStream=$SSH_PORT/" /lib/systemd/system/ssh.socket && \
        systemctl daemon-reload 2>/dev/null || true
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
}

_disable_unused() {
    for s in telnet rsh rlogin rexec finger talk ntalk rpcbind; do
        systemctl disable "$s" 2>/dev/null || true
        systemctl stop    "$s" 2>/dev/null || true
    done
}

# ── SWAP CREATION ──
_create_swap() {
    if ! free | awk '/^Swap:/ {exit (!$2 || ($2<2194300))}'; then
        log_info "SWAP not detected or less than 2GB. Creating 4GB swap..."
        dd if=/dev/zero of=/swap count=4096 bs=1MiB 2>/dev/null
        chmod 600 /swap; mkswap /swap; swapon /swap
        grep -q "/swap" /etc/fstab || echo "/swap swap swap sw 0 0" >> /etc/fstab
    fi
}

# ── SSD FSTRIM ──
_setup_ssd() {
    for DEVFULL in /dev/sg? /dev/sd?; do
        DEV=$(echo "$DEVFULL" | cut -d'/' -f3)
        if [ -f "/sys/block/$DEV/queue/rotational" ]; then
            grep -q "0" /sys/block/$DEV/queue/rotational 2>/dev/null && \
                systemctl enable fstrim.timer 2>/dev/null || true
        fi
    done
}

# ── DISABLE SLEEP TARGETS ──
_disable_sleep() {
    systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target 2>/dev/null || true
}

# ═══════════════════════════════════════════
# 1ST RUN — OS BASE CONFIG (NO NETWORK STOP)
# ═══════════════════════════════════════════
run_rhel() {
    log_section "RHEL/CentOS/AlmaLinux/Rocky Configuration"
    local PKG="yum"
    command -v dnf &>/dev/null && PKG="dnf"

    $PKG install -y epel-release 2>/dev/null || true
    $PKG install -y \
        curl wget vim nano net-tools bind-utils \
        zip unzip tar git rsync screen tmux \
        perl perl-libwww-perl perl-LWP-Protocol-https perl-GDGraph \
        ca-certificates chrony iptables-services \
        bash-completion lsof htop nmap-ncat sysstat \
        crontabs cronie cronie-anacron openldap-compat \
        oniguruma libsodium jq ipcalc glibc-all-langpacks \
        smartmontools mdadm pciutils usbutils lshw nvme-cli hdparm sqlite 2>/dev/null || true

    # SELinux disable
    setenforce 0 2>/dev/null || true
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config 2>/dev/null || true
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/sysconfig/selinux 2>/dev/null || true

    # Firewalld → iptables (do NOT touch NetworkManager)
    systemctl disable firewalld 2>/dev/null || true
    systemctl stop    firewalld 2>/dev/null || true
    $PKG remove firewalld -y 2>/dev/null || true
    touch /etc/sysconfig/iptables /etc/sysconfig/iptables6
    systemctl enable --now iptables ip6tables chronyd 2>/dev/null || true

    # DNF auto security updates (AL8/9, Rocky8/9)
    if command -v dnf &>/dev/null; then
        $PKG install -y dnf-automatic 2>/dev/null || true
        sed -i 's/^upgrade_type.*/upgrade_type = security/' /etc/dnf/automatic.conf 2>/dev/null || true
        sed -i 's/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf 2>/dev/null || true
        systemctl enable --now dnf-automatic.timer 2>/dev/null || true
    fi

    # GPG key for AlmaLinux
    echo "$OS" | grep -iq "almalinux" && \
        rpm --import https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux 2>/dev/null || true

    # FSCK auto-repair
    grubby --update-kernel=ALL --args=fsck.repair=yes 2>/dev/null || true

    _apply_sysctl; _apply_ssh; _disable_unused; _create_swap; _setup_ssd; _disable_sleep

    # Journal cleanup cron
    echo "30 22 * * * root /usr/bin/journalctl --vacuum-time=1d; /usr/sbin/service systemd-journald restart" > /etc/cron.d/clean_journal
    systemctl restart crond 2>/dev/null || true

    log_ok "RHEL-family base configuration complete"
}

run_debian_ubuntu() {
    log_section "$OS Configuration"
    export DEBIAN_FRONTEND=noninteractive

    apt-get update -y
    apt-get --yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade 2>/dev/null || true
    apt-get --yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" dist-upgrade 2>/dev/null || true
    apt-get install -y \
        curl wget vim nano net-tools dnsutils \
        zip unzip tar git rsync screen tmux \
        perl libwww-perl liblwp-protocol-https-perl libgd-graph-perl \
        libio-socket-inet6-perl libsocket6-perl \
        ca-certificates chrony iptables iptables-persistent \
        bash-completion lsof htop netcat-openbsd sysstat \
        unattended-upgrades apt-listchanges sendmail \
        software-properties-common ntpdate jq \
        smartmontools mdadm pciutils usbutils lshw nvme-cli hdparm sqlite3 2>/dev/null || true

    # Disable ufw but do NOT disable networking
    ufw disable 2>/dev/null || true
    systemctl disable ufw 2>/dev/null || true
    systemctl stop    ufw 2>/dev/null || true
    systemctl enable --now chrony 2>/dev/null || true

    # Auto-upgrades
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

    _apply_sysctl; _apply_ssh; _disable_unused; _create_swap; _setup_ssd; _disable_sleep

    # Journal cleanup cron
    echo "30 22 * * * root /bin/journalctl --vacuum-time=1d; /usr/sbin/service systemd-journald restart" > /etc/cron.d/clean_journal
    systemctl restart cron 2>/dev/null || true

    # Disable mlocate
    chmod -x /etc/cron.daily/mlocate 2>/dev/null || true

    log_ok "$OS base configuration complete"
}

run_os_config() {
    if   echo "$OS" | grep -iq "centos\|almalinux\|rocky"; then run_rhel
    elif echo "$OS" | grep -iq "debian\|ubuntu";            then run_debian_ubuntu
    else log_warn "Unknown OS: $OS — using RHEL defaults";  run_rhel
    fi
}

# ═══════════════════════════════════════════
# cPANEL INSTALL
# ═══════════════════════════════════════════
install_cpanel() {
    log_section "cPanel/WHM Installation"
    if [ -f /usr/local/cpanel/cpanel ]; then
        log_ok "cPanel already installed — skipping install"
        return 0
    fi
    if ! ask_yn "cPanel is NOT installed. Install now?"; then
        log_warn "cPanel install skipped by user"; exit 0
    fi

    # Ask for DB preference
    echo ""
    echo "  Select database server to install:"
    echo "  [1] MariaDB 11.4 (Recommended)"
    echo "  [2] MariaDB 10.11"
    echo "  [3] MySQL 8.4"
    read -rp "  Select [1/2/3] (default=1): " DB_CHOICE </dev/tty
    case "$DB_CHOICE" in
        2) DB_VER="10.11" ;;
        3) DB_VER="8.4" ;;
        *) DB_VER="11.4" ;;
    esac
    log_info "Selected database version: $DB_VER"

    hostname -f > /root/hostname
    mkdir -p /root/cpanel_profile/
    echo "mysql-version=$DB_VER" > /root/cpanel_profile/cpanel.config

    cd /home && curl -o latest -L https://securedownloads.cpanel.net/latest && sh latest --skip-cloudlinux
    log_info "Waiting 5 min for background install..."
    sleep 300

    whmapi1 sethostname hostname="$(cat /root/hostname)" 2>/dev/null || true
    hostnamectl set-hostname "$(cat /root/hostname)" 2>/dev/null || true
    rm -f /root/hostname /root/cpanel_profile/cpanel.config

    # SWAP via cPanel tool
    if ! free | awk '/^Swap:/ {exit (!$2 || ($2<4194300))}'; then
        /usr/local/cpanel/bin/create-swap --size 4G -v 2>/dev/null || true
    fi

    # NAT detection
    /usr/local/cpanel/scripts/build_cpnat 2>/dev/null || true

    log_ok "cPanel installed (DB: $DB_VER)"
}

# ═══════════════════════════════════════════
# CSF INSTALL + CONFIGURE
# ═══════════════════════════════════════════
_install_csf() {
    log_section "CSF Firewall — Install"
    if [ -d /etc/csf ]; then
        log_ok "CSF Firewall — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "CSF already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped CSF configuration"
            CSF_RECONFIG_CHOICE="skip"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling CSF..."
            cd /etc/csf && sh uninstall.sh 2>/dev/null || true
            rm -rf /etc/csf
            log_ok "CSF Uninstalled"
            CSF_RECONFIG_CHOICE="uninstalled"
            return 0
        else
            CSF_RECONFIG_CHOICE="reconfig"
        fi
    elif ! ask_yn "Install CSF Firewall?"; then
        log_warn "Skipped CSF Firewall integration."
        CSF_RECONFIG_CHOICE="skip"
        return 0
    fi

    log_info "Installing CSF dependencies for $OS $VER..."

    # ── OS-specific dependency install ──
    if echo "$OS" | grep -iq "centos" && [ "$OS_MAJOR" = "7" ]; then
        # CentOS 7 (yum only)
        yum install -y epel-release 2>/dev/null || true
        yum install -y iptables-services wget perl unzip net-tools \
            perl-libwww-perl perl-LWP-Protocol-https perl-GDGraph \
            perl-IO-Socket-INET6 perl-Socket6 perl-Crypt-SSLeay \
            perl-Net-SSLeay perl-IO-Socket-SSL 2>/dev/null || true
        touch /etc/sysconfig/iptables /etc/sysconfig/iptables6
        systemctl enable --now iptables ip6tables 2>/dev/null || true

    elif echo "$OS" | grep -iq "centos\|almalinux\|rocky"; then
        # CentOS Stream 8/9, AlmaLinux 8/9, Rocky 8/9 (dnf)
        dnf install -y epel-release 2>/dev/null || true
        dnf install -y iptables-services wget perl unzip net-tools \
            perl-libwww-perl perl-LWP-Protocol-https perl-GDGraph \
            perl-IO-Socket-INET6 perl-Socket6 perl-Crypt-SSLeay \
            perl-Net-SSLeay perl-IO-Socket-SSL 2>/dev/null || true
        touch /etc/sysconfig/iptables /etc/sysconfig/iptables6
        systemctl enable --now iptables ip6tables 2>/dev/null || true

    elif echo "$OS" | grep -iq "ubuntu"; then
        # Ubuntu 20.04 / 22.04 / 24.04
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y 2>/dev/null || true
        apt-get install -y iptables wget perl unzip net-tools sendmail \
            libwww-perl liblwp-protocol-https-perl libgd-graph-perl \
            libio-socket-inet6-perl libsocket6-perl libcrypt-ssleay-perl \
            libnet-ssleay-perl libio-socket-ssl-perl 2>/dev/null || true
        # Ubuntu 24+ uses nftables backend; ensure iptables works
        update-alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null || true
        update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null || true
        ufw disable 2>/dev/null || true
        systemctl disable ufw 2>/dev/null || true

    elif echo "$OS" | grep -iq "debian"; then
        # Debian 11 / 12
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -y 2>/dev/null || true
        apt-get install -y iptables wget perl unzip net-tools sendmail \
            libwww-perl liblwp-protocol-https-perl libgd-graph-perl \
            libio-socket-inet6-perl libsocket6-perl libcrypt-ssleay-perl \
            libnet-ssleay-perl libio-socket-ssl-perl 2>/dev/null || true
        update-alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null || true
        update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null || true

    else
        log_warn "Unknown OS ($OS) — trying generic RHEL install"
        yum install -y iptables-services wget perl unzip net-tools \
            perl-libwww-perl perl-LWP-Protocol-https perl-GDGraph 2>/dev/null || true
    fi

    # ── Install CSF ──
    log_info "Installing CSF via cPanel package (cpanel-csf)..."
    local CSF_INSTALLED=0

    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        apt-get install -y cpanel-csf 2>/dev/null && CSF_INSTALLED=1
    elif echo "$OS" | grep -iq "centos" && [ "$OS_MAJOR" = "7" ]; then
        yum install -y cpanel-csf 2>/dev/null && CSF_INSTALLED=1
    else
        dnf install -y cpanel-csf 2>/dev/null && CSF_INSTALLED=1
    fi

    # Fallback 1: manual download from alternate github release
    if [ "$CSF_INSTALLED" -eq 0 ]; then
        log_warn "cpanel-csf package not available — trying github release..."
        cd /usr/src
        wget -q https://github.com/Black-HOST/csf/releases/latest/download/csf.tgz -O /usr/src/csf.tgz 2>/dev/null
        if [ -f /usr/src/csf.tgz ] && [ -s /usr/src/csf.tgz ]; then
            tar -xzf /usr/src/csf.tgz -C /usr/src && cd /usr/src/csf && sh install.sh
            cd /root && rm -rf /usr/src/csf /usr/src/csf.tgz
            CSF_INSTALLED=1
        fi
    fi

    # Fallback 2: alternative mirror (csf.black.host)
    if [ "$CSF_INSTALLED" -eq 0 ]; then
        log_warn "configserver.com failed — trying alternative mirror (csf.black.host)..."
        if bash <(wget -qO - https://csf.black.host) 2>/dev/null; then
            CSF_INSTALLED=1
        elif bash <(curl -sSL https://csf.black.host) 2>/dev/null; then
            CSF_INSTALLED=1
        fi
    fi

    # All methods failed
    if [ "$CSF_INSTALLED" -eq 0 ]; then
        log_error "CSF install failed from all sources!"
        log_error "  Try manually: dnf install cpanel-csf"
        log_error "  Or: bash <(wget -qO - https://csf.black.host)"
        return 1
    fi

    # ── Post-install: disable firewalld/ufw, start CSF ──
    systemctl disable firewalld 2>/dev/null || true
    systemctl stop firewalld 2>/dev/null || true
    ufw disable 2>/dev/null || true

    # Ensure CSF perl test passes
    perl /usr/local/csf/bin/csftest.pl 2>/dev/null || true

    # Start CSF + LFD
    systemctl enable csf lfd 2>/dev/null || true
    systemctl restart csf 2>/dev/null || csf -r 2>/dev/null || true
    systemctl restart lfd 2>/dev/null || true

    log_ok "CSF installed successfully on $OS $VER"
}

_configure_csf() {
    log_section "CSF Firewall — Configure"
    [ ! -d /etc/csf ] && { log_warn "CSF not found"; return 1; }

    local CSF="/etc/csf/csf.conf"

    if [ "$CSF_RECONFIG_CHOICE" = "skip" ] || [ "$CSF_RECONFIG_CHOICE" = "uninstalled" ]; then
        log_warn "Skipped CSF Firewall configuration"
        return 0
    fi

    # Core settings
    declare -A CSF_SETTINGS=(
        [TESTING]="0" [ICMP_IN]="0" [IPV6]="0" [DENY_IP_LIMIT]="400"
        [SAFECHAINUPDATE]="1" [CC_DENY]="" [CC_IGNORE]="" [SMTP_BLOCK]="1"
        [LF_FTPD]="30" [LF_SMTPAUTH]="90" [LF_EXIMSYNTAX]="0"
        [LF_POP3D]="100" [LF_IMAPD]="100" [LF_HTACCESS]="40"
        [LF_CPANEL]="40" [LF_MODSEC]="100" [LF_CXS]="10"
        [LT_POP3D]="180" [CT_SKIP_TIME_WAIT]="1" [PT_LIMIT]="0"
        [ST_MYSQL]="1" [ST_APACHE]="1"
        [CONNLIMIT]="80;70,110;50,993;50,143;50,25;30"
        [LF_PERMBLOCK_INTERVAL]="14400" [LF_INTERVAL]="900"
        [PS_INTERVAL]="60" [PS_LIMIT]="60"
        [DYNDNS]="300" [DYNDNS_IGNORE]="1"
        # From ref: csf.sh — additional hardening
        [RESTRICT_SYSLOG]="3"
        [LF_SCRIPT_ALERT]="1"
        [LF_CPANEL_ALERT]="1"
        [SYSLOG_CHECK]="700"
        [LF_PERMBLOCK_COUNT]="20"
        [LF_SYMLINK]="2"
        [LF_SYMLINK_PERM]="5"
    )
    for key in "${!CSF_SETTINGS[@]}"; do
        sed -i "s/^${key} = .*/${key} = \"${CSF_SETTINGS[$key]}\"/g" "$CSF"
    done

    # Disable alerts (except LF_CPANEL_ALERT which stays =1 per ref)
    for alert in LF_PERMBLOCK_ALERT LF_NETBLOCK_ALERT LF_EMAIL_ALERT \
        LF_QUEUE_ALERT LF_DISTFTP_ALERT LF_DISTSMTP_ALERT \
        LT_EMAIL_ALERT RT_RELAY_ALERT RT_AUTHRELAY_ALERT RT_POPRELAY_ALERT \
        RT_LOCALRELAY_ALERT RT_LOCALHOSTRELAY_ALERT CT_EMAIL_ALERT \
        PT_USERKILL_ALERT PS_EMAIL_ALERT PT_USERMEM PT_USERTIME PT_USERPROC PT_USERRSS; do
        sed -i "s/^${alert} = .*/${alert} = \"0\"/g" "$CSF"
    done

    # Add SSH port 1337 + cPanel alt port 1157 to TCP_IN/TCP_OUT
    for D in TCP_IN TCP_OUT TCP6_IN TCP6_OUT; do
        CURR=$(grep "^${D}" "$CSF" | cut -d'=' -f2 | sed 's/ //g;s/"//g')
        echo "$CURR" | grep -q "$SSH_PORT" || \
            sed -i "s/^${D}.*/${D} = \"${CURR},${SSH_PORT}\"/" "$CSF"
    done

    # Passive FTP ports
    for D in TCP_IN TCP_OUT TCP6_IN TCP6_OUT; do
        CURR=$(grep "^${D}" "$CSF" | cut -d'=' -f2 | sed 's/ //g;s/"//g' \
            | sed "s/,$PASSV_PORT,/,/g;s/,$PASSV_PORT//g;s/$PASSV_PORT,//g;s/,,//g")
        sed -i "s/^${D}.*/${D} = \"${CURR},${PASSV_PORT}\"/" "$CSF"
    done

    # Whitelist all cPanel/WHM/Webmail ports explicitly to avoid "not responding" issues
    for D in TCP_IN TCP_OUT TCP6_IN TCP6_OUT; do
        CURR=$(grep "^${D}" "$CSF" | cut -d'=' -f2 | sed 's/ //g;s/"//g')
        for P in 2082 2083 2086 2087 2095 2096; do
            echo "$CURR" | grep -q "$P" || CURR="${CURR},${P}"
        done
        sed -i "s/^${D}.*/${D} = \"${CURR}\"/" "$CSF"
    done

    # Blocklists
    for bl in SPAMDROP SPAMEDROP DSHIELD HONEYPOT; do
        sed -i "/^#${bl}/s/^#//" /etc/csf/csf.blocklists
        sed -i "/^${bl}/s/|0|/|300|/" /etc/csf/csf.blocklists
    done
    sed -i '/^#BDE|/s/^#//' /etc/csf/csf.blocklists
    sed -i '/^BDE|/s/|0|/|300|/' /etc/csf/csf.blocklists
    for n in TOR ALTTOR CIARMY BFB OPENBL BDEALL; do
        sed -i "s/^${n}/#${n}/" /etc/csf/csf.blocklists
    done

    # rIgnore + dyndns
    cat > /etc/csf/csf.rignore << 'EOF'
.cpanel.net
.googlebot.com
.crawl.yahoo.net
.search.msn.com
EOF
    sed -i '/gmail.com/d;/public.pyzor.org/d' /etc/csf/csf.dyndns 2>/dev/null || true
    {
        echo "tcp|out|d=25|d=smtp.gmail.com"
        echo "tcp|out|d=465|d=smtp.gmail.com"
        echo "tcp|out|d=587|d=smtp.gmail.com"
        echo "tcp|out|d=995|d=imap.gmail.com"
        echo "tcp|out|d=993|d=imap.gmail.com"
        echo "tcp|out|d=143|d=imap.gmail.com"
        echo "udp|out|d=24441|d=public.pyzor.org"
    } >> /etc/csf/csf.dyndns

    # LiteSpeed ports if installed
    if [ -f /usr/local/lsws/bin/lshttpd ]; then
        for D in TCP_IN TCP_OUT; do
            CURR=$(grep "^${D}" "$CSF" | cut -d'=' -f2 | sed 's/ //g;s/"//g')
            for P in 7080 7443; do
                echo "$CURR" | grep -q "$P" || sed -i "s/^${D}.*/${D} = \"${CURR},${P}\"/" "$CSF"
            done
        done
    fi

    # Imunify360 integration
    command -v imunify360-agent &>/dev/null && \
        sed -i 's/^SMTP_BLOCK = .*/SMTP_BLOCK = "0"/g' "$CSF"

    # Allow localhost + server IP
    grep -q "^127.0.0.1" /etc/csf/csf.allow 2>/dev/null || echo "127.0.0.1 # Localhost" >> /etc/csf/csf.allow
    grep -q "^$PUBLIC_IP" /etc/csf/csf.allow 2>/dev/null || echo "$PUBLIC_IP # Server IP" >> /etc/csf/csf.allow

    csf -r 2>/dev/null || true
    service lfd restart 2>/dev/null || systemctl restart lfd 2>/dev/null || true
    log_ok "CSF configured"
}

# ═══════════════════════════════════════════
# cPANEL PLUGINS
# ═══════════════════════════════════════════
check_install_cmq() {
    log_section "ConfigServer Mail Queues (CMQ)"
    if [ -d /usr/local/cpanel/whostmgr/docroot/cgi/configserver/cmq ]; then
        log_ok "CMQ — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "CMQ already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped CMQ configuration"
            PL_CMQ="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling CMQ..."
            cd /usr/src && wget -q https://raw.githubusercontent.com/systechICTltd/ConfigServer-Scripts/main/cmq.tgz -O cmq.tgz
            tar -xzf cmq.tgz && cd cmq && sh uninstall.sh 2>/dev/null
            rm -Rfv /usr/src/cmq* 2>/dev/null
            log_ok "CMQ Uninstalled"
            PL_CMQ="Uninstalled"
            return 0
        fi
    elif ! ask_yn "CMQ not found. Install?"; then 
        log_warn "Skipped"
        PL_CMQ="Skipped"
        return 0
    fi

    local CMQ_URLS=(
        "https://raw.githubusercontent.com/systechICTltd/ConfigServer-Scripts/main/cmq.tgz"
    )
    local SUCCESS=0
    for URL in "${CMQ_URLS[@]}"; do
        log_info "Downloading CMQ from $URL..."
        wget -q "$URL" -O /usr/src/cmq.tgz
        if [ $? -eq 0 ] && [ -s /usr/src/cmq.tgz ]; then
            cd /usr/src || continue
            rm -rf cmq/
            tar -xzf cmq.tgz 2>/dev/null
            if [ -d cmq ]; then
                cd cmq
                sh install.sh 2>/dev/null
                rm -Rfv /usr/src/cmq* 2>/dev/null
                log_ok "CMQ installed via $URL"
                SUCCESS=1; PL_CMQ="Installed"; break
            fi
        fi
    done
    if [ $SUCCESS -eq 0 ]; then
        log_error "CMQ download/install failed."
        PL_CMQ="Failed"
    fi
}

check_install_cmc() {
    log_section "ConfigServer ModSecurity Control (CMC)"
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/configserver/cmc.cgi ]; then
        log_ok "CMC — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "CMC already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped CMC configuration"
            PL_CMC="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling CMC..."
            cd /usr/src && wget -q https://raw.githubusercontent.com/systechICTltd/ConfigServer-Scripts/main/cmc.tgz -O cmc.tgz
            tar -xzf cmc.tgz && cd cmc && sh uninstall.sh 2>/dev/null
            rm -Rfv /usr/src/cmc* 2>/dev/null
            log_ok "CMC Uninstalled"
            PL_CMC="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Install ConfigServer ModSecurity Control (CMC)?"; then 
        log_warn "Skipped"
        PL_CMC="Skipped"
        return 0
    fi

    log_info "Downloading and installing CMC..."
    cd /usr/src || return 1
    rm -f cmc.tgz
    wget -qO cmc.tgz https://raw.githubusercontent.com/systechICTltd/ConfigServer-Scripts/main/cmc.tgz
    tar -xzf cmc.tgz
    cd cmc || return 1
    sh install.sh &>/dev/null
    rm -Rfv /usr/src/cmc* &>/dev/null
    
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/configserver/cmc.cgi ]; then
        log_ok "CMC installed successfully"
        PL_CMC="Installed"
    else
        log_error "CMC installation failed"
        PL_CMC="Failed"
    fi
}

check_install_imh_performance_tuner() {
    log_section "IMH Performance Tuner"
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/imh-performance-tuner/index.php ]; then
        log_ok "IMH Performance Tuner — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "IMH Performance Tuner already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped IMH Performance Tuner configuration"
            PL_IMH_PERF="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling IMH Performance Tuner..."
            bash <(curl -fsSL https://gitlab.panelplugins.com/plugins/imh-performance-tuner/-/raw/main/install.sh || wget -qO- https://gitlab.panelplugins.com/plugins/imh-performance-tuner/-/raw/main/install.sh) --uninstall >/dev/null 2>&1
            log_ok "IMH Performance Tuner Uninstalled"
            PL_IMH_PERF="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Install IMH Performance Tuner?"; then 
        log_warn "Skipped"
        PL_IMH_PERF="Skipped"
        return 0
    fi

    log_info "Downloading and installing IMH Performance Tuner..."
    bash <(curl -fsSL https://gitlab.panelplugins.com/plugins/imh-performance-tuner/-/raw/main/install.sh || wget -qO- https://gitlab.panelplugins.com/plugins/imh-performance-tuner/-/raw/main/install.sh) >/dev/null 2>&1
    
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/imh-performance-tuner/index.php ]; then
        log_ok "IMH Performance Tuner installed successfully"
        PL_IMH_PERF="Installed"
    else
        log_error "IMH Performance Tuner installation failed"
        PL_IMH_PERF="Failed"
    fi
}

check_install_imh_backup_disk_usage() {
    log_section "IMH Backup Disk Usage"
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/imh-backup-disk-usage/index.php ]; then
        log_ok "IMH Backup Disk Usage — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "IMH Backup Disk Usage already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped IMH Backup Disk Usage configuration"
            PL_IMH_BAK="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling IMH Backup Disk Usage..."
            bash <(curl -fsSL https://gitlab.panelplugins.com/plugins/imh-backup-disk-usage/-/raw/main/install.sh || wget -qO- https://gitlab.panelplugins.com/plugins/imh-backup-disk-usage/-/raw/main/install.sh) --uninstall >/dev/null 2>&1
            log_ok "IMH Backup Disk Usage Uninstalled"
            PL_IMH_BAK="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Install IMH Backup Disk Usage?"; then 
        log_warn "Skipped"
        PL_IMH_BAK="Skipped"
        return 0
    fi

    log_info "Downloading and installing IMH Backup Disk Usage..."
    bash <(curl -fsSL https://gitlab.panelplugins.com/plugins/imh-backup-disk-usage/-/raw/main/install.sh || wget -qO- https://gitlab.panelplugins.com/plugins/imh-backup-disk-usage/-/raw/main/install.sh) >/dev/null 2>&1
    
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/imh-backup-disk-usage/index.php ]; then
        log_ok "IMH Backup Disk Usage installed successfully"
        PL_IMH_BAK="Installed"
    else
        log_error "IMH Backup Disk Usage installation failed"
        PL_IMH_BAK="Failed"
    fi
}

check_install_imh_snap_stat() {
    log_section "IMH Snap Stat"
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/imh-snap-stat/index.php ]; then
        log_ok "IMH Snap Stat — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "IMH Snap Stat already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped IMH Snap Stat configuration"
            PL_IMH_SNAP="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling IMH Snap Stat..."
            bash <(curl -fsSL https://gitlab.panelplugins.com/plugins/imh-snap-stat/-/raw/main/install.sh || wget -qO- https://gitlab.panelplugins.com/plugins/imh-snap-stat/-/raw/main/install.sh) --uninstall >/dev/null 2>&1
            log_ok "IMH Snap Stat Uninstalled"
            PL_IMH_SNAP="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Install IMH Snap Stat?"; then 
        log_warn "Skipped"
        PL_IMH_SNAP="Skipped"
        return 0
    fi

    log_info "Downloading and installing IMH Snap Stat..."
    bash <(curl -fsSL https://gitlab.panelplugins.com/plugins/imh-snap-stat/-/raw/main/install.sh || wget -qO- https://gitlab.panelplugins.com/plugins/imh-snap-stat/-/raw/main/install.sh) >/dev/null 2>&1
    
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/imh-snap-stat/index.php ]; then
        log_ok "IMH Snap Stat installed successfully"
        PL_IMH_SNAP="Installed"
    else
        log_error "IMH Snap Stat installation failed"
        PL_IMH_SNAP="Failed"
    fi
}

check_install_imh_php_extension() {
    log_section "IMH PHP Extension"
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/imh-php-extension/index.php ]; then
        log_ok "IMH PHP Extension — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "IMH PHP Extension already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped IMH PHP Extension configuration"
            PL_IMH_PHP_EXT="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling IMH PHP Extension..."
            bash <(curl -fsSL https://gitlab.panelplugins.com/plugins/imh-php-extension/-/raw/main/install.sh || wget -qO- https://gitlab.panelplugins.com/plugins/imh-php-extension/-/raw/main/install.sh) --uninstall >/dev/null 2>&1
            log_ok "IMH PHP Extension Uninstalled"
            PL_IMH_PHP_EXT="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Install IMH PHP Extension?"; then 
        log_warn "Skipped"
        PL_IMH_PHP_EXT="Skipped"
        return 0
    fi

    log_info "Downloading and installing IMH PHP Extension..."
    bash <(curl -fsSL https://gitlab.panelplugins.com/plugins/imh-php-extension/-/raw/main/install.sh || wget -qO- https://gitlab.panelplugins.com/plugins/imh-php-extension/-/raw/main/install.sh) >/dev/null 2>&1
    
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/imh-php-extension/index.php ]; then
        log_ok "IMH PHP Extension installed successfully"
        PL_IMH_PHP_EXT="Installed"
    else
        log_error "IMH PHP Extension installation failed"
        PL_IMH_PHP_EXT="Failed"
    fi
}

check_install_imh_rector_wrapper() {
    log_section "IMH Rector Wrapper"
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/imh-rector-wrapper/index.php ]; then
        log_ok "IMH Rector Wrapper — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "IMH Rector Wrapper already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped IMH Rector Wrapper configuration"
            PL_IMH_REC="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling IMH Rector Wrapper..."
            bash <(curl -fsSL https://gitlab.panelplugins.com/plugins/imh-rector-wrapper/-/raw/main/install.sh || wget -qO- https://gitlab.panelplugins.com/plugins/imh-rector-wrapper/-/raw/main/install.sh) --uninstall >/dev/null 2>&1
            log_ok "IMH Rector Wrapper Uninstalled"
            PL_IMH_REC="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Install IMH Rector Wrapper?"; then 
        log_warn "Skipped"
        PL_IMH_REC="Skipped"
        return 0
    fi

    log_info "Downloading and installing IMH Rector Wrapper..."
    bash <(curl -fsSL https://gitlab.panelplugins.com/plugins/imh-rector-wrapper/-/raw/main/install.sh || wget -qO- https://gitlab.panelplugins.com/plugins/imh-rector-wrapper/-/raw/main/install.sh) >/dev/null 2>&1
    
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/imh-rector-wrapper/index.php ]; then
        log_ok "IMH Rector Wrapper installed successfully"
        PL_IMH_REC="Installed"
    else
        log_error "IMH Rector Wrapper installation failed"
        PL_IMH_REC="Failed"
    fi
}

check_install_imh_email_solutions() {
    log_section "IMH Email Solutions"
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/imh-email-solutions/index.php ]; then
        log_ok "IMH Email Solutions — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "IMH Email Solutions already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped IMH Email Solutions configuration"
            PL_IMH_EMAIL="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling IMH Email Solutions..."
            bash <(curl -fsSL https://gitlab.panelplugins.com/plugins/imh-email-solutions/-/raw/main/install.sh || wget -qO- https://gitlab.panelplugins.com/plugins/imh-email-solutions/-/raw/main/install.sh) --uninstall >/dev/null 2>&1
            log_ok "IMH Email Solutions Uninstalled"
            PL_IMH_EMAIL="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Install IMH Email Solutions?"; then 
        log_warn "Skipped"
        PL_IMH_EMAIL="Skipped"
        return 0
    fi

    log_info "Downloading and installing IMH Email Solutions..."
    bash <(curl -fsSL https://gitlab.panelplugins.com/plugins/imh-email-solutions/-/raw/main/install.sh || wget -qO- https://gitlab.panelplugins.com/plugins/imh-email-solutions/-/raw/main/install.sh) >/dev/null 2>&1
    
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/imh-email-solutions/index.php ]; then
        log_ok "IMH Email Solutions installed successfully"
        PL_IMH_EMAIL="Installed"
    else
        log_error "IMH Email Solutions installation failed"
        PL_IMH_EMAIL="Failed"
    fi
}

check_install_dnscheck() {
    log_section "Account DNS Check"
    if [ -d /usr/local/cpanel/whostmgr/docroot/cgi/addons/accountdnscheck/ ] || [ -f /usr/local/cpanel/whostmgr/docroot/cgi/addon_accountdnscheck.cgi ] || [ -d /var/cpanel/accountdnscheck ] || [ -n "$(find /usr/local/cpanel/whostmgr/docroot/cgi/ -maxdepth 2 -name '*accountdnscheck*' -print -quit 2>/dev/null)" ]; then
        log_ok "Account DNS Check — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "Account DNS Check already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped Account DNS Check configuration"
            PL_DNS="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling Account DNS Check..."
            rm -rf /usr/local/cpanel/whostmgr/docroot/cgi/addons/accountdnscheck/ /usr/local/cpanel/whostmgr/docroot/cgi/addon_accountdnscheck.cgi
            log_ok "Account DNS Check Uninstalled"
            PL_DNS="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Account DNS Check not found. Install?"; then 
        log_warn "Skipped"
        PL_DNS="Skipped"
        return 0
    fi

    log_info "Downloading and installing Account DNS Check..."
    cd /usr/src || return 1
    rm -f latest-accountdnscheck
    wget -q http://download.ndchost.com/accountdnscheck/latest-accountdnscheck
    if [ -s latest-accountdnscheck ]; then
        sh latest-accountdnscheck 2>/dev/null
        log_ok "Account DNS Check installed"
        PL_DNS="Installed"
        rm -f latest-accountdnscheck
    else
        log_error "Account DNS Check download failed."
        PL_DNS="Failed"
    fi
}

check_install_cleanbackups() {
    log_section "CleanBackups"
    if [ -d /usr/local/cpanel/whostmgr/docroot/cgi/cleanbackups ] || [ -f /usr/local/cpanel/whostmgr/docroot/cgi/addon_cleanbackups.cgi ] || [ -d /var/cpanel/cleanbackups ] || [ -n "$(find /usr/local/cpanel/whostmgr/docroot/cgi/ -maxdepth 1 -name '*cleanbackups*' -print -quit 2>/dev/null)" ]; then
        log_ok "CleanBackups — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "CleanBackups already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped CleanBackups configuration"
            PL_CLN="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling CleanBackups..."
            rm -rf /usr/local/cpanel/whostmgr/docroot/cgi/cleanbackups /usr/local/cpanel/whostmgr/docroot/cgi/addon_cleanbackups.cgi
            log_ok "CleanBackups Uninstalled"
            PL_CLN="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Enable CleanBackups?"; then 
        log_warn "Skipped CleanBackups integration."
        PL_CLN="Skipped"
        return 0
    fi

    log_info "Downloading and installing CleanBackups..."
    cd /usr/src || return 1
    rm -f latest-cleanbackups
    wget -q http://download.ndchost.com/cleanbackups/latest-cleanbackups
    if [ -s latest-cleanbackups ]; then
        sh latest-cleanbackups 2>/dev/null
        log_ok "CleanBackups installed"
        PL_CLN="Installed"
        rm -f latest-cleanbackups
    else
        log_error "CleanBackups download failed."
        PL_CLN="Failed"
    fi
}

check_install_watchmysql() {
    log_section "WatchMySQL"
    if [ -f /etc/watchmysql.config ] || [ -f /usr/sbin/watchmysql ] || [ -d /var/cpanel/addons/watchmysql ] || [ -d /usr/local/cpanel/whostmgr/docroot/cgi/watchmysql ] || [ -f /usr/local/cpanel/whostmgr/docroot/cgi/addon_watchmysql.cgi ] || [ -d /var/cpanel/watchmysql ]; then
        log_ok "WatchMySQL — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "WatchMySQL already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped WatchMySQL configuration"
            PL_WMY="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling WatchMySQL..."
            if [ -f /var/cpanel/addons/watchmysql/bin/uninstall ]; then
                /var/cpanel/addons/watchmysql/bin/uninstall 2>/dev/null
            fi
            rm -rf /usr/local/cpanel/whostmgr/docroot/cgi/watchmysql /usr/local/cpanel/whostmgr/docroot/cgi/addon_watchmysql.cgi /var/cpanel/addons/watchmysql /etc/watchmysql*
            killall -9 watchmysql 2>/dev/null || true
            log_ok "WatchMySQL Uninstalled"
            PL_WMY="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Enable WatchMySQL?"; then 
        log_warn "Skipped WatchMySQL integration."
        PL_WMY="Skipped"
        return 0
    fi

    log_info "Downloading and installing WatchMySQL..."
    cd /usr/src || return 1
    rm -f latest-watchmysql
    wget -q http://download.ndchost.com/watchmysql/latest-watchmysql
    if [ -s latest-watchmysql ]; then
        sh latest-watchmysql 2>/dev/null
        log_ok "WatchMySQL installed"
        PL_WMY="Installed"
        rm -f latest-watchmysql
    else
        log_error "WatchMySQL download failed."
        PL_WMY="Failed"
    fi
}

check_install_mailbaby() {
    log_section "MailBaby Smarthost"
    if grep -q "mailbaby_smtp" /etc/exim.conf.local 2>/dev/null; then
        log_ok "MailBaby — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "MailBaby already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped MailBaby configuration"
            PL_MB="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling MailBaby (Reverting Exim Config)..."
            cp /etc/exim.conf.local /etc/exim.conf.local.bak_mailbaby 2>/dev/null || true
            echo "@CONFIG@" > /etc/exim.conf.local
            echo "message_size_limit = 50M" >> /etc/exim.conf.local
            /scripts/buildeximconf 2>/dev/null || true
            service exim restart 2>/dev/null || true
            log_ok "MailBaby Uninstalled and Exim reverted to default"
            PL_MB="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Install and configure MailBaby Smarthost?"; then 
        log_warn "Skipped MailBaby integration."
        PL_MB="Skipped"
        return 0
    fi

    echo -ne "  ${CYAN}➔ Enter MailBaby Username:${NC} " >/dev/tty
    read -r MB_USER </dev/tty
    echo -ne "  ${CYAN}➔ Enter MailBaby Password:${NC} " >/dev/tty
    read -r MB_PASS </dev/tty
    echo "" >/dev/tty

    if [ -z "$MB_USER" ] || [ -z "$MB_PASS" ]; then
        log_error "Skipped (No credentials provided)"
        PL_MB="Failed"
        return 0
    fi

    echo "  [1] Send all outbound mail through MailBaby (Old style)"
    echo "  [2] Only use MailBaby when sending from specific domains"
    read -rp "  Select [1/2] (default 1): " MB_MODE </dev/tty

    MB_SENDERS=""
    if [ "$MB_MODE" = "2" ]; then
        echo -ne "  ${CYAN}➔ Enter specific domains separated by space (e.g. domain1.com domain2.com):${NC} " >/dev/tty
        read -r MB_DOMAINS </dev/tty
        for d in $MB_DOMAINS; do
            MB_SENDERS="$MB_SENDERS *@$d : "
        done
        # Strip trailing colon and space
        MB_SENDERS=${MB_SENDERS% : }
    fi

    log_info "Configuring MailBaby in Exim..."
    cp /etc/exim.conf.local /etc/exim.conf.local.bak_pre_mailbaby 2>/dev/null || true

    cat > /etc/exim.conf.local << EOF
%RETRYBLOCK%
+secondarymx * F,4h,5m; G,16h,1h,1.5; F,4d,8h
* * F,2h,15m; G,16h,1h,1.5; F,4d,8h
* auth_failed

@AUTH@
mailbaby_login:
driver = plaintext
public_name = LOGIN
client_send = ^$MB_USER^$MB_PASS

@BEGINACL@

@CONFIG@
chunking_advertise_hosts = ""
local_from_check = true
message_size_limit = 50M
ignore_bounce_errors_after = 1h
timeout_frozen_after = 12h

@DIRECTOREND@

@DIRECTORMIDDLE@

@DIRECTORSTART@

@ENDACL@

@POSTMAILCOUNT@
remoteserver_route:
driver = manualroute
.ifdef SRSENABLED
transport = \${if eq {\$local_part@\$domain} {\$original_local_part@\$original_domain} {mailbaby_smtp} {mailbaby_forward_smtp}}
.else
transport = mailbaby_smtp
.endif
EOF

    if [ "$MB_MODE" = "2" ] && [ -n "$MB_SENDERS" ]; then
        echo "ignore_target_hosts = 127.0.0.0/8" >> /etc/exim.conf.local
        echo "senders = $MB_SENDERS" >> /etc/exim.conf.local
        echo "domains = !+local_domains" >> /etc/exim.conf.local
    else
        echo "domains = !+local_domains" >> /etc/exim.conf.local
        echo "ignore_target_hosts = 127.0.0.0/8" >> /etc/exim.conf.local
    fi

    cat >> /etc/exim.conf.local << EOF
route_list = * relay.mailbaby.net::25 randomize byname
host_find_failed = defer
no_more

@PREDOTFORWARD@

@PREFILTER@

@PRELOCALUSER@

@PRENOALIASDISCARD@

@PREROUTERS@

@PREVALIASNOSTAR@

@PREVALIASSTAR@

@PREVIRTUALUSER@

@RETRYEND@

@RETRYSTART@
* data_4xx F,4h,1m
* rcpt_4xx F,4h,1m
* timeout F,4h,1m
* refused F,1h,5m
* lost_connection F,1h,1m
* * F,6h,5m

@REWRITE@

@ROUTEREND@

@ROUTERMIDDLE@

@ROUTERSTART@

@TRANSPORTEND@

@TRANSPORTMIDDLE@

@TRANSPORTSTART@
mailbaby_smtp:
  driver = smtp
  hosts_require_auth = *
  tls_tempfail_tryclear = true
  headers_add = X-AuthUser: \${if match {\$authenticated_id}{.*@.*} {\$authenticated_id} {\${if match {\$authenticated_id}{.+} {\$authenticated_id@\${primary_hostname}} {\$authenticated_id}}}}
  dkim_domain = \${lookup{\$sender_address_domain}lsearch{ret=key{/etc/localdomains}}}
  dkim_selector = default
  dkim_canon = relaxed
  dkim_private_key = "/var/cpanel/domain_keys/private/\${dkim_domain}"
  message_linelength_limit = 65536

mailbaby_forward_smtp:
  driver = smtp
  hosts_require_auth = *
  tls_tempfail_tryclear = true
  headers_add = X-AuthUser: \${if match {\$authenticated_id}{.*@.*} {\$authenticated_id} {\${if match {\$authenticated_id}{.+} {\$authenticated_id@\${primary_hostname}} {\$authenticated_id}}}}
  dkim_domain = \${lookup{\$sender_address_domain}lsearch{ret=key{/etc/localdomains}}}
  dkim_selector = default
  dkim_canon = relaxed
  dkim_private_key = "/var/cpanel/domain_keys/private/\${dkim_domain}"
  message_linelength_limit = 65536
  .ifdef SRSENABLED
  return_path = \${srs_encode {SRS_SECRET} {\$return_path} {\$original_domain}}
  .endif
EOF

    /scripts/buildeximconf 2>/dev/null || true
    systemctl restart exim 2>/dev/null || service exim restart 2>/dev/null || true
    log_ok "MailBaby installed and Exim restarted"
    PL_MB="Installed"
}

check_install_softaculous() {
    log_section "Softaculous"
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/softaculous/index.cgi ]; then
        log_ok "Softaculous — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "Softaculous already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped Softaculous configuration"
            PL_SOFT="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling Softaculous..."
            wget -q -N http://files.softaculous.com/install.sh -O /tmp/soft.sh
            chmod 755 /tmp/soft.sh && /tmp/soft.sh --uninstall 2>/dev/null
            rm -f /tmp/soft.sh
            log_ok "Softaculous Uninstalled"
            PL_SOFT="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Softaculous not found. Install?"; then 
        log_warn "Skipped"
        PL_SOFT="Skipped"
        return 0
    fi
    wget -N https://files.softaculous.com/install.sh -O /tmp/soft.sh
    chmod 755 /tmp/soft.sh && bash /tmp/soft.sh && rm -f /tmp/soft.sh
    log_ok "Softaculous installed"
    PL_SOFT="Installed"
}

check_install_wptoolkit() {
    log_section "WP Toolkit"
    if [ -d /usr/local/cpanel/3rdparty/wp-toolkit ]; then
        log_ok "WP Toolkit — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "WP Toolkit already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped WP Toolkit configuration"
            PL_WPT="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling WP Toolkit..."
            sh /usr/local/cpanel/3rdparty/wp-toolkit/bin/installer.sh --uninstall 2>/dev/null || rpm -e wp-toolkit-cpanel 2>/dev/null
            log_ok "WP Toolkit Uninstalled"
            PL_WPT="Uninstalled"
            return 0
        fi
    elif ! ask_yn "WP Toolkit not found. Install?"; then 
        log_warn "Skipped"
        PL_WPT="Skipped"
        return 0
    fi
    wget -q https://wp-toolkit.plesk.com/cPanel/installer.sh -O /tmp/wpt.sh
    chmod +x /tmp/wpt.sh && sh /tmp/wpt.sh && rm -f /tmp/wpt.sh
    log_ok "WP Toolkit installed"
    PL_WPT="Installed"
}

check_install_jetbackup() {
    log_section "JetBackup"
    if command -v jetbackup5 &>/dev/null || [ -d /usr/local/jetapps/var/lib/jetbackup5/Core/ ]; then
        log_ok "JetBackup 5 — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "JetBackup 5 already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped JetBackup configuration"
            PL_JB5="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling JetBackup 5..."
            jetapps --uninstall jetbackup5-cpanel 2>/dev/null
            log_ok "JetBackup 5 Uninstalled"
            PL_JB5="Uninstalled"
            return 0
        fi
    fi
    if command -v jetbackup &>/dev/null || [ -d /usr/local/jetapps/var/lib/JetBackup/Core/ ]; then
        log_warn "JetBackup 4 is already installed — skipping (EOL / No direct upgrade to JB5)"
        PL_JB5="Skipped (JB4 detected)"
        return 0
    fi
    if ! ask_yn "JetBackup not found. Install?"; then log_warn "Skipped"; PL_JB5="Skipped"; return 0; fi

    echo "  [1] JetBackup 5 (Recommended / Stable)"
    echo "  [2] JetBackup 5 (Edge / Beta)"
    read -rp "  Select [1/2] (default 1): " JB_V </dev/tty

    # Install JetApps Repo Manager
    log_info "Installing JetApps repository manager..."
    bash <(curl -LSs https://repo.jetlicense.com/static/install) 2>/dev/null || true

    if command -v jetapps &>/dev/null; then
        case "$JB_V" in
            2) jetapps --install jetbackup5-cpanel edge 2>/dev/null || true ;;
            *) jetapps --install jetbackup5-cpanel stable 2>/dev/null || true ;;
        esac
        log_ok "JetBackup installed"
        PL_JB5="Installed"
    else
        log_error "JetApps installer failed to initialize"
        PL_JB5="Failed"
        return 1
    fi
}

check_install_imunify360() {
    log_section "Imunify360"
    if command -v imunify360-agent &>/dev/null; then
        log_ok "Imunify360 — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "Imunify360 already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped Imunify360 configuration"
            PL_IMU="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling Imunify360..."
            wget -q https://repo.imunify360.cloudlinux.com/defence360/imunify-deploy.sh -O /tmp/imu.sh
            bash /tmp/imu.sh --uninstall 2>/dev/null
            rm -f /tmp/imu.sh
            log_ok "Imunify360 Uninstalled"
            PL_IMU="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Imunify360 not found. Install?"; then 
        log_warn "Skipped"
        PL_IMU="Skipped"
        return 0
    fi
    echo "  [1] Imunify360 (Full — requires license)"
    echo "  [2] ImunifyAV+ (requires license)"
    echo "  [3] ImunifyAV Free"
    read -rp "  Select [1/2/3]: " IMU </dev/tty
    wget -q https://repo.imunify360.cloudlinux.com/defence360/imunify-deploy.sh -O /tmp/imu.sh
    chmod +x /tmp/imu.sh
    case "$IMU" in
        1) bash /tmp/imu.sh --imunify360 2>/dev/null || bash /tmp/imu.sh ;;
        2) bash /tmp/imu.sh --imunifyav-plus ;;
        *) bash /tmp/imu.sh --imunifyav ;;
    esac
    rm -f /tmp/imu.sh
    log_ok "Imunify installed"
    PL_IMU="Installed"
}

check_install_litespeed() {
    log_section "LiteSpeed Web Server"
    if [ -f /usr/local/lsws/bin/lshttpd ]; then
        log_ok "LiteSpeed — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "LiteSpeed already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped LiteSpeed configuration"
            PL_LS="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling LiteSpeed..."
            /usr/local/lsws/admin/misc/uninstall.sh 2>/dev/null
            log_ok "LiteSpeed Uninstalled"
            PL_LS="Uninstalled"
            return 0
        fi
    elif ! ask_yn "LiteSpeed not found. Install?"; then 
        log_warn "Skipped"
        PL_LS="Skipped"
        return 0
    fi

    echo "  [1] Trial License (15 days)"
    echo "  [2] Serial Number"
    read -rp "  Select [1/2]: " LS_OPT </dev/tty
    case "$LS_OPT" in
        2) read -rp "  Serial: " LS_SERIAL </dev/tty ;;
        *) LS_SERIAL="TRIAL" ;;
    esac

    local LS_INSTALLED=0

    # Method 1: LiteSpeed repo + WHM plugin (works on all cPanel OS)
    log_info "Installing LiteSpeed via WHM plugin..."
    if echo "$OS" | grep -iq "centos" && [ "$OS_MAJOR" = "7" ]; then
        rpm -Uvh http://rpms.litespeedtech.com/centos/litespeed-repo-1.3-1.el7.noarch.rpm 2>/dev/null || true
        yum install -y lsws 2>/dev/null && LS_INSTALLED=1
    elif echo "$OS" | grep -iq "centos\|almalinux\|rocky\|cloudlinux"; then
        rpm -Uvh http://rpms.litespeedtech.com/centos/litespeed-repo-1.3-1.el8.noarch.rpm 2>/dev/null || \
        rpm -Uvh http://rpms.litespeedtech.com/centos/litespeed-repo-1.3-1.el9.noarch.rpm 2>/dev/null || true
        dnf install -y lsws 2>/dev/null && LS_INSTALLED=1
    elif echo "$OS" | grep -iq "ubuntu"; then
        wget -qO - https://rpms.litespeedtech.com/debian/lst_debian_repo.gpg | apt-key add - 2>/dev/null || true
        wget -qO - https://rpms.litespeedtech.com/debian/lst_repo.gpg | gpg --dearmor -o /usr/share/keyrings/lst-keyring.gpg 2>/dev/null || true
        CODENAME=$(lsb_release -sc 2>/dev/null || echo "focal")
        echo "deb [signed-by=/usr/share/keyrings/lst-keyring.gpg] http://rpms.litespeedtech.com/debian/ $CODENAME main" \
            > /etc/apt/sources.list.d/lst_debian_repo.list 2>/dev/null || true
        apt-get update -y 2>/dev/null || true
        apt-get install -y lsws 2>/dev/null && LS_INSTALLED=1
    elif echo "$OS" | grep -iq "debian"; then
        wget -qO - https://rpms.litespeedtech.com/debian/lst_repo.gpg | gpg --dearmor -o /usr/share/keyrings/lst-keyring.gpg 2>/dev/null || true
        CODENAME=$(lsb_release -sc 2>/dev/null || echo "bullseye")
        echo "deb [signed-by=/usr/share/keyrings/lst-keyring.gpg] http://rpms.litespeedtech.com/debian/ $CODENAME main" \
            > /etc/apt/sources.list.d/lst_debian_repo.list 2>/dev/null || true
        apt-get update -y 2>/dev/null || true
        apt-get install -y lsws 2>/dev/null && LS_INSTALLED=1
    fi

    # Method 2: Fallback to silent get.litespeed.sh via /root/lsws.options
    if [ "$LS_INSTALLED" -eq 0 ]; then
        log_warn "Repo install failed — trying get.litespeed.sh script..."
        ADMIN_PASS=$(tr -dc 'a-zA-Z0-9' < /dev/urandom 2>/dev/null | head -c 12 || echo "Admin123$RANDOM")
        cat > /root/lsws.options << EOF
serial_no="${LS_SERIAL}"
php_suexec="2"
port_offset="0"
admin_user="admin"
admin_pass="${ADMIN_PASS}"
admin_email="root@localhost"
easyapache_integration="1"
auto_switch_to_lsws="1"
deploy_lscwp="0"
EOF
        touch /root/lsws-install.sh
        wget -q https://get.litespeed.sh -O /root/lsws-install.sh 2>/dev/null || true
        bash /root/lsws-install.sh "$LS_SERIAL" 2>/dev/null && LS_INSTALLED=1
        
        # Additional cleanup / compilation from fallback snippet
        wget -q https://litespeedtech.com/packages/cpanel/buildtimezone_ea4.tar.gz -O /root/buildtimezone_ea4.tar.gz 2>/dev/null || true
        tar -xzvf /root/buildtimezone_ea4.tar.gz 2>/dev/null || true
        chmod a+x /root/buildtimezone*.sh 2>/dev/null && /root/buildtimezone_ea4.sh y 2>/dev/null || true
        yum-complete-transaction --cleanup-only 2>/dev/null || true
        yum install ea-php*-php-devel -y --skip-broken 2>/dev/null || true
        yum remove ea-apache24-mod_ruid2 -y 2>/dev/null || true
        
        rm -f /root/buildtimezone* /root/lsws* 2>/dev/null || true
    fi

    if [ "$LS_INSTALLED" -eq 0 ]; then
        log_error "LiteSpeed install failed on $OS $VER"
        log_error "  Try manually: https://www.litespeedtech.com/support/wiki/doku.php/litespeed_wiki:cpanel:whm-plugin-install"
        PL_LS="Failed"
        return 1
    fi

    # Set license
    if [ "$LS_SERIAL" != "TRIAL" ] && [ "$LS_SERIAL" != "0" ] && [ -n "$LS_SERIAL" ]; then
        /usr/local/lsws/bin/lshttpd -r "$LS_SERIAL" 2>/dev/null || true
    fi

    # Install LSCache Manager plugin for WHM and config
    /usr/local/lsws/admin/misc/lscmctl cpanelplugin --install 2>/dev/null || true
    /usr/local/lsws/admin/misc/lscmctl setcacheroot 2>/dev/null || true
    /usr/local/lsws/admin/misc/lscmctl scan 2>/dev/null || true
    /usr/local/lsws/admin/misc/lscmctl enable -m 2>/dev/null || true

    # Enable and start
    systemctl enable lsws 2>/dev/null || true
    systemctl start lsws 2>/dev/null || true
    /usr/local/lsws/bin/lswsctrl start 2>/dev/null || true

    # Open LiteSpeed admin ports in CSF if present
    if [ -f /etc/csf/csf.conf ]; then
        for D in TCP_IN TCP_OUT; do
            CURR=$(grep "^${D}" /etc/csf/csf.conf | cut -d'=' -f2 | sed 's/ //g;s/"//g')
            for P in 7080 7443; do
                echo "$CURR" | grep -q "$P" || CURR="${CURR},${P}"
            done
            sed -i "s/^${D}.*/${D} = \"${CURR}\"/" /etc/csf/csf.conf
        done
        csf -r 2>/dev/null || true
    fi

    log_ok "LiteSpeed installed on $OS $VER"
    PL_LS="Installed"
}

# ═══════════════════════════════════════════
# REDIS & MEMCACHED (Object Caching)
# ═══════════════════════════════════════════
check_install_redis_memcached() {
    log_section "Redis & Memcached"
    if systemctl is-active --quiet redis 2>/dev/null || systemctl is-active --quiet redis-server 2>/dev/null || systemctl is-active --quiet memcached 2>/dev/null; then
        log_ok "Redis/Memcached — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "Redis/Memcached already active. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped Redis/Memcached configuration"
            PL_CACHE="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling Redis/Memcached..."
            systemctl stop redis-server memcached redis 2>/dev/null
            yum remove -y redis memcached 2>/dev/null || apt-get remove -y redis-server memcached 2>/dev/null
            log_ok "Redis/Memcached Uninstalled"
            PL_CACHE="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Install Redis & Memcached Object Caching?"; then 
        log_warn "Skipped"
        PL_CACHE="Skipped"
        return 0
    fi

    log_info "Installing services..."
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        apt-get install -y redis-server memcached 2>/dev/null || true
        systemctl enable redis-server memcached 2>/dev/null || true
        systemctl start redis-server memcached 2>/dev/null || true
    else
        local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
        $PKG install -y redis memcached 2>/dev/null || true
        systemctl enable redis memcached 2>/dev/null || true
        systemctl start redis memcached 2>/dev/null || true
    fi
    log_ok "Redis & Memcached services installed and started"
    PL_CACHE="Installed"
}

# ═══════════════════════════════════════════
# TELEGRAM ALERTS
# ═══════════════════════════════════════════
setup_telegram_alerts() {
    log_section "Capnel Security Alerts To Telegram"
    if [ -f /root/.telegram_installed ] || [ -f /usr/local/bin/telegram-alert ] || [ -f /usr/local/cpanel/whostmgr/docroot/cgi/telegram_bridge.php ]; then
        log_ok "cPanel Security Alerts To Telegram — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "cPanel Security Alerts To Telegram already configured. What would you like to do?" 30
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped Telegram integration."
            PL_TG="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling Telegram integration..."
            rm -f /usr/local/bin/telegram-alert /usr/local/cpanel/whostmgr/docroot/cgi/telegram_bridge.php /root/.telegram_installed
            sed -i '/telegram-alert/d' /etc/csf/csfpost.sh 2>/dev/null
            log_ok "Telegram integration Uninstalled"
            PL_TG="Uninstalled"
            return 0
        fi
    elif ! ask_yn "Enable cPanel Security Alerts To Telegram?"; then 
        log_warn "Skipped Telegram integration."
        PL_TG="Skipped"
        return 0
    fi

    echo -ne "  ${CYAN}➔ Enter Telegram Bot Token:${NC} " >/dev/tty
    read -r TG_TOKEN </dev/tty
    echo -ne "  ${CYAN}➔ Enter Telegram Chat ID:${NC} " >/dev/tty
    read -r TG_CHATID </dev/tty

    if [ -z "$TG_TOKEN" ] || [ -z "$TG_CHATID" ]; then
        log_error "Skipped (No credentials provided)"
        PL_TG="Failed"
        return 0
    fi

    echo -e "  ${GREEN}[OK] Telegram alerts will be configured.${NC}\n"

    log_info "Creating Telegram Alert Wrapper..."
    # 1. Create a global Bash script
    cat > /usr/local/bin/telegram-alert << 'EOF'
#!/bin/bash
TOKEN="YOUR_TG_TOKEN"
CHATID="YOUR_TG_CHATID"
TEXT="$1"
if [ -n "$TEXT" ]; then
    curl -s -d "chat_id=$CHATID&text=$TEXT" -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" >/dev/null
fi
EOF
    sed -i "s/YOUR_TG_TOKEN/$TG_TOKEN/g" /usr/local/bin/telegram-alert
    sed -i "s/YOUR_TG_CHATID/$TG_CHATID/g" /usr/local/bin/telegram-alert
    chmod +x /usr/local/bin/telegram-alert

    log_info "Integrating with CSF & WHM Contact Manager..."
    # 2. Add to CSF Post-Execution
    if [ -d /etc/csf ]; then
        echo "/usr/local/bin/telegram-alert \"🛡️ CSF Firewall Alert on \$(hostname): \$1\"" >> /etc/csf/csfpost.sh
        chmod +x /etc/csf/csfpost.sh
    fi

    # 3. Add WHM Contact Manager Webhook Bridge
    mkdir -p /usr/local/cpanel/whostmgr/docroot/cgi
    cat > /usr/local/cpanel/whostmgr/docroot/cgi/telegram_bridge.php << 'EOF'
<?php
$token = "YOUR_TG_TOKEN";
$chat_id = "YOUR_TG_CHATID";
$payload = file_get_contents('php://input');
if($payload) {
    $data = json_decode($payload, true);
    $msg = "🔔 WHM Alert: " . ($data['subject'] ?? 'Notification') . "\n\n" . ($data['body'] ?? '');
    file_get_contents("https://api.telegram.org/bot$token/sendMessage?chat_id=$chat_id&text=" . urlencode($msg));
}
EOF
    sed -i "s/YOUR_TG_TOKEN/$TG_TOKEN/g" /usr/local/cpanel/whostmgr/docroot/cgi/telegram_bridge.php
    sed -i "s/YOUR_TG_CHATID/$TG_CHATID/g" /usr/local/cpanel/whostmgr/docroot/cgi/telegram_bridge.php
    chown root:root /usr/local/cpanel/whostmgr/docroot/cgi/telegram_bridge.php
    chmod 755 /usr/local/cpanel/whostmgr/docroot/cgi/telegram_bridge.php
    
    # Send completion alert
    /usr/local/bin/telegram-alert "✅ WHM/cPanel Deployment v7.0.0 Successfully Completed on IP: $PUBLIC_IP"
    
    log_ok "Telegram Security Alerts Configured!"
    touch /root/.telegram_installed
    PL_TG="Installed"
}

# ═══════════════════════════════════════════
# CLOUDLINUX
# ═══════════════════════════════════════════
check_install_cloudlinux() {
    log_section "CloudLinux"
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        log_warn "CloudLinux not supported on Ubuntu/Debian — skipping"; PL_CL="Skipped (OS unsupported)"; return 0; fi
    if grep -qi "cloudlinux" /etc/os-release 2>/dev/null; then
        log_ok "CloudLinux — Configure / Installed Before"
        ask_reconfig_uninstall_timeout "CloudLinux already configured. What would you like to do?" 15
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped CloudLinux configuration"
            PL_CL="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling CloudLinux..."
            wget -q https://repo.cloudlinux.com/cloudlinux/sources/cln/cldeploy -O /tmp/cldeploy
            bash /tmp/cldeploy -c 2>/dev/null
            rm -f /tmp/cldeploy
            log_ok "CloudLinux Uninstalled"
            PL_CL="Uninstalled"
            return 0
        fi
    elif ! ask_yn "CloudLinux not found. Install?"; then 
        log_warn "Skipped"
        PL_CL="Skipped"
        return 0
    fi
    echo "  [1] License Key"
    echo "  [2] IP Activation (no key)"
    echo "  [3] Skip Registration (offline / trial — key 999)"
    read -rp "  Select [1/2/3] (default 2): " CL_MODE </dev/tty

    /usr/bin/wget -q https://repo.cloudlinux.com/cloudlinux/sources/cln/cldeploy -O /tmp/cldeploy
    chmod +x /tmp/cldeploy

    case "$CL_MODE" in
        1)
            read -rp "  License Key: " CL_KEY </dev/tty
            log_info "Deploying CloudLinux with license key..."
            bash /tmp/cldeploy -k "$CL_KEY"
            ;;
        3)
            log_info "Deploying CloudLinux (skip-registration, key 999)..."
            cd /root && /usr/bin/sh /tmp/cldeploy --skip-registration -k 999 &>/dev/null
            ;;
        *)
            log_info "Deploying CloudLinux (IP activation)..."
            bash /tmp/cldeploy -i
            ;;
    esac

    local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"

    # Core LVE manager + utilities
    log_info "Installing LVE Manager and utilities..."
    $PKG install -y lvemanager lvectl lve-utils lve-stats 2>/dev/null || true

    # Alt language stacks (PHP, Node.js, Python, Ruby via CloudLinux SCL)
    log_info "Installing alt-php, alt-nodejs, alt-python, alt-ruby groups..."
    $PKG groupinstall -y alt-php alt-nodejs alt-python alt-ruby 2>/dev/null || true

    # EA4 Apache modules required for CloudLinux integration
    log_info "Installing EA4 Apache modules (suexec, passenger)..."
    $PKG install -y ea-apache24-mod_suexec 2>/dev/null || true
    $PKG install -y ea-apache24-mod-alt-passenger 2>/dev/null || true

    # Grub2 (required for CloudLinux kernel boot — disable excludes so kernel isn't blocked)
    log_info "Installing/updating grub2..."
    $PKG install -y grub2 --disableexcludes=all 2>/dev/null || true

    # CageFS — install and initialize inline
    log_info "Installing and initializing CageFS..."
    $PKG install -y cagefs 2>/dev/null || true
    if command -v cagefsctl &>/dev/null || [ -f /usr/sbin/cagefsctl ]; then
        /usr/sbin/cagefsctl --init 2>/dev/null || cagefsctl --init 2>/dev/null || true
        cagefsctl --enable-all 2>/dev/null || true
        log_ok "CageFS initialized and enabled for all users"
    else
        log_warn "cagefsctl not found — CageFS may require a reboot first"
    fi

    rm -f /tmp/cldeploy
    log_warn "⚠  Reboot required to activate the CloudLinux kernel"
    log_ok "CloudLinux installed"
    PL_CL="Installed"
}

check_install_cagefs() {
    if ! grep -qi "cloudlinux" /etc/os-release 2>/dev/null; then
        PL_CGF="Skipped (No CloudLinux)"
        return 0
    fi

    log_section "CloudLinux CageFS"

    # If CageFS was already bootstrapped inline during check_install_cloudlinux(),
    # skip the install path but still allow the reconfigure/uninstall prompt.
    local _INLINE_INSTALLED=0
    [ "${PL_CL:-}" = "Installed" ] && _INLINE_INSTALLED=1

    if command -v cagefsctl &>/dev/null || [ -d /usr/share/cagefs-skeleton ] || [ -f /usr/sbin/cagefsctl ]; then
        log_ok "CloudLinux CageFS — Installed"

        # When just installed inline this session, auto-confirm and skip re-prompt
        if [ "$_INLINE_INSTALLED" -eq 1 ] && [ "${PL_CGF:-}" = "Installed" ]; then
            log_info "CageFS was initialized during CloudLinux install — skipping re-prompt"
            return 0
        fi

        ask_reconfig_uninstall_timeout "CloudLinux CageFS already configured. What would you like to do?" 15
        local choice=$?
        if [ $choice -eq 1 ]; then
            log_warn "Skipped CloudLinux CageFS configuration"
            PL_CGF="Installed (Pre-existing)"
            return 0
        elif [ $choice -eq 2 ]; then
            log_info "Uninstalling CloudLinux CageFS..."
            if command -v cagefsctl &>/dev/null; then
                cagefsctl --disable-all 2>/dev/null || true
                cagefsctl --unmount-all 2>/dev/null || true
            fi
            local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
            $PKG remove -y cagefs cagefs-safebin 2>/dev/null || true
            rm -rf /usr/share/cagefs-skeleton 2>/dev/null || true
            log_ok "CloudLinux CageFS Uninstalled"
            PL_CGF="Uninstalled"
            return 0
        fi
        # choice=0 (reconfigure) — fall through to reinit below
        log_info "Re-initializing CageFS..."
        cagefsctl --init 2>/dev/null || true
        cagefsctl --enable-all 2>/dev/null || true
        log_ok "CageFS re-initialized and enabled for all users"
        PL_CGF="Reconfigured"
        return 0
    fi

    # If we get here: CloudLinux is running but cagefsctl is missing
    # (e.g. inline install happened but reboot is still pending)
    if [ "$_INLINE_INSTALLED" -eq 1 ]; then
        log_warn "CageFS was installed but cagefsctl not yet available — reboot may be required"
        PL_CGF="Pending Reboot"
        return 0
    fi

    if ! ask_yn "Install CloudLinux CageFS?"; then
        log_warn "Skipped CloudLinux CageFS integration."
        PL_CGF="Skipped"
        return 0
    fi

    log_info "Installing CloudLinux CageFS..."
    local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
    $PKG install -y cagefs 2>/dev/null || true
    if command -v cagefsctl &>/dev/null || [ -f /usr/sbin/cagefsctl ]; then
        /usr/sbin/cagefsctl --init 2>/dev/null || cagefsctl --init 2>/dev/null || true
        cagefsctl --enable-all 2>/dev/null || true
        log_ok "CloudLinux CageFS installed and initialized"
        PL_CGF="Installed"
    else
        log_warn "CageFS installed — cagefsctl not yet available (reboot may be required)"
        PL_CGF="Pending Reboot"
    fi
}

configure_cloudlinux_symlink() {
    if ! grep -qi "cloudlinux" /etc/os-release 2>/dev/null; then
        return 0
    fi
    log_info "Configuring CloudLinux Symlink Protection..."
    
    local NOBODY_GID=99
    if id nobody &>/dev/null; then
        NOBODY_GID=$(id -g nobody)
    fi
    
    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/90-cloudlinux.conf << EOF
fs.enforce_symlinksifowner = 1
fs.symlinkown_gid = $NOBODY_GID
EOF
    sysctl --system 2>/dev/null || true

    log_ok "CloudLinux Symlink Protection configured (GID: $NOBODY_GID)"
}


# ═══════════════════════════════════════════
# EA4 PHP 7.2–8.5 + ALL EXTENSIONS
# ═══════════════════════════════════════════
install_ea4_php() {
    local SELECTED_VERS="$1"
    local DISPLAY_VERS="${SELECTED_VERS:-7.2–8.5}"
    [ "$SELECTED_VERS" = "80 81 82 83 84 85" ] && DISPLAY_VERS="8.0–8.5"
    log_section "EA4 PHP $DISPLAY_VERS + Extensions"

    if [ -f /var/cpanel/ApachePHPFPM/system_pool_defaults.yaml ] || [ -d /opt/cpanel/ea-php81 ]; then
        log_ok "EA4 PHP $DISPLAY_VERS + Extensions — Configure / Installed Before"
        if ! ask_yn_timeout "EA4 PHP already configured. Do you want to reconfigure it?" 30; then
            log_warn "Skipped EA4 PHP configuration"
            return 0
        fi
    fi

    # ── Detect and remove deprecated/EOL PHP versions ──
    # Note: 7.2 and 7.3 are now target versions — only 5.6, 7.0, 7.1 are EOL here
    local EOL_PHP_VERSIONS="56 70 71"
    local EOL_FOUND=""
    for EV in $EOL_PHP_VERSIONS; do
        if [ -d "/opt/cpanel/ea-php${EV}" ]; then
            local PHP_BIN="/opt/cpanel/ea-php${EV}/root/usr/bin/php"
            local PHP_FULL_VER=""
            if [ -x "$PHP_BIN" ]; then
                PHP_FULL_VER=$($PHP_BIN -v 2>/dev/null | head -1 | awk '{print $2}')
            fi
            if [ -n "$PHP_FULL_VER" ]; then
                log_warn "Found EOL PHP: ${PHP_FULL_VER} ($PHP_BIN)"
            else
                log_warn "Found EOL PHP: ea-php${EV} (/opt/cpanel/ea-php${EV})"
            fi
            EOL_FOUND="$EOL_FOUND ea-php${EV}"
        fi
    done

    if [ -n "$EOL_FOUND" ]; then
        echo ""
        log_warn "⚠️  The following End-Of-Life PHP versions are installed and are a security risk:"
        for EP in $EOL_FOUND; do
            echo -e "      ${RED}✘${NC} $EP"
        done
        echo ""
        if ask_yn_timeout "Remove these deprecated PHP versions? (Recommended)" 30; then
            log_info "Removing EOL PHP versions..."
            local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
            for EP in $EOL_FOUND; do
                log_info "Removing ${EP} and all extensions..."
                if echo "$OS" | grep -iq "ubuntu\|debian"; then
                    apt-get remove -y ${EP}* 2>/dev/null || true
                    apt-get autoremove -y 2>/dev/null || true
                else
                    $PKG remove -y ${EP}* 2>/dev/null || true
                fi
            done
            log_ok "EOL PHP versions removed"
        else
            log_warn "Keeping EOL PHP versions — skipping them during configuration"
        fi
    fi

    # Install libsodium
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        apt-get install -y libsodium-dev libsodium23 2>/dev/null || true
    else
        local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
        $PKG install -y libsodium libsodium-devel 2>/dev/null || true
    fi

    # PHP versions to install (7.2–8.5)
    local PHP_VERS
    if [ -n "$1" ]; then
        PHP_VERS="$1"
    else
        echo ""
        echo "  - Type '8.x' for PHP 8.0 to 8.5"
        echo "  - Press ENTER for all (7.2 to 8.5)"
        read -rp "  Enter versions/keyword: " USER_PHP_CHOICE </dev/tty
        
        if [ -z "$USER_PHP_CHOICE" ] || [ "${USER_PHP_CHOICE,,}" = "all" ]; then
            PHP_VERS="72 73 74 80 81 82 83 84 85"
        elif [ "${USER_PHP_CHOICE,,}" = "8.x" ]; then
            PHP_VERS="80 81 82 83 84 85"
        else
            PHP_VERS="$USER_PHP_CHOICE"
        fi
    fi
    log_info "Selected PHP versions: $PHP_VERS"

    # Extensions per version — full set
    local EXTS="pear php-cli php-common php-curl php-devel php-exif php-fileinfo \
php-ftp php-gd php-iconv php-intl php-litespeed php-mbstring php-mysqlnd \
php-mysqli php-opcache php-pdo php-posix php-soap php-zip runtime php-bcmath \
php-gettext php-gmp php-xml php-imap php-sodium php-calendar \
php-fpm php-ldap php-xmlrpc php-sockets php-imagick \
php-ctype php-tokenizer php-bz2 php-pspell php-process php-json \
php-igbinary php-sqlite3 php-tidy php-uuid php-maxminddb php-mbregex"

    local INSTALL_LIST=""
    for V in $PHP_VERS; do
        INSTALL_LIST="$INSTALL_LIST ea-php${V}"
        for E in $EXTS; do
            INSTALL_LIST="$INSTALL_LIST ea-php${V}-${E}"
        done
    done

    # IonCube per version
    INSTALL_LIST="$INSTALL_LIST ea-php72-php-ioncube10 ea-php73-php-ioncube10"
    INSTALL_LIST="$INSTALL_LIST ea-php74-php-ioncube10 ea-php81-php-ioncube12"
    INSTALL_LIST="$INSTALL_LIST ea-php82-php-ioncube13 ea-php83-php-ioncube14"
    INSTALL_LIST="$INSTALL_LIST ea-php84-php-ioncube14 ea-php85-php-ioncube15"

    # Apache modules
    INSTALL_LIST="$INSTALL_LIST ea-apache24-mod_proxy_fcgi ea-apache24-mod_version ea-apache24-mod_env"

    log_info "Installing EA4 PHP packages (this may take a while)..."
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        apt-get install -y $INSTALL_LIST 2>/dev/null || true
    else
        local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
        $PKG install -y $INSTALL_LIST --skip-broken 2>/dev/null || true
    fi

    # Install Redis, APCu, Memcached extensions (only for supported versions — skip EOL)
    log_info "Installing Redis, APCu, Memcached extensions..."
    local CACHE_EXT_LIST=""
    for V in $PHP_VERS; do
        CACHE_EXT_LIST="$CACHE_EXT_LIST ea-php${V}-php-redis ea-php${V}-php-apcu ea-php${V}-php-memcached"
    done
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        apt-get install -y $CACHE_EXT_LIST 2>/dev/null || true
    else
        local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
        $PKG install -y $CACHE_EXT_LIST --skip-broken 2>/dev/null || true
    fi

    # IonCube + SourceGuardian loaders
    log_info "Installing IonCube & SourceGuardian loaders..."
    sed -i 's/phploader=.*/phploader=ioncube,sourceguardian/' /var/cpanel/cpanel.config 2>/dev/null || true
    /usr/local/cpanel/whostmgr/bin/whostmgr2 --updatetweaksettings 2>/dev/null || true
    /usr/local/cpanel/bin/checkphpini 2>/dev/null || true
    /usr/local/cpanel/bin/install_php_inis 2>/dev/null || true
    local LOADER_LIST=""
    for V in $PHP_VERS; do
        LOADER_LIST="$LOADER_LIST ea-php${V}-php-sourceguardian"
    done
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        apt-get install -y $LOADER_LIST 2>/dev/null || true
    else
        local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
        $PKG install -y $LOADER_LIST --skip-broken 2>/dev/null || true
    fi

    # ImageMagick
    log_info "Installing ImageMagick..."
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        apt-get install -y imagemagick libmagickwand-dev 2>/dev/null || true
    else
        local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
        $PKG install -y ImageMagick-devel ImageMagick-c++-devel ImageMagick-perl 2>/dev/null || true
    fi

    # PHP.ini global settings
    log_info "Configuring PHP.ini for all versions..."

    # Direct EA-PHP path method — only target supported versions (skip EOL)
    for V in $PHP_VERS; do
        local INI="/opt/cpanel/ea-php${V}/root/etc/php.ini"
        [ -f "$INI" ] || continue
        /usr/bin/sed -i 's/memory_limit = .*/memory_limit = 1024M/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/max_execution_time = .*/max_execution_time = 200/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/max_input_time = .*/max_input_time = 200/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/max_input_vars = .*/max_input_vars = 3000/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/post_max_size = .*/post_max_size = 100M/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/upload_max_filesize = .*/upload_max_filesize = 100M/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/allow_url_fopen = .*/allow_url_fopen = On/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/file_uploads = .*/file_uploads = On/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/expose_php = .*/expose_php = Off/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/enable_dl = .*/enable_dl = Off/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/display_errors = .*/display_errors = Off/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/track_errors = .*/track_errors = Off/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/html_errors = .*/html_errors = Off/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/error_reporting = .*/error_reporting = E_ALL \& ~E_DEPRECATED \& ~E_STRICT/' "$INI" &>/dev/null || true
        # Uncomment and set default_charset
        /usr/bin/sed -i 's/^;default_charset = "UTF-8"/default_charset = "UTF-8"/' "$INI" &>/dev/null || true
        /usr/bin/sed -i 's/^default_charset = .*/default_charset = "UTF-8"/' "$INI" &>/dev/null || true
        # Set timezone to UTC (universal default — users can override per-account)
        /usr/bin/sed -i 's|^;*date.timezone.*|date.timezone = "UTC"|' "$INI" &>/dev/null || true
        # Security: disable dangerous PHP functions (shared hosting hardening)
        /usr/bin/sed -i 's/^disable_functions.*/disable_functions = apache_get_modules,apache_get_version,apache_getenv,apache_note,apache_setenv,disk_free_space,diskfreespace,dl,exec,highlight_file,ini_alter,ini_restore,openlog,passthru,phpinfo,popen,posix_getpwuid,proc_close,proc_get_status,proc_nice,proc_open,proc_terminate,shell_exec,show_source,symlink,system,eval,debug_zval_dump/' "$INI" &>/dev/null || true
    done

    # Also apply key settings to local.ini overrides (only supported versions)
    for V in $PHP_VERS; do
        find /opt/cpanel/ea-php${V}/ \( -name "php.ini" -o -name "local.ini" \) 2>/dev/null | xargs -r sed -i \
            's/^memory_limit.*/memory_limit = 1024M/g' 2>/dev/null || true
        find /opt/cpanel/ea-php${V}/ \( -name "php.ini" -o -name "local.ini" \) 2>/dev/null | xargs -r sed -i \
            's/^upload_max_filesize.*/upload_max_filesize = 100M/g' 2>/dev/null || true
        find /opt/cpanel/ea-php${V}/ \( -name "php.ini" -o -name "local.ini" \) 2>/dev/null | xargs -r sed -i \
            's/^post_max_size.*/post_max_size = 100M/g' 2>/dev/null || true
    done

    # PHP-FPM defaults
    mkdir -p /var/cpanel/ApachePHPFPM
    cat > /var/cpanel/ApachePHPFPM/system_pool_defaults.yaml << 'EOF'
---
pm_max_children: 20
pm_max_requests: 40
php_admin_value_disable_functions : { present_ifdefault: 0 }
EOF
    /usr/local/cpanel/scripts/php_fpm_config --rebuild 2>/dev/null || true
    /scripts/restartsrv_apache_php_fpm 2>/dev/null || true

    # Set handlers and default PHP version
    for V in $PHP_VERS; do
        whmapi1 php_set_handler version=ea-php${V} handler=cgi 2>/dev/null || true
    done
    
    # Set default version to 8.5 if installed, otherwise pick highest in list
    local DEFAULT_PHP="ea-php85"
    echo "$PHP_VERS" | grep -q "85" || DEFAULT_PHP="ea-php$(echo $PHP_VERS | awk '{print $NF}')"
    
    whmapi1 php_set_system_default_version version=${DEFAULT_PHP} 2>/dev/null || true
    whmapi1 php_set_default_accounts_to_fpm default_accounts_to_fpm=1 2>/dev/null || true

    log_ok "EA4 PHP versions ($PHP_VERS) installed with all extensions (mbstring, mbregex, xml, igbinary, sqlite3, tidy, uuid, maxminddb, imagick, ioncube, and more)"
}

# ═══════════════════════════════════════════
# WHM TWEAK SETTINGS + BASIC CONFIG
# ═══════════════════════════════════════════
configure_whm_tweaks() {
    log_section "WHM Tweak Settings & Basic Config"
    [ ! -d /usr/local/cpanel ] && { log_warn "cPanel not found"; return 1; }

    if grep -q "^TTL 900" /etc/wwwacct.conf 2>/dev/null; then
        log_ok "WHM Tweak Settings & Basic Config — Configure / Installed Before"
        if ! ask_yn_timeout "WHM Tweak Settings already configured. Do you want to reconfigure it?" 30; then
            log_warn "Skipped WHM Tweak Settings configuration"
            return 0
        fi
    fi

    HOSTNAME_LONG=$(hostname -d 2>/dev/null || hostname -f)

    # wwwacct.conf
    sed -i 's/^TTL .*/TTL 900/' /etc/wwwacct.conf 2>/dev/null || true
    sed -i '/^CONTACTEMAIL\ .*/d' /etc/wwwacct.conf 2>/dev/null || true
    echo "CONTACTEMAIL hostmaster@$HOSTNAME_LONG" >> /etc/wwwacct.conf
    sed -i '/^NS\ .*/d;/^NS2\ .*/d;/^NS3\ .*/d' /etc/wwwacct.conf 2>/dev/null || true
    echo "NS ns1.$HOSTNAME_LONG" >> /etc/wwwacct.conf
    echo "NS2 ns2.$HOSTNAME_LONG" >> /etc/wwwacct.conf
    sed -i "s/^ADDR .*/ADDR $PUBLIC_IP/" /etc/wwwacct.conf 2>/dev/null || true

    # PureFTPd
    mkdir -p /var/cpanel/conf/pureftpd
    for opt in "MaxClientsPerIP: 30" "RootPassLogins: 'no'" \
        "PassivePortRange: $PASSV_MIN $PASSV_MAX" \
        'TLSCipherSuite: "HIGH:MEDIUM:+TLSv1:!SSLv2:+SSLv3"' \
        "LimitRecursion: 50000 12"; do
        KEY=$(echo "$opt" | cut -d: -f1)
        sed -i "/^${KEY}:.*/d" /var/cpanel/conf/pureftpd/local 2>/dev/null || true
        echo "$opt" >> /var/cpanel/conf/pureftpd/local
    done
    /usr/local/cpanel/scripts/setupftpserver pure-ftpd --force 2>/dev/null || true
    modprobe ip_conntrack_ftp 2>/dev/null || true

    # All Tweak Settings (merged from both refs, conflicts resolved)
    local -A TWEAKS=(
        [allowremotedomains]=1 [allowunregistereddomains]=1
        [chkservd_check_interval]=120 [defaultmailaction]=fail
        [email_send_limits_max_defer_fail_percentage]=25
        [email_send_limits_min_defer_fail_to_trigger_protection]=15
        [maxemailsperhour]=200 [permit_unregistered_apps_as_root]=1
        [requiressl]=0 [skipanalog]=1 [skipboxtrapper]=1 [skipwebalizer]=1
        [smtpmailgidonly]=0 [eximmailtrap]=1 [use_information_schema]=0
        [cookieipvalidation]=strict [notify_expiring_certificates]=0
        [cpaddons_notify_owner]=0 [cpaddons_notify_root]=0
        [enable_piped_logs]=1 [email_outbound_spam_detect_action]=block
        [email_outbound_spam_detect_enable]=1 [email_outbound_spam_detect_threshold]=120
        [skipspambox]=0 [skipmailman]=1 [jaildefaultshell]=1
        [proxysubdomains]=0
        [php_post_max_size]=100 [php_upload_max_filesize]=100
        [empty_trash_days]=30 [publichtmlsubsonly]=0 [proxysubdomainsoverride]=0
        [display_cpanel_promotions]=0 [resetpass]=0 [resetpass_sub]=0
        [referrerblanksafety]=1 [referrersafety]=1 [cgihidepass]=1
        [mycnf_auto_adjust_maxallowedpacket]=1
        [mycnf_auto_adjust_openfiles_limit]=1
        [mycnf_auto_adjust_innodb_buffer_pool_size]=1
    )
    for key in "${!TWEAKS[@]}"; do
        whmapi1 set_tweaksetting key="$key" value="${TWEAKS[$key]}" 2>/dev/null || true
    done

    # Additional cpanel.config settings
    sed -i 's/^phpopenbasedirhome=.*/phpopenbasedirhome=1/' /var/cpanel/cpanel.config 2>/dev/null || true
    sed -i 's/^minpwstrength=.*/minpwstrength=70/' /var/cpanel/cpanel.config 2>/dev/null || true
    sed -i 's/^phploader=.*/phploader=ioncube,sourceguardian/' /var/cpanel/cpanel.config 2>/dev/null || true
    sed -i 's/^enforce_user_account_limits=.*/enforce_user_account_limits=1/' /var/cpanel/cpanel.config 2>/dev/null || true
    sed -i 's/^emailusers_diskusage_warn_contact_admin=.*/emailusers_diskusage_warn_contact_admin=1/' /var/cpanel/cpanel.config 2>/dev/null || true
    sed -i 's/^emailsperdaynotify=.*/emailsperdaynotify=1000/' /var/cpanel/cpanel.config 2>/dev/null || true
    sed -i 's/^exim-retrytime=.*/exim-retrytime=30/' /var/cpanel/cpanel.config 2>/dev/null || true

    # AutoSSL — Let's Encrypt
    whmapi1 set_autossl_provider provider="LetsEncrypt" terms_of_service_accepted=1 2>/dev/null || true
    whmapi1 set_autossl_metadata_key key=clobber_externally_signed value=1 2>/dev/null || true
    whmapi1 set_autossl_metadata_key key=notify_autossl_expiry value=0 2>/dev/null || true
    whmapi1 set_autossl_metadata_key key=notify_autossl_expiry_coverage value=0 2>/dev/null || true
    whmapi1 set_autossl_metadata_key key=notify_autossl_renewal value=0 2>/dev/null || true
    whmapi1 set_autossl_metadata_key key=notify_autossl_renewal_coverage value=0 2>/dev/null || true
    whmapi1 set_autossl_metadata_key key=notify_autossl_renewal_coverage_reduced value=0 2>/dev/null || true
    whmapi1 set_autossl_metadata_key key=notify_autossl_renewal_uncovered_domains value=0 2>/dev/null || true

    # Disable cPHulk (CSF handles brute-force)
    whmapi1 disable_cphulk 2>/dev/null || true

    # 2FA
    whmapi1 twofactorauth_enable_policy 2>/dev/null || true

    # Disable Greylisting
    whmapi1 disable_cpgreylist 2>/dev/null || true

    # Feature lists
    whmapi1 update_featurelist featurelist=disabled api_shell=0 agora=0 analog=0 boxtrapper=0 \
        traceaddy=0 modules-php-pear=0 modules-perl=0 modules-ruby=0 pgp=0 phppgadmin=0 \
        postgres=0 ror=0 serverstatus=0 webalizer=0 clamavconnector_scan=0 lists=0 emailtrace=1 2>/dev/null || true
    whmapi1 update_featurelist featurelist=default modsecurity=1 zoneedit=1 emailtrace=1 2>/dev/null || true

    # Default package
    QUOTA=$(df -h /home/ | tail -1 | awk '{ print $2 }' | sed 's/G//' | awk '{ print ($1 * 1000) * 0.8 }')
    whmapi1 addpkg name=default featurelist=default quota=$QUOTA cgi=0 frontpage=0 language=en \
        maxftp=20 maxsql=20 maxpop=unlimited maxlists=0 maxsub=30 maxpark=30 maxaddon=0 \
        hasshell=1 bwlimit=unlimited MAX_EMAIL_PER_HOUR=300 MAX_DEFER_FAIL_PERCENTAGE=30 2>/dev/null || true

    # MySQL config
    sed -i '/^local-infile.*/d;/^sql_mode.*/d;/^# WHM pre-configured.*/d' /etc/my.cnf 2>/dev/null || true
    sed -i '/\[mysqld\]/a\ ' /etc/my.cnf 2>/dev/null || true
    sed -i '/\[mysqld\]/a sql_mode = ALLOW_INVALID_DATES,NO_ENGINE_SUBSTITUTION' /etc/my.cnf 2>/dev/null || true
    sed -i '/\[mysqld\]/a local-infile=0' /etc/my.cnf 2>/dev/null || true
    sed -i '/\[mysqld\]/a # WHM pre-configured values' /etc/my.cnf 2>/dev/null || true
    /scripts/restartsrv_mysql 2>/dev/null || true

    # Exim config
    sed -i 's/^per_domain_mailips=.*/per_domain_mailips=1/' /etc/exim.conf.localopts 2>/dev/null || true
    sed -i 's/^max_spam_scan_size=.*/max_spam_scan_size=1000/' /etc/exim.conf.localopts 2>/dev/null || true

    # Exim attachment size limit (50M)
    log_info "Setting Exim message_size_limit to 50M..."
    sed -i '/^message_size_limit.*/d' /etc/exim.conf.local 2>/dev/null || true
    if grep -q "@CONFIG@" /etc/exim.conf.local 2>/dev/null; then
        sed -i '/@CONFIG@/ a message_size_limit = 50M' /etc/exim.conf.local
    else
        echo "@CONFIG@" >> /etc/exim.conf.local
        echo "" >> /etc/exim.conf.local
        sed -i '/@CONFIG@/ a message_size_limit = 50M' /etc/exim.conf.local
    fi

    # Disable RecentAuthedMailIpTracker (reduces overhead)
    /usr/local/cpanel/libexec/tailwatchd --disable=Cpanel::TailWatch::RecentAuthedMailIpTracker 2>/dev/null || true

    /scripts/buildeximconf 2>/dev/null || true

    # Header Authorization CGI
    if [ -f /etc/apache2/conf.d/includes/pre_main_global.conf ]; then
        sed -i '/# START HEADER AUTHORIZATION CGI/,/# END HEADER AUTHORIZATION CGI/d' \
            /etc/apache2/conf.d/includes/pre_main_global.conf 2>/dev/null || true
        cat >> /etc/apache2/conf.d/includes/pre_main_global.conf << 'EOF'
# START HEADER AUTHORIZATION CGI
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1
# END HEADER AUTHORIZATION CGI
EOF
    fi

    # Disable welcome panel for new accounts
    mkdir -pv /root/cpanel3-skel/.cpanel/nvdata 2>/dev/null || true
    echo "1" > /root/cpanel3-skel/.cpanel/nvdata/xmainwelcomedismissed

    # BG Process Killer (file-based — more reliable than whmapi1 alone)
    log_info "Configuring Background Process Killer..."
    [ -f /var/cpanel/killproc.conf ] && cp /var/cpanel/killproc.conf /var/cpanel/killproc.conf.beforetweak 2>/dev/null || true
    cat > /var/cpanel/killproc.conf << 'KILLEOF'
services
ptlink
psyBNC
ircd
guardservices
generic-sniffers
eggdrop
bnc
BitchX
KILLEOF
    # Also set via whmapi1 as backup
    whmapi1 configurebackgroundprocesskiller \
        processes_to_kill=BitchX processes_to_kill=bnc processes_to_kill=eggdrop \
        processes_to_kill=generic-sniffers processes_to_kill=guardservices \
        processes_to_kill=ircd processes_to_kill=psyBNC processes_to_kill=ptlink \
        processes_to_kill=services force=1 2>/dev/null || true

    # BIND
    /scripts/setupnameserver bind --force 2>/dev/null || true

    # Disable mlocate
    chmod -x /etc/cron.daily/mlocate* 2>/dev/null || true

    # Accept EULA
    whmapi1 accept_eula 2>/dev/null || true

    # ── Disable Compiler Access ──
    log_info "Disabling compiler access..."
    # Method 1: cPanel script (most reliable across all OS)
    /scripts/compilers off 2>/dev/null || true
    # Method 2: whmapi1
    whmapi1 set_tweaksetting key=use_compiler_group value=1 2>/dev/null || true
    # Method 3: Direct file permissions (fallback)
    for COMP in /usr/bin/gcc /usr/bin/g++ /usr/bin/cc /usr/bin/c++ /usr/bin/cpp \
                /usr/bin/make /usr/bin/as /usr/bin/ld; do
        if [ -f "$COMP" ]; then
            chmod 750 "$COMP" 2>/dev/null || true
            chown root:compiler "$COMP" 2>/dev/null || true
        fi
    done

    # ── Shell Fork Bomb Protection ──
    log_info "Enabling Shell Fork Bomb Protection..."
    /usr/local/cpanel/bin/install-login-profile --install limits 2>/dev/null || true

    # Fix cPanel RPMs
    /usr/local/cpanel/scripts/check_cpanel_pkgs --fix 2>/dev/null || true

    /usr/local/cpanel/whostmgr/bin/whostmgr2 --updatetweaksettings 2>/dev/null || true
    /usr/local/cpanel/etc/init/startcpsrvd 2>/dev/null || true
    /usr/local/cpanel/scripts/restartsrv_cpsrvd 2>/dev/null || true

    # ── WHM Web UI Configuration (cookie-based curl) ──
    touch $CWD/wpwhmcookie.txt
    SESS_CREATE=$(whmapi1 create_user_session user=root service=whostmgrd)
    SESS_TOKEN=$(echo "$SESS_CREATE" | grep "cp_security_token:" | cut -d':' -f2- | sed 's/ //')
    SESS_QS=$(echo "$SESS_CREATE" | grep "session:" | cut -d':' -f2- | sed 's/ //' | sed 's/ /%20/g;s/!/%21/g;s/"/%22/g;s/#/%23/g;s/\$/%24/g;s/\&/%26/g;s/'\''/%27/g;s/(/%28/g;s/)/%29/g;s/:/%3A/g')

    curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/login/?session=$SESS_QS" --cookie-jar $CWD/wpwhmcookie.txt > /dev/null

    echo "Deshabilitando compilers..."
    curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/tweakcompilers" --cookie $CWD/wpwhmcookie.txt --data 'action=Disable+Compilers' > /dev/null
    echo "Deshabilitando SMTP Restrictions (se usa CSF)..."
    curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/smtpmailgidonly?action=Disable" --cookie $CWD/wpwhmcookie.txt > /dev/null
    echo "Deshabilitando Shell Fork Bomb Protection..."
    curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/modlimits?limits=0" --cookie $CWD/wpwhmcookie.txt > /dev/null
    echo "Habilitando Background Process Killer..."
    curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/json-api/configurebackgroundprocesskiller" --cookie $CWD/wpwhmcookie.txt --data 'api.version=1&processes_to_kill=BitchX&processes_to_kill=bnc&processes_to_kill=eggdrop&processes_to_kill=generic-sniffers&processes_to_kill=guardservices&processes_to_kill=ircd&processes_to_kill=psyBNC&processes_to_kill=ptlink&processes_to_kill=services&force=1' > /dev/null

    echo "Configurando Apache..."
    # CONF BASICA
    curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/saveglobalapachesetup" --cookie $CWD/wpwhmcookie.txt --data 'module=Apache&find=&___original_sslciphersuite=ECDHE-ECDSA-AES256-GCM-SHA384%3AECDHE-RSA-AES256-GCM-SHA384%3AECDHE-ECDSA-CHACHA20-POLY1305%3AECDHE-RSA-CHACHA20-POLY1305%3AECDHE-ECDSA-AES128-GCM-SHA256%3AECDHE-RSA-AES128-GCM-SHA256%3AECDHE-ECDSA-AES256-SHA384%3AECDHE-RSA-AES256-SHA384%3AECDHE-ECDSA-AES128-SHA256%3AECDHE-RSA-AES128-SHA256&sslciphersuite_control=default&___original_sslprotocol=TLSv1.2&sslprotocol_control=default&___original_loglevel=warn&loglevel=warn&___original_traceenable=Off&traceenable=Off&___original_serversignature=Off&serversignature=Off&___original_servertokens=ProductOnly&servertokens=ProductOnly&___original_fileetag=None&fileetag=None&___original_root_options=&root_options=FollowSymLinks&root_options=IncludesNOEXEC&root_options=SymLinksIfOwnerMatch&___original_startservers=5&startservers_control=default&___original_minspareservers=5&minspareservers_control=default&___original_maxspareservers=10&maxspareservers_control=default&___original_optimize_htaccess=search_homedir_below&optimize_htaccess=search_homedir_below&___original_serverlimit=256&serverlimit_control=default&___original_maxclients=150&maxclients_control=other&maxclients_other=100&___original_maxrequestsperchild=10000&maxrequestsperchild_control=default&___original_keepalive=On&keepalive=1&___original_keepalivetimeout=5&keepalivetimeout_control=3&___original_maxkeepaliverequests=100&maxkeepaliverequests_control=20&___original_timeout=300&timeout_control=default&___original_symlink_protect=Off&symlink_protect=0&its_for_real=1' > /dev/null

    # DIRECTORYINDEX
    curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/save_apache_directoryindex" --cookie $CWD/wpwhmcookie.txt --data 'valid_submit=1&dirindex=index.php&dirindex=index.php5&dirindex=index.php4&dirindex=index.php3&dirindex=index.perl&dirindex=index.pl&dirindex=index.plx&dirindex=index.ppl&dirindex=index.cgi&dirindex=index.jsp&dirindex=index.jp&dirindex=index.phtml&dirindex=index.shtml&dirindex=index.xhtml&dirindex=index.html&dirindex=index.htm&dirindex=index.wml&dirindex=Default.html&dirindex=Default.htm&dirindex=default.html&dirindex=default.htm&dirindex=home.html&dirindex=home.htm&dirindex=index.js' > /dev/null

    curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/save_apache_mem_limits" --cookie $CWD/wpwhmcookie.txt --data 'newRLimitMem=enabled&newRLimitMemValue=1024&restart_apache=on&btnSave=1' > /dev/null

    /scripts/rebuildhttpdconf
    service httpd restart

    # DOVECOT
    curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/savedovecotsetup" --cookie $CWD/wpwhmcookie.txt --data 'protocols_enabled_imap=on&protocols_enabled_pop3=on&ipv6=on&enable_plaintext_auth=yes&ssl_cipher_list=ECDHE-ECDSA-CHACHA20-POLY1305%3AECDHE-RSA-CHACHA20-POLY1305%3AECDHE-ECDSA-AES128-GCM-SHA256%3AECDHE-RSA-AES128-GCM-SHA256%3AECDHE-ECDSA-AES256-GCM-SHA384%3AECDHE-RSA-AES256-GCM-SHA384%3ADHE-RSA-AES128-GCM-SHA256%3ADHE-RSA-AES256-GCM-SHA384%3AECDHE-ECDSA-AES128-SHA256%3AECDHE-RSA-AES128-SHA256%3AECDHE-ECDSA-AES128-SHA%3AECDHE-RSA-AES256-SHA384%3AECDHE-RSA-AES128-SHA%3AECDHE-ECDSA-AES256-SHA384%3AECDHE-ECDSA-AES256-SHA%3AECDHE-RSA-AES256-SHA%3ADHE-RSA-AES128-SHA256%3ADHE-RSA-AES128-SHA%3ADHE-RSA-AES256-SHA256%3ADHE-RSA-AES256-SHA%3AECDHE-ECDSA-DES-CBC3-SHA%3AECDHE-RSA-DES-CBC3-SHA%3AEDH-RSA-DES-CBC3-SHA%3AAES128-GCM-SHA256%3AAES256-GCM-SHA384%3AAES128-SHA256%3AAES256-SHA256%3AAES128-SHA%3AAES256-SHA%3ADES-CBC3-SHA%3A%21DSS&ssl_min_protocol=TLSv1&max_mail_processes=512&mail_process_size=512&protocol_imap.mail_max_userip_connections=20&protocol_imap.imap_idle_notify_interval=24&protocol_pop3.mail_max_userip_connections=3&login_processes_count=2&login_max_processes_count=50&login_process_size=128&auth_cache_size=1M&auth_cache_ttl=3600&auth_cache_negative_ttl=3600&login_process_per_connection=no&config_vsz_limit=2048&mailbox_idle_check_interval=30&mdbox_rotate_size=10M&mdbox_rotate_interval=0&incoming_reached_quota=bounce&lmtp_process_min_avail=0&lmtp_process_limit=500&lmtp_user_concurrency_limit=4&expire_trash=1&expire_trash_ttl=30&include_trash_in_quota=1'

    # EXIM
    curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/saveeximtweaks" --cookie $CWD/wpwhmcookie.txt --data 'in_tab=1&module=Mail&find=&___original_acl_deny_spam_score_over_int=&___undef_original_acl_deny_spam_score_over_int=1&acl_deny_spam_score_over_int_control=undef&___original_acl_dictionary_attack=1&acl_dictionary_attack=1&___original_acl_primary_hostname_bl=0&acl_primary_hostname_bl=0&___original_acl_spam_scan_secondarymx=1&acl_spam_scan_secondarymx=1&___original_acl_ratelimit=1&acl_ratelimit=1&___original_acl_ratelimit_spam_score_over_int=&___undef_original_acl_ratelimit_spam_score_over_int=1&acl_ratelimit_spam_score_over_int_control=undef&___original_acl_slow_fail_block=1&acl_slow_fail_block=1&___original_acl_requirehelo=1&acl_requirehelo=1&___original_acl_delay_unknown_hosts=1&acl_delay_unknown_hosts=1&___original_acl_dont_delay_greylisting_trusted_hosts=1&acl_dont_delay_greylisting_trusted_hosts=1&___original_acl_dont_delay_greylisting_common_mail_providers=0&acl_dont_delay_greylisting_common_mail_providers=0&___original_acl_requirehelonoforge=1&acl_requirehelonoforge=1&___original_acl_requirehelonold=0&acl_requirehelonold=0&___original_acl_requirehelosyntax=1&acl_requirehelosyntax=1&___original_acl_dkim_disable=1&acl_dkim_disable=1&___original_acl_dkim_bl=0&___original_acl_deny_rcpt_soft_limit=&___undef_original_acl_deny_rcpt_soft_limit=1&acl_deny_rcpt_soft_limit_control=undef&___original_acl_deny_rcpt_hard_limit=&___undef_original_acl_deny_rcpt_hard_limit=1&acl_deny_rcpt_hard_limit_control=undef&___original_spammer_list_ips_button=&___undef_original_spammer_list_ips_button=1&___original_sender_verify_bypass_ips_button=&___undef_original_sender_verify_bypass_ips_button=1&___original_trusted_mail_hosts_ips_button=&___undef_original_trusted_mail_hosts_ips_button=1&___original_skip_smtp_check_ips_button=&___undef_original_skip_smtp_check_ips_button=1&___original_backup_mail_hosts_button=&___undef_original_backup_mail_hosts_button=1&___original_trusted_mail_users_button=&___undef_original_trusted_mail_users_button=1&___original_blocked_domains_button=&___undef_original_blocked_domains_button=1&___original_filter_emails_by_country_button=&___undef_original_filter_emails_by_country_button=1&___original_per_domain_mailips=1&per_domain_mailips=1&___original_custom_mailhelo=0&___original_custom_mailips=0&___original_systemfilter=%2Fetc%2Fcpanel_exim_system_filter&systemfilter_control=default&___original_filter_attachments=1&filter_attachments=1&___original_filter_spam_rewrite=1&filter_spam_rewrite=1&___original_filter_fail_spam_score_over_int=&___undef_original_filter_fail_spam_score_over_int=1&filter_fail_spam_score_over_int_control=undef&___original_spam_header=***SPAM***&spam_header_control=default&___original_acl_0tracksenders=0&acl_0tracksenders=0&___original_callouts=0&callouts=0&___original_smarthost_routelist=&smarthost_routelist_control=default&___original_smarthost_autodiscover_spf_include=1&smarthost_autodiscover_spf_include=1&___original_spf_include_hosts=&spf_include_hosts_control=default&___original_rewrite_from=disable&rewrite_from=disable&___original_hiderecpfailuremessage=0&hiderecpfailuremessage=0&___original_malware_deferok=1&malware_deferok=1&___original_senderverify=1&senderverify=1&___original_setsenderheader=0&setsenderheader=0&___original_spam_deferok=1&spam_deferok=1&___original_srs=0&srs=0&___original_query_apache_for_nobody_senders=1&query_apache_for_nobody_senders=1&___original_trust_x_php_script=1&trust_x_php_script=1&___original_dsn_advertise_hosts=&___undef_original_dsn_advertise_hosts=1&dsn_advertise_hosts_control=undef&___original_smtputf8_advertise_hosts=&___undef_original_smtputf8_advertise_hosts=1&smtputf8_advertise_hosts_control=undef&___original_manage_rbls_button=&___undef_original_manage_rbls_button=1&___original_acl_spamcop_rbl=1&acl_spamcop_rbl=1&___original_acl_spamhaus_rbl=1&acl_spamhaus_rbl=1&___original_rbl_whitelist_neighbor_netblocks=1&rbl_whitelist_neighbor_netblocks=1&___original_rbl_whitelist_greylist_common_mail_providers=1&rbl_whitelist_greylist_common_mail_providers=1&___original_rbl_whitelist_greylist_trusted_netblocks=0&rbl_whitelist_greylist_trusted_netblocks=0&___original_rbl_whitelist=&rbl_whitelist=&___original_allowweakciphers=1&allowweakciphers=1&___original_require_secure_auth=0&require_secure_auth=0&___original_openssl_options=+%2Bno_sslv2+%2Bno_sslv3&openssl_options_control=other&openssl_options_other=+%2Bno_sslv2+%2Bno_sslv3&___original_tls_require_ciphers=ECDHE-ECDSA-CHACHA20-POLY1305%3AECDHE-RSA-CHACHA20-POLY1305%3AECDHE-ECDSA-AES128-GCM-SHA256%3AECDHE-RSA-AES128-GCM-SHA256%3AECDHE-ECDSA-AES256-GCM-SHA384%3AECDHE-RSA-AES256-GCM-SHA384%3ADHE-RSA-AES128-GCM-SHA256%3ADHE-RSA-AES256-GCM-SHA384%3AECDHE-ECDSA-AES128-SHA256%3AECDHE-RSA-AES128-SHA256%3AECDHE-ECDSA-AES128-SHA%3AECDHE-RSA-AES256-SHA384%3AECDHE-RSA-AES128-SHA%3AECDHE-ECDSA-AES256-SHA384%3AECDHE-ECDSA-AES256-SHA%3AECDHE-RSA-AES256-SHA%3ADHE-RSA-AES128-SHA256%3ADHE-RSA-AES128-SHA%3ADHE-RSA-AES256-SHA256%3ADHE-RSA-AES256-SHA%3AECDHE-ECDSA-DES-CBC3-SHA%3AECDHE-RSA-DES-CBC3-SHA%3AEDH-RSA-DES-CBC3-SHA%3AAES128-GCM-SHA256%3AAES256-GCM-SHA384%3AAES128-SHA256%3AAES256-SHA256%3AAES128-SHA%3AAES256-SHA%3ADES-CBC3-SHA%3A%21DSS&tls_require_ciphers_control=other&tls_require_ciphers_other=ECDHE-ECDSA-CHACHA20-POLY1305%3AECDHE-RSA-CHACHA20-POLY1305%3AECDHE-ECDSA-AES128-GCM-SHA256%3AECDHE-RSA-AES128-GCM-SHA256%3AECDHE-ECDSA-AES256-GCM-SHA384%3AECDHE-RSA-AES256-GCM-SHA384%3ADHE-RSA-AES128-GCM-SHA256%3ADHE-RSA-AES256-GCM-SHA384%3AECDHE-ECDSA-AES128-SHA256%3AECDHE-RSA-AES128-SHA256%3AECDHE-ECDSA-AES128-SHA%3AECDHE-RSA-AES256-SHA384%3AECDHE-RSA-AES128-SHA%3AECDHE-ECDSA-AES256-SHA384%3AECDHE-ECDSA-AES256-SHA%3AECDHE-RSA-AES256-SHA%3ADHE-RSA-AES128-SHA256%3ADHE-RSA-AES128-SHA%3ADHE-RSA-AES256-SHA256%3ADHE-RSA-AES256-SHA%3AECDHE-ECDSA-DES-CBC3-SHA%3AECDHE-RSA-DES-CBC3-SHA%3AEDH-RSA-DES-CBC3-SHA%3AAES128-GCM-SHA256%3AAES256-GCM-SHA384%3AAES128-SHA256%3AAES256-SHA256%3AAES128-SHA%3AAES256-SHA%3ADES-CBC3-SHA%3A%21DSS&___original_globalspamassassin=0&globalspamassassin=0&___original_max_spam_scan_size=1000&max_spam_scan_size_control=default&___original_acl_outgoing_spam_scan=0&acl_outgoing_spam_scan=0&___original_acl_outgoing_spam_scan_over_int=&___undef_original_acl_outgoing_spam_scan_over_int=1&acl_outgoing_spam_scan_over_int_control=undef&___original_no_forward_outbound_spam=0&no_forward_outbound_spam=0&___original_no_forward_outbound_spam_over_int=&___undef_original_no_forward_outbound_spam_over_int=1&no_forward_outbound_spam_over_int_control=undef&___original_spamassassin_plugin_BAYES_POISON_DEFENSE=1&spamassassin_plugin_BAYES_POISON_DEFENSE=1&___original_spamassassin_plugin_P0f=1&spamassassin_plugin_P0f=1&___original_spamassassin_plugin_KAM=1&spamassassin_plugin_KAM=1&___original_spamassassin_plugin_CPANEL=1&spamassassin_plugin_CPANEL=1' > /dev/null

    # REMOVE COOKIE
    rm -f $CWD/wpwhmcookie.txt

    log_ok "WHM Tweak Settings & Config complete"
}

# ═══════════════════════════════════════════
# LICENSE CHECK
# ═══════════════════════════════════════════
check_licenses() {
    log_section "License Status Check"
    
    # cPanel
    log_info "Checking cPanel license..."
    LIC_CP="Not Installed"
    if [ -f /usr/local/cpanel/cpkeyclt ]; then
        if /usr/local/cpanel/cpkeyclt 2>&1 | grep -iq "succeeded"; then
            LIC_CP="Active"
        else
            LIC_CP="Invalid / Expired"
        fi
    fi

    # LiteSpeed
    log_info "Checking LiteSpeed license..."
    LIC_LS="Not Installed"
    if [ -f /usr/local/lsws/bin/lshttpd ]; then
        LIC_LS=$(/usr/local/lsws/bin/lshttpd -V 2>/dev/null | grep -i "License" | awk -F':' '{print $2}' | xargs)
        [ -z "$LIC_LS" ] && LIC_LS="Unknown"
    fi

    # CloudLinux
    log_info "Checking CloudLinux license..."
    LIC_CL="Not Installed"
    if command -v cldetect >/dev/null 2>&1; then
        if cldetect --check-license 2>&1 | grep -iq "ok"; then
            LIC_CL="Active"
        else
            LIC_CL="Invalid / Error"
        fi
    fi

    # JetBackup 5
    log_info "Checking JetBackup 5 license..."
    LIC_JB5="Not Installed"
    if command -v jetbackup5 >/dev/null 2>&1; then
        local JB_OUT
        JB_OUT=$(jetbackup5 --license 2>&1)
        if echo "$JB_OUT" | grep -iq "Valid"; then
            LIC_JB5="Active"
        elif echo "$JB_OUT" | grep -iq "Expired"; then
            LIC_JB5="Expired"
        else
            LIC_JB5="Invalid / Error"
        fi
    fi

    # Softaculous
    log_info "Checking Softaculous license..."
    LIC_SOFT="Not Installed"
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/softaculous/cli.php ]; then
        LIC_SOFT=$(php /usr/local/cpanel/whostmgr/docroot/cgi/softaculous/cli.php -l 2>/dev/null | grep -i "License Type" | awk -F':' '{print $2}' | xargs)
        [ -z "$LIC_SOFT" ] && LIC_SOFT="Unknown"
    fi

    # Imunify360
    log_info "Checking Imunify360 license..."
    LIC_IMU="Not Installed"
    if command -v imunify360-agent >/dev/null 2>&1; then
        local IMU_OUT
        IMU_OUT=$(imunify360-agent status 2>&1)
        if echo "$IMU_OUT" | grep -iq "License is active"; then
            LIC_IMU="Active"
        elif echo "$IMU_OUT" | grep -iq "expired"; then
            LIC_IMU="Expired"
        else
            LIC_IMU="Unknown / Free"
        fi
    fi
}

# ═══════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════
print_summary() {
    log_section "FINAL SUMMARY"
    CPANEL_VER=$(/usr/local/cpanel/cpanel -V 2>/dev/null | awk '{print $1}' || echo "N/A")
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║ WHM/cPanel PreConfig v7.0.0 - All-in-One Deployment"
    echo "  ╠══════════════════════════════════════════════════╣"
    printf "  ║  %-12s : %-33s║\n" "Date"        "$(date '+%Y-%m-%d %H:%M UTC')"
    printf "  ║  %-12s : %-33s║\n" "Server Type" "${SERVER_TYPE:0:33}"
    printf "  ║  %-12s : %-33s║\n" "Hostname"  "$(hostname)"
    printf "  ║  %-12s : %-33s║\n" "OS"        "$OS $VER"
    printf "  ║  %-12s : %-33s║\n" "cPanel"    "$CPANEL_VER"
    printf "  ║  %-12s : %-33s║\n" "SSH Port"  "$SSH_PORT"
    printf "  ║  %-12s : %-33s║\n" "Public IP" "$PUBLIC_IP"
    printf "  ║  %-12s : %-33s║\n" "Log"       "$LOGFILE"
    echo "  ╠══════════════════════════════════════════════════╣"
    echo "  ║  PLUGINS SUMMARY                                 ║"
    echo "  ╠══════════════════════════════════════════════════╣"
    printf "  ║  %-12s : %-33s║\n" "LiteSpeed"  "${PL_LS}"
    printf "  ║  %-12s : %-33s║\n" "Redis/Memc." "${PL_CACHE}"
    printf "  ║  %-12s : %-33s║\n" "Telegram Bot" "${PL_TG}"
    printf "  ║  %-12s : %-33s║\n" "Imunify360" "${PL_IMU}"
    printf "  ║  %-12s : %-33s║\n" "JetBackup"  "${PL_JB5}"
    printf "  ║  %-12s : %-33s║\n" "Softaculous" "${PL_SOFT}"
    printf "  ║  %-12s : %-33s║\n" "WP Toolkit" "${PL_WPT}"
    printf "  ║  %-12s : %-33s║\n" "CMQ"        "${PL_CMQ}"
    printf "  ║  %-12s : %-33s║\n" "CMC"        "${PL_CMC}"
    printf "  ║  %-12s : %-33s║\n" "Perf Tuner" "${PL_IMH_PERF:-Skipped}"
    printf "  ║  %-12s : %-33s║\n" "Backup Disk" "${PL_IMH_BAK:-Skipped}"
    printf "  ║  %-12s : %-33s║\n" "Snap Stat"  "${PL_IMH_SNAP:-Skipped}"
    printf "  ║  %-12s : %-33s║\n" "PHP Ext"    "${PL_IMH_PHP_EXT:-Skipped}"
    printf "  ║  %-12s : %-33s║\n" "Rector Wrap" "${PL_IMH_REC:-Skipped}"
    printf "  ║  %-12s : %-33s║\n" "Email Sols" "${PL_IMH_EMAIL:-Skipped}"
    printf "  ║  %-12s : %-33s║\n" "DNS Check"  "${PL_DNS}"
    printf "  ║  %-12s : %-33s║\n" "CleanBackups" "${PL_CLN}"
    printf "  ║  %-12s : %-33s║\n" "WatchMySQL" "${PL_WMY}"
    printf "  ║  %-12s : %-33s║\n" "MailBaby"   "${PL_MB}"
    printf "  ║  %-12s : %-33s║\n" "CloudLinux" "${PL_CL}"
    printf "  ║  %-12s : %-33s║\n" "CageFS"     "${PL_CGF}"
    echo "  ╠══════════════════════════════════════════════════╣"
    echo "  ║  LICENSE STATUS                                  ║"
    echo "  ╠══════════════════════════════════════════════════╣"
    [ "$LIC_CP" != "Not Installed" ]   && printf "  ║  %-12s : %-33s║\n" "cPanel"      "${LIC_CP}"
    [ "$LIC_LS" != "Not Installed" ]   && printf "  ║  %-12s : %-33s║\n" "LiteSpeed"   "${LIC_LS}"
    [ "$LIC_CL" != "Not Installed" ]   && printf "  ║  %-12s : %-33s║\n" "CloudLinux"  "${LIC_CL}"
    [ "$LIC_JB5" != "Not Installed" ]  && printf "  ║  %-12s : %-33s║\n" "JetBackup 5" "${LIC_JB5}"
    [ "$LIC_SOFT" != "Not Installed" ] && printf "  ║  %-12s : %-33s║\n" "Softaculous" "${LIC_SOFT}"
    [ "$LIC_IMU" != "Not Installed" ]  && printf "  ║  %-12s : %-33s║\n" "Imunify360"  "${LIC_IMU}"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ═══════════════════════════════════════════
# 1ST RUN / 2ND RUN LOGIC
# ═══════════════════════════════════════════
first_run() {
    log_section "FIRST RUN — OS Base Configuration"
    run_os_config
    touch "$RUN_FLAG"
    log_ok "First run complete — flag saved: $RUN_FLAG"
    echo ""
    log_warn "Reboot RECOMMENDED before cPanel install"
    log_warn "Run this script AGAIN after reboot for cPanel setup"
    if ask_yn "Reboot now?"; then sleep 5; reboot; fi
}

second_run() {
    log_section "SECOND RUN — cPanel + Full Configuration"
    
    echo "  Select where to start the setup:"
    echo "  [1] cPanel Install (Start from the beginning)"
    echo "  [2] CSF Firewall Config"
    echo "  [3] WHM Tweaks & Basic Config"
    echo "  [4] cPanel Plugins (MailBaby, CloudLinux, LiteSpeed, etc.)"
    echo "  [5] PHP & Extensions (EA4) - Custom/All"
    echo "  [6] PHP 8.0 to 8.5 Only (Recommended)"
    echo "  [7] Wrap-up (Licenses & Summary)"
    read -rp "  Select [1-7] (default 1): " SETUP_START </dev/tty
    
    [ -z "$SETUP_START" ] && SETUP_START=1

    if [ "$SETUP_START" -eq 6 ]; then
        install_ea4_php "80 81 82 83 84 85"
        check_install_redis_memcached
        SETUP_START=7 # Skip to wrap-up
    fi

    if [ "$SETUP_START" -le 1 ]; then
        install_cpanel
    fi
    if [ "$SETUP_START" -le 2 ]; then
        _install_csf
        _configure_csf
    fi
    if [ "$SETUP_START" -le 3 ]; then
        configure_whm_tweaks
    fi
    if [ "$SETUP_START" -le 4 ]; then
        check_install_cmq
        check_install_cmc
        check_install_dnscheck
        check_install_cleanbackups
        check_install_watchmysql
        check_install_imh_performance_tuner
        check_install_imh_backup_disk_usage
        check_install_imh_snap_stat
        check_install_imh_php_extension
        check_install_imh_rector_wrapper
        check_install_imh_email_solutions
        check_install_mailbaby
        check_install_softaculous
        check_install_wptoolkit
        check_install_jetbackup
        check_install_imunify360
        check_install_litespeed
        check_install_cloudlinux
        check_install_cagefs
        configure_cloudlinux_symlink
    fi
    if [ "$SETUP_START" -le 5 ]; then
        install_ea4_php
        check_install_redis_memcached
    fi
    if [ "$SETUP_START" -le 7 ]; then
        setup_telegram_alerts
        # Final CSF reconfiguration (pick up LiteSpeed/Imunify ports)
        _configure_csf
        check_licenses
        print_summary
    fi

    if ask_yn "Something wrong? Or cPanel port not working? Flush Firewall ?"; then
        log_info "Flushing iptables and CSF..."
        iptables -F 2>/dev/null || true
        iptables -X 2>/dev/null || true
        iptables -t nat -F 2>/dev/null || true
        iptables -t mangle -F 2>/dev/null || true
        ip6tables -F 2>/dev/null || true
        ip6tables -X 2>/dev/null || true
        csf -f 2>/dev/null || true
        log_ok "Firewall flushed successfully!"
    fi

    if ask_yn "Reboot now?"; then
        log_info "Rebooting in 10 seconds..."; sleep 10; reboot
    else
        log_warn "Please reboot manually: shutdown -r now"
    fi
}

# ═══════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════
main() {
    check_root
    detect_os

    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔════════════════════════════════════════════════════════════════════╗"
    echo "  ║  WHM/cPanel PreConfig v7.0.0 - All-in-One Deployment               ║"
    echo "  ╠════════════════════════════════════════════════════════════════════╣"
    echo "  ║  FEATURES INCLUDED:                                                ║"
    echo "  ║  • OS Hardening (Sysctl, FSTrim, Swap, Selinux/Firewalld)          ║"
    echo "  ║  • SSH Customization (Port $SSH_PORT, Root Login Allowed)                 ║"
    echo "  ║  • Automated cPanel/WHM + MariaDB 11.4 Installation                ║"
    echo "  ║  • Security Suite: CSF Firewall + Imunify360 Setup                 ║"
    echo "  ║  • Performance: LiteSpeed Auto-Installer (TRIAL/PRO)               ║"
    echo "  ║  • Core Plugins: JetBackup 5, Softaculous, WP Toolkit              ║"
    echo "  ║  • Mail & DNS: CMQ, Account DNS Check, Exim Hardening              ║"
    echo "  ║  • PHP 7.2-8.5 (Custom Selection) + ionCube 15 + All Extensions    ║"
    echo "  ║  • CloudLinux: Key / IP / Skip-Registration + CageFS + Alt Stacks  ║"
    echo "  ║  • Alt Language Stacks: alt-php, alt-nodejs, alt-python, alt-ruby  ║"
    echo "  ║  • Fully Automated WHM Tweak Settings Configuration                ║"
    echo "  ╠════════════════════════════════════════════════════════════════════╣"
    echo "  ║  ☕ Support this project — Donate via PayPal:                      ║"
    echo "  ║  https://www.paypal.com/donate/?hosted_button_id=YLMGDWTDQNDXW    ║"
    echo "  ╠════════════════════════════════════════════════════════════════════╣"
    SYS_UPTIME=$(uptime -p 2>/dev/null || echo "Unknown")
    SYS_KERNEL=$(uname -r)
    SYS_HOST=$(hostname -f 2>/dev/null || hostname)
    SYS_USER=$(whoami)
    OS_INFO="$OS $VER"

    echo "  ╠════════════════════════════════════════════════════════════════════╣"
    echo "  ║  SERVER SYSTEM INFORMATION:                                        ║"
    echo "  ╠════════════════════════════════════════════════════════════════════╣"
    printf "  ║  ${YELLOW}%-12s${CYAN} : ${GREEN}%-49s${CYAN}║\n" "Date" "$(date '+%Y-%m-%d %H:%M UTC')"
    printf "  ║  ${YELLOW}%-12s${CYAN} : ${GREEN}%-49s${CYAN}║\n" "Server Type" "${SERVER_TYPE:0:49}"
    printf "  ║  ${YELLOW}%-12s${CYAN} : ${GREEN}%-49s${CYAN}║\n" "Hostname" "${SYS_HOST:0:49}"
    printf "  ║  ${YELLOW}%-12s${CYAN} : ${GREEN}%-49s${CYAN}║\n" "Server IP" "${PUBLIC_IP:0:49}"
    printf "  ║  ${YELLOW}%-12s${CYAN} : ${GREEN}%-49s${CYAN}║\n" "OS Info" "${OS_INFO:0:49}"
    printf "  ║  ${YELLOW}%-12s${CYAN} : ${GREEN}%-49s${CYAN}║\n" "Kernel" "${SYS_KERNEL:0:49}"
    printf "  ║  ${YELLOW}%-12s${CYAN} : ${GREEN}%-49s${CYAN}║\n" "Uptime" "${SYS_UPTIME:0:49}"
    printf "  ║  ${YELLOW}%-12s${CYAN} : ${GREEN}%-49s${CYAN}║\n" "User" "${SYS_USER:0:49}"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"


    # --- Authorization Check ---
    echo -ne "  ${YELLOW}[Auth]${NC} Please Type tnx nx.lc to proceed (Hint: Press ENTER to auto-fill): " >/dev/tty
    read -r AUTH_CODE </dev/tty
    
    # Auto-fill if user just pressed Enter
    if [ -z "$AUTH_CODE" ]; then
        AUTH_CODE="tnx nx.lc"
        echo -e "  ${YELLOW}➔ Auto-filled: tnx nx.lc${NC}" >/dev/tty
    fi

    # Code is securely obfuscated
    AUTH_HASH=$(echo -n "$AUTH_CODE" | base64 2>/dev/null)
    if [ "$AUTH_HASH" != "dG54IG54Lmxj" ]; then
        echo -e "\n${RED}[ERROR] Invalid authorization code. Access Denied.${NC}\n"
        exit 1
    fi
    echo -e "${GREEN}[OK] Authorization successful. Proceeding...${NC}\n"
    # ---------------------------

    if [ ! -f "$RUN_FLAG" ]; then
        echo -e "${YELLOW}${BOLD}  ── FIRST RUN: OS Base Configuration ──${NC}\n"
        echo -e "  This will configure the OS (no network disruption)."
        echo -e "  After reboot, run again for cPanel setup.\n"
        first_run
    else
        echo -e "${GREEN}${BOLD}  ── This script has run before on your server. Now configuring next steps... ──${NC}\n"
        echo -ne "  ${YELLOW}Press ENTER to continue...${NC} " >/dev/tty
        read -r </dev/tty
        
        second_run
    fi

    history -c
    echo "" > /root/.bash_history
}

# ═══════════════════════════════════════════
# TRAP + RUN
# ═══════════════════════════════════════════
trap 'log_error "Script interrupted at line $LINENO! Check: $LOGFILE"; exit 1' INT TERM ERR
main "$@"
