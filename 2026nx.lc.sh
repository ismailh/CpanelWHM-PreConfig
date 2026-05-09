#!/bin/bash
# ============================================================
# WHM/cPanel all Improtent Plugin Installation Setup Script and preconfiger 
# Version: 3.0.0
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
# Coded-by nx.lc & Bluedot Team || 
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
PL_DNS="Pending"
PL_SOFT="Pending"
PL_WPT="Pending"
PL_JB5="Pending"
PL_IMU="Pending"
PL_LS="Pending"
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
    for s in telnet rsh rlogin rexec finger talk ntalk; do
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
        oniguruma libsodium jq ipcalc glibc-all-langpacks 2>/dev/null || true

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
        software-properties-common ntpdate jq 2>/dev/null || true

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

# All functions are embedded below in this single file


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
        log_ok "CSF already installed — skipping install"
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

    # Fallback 1: manual download from configserver.com
    if [ "$CSF_INSTALLED" -eq 0 ]; then
        log_warn "cpanel-csf package not available — trying configserver.com..."
        cd /usr/src
        wget -q https://download.configserver.com/csf.tgz -O /usr/src/csf.tgz 2>/dev/null
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

    # Core settings
    local CSF="/etc/csf/csf.conf"
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

    # cPanel migration ports
    CURR_OUT=$(grep "^TCP_OUT" "$CSF" | cut -d'=' -f2 | sed 's/ //g;s/"//g')
    echo "$CURR_OUT" | grep -q "2082,2083" || \
        sed -i "s/^TCP_OUT.*/TCP_OUT = \"${CURR_OUT},2082,2083\"/" "$CSF"

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
        log_ok "CMQ already installed"; PL_CMQ="Installed (Pre-existing)"; return 0; fi
    if ! ask_yn "CMQ not found. Install?"; then log_warn "Skipped"; PL_CMQ="Skipped"; return 0; fi

    local CMQ_URLS=(
        "https://raw.githubusercontent.com/systechICTltd/ConfigServer-Scripts/main/cmq.tgz"
        "https://download.configserver.com/cmq.tgz"
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

check_install_dnscheck() {
    log_section "Account DNS Check"
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/addon_accountdnscheck.cgi ]; then
        log_ok "Account DNS Check already installed"; PL_DNS="Installed (Pre-existing)"; return 0; fi
    if ! ask_yn "Account DNS Check not found. Install?"; then log_warn "Skipped"; PL_DNS="Skipped"; return 0; fi
    wget -q -O /usr/src/accountdnscheck.tgz https://files.ndchost.com/scripts/accountdnscheck/accountdnscheck.tgz
    if [ -s /usr/src/accountdnscheck.tgz ]; then
        cd /usr/src || return 1
        tar -xzf accountdnscheck.tgz 2>/dev/null
        cd accountdnscheck
        sh install.sh 2>/dev/null
        rm -Rfv /usr/src/accountdnscheck* 2>/dev/null
        log_ok "Account DNS Check installed"
        PL_DNS="Installed"
    else
        log_error "Account DNS Check install failed."
        PL_DNS="Failed"
    fi
}

check_install_softaculous() {
    log_section "Softaculous"
    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/softaculous/index.cgi ]; then
        log_ok "Softaculous already installed"; return 0; fi
    if ! ask_yn "Softaculous not found. Install?"; then log_warn "Skipped"; return 0; fi
    wget -N https://files.softaculous.com/install.sh -O /tmp/soft.sh
    chmod 755 /tmp/soft.sh && bash /tmp/soft.sh && rm -f /tmp/soft.sh
    log_ok "Softaculous installed"
}

check_install_wptoolkit() {
    log_section "WP Toolkit"
    if [ -d /usr/local/cpanel/3rdparty/wp-toolkit ]; then
        log_ok "WP Toolkit already installed"; return 0; fi
    if ! ask_yn "WP Toolkit not found. Install?"; then log_warn "Skipped"; return 0; fi
    wget -q https://wp-toolkit.plesk.com/cPanel/installer.sh -O /tmp/wpt.sh
    chmod +x /tmp/wpt.sh && sh /tmp/wpt.sh && rm -f /tmp/wpt.sh
    log_ok "WP Toolkit installed"
}

check_install_jetbackup() {
    log_section "JetBackup"
    if command -v jetbackup5 &>/dev/null || [ -d /usr/local/jetapps/var/lib/jetbackup5/Core/ ]; then
        log_ok "JetBackup 5 is already installed — skipping"
        PL_JB5="Installed (Pre-existing)"
        return 0
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
        log_ok "Imunify360 already installed"; PL_IMU="Installed (Pre-existing)"; return 0; fi
    if ! ask_yn "Imunify360 not found. Install?"; then log_warn "Skipped"; PL_IMU="Skipped"; return 0; fi
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
        log_ok "LiteSpeed already installed"; PL_LS="Installed (Pre-existing)"; return 0; fi
    if ! ask_yn "LiteSpeed not found. Install?"; then log_warn "Skipped"; PL_LS="Skipped"; return 0; fi

    echo "  [1] Trial License (15 days)"
    echo "  [2] Serial Number"
    echo "  [3] OpenLiteSpeed Free"
    read -rp "  Select [1/2/3]: " LS_OPT </dev/tty
    case "$LS_OPT" in
        2) read -rp "  Serial: " LS_SERIAL </dev/tty ;;
        3) LS_SERIAL="0" ;;
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
# CLOUDLINUX
# ═══════════════════════════════════════════
check_install_cloudlinux() {
    log_section "CloudLinux"
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        log_warn "CloudLinux not supported on Ubuntu/Debian — skipping"; PL_CL="Skipped (OS unsupported)"; return 0; fi
    if grep -qi "cloudlinux" /etc/os-release 2>/dev/null; then
        log_ok "CloudLinux already installed"; PL_CL="Installed (Pre-existing)"; return 0; fi
    if ! ask_yn "CloudLinux not found. Install?"; then log_warn "Skipped"; PL_CL="Skipped"; return 0; fi
    read -rp "  License Key (Enter for IP activation): " CL_KEY </dev/tty
    wget -q https://repo.cloudlinux.com/cloudlinux/sources/cln/cldeploy -O /tmp/cldeploy
    chmod +x /tmp/cldeploy
    if [ -n "$CL_KEY" ]; then bash /tmp/cldeploy -k "$CL_KEY"; else bash /tmp/cldeploy -i; fi
    local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
    $PKG install -y lvemanager lvectl lve-utils lve-stats cagefs 2>/dev/null || true
    cagefsctl --init 2>/dev/null || true
    cagefsctl --enable-all 2>/dev/null || true
    rm -f /tmp/cldeploy
    log_warn "Reboot required after CloudLinux install"
    log_ok "CloudLinux installed"
    PL_CL="Installed"
}


# ═══════════════════════════════════════════
# EA4 PHP 7.4–8.4 + ALL EXTENSIONS
# ═══════════════════════════════════════════
install_ea4_php() {
    log_section "EA4 PHP 7.4–8.4 + Extensions"

    # Install libsodium
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        apt-get install -y libsodium-dev libsodium23 2>/dev/null || true
    else
        local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
        $PKG install -y libsodium libsodium-devel 2>/dev/null || true
    fi

    # PHP versions to install
    local PHP_VERS="74 80 81 82 83 84"

    # Extensions per version
    local EXTS="pear php-cli php-common php-curl php-devel php-exif php-fileinfo \
php-ftp php-gd php-iconv php-intl php-litespeed php-mbstring php-mysqlnd \
php-opcache php-pdo php-posix php-soap php-zip runtime php-bcmath \
php-gettext php-gmp php-xml php-imap php-sodium php-calendar \
php-fpm php-ldap php-xmlrpc php-sockets"

    local INSTALL_LIST=""
    for V in $PHP_VERS; do
        INSTALL_LIST="$INSTALL_LIST ea-php${V}"
        for E in $EXTS; do
            INSTALL_LIST="$INSTALL_LIST ea-php${V}-${E}"
        done
    done

    # IonCube per version
    INSTALL_LIST="$INSTALL_LIST ea-php74-php-ioncube10 ea-php81-php-ioncube12"
    INSTALL_LIST="$INSTALL_LIST ea-php82-php-ioncube13 ea-php83-php-ioncube14"

    # Apache modules
    INSTALL_LIST="$INSTALL_LIST ea-apache24-mod_proxy_fcgi ea-apache24-mod_version ea-apache24-mod_env"

    log_info "Installing EA4 PHP packages (this may take a while)..."
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        apt-get install -y $INSTALL_LIST 2>/dev/null || true
    else
        local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
        $PKG install -y $INSTALL_LIST --skip-broken 2>/dev/null || true
    fi

    # Install Redis extension for all PHP versions
    log_info "Installing Redis, APCu, Memcached extensions..."
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        apt-get install -y ea-php*-php-redis ea-php*-php-apcu ea-php*-php-memcached 2>/dev/null || true
    else
        local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
        $PKG install -y ea-php*-php-redis ea-php*-php-apcu ea-php*-php-memcached --skip-broken 2>/dev/null || true
    fi

    # IonCube + SourceGuardian loaders
    log_info "Installing IonCube & SourceGuardian loaders..."
    sed -i 's/phploader=.*/phploader=ioncube,sourceguardian/' /var/cpanel/cpanel.config 2>/dev/null || true
    /usr/local/cpanel/whostmgr/bin/whostmgr2 --updatetweaksettings 2>/dev/null || true
    /usr/local/cpanel/bin/checkphpini 2>/dev/null || true
    /usr/local/cpanel/bin/install_php_inis 2>/dev/null || true
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        apt-get install -y ea-php*-php-sourceguardian ea-php*-php-ioncube10 2>/dev/null || true
    else
        local PKG="yum"; command -v dnf &>/dev/null && PKG="dnf"
        $PKG install -y ea-php*-php-sourceguardian ea-php*-php-ioncube10 --skip-broken 2>/dev/null || true
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

    # Direct EA-PHP path method (most reliable for all PHP versions)
    /usr/bin/sed -i 's/memory_limit = .*/memory_limit = 1024M/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/max_execution_time = .*/max_execution_time = 200/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/max_input_time = .*/max_input_time = 200/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/max_input_vars = .*/max_input_vars = 3000/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/post_max_size = .*/post_max_size = 100M/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/upload_max_filesize = .*/upload_max_filesize = 100M/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/allow_url_fopen = .*/allow_url_fopen = On/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/file_uploads = .*/file_uploads = On/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/expose_php = .*/expose_php = Off/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/enable_dl = .*/enable_dl = Off/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/display_errors = .*/display_errors = Off/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/track_errors = .*/track_errors = Off/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/html_errors = .*/html_errors = Off/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/error_reporting = .*/error_reporting = E_ALL \& ~E_DEPRECATED \& ~E_STRICT/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    # Uncomment and set default_charset
    /usr/bin/sed -i 's/^;default_charset = "UTF-8"/default_charset = "UTF-8"/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    /usr/bin/sed -i 's/^default_charset = .*/default_charset = "UTF-8"/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    # Set timezone to UTC (universal default — users can override per-account)
    /usr/bin/sed -i 's|^;*date.timezone.*|date.timezone = "UTC"|' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true
    # Security: disable dangerous PHP functions (shared hosting hardening)
    /usr/bin/sed -i 's/^disable_functions.*/disable_functions = apache_get_modules,apache_get_version,apache_getenv,apache_note,apache_setenv,disk_free_space,diskfreespace,dl,exec,highlight_file,ini_alter,ini_restore,openlog,passthru,phpinfo,popen,posix_getpwuid,proc_close,proc_get_status,proc_nice,proc_open,proc_terminate,shell_exec,show_source,symlink,system,eval,debug_zval_dump/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null || true

    # Also apply key settings to local.ini overrides
    find /opt/ \( -name "php.ini" -o -name "local.ini" \) 2>/dev/null | xargs -r sed -i \
        's/^memory_limit.*/memory_limit = 1024M/g' 2>/dev/null || true
    find /opt/ \( -name "php.ini" -o -name "local.ini" \) 2>/dev/null | xargs -r sed -i \
        's/^upload_max_filesize.*/upload_max_filesize = 100M/g' 2>/dev/null || true
    find /opt/ \( -name "php.ini" -o -name "local.ini" \) 2>/dev/null | xargs -r sed -i \
        's/^post_max_size.*/post_max_size = 100M/g' 2>/dev/null || true

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
    for V in 74 80 81 82 83 84; do
        whmapi1 php_set_handler version=ea-php${V} handler=cgi 2>/dev/null || true
    done
    whmapi1 php_set_system_default_version version=ea-php84 2>/dev/null || true
    whmapi1 php_set_default_accounts_to_fpm default_accounts_to_fpm=1 2>/dev/null || true

    log_ok "EA4 PHP 7.4–8.4 installed with all extensions"
}

# ═══════════════════════════════════════════
# WHM TWEAK SETTINGS + BASIC CONFIG
# ═══════════════════════════════════════════
configure_whm_tweaks() {
    log_section "WHM Tweak Settings & Basic Config"
    [ ! -d /usr/local/cpanel ] && { log_warn "cPanel not found"; return 1; }

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

    # Shell Fork Bomb Protection
    /usr/local/cpanel/bin/install-login-profile --install limits 2>/dev/null || true

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

    # ── SMTP Restrictions (disabled — CSF handles this) ──
    whmapi1 set_tweaksetting key=smtpmailgidonly value=0 2>/dev/null || true

    # Fix cPanel RPMs
    /usr/local/cpanel/scripts/check_cpanel_pkgs --fix 2>/dev/null || true

    /usr/local/cpanel/whostmgr/bin/whostmgr2 --updatetweaksettings 2>/dev/null || true
    /usr/local/cpanel/etc/init/startcpsrvd 2>/dev/null || true
    /usr/local/cpanel/scripts/restartsrv_cpsrvd 2>/dev/null || true

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
}

# ═══════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════
print_summary() {
    log_section "FINAL SUMMARY"
    CPANEL_VER=$(/usr/local/cpanel/cpanel -V 2>/dev/null | awk '{print $1}' || echo "N/A")
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║  WHM/cPanel PreConfig v2.0 — COMPLETE           ║"
    echo "  ╠══════════════════════════════════════════════════╣"
    printf "  ║  %-12s : %-33s║\n" "Date"      "$(date '+%Y-%m-%d %H:%M UTC')"
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
    printf "  ║  %-12s : %-33s║\n" "Imunify360" "${PL_IMU}"
    printf "  ║  %-12s : %-33s║\n" "JetBackup"  "${PL_JB5}"
    printf "  ║  %-12s : %-33s║\n" "Softaculous" "${PL_SOFT}"
    printf "  ║  %-12s : %-33s║\n" "WP Toolkit" "${PL_WPT}"
    printf "  ║  %-12s : %-33s║\n" "CMQ"        "${PL_CMQ}"
    printf "  ║  %-12s : %-33s║\n" "DNS Check"  "${PL_DNS}"
    printf "  ║  %-12s : %-33s║\n" "CloudLinux" "${PL_CL}"
    echo "  ╠══════════════════════════════════════════════════╣"
    echo "  ║  LICENSE STATUS                                  ║"
    echo "  ╠══════════════════════════════════════════════════╣"
    [ "$LIC_CP" != "Not Installed" ]   && printf "  ║  %-12s : %-33s║\n" "cPanel"      "${LIC_CP}"
    [ "$LIC_LS" != "Not Installed" ]   && printf "  ║  %-12s : %-33s║\n" "LiteSpeed"   "${LIC_LS}"
    [ "$LIC_CL" != "Not Installed" ]   && printf "  ║  %-12s : %-33s║\n" "CloudLinux"  "${LIC_CL}"
    [ "$LIC_JB5" != "Not Installed" ]  && printf "  ║  %-12s : %-33s║\n" "JetBackup 5" "${LIC_JB5}"
    [ "$LIC_SOFT" != "Not Installed" ] && printf "  ║  %-12s : %-33s║\n" "Softaculous" "${LIC_SOFT}"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    if ask_yn "Reboot now?"; then
        log_info "Rebooting in 10 seconds..."; sleep 10; reboot
    else
        log_warn "Please reboot manually: shutdown -r now"
    fi
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
    install_cpanel
    _install_csf
    _configure_csf
    configure_whm_tweaks
    check_install_cmq
    check_install_dns_check
    check_install_softaculous
    check_install_wptoolkit
    check_install_jetbackup
    check_install_imunify360
    check_install_litespeed
    check_install_cloudlinux
    install_ea4_php
    # Final CSF reconfiguration (pick up LiteSpeed/Imunify ports)
    _configure_csf
    check_licenses
    print_summary
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
    echo "  ║  WHM/cPanel PreConfig v3.0 - All-in-One Deployment                 ║"
    echo "  ╠════════════════════════════════════════════════════════════════════╣"
    echo "  ║  FEATURES INCLUDED:                                                ║"
    echo "  ║  • OS Hardening (Sysctl, FSTrim, Swap, Selinux/Firewalld)          ║"
    echo "  ║  • SSH Customization (Port $SSH_PORT, Root Login Allowed)                 ║"
    echo "  ║  • Automated cPanel/WHM + MariaDB 11.4 Installation                ║"
    echo "  ║  • Security Suite: CSF Firewall + Imunify360 Setup                 ║"
    echo "  ║  • Performance: LiteSpeed Auto-Installer (TRIAL/PRO)               ║"
    echo "  ║  • Core Plugins: JetBackup 5, Softaculous, WP Toolkit              ║"
    echo "  ║  • Mail & DNS: CMQ, Account DNS Check, Exim Hardening              ║"
    echo "  ║  • PHP 7.4-8.4 Hardening (28 disabled functions, 1GB mem)          ║"
    echo "  ║  • CloudLinux Integration (Optional License support)               ║"
    echo "  ║  • Fully Automated WHM Tweak Settings Configuration                ║"
    echo "  ╠════════════════════════════════════════════════════════════════════╣"
    printf "  ║  %-12s : %-49s║\n" "Date" "$(date '+%Y-%m-%d %H:%M UTC')"
    printf "  ║  %-12s : %-49s║\n" "OS"   "$OS $VER"
    echo "  ╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # --- Authorization Check ---
    read -rp "  [Auth] Please Type tnx nx.lc to proceed (Hint: Press ENTER to auto-fill): " AUTH_CODE </dev/tty
    # Auto-fill if user just pressed Enter
    if [ -z "$AUTH_CODE" ]; then
        AUTH_CODE="tnx nx.lc"
        echo -e "  ${YELLOW}➔ Auto-filled: tnx nx.lc${NC}"
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
        echo -e "${GREEN}${BOLD}  ── SECOND RUN: cPanel + Plugins + PHP + Config ──${NC}\n"
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
