#!/bin/bash
# ============================================================
# WHM/cPanel Pre-Configuration Script
# Version  : 1.0.0# Date     : 2026-05-07 07:26 UTC
# Ref      : 
#             
#             
#             
# OS       : CentOS 7 | AlmaLinux 8/9 | Rocky 8/9
#            Ubuntu 20.04/22.04 | Debian 11/12
#
# FLOW:
#   1st Run → OS Detection + OS Base Config
#   2nd Run → cPanel Install → then:
#             ├─ CSF (install + configure)
#             ├─ cPanel Plugins (ask if missing):
#             │    ├─ CMQ
#             │    ├─ Account DNS Check
#             │    ├─ Softaculous
#             │    ├─ WP Toolkit
#             │    ├─ JetBackup 4 / 5
#             │    └─ Imunify360
#             ├─ LiteSpeed   (ask if not installed)
#             └─ CloudLinux  (ask if not installed)
#
# ⚠️  OUTDATED FLAGS (as of May 2026):
#     CentOS 7 EOL Jun 2024    → AlmaLinux 9 / Rocky 9
#     Ubuntu 18.04 EOL         → Ubuntu 20.04 / 22.04
#     Debian 10 EOL            → Debian 11 / 12
#     PHP 7.x / 8.0 EOL        → PHP 8.2 / 8.3 / 8.4
#     MySQL 5.7 EOL Oct 2023   → MariaDB 10.11 LTS
#     MySQL 8.0 EOL Apr 2026   → MySQL 8.4 LTS
#     JetBackup 4 EOL          → JetBackup 5
#     LiteSpeed 5.x            → LiteSpeed 6.x (HTTP/3)
#     TLS 1.0 / 1.1            → TLS 1.2 / 1.3 only
#     mod_php / suPHP          → PHP-FPM / LSAPI
#     CloudLinux 6/7           → CloudLinux 8/9
# ============================================================

set -o pipefail
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# ─────────────────────────────────────────
# GLOBALS
# ─────────────────────────────────────────
CWD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
LOGFILE="/var/log/whm_preconfig_$(date +%Y%m%d_%H%M%S).log"
RUN_FLAG="/root/.whm_preconfig_run1_done"
PASSV_MIN="49152"
PASSV_MAX="65534"
PASSV_PORT="${PASSV_MIN}:${PASSV_MAX}"
PUBLIC_IP=$(curl -s https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
ISVPS="NO"
[ -f /proc/user_beancounters ] && ISVPS="YES"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

mkdir -p /var/log
touch "$LOGFILE"

log_info()    { echo -e "${GREEN}[INFO]${NC}     $1"  | tee -a "$LOGFILE"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}     $1" | tee -a "$LOGFILE"; }
log_error()   { echo -e "${RED}[ERROR]${NC}    $1"    | tee -a "$LOGFILE"; }
log_flag()    { echo -e "${RED}[OUTDATED]${NC} ⚠️  $1" | tee -a "$LOGFILE"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}       ✅ $1" | tee -a "$LOGFILE"; }
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
            *) echo -e "${RED}    ✗ Type y or n${NC}" ;;
        esac
    done
}

check_root() { [ "$EUID" -ne 0 ] && { log_error "Run as root!"; exit 1; }; }

# ═════════════════════════════════════════
# OS DETECTION — Ref:  
# ═════════════════════════════════════════
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME; VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si); VER=$(lsb_release -sr)
    elif [ -f /etc/almalinux-release ]; then
        OS="almalinux"; VER=$(grep -o "[0-9]" /etc/almalinux-release | head -1)
    elif [ -f /etc/redhat-release ]; then
        OS="centos"; VER=$(grep -o "[0-9]" /etc/redhat-release | head -1)
    else
        OS=$(uname -s); VER=$(uname -r)
    fi
    OS_MAJOR="${VER%%.*}"
    log_info "Sistema operativo detectado: $OS, versión: $VER"

    echo "$OS" | grep -iq "centos" && log_flag "CentOS 7 EOL Jun 2024 → AlmaLinux 9"
    echo "$OS" | grep -iq "ubuntu" && [ "${OS_MAJOR:-0}" -lt 20 ] 2>/dev/null && \
        log_flag "Ubuntu ${VER} EOL → Use 20.04/22.04"
    echo "$OS" | grep -iq "debian" && [ "${OS_MAJOR:-0}" -lt 11 ] 2>/dev/null && \
        log_flag "Debian ${VER} EOL → Use 11/12"

    export OS VER OS_MAJOR
}

# ═════════════════════════════════════════
# SHARED HELPERS
# ═════════════════════════════════════════
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

_apply_ssh() {
    log_info "Hardening SSH..."
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%s)" 2>/dev/null || true
    cat > /etc/ssh/sshd_config << 'EOF'
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
LoginGraceTime 30
PermitRootLogin prohibit-password
MaxAuthTries 3
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
X11Forwarding no
UseDNS no
ClientAliveInterval 300
ClientAliveCountMax 2
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
}

_disable_unused() {
    for s in telnet rsh rlogin rexec finger talk ntalk; do
        systemctl disable "$s" 2>/dev/null || true
        systemctl stop    "$s" 2>/dev/null || true
    done
}

# ═════════════════════════════════════════
# CSF INSTALL HELPERS
# Ref: 
# ═════════════════════════════════════════
_install_csf_rhel() {
    command -v dnf &>/dev/null && PKG="dnf" || PKG="yum"

    touch /etc/sysconfig/iptables /etc/sysconfig/iptables6
    systemctl enable --now iptables  2>/dev/null || true
    systemctl enable --now ip6tables 2>/dev/null || true

    systemctl disable firewalld 2>/dev/null || true
    systemctl stop    firewalld 2>/dev/null || true
    $PKG remove firewalld -y 2>/dev/null || true

    $PKG install -y iptables-services wget perl unzip net-tools \
        perl-libwww-perl perl-LWP-Protocol-https perl-GDGraph 2>/dev/null || true

    $PKG install -y cpanel-csf 2>/dev/null || {
        log_warn "cpanel-csf not in repo — installing from source..."
        wget -q https://download.configserver.com/csf.tgz -O /usr/src/csf.tgz
        tar -xzf /usr/src/csf.tgz -C /usr/src
        cd /usr/src/csf && sh install.sh
        cd /root && rm -rf /usr/src/csf /usr/src/csf.tgz /usr/src/error_log 2>/dev/null || true
    }
}

_install_csf_debian() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y wget perl unzip net-tools \
        libwww-perl liblwp-protocol-https-perl libgd-graph-perl \
        libio-socket-inet6-perl libsocket6-perl \
        sendmail dnsutils iptables iptables-persistent 2>/dev/null || true

    ufw disable 2>/dev/null || true
    systemctl disable ufw 2>/dev/null || true
    systemctl stop    ufw 2>/dev/null || true

    cd /tmp
    wget -q https://download.configserver.com/csf.tgz -O /tmp/csf.tgz
    tar -xzf /tmp/csf.tgz -C /tmp
    cd /tmp/csf && sh install.sh
    cd /root && rm -rf /tmp/csf /tmp/csf.tgz 2>/dev/null || true
}

# ═════════════════════════════════════════
# CSF CONFIGURE — Ref:  
# ═════════════════════════════════════════
_configure_csf() {
    log_section "CSF Firewall — Configure"
    [ ! -d /etc/csf ] && { log_warn "CSF not installed"; return 1; }

    log_info "Applying CSF config (100% ref based)..."

    # Core
    sed -i 's/^TESTING = .*/TESTING = "0"/g'                                     /etc/csf/csf.conf
    sed -i 's/^ICMP_IN = .*/ICMP_IN = "0"/g'                                    /etc/csf/csf.conf
    sed -i 's/^IPV6 = .*/IPV6 = "0"/g'                                          /etc/csf/csf.conf
    sed -i 's/^DENY_IP_LIMIT = .*/DENY_IP_LIMIT = "400"/g'                      /etc/csf/csf.conf
    sed -i 's/^SAFECHAINUPDATE = .*/SAFECHAINUPDATE = "1"/g'                     /etc/csf/csf.conf
    sed -i 's/^CC_DENY = .*/CC_DENY = ""/g'                                     /etc/csf/csf.conf
    sed -i 's/^CC_IGNORE = .*/CC_IGNORE = ""/g'                                 /etc/csf/csf.conf
    sed -i 's/^SMTP_BLOCK = .*/SMTP_BLOCK = "1"/g'                              /etc/csf/csf.conf

    # LF Detection
    sed -i 's/^LF_FTPD = .*/LF_FTPD = "30"/g'                                  /etc/csf/csf.conf
    sed -i 's/^LF_SMTPAUTH = .*/LF_SMTPAUTH = "90"/g'                          /etc/csf/csf.conf
    sed -i 's/^LF_EXIMSYNTAX = .*/LF_EXIMSYNTAX = "0"/g'                       /etc/csf/csf.conf
    sed -i 's/^LF_POP3D = .*/LF_POP3D = "100"/g'                               /etc/csf/csf.conf
    sed -i 's/^LF_IMAPD = .*/LF_IMAPD = "100"/g'                               /etc/csf/csf.conf
    sed -i 's/^LF_HTACCESS = .*/LF_HTACCESS = "40"/g'                          /etc/csf/csf.conf
    sed -i 's/^LF_CPANEL = .*/LF_CPANEL = "40"/g'                              /etc/csf/csf.conf
    sed -i 's/^LF_MODSEC = .*/LF_MODSEC = "100"/g'                             /etc/csf/csf.conf
    sed -i 's/^LF_CXS = .*/LF_CXS = "10"/g'                                    /etc/csf/csf.conf
    sed -i 's/^LT_POP3D = .*/LT_POP3D = "180"/g'                               /etc/csf/csf.conf
    sed -i 's/^CT_SKIP_TIME_WAIT = .*/CT_SKIP_TIME_WAIT = "1"/g'                /etc/csf/csf.conf
    sed -i 's/^PT_LIMIT = .*/PT_LIMIT = "0"/g'                                  /etc/csf/csf.conf
    sed -i 's/^ST_MYSQL = .*/ST_MYSQL = "1"/g'                                  /etc/csf/csf.conf
    sed -i 's/^ST_APACHE = .*/ST_APACHE = "1"/g'                                /etc/csf/csf.conf
    sed -i 's/^CONNLIMIT = .*/CONNLIMIT = "80;70,110;50,993;50,143;50,25;30"/g' /etc/csf/csf.conf
    sed -i 's/^LF_PERMBLOCK_INTERVAL = .*/LF_PERMBLOCK_INTERVAL = "14400"/g'    /etc/csf/csf.conf
    sed -i 's/^LF_INTERVAL = .*/LF_INTERVAL = "900"/g'                         /etc/csf/csf.conf
    sed -i 's/^PS_INTERVAL = .*/PS_INTERVAL = "60"/g'                           /etc/csf/csf.conf
    sed -i 's/^PS_LIMIT = .*/PS_LIMIT = "60"/g'                                 /etc/csf/csf.conf

    # Disable ALL alerts
    for alert in LF_PERMBLOCK_ALERT LF_NETBLOCK_ALERT LF_EMAIL_ALERT \
                 LF_CPANEL_ALERT LF_QUEUE_ALERT LF_DISTFTP_ALERT \
                 LF_DISTSMTP_ALERT LT_EMAIL_ALERT RT_RELAY_ALERT \
                 RT_AUTHRELAY_ALERT RT_POPRELAY_ALERT RT_LOCALRELAY_ALERT \
                 RT_LOCALHOSTRELAY_ALERT CT_EMAIL_ALERT PT_USERKILL_ALERT \
                 PS_EMAIL_ALERT PT_USERMEM PT_USERTIME PT_USERPROC PT_USERRSS; do
        sed -i "s/^${alert} = .*/${alert} = \"0\"/g" /etc/csf/csf.conf
    done

    # Passive FTP
    for D in TCP_IN TCP_OUT TCP6_IN TCP6_OUT; do
        CURR=$(grep "^${D}" /etc/csf/csf.conf | cut -d'=' -f2 \
            | sed 's/\ //g;s/\"//g' \
            | sed "s/,$PASSV_PORT,/,/g;s/,$PASSV_PORT//g;s/$PASSV_PORT,//g;s/,,//g")
        sed -i "s/^${D}.*/${D} = \"${CURR},${PASSV_PORT}\"/" /etc/csf/csf.conf
    done

    # cPanel migration ports 2082,2083
    CURR_OUT=$(grep "^TCP_OUT" /etc/csf/csf.conf | cut -d'=' -f2 \
        | sed 's/\ //g;s/\"//g' \
        | sed "s/,2082,2083,/,/g;s/,2082,2083//g;s/2082,2083,//g;s/,,//g")
    sed -i "s/^TCP_OUT.*/TCP_OUT = \"${CURR_OUT},2082,2083\"/" /etc/csf/csf.conf

    # Blocklists
    for bl in SPAMDROP SPAMEDROP DSHIELD HONEYPOT; do
        sed -i "/^#${bl}/s/^#//"           /etc/csf/csf.blocklists
        sed -i "/^${bl}/s/|0|/|300|/"      /etc/csf/csf.blocklists
    done
    sed -i '/^#BDE|/s/^#//'                /etc/csf/csf.blocklists
    sed -i '/^BDE|/s/|0|/|300|/'           /etc/csf/csf.blocklists
    for n in TOR ALTTOR CIARMY BFB OPENBL BDEALL; do
        sed -i "s/^${n}/#${n}/"            /etc/csf/csf.blocklists
    done

    # rIgnore
    cat > /etc/csf/csf.rignore << 'EOF'
.cpanel.net
.googlebot.com
.crawl.yahoo.net
.search.msn.com
EOF

    # DynDNS
    sed -i 's/^DYNDNS = .*/DYNDNS = "300"/g'             /etc/csf/csf.conf
    sed -i 's/^DYNDNS_IGNORE = .*/DYNDNS_IGNORE = "1"/g' /etc/csf/csf.conf
    sed -i '/gmail.com/d;/public.pyzor.org/d'            /etc/csf/csf.dyndns
    {
        echo "tcp|out|d=25|d=smtp.gmail.com"
        echo "tcp|out|d=465|d=smtp.gmail.com"
        echo "tcp|out|d=587|d=smtp.gmail.com"
        echo "tcp|out|d=995|d=imap.gmail.com"
        echo "tcp|out|d=993|d=imap.gmail.com"
        echo "tcp|out|d=143|d=imap.gmail.com"
        echo "udp|out|d=24441|d=public.pyzor.org"
    } >> /etc/csf/csf.dyndns

    # Integrations
    if [ -f /usr/local/lsws/bin/lshttpd ]; then
        log_info "LiteSpeed detected — adding ports 7080, 7443..."
        for D in TCP_IN TCP_OUT; do
            CURR=$(grep "^${D}" /etc/csf/csf.conf | cut -d'=' -f2 | sed 's/\ //g;s/\"//g')
            for P in 7080 7443; do
                echo "$CURR" | grep -q "$P" || \
                    sed -i "s/^${D}.*/${D} = \"${CURR},${P}\"/" /etc/csf/csf.conf
            done
        done
    fi
    if command -v imunify360-agent &>/dev/null; then
        log_info "Imunify360 detected — disabling CSF SMTP_BLOCK"
        sed -i 's/^SMTP_BLOCK = .*/SMTP_BLOCK = "0"/g' /etc/csf/csf.conf
    fi

    grep -q "^127.0.0.1"  /etc/csf/csf.allow 2>/dev/null || echo "127.0.0.1 # Localhost"  >> /etc/csf/csf.allow
    grep -q "^$PUBLIC_IP" /etc/csf/csf.allow 2>/dev/null || echo "$PUBLIC_IP # Server IP" >> /etc/csf/csf.allow

    csf -r
    service lfd restart 2>/dev/null || systemctl restart lfd 2>/dev/null || true
    log_ok "CSF configured"
}

# ═════════════════════════════════════════
# 1ST RUN — OS BASE CONFIG
# ═════════════════════════════════════════
run_centos() {
    log_section "CentOS Configuration"
    echo "Ejecutando script para CentOS..."

    yum install -y epel-release 2>/dev/null || true
    yum install -y \
        curl wget vim nano net-tools bind-utils \
        zip unzip tar git rsync screen tmux \
        perl perl-libwww-perl perl-LWP-Protocol-https perl-GDGraph \
        ca-certificates chrony iptables-services \
        bash-completion lsof htop nmap-ncat sysstat 2>/dev/null || true

    setenforce 0 2>/dev/null || true
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config

    systemctl disable firewalld NetworkManager 2>/dev/null || true
    systemctl stop    firewalld NetworkManager 2>/dev/null || true
    yum remove firewalld -y 2>/dev/null || true

    touch /etc/sysconfig/iptables /etc/sysconfig/iptables6
    systemctl enable --now iptables ip6tables chronyd 2>/dev/null || true

    _apply_sysctl
    _apply_ssh
    _disable_unused

    log_ok "CentOS base configuration complete"
}

run_almalinux() {
    log_section "AlmaLinux Configuration"
    echo "Ejecutando script para AlmaLinux..."

    dnf install -y epel-release 2>/dev/null || true
    dnf install -y \
        curl wget vim nano net-tools bind-utils \
        zip unzip tar git rsync screen tmux \
        perl perl-libwww-perl perl-LWP-Protocol-https perl-GDGraph \
        ca-certificates chrony iptables-services \
        bash-completion lsof htop nmap-ncat sysstat \
        dnf-automatic 2>/dev/null || true

    setenforce 0 2>/dev/null || true
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config

    systemctl disable firewalld NetworkManager 2>/dev/null || true
    systemctl stop    firewalld NetworkManager 2>/dev/null || true
    dnf remove firewalld -y 2>/dev/null || true

    touch /etc/sysconfig/iptables /etc/sysconfig/iptables6
    systemctl enable --now iptables ip6tables chronyd 2>/dev/null || true

    # ✅ DNF auto security updates
    sed -i 's/^upgrade_type.*/upgrade_type = security/' /etc/dnf/automatic.conf 2>/dev/null || true
    sed -i 's/^apply_updates.*/apply_updates = yes/'     /etc/dnf/automatic.conf 2>/dev/null || true
    systemctl enable --now dnf-automatic.timer 2>/dev/null || true

    _apply_sysctl
    _apply_ssh
    _disable_unused

    log_ok "AlmaLinux base configuration complete"
}

run_debian() {
    log_section "Debian Configuration"
    echo "Ejecutando script para Debian..."

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y && apt-get upgrade -y
    apt-get install -y \
        curl wget vim nano net-tools dnsutils \
        zip unzip tar git rsync screen tmux \
        perl libwww-perl liblwp-protocol-https-perl libgd-graph-perl \
        libio-socket-inet6-perl libsocket6-perl \
        ca-certificates chrony iptables iptables-persistent \
        bash-completion lsof htop netcat-openbsd sysstat \
        unattended-upgrades apt-listchanges sendmail 2>/dev/null || true

    ufw disable 2>/dev/null || true
    systemctl disable ufw apparmor 2>/dev/null || true
    systemctl stop    ufw apparmor 2>/dev/null || true
    systemctl enable --now chrony 2>/dev/null || true

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

    _apply_sysctl
    _apply_ssh
    _disable_unused

    log_ok "Debian base configuration complete"
}

run_ubuntu() {
    log_section "Ubuntu Configuration"
    echo "Ejecutando script para Ubuntu..."

    if [ "${OS_MAJOR:-0}" -lt 20 ] 2>/dev/null; then
        log_flag "Ubuntu ${VER} EOL! Use 20.04 or 22.04!"
    fi

    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y && apt-get upgrade -y
    apt-get install -y \
        curl wget vim nano net-tools dnsutils \
        zip unzip tar git rsync screen tmux \
        perl libwww-perl liblwp-protocol-https-perl libgd-graph-perl \
        libio-socket-inet6-perl libsocket6-perl \
        ca-certificates chrony iptables iptables-persistent \
        bash-completion lsof htop netcat-openbsd sysstat \
        unattended-upgrades apt-listchanges \
        software-properties-common sendmail 2>/dev/null || true

    ufw disable 2>/dev/null || true
    systemctl disable ufw apparmor 2>/dev/null || true
    systemctl stop    ufw apparmor 2>/dev/null || true
    systemctl enable --now chrony 2>/dev/null || true

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

    _apply_sysctl
    _apply_ssh
    _disable_unused

    log_ok "Ubuntu base configuration complete"
}

run_os_config() {
    if   echo "$OS" | grep -iq "centos";                 then run_centos
    elif echo "$OS" | grep -iq "almalinux\|rocky";       then run_almalinux
    elif echo "$OS" | grep -iq "debian";                 then run_debian
    elif echo "$OS" | grep -iq "ubuntu";                 then run_ubuntu
    else log_warn "Unknown OS: $OS — using AlmaLinux defaults"; run_almalinux
    fi
}

# ═════════════════════════════════════════
# 2ND RUN — cPANEL INSTALL
# Ref:  — exact
# ═════════════════════════════════════════
install_cpanel() {
    log_section "cPanel/WHM Installation"
    echo "####### INSTALLING CPANEL #######"

    if [ -f /usr/local/cpanel/cpanel ]; then
        echo "cPanel already detected — configuring only (CTRL+C to cancel)"
        sleep 10
        systemctl enable --now network.service 2>/dev/null || true
    else
        hostname -f > /root/hostname
        log_info "Saved hostname: $(cat /root/hostname)"

        log_info "Downloading cPanel latest installer..."
        cd /home
        curl -o latest -L https://securedownloads.cpanel.net/latest
        sh latest --skip-cloudlinux

        log_info "Waiting 5 minutes for background install to finish..."
        sleep 300

        # Fix hostname changed by cPanel
        log_info "Restoring hostname..."
        whmapi1 sethostname hostname="$(cat /root/hostname)"
        hostnamectl set-hostname "$(cat /root/hostname)"
        rm -f /root/hostname
    fi

    CPANEL_VER=$(/usr/local/cpanel/cpanel -V 2>/dev/null | awk '{print $1}' || echo "N/A")
    log_ok "cPanel Version: ${CPANEL_VER}"
    echo "####### END INSTALLING CPANEL #######"
}

# ═════════════════════════════════════════
# CSF CHECK + INSTALL (AFTER cPanel)
# ═════════════════════════════════════════
check_install_csf() {
    log_section "CSF Firewall — Check & Install"

    if [ -d /usr/local/cpanel/whostmgr/docroot/cgi/configserver/csf ] || [ -d /etc/csf ]; then
        log_ok "CSF already installed"
    else
        if ask_yn "CSF not detected — install now?"; then
            if echo "$OS" | grep -iq "ubuntu\|debian"; then
                _install_csf_debian
            else
                _install_csf_rhel
            fi
        else
            log_warn "CSF install skipped"
            return 0
        fi
    fi

    _configure_csf
}

# ═════════════════════════════════════════
# WHM BASICS (FTP + TWEAKS)
# Ref:  
# ═════════════════════════════════════════
configure_whm_basics() {
    log_section "WHM Basic Config + FTP + Tweak Settings"

    HOSTNAME_LONG=$(hostname -d)

    # wwwacct.conf
    sed -i 's/^TTL .*/TTL 900/' /etc/wwwacct.conf
    sed -i '/^CONTACTEMAIL\ .*/d' /etc/wwwacct.conf
    echo "CONTACTEMAIL hostmaster@$HOSTNAME_LONG" >> /etc/wwwacct.conf
    sed -i '/^NS\ .*/d;/^NS2\ .*/d;/^NS3\ .*/d' /etc/wwwacct.conf
    echo "NS ns1.$HOSTNAME_LONG"  >> /etc/wwwacct.conf
    echo "NS2 ns2.$HOSTNAME_LONG" >> /etc/wwwacct.conf
    sed -i "s/^ADDR .*/ADDR $PUBLIC_IP/" /etc/wwwacct.conf

    # PureFTPd
    mkdir -p /var/cpanel/conf/pureftpd
    sed -i '/^MaxClientsPerIP:.*/d;/^RootPassLogins:.*/d;/^PassivePortRange:.*/d;/^TLSCipherSuite:.*/d;/^LimitRecursion:.*/d' \
        /var/cpanel/conf/pureftpd/local 2>/dev/null || true
    {
        echo "MaxClientsPerIP: 30"
        echo "RootPassLogins: 'no'"
        echo "PassivePortRange: $PASSV_MIN $PASSV_MAX"
        echo 'TLSCipherSuite: "HIGH:MEDIUM:+TLSv1:!SSLv2:+SSLv3"'
        echo "LimitRecursion: 50000 12"
    } >> /var/cpanel/conf/pureftpd/local

    /usr/local/cpanel/scripts/setupftpserver pure-ftpd --force
    modprobe ip_conntrack_ftp 2>/dev/null || true

    # Tweak Settings
    whmapi1 set_tweaksetting key=allowremotedomains                                     value=1
    whmapi1 set_tweaksetting key=allowunregistereddomains                               value=1
    whmapi1 set_tweaksetting key=chkservd_check_interval                                value=120
    whmapi1 set_tweaksetting key=defaultmailaction                                      value=fail
    whmapi1 set_tweaksetting key=email_send_limits_max_defer_fail_percentage            value=25
    whmapi1 set_tweaksetting key=email_send_limits_min_defer_fail_to_trigger_protection value=15
    whmapi1 set_tweaksetting key=maxemailsperhour                                       value=200
    whmapi1 set_tweaksetting key=permit_unregistered_apps_as_root                       value=1
    whmapi1 set_tweaksetting key=requiressl                                             value=0
    whmapi1 set_tweaksetting key=skipanalog                                             value=1
    whmapi1 set_tweaksetting key=skipboxtrapper                                         value=1
    whmapi1 set_tweaksetting key=skipwebalizer                                          value=1
    whmapi1 set_tweaksetting key=smtpmailgidonly                                        value=0
    whmapi1 set_tweaksetting key=eximmailtrap                                           value=1
    whmapi1 set_tweaksetting key=use_information_schema                                 value=0
    whmapi1 set_tweaksetting key=cookieipvalidation                                     value=disabled
    whmapi1 set_tweaksetting key=notify_expiring_certificates                           value=0
    whmapi1 set_tweaksetting key=notify_ssl_expiry                                      value=0
    whmapi1 set_tweaksetting key=autossl_notify_expiry                                  value=0
       whmapi1 set_tweaksetting key=autossl_notify_start                                   value=0
    whmapi1 set_tweaksetting key=autossl_notify_start_type                              value=0
    whmapi1 set_tweaksetting key=autossl_notify_problem                                 value=0
    whmapi1 set_tweaksetting key=autossl_notify_problem_type                            value=0
    whmapi1 set_tweaksetting key=autossl_notify_renewal                                 value=0
    whmapi1 set_tweaksetting key=autossl_notify_renewal_type                            value=0
    whmapi1 set_tweaksetting key=autossl_allow_x509_wildcards                           value=1

    # ✅ Let's Encrypt AutoSSL
    # ⚠️  cPanel-provided SSL is outdated — Let's Encrypt is the standard
    whmapi1 set_autossl_provider \
        provider="LetsEncrypt" \
        terms_of_service_accepted=1 2>/dev/null || true

    # ✅ TLS 1.2 / 1.3 only
    # ⚠️  TLS 1.0 / 1.1 EOL — disabled
    whmapi1 set_tweaksetting key=sslprotocol value="TLSv1.2 TLSv1.3"

    # ✅ Modern cipher suite
    # ⚠️  RC4, DES, 3DES, MD5 removed — insecure
    whmapi1 set_tweaksetting key=sslciphersuite \
        value="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"

    log_ok "WHM basic config + FTP + Tweak Settings complete"
}

# ═════════════════════════════════════════
# cPANEL PLUGINS — CHECK & ASK IF MISSING
# ═════════════════════════════════════════

# ── CMQ (ConfigServer MailQueues) ────────
check_install_cmq() {
    log_section "ConfigServer MailQueues (CMQ)"

    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/configserver/cmq.cgi ]; then
        log_ok "CMQ already installed"
        return 0
    fi

    if ask_yn "CMQ not detected — install now?"; then
        cd /tmp
        wget -q https://download.configserver.com/cmq.tgz
        tar -xzf cmq.tgz
        cd cmq && sh install.sh
        cd /root && rm -rf /tmp/cmq /tmp/cmq.tgz
        log_ok "CMQ installed"
    else
        log_warn "CMQ install skipped"
    fi
}

# ── Account DNS Check ────────────────────
check_install_dns_check() {
    log_section "Account DNS Check"
    echo "####### CONFIGURANDO DNS CHECK #######"

    log_info "Rebuilding DNS config..."
    /usr/local/cpanel/scripts/rebuilddnsconfig 2>/dev/null || true

    log_info "Enabling DNSSEC..."
    whmapi1 set_tweaksetting key=dnssec value=1 2>/dev/null || true

    log_info "Running SSL cert check..."
    /usr/local/cpanel/scripts/checkallsslcerts --verbose 2>/dev/null || true

    log_info "Restarting DNS service..."
    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        systemctl restart bind9 2>/dev/null || true
    else
        systemctl restart named 2>/dev/null || true
    fi

    echo "####### END CONFIGURANDO DNS CHECK #######"
    log_ok "Account DNS Check configured"
}

# ── Softaculous ──────────────────────────
check_install_softaculous() {
    log_section "Softaculous Auto-Installer"

    if [ -f /usr/local/cpanel/whostmgr/docroot/cgi/softaculous/index.cgi ]; then
        log_ok "Softaculous already installed — updating..."
        /usr/local/cpanel/whostmgr/docroot/cgi/softaculous/softaculous.sh update 2>/dev/null || true
        return 0
    fi

    if ask_yn "Softaculous not detected — install now?"; then
        wget -N https://files.softaculous.com/install.sh -O /tmp/soft.sh
        chmod 755 /tmp/soft.sh
        bash /tmp/soft.sh
        rm -f /tmp/soft.sh
        whmapi1 set_tweaksetting key=softaculous value=1 2>/dev/null || true
        log_ok "Softaculous installed"
    else
        log_warn "Softaculous install skipped"
    fi
}

# ── WP Toolkit ───────────────────────────
check_install_wptoolkit() {
    log_section "WP Toolkit"

    if [ -d /usr/local/cpanel/3rdparty/wp-toolkit ] || \
       rpm -qa 2>/dev/null | grep -q wp-toolkit-cpanel || \
       dpkg -l 2>/dev/null | grep -q wp-toolkit-cpanel; then
        log_ok "WP Toolkit already installed"
        return 0
    fi

    if ask_yn "WP Toolkit not detected — install now?"; then
        if echo "$OS" | grep -iq "ubuntu\|debian"; then
            apt-get install -y wp-toolkit-cpanel 2>/dev/null || \
                log_warn "WP Toolkit install failed via apt"
        else
            command -v dnf &>/dev/null && PKG="dnf" || PKG="yum"
            $PKG install -y wp-toolkit-cpanel 2>/dev/null || \
                log_warn "WP Toolkit install failed via $PKG"
        fi
        log_ok "WP Toolkit installed"
    else
        log_warn "WP Toolkit install skipped"
    fi
}

# ── JetBackup 4 / 5 ──────────────────────
check_install_jetbackup() {
    log_section "JetBackup 4 / 5"

    if command -v jetbackup5 &>/dev/null; then
        log_ok "JetBackup 5 already installed"
        return 0
    fi
    if command -v jetbackup &>/dev/null; then
        log_flag "JetBackup 4 detected — EOL! Upgrade to JetBackup 5"
        return 0
    fi

    if ! ask_yn "JetBackup not detected — install now?"; then
        log_warn "JetBackup install skipped"
        return 0
    fi

    log_flag "JetBackup 4.x is EOL! JetBackup 5.x is current (2026)"
    echo ""
    echo "  [1] JetBackup 5 ✅ (Current — Recommended)"
    echo "  [2] JetBackup 4 ⚠️  (Legacy/EOL — Not Recommended)"
    read -rp "  Select [1/2]: " JB_V </dev/tty

    case "$JB_V" in
        1)
            log_info "Installing JetBackup 5..."
            if echo "$OS" | grep -iq "ubuntu\|debian"; then
                wget -q https://repo.jetlicense.com/ubuntu/jetapps-repo-latest.deb -O /tmp/jet.deb
                dpkg -i /tmp/jet.deb
                apt-get update -y
                apt-get install -y jetbackup5-cpanel
                rm -f /tmp/jet.deb
            else
                command -v dnf &>/dev/null && PKG="dnf" || PKG="yum"
                wget -q https://repo.jetlicense.com/centOS/jetapps-repo-latest.rpm -O /tmp/jet.rpm
                $PKG install -y /tmp/jet.rpm
                $PKG install -y jetbackup5-cpanel
                rm -f /tmp/jet.rpm
            fi
            systemctl enable --now jetbackup5 2>/dev/null || true

            # ✅ JetBackup 5 best-practice config
            mkdir -p /etc/jetapps
            cat > /etc/jetapps/jetbackup5.conf << 'EOF'
[general]
max_backup_processes=2
backup_nice_level=10
backup_ionice_class=2
backup_ionice_level=4
[retention]
local_retention=7
remote_retention=30
[notifications]
email_on_failure=1
email_on_success=0
EOF
            log_ok "JetBackup 5 installed"
            ;;
        2)
            log_warn "Installing JetBackup 4 (Legacy/EOL)..."
            if echo "$OS" | grep -iq "ubuntu\|debian"; then
                log_error "JetBackup 4 not supported on Ubuntu/Debian — install JetBackup 5"
            else
                command -v dnf &>/dev/null && PKG="dnf" || PKG="yum"
                wget -q https://repo.jetlicense.com/centOS/jetapps-repo-latest.rpm -O /tmp/jet.rpm
                $PKG install -y /tmp/jet.rpm
                $PKG install -y jetbackup-cpanel 2>/dev/null || \
                    log_error "JetBackup 4 install failed — upgrade to JetBackup 5"
                rm -f /tmp/jet.rpm
            fi
            ;;
        *)
            log_warn "Invalid option — skipping JetBackup"
            ;;
    esac
}

# ── Imunify360 ───────────────────────────
check_install_imunify360() {
    log_section "Imunify360"

    if command -v imunify360-agent &>/dev/null; then
        log_ok "Imunify360 already installed"
        return 0
    fi

    if ! ask_yn "Imunify360 not detected — install now?"; then
        log_warn "Imunify360 install skipped"
        return 0
    fi

    echo ""
    echo "  [1] Imunify360     (Full — requires license)"
    echo "  [2] ImunifyAV+     (requires license)"
    echo "  [3] ImunifyAV Free (no license needed)"
    read -rp "  Select [1/2/3]: " IMU </dev/tty

    wget -q https://repo.imunify360.cloudlinux.com/defence360/imunify-deploy.sh -O /tmp/imu.sh
    chmod +x /tmp/imu.sh
    case "$IMU" in
        1) bash /tmp/imu.sh --imunify360 2>/dev/null || bash /tmp/imu.sh ;;
        2) bash /tmp/imu.sh --imunifyav-plus ;;
        3) bash /tmp/imu.sh --imunifyav ;;
        *) bash /tmp/imu.sh --imunifyav ;;
    esac

    # ✅ Best-practice Imunify360 config
    imunify360-agent config update '{
        "MALWARE_SCAN_INTENSITY": {"cpu": 2, "io": 1, "ram": 1024},
        "MALWARE_SCANNING": {"background_scan": true, "full_scan_day": 0},
        "PAM": {"enable": true, "exim_dovecot_protection": true},
        "WEBSHIELD": {"enable": true},
        "PROACTIVE_DEFENCE": {"mode": "KILL"},
        "DOS": {"enabled": true},
        "SMTP_BLOCKING": {"enable": true, "ports": [25, 587, 465], "allow_groups": ["mail"]}
    }' 2>/dev/null || log_warn "Could not apply Imunify360 config"

    rm -f /tmp/imu.sh
    log_ok "Imunify360 installed"
}

# ═════════════════════════════════════════
# LITESPEED — ask if not installed
# ⚠️  LiteSpeed 5.x old → LiteSpeed 6.x
# ✅  HTTP/3 QUIC + Brotli (2026 standard)
# ═════════════════════════════════════════
check_install_litespeed() {
    log_section "LiteSpeed Web Server"

    if [ -f /usr/local/lsws/bin/lshttpd ]; then
        LS_VER=$(/usr/local/lsws/bin/lshttpd -v 2>/dev/null | head -1)
        log_ok "LiteSpeed already installed: $LS_VER"
        return 0
    fi

    if ! ask_yn "LiteSpeed not detected — install now?"; then
        log_warn "LiteSpeed install skipped"
        return 0
    fi

    log_flag "LiteSpeed 5.x → LiteSpeed 6.x (HTTP/3 QUIC)"

    echo ""
    echo "  [1] Trial License (15 days free)"
    echo "  [2] Serial Number (paid)"
    echo "  [3] LSWS Free (up to 2GB RAM)"
    read -rp "  Select [1/2/3]: " LS_OPT </dev/tty
    case "$LS_OPT" in
        1) LS_SERIAL="TRIAL" ;;
        2) read -rp "  Serial: " LS_SERIAL </dev/tty ;;
        3) LS_SERIAL="FREE" ;;
        *) LS_SERIAL="TRIAL" ;;
    esac

    wget -q https://www.litespeedtech.com/packages/cpanel/lsws_whm_autoinstaller.sh \
        -O /tmp/lsws_install.sh
    chmod +x /tmp/lsws_install.sh
    echo "$LS_SERIAL" | bash /tmp/lsws_install.sh

    # LSCache
    /usr/local/lsws/admin/misc/lscmctl install 2>/dev/null || true

    # ⚠️  PHP 7.x / 8.0 EOL — install PHP 8.1/8.2/8.3/8.4 only
    for V in lsphp81 lsphp82 lsphp83 lsphp84; do
        /usr/local/lsws/admin/misc/lsphp_mgr.sh install "$V" 2>/dev/null || true
    done

    # ✅ HTTP/3 QUIC + Brotli config
    mkdir -p /usr/local/lsws/conf/httpd_config.conf.d
    cat > /usr/local/lsws/conf/httpd_config.conf.d/whm_optimized.conf << 'EOF'
# ✅ LiteSpeed Optimized Config - 2026
enableQuic          1
quicEnable          1
enableBr            1
enableGzip          1
gzipCompressLevel   6
brCompressLevel     6
maxConnections      20000
maxSSLConnections   20000
EOF

    systemctl enable --now lsws 2>/dev/null || true

    # Re-apply CSF to pick up LiteSpeed ports 7080/7443
    _configure_csf

    rm -f /tmp/lsws_install.sh
    log_ok "LiteSpeed installed with HTTP/3 QUIC + Brotli"
}

# ═════════════════════════════════════════
# CLOUDLINUX — ask if not installed
# ⚠️  NOT supported on Ubuntu/Debian
# ═════════════════════════════════════════
check_install_cloudlinux() {
    log_section "CloudLinux"

    if echo "$OS" | grep -iq "ubuntu\|debian"; then
        log_warn "CloudLinux NOT supported on Ubuntu/Debian — skipping"
        return 0
    fi

    if grep -qi "cloudlinux" /etc/os-release 2>/dev/null; then
        log_ok "CloudLinux already running"
        return 0
    fi

    if ! ask_yn "CloudLinux not installed — install now?"; then
        log_warn "CloudLinux skipped"
        return 0
    fi

    read -rp "  License Key (Enter for IP activation): " CL_KEY </dev/tty

    wget -q https://repo.cloudlinux.com/cloudlinux/sources/cln/cldeploy -O /tmp/cldeploy
    chmod +x /tmp/cldeploy

    if [ -n "$CL_KEY" ]; then
        bash /tmp/cldeploy -k "$CL_KEY"
    else
        bash /tmp/cldeploy -i
    fi

    command -v dnf &>/dev/null && PKG="dnf" || PKG="yum"
    $PKG install -y lvemanager lvectl lve-utils lve-stats \
        cagefs alt-php-config governor-mysql 2>/dev/null || true
    cagefsctl --init              2>/dev/null || true
    cagefsctl --enable-all        2>/dev/null || true
    cagefsctl --setup-cl-selector 2>/dev/null || true
    /usr/share/lve/dbgovernor/mysqlgovernor.py --install 2>/dev/null || true

    rm -f /tmp/cldeploy

    log_warn "⚠️  Reboot required after CloudLinux install"
    log_ok "CloudLinux installed"
}

# ═════════════════════════════════════════
# FINAL SUMMARY
# ═════════════════════════════════════════
print_summary() {
    log_section "FINAL SUMMARY"
    CPANEL_VER=$(/usr/local/cpanel/cpanel -V 2>/dev/null | awk '{print $1}' || echo "N/A")

    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║  WHM/cPanel PreConfig v1.0 — COMPLETE           ║"
    echo "  ╠══════════════════════════════════════════════════╣"
    printf "  ║  %-12s : %-33s║\n" "Date"      "$(date '+%Y-%m-%d %H:%M UTC')"
    printf "  ║  %-12s : %-33s║\n" "Hostname"  "$(hostname)"
    printf "  ║  %-12s : %-33s║\n" "OS"        "$OS $VER"
    printf "  ║  %-12s : %-33s║\n" "cPanel"    "$CPANEL_VER"
    printf "  ║  %-12s : %-33s║\n" "Public IP" "$PUBLIC_IP"
    printf "  ║  %-12s : %-33s║\n" "Log"       "$LOGFILE"
    echo "  ╠══════════════════════════════════════════════════╣"
    echo "  ║  ✅ COMPONENTS CONFIGURED:                       ║"
    echo "  ║     • OS Base Config                             ║"
    echo "  ║     • cPanel/WHM                                 ║"
    echo "  ║     • CSF Firewall                               ║"
    echo "  ║     • WHM Basic + FTP + Tweak Settings           ║"
    echo "  ║     • CMQ                                        ║"
    echo "  ║     • Account DNS Check                          ║"
    echo "  ║     • Softaculous                                ║"
    echo "  ║     • WP Toolkit                                 ║"
    echo "  ║     • JetBackup 4 / 5                            ║"
    echo "  ║     • Imunify360                                 ║"
    echo "  ║     • LiteSpeed 6.x + HTTP/3 QUIC                ║"
    echo "  ║     • CloudLinux (if applicable)                 ║"
    echo "  ╠══════════════════════════════════════════════════╣"
    echo "  ║  ⚠️  POST-INSTALL TODO:                          ║"
    echo "  ║   1. Reboot server (CloudLinux kernel)           ║"
    echo "  ║   2. Verify SSH access                           ║"
    echo "  ║   3. Activate LiteSpeed license                  ║"
    echo "  ║   4. Activate Imunify360 license                 ║"
    echo "  ║   5. Configure JetBackup destinations in WHM     ║"
    echo "  ║   6. Test AutoSSL on a domain                    ║"
    echo "  ║   7. Verify CSF is NOT in TESTING mode           ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "  ${CYAN}Monitor log:${NC} tail -f $LOGFILE\n"

    if ask_yn "Reboot now?"; then
        log_info "Rebooting in 10 seconds... (CTRL+C to cancel)"
        sleep 10
        reboot
    else
        log_warn "Please reboot manually: shutdown -r now"
    fi
}

# ═════════════════════════════════════════
# 1ST RUN / 2ND RUN LOGIC
# ═════════════════════════════════════════
first_run() {
    log_section "🔥 FIRST RUN — OS Base Configuration"

    run_os_config

    touch "$RUN_FLAG"
    log_ok "First run complete — flag saved: $RUN_FLAG"

    echo ""
    log_warn "⚠️  Reboot RECOMMENDED before cPanel install"
    log_warn "⚠️  Run this script AGAIN after reboot for cPanel setup"
    echo ""

    if ask_yn "Reboot now?"; then
        sleep 5
        reboot
    fi
}

second_run() {
    log_section "🔥 SECOND RUN — cPanel Install & Configuration"

    # [1] Install cPanel
    install_cpanel

    # [2] After cPanel done → CSF install + configure
    check_install_csf

    # [3] WHM Basics (FTP + Tweak Settings)
    configure_whm_basics

    # [4] cPanel Plugins — check & ask if missing
    check_install_cmq
    check_install_dns_check
    check_install_softaculous
    check_install_wptoolkit
    check_install_jetbackup
    check_install_imunify360

    # [5] LiteSpeed (ask if not installed)
    check_install_litespeed

    # [6] CloudLinux (ask if not installed)
    check_install_cloudlinux

    # [7] Final CSF reconfiguration
    log_info "Final CSF reconfiguration (LiteSpeed/CloudLinux/Imunify integration)..."
    _configure_csf

    print_summary
}

# ═════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════
main() {
    check_root
    detect_os

    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║  🚀 WHM/cPanel PreConfig v1.0                   ║"
    echo "  ║  Date : $(date '+%Y-%m-%d %H:%M UTC')                    ║"
    echo "  ║  OS   : $OS $VER"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # ── 1st Run / 2nd Run Logic ──────────────
    if [ ! -f "$RUN_FLAG" ]; then
        echo -e "${YELLOW}${BOLD}  ── FIRST RUN: OS Base Configuration ──${NC}\n"
        echo -e "  This run will configure the OS base system."
        echo -e "  After reboot, run the script AGAIN for cPanel setup.\n"
        first_run
    else
        echo -e "${GREEN}${BOLD}  ── SECOND RUN: cPanel + Plugins + LS + CL ──${NC}\n"
        echo -e "  OS base config already complete."
        echo -e "  Proceeding with cPanel/WHM installation & configuration.\n"
        second_run
    fi

    # ── History cleanup ──────────────────────
    # Ref:  
    history -c
    echo "" > /root/.bash_history
}

# ═════════════════════════════════════════
# TRAP HANDLER
# ═════════════════════════════════════════
trap 'log_error "Script interrupted at line $LINENO! Check log: $LOGFILE"; exit 1' INT TERM ERR

# ═════════════════════════════════════════
# RUN
# ═════════════════════════════════════════
main "$@"
