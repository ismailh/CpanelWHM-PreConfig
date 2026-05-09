#!/bin/bash
# ============================================================
# cPanel Plugins Master Uninstaller Script
# Coded-by nx.lc & Bluedot Team
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

[ "$EUID" -ne 0 ] && { echo -e "${RED}[ERROR] Run as root!${NC}"; exit 1; }

echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}  ➤  cPanel Plugins Master Uninstaller             ${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}\n"

ask_uninstall() {
    local plugin_name="$1"
    local uninstall_cmd="$2"
    
    echo -e "${YELLOW}--------------------------------------------------${NC}"
    echo -ne "${BOLD}Do you want to uninstall ${CYAN}${plugin_name}${NC}${BOLD}?${NC}\n(Type 'need unistall' to confirm, or press Enter to skip): "
    read -r a </dev/tty
    
    if [[ "${a,,}" == "need unistall" || "${a,,}" == "need uninstall" ]]; then
        echo -e "${GREEN}[INFO] Uninstalling ${plugin_name}...${NC}"
        eval "$uninstall_cmd"
        echo -e "${GREEN}[OK] ✅ ${plugin_name} uninstalled.${NC}\n"
    else
        echo -e "${YELLOW}[WARN] Skipped ${plugin_name}.${NC}\n"
    fi
}

# 1. ConfigServer Security & Firewall (CSF)
ask_uninstall "CSF Firewall" "cd /etc/csf && sh uninstall.sh 2>/dev/null"

# 2. ConfigServer Mail Queues (CMQ)
ask_uninstall "ConfigServer Mail Queues (CMQ)" "cd /usr/src && wget -q https://raw.githubusercontent.com/systechICTltd/ConfigServer-Scripts/main/cmq.tgz -O cmq.tgz && tar -xzf cmq.tgz && cd cmq && sh uninstall.sh 2>/dev/null; rm -Rfv /usr/src/cmq* 2>/dev/null"

# 3. ConfigServer ModSecurity Control (CMC)
ask_uninstall "ConfigServer ModSecurity Control (CMC)" "cd /usr/src && wget -q https://raw.githubusercontent.com/systechICTltd/ConfigServer-Scripts/main/cmc.tgz -O cmc.tgz && tar -xzf cmc.tgz && cd cmc && sh uninstall.sh 2>/dev/null; rm -Rfv /usr/src/cmc* 2>/dev/null"

# 4. Account DNS Check
ask_uninstall "Account DNS Check" "rm -rf /usr/local/cpanel/whostmgr/docroot/cgi/addons/accountdnscheck/ /usr/local/cpanel/whostmgr/docroot/cgi/addon_accountdnscheck.cgi"

# 5. CleanBackups
ask_uninstall "CleanBackups" "rm -rf /usr/local/cpanel/whostmgr/docroot/cgi/cleanbackups /usr/local/cpanel/whostmgr/docroot/cgi/addon_cleanbackups.cgi"

# 6. WatchMySQL
ask_uninstall "WatchMySQL" "rm -rf /usr/local/cpanel/whostmgr/docroot/cgi/watchmysql /usr/local/cpanel/whostmgr/docroot/cgi/addon_watchmysql.cgi"

# 7. Softaculous
ask_uninstall "Softaculous" "wget -q -N http://files.softaculous.com/install.sh -O /tmp/soft.sh && chmod 755 /tmp/soft.sh && /tmp/soft.sh --uninstall 2>/dev/null; rm -f /tmp/soft.sh"

# 8. WP Toolkit
ask_uninstall "WP Toolkit" "sh /usr/local/cpanel/3rdparty/wp-toolkit/bin/installer.sh --uninstall 2>/dev/null || rpm -e wp-toolkit-cpanel 2>/dev/null"

# 9. JetBackup 5
ask_uninstall "JetBackup 5" "jetapps --uninstall jetbackup5-cpanel 2>/dev/null"

# 10. Imunify360
ask_uninstall "Imunify360" "wget -q https://repo.imunify360.cloudlinux.com/defence360/imunify-deploy.sh -O /tmp/imu.sh && bash /tmp/imu.sh --uninstall 2>/dev/null; rm -f /tmp/imu.sh"

# 11. LiteSpeed Web Server
ask_uninstall "LiteSpeed Web Server" "/usr/local/lsws/admin/misc/uninstall.sh 2>/dev/null"

# 12. CloudLinux
ask_uninstall "CloudLinux" "wget -q https://repo.cloudlinux.com/cloudlinux/sources/cln/cldeploy -O /tmp/cldeploy && bash /tmp/cldeploy -c 2>/dev/null; rm -f /tmp/cldeploy"

# 13. Redis & Memcached
ask_uninstall "Redis & Memcached" "systemctl stop redis-server memcached redis 2>/dev/null; yum remove -y redis memcached 2>/dev/null || apt-get remove -y redis-server memcached 2>/dev/null"

# 14. Telegram Alerts (CSF & WHM Bridge)
ask_uninstall "Telegram Alerts Bridge" "rm -f /usr/local/bin/telegram-alert /usr/local/cpanel/whostmgr/docroot/cgi/telegram_bridge.php /root/.telegram_installed; sed -i '/telegram-alert/d' /etc/csf/csfpost.sh 2>/dev/null"

echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}  ➤  Uninstallation Process Complete!              ${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}\n"
