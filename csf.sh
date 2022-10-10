#!/bin/bash
echo " Setting CSF..."
yum remove firewalld -y
yum -y install iptables-services wget perl unzip net-tools perl-libwww-perl perl-LWP-Protocol-https perl-GDGraph

sed -i 's/^TESTING = .*/TESTING = "0"/g' /etc/csf/csf.conf
sed -i 's/^ICMP_IN = .*/ICMP_IN = "0"/g' /etc/csf/csf.conf
sed -i 's/^IPV6 = .*/IPV6 = "0"/g' /etc/csf/csf.conf
sed -i 's/^DENY_IP_LIMIT = .*/DENY_IP_LIMIT = "400"/g' /etc/csf/csf.conf
sed -i 's/^SAFECHAINUPDATE = .*/SAFECHAINUPDATE = "1"/g' /etc/csf/csf.conf
sed -i 's/^CC_DENY = .*/CC_DENY = ""/g' /etc/csf/csf.conf
sed -i 's/^CC_IGNORE = .*/CC_IGNORE = ""/g' /etc/csf/csf.conf
sed -i 's/^SMTP_BLOCK = .*/SMTP_BLOCK = "1"/g' /etc/csf/csf.conf
sed -i 's/^LF_FTPD = .*/LF_FTPD = "30"/g' /etc/csf/csf.conf
sed -i 's/^LF_SMTPAUTH = .*/LF_SMTPAUTH = "90"/g' /etc/csf/csf.conf
sed -i 's/^LF_EXIMSYNTAX = .*/LF_EXIMSYNTAX = "0"/g' /etc/csf/csf.conf
sed -i 's/^LF_POP3D = .*/LF_POP3D = "100"/g' /etc/csf/csf.conf
sed -i 's/^LF_IMAPD = .*/LF_IMAPD = "100"/g' /etc/csf/csf.conf
sed -i 's/^LF_HTACCESS = .*/LF_HTACCESS = "40"/g' /etc/csf/csf.conf
sed -i 's/^LF_CPANEL = .*/LF_CPANEL = "40"/g' /etc/csf/csf.conf
sed -i 's/^LF_MODSEC = .*/LF_MODSEC = "100"/g' /etc/csf/csf.conf
sed -i 's/^LF_CXS = .*/LF_CXS = "10"/g' /etc/csf/csf.conf
sed -i 's/^LT_POP3D =  .*/LT_POP3D = "180"/g' /etc/csf/csf.conf
sed -i 's/^CT_SKIP_TIME_WAIT = .*/CT_SKIP_TIME_WAIT = "1"/g' /etc/csf/csf.conf
sed -i 's/^PT_LIMIT = .*/PT_LIMIT = "0"/g' /etc/csf/csf.conf
sed -i 's/^ST_MYSQL = .*/ST_MYSQL = "1"/g' /etc/csf/csf.conf
sed -i 's/^ST_APACHE = .*/ST_APACHE = "1"/g' /etc/csf/csf.conf
sed -i 's/^CONNLIMIT = .*/CONNLIMIT = "80;70,110;50,993;50,143;50,25;30"/g' /etc/csf/csf.conf
sed -i 's/^LF_PERMBLOCK_INTERVAL = .*/LF_PERMBLOCK_INTERVAL = "14400"/g' /etc/csf/csf.conf
sed -i 's/^LF_INTERVAL = .*/LF_INTERVAL = "900"/g' /etc/csf/csf.conf
sed -i 's/^PS_INTERVAL = .*/PS_INTERVAL = "60"/g' /etc/csf/csf.conf
sed -i 's/^PS_LIMIT = .*/PS_LIMIT = "60"/g' /etc/csf/csf.conf
sed -i 's/^RESTRICT_SYSLOG = .*/RESTRICT_SYSLOG = "3"/g' /etc/csf/csf.conf
sed -i 's/^LF_SCRIPT_ALERT = .*/LF_SCRIPT_ALERT = "1"/g' /etc/csf/csf.conf
sed -i 's/^LF_CPANEL_ALERT = .*/LF_CPANEL_ALERT = "1"/g' /etc/csf/csf.conf
sed -i 's/^SYSLOG_CHECK = .*/SYSLOG_CHECK = "700"/g' /etc/csf/csf.conf
sed -i 's/LF_PERMBLOCK_COUNT = "4"/LF_PERMBLOCK_COUNT = "20"/' /etc/csf/csf.conf
sed -i 's/LF_SYMLINK = "0"/LF_SYMLINK = "2"/' /etc/csf/csf.conf
sed -i 's/LF_SYMLINK_PERM = "1"/LF_SYMLINK_PERM = "5"/' /etc/csf/csf.conf
sed -i 's/2095,2096"/2095,2096,49152:65534,1157"/' /etc/csf/csf.conf

echo "Disabling alerts..."

sed -i 's/^LF_PERMBLOCK_ALERT = .*/LF_PERMBLOCK_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^LF_NETBLOCK_ALERT = .*/LF_NETBLOCK_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^LF_EMAIL_ALERT = .*/LF_EMAIL_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^LF_QUEUE_ALERT = .*/LF_QUEUE_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^LF_DISTFTP_ALERT = .*/LF_DISTFTP_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^LF_DISTSMTP_ALERT = .*/LF_DISTSMTP_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^LT_EMAIL_ALERT = .*/LT_EMAIL_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^RT_RELAY_ALERT = .*/RT_RELAY_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^RT_AUTHRELAY_ALERT = .*/RT_AUTHRELAY_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^RT_POPRELAY_ALERT = .*/RT_POPRELAY_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^RT_LOCALRELAY_ALERT = .*/RT_LOCALRELAY_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^RT_LOCALHOSTRELAY_ALERT = .*/RT_LOCALHOSTRELAY_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^CT_EMAIL_ALERT = .*/CT_EMAIL_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^PT_USERKILL_ALERT = .*/PT_USERKILL_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^PS_EMAIL_ALERT = .*/PS_EMAIL_ALERT = "0"/g' /etc/csf/csf.conf
sed -i 's/^PT_USERMEM = .*/PT_USERMEM = "0"/g' /etc/csf/csf.conf
sed -i 's/^PT_USERTIME = .*/PT_USERTIME = "0"/g' /etc/csf/csf.conf
sed -i 's/^PT_USERPROC = .*/PT_USERPROC = "0"/g' /etc/csf/csf.conf
sed -i 's/^PT_USERRSS = .*/PT_USERRSS = "0"/g' /etc/csf/csf.conf

echo "Enabling blacklists..."
sed -i '/^#SPAMDROP/s/^#//' /etc/csf/csf.blocklists
sed -i '/^#SPAMEDROP/s/^#//' /etc/csf/csf.blocklists
sed -i '/^#DSHIELD/s/^#//' /etc/csf/csf.blocklists
sed -i '/^#HONEYPOT/s/^#//' /etc/csf/csf.blocklists
#sed -i '/^#MAXMIND/s/^#//' /etc/csf/csf.blocklists #FALSE POSITIVES
sed -i '/^#BDE|/s/^#//' /etc/csf/csf.blocklists

sed -i '/^SPAMDROP/s/|0|/|300|/' /etc/csf/csf.blocklists
sed -i '/^SPAMEDROP/s/|0|/|300|/' /etc/csf/csf.blocklists
sed -i '/^DSHIELD/s/|0|/|300|/' /etc/csf/csf.blocklists
sed -i '/^HONEYPOT/s/|0|/|300|/' /etc/csf/csf.blocklists
#sed -i '/^MAXMIND/s/|0|/|300|/' /etc/csf/csf.blocklists #FALSE POSITIVES
sed -i '/^BDE|/s/|0|/|300|/' /etc/csf/csf.blocklists

sed -i '/^TOR/s/^TOR/#TOR/' /etc/csf/csf.blocklists
sed -i '/^ALTTOR/s/^ALTTOR/#ALTTOR/' /etc/csf/csf.blocklists
sed -i '/^CIARMY/s/^CIARMY/#CIARMY/' /etc/csf/csf.blocklists
sed -i '/^BFB/s/^BFB/#BFB/' /etc/csf/csf.blocklists
sed -i '/^OPENBL/s/^OPENBL/#OPENBL/' /etc/csf/csf.blocklists
sed -i '/^BDEALL/s/^BDEALL/#BDEALL/' /etc/csf/csf.blocklists
	
cat > /etc/csf/csf.rignore << EOF
.cpanel.net
.googlebot.com
.crawl.yahoo.net
.search.msn.com
EOF

echo "Activating DYNDNS..."
sed -i 's/^DYNDNS = .*/DYNDNS = "300"/g' /etc/csf/csf.conf
sed -i 's/^DYNDNS_IGNORE = .*/DYNDNS_IGNORE = "1"/g' /etc/csf/csf.conf

echo "Adding a csf.dyndns..."
sed -i '/gmail.com/d' /etc/csf/csf.dyndns
sed -i '/public.pyzor.org/d' /etc/csf/csf.dyndns
echo "tcp|out|d=25|d=smtp.gmail.com" >> /etc/csf/csf.dyndns
echo "tcp|out|d=465|d=smtp.gmail.com" >> /etc/csf/csf.dyndns
echo "tcp|out|d=587|d=smtp.gmail.com" >> /etc/csf/csf.dyndns
echo "tcp|out|d=995|d=imap.gmail.com" >> /etc/csf/csf.dyndns
echo "tcp|out|d=993|d=imap.gmail.com" >> /etc/csf/csf.dyndns
echo "tcp|out|d=143|d=imap.gmail.com" >> /etc/csf/csf.dyndns
echo "udp|out|d=24441|d=public.pyzor.org" >> /etc/csf/csf.dyndns

csf -r
service lfd restart

echo "####### END CONFIGURING CSF #######"