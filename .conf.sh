#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
CWD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
HOSTNAME=$(hostname -f)
PASSV_PORT="50000:65534";
PASSV_MIN=$(echo $PASSV_PORT | cut -d':' -f1)
PASSV_MAX=$(echo $PASSV_PORT | cut -d':' -f2)
ISVPS=$(((dmidecode -t system 2>/dev/null | grep "Manufacturer" | grep -i 'VMware\|KVM\|Bochs\|Virtual\|HVM' > /dev/null) || [ -f /proc/vz/veinfo ]) && echo "SI" || echo "NO")
echo ""
echo ""
echo "	##      ##   ###      ###        ####        ##    ##         "
echo "	##    ##     ###      ###        ####        ##    ##         "
echo "	##   ##      ## ##  ## ##       ##  ##       ##    ##         "    
echo "	##    ##     ##   ##   ##      ##    ##      ##    ##         "   
echo "	##      ##   ##        ##     ##########     ##    ##         "   
echo "	##      ##   ##        ##    ##        ##    ##    ##         "   
echo "	##     ##    ##        ##   ##          ##   ##    ##      ## "   
echo "	##   ##      ##        ##  ##            ##  ##    ########## "   

echo ""
echo ""
echo "  ####################### cPanel Install in Best Configuration by ismail.info #######################  "
echo ""
echo ""
echo "installs L3 Admin cPanel (CTRL + C to cancel)"
sleep 10

echo "####### CPANEL PRE-CONFIGURATION ##########"
echo "####### Disabling yum-cron...########"
yum erase yum-cron -y
systemctl stop NetworkManager.service
systemctl disable NetworkManager.service
yum erase NetworkManager -y
yum install nano wget epel-release -y
yum install screen -y
yum clean all
echo "####### Required Files Installation Successful########"
sleep 3
mkdir /root/cpanel_profile
touch /root/cpanel_profile/cpanel.config
echo "mysql-version=10.3" > /root/cpanel_profile/cpanel.config
echo "#########Customization Has been Completed########"

echo "######### CONFIGURING DNS AND NETWORK ########"
NETWORK=$(route -n | awk '$1 == "0.0.0.0" {print $8}')
ETHCFG="/etc/sysconfig/network-scripts/ifcfg-$NETWORK"

sed -i '/^NM_CONTROLLED=.*/d' $ETHCFG
sed -i '/^DNS1=.*/d' $ETHCFG
sed -i '/^DNS2=.*/d' $ETHCFG
	
echo "Configuring network..."
echo "PEERDNS=no" >> $ETHCFG
echo "NM_CONTROLLED=no" >> $ETHCFG
echo "DNS1=127.0.0.1" >> $ETHCFG
echo "DNS2=8.8.8.8" >> $ETHCFG

echo "Rewriting /etc/resolv.conf..."
echo "nameserver 8.8.8.8" >> /etc/resolv.conf # Google
echo "nameserver 8.8.4.4" >> /etc/resolv.conf # Google
echo "######### END CONFIGURING DNS AND NETWORK ########"

#echo "Changing runlevel to 3 ... "# It brought some problems with CentOS 7.7: https://bugs.centos.org/view.php?id=16440
#systemctl isolate runlevel3.target
#systemctl set-default runlevel3.target

echo "####### INSTALLING CPANEL #######"
if [ -f /usr/local/cpanel/cpanel ]; then
        echo "cPanel already detected, not installed, only configured (CTRL + C to cancel)"
        sleep 10
else
	hostname -f > /root/hostname

        cd /home && curl -o latest -L https://securedownloads.cpanel.net/latest && sh latest --skip-cloudlinux
	
		echo "Waiting 5 minutes for you to finish installing remaining packages in the background to continue ..."
	        sleep 300
		
	whmapi1 sethostname hostname=$(cat /root/hostname) # Fix hostname change by cprapid.com cpanel v90 https://docs.cpanel.net/knowledge-base/dns/automatically-issued-hostnames/
	hostnamectl set-hostname $(cat /root/hostname)
	rm -f /root/hostname
fi
echo "####### END INSTALLING CPANEL #######"

	if [ -d /usr/local/cpanel/whostmgr/docroot/cgi/configserver/csf ] ; then
			echo "CSF is already installed on the server!";
		else
			echo -n "csf not detected! Would you like to install? (y/n) ";
			read yesno < /dev/tty
			if [ "x$yesno" = "xy" ] ; then
				/usr/bin/wget https://download.configserver.com/csf.tgz -O /usr/src/csf.tgz &>/dev/null
				/usr/bin/tar -xzf /usr/src/csf.tgz -C /usr/src && cd /usr/src/csf && sh install.sh &>/dev/null
				yum remove firewalld -y
				yum -y install iptables-services wget perl unzip net-tools perl-libwww-perl perl-LWP-Protocol-https perl-GDGraph
				/usr/bin/wget https://raw.githubusercontent.com/ismailh/CpanelWHM-PreConfig/main/csf.conf -O /etc/csf/csf.conf &>/dev/null
				cd /root && /usr/bin/rm -rf /usr/src/csf /usr/src/csf.tgz /usr/src/error_log &>/dev/null
			echo " Setting CSF..."

			
                    touch /etc/sysconfig/iptables
	                touch /etc/sysconfig/iptables6
	                systemctl start iptables
	                systemctl start ip6tables
	                systemctl enable iptables
	                systemctl enable ip6tables


			/usr/bin/systemctl restart csf &>/dev/null && /usr/bin/systemctl restart lfd &>/dev/null
				echo "Done! CSF successfully installed & Config !";

				
			else
				echo "Successfully skipped the installation of CSF.";
			fi
		fi
	if [ -d /usr/local/cpanel/whostmgr/docroot/cgi/configserver/cmc ] ; then
				echo "CMC is already installed on the server!";
			else
				echo -n "CMC not found! Would you like to install? (y/n) ";
				read yesno < /dev/tty
				if [ "x$yesno" = "xy" ] ; then
					/usr/bin/wget https://download.configserver.com/cmc.tgz -O /usr/src/cmc.tgz &>/dev/null
					/usr/bin/tar -xzf /usr/src/cmc.tgz -C /usr/src && cd /usr/src/cmc && /usr/bin/sh install.sh &>/dev/null
					cd /root && /usr/bin/rm -rf /usr/src/cmc /usr/src/cmc.tgz /usr/src/error_log &>/dev/null
					echo "Done! CMC successfully installed & enabled!";
				else
					echo "Successfully skipped the installation of CMC.";
				fi
			fi



	if [ -d /usr/local/cpanel/whostmgr/docroot/cgi/configserver/cmq ] ; then
				echo "CMQ is already installed on the server!";
			else
				echo -n "CMQ not found! Would you like to install? (y/n) ";
				read yesno < /dev/tty
				if [ "x$yesno" = "xy" ] ; then
					wget http://download.configserver.com/cmq.tgz -O /usr/src/cmq.tgz &>/dev/null
					/usr/bin/tar -xzf /usr/src/cmq.tgz -C /usr/src && cd /usr/src/cmq && /usr/bin/sh install.sh &>/dev/null
					cd /root && /usr/bin/rm -rf /usr/src/cmq /usr/src/cmq.tgz /usr/src/error_log &>/dev/null
					echo "Done! CMQ successfully installed & enabled!";
				else
					echo "Successfully skipped the installation of CMQ.";
				fi
			fi



	if [ -d /usr/local/cpanel/whostmgr/docroot/cgi/addons/accountdnscheck/ ] ; then
				echo "Account DNS Check is already installed on the server!";
			else
				echo -n "Account DNS Check not found! Would you like to install? (y/n) ";
				read yesno < /dev/tty
				if [ "x$yesno" = "xy" ] ; then

						cd /usr/src
					wget http://download.ndchost.com/accountdnscheck/latest-accountdnscheck
					sh latest-accountdnscheck
				echo "Done! Account DNS Check successfully installed & enabled!";
				else
					echo "Successfully skipped the installation of Account DNS Check.";
				fi
			fi




echo "Disabling IPv6 address on the server's network"
		grep -q '^net.ipv6.conf.all.disable_ipv6 = .*' /etc/sysctl.conf && grep -q '^net.ipv6.conf.default.disable_ipv6 = .*' /etc/sysctl.conf
		/usr/bin/sed -i 's/^net.ipv6.conf.all.disable_ipv6 = .*/net.ipv6.conf.all.disable_ipv6 = 1/' /etc/sysctl.conf
		/usr/bin/sed -i 's/^net.ipv6.conf.default.disable_ipv6 = .*/net.ipv6.conf.default.disable_ipv6 = 1/' /etc/sysctl.conf
		echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.conf && echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf
		/usr/sbin/sysctl -p &>/dev/null # make the settings effective
		
# Uninstallation of ImunifyAV from cPanel v88
		if [ -f /usr/bin/imunify-antivirus ]; then
			/usr/bin/wget https://repo.imunify360.cloudlinux.com/defence360/imav-deploy.sh -O /root/imav-deploy.sh &>/dev/null
			/usr/bin/chmod +x /root/imav-deploy.sh && /root/imav-deploy.sh --uninstall &>/dev/null && rm -f /root/imav-deploy.sh &>/dev/null
		fi		

if [ -f /usr/bin/imunify360-agent ] ; then
			echo "Imunify360 is already installed on the server!";
		else
			echo -n "Imunify360 not found! Would you like to install? (y/n) ";
			read yesno < /dev/tty
			if [ "x$yesno" = "xy" ] ; then
				/usr/bin/wget https://repo.imunify360.cloudlinux.com/defence360/i360deploy.sh -O /root/i360deploy.sh &>/dev/null
				/usr/bin/chmod +x /root/i360deploy.sh && sh /root/i360deploy.sh &>/dev/null
				cd /root && /usr/bin/rm -f /root/i360deploy.sh /root/error_log &>/dev/null
				echo "Done! Imunify360 successfully installed & enabled!";
			else
				echo "Successfully skipped the installation of Imunify360.";
			fi
		fi

if [ -d /usr/local/cpanel/whostmgr/docroot/cgi/softaculous ] ; then
			echo "Softaculous is already installed on the server!";
		else
			echo -n "Softaculous not found! Would you like to install? (y/n) ";
			read yesno < /dev/tty
			if [ "x$yesno" = "xy" ] ; then
				/usr/bin/sed -i -e \'s/127.0.0.1.*api.softaculous.com//g\' \'/etc/hosts\' &>/dev/null
				/usr/bin/sed -i \'/^$/d\' \'/etc/hosts\' &>/dev/null # Remove API from /etc/hosts File
				/usr/bin/wget https://files.softaculous.com/install.sh -O /root/install.sh &>/dev/null
				/usr/bin/chmod +x /root/install.sh && sh /root/install.sh &>/dev/null
				echo "Done! Softaculous successfully installed on your server!";
			else
				echo "Successfully skipped the installation of Softaculous.";
			fi
		fi

		if [ -d /usr/local/cpanel/3rdparty/wp-toolkit ] ; then
			echo "WP Toolkit is already installed on the server!";
		else
			echo -n "WP Toolkit not found! Would you like to install? (y/n) ";
			read yesno < /dev/tty
			if [ "x$yesno" = "xy" ] ; then
				/usr/bin/wget https://wp-toolkit.plesk.com/cPanel/installer.sh -O /root/installer.sh &>/dev/null
				/usr/bin/chmod +x /root/installer.sh && sh /root/installer.sh &>/dev/null
				echo "Done! WP Toolkit successfully installed on your server!";
			else
				echo "Successfully skipped the installation of WP Toolkit.";
			fi
		fi

		if [ -f /etc/redhat-release ] ; then
			echo "Shortly you'll be asked for the installation of JB";
			echo "Firstly, JetBackup4 & secondly JetBackup5 process.";
			echo "If you wish to install JetBackup5, please skip JB4.";
			if [ -d /usr/local/jetapps/var/lib/JetBackup/Core/ ] ; then
				echo "JetBackup 4 is already installed on the server!";
			else
				echo -n "JetBackup 4 not found! Would you like to install? (y/n) ";
				read yesno < /dev/tty
				if [ "x$yesno" = "xy" ] ; then
					/usr/bin/yum install https://repo.jetlicense.com/centOS/jetapps-repo-latest.rpm -y &>/dev/null
					/usr/bin/yum clean all --enablerepo=jetapps* &>/dev/null
					/usr/bin/yum install jetapps-cpanel --disablerepo=* --enablerepo=jetapps -y &>/dev/null
					/usr/bin/jetapps --install jetbackup stable &>/dev/null
					echo "Done! JetBackup 4 successfully installed on your server!";
				else
					echo "Successfully skipped the installation of JetBackup 4.";
				fi
			fi
		fi

		if [ -d /usr/local/jetapps/var/lib/jetbackup5/Core/ ] ; then
			echo "JetBackup 5 is already installed on the server!";
		else
			echo -n "JetBackup 5 not found! Would you like to install? (y/n) ";
			read yesno < /dev/tty
			if [ "x$yesno" = "xy" ] ; then
				/usr/bin/bash <(/usr/bin/curl -LSs https://repo.jetlicense.com/static/install) &>/dev/null
				/usr/bin/jetapps --install jetbackup5-cpanel stable &>/dev/null
				echo "Done! JetBackup 5 successfully installed on your server!";
			else
				echo "Successfully skipped the installation of JetBackup 5.";
			fi
		fi

		if [ -f /usr/local/lsws/admin/misc/lscmctl ] ; then
			echo "LiteSpeed is already installed on the server!";
		else
			echo -n "LiteSpeed not found! Would you like to install? (y/n) ";
			read yesno < /dev/tty
			if [ "x$yesno" = "xy" ] ; then
				touch /root/lsws-install.sh
				echo "serial_no="TRIAL"
php_suexec="2"
port_offset="1000"
admin_user="admin"
admin_pass="webhost321"
admin_email="root@localhost"
easyapache_integration="1"
auto_switch_to_lsws="1"
deploy_lscwp="0"" > "/root/lsws.options";
				/usr/bin/wget https://get.litespeed.sh -O /root/lsws-install.sh &>/dev/null
				/usr/bin/sh /root/lsws-install.sh TRIAL &>/dev/null
				/usr/bin/wget https://litespeedtech.com/packages/cpanel/buildtimezone_ea4.tar.gz -O /root/buildtimezone_ea4.tar.gz &>/dev/null
				/usr/bin/tar -xzvf /root/buildtimezone_ea4.tar.gz &>/dev/null
				/usr/bin/chmod a+x /root/buildtimezone*.sh && /root/buildtimezone_ea4.sh y &>/dev/null
				/usr/sbin/yum-complete-transaction --cleanup-only &>/dev/null
				/usr/bin/yum install ea-php*-php-devel -y --skip-broken 1> /dev/null
				/usr/bin/yum remove ea-apache24-mod_ruid2 -y &>/dev/null
				/usr/local/lsws/admin/misc/lscmctl cpanelplugin --install &>/dev/null
				/usr/local/lsws/admin/misc/lscmctl setcacheroot &>/dev/null
				/usr/local/lsws/admin/misc/lscmctl scan &>/dev/null
				/usr/local/lsws/admin/misc/lscmctl enable -m &>/dev/null
				/usr/bin/rm -f /root/buildtimezone* /root/lsws* &>/dev/null
				echo "Done! LiteSpeed successfully installed on your server!";
			else
				echo "Successfully skipped the installation of LiteSpeed.";
			fi
		fi

		if [ -f /etc/redhat-release ] ; then
			if [[ -f /usr/sbin/clnreg_ks && -f /usr/bin/cldetect ]] ; then
				echo "CloudLinux is already installed on the server!";
			else
				echo -n "CloudLinux not found! Would you like to install? (y/n) ";
				read yesno < /dev/tty
				if [ "x$yesno" = "xy" ] ; then
					/usr/bin/wget https://repo.cloudlinux.com/cloudlinux/sources/cln/cldeploy -O /root/cldeploy &>/dev/null
					cd /root && /usr/bin/sh cldeploy --skip-registration -k 999 &> /dev/null
					/usr/bin/yum install lvemanager -y &> /dev/null
					/usr/bin/yum groupinstall alt-php alt-nodejs alt-python alt-ruby -y &> /dev/null
					/usr/bin/yum install ea-apache24-mod_suexec -y &> /dev/null
					/usr/bin/yum install ea-apache24-mod-alt-passenger -y &> /dev/null
					/usr/bin/yum install grub2 --disableexcludes=all -y &> /dev/null
					/usr/bin/yum install cagefs -y &> /dev/null && /usr/sbin/cagefsctl –init &> /dev/null
					echo "Done! CloudLinux successfully installed on your server!";
				else
					echo "Successfully skipped the installation of CloudLinux.";
				fi
			fi
		fi

echo "####### SETTING CPANEL #######"

if [ ! -d /usr/local/cpanel ]; then
	echo "cPanel not detected. Aborting."
	exit 0
fi

HOSTNAME_LONG=$(hostname -d)

echo "DNS TTL down to 15 min..."
sed -i 's / ^ TTL . * / TTL 900 /' /etc/wwwacct.conf

echo "Changing contact email..."
sed -i '/^CONTACTEMAIL\ .*/d' /etc/wwwacct.conf
echo "CONTACTEMAIL hostmaster@$HOSTNAME_LONG" >> /etc/wwwacct.conf

echo "Changing default DNSs..."
sed -i '/^NS\ .*/d' /etc/wwwacct.conf
sed -i '/^NS2\ .*/d' /etc/wwwacct.conf
sed -i '/^NS3\ .*/d' /etc/wwwacct.conf
echo "NS ns1.$HOSTNAME_LONG" >> /etc/wwwacct.conf
echo "NS2 ns2.$HOSTNAME_LONG" >> /etc/wwwacct.conf

echo "Setting FTP..."
sed -i '/^MaxClientsPerIP:.*/d' / var / cpanel / conf / pureftpd / local; echo "MaxClientsPerIP: 30 " >> / var / cpanel / conf / pureftpd / local
sed -i '/^RootPassLogins:.*/d' / var / cpanel / conf / pureftpd / local; echo "RootPassLogins: 'no'" >> / var / cpanel / conf / pureftpd / local
sed -i '/^PassivePortRange:.*/d' / var / cpanel / conf / pureftpd / local; echo "PassivePortRange: $ PASSV_MIN  $ PASSV_MAX " >> / var / cpanel / conf / pureftpd / local
sed -i '/^TLSCipherSuite:.*/d' / var / cpanel / conf / pureftpd / local; echo 'TLSCipherSuite: "HIGH: MEDIUM: + TLSv 1 :! SSLv 2 : + SSLv 3 "' >> / var / cpanel / conf / pureftpd / local
sed -i '/^LimitRecursion:.*/d' / var / cpanel / conf / pureftpd / local; echo "LimitRecursion: 50000  12 " >> / var / cpanel / conf / pureftpd / local
echo "pure-ftpd  installed on the server."
/usr/local/cpanel/scripts/setupftpserver pure-ftpd --force &>/dev/null
		echo "Pure-FTP Installed & it has been initialized.";
		# Installing ionCube and SourceGuardian Loader
		/usr/bin/sed -i 's/phploader=.*/phploader=ioncube,sourceguardian/' /var/cpanel/cpanel.config
		/usr/local/cpanel/whostmgr/bin/whostmgr2 --updatetweaksettings &>/dev/null
		/usr/local/cpanel/bin/checkphpini &>/dev/null && /usr/local/cpanel/bin/install_php_inis &>/dev/null
		if [ -f /etc/redhat-release ]; then
			/usr/bin/yum install ea-php74-php-ioncube12 ea-php81-php-ioncube12 -y --skip-broken &>/dev/null
			/usr/bin/yum install ea-php*-php-sourceguardian ea-php*-php-ioncube10 -y --skip-broken &>/dev/null
		elif [ -f /etc/lsb-release ]; then
			/usr/bin/apt install ea-php74-php-ioncube12 ea-php81-php-ioncube12 -y &>/dev/null
			/usr/bin/apt install ea-php*-php-sourceguardian ea-php*-php-ioncube10 -y &>/dev/null
		fi
 echo "ionCube and SourceGuardian Loader config.";       

echo "Activating module ip_conntrack_ftp..."
modprobe ip_conntrack_ftp
echo "modprobe ip_conntrack_ftp" >> /etc/rc.modules
chmod +x /etc/rc.modules


echo "Setting Tweak Settings..."
whmapi1 set_tweaksetting key=allowremotedomains value=1
whmapi1 set_tweaksetting key=allowunregistereddomains value=1
whmapi1 set_tweaksetting key=chkservd_check_interval value=120
whmapi1 set_tweaksetting key=defaultmailaction value=fail
whmapi1 set_tweaksetting key=email_send_limits_max_defer_fail_percentage value=25
whmapi1 set_tweaksetting key=email_send_limits_min_defer_fail_to_trigger_protection value=15
whmapi1 set_tweaksetting key=maxemailsperhour value=200
whmapi1 set_tweaksetting key=permit_unregistered_apps_as_root value=1
whmapi1 set_tweaksetting key=requiressl value=0
whmapi1 set_tweaksetting key=skipanalog value=1
whmapi1 set_tweaksetting key=skipboxtrapper value=1
whmapi1 set_tweaksetting key=skipwebalizer value=1
whmapi1 set_tweaksetting key=smtpmailgidonly value=0
whmapi1 set_tweaksetting key=eximmailtrap value=1
whmapi1 set_tweaksetting key=use_information_schema value=0
whmapi1 set_tweaksetting key=cookieipvalidation value=disabled
whmapi1 set_tweaksetting key=notify_expiring_certificates value=0
whmapi1 set_tweaksetting key=cpaddons_notify_owner value=0
whmapi1 set_tweaksetting key=cpaddons_notify_root value=0
whmapi1 set_tweaksetting key=enable_piped_logs value=1
whmapi1 set_tweaksetting key=email_outbound_spam_detect_action value=block
whmapi1 set_tweaksetting key=email_outbound_spam_detect_enable value=1
whmapi1 set_tweaksetting key=email_outbound_spam_detect_threshold value=120
whmapi1 set_tweaksetting key=skipspambox value=0
whmapi1 set_tweaksetting key=skipmailman value=1
whmapi1 set_tweaksetting key=jaildefaultshell value=1
whmapi1 set_tweaksetting key=php_post_max_size value=100
whmapi1 set_tweaksetting key=php_upload_max_filesize value=100
whmapi1 set_tweaksetting key=empty_trash_days value=30
whmapi1 set_tweaksetting key=publichtmlsubsonly value=0
whmapi1 set_tweaksetting key=phploader value=ioncube
whmapi1 set_tweaksetting key=cookieipvalidation value=strict
whmapi1 set_tweaksetting key=referrerblanksafety value=1
whmapi1 set_tweaksetting key=referrersafety value=1
whmapi1 set_tweaksetting key=cgihidepass value=1

echo"BG Process Killer"

cp /var/cpanel/killproc.conf    /var/cpanel/killproc.conf.beforetweak
echo "services" > /var/cpanel/killproc.conf
echo "ptlink" >> /var/cpanel/killproc.conf
echo "psyBNC" >> /var/cpanel/killproc.conf
echo "ircd" >> /var/cpanel/killproc.conf
echo "guardservices" >> /var/cpanel/killproc.conf
echo "generic-sniffers" >> /var/cpanel/killproc.conf
echo "eggdrop" >> /var/cpanel/killproc.conf
echo "bnc" >> /var/cpanel/killproc.conf
echo "BitchX" >> /var/cpanel/killproc.conf


echo "Disable Compiler Access"
chmod 750 /usr/bin/gcc 
chown root:compiler /usr/bin/gcc 



# DEACTIVATE PASSWORD RESET BY MAIL
whmapi1 set_tweaksetting key=resetpass value=0
whmapi1 set_tweaksetting key=resetpass_sub value=0

sed -i 's/^phpopenbasedirhome=.*/phpopenbasedirhome=1/' /var/cpanel/cpanel.config
sed -i 's/^minpwstrength=.*/minpwstrength=70/' /var/cpanel/cpanel.config

/usr/local/cpanel/etc/init/startcpsrvd

# CONFIGURATIONS THAT CANNOT BE DONE BY CONSOLE
echo "Configuring the inconfigurable from console..."
yum install -y curl

touch $CWD/wpwhmcookie.txt
SESS_CREATE=$(whmapi1 create_user_session user=root service=whostmgrd)
SESS_TOKEN=$(echo "$SESS_CREATE" | grep "cp_security_token:" | cut -d':' -f2- | sed 's/ //')
SESS_QS=$(echo "$SESS_CREATE" | grep "session:" | cut -d':' -f2- | sed 's/ //' | sed 's/ /%20/g;s/!/%21/g;s/"/%22/g;s/#/%23/g;s/\$/%24/g;s/\&/%26/g;s/'\''/%27/g;s/(/%28/g;s/)/%29/g;s/:/%3A/g')

curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/login/?session=$SESS_QS" --cookie-jar $CWD/wpwhmcookie.txt > /dev/null

echo "Disabling compilers..."
curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/tweakcompilers" --cookie $CWD/wpwhmcookie.txt --data 'action=Disable+Compilers' > /dev/null
echo "Disabling SMTP Restrictions (se usa CSF)..."
curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/smtpmailgidonly?action=Disable" --cookie $CWD/wpwhmcookie.txt > /dev/null
echo "Disabling Shell Fork Bomb Protection..."
curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/modlimits?limits=0" --cookie $CWD/wpwhmcookie.txt > /dev/null
echo "Enabling Background Process Killer..."
curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/json-api/configurebackgroundprocesskiller" --cookie $CWD/wpwhmcookie.txt --data 'api.version=1&processes_to_kill=BitchX&processes_to_kill=bnc&processes_to_kill=eggdrop&processes_to_kill=generic-sniffers&processes_to_kill=guardservices&processes_to_kill=ircd&processes_to_kill=psyBNC&processes_to_kill=ptlink&processes_to_kill=services&force=1' > /dev/null

echo "Setting Apache..."
# BASIC CONFIG
curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/saveglobalapachesetup" --cookie $CWD/wpwhmcookie.txt --data 'module=Apache&find=&___original_sslciphersuite=ECDHE-ECDSA-AES256-GCM-SHA384%3AECDHE-RSA-AES256-GCM-SHA384%3AECDHE-ECDSA-CHACHA20-POLY1305%3AECDHE-RSA-CHACHA20-POLY1305%3AECDHE-ECDSA-AES128-GCM-SHA256%3AECDHE-RSA-AES128-GCM-SHA256%3AECDHE-ECDSA-AES256-SHA384%3AECDHE-RSA-AES256-SHA384%3AECDHE-ECDSA-AES128-SHA256%3AECDHE-RSA-AES128-SHA256&sslciphersuite_control=default&___original_sslprotocol=TLSv1.2&sslprotocol_control=default&___original_loglevel=warn&loglevel=warn&___original_traceenable=Off&traceenable=Off&___original_serversignature=Off&serversignature=Off&___original_servertokens=ProductOnly&servertokens=ProductOnly&___original_fileetag=None&fileetag=None&___original_root_options=&root_options=FollowSymLinks&root_options=IncludesNOEXEC&root_options=SymLinksIfOwnerMatch&___original_startservers=5&startservers_control=default&___original_minspareservers=5&minspareservers_control=default&___original_maxspareservers=10&maxspareservers_control=default&___original_optimize_htaccess=search_homedir_below&optimize_htaccess=search_homedir_below&___original_serverlimit=256&serverlimit_control=default&___original_maxclients=150&maxclients_control=other&maxclients_other=100&___original_maxrequestsperchild=10000&maxrequestsperchild_control=default&___original_keepalive=On&keepalive=1&___original_keepalivetimeout=5&keepalivetimeout_control=default&___original_maxkeepaliverequests=100&maxkeepaliverequests_control=default&___original_timeout=300&timeout_control=default&___original_symlink_protect=Off&symlink_protect=0&its_for_real=1' > /dev/null

# DIRECTORYINDEX
curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/save_apache_directoryindex" --cookie $CWD/wpwhmcookie.txt --data 'valid_submit=1&dirindex=index.php&dirindex=index.php5&dirindex=index.php4&dirindex=index.php3&dirindex=index.perl&dirindex=index.pl&dirindex=index.plx&dirindex=index.ppl&dirindex=index.cgi&dirindex=index.jsp&dirindex=index.jp&dirindex=index.phtml&dirindex=index.shtml&dirindex=index.xhtml&dirindex=index.html&dirindex=index.htm&dirindex=index.wml&dirindex=Default.html&dirindex=Default.htm&dirindex=default.html&dirindex=default.htm&dirindex=home.html&dirindex=home.htm&dirindex=index.js' > /dev/null

curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/save_apache_mem_limits" --cookie $CWD/wpwhmcookie.txt --data 'newRLimitMem=enabled&newRLimitMemValue=1024&restart_apache=on&btnSave=1' > /dev/null

/scripts/rebuildhttpdconf
service httpd restart

# DOVECOT
curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/savedovecotsetup" --cookie $ CWD / wpwhmcookie.txt --data 'protocols_enabled_imap = on & protocols_enabled_pop3 = on & ipv6 = on & enable_plaintext_auth = yes & yesssl_cipher_list = ECDHE-ECDSA-CHACHA20-POLY1305% 3AECDHE-RSA-CHACHA20-POLY1305% 3AECDHE-ECDSA-AES128-GCM-SHA256% 3AECDHE-RSA-AES128-GCM-SHA256% -AECA-6A GCA-6A GCA-6A GCA-6A-GCA-6A GCA-6A-GCAA6E-GCA-6A GCA-6A-GCAA6E-GCAA6E-GCAA6E-GCAA6E-GCAA6E-GCAA6E-A6A-GCAA6E-GCAA6E-GCAA6E-GCAA6E-GCAA6E-GCAA6E-GCAA6A-GCAA6E-GCAA6E-GCAA6A-GCAA6E-GCAA6A-GCAA6E-6% GCA-A6D RSA-AES256-GCM-SHA384% 3ADHE-RSA-AES128-GCM-SHA256% 3ADHE-RSA-AES256-GCM-SHA384% 3AECDHE-ECDSA-AES128-SHA256% 3AECDHE-RSA-AES128-SHA256-ECA-AES128-ECA-AES128-ECA-AES128-ECA-AES128-ECA-AES128-ECA-AES128-ECA-AES128-ECA-AES128-ECA-AES128-ECA-AES128-ECA-AES128-ECA-AES128-ECA-AES128-ECA-AES128-ECA-AES128-SHA256 SHA% 3AECDHE-RSA-AES256-SHA384% 3AECDHE-RSA-AES128-SHA% 3AECDHE-ECDSA-AES256-SHA384% 3AECDHE-ECDSA-AES256-SHA% 3AECDHE-RSA-AES256-SHA% 3ADHE-RSA-AES128-SHA256% 3ADHE-RSA-AES128-SHA% 3ADHE-RSA-AES256-SHA256% 3ADHE-RSA-AES256-SHA% 3AECDHE-ECDSA-DES-CBC3-SHA% 3AECDHE-RSA-DES-CBC3-SHA% 3AEDH-RSA-RSA-RSA-RSA-RSA CBC3-SHA% 3AAES128-GCM-SHA256% 3AAES256-GCM-SHA384% 3AAES128-SHA256% 3AAES256-SHA256% 3AAES128-SHA% 3AAES256-SHA% 3ADES-CBC3-SHA% 3A% 21DSS & ssl_min_protocol = TLSv1 & max_mail_processes = 512 & mail_process_size = 512 & protocol_imap.mail_max_userip_connections = 20 protocol_imap.imap_idle_notify_interval & = 24 & protocol_pop3.mail_max_userip_connections = 3 & login_processes_count = 2 & login_max_processes_count = 50 & login_process_size = 128 & auth_cache_size = 1M & auth_cache_ttl = 3600 & auth_cache_negative_ttl = 3600 & login_process_per_connection = no & config_vsz_limit = 2048 mailbox_idle_check_interval & = 30 & mdbox_rotate_size = 10M & mdbox_rotate_interval = 0 & incoming_reached_quota = bounce & lmtp_process_min_avail = 0 & lmtp_process_limit = 500 & lmtp_user_concurrency_limit = 4 & expire_trash = 1 & expire_trash_ttl = 30 & include_trash_in_quota = 1 'auth_cache_size = 1M & auth_cache_ttl = 3600 & auth_cache_negative_ttl = 3600 & login_process_per_connection = no & config_vsz_limit = 2048 mailbox_idle_check_interval & = 30 & mdbox_rotate_size = 10M & mdbox_rotate_interval = 0 & incoming_reached_quota = bounce & lmtp_process_min_avail = 0 & lmtp_process_limit = 500 & lmtp_user_concurrency_limit = 4 & expire_trash = 1 & expire_trash_ttl = 30 & include_trash_in_quota = 1 'auth_cache_size = 1M & auth_cache_ttl = 3600 & auth_cache_negative_ttl = 3600 & login_process_per_connection = no & config_vsz_limit = 2048 mailbox_idle_check_interval & = 30 & mdbox_rotate_size = 10M & mdbox_rotate_interval = 0 & incoming_reached_quota = bounce & lmtp_process_min_avail = 0 & lmtp_process_limit = 500 & lmtp_user_concurrency_limit = 4 & expire_trash = 1 & expire_trash_ttl = 30 & include_trash_in_quota = 1 '

# EXIM
curl -sk "https://127.0.0.1:2087/$SESS_TOKEN/scripts2/saveeximtweaks" --cookie $COOKIE_FILE --data 'in_tab=1&module=Mail&find=&___original_acl_deny_spam_score_over_int=&___undef_original_acl_deny_spam_score_over_int=1&acl_deny_spam_score_over_int_control=undef&___original_acl_dictionary_attack=1&acl_dictionary_attack=1&___original_acl_primary_hostname_bl=0&acl_primary_hostname_bl=0&___original_acl_spam_scan_secondarymx=1&acl_spam_scan_secondarymx=1&___original_acl_ratelimit=1&acl_ratelimit=1&___original_acl_ratelimit_spam_score_over_int=&___undef_original_acl_ratelimit_spam_score_over_int=1&acl_ratelimit_spam_score_over_int_control=undef&___original_acl_slow_fail_block=1&acl_slow_fail_block=1&___original_acl_requirehelo=1&acl_requirehelo=1&___original_acl_delay_unknown_hosts=1&acl_delay_unknown_hosts=1&___original_acl_dont_delay_greylisting_trusted_hosts=1&acl_dont_delay_greylisting_trusted_hosts=1&___original_acl_dont_delay_greylisting_common_mail_providers=0&acl_dont_delay_greylisting_common_mail_providers=0&___original_acl_requirehelonoforge=1&acl_requirehelonoforge=1&___original_acl_requirehelonold=0&acl_requirehelonold=0&___original_acl_requirehelosyntax=1&acl_requirehelosyntax=1&___original_acl_dkim_disable=1&acl_dkim_disable=1&___original_acl_dkim_bl=0&___original_acl_deny_rcpt_soft_limit=&___undef_original_acl_deny_rcpt_soft_limit=1&acl_deny_rcpt_soft_limit_control=undef&___original_acl_deny_rcpt_hard_limit=&___undef_original_acl_deny_rcpt_hard_limit=1&acl_deny_rcpt_hard_limit_control=undef&___original_spammer_list_ips_button=&___undef_original_spammer_list_ips_button=1&___original_sender_verify_bypass_ips_button=&___undef_original_sender_verify_bypass_ips_button=1&___original_trusted_mail_hosts_ips_button=&___undef_original_trusted_mail_hosts_ips_button=1&___original_skip_smtp_check_ips_button=&___undef_original_skip_smtp_check_ips_button=1&___original_backup_mail_hosts_button=&___undef_original_backup_mail_hosts_button=1&___original_trusted_mail_users_button=&___undef_original_trusted_mail_users_button=1&___original_blocked_domains_button=&___undef_original_blocked_domains_button=1&___original_filter_emails_by_country_button=&___undef_original_filter_emails_by_country_button=1&___original_per_domain_mailips=1&per_domain_mailips=1&___original_custom_mailhelo=0&___original_custom_mailips=0&___original_systemfilter=%2Fetc%2Fcpanel_exim_system_filter&systemfilter_control=default&___original_filter_attachments=1&filter_attachments=1&___original_filter_spam_rewrite=1&filter_spam_rewrite=1&___original_filter_fail_spam_score_over_int=&___undef_original_filter_fail_spam_score_over_int=1&filter_fail_spam_score_over_int_control=undef&___original_spam_header=***SPAM***&spam_header_control=default&___original_acl_0tracksenders=0&acl_0tracksenders=0&___original_callouts=0&callouts=0&___original_smarthost_routelist=&smarthost_routelist_control=default&___original_smarthost_autodiscover_spf_include=1&smarthost_autodiscover_spf_include=1&___original_spf_include_hosts=&spf_include_hosts_control=default&___original_rewrite_from=disable&rewrite_from=disable&___original_hiderecpfailuremessage=0&hiderecpfailuremessage=0&___original_malware_deferok=1&malware_deferok=1&___original_senderverify=1&senderverify=1&___original_setsenderheader=0&setsenderheader=0&___original_spam_deferok=1&spam_deferok=1&___original_srs=0&srs=0&___original_query_apache_for_nobody_senders=1&query_apache_for_nobody_senders=1&___original_trust_x_php_script=1&trust_x_php_script=1&___original_dsn_advertise_hosts=&___undef_original_dsn_advertise_hosts=1&dsn_advertise_hosts_control=undef&___original_smtputf8_advertise_hosts=&___undef_original_smtputf8_advertise_hosts=1&smtputf8_advertise_hosts_control=undef&___original_manage_rbls_button=&___undef_original_manage_rbls_button=1&___original_acl_spamcop_rbl=1&acl_spamcop_rbl=1&___original_acl_spamhaus_rbl=1&acl_spamhaus_rbl=1&___original_rbl_whitelist_neighbor_netblocks=1&rbl_whitelist_neighbor_netblocks=1&___original_rbl_whitelist_greylist_common_mail_providers=1&rbl_whitelist_greylist_common_mail_providers=1&___original_rbl_whitelist_greylist_trusted_netblocks=0&rbl_whitelist_greylist_trusted_netblocks=0&___original_rbl_whitelist=&rbl_whitelist=&___original_allowweakciphers=1&allowweakciphers=1&___original_require_secure_auth=0&require_secure_auth=0&___original_openssl_options=+%2Bno_sslv2+%2Bno_sslv3&openssl_options_control=other&openssl_options_other=+%2Bno_sslv2+%2Bno_sslv3&___original_tls_require_ciphers=ECDHE-ECDSA-CHACHA20-POLY1305%3AECDHE-RSA-CHACHA20-POLY1305%3AECDHE-ECDSA-AES128-GCM-SHA256%3AECDHE-RSA-AES128-GCM-SHA256%3AECDHE-ECDSA-AES256-GCM-SHA384%3AECDHE-RSA-AES256-GCM-SHA384%3ADHE-RSA-AES128-GCM-SHA256%3ADHE-RSA-AES256-GCM-SHA384%3AECDHE-ECDSA-AES128-SHA256%3AECDHE-RSA-AES128-SHA256%3AECDHE-ECDSA-AES128-SHA%3AECDHE-RSA-AES256-SHA384%3AECDHE-RSA-AES128-SHA%3AECDHE-ECDSA-AES256-SHA384%3AECDHE-ECDSA-AES256-SHA%3AECDHE-RSA-AES256-SHA%3ADHE-RSA-AES128-SHA256%3ADHE-RSA-AES128-SHA%3ADHE-RSA-AES256-SHA256%3ADHE-RSA-AES256-SHA%3AECDHE-ECDSA-DES-CBC3-SHA%3AECDHE-RSA-DES-CBC3-SHA%3AEDH-RSA-DES-CBC3-SHA%3AAES128-GCM-SHA256%3AAES256-GCM-SHA384%3AAES128-SHA256%3AAES256-SHA256%3AAES128-SHA%3AAES256-SHA%3ADES-CBC3-SHA%3A%21DSS&tls_require_ciphers_control=other&tls_require_ciphers_other=ECDHE-ECDSA-CHACHA20-POLY1305%3AECDHE-RSA-CHACHA20-POLY1305%3AECDHE-ECDSA-AES128-GCM-SHA256%3AECDHE-RSA-AES128-GCM-SHA256%3AECDHE-ECDSA-AES256-GCM-SHA384%3AECDHE-RSA-AES256-GCM-SHA384%3ADHE-RSA-AES128-GCM-SHA256%3ADHE-RSA-AES256-GCM-SHA384%3AECDHE-ECDSA-AES128-SHA256%3AECDHE-RSA-AES128-SHA256%3AECDHE-ECDSA-AES128-SHA%3AECDHE-RSA-AES256-SHA384%3AECDHE-RSA-AES128-SHA%3AECDHE-ECDSA-AES256-SHA384%3AECDHE-ECDSA-AES256-SHA%3AECDHE-RSA-AES256-SHA%3ADHE-RSA-AES128-SHA256%3ADHE-RSA-AES128-SHA%3ADHE-RSA-AES256-SHA256%3ADHE-RSA-AES256-SHA%3AECDHE-ECDSA-DES-CBC3-SHA%3AECDHE-RSA-DES-CBC3-SHA%3AEDH-RSA-DES-CBC3-SHA%3AAES128-GCM-SHA256%3AAES256-GCM-SHA384%3AAES128-SHA256%3AAES256-SHA256%3AAES128-SHA%3AAES256-SHA%3ADES-CBC3-SHA%3A%21DSS&___original_globalspamassassin=0&globalspamassassin=0&___original_max_spam_scan_size=1000&max_spam_scan_size_control=default&___original_acl_outgoing_spam_scan=0&acl_outgoing_spam_scan=0&___original_acl_outgoing_spam_scan_over_int=&___undef_original_acl_outgoing_spam_scan_over_int=1&acl_outgoing_spam_scan_over_int_control=undef&___original_no_forward_outbound_spam=0&no_forward_outbound_spam=0&___original_no_forward_outbound_spam_over_int=&___undef_original_no_forward_outbound_spam_over_int=1&no_forward_outbound_spam_over_int_control=undef&___original_spamassassin_plugin_BAYES_POISON_DEFENSE=1&spamassassin_plugin_BAYES_POISON_DEFENSE=1&___original_spamassassin_plugin_P0f=1&spamassassin_plugin_P0f=1&___original_spamassassin_plugin_KAM=1&spamassassin_plugin_KAM=1&___original_spamassassin_plugin_CPANEL=1&spamassassin_plugin_CPANEL=1'

# ACTIVATE BIND INSTEAD OF POWERDNS
-sk curl "https://127.0.0.1:2087/$SESS_TOKEN/scripts/doconfigurenameserver nameserver = bind" --cookie $ COOKIE_FILE

# REMOVE COOKIE
rm -f $CWD/wpwhmcookie.txt

echo "SETTING exim..."
/usr/bin/sed -i 's/^acl_spamhaus_rbl=.*/acl_spamhaus_rbl=1/' /etc/exim.conf.localopts
/usr/bin/sed -i 's/^acl_spamcop_rbl=.*/acl_spamcop_rbl=1/' /etc/exim.conf.localopts
/usr/bin/sed -i 's/^require_secure_auth=.*/require_secure_auth=0/' /etc/exim.conf.localopts
/usr/bin/sed -i 's/^acl_spamcop_rbl=.*/acl_spamcop_rbl=1/' /etc/exim.conf.localopts
/usr/bin/sed -i 's/^allowweakciphers=.*/allowweakciphers=1/' /etc/exim.conf.localopts
/usr/bin/sed -i 's/^per_domain_mailips=.*/per_domain_mailips=1/' /etc/exim.conf.localopts # IT SEEMS TO HAVE A BUG WHEIN IT IS CONFIGUERD WITH CURL
/usr/bin/sed -i 's/^max_spam_scan_size=.*/max_spam_scan_size=1000/' /etc/exim.conf.localopts
/usr/bin/sed -i 's/^openssl_options=.*/openssl_options= +no_sslv2 +no_sslv3/' /etc/exim.conf.localopts
/usr/bin/sed -i 's/^tls_require_ciphers=.*/tls_require_ciphers=ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS/' /etc/exim.conf.localopts

# Installing PHP extensions for popular CMS
		if [ -f /etc/redhat-release ]; then
			/usr/bin/yum install ea-php*-php-xmlrpc ea-php*-php-soap ea-php*-php-iconv ea-php*-php-mbstring -y &>/dev/null
			/usr/bin/yum install ea-php*-php-gmp ea-php*-php-bcmath ea-php*-php-intl ea-php*-php-fileinfo -y &>/dev/null
			/usr/bin/yum install ea-php*-php-pdo ea-php*-php-imap ea-php*-php-ldap ea-php*-php-zip -y &>/dev/null
		elif [ -f /etc/lsb-release ]; then
			/usr/bin/apt install ea-php*-php-xmlrpc ea-php*-php-soap ea-php*-php-iconv ea-php*-php-mbstring -y &>/dev/null
			/usr/bin/apt install ea-php*-php-gmp ea-php*-php-bcmath ea-php*-php-intl ea-php*-php-fileinfo -y &>/dev/null
			/usr/bin/apt install ea-php*-php-pdo ea-php*-php-imap ea-php*-php-ldap ea-php*-php-zip -y &>/dev/null
		fi

# Increasing php.ini limitations for all EA-PHP
/usr/bin/sed -i 's/disable_functions = .*/disable_functions = /' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null
/usr/bin/sed -i 's/max_execution_time = .*/max_execution_time = 200/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null
/usr/bin/sed -i 's/max_input_time = .*/max_input_time = 200/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null
/usr/bin/sed -i 's/max_input_vars = .*/max_input_vars = 3000/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null
/usr/bin/sed -i 's/memory_limit = .*/memory_limit = 248M/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null
/usr/bin/sed -i 's/post_max_size = .*/post_max_size = 100M/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null
/usr/bin/sed -i 's/upload_max_filesize = .*/upload_max_filesize = 100M/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null
/usr/bin/sed -i 's/allow_url_fopen = .*/allow_url_fopen = On/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null
/usr/bin/sed -i 's/file_uploads = .*/file_uploads = On/' /opt/cpanel/ea-php*/root/etc/php.ini &>/dev/null
/usr/local/cpanel/whostmgr/bin/whostmgr2 --updatetweaksettings &>/dev/null
/usr/local/cpanel/scripts/restartsrv_cpsrvd &>/dev/null # Restarting cPanel to save the changes
/usr/local/cpanel/bin/install-login-profile --install limits &>/dev/null # Enabling Shell Fork Bomb Protection

# Performing Tweak Settings for cPanel server
/usr/bin/sed -i 's/allowremotedomains=.*/allowremotedomains=1/' /var/cpanel/cpanel.config &>/dev/null
/usr/bin/sed -i 's/resetpass=.*/resetpass=0/' /var/cpanel/cpanel.config &>/dev/null
/usr/bin/sed -i 's/resetpass_sub=.*/resetpass_sub=0/' /var/cpanel/cpanel.config &>/dev/null
/usr/bin/sed -i 's/enforce_user_account_limits=.*/enforce_user_account_limits=1/' /var/cpanel/cpanel.config &>/dev/null
/usr/bin/sed -i 's/publichtmlsubsonly=.*/publichtmlsubsonly=0/' /var/cpanel/cpanel.config &>/dev/null
/usr/bin/sed -i 's/emailusers_diskusage_warn_contact_admin=.*/emailusers_diskusage_warn_contact_admin=1/' /var/cpanel/cpanel.config &>/dev/null
/usr/bin/sed -i 's/maxemailsperhour=.*/maxemailsperhour=50/' /var/cpanel/cpanel.config &>/dev/null
/usr/bin/sed -i 's/emailsperdaynotify=.*/emailsperdaynotify=1000/' /var/cpanel/cpanel.config &>/dev/null
/usr/bin/sed -i 's/exim-retrytime=.*/exim-retrytime=30/' /var/cpanel/cpanel.config &>/dev/null
/usr/bin/sed -i 's/mycnf_auto_adjust_innodb_buffer_pool_size=.*/mycnf_auto_adjust_innodb_buffer_pool_size=1/' /var/cpanel/cpanel.config &>/dev/null
/usr/local/cpanel/whostmgr/bin/whostmgr2 --updatetweaksettings &>/dev/null
/usr/local/cpanel/scripts/restartsrv_cpsrvd &>/dev/null # Restarting cPanel to save the changes

# LIMIT OF ATTACHMENTS
sed -i '/^message_size_limit.*/d' /etc/exim.conf.local
if grep "@CONFIG@" /etc/exim.conf.local > /dev/null; then
        sed -i '/@CONFIG@/ a message_size_limit = 25M' /etc/exim.conf.local
else
        echo "@CONFIG@" >> /etc/exim.conf.local
        echo "" >> /etc/exim.conf.local
        sed -i '/@CONFIG@/ a message_size_limit = 25M' /etc/exim.conf.local
fi

/scripts/buildeximconf
echo "Installing EasyApache 4 PHP packages..."
yum install -y \
ea-apache24-mod_proxy_fcgi \
libcurl-devel \
openssl-devel \
unixODBC \
ea-apache24-mod_version \
ea-apache24-mod_env \
ea-php55-php-curl \
ea-php55-php-fileinfo \
ea-php55-php-fpm \
ea-php55-php-gd \
ea-php55-php-iconv \
ea-php55-php-ioncube \
ea-php55-php-intl \
ea-php55-php-mbstring \
ea-php55-php-mcrypt \
ea-php55-php-pdo \
ea-php55-php-soap \
ea-php55-php-zip \
ea-php55-php-mysqlnd \
ea-php55-php-exif \
ea-php55-php-xmlrpc \
ea-php55-php-gmp \
ea-php55-php-gettext \
ea-php55-php-fpm \
ea-php55-php-xml \
ea-php55-php-bcmath \
ea-php55-php-imap \
ea-php56-php-curl \
ea-php56-php-fileinfo \
ea-php56-php-fpm \
ea-php56-php-gd \
ea-php56-php-iconv \
ea-php56-php-ioncube \
ea-php56-php-intl \
ea-php56-php-mbstring \
ea-php56-php-mcrypt \
ea-php56-php-pdo \
ea-php56-php-soap \
ea-php56-php-zip \
ea-php56-php-opcache \
ea-php56-php-mysqlnd \
ea-php56-php-bcmath \
ea-php56-php-exif \
ea-php56-php-xmlrpc \
ea-php56-php-gettext \
ea-php56-php-gmp \
ea-php56-php-fpm \
ea-php56-php-xml \
ea-php56-php-imap \
ea-php70-php-curl \
ea-php70-php-fileinfo \
ea-php70-php-fpm \
ea-php70-php-gd \
ea-php70-php-iconv \
ea-php70-php-intl \
ea-php70-php-mbstring \
ea-php70-php-mcrypt \
ea-php70-php-pdo \
ea-php70-php-soap \
ea-php70-php-xmlrpc \
ea-php70-php-xml \
ea-php70-php-zip \
ea-php70-php-ioncube10 \
ea-php70-php-opcache \
ea-php70-php-mysqlnd \
ea-php70-php-bcmath \
ea-php70-php-exif \
ea-php70-php-gettext \
ea-php70-php-gmp \
ea-php70-php-fpm \
ea-php70-php-imap \
ea-php71 \
ea-php71-pear \
ea-php71-php-cli \
ea-php71-php-common \
ea-php71-php-curl \
ea-php71-php-devel \
ea-php71-php-exif \
ea-php71-php-fileinfo \
ea-php71-php-fpm \
ea-php71-php-ftp \
ea-php71-php-gd \
ea-php71-php-iconv \
ea-php71-php-intl \
ea-php71-php-litespeed \
ea-php71-php-mbstring \
ea-php71-php-mcrypt \
ea-php71-php-mysqlnd \
ea-php71-php-odbc \
ea-php71-php-opcache \
ea-php71-php-pdo \
ea-php71-php-posix \
ea-php71-php-soap \
ea-php71-php-zip \
ea-php71-runtime \
ea-php71-php-bcmath \
ea-php71-php-ioncube10 \
ea-php71-php-xmlrpc \
ea-php71-php-gettext \
ea-php71-php-gmp \
ea-php71-php-xml \
ea-php71-php-imap \
ea-php72 \
ea-php72-pear \
ea-php72-php-cli \
ea-php72-php-common \
ea-php72-php-curl \
ea-php72-php-devel \
ea-php72-php-exif \
ea-php72-php-fileinfo \
ea-php72-php-fpm \
ea-php72-php-ftp \
ea-php72-php-gd \
ea-php72-php-iconv \
ea-php72-php-intl \
ea-php72-php-litespeed \
ea-php72-php-mbstring \
ea-php72-php-mysqlnd \
ea-php72-php-opcache \
ea-php72-php-pdo \
ea-php72-php-posix \
ea-php72-php-soap \
ea-php72-php-zip \
ea-php72-runtime \
ea-php72-php-bcmath \
ea-php72-php-ioncube10 \
ea-php72-php-xmlrpc \
ea-php72-php-gettext \
ea-php72-php-gmp \
ea-php72-php-xml \
ea-php72-php-imap \
ea-php73 \
ea-php73-pear \
ea-php73-php-cli \
ea-php73-php-common \
ea-php73-php-curl \
ea-php73-php-devel \
ea-php73-php-exif \
ea-php73-php-fileinfo \
ea-php73-php-fpm \
ea-php73-php-ftp \
ea-php73-php-gd \
ea-php73-php-iconv \
ea-php73-php-intl \
ea-php73-php-litespeed \
ea-php73-php-mbstring \
ea-php73-php-mysqlnd \
ea-php73-php-opcache \
ea-php73-php-pdo \
ea-php73-php-posix \
ea-php73-php-soap \
ea-php73-php-zip \
ea-php73-runtime \
ea-php73-php-bcmath \
ea-php73-php-ioncube10 \
ea-php73-php-xmlrpc \
ea-php73-php-gettext \
ea-php73-php-gmp \
ea-php73-php-xml \
ea-php73-php-imap \
ea-php74 \
ea-php74-pear \
ea-php74-php-cli \
ea-php74-php-common \
ea-php74-php-curl \
ea-php74-php-devel \
ea-php74-php-exif \
ea-php74-php-fileinfo \
ea-php74-php-fpm \
ea-php74-php-ftp \
ea-php74-php-gd \
ea-php74-php-iconv \
ea-php74-php-intl \
ea-php74-php-litespeed \
ea-php74-php-mbstring \
ea-php74-php-mysqlnd \
ea-php74-php-opcache \
ea-php74-php-pdo \
ea-php74-php-posix \
ea-php74-php-soap \
ea-php74-php-zip \
ea-php74-runtime \
ea-php74-php-bcmath \
ea-php74-php-ioncube10 \
ea-php74-php-xmlrpc \
ea-php74-php-gettext \
ea-php74-php-gmp \
ea-php74-php-xml \
ea-php74-php-imap \
ea-php80 \
ea-php80-pear \
ea-php80-php-cli \
ea-php80-php-common \
ea-php80-php-curl \
ea-php80-php-devel \
ea-php80-php-exif \
ea-php80-php-fileinfo \
ea-php80-php-fpm \
ea-php80-php-ftp \
ea-php80-php-gd \
ea-php80-php-iconv \
ea-php80-php-intl \
ea-php80-php-litespeed \
ea-php80-php-mbstring \
ea-php80-php-mysqlnd \
ea-php80-php-opcache \
ea-php80-php-pdo \
ea-php80-php-posix \
ea-php80-php-soap \
ea-php80-php-zip \
ea-php80-runtime \
ea-php80-php-bcmath \
ea-php80-php-gettext \
ea-php80-php-gmp \
ea-php80-php-xml \
ea-php80-php-imap \
ea-php81 \
ea-php81-libc-client \
ea-php81-pear \
ea-php81-php-bcmath \
ea-php81-php-calendar \
ea-php81-php-cli \
ea-php81-php-common \
ea-php81-php-curl \
ea-php81-php-devel \
ea-php81-php-exif \
ea-php81-php-fileinfo \
ea-php81-php-fpm \
ea-php81-php-ftp \
ea-php81-php-gd \
ea-php81-php-iconv \
ea-php81-php-imap \
ea-php81-php-intl \
ea-php81-php-litespeed \
ea-php81-php-mbstring \
ea-php81-php-mysqlnd \
ea-php81-php-opcache \
ea-php81-php-pdo \
ea-php81-php-posix \
ea-php81-php-soap \
ea-php81-php-sockets \
ea-php81-php-sodium \
ea-php81-php-xml \
ea-php81-php-zip \
ea-php81-runtime \

--skip-broken
echo "Setting EasyApache 4 PHP..."
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^memory_limit.*/memory_limit = 1024M/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^enable_dl.*/enable_dl = Off/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^expose_php.*/expose_php = Off/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^register_globals.*/register_globals = Off/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^emagic_quotes_gpc.*/magic_quotes_gpc = Off/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^disable_functions.*/disable_functions = apache_get_modules,apache_get_version,apache_getenv,apache_note,apache_setenv,disk_free_space,diskfreespace,dl,exec,highlight_file,ini_alter,ini_restore,openlog,passthru,phpinfo,popen,posix_getpwuid,proc_close,proc_get_status,proc_nice,proc_open,proc_terminate,shell_exec,show_source,symlink,system,eval,debug_zval_dump/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^upload_max_filesize.*/upload_max_filesize = 100M/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^post_max_size.*/post_max_size = 100M/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^date.timezone.*/date.timezone = "America\/Argentina\/Buenos_Aires"/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^allow_url_fopen.*/allow_url_fopen = On/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^max_execution_time.*/max_execution_time = 200/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^max_input_time.*/max_input_time = 200/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^max_input_vars.*/max_input_vars = 3000/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^;default_charset = "UTF-8"/default_charset = "UTF-8"/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^default_charset.*/default_charset = "UTF-8"/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^display_errors.*/display_errors = Off/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^track_errors.*/track_errors = Off/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^html_errors.*/html_errors = Off/g'
find /opt/ \( -name "php.ini" -o -name "local.ini" \) | xargs sed -i 's/^error_reporting.*/error_reporting = E_ALL \& \~E_DEPRECATED \& \~E_STRICT/g'
echo "Setting default PHP-FPM values..." # https://documentation.cpanel.net/display/74Docs/Configuration+Values+of+PHP-FPM
mkdir -p /var/cpanel/ApachePHPFPM
cat > /var/cpanel/ApachePHPFPM/system_pool_defaults.yaml << EOF
---
pm_max_children: 20
pm_max_requests: 40
php_admin_value_disable_functions : { present_ifdefault: 0 }
EOF
/usr/local/cpanel/scripts/php_fpm_config --rebuild
/scripts/restartsrv_apache_php_fpm
echo "Configuring Handlers..."
whmapi1 php_set_handler version=ea-php55 handler=cgi
whmapi1 php_set_handler version=ea-php56 handler=cgi
whmapi1 php_set_handler version=ea-php70 handler=cgi
whmapi1 php_set_handler version=ea-php71 handler=cgi
whmapi1 php_set_handler version=ea-php72 handler=cgi
whmapi1 php_set_system_default_version version=ea-php72
echo "Configuring PHP-FPM..."
whmapi1 php_set_default_accounts_to_fpm default_accounts_to_fpm=1
whmapi1 convert_all_domains_to_fpm
if [ $ISVPS = "NO" ]; then
	echo "Configuring ModSecurity..."
	URL="https%3A%2F%2Fwaf.comodo.com%2Fdoc%2Fmeta_comodo_apache.yaml"
	whmapi1 modsec_add_vendor url=$URL
                
	MODSEC_DISABLE_CONF=("00_Init_Initialization.conf" "10_Bruteforce_Bruteforce.conf" "12_HTTP_HTTPDoS.conf")
	for CONF in "${MODSEC_DISABLE_CONF[@]}"
	do
		echo "Disabling conf $CONF..."
		whmapi1 modsec_make_config_inactive config=modsec_vendor_configs%2Fcomodo_apache%2F$CONF
	done
	whmapi1 modsec_enable_vendor vendor_id=comodo_apache
	function disable_rule {
	        whmapi1 modsec_disable_rule config=$2 id=$1
	        whmapi1 modsec_deploy_rule_changes config=$2
	}
	echo "Disabling conflicting rules..."
	disable_rule 211050 modsec_vendor_configs/comodo_apache/09_Global_Other.conf
	disable_rule 214420 modsec_vendor_configs/comodo_apache/17_Outgoing_FilterPHP.conf
	disable_rule 214940 modsec_vendor_configs/comodo_apache/22_Outgoing_FiltersEnd.conf
	disable_rule 222390 modsec_vendor_configs/comodo_apache/26_Apps_Joomla.conf
	disable_rule 211540 modsec_vendor_configs/comodo_apache/24_SQL_SQLi.conf
	disable_rule 210730 modsec_vendor_configs/comodo_apache/11_HTTP_HTTP.conf
	disable_rule 221570 modsec_vendor_configs/comodo_apache/32_Apps_OtherApps.conf
	disable_rule 212900 modsec_vendor_configs/comodo_apache/08_XSS_XSS.conf
	disable_rule 212000 modsec_vendor_configs/comodo_apache/08_XSS_XSS.conf
	disable_rule 212620 modsec_vendor_configs/comodo_apache/08_XSS_XSS.conf
	disable_rule 212700 modsec_vendor_configs/comodo_apache/08_XSS_XSS.conf
	disable_rule 212740 modsec_vendor_configs/comodo_apache/08_XSS_XSS.conf
	disable_rule 212870 modsec_vendor_configs/comodo_apache/08_XSS_XSS.conf
	disable_rule 212890 modsec_vendor_configs/comodo_apache/08_XSS_XSS.conf
	disable_rule 212640 modsec_vendor_configs/comodo_apache/08_XSS_XSS.conf
	disable_rule 212650 modsec_vendor_configs/comodo_apache/08_XSS_XSS.conf
	disable_rule 221560 modsec_vendor_configs/comodo_apache/32_Apps_OtherApps.conf
	disable_rule 210831 modsec_vendor_configs/comodo_apache/03_Global_Agents.conf
fi
echo "Configuring MySQL..."
sed -i '/^local-infile.*/d' /etc/my.cnf
sed -i '/^query_cache_type.*/d' /etc/my.cnf
sed -i '/^query_cache_size.*/d' /etc/my.cnf
sed -i '/^join_buffer_size.*/d' /etc/my.cnf
sed -i '/^tmp_table_size.*/d' /etc/my.cnf
sed -i '/^max_heap_table_size.*/d' /etc/my.cnf
sed -i '/^sql_mode.*/d' /etc/my.cnf
sed -i '/^# WNPower pre-configured values.*/d' /etc/my.cnf
sed  -i '/\[mysqld\]/a\ ' /etc/my.cnf
sed  -i '/\[mysqld\]/a sql_mode = ALLOW_INVALID_DATES,NO_ENGINE_SUBSTITUTION' /etc/my.cnf
sed  -i '/\[mysqld\]/a local-infile=0' /etc/my.cnf
sed  -i '/\[mysqld\]/a query_cache_type=1' /etc/my.cnf
sed  -i '/\[mysqld\]/a query_cache_size=12M' /etc/my.cnf
sed  -i '/\[mysqld\]/a join_buffer_size=12M' /etc/my.cnf
sed  -i '/\[mysqld\]/a tmp_table_size=192M' /etc/my.cnf
sed  -i '/\[mysqld\]/a max_heap_table_size=256M' /etc/my.cnf
sed  -i '/\[mysqld\]/a # WNPower pre-configured values' /etc/my.cnf
/scripts/restartsrv_mysql
echo "Updating a MariaDB 10.3..."
whmapi1 start_background_mysql_upgrade version=10.3
echo "Configuring disabled features..."
whmapi 1 update_featurelist featurelist = disabled api_shell = 0 agora = 0 analog = 0 boxtrapper = 0 traceaddy = 0 modules-php-pear = 0 modules-perl = 0 modules-ruby = 0 pgp = 0 phppgadmin = 0 postgres = 0 ror = 0 serverstatus = 0 webalizer = 0 clamavconnector_scan = 0 lists = 0
echo "defaultSetting features..."
whmapi1 update_featurelist featurelist=default modsecurity=1 zoneedit=1 emailtrace=1
echo "Creating default package..."
# It IS ESTIMATED 80% OF THE DISC FOR DEFAULT ACCOUNT
QUOTA=$(df -h /home/ | tail -1 | awk '{ print $2 }' | sed 's/G//' | awk '{ print ($1 * 1000) * 0.8 }')
whmapi1 addpkg name=default featurelist=default quota=$QUOTA cgi=0 frontpage=0 language=en maxftp=20 maxsql=20 maxpop=unlimited maxlists=0 maxsub=30 maxpark=30 maxaddon=0 hasshell=1 bwlimit=unlimited MAX_EMAIL_PER_HOUR=300 MAX_DEFER_FAIL_PERCENTAGE=30
echo "Setting server time..."
yum install ntpdate -y
echo "Synchronizing date with pool.ntp.org..."
ntpdate 0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org 0.south-america.pool.ntp.org
if [ -f /usr/share/zoneinfo/America/New_York ]; then
        echo "Configuring TIME ZONE America/New_York..."
        mv /etc/localtime /etc/localtime.old
        ln -s /usr/share/zoneinfo/America/New_York /etc/localtime
fi
echo "Setting BIOS date..."
hwclock -r
echo "Disabling mlocate cron..."
chmod -x /etc/cron.daily/mlocate* 2>&1 > /dev/null
if [ -f /proc/user_beancounters ]; then
	echo "OpenVZ detected, implementing hostname patch..."
	echo "/usr/bin/hostnamectl set-hostname $HOSTNAME" >> /etc/rc.d/rc.local
	echo "/bin/systemctl restart exim.service" >> /etc/rc.d/rc.local
	chmod +x /etc/rc.d/rc.local
fi
echo "Configuring AutoSSL..."
whmapi1 set_autossl_metadata_key key=clobber_externally_signed value=1
whmapi1 set_autossl_metadata_key key=notify_autossl_expiry value=0
whmapi1 set_autossl_metadata_key key=notify_autossl_expiry_coverage value=0
whmapi1 set_autossl_metadata_key key=notify_autossl_renewal value=0
whmapi1 set_autossl_metadata_key key=notify_autossl_renewal_coverage value=0
whmapi1 set_autossl_metadata_key key=notify_autossl_renewal_coverage_reduced value=0
whmapi1 set_autossl_metadata_key key=notify_autossl_renewal_uncovered_domains value=0
echo "Disabling cPHulk..."
whmapi1 disable_cphulk
echo "Activating Header Authorization in CGI..."
sed -i '/# ACTIVATE HEADER AUTHORIZATION CGI/,/# END ACTIVATE HEADER AUTHORIZATION CGI/d' /etc/apache2/conf.d/includes/pre_main_global.conf
cat >> /etc/apache2/conf.d/includes/pre_main_global.conf << 'EOF'
# START ACTIVATE HEADER AUTHORIZATION CGI
SetEnvIf Authorization "(.*)" HTTP_AUTHORIZATION=$1
# END ACTIVATE HEADER AUTHORIZATION CGI
EOF
/scripts/restartsrv_apache
echo "Activating 2FA..."
/usr/local/cpanel/bin/whmapi1 twofactorauth_enable_policy
echo "Patch Webmail x3 error..."
ln -s /usr/local/cpanel/base/webmail/paper_lantern /usr/local/cpanel/base/webmail/x3
echo "disabling mod_userdir (old preview with ~ user)..."
sed -i 's/:.*/:/g' /var/cpanel/moddirdomains
find /var/cpanel/userdata/ -type f -exec grep -H "userdirprotect: -1" {} \; | while read LINE
do
        FILE=$(echo "$LINE" | cut -d':' -f1)
        sed -i "s/userdirprotect: -1/userdirprotect: ''/" "$FILE"
done
/scripts/rebuildhttpdconf
/scripts/
echo "Configuring JailShell..."
echo "/etc/pki/java" >> /var/cpanel/jailshell-additional-mounts
echo "Miscellaneous..."
# DOES NOT HAVE EXECUTION PERMITS FOR EVERYONE BY DEFAULT
chmod 755 /usr/bin/wget
chmod 755 /usr/bin/curl 
echo "INSTALLING PHP ImageMagick..."
yum -y install ImageMagick-devel ImageMagick-c++-devel ImageMagick-perl
for phpver in $(ls -1 /opt/cpanel/ |grep ea-php | sed 's/ea-php//g') ; do
        printf "\autodetect" | exec /opt/cpanel/ea-php$phpver/root/usr/bin/php -C \
        -d include_path=/usr/share/pear \
        -d date.timezone=UTC \
        -d output_buffering=1 \
        -d variables_order=EGPCS \
        -d safe_mode=0 \
        -d register_argc_argv="On" \
        -d disable_functions="" \
        /opt/cpanel/ea-php$phpver/root/usr/share/pear/peclcmd.php install imagick
        #sed -i 's/extension=imagick.so//' /opt/cpanel/ea-php$phpver/root/etc/php.d/imagick.ini
        #echo 'extension=imagick.so' >> /opt/cpanel/ea-php$phpver/root/etc/php.d/imagick.ini
done
/scripts/restartsrv_httpd
/scripts/restartsrv_apache_php_fpm
echo "Disabling Greylisting ..."
whmapi 1 disable_cpgreylist


if [ -d /usr/local/cpanel/whostmgr/docroot/cgi/whmreseller ] ; then
			echo "WHMReseller is already installed on the server!";
		else
			echo -n "WHMReseller not found! Would you like to install? (y/n) ";
			read yesno < /dev/tty
			if [ "x$yesno" = "xy" ] ; then
                cd /usr/local/cpanel/whostmgr/docroot/cgi
                wget http://deasoft.com/install.cpp
                g++ install.cpp -o install
                chmod 700 install
                ./install
                rm install
                rm install.cpp
				echo "Done! WHMResellersuccessfully installed on your server!";
			else
				echo "Successfully skipped the installation of WHMReseller";
			fi
		fi

echo "Cleaning...."
echo "" > /root/.conf.sh
history -c
echo "" > /root/.bash_history

echo "#### Please any issue please contact ismail@bluedot.ltd  ####"
