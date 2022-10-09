if [ -f /etc/redhat-release ] ; then
			if [[ -f /usr/sbin/clnreg_ks && -f /usr/bin/cldetect ]] ; then
				echo "CloudLinux is already installed on the server!";
			else
				echo -n "CloudLinux not found! Would you like to install? (y/n) ";
				read yesno < /dev/tty
				if [ "x$yesno" = "xy" ] ; then
				/usr/bin/wget https://repo.cloudlinux.com/cloudlinux/sources/cln/cldeploy -O /root/cldeploy &>/dev/null

cd /home && /usr/bin/sh cldeploy --skip-registration -k 999 &> /dev/null

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
