#!/bin/bash

PATH_TO_FILE="/etc/modprobe.d/hardening.conf"

# 2.2 Restrict Dynamic Mounting and Unmounting of Filesystems
restrict_dynamic_mount_unmount_fs() {
echo "Restrict Dynamic Mounting and Unmounting of Filesystems"
cat << EOF > $PATH_TO_FILE
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install fat /bin/true
install vfat /bin/true
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install gfs2 /bin/true
install bnep /bin/true
install bluetooth /bin/true
install btusb /bin/true
install net-pf-31 /bin/true
install appletalk /bin/true
options ipv6 disable=1
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
}

# 2.3 Prevent Users Mounting USB Storage
prevent_users_mounting_usb_storage() {
echo "Preventing Mounting USB Storage by users"
echo "Disabling modprobe loading of USB and FireWire storage drivers"
echo "blacklist usb-storage
blacklist firewire-core
install usb-storage /bin/true" >> $PATH_TO_FILE
echo "Disabling USB authorisation"
cat << EOF >/opt/usb-auth.sh
#!/bin/bash
echo 0 > /sys/bus/usb/devices/usb1/authorized
echo 0 > /sys/bus/usb/devices/usb1/authorized_default
EOF

cat << EOF > /etc/systemd/system/usb-auth.service
[Unit]
Description=Disable USB auth
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/bin/bash /opt/usb-auth.sh

[Install]
WantedBy=multi-user.target
EOF

chmod 0700 /opt/usb-auth.sh
systemctl enable usb-auth.service
systemctl start usb-auth.service
}

# 2.4 Restrict Programs from Dangerous Execution Patterns
restrict_prgrm_from_danger_patterns() {
echo "Restricting Programs from Dangerous Execution Patterns"
cat << EOF > /etc/sysctl.conf
# Disable core dumps
fs.suid_dumpable = 0

# Disable System Request debugging functionality
kernel.sysrq = 0

# Restrict access to kernel logs
kernel.dmesg_restrict = 1

# Enable ExecShield protection - not available on CentOS 7
# kernel.exec-shield = 1

# Randomise memory space
kernel.randomize_va_space = 2

# Hide kernel pointers
kernel.kptr_restrict = 2
EOF
sysctl -p
}

# 2.5 Set UMASK 027
# The following files require umask hardening: /etc/bashrc, /etc/csh.cshrc, /etc/init.d/functions and /etc/profile.
set_umask_027() {
echo "Set UMASK 027"
echo "The following files require umask hardening: /etc/bashrc, /etc/csh.cshrc, /etc/init.d/functions and /etc/profile."
echo "The 027 umask setting means that the owning group would be allowed to read the newly-created files as well"
sed -i -e 's/umask 022/umask 027/g' -e 's/umask 002/umask 027/g' /etc/bashrc
sed -i -e 's/umask 022/umask 027/g' -e 's/umask 002/umask 027/g' /etc/csh.cshrc
sed -i -e 's/umask 022/umask 027/g' -e 's/umask 002/umask 027/g' /etc/profile
sed -i -e 's/umask 022/umask 027/g' -e 's/umask 002/umask 027/g' /etc/init.d/functions
}

# 2.6 Disable Core Dumps
# and
# 2.7 Set Security Limits to Prevent DoS
disable_core_dumps_pr_DoS(){
echo "Disabling Core Dumps and setting up Security Limits to Prevent DoS"
cat << EOF > /etc/security/limits.conf
# 4096 is a good starting point
*      hard   core      0
*      soft   nofile    4096
*      hard   nofile    65536
*      soft   nproc     4096
*      hard   nproc     4096
*      soft   locks     4096
*      hard   locks     4096
*      soft   stack     10240
*      hard   stack     32768
*      soft   memlock   64
*      hard   memlock   64
*      hard   maxlogins 10

# Soft limit 32GB, hard 64GB
*      soft   fsize     33554432
*      hard   fsize     67108864

# Limits for root
root   soft   nofile    4096
root   hard   nofile    65536
root   soft   nproc     4096
root   hard   nproc     4096
root   soft   stack     10240
root   hard   stack     32768
root   soft   fsize     33554432
EOF
}

# 2.8 Verify Permissions of Files
verify_perms_files() {
echo "Verifying Permissions of Files"
find / -ignore_readdir_race -nouser -print -exec chown root {} \;
find / -ignore_readdir_race -nogroup -print -exec chgrp root {} \;
find / -ignore_readdir_race -not -path "/proc/*" -nouser -print -exec chown root {} \;

# Automate the process by creating a cron file /etc/cron.daily/unowned_files with the following content:
echo "Automating the file verifying process by creating a cron file /etc/cron.daily/unowned files"
cat << EOF > /etc/cron.daily/unowned_files
#!/bin/bash
find / -ignore_readdir_race \( -nouser -print -exec chown root {} \; \) , \( -nogroup -print -exec chgrp root {} \; \)
EOF
chown root:root /etc/cron.daily/unowned_files
chmod 0700 /etc/cron.daily/unowned_files
}

# 2.9 Monitor SUID/GUID Files
# Search for setuid/setgid files and identify if all are required:
monitor_SG_files() {
echo "Searching for setuid/setgid files and identify if all are required"
find / -xdev -type f -perm -4000 -o -perm -2000
}

# FIREWALL

fw_hardening() {
echo "Setting up the Firewall"
sed -i "s/DefaultZone=.*/DefaultZone=drop/g" /etc/firewalld/firewalld.conf
systemctl stop firewalld.service
systemctl mask firewalld.service
systemctl daemon-reload
yum install iptables-services
systemctl enable iptables.service ip6tables.service

cat << EOF > /etc/sysconfig/iptables
*filter
-F INPUT
-F OUTPUT
-F FORWARD
-P INPUT ACCEPT
-P FORWARD DROP
-P OUTPUT ACCEPT
-A INPUT -i lo -m comment --comment local -j ACCEPT
-A INPUT -d 127.0.0.0/8 ! -i lo -j REJECT --reject-with icmp-port-unreachable
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp -m conntrack --ctstate NEW --dport 22 -s 10.10.0.0/18 -j ACCEPT
-A INPUT -p tcp -m tcp -m conntrack --ctstate NEW --dport 22 -s 172.16.0.0/12 -j ACCEPT
-A INPUT -p tcp -m tcp -m conntrack --ctstate NEW --dport 22 -s 192.168.0.0/16 -j ACCEPT
-A INPUT -p tcp -m tcp -m conntrack --ctstate NEW --dport 22 -j ACCEPT
-A INPUT -j DROP
-A OUTPUT -d 127.0.0.0/8 -o lo -m comment --comment local -j ACCEPT
-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -p icmp -m icmp --icmp-type any -j ACCEPT
-A OUTPUT -p udp -m udp -m conntrack --ctstate NEW --dport 53 -j ACCEPT
-A OUTPUT -p tcp -m tcp -m conntrack --ctstate NEW --dport 53 -j ACCEPT
-A OUTPUT -p udp -m udp -m conntrack --ctstate NEW --dport 123 -j ACCEPT
-A OUTPUT -p tcp -m tcp -m conntrack --ctstate NEW --dport 80 -j ACCEPT
-A OUTPUT -p tcp -m tcp -m conntrack --ctstate NEW --dport 443 -j ACCEPT
-A OUTPUT -p tcp -m tcp -m conntrack --ctstate NEW --dport 587 -j ACCEPT
-A OUTPUT -j LOG --log-prefix "iptables_output "
-A OUTPUT -j REJECT --reject-with icmp-port-unreachable
COMMIT
EOF
cat << EOF > /etc/sysconfig/ip6tables
*filter
-F INPUT
-F OUTPUT
-F FORWARD
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT DROP
COMMIT
EOF
iptables-restore < /etc/sysconfig/iptables
ip6tables-restore < /etc/sysconfig/ip6tables
systemctl start ip6tables.service
systemctl start iptables.service
}

hosts_allow_deny() {
echo "Setting up /etc/hosts.allow and /etc/hosts.deny"
cat << EOF > /etc/hosts.allow
ALL: 127.0.0.1
sshd: ALL
EOF
cat << EOF > /etc/hosts.deny
ALL: ALL
EOF
}

# 3.3 Kernel Parameters Which Affect Networking
sysctl_kern_network() {
echo "Setting up kernel parameters which affect networking"
cat << EOF > /etc/sysctl.conf
# Disable packet forwarding
net.ipv4.ip_forward = 0

# Disable redirects, not a router
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Enable source validation by reversed path
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log packets with impossible addresses to kernel log
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Against SYN flood attacks
net.ipv4.tcp_syncookies = 1

# Turning off timestamps could improve security but degrade performance.
# TCP timestamps are used to improve performance as well as protect against
# late packets messing up your data flow. A side effect of this feature is
# that the uptime of the host can sometimes be computed.
# If you disable TCP timestamps, you should expect worse performance
# and less reliable connections.
net.ipv4.tcp_timestamps = 1

# Disable IPv6 unless required
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Do not accept router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
}

# disable all the wireless and drivers
disable_radio() {
echo "Disabling radios"
for i in $(find /lib/modules/$(uname -r)/kernel/drivers/net/wireless -name "*.ko" -type f);do echo blacklist "$i" >>/etc/modprobe.d/hardening-wireless.conf;done
nmcli radio all off
echo "NOZEROCONF=yes
NETWORKING_IPV6=no
IPV6INIT=no" >> /etc/sysconfig/network
}

check_selinux() {
echo "Ensure that SELinux is not disabled"
sestatus
}

# 5. System Settings – Account and Access Control
# 5.1 Delete Unused Accounts and Groups
del_unused_acc_grp() {
echo "Deleting unused accounts and groups"
userdel -r adm
userdel -r ftp
userdel -r games
userdel -r lp
groupdel games
}
# 5.2 Disable Direct root Login
dis_direct_root_login() {
echo "Disabling direct root login"
echo > /etc/securetty
}

# 5.3 Enable Secure (high quality) Password Policy
set_passwd_policy() {
echo "Enabling secure (high quality) password policy"
authconfig --passalgo=sha512 \
 --passminlen=16 \
 --passminclass=4 \
 --passmaxrepeat=2 \
 --passmaxclassrepeat=2 \
 --enablereqlower \
 --enablerequpper \
 --enablereqdigit \
 --enablereqother \
 --update
cat << EOF > /etc/security/pwquality.conf
difok = 8
gecoscheck = 1
EOF
}

# 5.4 Prevent Log In to Accounts With Empty Password
diable_login_with_empty_passwd() {
echo "Preventing log in to accounts with empty password"
sed -i 's/\<nullok\>//g' /etc/pam.d/system-auth /etc/pam.d/system-auth-ac
sed -i 's/\<nullok\>//g' /etc/pam.d/password-auth /etc/pam.d/password-auth-ac
}

# 5.5 Set Account Expiration Following Inactivity
set_acc_exp_inact() {
echo "Setting up account expiration following inactivity"
sed -i 's/^INACTIVE.*/INACTIVE=0/' /etc/default/useradd
}

# 5.6 Secure Password Policy
sec_passwd_policy() {
echo "Setting up secure password policy"
sed -i -e 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' \
  -e 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' \
  -e 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 14/' \
  -e 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
}

# Login definitions
login_defs() {
echo "Setting up login definitions"
# 5.7 Log Failed Login Attemps
echo "FAILLOG_ENAB yes" >> /etc/login.defs
echo "FAIL_DELAY 4" >> /etc/login.defs
# 5.8 Ensure Home Directories are Created for New Users
echo "CREATE_HOME yes" >> /etc/login.defs
echo "Verify All Account Password Hashes are Shadowed"
echo "should return “x”"
cut -d: -f2 /etc/passwd|uniq
}

# 5.10 Set Deny and Lockout Time for Failed Password Attempts
set_deny_lockout() {
echo "Setting up the ban and block time for failed password attempts"
echo "5.10 Set Deny and Lockout Time for Failed Password Attempts"
sed  -i '/auth        sufficient    pam_unix.so/i auth        required pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900' /etc/pam.d/system-auth
sed  -i '/auth        sufficient    pam_unix.so/i auth        required pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900' /etc/pam.d/password-auth
sed  -i '/auth        sufficient    pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900' /etc/pam.d/system-auth
sed  -i '/auth        sufficient    pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900' /etc/pam.d/password-auth
sed  -i '/account     required      pam_unix.so/i account required pam_faillock.so' /etc/pam.d/system-auth
sed  -i '/account     required      pam_unix.so/i account required pam_faillock.so' /etc/pam.d/password-auth
sed  -i '/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok/s/$/ remember=5/' /etc/pam.d/system-auth
sed  -i '/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok/s/$/ remember=5/' /etc/pam.d/password-auth

# Make /etc/pam.d/system-auth and /etc/pam.d/password-auth configurations immutable so that they don’t get overwritten when authconfig is run
chattr +i /etc/pam.d/system-auth /etc/pam.d/password-auth
# Use the following to clear user’s fail count:
echo "faillock --user user_name --reset"
}

# 5.14 Multiple Console Screens and Console Locking
install_soft() {
echo "Installing the screen package to be able to emulate multiple console windows"
yum install screen
echo "Installing the vlock package to enable console screen locking"
yum install vlock
}

# 5.15 Disable Ctrl-Alt-Del Reboot Activation
disable_ctrl_alt_del_reboot() {
echo "Disabling Ctrl-Alt-Del reboot activation"
systemctl mask ctrl-alt-del.target
}

# 5.16 Warning Banners for System Access
setup_warning_baners() {
echo "Setting up warning banners for system access: /etc/issue and /etc/issue.net"
echo "Unauthorised access prohibited. Logs are recorded and monitored." > /etc/issue
echo "Unauthorised access prohibited. Logs are recorded and monitored." > /etc/issue.net
}

# 5.17 Set Interactive Session Timeout
set_session_timeout() {
echo "Setting up interactive session timeout"
echo "readonly TMOUT=900" >> /etc/profile
}

# 5.18 Two Factor Authentication
setup_two_f_auth() {
echo "Setting up ssh two factor authentication"
echo "AuthenticationMethods publickey,password" >> /etc/ssh/sshd_config
}

# 5.19 Configure History File Size
conf_hist_file_size() {
echo "Configuring history file size"
sed -i 's/HISTSIZE=.*/HISTSIZE=5000/g' /etc/profile
}

# 6.1 Auditd Configuration
auditd_conf() {
echo "Setting up Auditd configuration"
sed -i 's/local_events.*/local_events = yes/g' /etc/audit/auditd.conf
sed -i 's/write_logs.*/write_logs = yes/g' /etc/audit/auditd.conf
sed -i 's/max_log_file .*/max_log_file = 25/g' /etc/audit/auditd.conf
sed -i 's/num_logs .*/num_logs = 10/g' /etc/audit/auditd.conf
sed -i 's/max_log_file_action .*/max_log_file_action = rotate/g' /etc/audit/auditd.conf
sed -i 's/space_left .*/space_left = 30/g' /etc/audit/auditd.conf
sed -i 's/space_left_action .*/space_left_action = email/g' /etc/audit/auditd.conf
sed -i 's/admin_space_left .*/admin_space_left = 10/g' /etc/audit/auditd.conf
sed -i 's/admin_space_left_action .*/admin_space_left_action = email/g' /etc/audit/auditd.conf
sed -i 's/disk_full_action .*/disk_full_action = suspend/g' /etc/audit/auditd.conf
sed -i 's/disk_error_action .*/disk_error_action = suspend/g' /etc/audit/auditd.conf
sed -i 's/action_mail_acct .*/action_mail_acct = root@example.com/g' /etc/audit/auditd.conf
sed -i 's/flush .*/flush = data/g' /etc/audit/auditd.conf
}

# 6.2 Auditd Rules
set_auditd_rules() {
echo "Setting up Auditd rules"
cat << EOF > /etc/audit/rules.d/audit.rules
# Delete all currently loaded rules
-D

# Set kernel buffer size
-b 8192

# Set the action that is performed when a critical error is detected.
# Failure modes: 0=silent 1=printk 2=panic
-f 1

# Record attempts to alter the localtime file
-w /etc/localtime -p wa -k audit_time_rules

# Record events that modify user/group information
-w /etc/group -p wa -k audit_rules_usergroup_modification
-w /etc/passwd -p wa -k audit_rules_usergroup_modification
-w /etc/gshadow -p wa -k audit_rules_usergroup_modification
-w /etc/shadow -p wa -k audit_rules_usergroup_modification
-w /etc/security/opasswd -p wa -k audit_rules_usergroup_modification

# Record events that modify the system's network environment
-w /etc/issue.net -p wa -k audit_rules_networkconfig_modification
-w /etc/issue -p wa -k audit_rules_networkconfig_modification
-w /etc/hosts -p wa -k audit_rules_networkconfig_modification
-w /etc/sysconfig/network -p wa -k audit_rules_networkconfig_modification
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_rules_networkconfig_modification
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_rules_networkconfig_modification

# Record events that modify the system's mandatory access controls
-w /etc/selinux/ -p wa -k MAC-policy

# Record attempts to alter logon and logout events
-w /var/log/tallylog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Record attempts to alter process and session initiation information
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/run/utmp -p wa -k session

# Ensure auditd collects information on kernel module loading and unloading
-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules
-w /usr/sbin/rmmod -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Ensure auditd collects system administrator actions
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Record attempts to alter time through adjtimex
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k audit_time_rules

# Record attempts to alter time through settimeofday
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k audit_time_rules

# Record attempts to alter time through clock_settime
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change

# Record attempts to alter time through clock_settime
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change

# Record events that modify the system's discretionary access controls
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Ensure auditd collects unauthorised access attempts to files (unsuccessful)
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Ensure auditd collects information on exporting to media (successful)
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k export
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k export

# Ensure auditd collects file deletion events by user
-a always,exit -F arch=b32 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Ensure auditd collects information on the use of privileged commands
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged-priv_change
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/screen -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/restorecon -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged-priv_change
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged-priv_change
-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged-priv_change
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Make the auditd configuration immutable.
# The configuration can only be changed by rebooting the machine.
-e 2
EOF
chown root:root /etc/audit/rules.d/audit.rules
chmod 0640 /etc/audit/rules.d/audit.rules
sed -i 's/active .*/active = yes/g' /etc/audisp/plugins.d/syslog.conf
systemctl enable auditd.service
systemctl start auditd.service
}

# 6.3. Enable Kernel Auditing
enable_kernel_audit() {
echo "Enabling Kernel auditing"
sed -i '/GRUB_CMDLINE_LINUX/s/.$/ audit=1"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
}

# 7.1 Advanced Intrusion Detection Environment (AIDE)
install_aide() {
echo "Installing Advanced Intrusion Detection Environment (AIDE)"
yum install aide
echo "Init AIDE DB"
/usr/sbin/aide --init
cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
echo "Check changes in files"
/usr/sbin/aide --check
echo "30 4 * * * root /usr/sbin/aide --check|mail -s 'AIDE' root@example.com" >> /etc/crontab
}

# 7.3 Prelink

install_prelink() {
echo "Installing prelink"
yum install prelink
sed -i 's/PRELINKING.*/PRELINKING=no/g' /etc/sysconfig/prelink
prelink -ua
}

#8.1 Configure Persistent Journald Storage
conf_pers_journl_stor() {
echo "Configuring persistent journald storage"
echo "Storage=persistent

# How much disk space the journal may use up at most
SystemMaxUse=256M

# How much disk space systemd-journald shall leave free for other uses
SystemKeepFree=512M

# How large individual journal files may grow at most
SystemMaxFileSize=32M" >> /etc/systemd/journald.conf
systemctl daemon-reload
systemctl restart systemd-journald
}

# 8.2 Configure Message Forwarding to Remote Server
conf_mess_forwrd_to_rem_serv() {
echo "Configiring message forwarding to remote server"
echo "*.* @graylog.example.com:514" >> /etc/rsyslog.conf
}

# 8.3 Logwatch
install_logwatch() {
echo "Installing Logwatch"
yum install logwatch
}

# 9.1 Malware Scanners
install_mlwr_scanners() {
echo "Installing malware scanners"
yum install epel-release
yum install rkhunter clamav clamav-update
rkhunter --update
rkhunter --propupd
freshclam -v
}

# 10. System Settings – OS Update Installation
os_update() {
echo "OS Update Installation"
yum install yum-utils
yum install yum-cron
cat << EOF > /etc/yum/yum-cron.conf
update_cmd = default
update_messages = yes
download_updates = no
apply_updates = no
emit_via = email
email_from = root@example.com
email_to = user@example.com
email_host = localhost
EOF

cat << EOF > /etc/yum/yum-cron-hourly.conf
update_cmd = minimal # yum --bugfix update-minimal
update_messages = yes
download_updates = yes
apply_updates = yes
emit_via = stdio
EOF
systemctl enable yum-cron.service
systemctl start yum-cron.service
}

#11. System Settings – Process Accounting
installing_psacct() {
echo "Installing Psacct"
echo "The package psacct contain utilities for monitoring process activities:"
echo ""
echo "ac – displays statistics about how long users have been logged on."
echo "lastcomm – displays information about previously executed commands."
echo "accton – turns process accounting on or off."
echo "sa – summarises information about previously executed commands."
yum install psacct
systemctl enable psacct.service
systemctl start psacct.service
}

#11.1 Services – SSH Server
conf_ssh_serv() {
echo "Creating a group for SSH access as well as some regular user account who will be a member of the group"
groupadd ssh-users
echo "use: useradd -m -s /bin/bash -G ssh-users user_name"
echo "Generating SSH keys for the user:"
echo "$ su - tomas"
echo "$ mkdir --mode=0700 ~/.ssh"
echo "$ ssh-keygen -b 4096 -t rsa -C 'user_name' -f ~/.ssh/id_rsa"
echo "Generating SSH host keys:"

ssh-keygen -b 4096 -t rsa -N "" -f /etc/ssh/ssh_host_rsa_key
ssh-keygen -b 1024 -t dsa -N "" -f /etc/ssh/ssh_host_dsa_key
ssh-keygen -b 521 -t ecdsa -N "" -f /etc/ssh/ssh_host_ecdsa_key
ssh-keygen -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
chmod 0600 /etc/ssh/*_key

cat << EOF > /etc/ssh/sshd_config
# SSH port.
Port 22

# Listen on IPv4 only.
ListenAddress 0.0.0.0

# Protocol version 1 has been exposed.
Protocol 2

#
# OpenSSH cipher-related release notes.
# OpenSSH 6.2: added support for AES-GCM authenticated encryption. 
# The cipher is available as aes128-gcm@openssh.com and aes256-gcm@openssh.com.
# OpenSSH 6.5: added new cipher chacha20-poly1305@openssh.com.
# OpenSSH 6.7: removed unsafe algorithms. CBC ciphers are disabled by default:
# aes128-cbc, aes192-cbc, aes256-cbc, 3des-cbc, blowfish-cbc, cast128-cbc.
# OpenSSH 6.9: promoted chacha20-poly1305@openssh.com to be the default cipher.
#
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

#
# OpenSSH 6.2: added support for the UMAC-128 MAC as umac-128@openssh.com 
# and umac-128-etm@openssh.com. The latter being an encrypt-then-mac mode.
# Do not use umac-64 or umac-64-etm because of a small 64 bit tag size.
# Do not use any SHA1 (e.g. hmac-sha1, hmac-sha1-etm@openssh.com) MACs 
# because of a weak hashing algorithm. 
# Do not use hmac-sha2-256, hmac-sha2-512 or umac-128@openssh.com 
# because of an encrypt-and-MAC mode. See the link below:
# https://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac
#
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

#
# OpenSSH 6.5: added support for ssh-ed25519. It offers better security 
# than ECDSA and DSA.
# OpenSSH 7.0: disabled support for ssh-dss. 
# OpenSSH 7.2: added support for rsa-sha2-512 and rsa-sha2-256.
#
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com

#
# OpenSSH 6.5: added support for key exchange using elliptic-curve
# Diffie Hellman in Daniel Bernstein's Curve25519.
# OpenSSH 7.3: added support for diffie-hellman-group14-sha256,
# diffie-hellman-group16-sha512 and diffie-hellman-group18-sha512.
#
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256

# HostKeys for protocol version 2.
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Disabled because uses a small 1024 bit key.
#HostKey /etc/ssh/ssh_host_dsa_key

# Disabled because uses weak elliptic curves.
# See: https://safecurves.cr.yp.to/
#HostKey /etc/ssh/ssh_host_ecdsa_key


# INFO is a basic logging level that will capture user login/logout activity.
# DEBUG logging level is not recommended for production servers.
LogLevel INFO

# Disconnect if no successful login is made in 60 seconds.
LoginGraceTime 60

# Do not permit root logins via SSH.
PermitRootLogin no

# Check file modes and ownership of the user's files before login.
StrictModes yes

# Close TCP socket after 2 invalid login attempts.
MaxAuthTries 2

# The maximum number of sessions per network connection.
MaxSessions 3

# User/group permissions.
AllowUsers
AllowGroups ssh-users
DenyUsers root
DenyGroups root

# Password and public key authentications.
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile  .ssh/authorized_keys

# Disable unused authentications mechanisms.
RSAAuthentication no # DEPRECATED
RhostsRSAAuthentication no # DEPRECATED
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreUserKnownHosts yes

# Disable insecure access via rhosts files.
IgnoreRhosts yes

AllowAgentForwarding no
AllowTcpForwarding no

# Disable X Forwarding.
X11Forwarding no

# Disable message of the day but print last log.
PrintMotd no
PrintLastLog yes

# Show banner.
Banner /etc/issue

# Do not send TCP keepalive messages.
TCPKeepAlive no

# Default for new installations.
UsePrivilegeSeparation sandbox

# Prevent users from potentially bypassing some access restrictions.
PermitUserEnvironment no

# Disable compression.
Compression no

# Disconnect the client if no activity has been detected for 900 seconds.
ClientAliveInterval 900
ClientAliveCountMax 0

# Do not look up the remote hostname.
UseDNS no

UsePAM yes
EOF
#In case you want to change the default SSH port to something else, you will need to tell SELinux about it.
# yum install policycoreutils-python
#For example, to allow SSH server to listen on TCP 2222, do the following:
# semanage port -a -t ssh_port_t 2222 -p tcp
}

# 11.2. Service – Network Time Protocol
enable_ntp() {
echo "Making sure that the service Chronyd (NTP) is enabled"
systemctl enable chronyd.service
}

# 11.3. Services – Mail Server
install_postfix() {
echo "Installing mail system"
yum install postfix
systemctl enable postfix.service

echo "smtpd_banner = $myhostname ESMTP" >> /etc/postfix/main.cf
sed -i 's/inet_interfaces .*/inet_interfaces = loopback-only/g' /etc/postfix/main.cf
sed -i 's/inet_protocols .*/inet_protocols = ipv4/g' /etc/postfix/main.cf
sed -i 's/mydestination .*/mydestination =/g' /etc/postfix/main.cf
echo "local_transport = error: local delivery disabled" >> /etc/postfix/main.cf
sed -i 's/unknown_local_recipient_reject_code .*/unknown_local_recipient_reject_code = 550/g' /etc/postfix/main.cf
echo "mynetworks = 127.0.0.0/8" >> /etc/postfix/main.cf
echo "relayhost = [mail.example.com]:587" >> /etc/postfix/main.cf
}

# 11.4. Services – Remove Obsolete Services
remove_obsolete_serv() {
echo "Removing obsolete services"
yum remove xinetd telnet-server rsh-server \
  telnet rsh ypbind ypserv tfsp-server bind \
  vsfptd dovecot squid net-snmpd talk-server talk
echo "Check all enabled services:"
systemctl list-unit-files --type=service|grep enabled
echo "Disabling kernel dump service:"
systemctl disable kdump.service
systemctl mask kdump.service
echo "Disabling everything that is not required, e.g.:"
systemctl disable tuned.service
}

# 11.5. Services – Restrict at and cron to Authorised Users
restr_cron() {
echo "Restricting 'at' and 'cron' to Authorised Users"
echo root > /etc/cron.allow
echo root > /etc/at.allow
rm -f /etc/at.deny /etc/cron.deny
}

# 11.6. Services – Disable X Windows Startup
disable_x_windows() {
echo "Disabling X Windows startup"
systemctl set-default multi-user.target
}

# 11.7. Services – Fail2ban
install_file2bann() {
echo "Installing File2ban and configuring it"
yum install epel-release
yum install fail2ban
cat << EOF > /etc/fail2ban/jail.d/00-firewalld.conf
[DEFAULT]
#banaction = firewallcmd-ipset[actiontype=<multiport>]
banaction_allports = firewallcmd-ipset[actiontype=<allports>]
EOF

sed -i '/^\[sshd\]/a enabled = true' /etc/fail2ban/jail.conf
sed -i '/^\[sshd\]/a ignoreip = 10.10.0.13' /etc/fail2ban/jail.conf
sed -i '/^\[sshd\]/a bantime  = 600' /etc/fail2ban/jail.conf
sed -i '/^\[sshd\]/a maxretry = 5' /etc/fail2ban/jail.conf
systemctl enable fail2ban.service
systemctl start fail2ban.service
}

# 11.8. Services – Sysstat to Collect Performance Activity
collect_ativity() {
echo "Installing Sysstat"
yum -y install sysstat
systemctl enable sysstat.service
systemctl start sysstat.service
}


#restrict_dynamic_mount_unmount_fs
#prevent_users_mounting_usb_storage
#restrict_prgrm_from_danger_patterns
#set_umask_027
#disable_core_dumps_pr_DoS
#verify_perms_files
#monitor_SG_files
#fw_hardening
#hosts_allow_deny
#sysctl_kern_network
#disable_radio
#del_unused_acc_grp
#check_selinux
#dis_direct_root_login
#set_passwd_policy
#diable_login_with_empty_passwd
#set_acc_exp_inact
#sec_passwd_policy
#login_defs
#set_deny_lockout
#install_soft
#disable_ctrl_alt_del_reboot
#setup_warning_baners
#set_session_timeout
#setup_two_f_auth
#conf_hist_file_size
#auditd_conf
#set_auditd_rules
#install_aide
#install_prelink
#conf_pers_journl_stor
#conf_mess_forwrd_to_rem_serv
#install_logwatch
#install_mlwr_scanners
#os_update
#installing_psacct
#conf_ssh_serv
#enable_ntp
#install_postfix
#remove_obsolete_serv
#restr_cron
#disable_x_windows
#install_file2bann
#collect_ativity
