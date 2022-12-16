#!bin/bash
 
sudo apt install snort3 -y
sudo apt-get upgrade snort
ifconfig
IP=$(ifconfig | awk '/inet /{print $2}' | head -1 )
 
# configure snort.conf file
sudo echo "var RULE_PATH /etc/snort/rules" >> /etc/snort/snort.conf
 
sudo echo "var SO_RULE_PATH /etc/snort/so_rules" >> /etc/snort/snort.conf
 
sudo echo "var PREPROC_RULE_PATH /etc/snort/preproc_rules" >> /etc/snort/snort.conf
 
sudo echo "output log_tcpdump: tcpdump.log" >> /etc/snort/snort.conf
 
sudo echo "include $RULE_PATH/attack-responses.rules" >> /etc/snort/snort.conf
 
sudo echo "include $RULE_PATH/backdoor.rules" >> /etc/snort/snort.conf
 
sudo echo "include $RULE_PATH/bad-traffic.rules" >> /etc/snort/snort.conf
 
sudo echo "include $RULE_PATH/icmp.rules" >> /etc/snort/snort.conf
 
sudo echo "include $RULE_PATH/ftp.rules" >> /etc/snort/snort.conf
 
sudo echo "include $RULE_PATH/scan.rules" >> /etc/snort/snort.conf
 
sudo echo "include $RULE_PATH/local.rules" >> /etc/snort/snort.conf
 
 
# configure local.rules file
sudo echo "alert tcp any any -> $IP 22 (msg: "NMAP TCP Scan";sid:10000005; rev:2 ;Priority: 3;>" >> /etc/snort/rules/local.rules
sudo echo "alert tcp any any -> $IP any (msg: "TCP ping sweep Scan";Priority: 1;dsize:0;s>" >> /etc/snort/rules/local.rules
sudo echo "alert icmp any any -> $IP any (msg:"PING detected";Priority: 1;>" >> /etc/snort/rules/local.rules
sudo echo "alert ip any any -> $IP any (msg:"Trace route packet detected"; Priority: 2;>" >> /etc/snort/rules/local.rules
sudo echo "aalert ip any any -> $IP any (msg:"Tear drop attack detected"; Priority: 3; content:"teardrop";)>" >> /etc/snort/rules/local.rules

#start snort
#Network interface name is enp0s5, may not be the same for you
snort -T -i enp0s5 -c etc/snort/snort.conf