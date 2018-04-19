#!/bin/bash -v

set -ex

if [ "x$REJECT_OUTBOUND" == "xYES" ]; then
PNDA_MIRROR_IP=$(echo $PNDA_MIRROR | awk -F'[/:]' '/http:\/\//{print $4}')

# Log the global scope IP connection.
cat > /etc/rsyslog.d/10-iptables.conf <<EOF
:msg,contains,"[ipreject] " /var/log/iptables.log
STOP
EOF
sudo service rsyslog restart
iptables -F LOGGING | true
iptables -F OUTPUT | true
iptables -X LOGGING | true
iptables -N LOGGING
iptables -A OUTPUT -j LOGGING
## Accept all local scope IP packets.
  ip address show  | awk '/inet /{print $2}' | while IFS= read line; do \
iptables -A LOGGING -d  $line -j ACCEPT
  done
## Log and reject all the remaining IP connections.
iptables -A LOGGING -j LOG --log-prefix "[ipreject] " --log-level 7 -m state --state NEW
iptables -A LOGGING -d  $PNDA_MIRROR_IP/32 -j ACCEPT # PNDA mirror
if [ "x$CLIENT_IP" != "x" ]; then
iptables -A LOGGING -d  $CLIENT_IP/32 -j ACCEPT # PNDA client
fi
if [ "x$NTP_SERVERS" != "x" ]; then
NTP_SERVERS=$(echo "$NTP_SERVERS" | sed -e 's|[]"'\''\[ ]||g')
iptables -A LOGGING -d  $NTP_SERVERS -j ACCEPT # NTP server
fi
if [ "x$vpcCidr" != "x" ]; then
iptables -A LOGGING -d  ${vpcCidr} -j ACCEPT # PNDA network for AWS
else
  if [ "x$privateSubnetCidr" != "x" ]; then
 iptables -A LOGGING -d  ${privateSubnetCidr} -j ACCEPT # PNDA network for openstack and production
  fi
  if [ "x$publicProducerSubnetCidr:" != "x" ]; then
 iptables -A LOGGING -d  ${publicProducerSubnetCidr} -j ACCEPT # Kafka Ingest network for openstack and production
  fi
fi
iptables -A LOGGING -j REJECT --reject-with icmp-net-unreachable
iptables-save > /etc/iptables.conf
echo -e '#!/bin/sh\niptables-restore < /etc/iptables.conf' > /etc/rc.local
chmod +x /etc/rc.d/rc.local | true
fi

DISTRO=$(cat /etc/*-release|grep ^ID\=|awk -F\= {'print $2'}|sed s/\"//g)

if [ "x$ADD_ONLINE_REPOS" == "xYES" ]; then
  yum install -y yum-utils
  RPM_EXTRAS=$RPM_EXTRAS_REPO_NAME
  RPM_OPTIONAL=$RPM_OPTIONAL_REPO_NAME
  yum-config-manager --enable $RPM_EXTRAS $RPM_OPTIONAL
  yum install -y yum-plugin-priorities
  PNDA_REPO=${PNDA_MIRROR/http\:\/\//}
  PNDA_REPO=${PNDA_REPO/\//_mirror_rpm}
  yum-config-manager --add-repo $PNDA_MIRROR/mirror_rpm
  yum-config-manager --setopt="$PNDA_REPO.priority=1" --enable $PNDA_REPO
else
  mkdir -p /etc/yum.repos.d.backup/
  mv /etc/yum.repos.d/* /etc/yum.repos.d.backup/
  
  cat << EOF > /etc/yum.repos.d/pnda_mirror.repo

[pnda_mirror]
name=added from: $PNDA_MIRROR/mirror_rpm
baseurl=$PNDA_MIRROR/mirror_rpm
enabled=1
priority = 1
gpgcheck = 1
keepcache = 0

EOF

fi

if [ "x$DISTRO" == "xrhel" ]; then
  rpm --import $PNDA_MIRROR/mirror_rpm/RPM-GPG-KEY-redhat-release
fi
rpm --import $PNDA_MIRROR/mirror_rpm/RPM-GPG-KEY-mysql
rpm --import $PNDA_MIRROR/mirror_rpm/RPM-GPG-KEY-cloudera
rpm --import $PNDA_MIRROR/mirror_rpm/RPM-GPG-KEY-EPEL-7
rpm --import $PNDA_MIRROR/mirror_rpm/SALTSTACK-GPG-KEY.pub
rpm --import $PNDA_MIRROR/mirror_rpm/RPM-GPG-KEY-CentOS-7
rpm --import $PNDA_MIRROR/mirror_rpm/RPM-GPG-KEY-Jenkins

PIP_INDEX_URL="$PNDA_MIRROR/mirror_python/simple"
TRUSTED_HOST=$(echo $PIP_INDEX_URL | awk -F'[/:]' '/http:\/\//{print $4}')
cat << EOF > /etc/pip.conf
[global]
index-url=$PIP_INDEX_URL
trusted-host=$TRUSTED_HOST
EOF
cat << EOF > /root/.pydistutils.cfg
[easy_install]
index_url=$PIP_INDEX_URL
EOF

if [ "x$ADD_ONLINE_REPOS" == "xYES" ]; then
cat << EOF >> /etc/pip.conf
extra-index-url=https://pypi.python.org/simple/
EOF
cat << EOF >> /root/.pydistutils.cfg
find_links=https://pypi.python.org/simple/
EOF
fi

