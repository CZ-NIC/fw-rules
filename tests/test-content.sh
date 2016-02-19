#!/bin/sh

CONF_DIR=files/script

echo "===Testing the content of issued firewall rules==="

# rules can be set as first argument
export OVERRIDE_IPSETS=$1

# reload the rules
/usr/share/firewall/turris || exit 1

retval=0

# curl test
if curl --ipv4 'https://api.turris.cz/' >/dev/null 2>&1 ; then
	echo "* test 'curl for api.turris.cz ipv4' passed."
else
	echo "* test 'curl for api.turris.cz ipv4' failed."
	retval=1
fi

if curl --ipv6 'https://api.turris.cz/' >/dev/null 2>&1 ; then
	echo "* test 'curl for api.turris.cz ipv6' passed."
else
	echo "* test 'curl for api.turris.cz ipv6' failed."
	retval=1
fi


# opkg test
if opkg update >/dev/null 2>&1 ; then
	echo "* test 'opkg update' passed."
else
	echo "* test 'opkg update' failed."
	retval=1
fi


# test ping to root nameserver
PING_COUNT=5
for server in a b c d e f h i j k l m ; do  # g doesn't work
	server_name=${server}.root-servers.net
	if ping ${server_name} -c ${PING_COUNT} >/dev/null 2>&1 ; then
		echo "* test 'ping ${server_name}' passed."
	else
		echo "* test 'ping ${server_name}' failed."
		retval=1
	fi
done

for server in a b c d f h i j k l m ; do  # g doesn't work and e doesn't have ipv6 address
	server_name=${server}.root-servers.net
	if ping6 ${server_name} -c ${PING_COUNT} >/dev/null 2>&1 ; then
		echo "* test 'ping6 ${server_name}' passed."
	else
		echo "* test 'ping6 ${server_name}' failed."
		retval=1
	fi
done

exit ${retval}
