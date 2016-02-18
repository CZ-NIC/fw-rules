#!/bin/sh

CONF_DIR=files/script
TEST_DIR=${TEST_DIR:-/tmp/fw-test/script}
TEST_CONF_DIR="${TEST_DIR}"/config
TMP_OUT="${TEST_DIR}"/out

mkdir -p "${TEST_DIR}"
mkdir -p "${TEST_CONF_DIR}"

echo "===Testing apply script==="

cp "${CONF_DIR}"/firewall-turris.config "${TEST_CONF_DIR}"/firewall-turris

export OVERRIDE_IPSETS="${CONF_DIR}"/turris-ipsets.gz
export UCI_CONFIG_DIR="${TEST_CONF_DIR}"
export OVERRIDE_WAN=eth0
export OVERRIDE_WAN6=eth1


/usr/share/firewall/turris || exit 1

retval=0

# compare iptables
iptables-save | grep turris > "${TMP_OUT}"
diff="$(diff -u "${CONF_DIR}/iptables.out" "${TMP_OUT}")"
if [ -n "${diff}" ] ; then
	diff_file="${TEST_DIR}/iptables.diff"
	echo "${diff}" > "${diff_file}"
	echo "* test 'iptables-save' failed. See '${diff_file}'"
	retval=1
	else
	echo "* test 'iptables-save' passed."
fi

# compare ip6tables
ip6tables-save | grep turris > "${TMP_OUT}"
diff="$(diff -u "${CONF_DIR}/ip6tables.out" "${TMP_OUT}")"
if [ -n "${diff}" ] ; then
	diff_file="${TEST_DIR}/ip6tables.diff"
	echo "${diff}" > "${diff_file}"
	echo "* test 'ip6tables-save' failed. See '${diff_file}'"
	retval=1
	else
	echo "* test 'ip6tables-save' passed."
fi

# compare ipsets
ipset save | grep 000000 | sort > "${TMP_OUT}"
diff="$(diff -u "${CONF_DIR}/ipset-save.out" "${TMP_OUT}")"
if [ -n "${diff}" ] ; then
	diff_file="${TEST_DIR}/ipset-save.diff"
	echo "${diff}" > "${diff_file}"
	echo "* test 'ipset save' failed. See '${diff_file}'"
	retval=1
	else
	echo "* test 'ipset save' passed."
fi

rm -rf "${TMP_OUT}"
rm -rf "${TEST_CONF_DIR}"

exit ${retval}
