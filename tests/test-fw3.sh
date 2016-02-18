#!/bin/sh
CONF_DIR=files/fw3
TEST_DIR=${TEST_DIR:-/tmp/fw-test/fw3}
TEST_CONF_DIR="${TEST_DIR}"/config
TMP_OUT="${TEST_DIR}"/out

mkdir -p "${TEST_DIR}"
mkdir -p "${TEST_CONF_DIR}"

echo "===Testing FW3==="

retval=0
test_output() {
	local family="$1"
	local basename="$2"
	local expected_out="$3"
	fw3 -${family} -u "${TEST_CONF_DIR}" print > "${TMP_OUT}" 2> /dev/null

	local res="$(diff -u "${expected_out}" "${TMP_OUT}")"
	if [ -n "${res}" ] ; then
		local outdiff="${TEST_DIR}/${basename}-${family}.diff"
		echo "${res}" > "${outdiff}"
		echo "* test '${basename}' for IPv${family} failed. See '${outdiff}'"
		retval=1
	else
		echo "* test '${basename}' for IPv${family} passed."
	fi
	
}

for conf in "${CONF_DIR}"/*.config
do
	base="${conf%.*}"
	out4="${base}-4.out"
	out6="${base}-6.out"
	basename=$(basename "$base")

	cp "${conf}" "${TEST_CONF_DIR}"/firewall
	test_output 4 "${basename}" "${out4}"
	test_output 6 "${basename}" "${out6}"

done

rm -rf "${TMP_OUT}"
rm -rf "${TEST_CONF_DIR}"

exit ${retval}
