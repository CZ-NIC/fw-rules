#!/bin/busybox sh

# Copyright (c) 2013-2015, CZ.NIC, z.s.p.o. (http://www.nic.cz/)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#    * Neither the name of the CZ.NIC nor the
#      names of its contributors may be used to endorse or promote products
#      derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL CZ.NIC BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#
# This file is interpreted as shell script.
# It downloads firewall rules issued by CZ.NIC s.z.p.o.
# as a part of Turris project (see https://www.turris.cz/)
#
# It is periodically run using cron (see /etc/cron.d/fw-rules)
#
# Related UCI config /etc/config/firewall-turris
#

. $IPKG_INSTROOT/lib/functions.sh

LOCK_FILE="/tmp/turris-firewall-rules-download.lock"

acquire_lockfile() {
    set -o noclobber

    if [ -e "${LOCK_FILE}" ]; then
        if kill -0 `cat "${LOCK_FILE}"`; then
            logger -t turris-firewall-rules -p err "An instance of turris-firewall-rules is already running!"
            return 1
        else
            rm -rf "${LOCK_FILE}"
        fi
    fi

    echo -n $$ > "${LOCK_FILE}"
    if [ ! "$?" = 0 ]; then
        logger -t turris-firewall-rules -p err "An instance of turris-firewall-rules is already running!"
        return 1
    fi
    set +o noclobber

    return 0
}

release_lockfile() {
    if [ -e "${LOCK_FILE}" -a  `cat "${LOCK_FILE}"` = "$$" ]; then
        rm -rf "${LOCK_FILE}"
    fi
}

exit_on_failure() {
    release_lockfile
    exit 1
}

acquire_lockfile || exit_on_failure

# Enable debug
if [ -n "${DEBUG}" ] ; then
    set -x
fi

IPSETS_URL="https://api.turris.cz/firewall/turris-ipsets.gz"
IPSETS_SIGN_URL="${IPSETS_URL}.sign"
PERSISTENT_IPSETS="/usr/share/firewall/turris-ipsets.gz"

DOWNLOAD_DIR="/tmp/fw-rules"
DOWNLOAD_IPSETS="${DOWNLOAD_DIR}/turris-ipsets.gz"
DOWNLOAD_IPSETS_SIGN="${DOWNLOAD_IPSETS}.sign"

SIGN_KEY="/etc/ssl/turris-rules.pub"
DOWNLOAD_INTERVAL=$((4*60))
VERSION=0

TEST_SIGN_KEY="${DOWNLOAD_DIR}/turris-rules.pub"
TEST_SIGN_KEY_URL="https://api.turris.cz/firewall-test/turris-rules.pub"
TEST_IPSETS_URL="https://api.turris.cz/firewall-test/turris-ipsets.gz"
TEST_IPSETS_SIGN_URL="${TEST_IPSETS_URL}.sign"

CRL_FILE_PERSISTENT="/etc/ssl/crl.pem"
CRL_FILE_TEMPORAL="/tmp/crl.pem"

# Temporal crl file should be up-to date
if [ -f "${CRL_FILE_TEMPORAL}" ]; then
    CRL_FILE="${CRL_FILE_TEMPORAL}"
else
    CRL_FILE="${CRL_FILE_PERSISTENT}"
fi

# Return md5 of a file the file should exist
file_md5() {
    local file="$1"
    echo $(md5sum "${file}" | sed 's/ .*//')
}

download() {
    local master_url="$1"
    local test_url="$2"
    local destination="$3"
    local interval="$4"

    if [ -n "$interval" ]; then
        if ! download_needed "${destination}" "${interval}" ; then
            return 0
        fi
    fi

    if [ "${test}" == "true" ]; then
        url="$test_url"
    else
        url="$master_url"
    fi

    curl -fs --cacert /etc/ssl/startcom.pem --crlfile "${CRL_FILE}" "${url}" -o "${destination}"
    if [ $? -eq 0 ]; then
        return 0
    else
        logger -t turris-firewall-rules -p err "(v${VERSION}) Failed to download ${url}"
        return 1
    fi
}

# Check whether the selected file is older then X seconds
download_needed() {
    local file="$1"
    local seconds="$2"
    local current=`date +%s`
    if [ -f "${file}" ]; then
        local file_age=`date -r "${file}" +%s`
        if [ "${current}" -lt "$((file_age + seconds))" ] ; then
            return 1
        else
            return 0
        fi
        return 1
    else
        return 0
    fi
}

# Verifies signature
verify_signature() {

    local file="$1"
    local signature="$2"

    if [ "${test}" == "true" ]; then
        key="${TEST_SIGN_KEY}"
    else
        key="${SIGN_KEY}"
    fi

    openssl dgst -sha256 -verify "${key}" -signature "${signature}" "${file}" > /dev/null 2>&1
    return $?
}

# Update the persistent file
update_file() {

    local signature="$1"
    local downloaded="$2"
    local persistent="$3"
    local file_name=$(basename "${persistent}")

    # test the signature
    if [ -f "${signature}" -a -f "${downloaded}" ]; then
        verify_signature "${downloaded}" "${signature}"
        if [ $? -eq 1 ]; then
            logger -t turris-firewall-rules -p err "(v${VERSION}) Incorrect signature for downloaded ${file_name}"
            return 1
        fi
    else
        return 1
    fi

    # Update the files
    local new_md5=$(file_md5 "${downloaded}")
    if [ -f "${persistent}" ]; then
        cmp -s "${downloaded}" "${persistent}"
        if [ $? -eq 1 ]; then
            local old_md5=$(file_md5 "${persistent}")
            logger -t turris-firewall-rules "(v${VERSION}) Switching ${file_name} ${old_md5} -> ${new_md5}"
        else
            # No need to update the file
            return 0
        fi
    else
        logger -t turris-firewall-rules "(v${VERSION}) Setting ${file_name} ${new_md5}"
    fi
    cp "${downloaded}" "${persistent}.to-be-applied"
    mv "${persistent}.to-be-applied" "${persistent}"
}

# are we in the test branch?
test_branch() {

    if x=$(command -v getbranch) ; then
        branch=$(getbranch)
    else
        return 1
    fi

    if [ `getbranch` == "test" ] ; then
        return 0
    fi

    return 1
}


########## Actual code ##########
# Try to update CRL
get-api-crl 1>/dev/null 2>&1

# Create directory for the rules
mkdir -p "${DOWNLOAD_DIR}"

if test_branch ; then
    if [ ! -f "${TEST_SIGN_KEY}" ] ; then
        curl -fs --cacert /etc/ssl/startcom.pem --crlfile "${CRL_FILE}" "${TEST_SIGN_KEY_URL}" -o "${TEST_SIGN_KEY}"
    fi
    test="true"
else
    test="false"
fi

# Download the ipsets signature
download "${IPSETS_SIGN_URL}" "${TEST_IPSETS_SIGN_URL}" "${DOWNLOAD_IPSETS_SIGN}" "${DOWNLOAD_INTERVAL}" || exit_on_failure

# test whether is necessary to download the whole file
if [ -f "${PERSISTENT_IPSETS}" ]; then
    verify_signature "${PERSISTENT_IPSETS}" "${DOWNLOAD_IPSETS_SIGN}"
    if [ $? -eq 0 ]; then
        # Signature matches we can copy persistent rules to tmp
        # this way file DOWNLOAD_IPSETS will always exits
        cp "${PERSISTENT_IPSETS}" "${DOWNLOAD_IPSETS}"
    else
        # download new rules
        download "${IPSETS_URL}" "${TEST_IPSETS_URL}" "${DOWNLOAD_IPSETS}" || exit_on_failure
    fi
else
    download "${IPSETS_URL}" "${TEST_IPSETS_URL}" "${DOWNLOAD_IPSETS}" || exit_on_failure
fi

# update file in the persistent memory
update_file "${DOWNLOAD_IPSETS_SIGN}" "${DOWNLOAD_IPSETS}" "${PERSISTENT_IPSETS}"

# generate the rule description file
$(dirname $(readlink -f "$0"))/turris-description

release_lockfile
