#!/bin/busybox sh

# Copyright (c) 2013-2014, CZ.NIC, z.s.p.o. (http://www.nic.cz/)
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
# It contains firewall rules issued by CZ.NIC s.z.p.o.
# as a part of Turris project (see https://www.turris.cz/)
# 
# To enable/disable the rules please edit /etc/config/firewall
#
# config include
#   option path /usr/share/firewall/turris
#

. $IPKG_INSTROOT/lib/functions.sh

LOCK_FILE="/tmp/turris-firewall-rules.lock"

acquire_lockfile() {
    set -o noclobber

    if [ -e "${LOCK_FILE}" ]; then
        if kill -0 `cat "${LOCK_FILE}"`; then
            logger -t turris-firewall-rules -p err "An instance of turris-firewall-rules is already running!"
            exit 1
        else
            rm -rf "${LOCK_FILE}"
        fi
    fi

    echo -n $$ > "${LOCK_FILE}"
    if [ ! "$?" = 0 ]; then
        logger -t turris-firewall-rules -p err "An instance of turris-firewall-rules is already running!"
        exit 1
    fi
    set +o noclobber
}

release_lockfile() {
    if [ -e "${LOCK_FILE}" -a  `cat "${LOCK_FILE}"` = "$$" ]; then
        rm -rf "${LOCK_FILE}"
    fi
}

acquire_lockfile

# Enable debug
if [ -n "${DEBUG}" ] ; then
    set -x
fi

IPSETS_URL="https://api.turris.cz/firewall/turris-ipsets"
IPSETS_SIGN_URL="${IPSETS_URL}.sign"

TMP_FILE="/tmp/iptables.rules"
TMP_FILE6="/tmp/ip6tables.rules"
PERSISTENT_IPSETS="/usr/share/firewall/turris-ipsets"
ULOGD_FILE="/tmp/etc/ulogd-turris.conf"
PCAP_DIR="/var/log/turris-pcap"

DOWNLOAD_DIR="/tmp/fw-rules"
DOWNLOAD_IPSETS="${DOWNLOAD_DIR}/turris-ipsets"
DOWNLOAD_IPSETS_SIGN="${DOWNLOAD_IPSETS}.sign"

SIGN_KEY="/etc/ssl/turris-rules.pub"
DOWNLOAD_INTERVAL=$((4*60))
VERSION=0
WAN=""

TEST_SIGN_KEY="${DOWNLOAD_DIR}/turris-rules.pub"
TEST_SIGN_KEY_URL="https://api.turris.cz/firewall-test/turris-rules.pub"
TEST_IPSETS_URL="https://api.turris.cz/firewall-test/turris-ipsets"
TEST_IPSETS_SIGN_URL="${TEST_IPSETS_URL}.sign"

RULE_DESCRIPTION_FILE="/tmp/rule-description.txt"
RULE_DESCRIPTION_AWK_FILE="/tmp/rule-description.awk"

CRL_FILE_PERSISTENT="/etc/ssl/crl.pem"
CRL_FILE_TEMPORAL="/tmp/crl.pem"

# Temporal crl file should be up-to date
if [ -f "${CRL_FILE_TEMPORAL}" ]; then
    CRL_FILE="${CRL_FILE_TEMPORAL}"
else
    CRL_FILE="${CRL_FILE_PERSISTENT}"
fi

generate_rule_description_file() {
    cat > $RULE_DESCRIPTION_AWK_FILE <<"EOF"
BEGIN {
    comments=""
    comments_idx=0
}
/#/ {
    can_print=1
    tmp=$0
    sub(/# /, "", tmp)
    comments[comments_idx]=tmp
    comments_idx++
}
/^add/ {
    if (can_print) {
        split($2, parsed, "_")
        rule_id=substr(parsed[2], 0, 7)
        print rule_id "0"
        for (i=0; i<comments_idx; ++i) {
            print "\t" comments[i]
        }
        print "\n"
    }
    can_print=0
}
!/#/ {
    comments_idx=0
}
EOF
    awk -f "$RULE_DESCRIPTION_AWK_FILE" < "$PERSISTENT_IPSETS" > "$RULE_DESCRIPTION_FILE"
    rm -rf "$RULE_DESCRIPTION_AWK_FILE"
}

while [ -z "${WAN}" ]; do

    # read wan from nikola
    config_load nikola
    config_get WAN main wan_ifname
    [ -n "${WAN}" ] && break

    # read wan from network
    config_load network
    config_get WAN wan ifname
    [ -n "${WAN}" ] && break

    # read wan from ucollect
    set_WAN() {
        local cfg="$1"
        config_get WAN "${cfg}" ifname
    }
    config_load ucollect
    config_foreach set_WAN interface
    [ -n "${WAN}" ] && break

    break
done


# Test whether sysctl variable net.netfilter.nf_conntrack_skip_filter variable is set properly
test_skip_filter() {
    if [ "$(sysctl -n net.netfilter.nf_conntrack_skip_filter)" == "1" ]; then
        logger -t turris-firewall-rules -p err "(v${VERSION}) sysctl variable net.netfilter.nf_conntrack_skip_filter is set to 1. Some features of the firewall might not work properly. Please consider setting it to 0."
    fi
}

# Are ipset modules for ipset loaded
test_ipset_modules() {
    if [ -n "$(lsmod | grep ip_set)" ]; then
        return 0
    else
        return 1
    fi
}

# is NFLOG module loaded
test_nflog_modules() {
    if [ -n "$(lsmod | grep xt_NFLOG)" ]; then
        return 0
    else
        return 1
    fi
}

# Should load NFLOG
test_nflog() {
    if test_nflog_modules ; then

        config_load firewall-turris

        # test using uci
        config_get_bool pcap_enabled pcap enabled "0"
        if [ "$pcap_enabled" = "1" ]; then
            return 0
        fi
    fi
    return 1
}

# Should use exensive dumping
# might create huge dumps...
test_nflog_extensive() {
    if test_nflog_modules ; then

        config_load firewall-turris

        # test using uci
        config_get_bool pcap_extensive pcap extensive "0"
        if [ "$pcap_extensive" = "1" ]; then
            return 0
        fi
    fi
    return 1
}

# Load overrides
load_overrides() {
    overrides_block=""
    overrides_log=""
    overrides_log_and_block=""
    overrides_nothing=""
    overrides_pcap_enabled_true=""
    overrides_pcap_enabled_false=""
    overrides_pcap_extensive_true=""
    overrides_pcap_extensive_false=""

    config_load firewall-turris

    append_overrides() {
        local cfg="$1"
        local rule_id
        local action
        config_get rule_id "${cfg}" rule_id "${cfg}"

        config_get action "${cfg}" action
        if [ "$action" == "block" ]; then
            overrides_block="$overrides_block $rule_id"
        elif [ "$action" == "log" ]; then
            overrides_log="$overrides_log $rule_id"
        elif [ "$action" == "log_and_block" ]; then
            overrides_log_and_block="$overrides_log_and_block $rule_id"
        elif [ "$action" == "nothing" ]; then
            overrides_nothing="$overrides_nothing $rule_id"
        fi

        config_get_bool pcap_enabled "${cfg}" pcap_enabled ""
        if [ "$pcap_enabled" == "1" ]; then
            overrides_pcap_enabled_true="$overrides_pcap_enabled_true $rule_id"
        elif [ "$pcap_enabled" == "0" ]; then
            overrides_pcap_enabled_false="$overrides_pcap_enabled_false $rule_id"
        fi
        config_get_bool pcap_extensive "${cfg}" pcap_extensive ""
        if [ "$pcap_extensive" == "1" ]; then
            overrides_pcap_extensive_true="$overrides_pcap_extensive_true $rule_id"
        elif [ "$pcap_extensive" == "0" ]; then
            overrides_pcap_extensive_false="$overrides_pcap_extensive_false $rule_id"
        fi
    }

    config_foreach append_overrides rule_override
}

# is in list 
is_in_list() {
    local item="$1"
    local list="$2"
    if [ "${list/$item}" == "${list}" ]; then
        return 1
    fi
    return 0
}

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
    if [ -f "${persistent}" ]; then
        cmp -s "${downloaded}" "${persistent}"
        if [ $? -eq 1 ]; then
            local new_md5=$(file_md5 "${downloaded}")
            local old_md5=$(file_md5 "${persistent}")
            logger -t turris-firewall-rules "(v${VERSION}) Switching ${file_name} ${old_md5} -> ${new_md5}"
            cp "${downloaded}" "${persistent}"
        fi
    else
        local new_md5=$(file_md5 "${downloaded}")
        logger -t turris-firewall-rules "(v${VERSION}) Setting ${file_name} ${new_md5}"
        cp "${downloaded}" "${persistent}"
    fi
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

# create config for ulogd
make_ulogd_config() {
    local ids="$@"
    local idx=0
    local rule_id

    # Create a directory for logging
    mkdir -p "${PCAP_DIR}"

    # Part of a global section
    echo "# This file is generated using turris-firewall-rules any local changes will be destroyed." > "${ULOGD_FILE}"
    echo "[global]" >> "${ULOGD_FILE}"
    echo "plugin=\"/usr/lib/ulogd/ulogd_inppkt_NFLOG.so\"" >> "${ULOGD_FILE}"
    echo "plugin=\"/usr/lib/ulogd/ulogd_output_PCAP.so\"" >> "${ULOGD_FILE}"
    echo "plugin=\"/usr/lib/ulogd/ulogd_raw2packet_BASE.so\"" >> "${ULOGD_FILE}"

    # stacks
    for rule_id in $ids; do
        group_id=$(($idx + 1000))
        echo "stack=log${group_id}:NFLOG,base1:BASE,pcap${group_id}:PCAP" >> "${ULOGD_FILE}"
        idx=$(($idx + 1))
    done

    idx=0
    # sections
    for rule_id in $ids; do
        group_id=$(($idx + 1000))
        echo "[log${group_id}]" >> "${ULOGD_FILE}"
        echo "group=${group_id}" >> "${ULOGD_FILE}"
        echo "[pcap${group_id}]" >> "${ULOGD_FILE}"
        echo "file=\"${PCAP_DIR}/${rule_id}.pcap\"" >> "${ULOGD_FILE}"
        echo "sync=1" >> "${ULOGD_FILE}"
        idx=$(($idx + 1))
    done
}

ulogd_restart() {
    local log="$1"

    # restart when checksum does not exist
    if [ ! -e "${ULOGD_FILE}.md5" ]; then
        /etc/init.d/ulogd restart

    else

        # restart when the configuration changes
        if md5sum -s -c "${ULOGD_FILE}.md5"; then

            # restart when log is enabled and the process is not running
            if [ "${log}" = "yes" ]; then
                if start-stop-daemon -q -K -t -x /usr/sbin/ulogd; then
                    :
                else
                    /etc/init.d/ulogd restart
                fi
            fi
        else
            /etc/init.d/ulogd restart
        fi
    fi

    # store checksum
    md5sum "${ULOGD_FILE}" > "${ULOGD_FILE}.md5"
}

apply_isets() {
    if [ -f "${PERSISTENT_IPSETS}" ]; then
        # Append header to files
        echo ':turris - [0:0]' >> "${TMP_FILE}"
        echo ':turris - [0:0]' >> "${TMP_FILE6}"
        eval echo "-I accept -o ${WAN} -j turris" >> "${TMP_FILE}"
        eval echo "-I accept -o ${WAN} -j turris" >> "${TMP_FILE6}"

        local count="$(grep '^add [^ ]*_4' ${PERSISTENT_IPSETS} | wc -l)"
        local count6="$(grep '^add [^ ]*_6' ${PERSISTENT_IPSETS} | wc -l)"
        local skip_count=0
        local override_count=0

        # Load new ipsets
        ipset restore -f "${PERSISTENT_IPSETS}"

        # Create all if exist swap otherwise rename append rules
        local old_names="$(ipset list | grep 'Name: turris_' | cut -d' ' -f2- | sort)"
        local new_names="$(grep create ${PERSISTENT_IPSETS} | cut -d' ' -f2 | sort)"

        # Should NFLOG be activated (to be applied)
        nflog_idx=0
        if test_nflog ; then
            nflog="yes"

            local rule_ids=$(echo "${new_names}" | cut -d_ -f2)
            make_ulogd_config "${rule_ids}"

        else
            # clear the log file when disabled
            echo > "${ULOGD_FILE}"
        fi
        if test_nflog_extensive ; then
            nflog_extensive="yes"
            nflog_chain="turris-nflog"
        else
            nflog_chain="turris"
        fi

        # add a new chain for extensive pcap logging
        echo ':turris-nflog - [0:0]' >> "${TMP_FILE}"
        echo ':turris-nflog - [0:0]' >> "${TMP_FILE6}"
        eval echo "-I forwarding_rule -j turris-nflog" >> "${TMP_FILE}"
        eval echo "-I forwarding_rule -j turris-nflog" >> "${TMP_FILE6}"

        # add a new chain for storing dropped packets which match issued with a propper ID
        echo ':turris-reject - [0:0]' >> "${TMP_FILE}"
        echo ':turris-reject - [0:0]' >> "${TMP_FILE6}"
        eval echo "-I reject -j turris-reject" >> "${TMP_FILE}"
        eval echo "-I reject -j turris-reject" >> "${TMP_FILE6}"

        # restart ulogd to reinit configuration
        ulogd_restart "${nflog}"

        local nflog_rules_4=""
        local log_rules_4=""
        local drop_rules_4=""

        local nflog_rules_6=""
        local log_rules_6=""
        local drop_rules_6=""

        # load the overrides
        load_overrides

        # Create iptables rules
        for ipset_name in ${new_names}; do
            local rule_id="$(echo ${ipset_name} | cut -d_ -f2)"
            local action="$(echo ${ipset_name} | cut -d_ -f3)"
            local type="$(echo ${ipset_name} | cut -d_ -f4)"
            local ip_type="$(echo ${ipset_name} | cut -d_ -f5)"
            local ipset_name_x="${ipset_name}_X"

            if [ "${old_names/${ipset_name_x}}" = "${old_names}" ]; then
                # set is brand new -> rename
                ipset rename "${ipset_name}" "${ipset_name_x}"
            else
                # set with is active -> swap and delete
                if ipset swap "${ipset_name}" "${ipset_name_x}"; then
                    ipset destroy "${ipset_name}"
                else
                    # When swap fails (This could happen when ipsets have a different type)
                    # destroy the original list and rename the new one
                    #
                    # atomicity is lost, but this should be a rare situation
                    logger -t turris-firewall-rules -p warn "(v${VERSION}) Need to flush turris iptable chain (Atomicity is lost)"
                    iptables -F turris  # can't destroy ipset which is used so we need to detele the iptable rules first
                    ipset destroy "${ipset_name_x}"
                    ipset rename "${ipset_name}" "${ipset_name_x}"
                fi
            fi

            if [ "${type}" = "a" ]; then
                match="dst"
                match_src="src"
            elif [ "${type}" = "ap" ]; then
                match="dst,dst"
                match_src="src,src"
            fi

            # apply rule_overrides
            if is_in_list "${rule_id}" "${overrides_nothing}"; then
                action="n"
                override_count=$(($override_count + 1))
            elif is_in_list "${rule_id}" "${overrides_log_and_block}"; then
                action="lb"
                override_count=$(($override_count + 1))
            elif is_in_list "${rule_id}" "${overrides_block}"; then
                action="b"
                override_count=$(($override_count + 1))
            elif is_in_list "${rule_id}" "${overrides_log}"; then
                action="l"
                override_count=$(($override_count + 1))
            fi

            # apply override nflog rules
            if is_in_list "${rule_id}" "${overrides_pcap_extensive_true}"; then
                local nflog_extensive_local="yes"
                local nflog_chain_local="turris-nflog"
            elif is_in_list "${rule_id}" "${overrides_pcap_extensive_false}"; then
                local nflog_extensive_local="no"
                local nflog_chain_local="turris"
            else
                local nflog_extensive_local=$nflog_extensive
                local nflog_chain_local=$nflog_chain
            fi

            if is_in_list "${rule_id}" "${overrides_pcap_enabled_true}"; then
                local nflog_local="yes"
            elif is_in_list "${rule_id}" "${overrides_pcap_enabled_false}"; then
                local nflog_local="no"
            else
                local nflog_local=$nflog
            fi

            if [ ! "$action" == "n" -a "$nflog_local" == "yes" ]; then
                eval nflog_rules_${ip_type}=\"$(eval echo '$'nflog_rules_${ip_type})"-A ${nflog_chain_local} -o ${WAN} -m set --match-set ${ipset_name_x} ${match} -m comment --comment turris-nflog -j NFLOG --nflog-group $((1000 + $nflog_idx))\n"\"
                if [ "$nflog_extensive_local" == "yes" ]; then
                    eval nflog_rules_${ip_type}=\"$(eval echo '$'nflog_rules_${ip_type})"-A ${nflog_chain_local} -i ${WAN} -m set --match-set ${ipset_name_x} ${match_src} -m comment --comment turris-nflog -j NFLOG --nflog-group $((1000 + $nflog_idx))\n"\"
                fi
            fi

            case "${action}" in
                "b")
                    eval drop_rules_${ip_type}=\"$(eval echo '$'drop_rules_${ip_type})"-A turris -o ${WAN} -m set --match-set ${ipset_name_x} ${match} -j DROP\n"\"
                    eval drop_rules_${ip_type}=\"$(eval echo '$'drop_rules_${ip_type})"-A turris -i ${WAN} -m set --match-set ${ipset_name_x} ${match_src} -j DROP\n"\"
                    ;;
                "l")
                    eval log_rules_${ip_type}=\""$(eval echo '$'log_rules_${ip_type})"-A turris -o ${WAN} -m limit --limit 1/sec -m set --match-set ${ipset_name_x} ${match} -j LOG --log-prefix \'turris-${rule_id}: \' --log-level debug\\n\"
                    eval log_rules_${ip_type}=\""$(eval echo '$'log_rules_${ip_type})"-A turris -i ${WAN} -m limit --limit 1/sec -m set --match-set ${ipset_name_x} ${match_src} -j LOG --log-prefix \'turris-${rule_id}: \' --log-level debug\\n\"
                    eval reject_rules_${ip_type}=\""$(eval echo '$'reject_rules_${ip_type})"-A turris-reject -i ${WAN} -m limit --limit 1/sec -m set --match-set ${ipset_name_x} ${match_src} -j LOG --log-prefix \'turris-${rule_id}: \' --log-level debug\\n\"
                    ;;
                "lb")
                    eval log_rules_${ip_type}=\""$(eval echo '$'log_rules_${ip_type})"-A turris -o ${WAN} -m limit --limit 1/sec -m set --match-set ${ipset_name_x} ${match} -j LOG --log-prefix \'turris-${rule_id}: \' --log-level debug\\n\"
                    eval log_rules_${ip_type}=\""$(eval echo '$'log_rules_${ip_type})"-A turris -i ${WAN} -m limit --limit 1/sec -m set --match-set ${ipset_name_x} ${match_src} -j LOG --log-prefix \'turris-${rule_id}: \' --log-level debug\\n\"
                    eval reject_rules_${ip_type}=\""$(eval echo '$'reject_rules_${ip_type})"-A turris-reject -i ${WAN} -m limit --limit 1/sec -m set --match-set ${ipset_name_x} ${match_src} -j LOG --log-prefix \'turris-${rule_id}: \' --log-level debug\\n\"
                    eval drop_rules_${ip_type}=\"$(eval echo '$'drop_rules_${ip_type})"-A turris -o ${WAN} -m set --match-set ${ipset_name_x} ${match} -j DROP\n"\"
                    eval drop_rules_${ip_type}=\"$(eval echo '$'drop_rules_${ip_type})"-A turris -i ${WAN} -m set --match-set ${ipset_name_x} ${match_src} -j DROP\n"\"
                    ;;
                "n")
                    skip_count=$(($skip_count + 1))
            esac

            # increase nflog_group number
            nflog_idx=$(($nflog_idx + 1))
        done

        echo -e "${nflog_rules_4}" >> "${TMP_FILE}"
        echo -e "${nflog_rules_6}" >> "${TMP_FILE6}"

        # iptables-restore does not like ' character
        echo -e "${log_rules_4}" | tr \' \" >> "${TMP_FILE}"
        echo -e "${log_rules_6}" | tr \' \" >> "${TMP_FILE6}"
        echo -e "${reject_rules_4}" | tr \' \" >> "${TMP_FILE}"
        echo -e "${reject_rules_6}" | tr \' \" >> "${TMP_FILE6}"
        echo -e "${drop_rules_4}" >> "${TMP_FILE}"
        echo -e "${drop_rules_6}" >> "${TMP_FILE6}"

        # Add the commit
        echo COMMIT >> "${TMP_FILE}"
        echo COMMIT >> "${TMP_FILE6}"

        # Apply iptables
        iptables-restore -T filter < "${TMP_FILE}"
        if [ $? -eq 1 ]; then
            logger -t turris-firewall-rules -p err "(v${VERSION}) Failed to load downloaded ipv4 rules"
            release_lockfile
            exit 1
        fi
        ip6tables-restore -T filter < "${TMP_FILE6}"
        if [ $? -eq 1 ]; then
            logger -t turris-firewall-rules -p err "(v${VERSION}) Failed to load downloaded ipv6 rules"
            release_lockfile
            exit 1
        fi

        md5=$(file_md5 "${PERSISTENT_IPSETS}")
        logger -t turris-firewall-rules "(v${VERSION}) ${count} ipv4 address(es) and ${count6} ipv6 address(es) were loaded ($md5), ${override_count} rule(s) overriden, ${skip_count} rule(s) skipped"
    fi
}

if [ -n "${WAN}" ]; then
    CHAIN="turris"

    if test_branch ; then
        if [ ! -f "${TEST_SIGN_KEY}" ] ; then
            curl -fs --cacert /etc/ssl/startcom.pem --crlfile "${CRL_FILE}" "${TEST_SIGN_KEY_URL}" -o "${TEST_SIGN_KEY}"
        fi
        test="true"
    else
        test="false"
    fi

    test_skip_filter

    # Don't any turris related rules and COMMIT
    iptables-save -t filter | grep -v '\-j turris' | grep -v '^-. turris' | grep -v '^:turris' | grep -v COMMIT > "${TMP_FILE}"
    ip6tables-save -t filter | grep -v '\-j turris' | grep -v '^-. turris' | grep -v '^:turris' | grep -v COMMIT > "${TMP_FILE6}"

    # Create directory for the rules
    mkdir -p "${DOWNLOAD_DIR}"

    # Try to update CRL
    get-api-crl 1>/dev/null 2>&1

    if test_ipset_modules ; then
        # Using ipset

        # Download the ipsets signature
        download "${IPSETS_SIGN_URL}" "${TEST_IPSETS_SIGN_URL}" "${DOWNLOAD_IPSETS_SIGN}" "${DOWNLOAD_INTERVAL}"

        # test whether is necessary to download the whole file
        if [ -f "${PERSISTENT_IPSETS}" ]; then
            verify_signature "${PERSISTENT_IPSETS}" "${DOWNLOAD_IPSETS_SIGN}"
            if [ $? -eq 0 ]; then
                # Skip when signature matches
                :
            else
                # download new rules
                download "${IPSETS_URL}" "${TEST_IPSETS_URL}" "${DOWNLOAD_IPSETS}"
            fi
        else
            download "${IPSETS_URL}" "${TEST_IPSETS_URL}" "${DOWNLOAD_IPSETS}"
        fi

        # update file in the persistent memory
        update_file "${DOWNLOAD_IPSETS_SIGN}" "${DOWNLOAD_IPSETS}" "${PERSISTENT_IPSETS}"

        # generate the rule description file
        generate_rule_description_file

        # Apply the sets
        apply_isets

    else
        logger -t turris-firewall-rules "(v${VERSION}) Ipset modules not loaded. Turris rules were not applied!"
    fi

    rm -f "${TMP_FILE}"
    rm -f "${TMP_FILE6}"
fi

release_lockfile
