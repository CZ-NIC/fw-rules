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
# It applies firewall rules issued by CZ.NIC s.z.p.o.
# as a part of Turris project (see https://www.turris.cz/)
#
# To enable/disable the rules please edit /etc/config/firewall
#
# config include
#   option path /usr/share/firewall/turris
#
# It is periodically executed using cron (see /etc/cron.d/fw-rules - within firewall reload)
#
# Related UCI config /etc/config/firewall-turris
#

. $IPKG_INSTROOT/lib/functions.sh

LOCK_FILE="/tmp/turris-firewall-rules-apply.lock"

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

get_wan() {
    IFACES="$1"
    IGNORE="$2"
    for iface in $IFACES ; do
        if echo "$IGNORE" | grep -qwF "$iface" ; then
            continue;
        fi
        echo "$iface"
        return
    done
}

acquire_lockfile

# Enable debug
if [ -n "${DEBUG}" ]; then
    set -x
fi

TMP_FILE="/tmp/iptables.rules"
TMP_FILE6="/tmp/ip6tables.rules"
PERSISTENT_IPSETS="/usr/share/firewall/turris-ipsets.gz"
TMP_IPSETS="/tmp/turris-ipsets"
ULOGD_FILE="/tmp/etc/ulogd-turris.conf"
PCAP_DIR="/var/log/turris-pcap"

VERSION=0
WAN=""
WAN6=""

while [ -z "${WAN}" ]; do

    # read wan from nikola
    config_load nikola
    config_get WAN main wan_ifname
    config_get WAN6 main wan6_ifname

    # autodetect using default routes (taken from ucollect init script)

    # Look into the routing tables to guess WAN interfaces
    V4=$(route -n | sed -ne 's/ *$//;/^0\.0\.0\.0  *[0-9.][0-9.]*  *0\.0\.0\.0/s/.* //p')
    V6=$(route -n -A inet6 | sed -ne 's/ *$//;/^::\/0  /s/.* //p')

    # Unify them and remove duplicates
    V4=$(echo "$V4" | sed -e 's/  */ /g;s/ /\n/g' | sort -u)
    V6=$(echo "$V6" | sed -e 's/  */ /g;s/ /\n/g' | sort -u)

    IGNORE=$(uci -X show network | sed -ne 's/^network\.\([^.]*\)=interface$/\1/p' | while read iface ; do
        proto=$(uci get -q network.$iface.proto)
        name=$(echo "$proto-$iface" | head -c 15)
        # TODO: What about L2TP? #3093
        if [ "$proto" = "6in4" -o "$proto" = "6to4" -o "$proto" = "6rd" -o "$proto" = "dslite" ] ; then
            # These are tunnels. We can look into them (and do) and they'll travel through the
            # WAN interface, so we don't need these. Ignore them.
            echo "$name"
        fi
    done)

    if [ -z "${WAN}" ]; then
        WAN=$(get_wan "$V4" "$IGNORE")
    fi
    if [ -z "${WAN6}" ]; then
        WAN6=$(get_wan "$V6" "$IGNORE")
        if [ -z "${WAN6}" ]; then  # when WAN6 not set assign WAN as WAN6
            WAN6=${WAN}
        fi
    fi

    if [ -z "${WAN}" ]; then
        logger -t turris-firewall-rules -p err "(v${VERSION}) Unable to determine the WAN interface. Exiting..."
        release_lockfile
        exit 1
    else
        logger -t turris-firewall-rules -p info "(v${VERSION}) IPv4 WAN interface used - '${WAN}'"
        logger -t turris-firewall-rules -p info "(v${VERSION}) IPv6 WAN interface used - '${WAN6}'"
    fi
done

remove_tmp_files() {
    rm -f "${TMP_FILE}"
    rm -f "${TMP_FILE6}"
    rm -f "${TMP_FILE}.part"
    rm -f "${TMP_FILE6}.part"
    rm -f "${TMP_IPSETS}"
}

# Return md5 of a file the file should exist
file_md5() {
    local file="$1"
    echo $(md5sum "${file}" | sed 's/ .*//')
}

# Test whether sysctl variable net.netfilter.nf_conntrack_skip_filter variable is set properly
test_skip_filter() {
    if [ "$(sysctl -e -n net.netfilter.nf_conntrack_skip_filter)" = "1" ]; then
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

# load nflog values
load_nflog_variables() {
    if [ -n "$(lsmod | grep xt_NFLOG)" ]; then
        global_nflog_modules="yes"
    else
        global_nflog_modules="no"
    fi

    config_load firewall-turris

    local pcap_extensive
    config_get_bool pcap_extensive pcap extensive "0"
    if [ "$pcap_extensive" = "1" ]; then
        global_nflog_extensive="yes"
        global_nflog_chain="turris-nflog"
    else
        global_nflog_extensive="no"
        global_nflog_chain="turris"
    fi

    local pcap_dropped
    config_get_bool pcap_dropped pcap log_dropped "0"
    if [ "$pcap_dropped" = "1" ]; then
        global_nflog_dropped="yes"
    else
        global_nflog_dropped="no"
    fi

    local pcap_other_dropped
    config_get_bool pcap_other_dropped pcap log_other_dropped "0"
    if [ "$pcap_other_dropped" = "1" ]; then
        global_nflog_other_dropped="yes"
    else
        global_nflog_other_dropped="no"
    fi

    local pcap_enabled
    config_get_bool pcap_enabled pcap enabled "0"
    global_pcap_enabled="$pcap_enabled"
    if [ "$pcap_enabled" = "1" ]; then
        global_pcap_enabled="yes"
    else
        global_pcap_enabled="no"
    fi
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
    overrides_pcap_dropped_true=""
    overrides_pcap_dropped_false=""

    config_load firewall-turris

    append_overrides() {
        local cfg="$1"
        local rule_id
        local action
        local pcap_enabled
        local pcap_extensive
        local pcap_log_dropped

        config_get rule_id "${cfg}" rule_id "${cfg}"

        config_get action "${cfg}" action
        if [ "$action" = "block" ]; then
            overrides_block="$overrides_block $rule_id"
        elif [ "$action" = "log" ]; then
            overrides_log="$overrides_log $rule_id"
        elif [ "$action" = "log_and_block" ]; then
            overrides_log_and_block="$overrides_log_and_block $rule_id"
        elif [ "$action" = "nothing" ]; then
            overrides_nothing="$overrides_nothing $rule_id"
        fi

        config_get_bool pcap_enabled "${cfg}" pcap_enabled ""
        if [ "$pcap_enabled" = "1" ]; then
            overrides_pcap_enabled_true="$overrides_pcap_enabled_true $rule_id"
        elif [ "$pcap_enabled" = "0" ]; then
            overrides_pcap_enabled_false="$overrides_pcap_enabled_false $rule_id"
        fi
        config_get_bool pcap_extensive "${cfg}" pcap_extensive ""
        if [ "$pcap_extensive" = "1" ]; then
            overrides_pcap_extensive_true="$overrides_pcap_extensive_true $rule_id"
        elif [ "$pcap_extensive" = "0" ]; then
            overrides_pcap_extensive_false="$overrides_pcap_extensive_false $rule_id"
        fi
        config_get_bool pcap_log_dropped "${cfg}" pcap_log_dropped ""
        if [ "$pcap_log_dropped" = "1" ]; then
            overrides_pcap_dropped_true="$overrides_pcap_dropped_true $rule_id"
        elif [ "$pcap_log_dropped" = "0" ]; then
            overrides_pcap_dropped_false="$overrides_pcap_dropped_false $rule_id"
        fi
    }

    config_foreach append_overrides rule_override
}

# is in list 
is_in_list() {
    local item="$1"
    local list="$2"
    if [ "${list/$item}" = "${list}" ]; then
        return 1
    fi
    return 0
}

# create config for ulogd
make_ulogd_config() {
    local ids="$1"
    local true_overrides="$2"
    local false_overrides="$3"
    local enabled="$4"
    local other_dropped="$5"
    local idx=0
    local rule_id
    local final_list=""

    for rule_id in $ids; do
        if [ "$enabled" = "yes" ]; then
            if is_in_list "${rule_id}" "${false_overrides}"; then
                continue
            else
                final_list="$final_list ${rule_id}"
            fi
        elif [ "$enabled" = "no" ]; then
            if is_in_list "${rule_id}" "${true_overrides}"; then
                final_list="$final_list ${rule_id}"
            else
                continue
            fi
        fi
    done

    # Create a directory for logging
    mkdir -p "${PCAP_DIR}"

    # Part of a global section
    echo "# This file is generated using turris-firewall-rules any local changes will be destroyed." > "${ULOGD_FILE}"
    echo "[global]" >> "${ULOGD_FILE}"
    echo "plugin=\"/usr/lib/ulogd/ulogd_inppkt_NFLOG.so\"" >> "${ULOGD_FILE}"
    echo "plugin=\"/usr/lib/ulogd/ulogd_output_PCAP.so\"" >> "${ULOGD_FILE}"
    echo "plugin=\"/usr/lib/ulogd/ulogd_raw2packet_BASE.so\"" >> "${ULOGD_FILE}"

    if [ $enabled == "yes" -a $other_dropped == "yes" ]; then
        echo "stack=log999:NFLOG,base1:BASE,pcap999:PCAP" >> "${ULOGD_FILE}"
    fi

    # stacks
    for rule_id in $final_list; do
        group_id=$(($idx + 1000))
        echo "stack=log${group_id}:NFLOG,base1:BASE,pcap${group_id}:PCAP" >> "${ULOGD_FILE}"
        idx=$(($idx + 1))
    done

    if [ $enabled == "yes" -a $other_dropped == "yes" ]; then
        echo "[log999]" >> "${ULOGD_FILE}"
        echo "group=999" >> "${ULOGD_FILE}"
        echo "[pcap999]" >> "${ULOGD_FILE}"
        echo "file=\"${PCAP_DIR}/00000000.pcap\"" >> "${ULOGD_FILE}"
        echo "sync=1" >> "${ULOGD_FILE}"
    fi

    idx=0
    # sections
    for rule_id in $final_list; do
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

    # restart when checksum does not exist
    if [ ! -e "${ULOGD_FILE}.md5" ]; then
        /etc/init.d/ulogd restart

    else

        # restart when the configuration changes
        if md5sum -s -c "${ULOGD_FILE}.md5"; then

            # restart when the process is not running
            if start-stop-daemon -q -K -t -x /usr/sbin/ulogd; then
                :
            else
                /etc/init.d/ulogd restart
            fi
        else
            /etc/init.d/ulogd restart
        fi
    fi

    # store checksum
    md5sum "${ULOGD_FILE}" > "${ULOGD_FILE}.md5"
}

load_ipsets_to_iptables() {
    # Append header to files
    echo ':turris - [0:0]' > "${TMP_FILE}.part"
    echo ':turris - [0:0]' > "${TMP_FILE6}.part"
    eval echo "-I accept -j turris" >> "${TMP_FILE}.part"
    eval echo "-I accept -j turris" >> "${TMP_FILE6}.part"

    skip_count=0
    override_count=0

    # Load new ipsets
    ipset restore -f "${TMP_IPSETS}"
    if [ ! "$?" = 0 ]; then
        logger -t turris-firewall-rules -p err "(v${VERSION}) Failed to restore ipsets"
        remove_tmp_files
        release_lockfile
        exit 1
    fi

    # Create all if exist swap otherwise rename append rules
    local old_names="$(ipset list | grep 'Name: turris_' | cut -d' ' -f2- | sort)"
    local new_names="$(grep create ${TMP_IPSETS} | cut -d' ' -f2 | sort)"

    # load the overrides
    load_overrides

    # load local variables
    load_nflog_variables

    nflog_idx=0

    # Should NFLOG be activated (to be applied)
    if [ "$global_nflog_modules" = "yes" -a \( "$global_pcap_enabled" = "yes" -o -n "$overrides_pcap_enabled_true" \) ] ; then

        local rule_ids=$(echo "${new_names}" | cut -d_ -f2)
        make_ulogd_config "${rule_ids}" "${overrides_pcap_enabled_true}" "${overrides_pcap_enabled_false}" "${global_pcap_enabled}" "${global_nflog_other_dropped}"

    else
        # clear the log file when disabled
        echo > "${ULOGD_FILE}"
    fi

    # add a new chain for extensive pcap logging
    echo ':turris-nflog - [0:0]' >> "${TMP_FILE}.part"
    echo ':turris-nflog - [0:0]' >> "${TMP_FILE6}.part"
    echo "-I forwarding_rule -j turris-nflog" >> "${TMP_FILE}.part"
    echo "-I forwarding_rule -j turris-nflog" >> "${TMP_FILE6}.part"
    echo "-I input_rule -j turris-nflog" >> "${TMP_FILE}.part"
    echo "-I input_rule -j turris-nflog" >> "${TMP_FILE6}.part"
    echo "-I output_rule -j turris-nflog" >> "${TMP_FILE}.part"
    echo "-I output_rule -j turris-nflog" >> "${TMP_FILE6}.part"

    # add a new chain for storing dropped packets which match issued with a propper ID
    echo ':turris-log-incoming - [0:0]' >> "${TMP_FILE}.part"
    echo ':turris-log-incoming - [0:0]' >> "${TMP_FILE6}.part"
    echo "-I reject -j turris-log-incoming" >> "${TMP_FILE}.part"
    echo "-I reject -j turris-log-incoming" >> "${TMP_FILE6}.part"
    echo "-I drop -j turris-log-incoming" >> "${TMP_FILE}.part"
    echo "-I drop -j turris-log-incoming" >> "${TMP_FILE6}.part"

    # restart ulogd to reinit configuration
    ulogd_restart

    local nflog_rules_4=""
    local log_rules_4=""
    local drop_rules_4=""

    local nflog_rules_6=""
    local log_rules_6=""
    local drop_rules_6=""

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
            local nflog_extensive_local=$global_nflog_extensive
            local nflog_chain_local=$global_nflog_chain
        fi
        if [ "$nflog_extensive_local" = "no" ]; then
            if is_in_list "${rule_id}" "${overrides_pcap_dropped_true}"; then
                local nflog_dropped_local="yes"
            elif is_in_list "${rule_id}" "${overrides_pcap_dropped_false}"; then
                local nflog_dropped_local="no"
            else
                local nflog_dropped_local=$global_nflog_dropped
            fi
        else
            local nflog_dropped_local="no"
        fi

        if is_in_list "${rule_id}" "${overrides_pcap_enabled_true}"; then
            local nflog_local="yes"
        elif is_in_list "${rule_id}" "${overrides_pcap_enabled_false}"; then
            local nflog_local="no"
        else
            nflog_local=$global_pcap_enabled
        fi

        if [ "${ip_type}" = "6" ]; then
            local wan_local=${WAN6}
        else
            local wan_local=${WAN}
        fi

        if [ ! "$action" = "n" -a "$nflog_local" = "yes" ]; then
            eval nflog_rules_${ip_type}=\"$(eval echo '$'nflog_rules_${ip_type})"-A ${nflog_chain_local} -o ${wan_local} -m set --match-set ${ipset_name_x} ${match} -m comment --comment turris-nflog -j NFLOG --nflog-group $((1000 + $nflog_idx))\n"\"
            if [ "$nflog_extensive_local" = "yes" ]; then
                eval nflog_rules_${ip_type}=\"$(eval echo '$'nflog_rules_${ip_type})"-A ${nflog_chain_local} -i ${wan_local} -m set --match-set ${ipset_name_x} ${match_src} -m comment --comment turris-nflog -j NFLOG --nflog-group $((1000 + $nflog_idx))\n"\"
            fi
            if [ "$nflog_dropped_local" =  "yes" ]; then
                eval nflog_log_drop_${ip_type}=\"$(eval echo '$'nflog_log_drop_${ip_type})"-A turris-log-incoming -i ${wan_local} -m set --match-set ${ipset_name_x} ${match_src} -m comment --comment turris-nflog -j NFLOG --nflog-group $((1000 + $nflog_idx))\n"\"
            fi
        fi

        case "${action}" in
            "b")
                eval drop_rules_${ip_type}=\"$(eval echo '$'drop_rules_${ip_type})"-A turris -o ${wan_local} -m set --match-set ${ipset_name_x} ${match} -j DROP\n"\"
                eval drop_rules_${ip_type}=\"$(eval echo '$'drop_rules_${ip_type})"-A turris -i ${wan_local} -m set --match-set ${ipset_name_x} ${match_src} -j DROP\n"\"
                ;;
            "l")
                eval log_rules_${ip_type}=\""$(eval echo '$'log_rules_${ip_type})"-A turris -o ${wan_local} -m limit --limit 1/sec -m set --match-set ${ipset_name_x} ${match} -j LOG --log-prefix \'turris-${rule_id}: \' --log-level debug\\n\"
                eval log_rules_${ip_type}=\""$(eval echo '$'log_rules_${ip_type})"-A turris -i ${wan_local} -m limit --limit 1/sec -m set --match-set ${ipset_name_x} ${match_src} -j LOG --log-prefix \'turris-${rule_id}: \' --log-level debug\\n\"
                eval reject_rules_${ip_type}=\""$(eval echo '$'reject_rules_${ip_type})"-A turris-log-incoming -i ${wan_local} -m limit --limit 1/sec -m set --match-set ${ipset_name_x} ${match_src} -j LOG --log-prefix \'turris-${rule_id}: \' --log-level debug\\n\"
                eval return_rules_${ip_type}=\"$(eval echo '$'return_rules_${ip_type})"-A turris-log-incoming -i ${wan_local} -m set --match-set ${ipset_name_x} ${match_src} -j RETURN\n"\"
                ;;
            "lb")
                eval log_rules_${ip_type}=\""$(eval echo '$'log_rules_${ip_type})"-A turris -o ${wan_local} -m limit --limit 1/sec -m set --match-set ${ipset_name_x} ${match} -j LOG --log-prefix \'turris-${rule_id}: \' --log-level debug\\n\"
                eval log_rules_${ip_type}=\""$(eval echo '$'log_rules_${ip_type})"-A turris -i ${wan_local} -m limit --limit 1/sec -m set --match-set ${ipset_name_x} ${match_src} -j LOG --log-prefix \'turris-${rule_id}: \' --log-level debug\\n\"
                eval reject_rules_${ip_type}=\""$(eval echo '$'reject_rules_${ip_type})"-A turris-log-incoming -i ${wan_local} -m limit --limit 1/sec -m set --match-set ${ipset_name_x} ${match_src} -j LOG --log-prefix \'turris-${rule_id}: \' --log-level debug\\n\"
                eval return_rules_${ip_type}=\"$(eval echo '$'return_rules_${ip_type})"-A turris-log-incoming -i ${wan_local} -m set --match-set ${ipset_name_x} ${match_src} -j RETURN\n"\"
                eval drop_rules_${ip_type}=\"$(eval echo '$'drop_rules_${ip_type})"-A turris -o ${wan_local} -m set --match-set ${ipset_name_x} ${match} -j DROP\n"\"
                eval drop_rules_${ip_type}=\"$(eval echo '$'drop_rules_${ip_type})"-A turris -i ${wan_local} -m set --match-set ${ipset_name_x} ${match_src} -j DROP\n"\"
                ;;
            "n")
                skip_count=$(($skip_count + 1))
        esac

        if [ "$nflog_local" = "yes" ]; then
            # increase nflog_group number
            nflog_idx=$(($nflog_idx + 1))
        fi
    done

    echo -e "${nflog_rules_4}" >> "${TMP_FILE}.part"
    echo -e "${nflog_rules_6}" >> "${TMP_FILE6}.part"

    # iptables-restore does not like ' character
    echo -e "${log_rules_4}" | tr \' \" >> "${TMP_FILE}.part"
    echo -e "${reject_rules_4}" | tr \' \" >> "${TMP_FILE}.part"
    echo -e "${nflog_log_drop_4}" >> "${TMP_FILE}.part"
    echo -e "${return_rules_4}" | tr \' \" >> "${TMP_FILE}.part"
    echo -e "-A turris-log-incoming -m limit --limit 1/sec --limit-burst 500 -j LOG --log-prefix \"turris-00000000: \" --log-level 7" >> "${TMP_FILE}.part"
    if [ $global_pcap_enabled = "yes" -a $global_nflog_other_dropped = "yes" ]; then
        echo -e "-A turris-log-incoming -i ${WAN} -m comment --comment turris-nflog -j NFLOG --nflog-group 999" >> "${TMP_FILE}.part"
    fi
    echo -e "${drop_rules_4}" >> "${TMP_FILE}.part"

    echo -e "${log_rules_6}" | tr \' \" >> "${TMP_FILE6}.part"
    echo -e "${reject_rules_6}" | tr \' \" >> "${TMP_FILE6}.part"
    echo -e "${nflog_log_drop_6}" >> "${TMP_FILE6}.part"
    echo -e "${return_rules_6}" | tr \' \" >> "${TMP_FILE6}.part"
    echo -e "-A turris-log-incoming -m limit --limit 1/sec --limit-burst 500 -j LOG --log-prefix \"turris-00000000: \" --log-level 7" >> "${TMP_FILE6}.part"
    if [ $global_pcap_enabled = "yes" -a $global_nflog_other_dropped = "yes" ]; then
        echo -e "-A turris-log-incoming -i ${WAN6} -m comment --comment turris-nflog -j NFLOG --nflog-group 999" >> "${TMP_FILE6}.part"
    fi
    echo -e "" >> "${TMP_FILE6}.part"
    echo -e "${drop_rules_6}" >> "${TMP_FILE6}.part"

    # Add the commit
    echo COMMIT >> "${TMP_FILE}.part"
    echo COMMIT >> "${TMP_FILE6}.part"
}

load_empty_ipsets_to_iptables() {
    echo ":turris-log-incoming - [0:0]" > "${TMP_FILE}.part"
    echo ":turris-log-incoming - [0:0]" > "${TMP_FILE6}.part"
    echo "-I reject -j turris-log-incoming" >> "${TMP_FILE}.part"
    echo "-I reject -j turris-log-incoming" >> "${TMP_FILE6}.part"
    echo "-I drop -j turris-log-incoming" >> "${TMP_FILE}.part"
    echo "-I drop -j turris-log-incoming" >> "${TMP_FILE6}.part"
    echo -e "-A turris-log-incoming -m limit --limit 1/sec --limit-burst 500 -j LOG --log-prefix \"turris-00000000: \" --log-level 7" >> "${TMP_FILE6}.part"
    echo -e "-A turris-log-incoming -m limit --limit 1/sec --limit-burst 500 -j LOG --log-prefix \"turris-00000000: \" --log-level 7" >> "${TMP_FILE}.part"
    echo COMMIT >> "${TMP_FILE}.part"
    echo COMMIT >> "${TMP_FILE6}.part"
}

store_iptables() {
    # Don't any turris related rules and COMMIT
    iptables-save -t filter | grep -v '\-j turris' | grep -v '^-. turris' | grep -v '^:turris' | grep -v COMMIT > "${TMP_FILE}"
    ip6tables-save -t filter | grep -v '\-j turris' | grep -v '^-. turris' | grep -v '^:turris' | grep -v COMMIT > "${TMP_FILE6}"
}

restore_iptables() {
    cat "${TMP_FILE}.part" >> "${TMP_FILE}"
    cat "${TMP_FILE6}.part" >> "${TMP_FILE6}"

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
}

apply_isets() {
    if [ -f "${PERSISTENT_IPSETS}" ]; then
        # Unpack PERSISTENT_IPSETS
        gunzip -c "${PERSISTENT_IPSETS}" > "${TMP_IPSETS}" 2>/dev/null
        if [ ! "$?" = 0 ]; then
            logger -t turris-firewall-rules -p err "(v${VERSION}) Failed to unpack ipset rules"
            remove_tmp_files
            release_lockfile
            exit 1
        fi

        load_ipsets_to_iptables
        store_iptables
        restore_iptables

        local md5=$(file_md5 "${PERSISTENT_IPSETS}")
        local count="$(grep '^add [^ ]*_4' ${TMP_IPSETS} | wc -l)"
        local count6="$(grep '^add [^ ]*_6' ${TMP_IPSETS} | wc -l)"
        logger -t turris-firewall-rules "(v${VERSION}) ${count} ipv4 address(es) and ${count6} ipv6 address(es) were loaded ($md5), ${override_count} rule(s) overriden, ${skip_count} rule(s) skipped"

        # generate the rule description file
        $(dirname $(readlink -f "$0"))/turris-description
    else

        load_empty_ipsets_to_iptables
        store_iptables
        restore_iptables

        logger -t turris-firewall-rules "(v${VERSION}) Turris rules haven't been downloaded from the server yet."
    fi
}

if [ -n "${WAN}" ]; then
    CHAIN="turris"

    test_skip_filter

    if test_ipset_modules ; then

        # Apply the sets
        apply_isets

    else
        logger -t turris-firewall-rules "(v${VERSION}) Ipset modules not loaded. Turris rules were not applied!"
    fi

    remove_tmp_files
fi

release_lockfile
