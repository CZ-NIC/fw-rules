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
# It update description of previously downloaded firewall rules
# as a part of Turris project (see https://www.turris.cz/)
#

. $IPKG_INSTROOT/lib/functions.sh

# Enable debug
if [ -n "${DEBUG}" ] ; then
    set -x
fi

PERSISTENT_IPSETS="/usr/share/firewall/turris-ipsets.gz"
RULE_DESCRIPTION_FILE="/tmp/rule-description.txt"
RULE_DESCRIPTION_AWK_FILE="/tmp/rule-description.awk"

generate_rule_description_file() {
    cat > $RULE_DESCRIPTION_AWK_FILE <<"EOF"
BEGIN {
    comments=""
    comments_idx=0
}
/# / {
    can_print=1
    tmp=$0
    sub(/# /, "", tmp)
    comments[comments_idx]=tmp
    comments_idx++
}
/^add |^create |^#Create/ {
    if (can_print) {
        split($2, parsed, "_")
        rule_id=substr(parsed[2], 0, 7)
        rule_id=rule_id "0"
        if (!(rule_id in used)) {
            print rule_id
            for (i = 0; i < comments_idx; ++i) {
                print "\t" comments[i]
            }
            print "\n"
            used[rule_id] = true
        }
    }
    can_print=0
}
!/# / {
    comments_idx=0
}
EOF
    gunzip -c "$PERSISTENT_IPSETS" | awk -f "$RULE_DESCRIPTION_AWK_FILE" - > "$RULE_DESCRIPTION_FILE"
    rm -rf "$RULE_DESCRIPTION_AWK_FILE"
}

generate_rule_description_file
