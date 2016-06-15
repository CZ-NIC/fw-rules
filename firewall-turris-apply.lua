#!/usr/bin/env lua

-- Copyright (c) 2013-2015, CZ.NIC, z.s.p.o. (http://www.nic.cz/)
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions are met:
--    * Redistributions of source code must retain the above copyright
--      notice, this list of conditions and the following disclaimer.
--    * Redistributions in binary form must reproduce the above copyright
--      notice, this list of conditions and the following disclaimer in the
--      documentation and/or other materials provided with the distribution.
--    * Neither the name of the CZ.NIC nor the
--      names of its contributors may be used to endorse or promote products
--      derived from this software without specific prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
-- ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
-- WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
-- DISCLAIMED. IN NO EVENT SHALL CZ.NIC BE LIABLE FOR ANY
-- DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
-- (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
-- LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
-- ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-- (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
-- SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

--
-- This file is interpreted as a lua script.
-- It applies firewall rules issued by CZ.NIC s.z.p.o.
-- as a part of Turris project (see https://www.turris.cz/)
--
-- To enable/disable the rules please edit /etc/config/firewall
--
-- config include
--   option path /usr/share/firewall/turris
--
-- It is periodically executed using cron (see /etc/cron.d/fw-rules - within firewall reload)
--
-- Related UCI config /etc/config/firewall-turris
--

--TODO
-- Get WAN device
-- parse uci config
-- load overrides
-- Unzip and read file
-- tests (loaded ipsets, loaded NFLOG, ...)
-- Remove existing injected ipsets
-- Load ipsets
-- Create iptables rules if needed
-- Handle ulogd
-- debug mode
--TODO

local nixio = require 'nixio'
local io = require 'io'
local os = require 'os'

local VERSION = "0"
local LOCK_FILE_PATH = "/tmp/turris-firewall-rules.lock"
local lock_file = nil


function log(level, message)
	nixio.openlog("turris-firewall-rules")
	nixio.syslog(level, '(v' .. VERSION .. ') ' .. message)
	nixio.closelog()
end

function lock()
	lock_file = nixio.open(LOCK_FILE_PATH, "w")
	if not lock_file:lock("tlock") then
		log('err', "An instance of turris-firewall-rules is already running!")
		os.exit(1)
	end
end

function unlock()
	if lock_file then
		nixio.fs.unlink(LOCK_FILE_PATH)
		lock_file:close()
	end
end

-- locking
lock()


-- unlocking
unlock()
