#!/bin/sh

: <<-'EOF'
Copyright 2017 Xingwang Liao <kuoruan@gmail.com>
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
	http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
EOF

INTERFACE='venet0'
LKL_TAP_NAME='lkl'
HAPROXY_LKL_DIR=

HAPROXY_BIN="${HAPROXY_LKL_DIR}/sbin/haproxy"
PROT_RULES_FILE="${HAPROXY_LKL_DIR}/etc/port-rules"
HAPROXY_CFG_FILE="${HAPROXY_LKL_DIR}/etc/haproxy.cfg"

PIDFILE='/var/run/haproxy-lkl.pid'

RETVAL=0

command_exists() {
	command -v "$@" >/dev/null 2>&1
}

check_constants() {
	if [ -z "$INTERFACE" ]; then
		cat >&2 <<-EOF
		Error: Please set your network interface first.
		    * Edit $0 and set INTERFACE at the top.
		EOF
		exit 1
	fi

	if [ -z "$HAPROXY_LKL_DIR" ]; then
		cat >&2 <<-EOF
		Error: Please set your haproxy lkl install dir first.
		    * Edit $0 and set HAPROXY_LKL_DIR at the top.
				* Default is /usr/local/haproxy-lkl
		EOF
		exit 1
	fi
}

set_network() {
	if ( command_exists ip && ip tuntap 2>/dev/null ); then
		ip tuntap del dev ${LKL_TAP_NAME} mode tap 2>/dev/null
		ip tuntap add dev ${LKL_TAP_NAME} mode tap 2>/dev/null
	elif command_exists tunctl; then
		tunctl -d ${LKL_TAP_NAME} >/dev/null 2>&1
		tunctl -t ${LKL_TAP_NAME} -u haproxy >/dev/null 2>&1
	else
		cat >&2 <<-'EOF'
		Error: Can't find command ip (with tuntap) or tunctl.
		Please install first.
		EOF

		exit 1
	fi

	if command_exists ip; then
		ip addr add dev ${LKL_TAP_NAME} 10.0.0.1/24 2>/dev/null
		ip link set dev ${LKL_TAP_NAME} up 2>/dev/null

		if ! ( ip -o link show | grep -q "$INTERFACE" ); then
			cat >&2 <<-EOF
			Error: You have set a wrong network interface.
			    * Edit $0 and reset the INTERFACE at the top.
			EOF
			exit 1
		fi
	elif command_exists ifconfig; then
		ifconfig ${LKL_TAP_NAME} 10.0.0.1 netmask 255.255.255.0 up

		if ! ( ifconfig -s | grep -q "$INTERFACE" ); then
			cat >&2 <<-EOF
			Error: You have set a wrong network interface.
			    * Edit $0 and reset the INTERFACE at the top.
			EOF
			exit 1
		fi
	else
		cat >&2 <<-'EOF'
		Error: Can't find command ip or ifconfig.
		Please install first.
		EOF
		exit 1
	fi

	if ! command_exists iptables; then
		cat >&2 <<-'EOF'
		Error: Can't find iptables.
		Please install first.
		EOF
		exit 1
	fi

	iptables -P FORWARD ACCEPT 2>/dev/null

	if ! iptables -t nat -C POSTROUTING -o $INTERFACE -j MASQUERADE 2>/dev/null; then
		iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE 2>/dev/null
	fi
}

gen_cfg_file() {
	is_port() {
		local port=$1
		expr $port + 1 >/dev/null 2>&1 && \
			[ "$port" -ge "1" -a "$port" -le "65535" ]
	}

	local created=
	create_empty_rule_file() {
		if [ -z "$created" ]; then
			cat >"$PROT_RULES_FILE" <<-EOF
			# You can config HAproxy-lkl ports by this file.
			# Format: [new port]=[old port]
			# Eg. 8833=443
			# It means HAproxy listen on port 8833,
			# and 443 is the port you want accelerate.
			# One rule per line.
			EOF

			created=1
		fi
	}

	if [ ! -r "$PROT_RULES_FILE" ]; then
		create_empty_rule_file
	fi

	local port_rule_lines="$(grep -v '^#' ${PROT_RULES_FILE})"

	if [ -n "$port_rule_lines" ]; then

		cat >"$HAPROXY_CFG_FILE" <<-EOF
		global
		    user haproxy
		    group haproxy
		defaults
		    mode tcp
		    timeout client 30s
		    timeout server 30s
		    timeout connect 5s
		EOF

		local new_port=
		local old_port=
		local i=0
		for line in $port_rule_lines; do
			new_port="$(echo $line | cut -d '=' -f1)"
			old_port="$(echo $line | cut -d '=' -f2)"

			if [ -n "$old_port" -a -n "$new_port" ] && \
				( is_port "$old_port" && is_port "$new_port" ); then

				i=`expr $i + 1`
				cat >>"$HAPROXY_CFG_FILE" <<-EOF
				listen proxy${i}
				    bind 10.0.0.2:${new_port}
				    server server${i} 10.0.0.1:${old_port}
				EOF

				forword_port "$new_port" "$old_port"
			fi
		done

		if [ "$i" = "0" ]; then
			cat >&2 <<-'EOF'
			Error: You port rule file has a wrong format
			EOF
		fi
	fi

	create_empty_rule_file
}

forword_port() {
	local new_port=$1
	local old_port=$2

	if ! iptables -t nat -C PREROUTING -i $INTERFACE -p tcp \
		--dport $new_port -j DNAT --to-destination 10.0.0.2 2>/dev/null; then
		iptables -t nat -A PREROUTING -i $INTERFACE -p tcp \
			--dport $new_port -j DNAT --to-destination 10.0.0.2 2>/dev/null
	fi

	if ! iptables -t nat -C PREROUTING -i $INTERFACE -p udp \
		--dport $new_port -j REDIRECT --to-port $old_port 2>/dev/null; then
		iptables -t nat -A PREROUTING -i $INTERFACE -p udp \
			--dport $new_port -j REDIRECT --to-port $old_port 2>/dev/null
	fi
}

start_haproxy_lkl() {
	check_constants
	set_network
	gen_cfg_file

	mkdir -p "$HAPROXY_LKL_DIR"

	if [ ! -f "$HAPROXY_BIN" ]; then
		cat >&2 <<-EOF
		Error: Can't find haproxy bin.
		Please put haproxy in ${HAPROXY_BIN}
		EOF
		exit 1
	fi

	if [ ! -x "$HAPROXY_BIN" ]; then
		chmod +x "$HAPROXY_BIN"
	fi

	LD_PRELOAD="${HAPROXY_LKL_DIR}/lib64/liblkl-hijack.so" \
	LKL_HIJACK_NET_QDISC='root|fq' \
	LKL_HIJACK_SYSCTL='net.ipv4.tcp_wmem=4096 65536 67108864' \
	LKL_HIJACK_NET_IFTYPE=tap \
	LKL_HIJACK_NET_IFPARAMS="$LKL_TAP_NAME" \
	LKL_HIJACK_NET_IP=10.0.0.2 \
	LKL_HIJACK_NET_NETMASK_LEN=24 \
	LKL_HIJACK_NET_GATEWAY=10.0.0.1 \
	LKL_HIJACK_OFFLOAD=0x8883 \
	$HAPROXY_BIN -f "$HAPROXY_CFG_FILE" $* &
	RETVAL=$?
	local pid=$!
	if [ "$RETVAL" = "0" ]; then
		echo "$pid" >"$PIDFILE"
	fi
}

start_haproxy_lkl $*
exit $RETVAL
