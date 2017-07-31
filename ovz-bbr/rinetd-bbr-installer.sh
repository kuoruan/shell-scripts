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

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SERVICE_NAME="rinetd-bbr"

BASE_URL='https://github.com/kuoruan/shell-scripts/raw/master/ovz-bbr'
RINETD_BBR_URL="${BASE_URL}/bin/rinetd-bbr"
RINETD_BBR_CFG_FILE="/etc/rinetd-bbr.conf"
RINETD_BBR_SERVICE_DEBIAN_URL="${BASE_URL}/startup/rinetd-bbr.debain"
RINETD_BBR_SERVICE_REDHAT_URL="${BASE_URL}/startup/rinetd-bbr.redhat"
RINETD_BBR_SYSTEMD_FILE_URL="${BASE_URL}/startup/rinetd-bbr.systemd"

# 需要 BBR 加速的端口
ACCELERATE_PORT=

clear

cat >&2 <<-'EOF'
#######################################################
# OpenVZ BBR 一键安装脚本（Rinetd 版）                   #
# 该脚本用于在 OpenVZ 服务器上安装配置 Rinetd BBR     #
# 脚本作者: Xingwang Liao <kuoruan@gmail.com>         #
# 作者博客: https://blog.kuoruan.com/                 #
# Github: https://github.com/kuoruan/shell-scripts    #
# QQ交流群: 43391448, 68133628                        #
#           633945405                                 #
#######################################################
EOF

command_exists() {
	command -v "$@" >/dev/null 2>&1
}

any_key_to_continue() {
	echo "请按任意键继续或 Ctrl + C 退出"
	local saved
	saved="$(stty -g)"
	stty -echo
	stty cbreak
	dd if=/dev/tty bs=1 count=1 2>/dev/null
	stty -raw
	stty echo
	stty $saved
}

check_root() {
	local user
	user="$(id -un 2>/dev/null || true)"
	if [ "$user" != "root" ]; then
		cat >&2 <<-'EOF'
		权限错误, 请使用 root 用户运行此脚本!
		EOF
		exit 1
	fi
}

check_ovz() {
	if [ ! -d /proc/vz ]; then
		cat >&1 <<-'EOF'
		当前服务器好像不是 OpenVZ 架构，你可以直接更换内核以启用 BBR。
		当然，你也可以继续安装。
		EOF
		any_key_to_continue
	fi
}

get_os_info() {
	lsb_dist=''
	dist_version=''
	if command_exists lsb_release; then
		lsb_dist="$(lsb_release -si)"
	fi

	if [ -z "$lsb_dist" ] && [ -r /etc/lsb-release ]; then
		lsb_dist="$(. /etc/lsb-release && echo "$DISTRIB_ID")"
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/debian_version ]; then
		lsb_dist='debian'
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/fedora-release ]; then
		lsb_dist='fedora'
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/oracle-release ]; then
		lsb_dist='oracleserver'
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/centos-release ]; then
		lsb_dist='centos'
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/redhat-release ]; then
		lsb_dist='redhat'
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/photon-release ]; then
		lsb_dist='photon'
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/os-release ]; then
		lsb_dist="$(. /etc/os-release && echo "$ID")"
	fi

	lsb_dist="$(echo "$lsb_dist" | tr '[:upper:]' '[:lower:]')"

	if [ "${lsb_dist}" = "redhatenterpriseserver" ]; then
		lsb_dist='redhat'
	fi

	case "$lsb_dist" in
		ubuntu)
			if command_exists lsb_release; then
				dist_version="$(lsb_release --codename | cut -f2)"
			fi
			if [ -z "$dist_version" ] && [ -r /etc/lsb-release ]; then
				dist_version="$(. /etc/lsb-release && echo "$DISTRIB_CODENAME")"
			fi
		;;

		debian|raspbian)
			dist_version="$(cat /etc/debian_version | sed 's/\/.*//' | sed 's/\..*//')"
			case "$dist_version" in
				9)
					dist_version="stretch"
				;;
				8)
					dist_version="jessie"
				;;
				7)
					dist_version="wheezy"
				;;
			esac
		;;

		oracleserver)
			lsb_dist="oraclelinux"
			dist_version="$(rpm -q --whatprovides redhat-release --queryformat "%{VERSION}\n" | sed 's/\/.*//' | sed 's/\..*//' | sed 's/Server*//')"
		;;

		fedora|centos|redhat)
			dist_version="$(rpm -q --whatprovides ${lsb_dist}-release --queryformat "%{VERSION}\n" | sed 's/\/.*//' | sed 's/\..*//' | sed 's/Server*//' | sort | tail -1)"
		;;

		"vmware photon")
			lsb_dist="photon"
			dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
		;;

		*)
			if command_exists lsb_release; then
				dist_version="$(lsb_release --codename | cut -f2)"
			fi
			if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
				dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
			fi
		;;
	esac

	if [ -z "$lsb_dist" ] || [ -z "$dist_version" ]; then
		cat >&2 <<-EOF
		无法确定服务器系统版本信息。
		请联系脚本作者。
		EOF
		exit 1
	fi
}

install_deps() {
	ip_support_tuntap() {
		command_exists ip && ip tuntap >/dev/null 2>&1
	}
	case "$lsb_dist" in
		ubuntu|debian|raspbian)
			local did_apt_get_update=
			apt_get_update() {
				if [ -z "$did_apt_get_update" ]; then
					( set -x; sleep 3; apt-get update )
					did_apt_get_update=1
				fi
			}

			if ! command_exists wget; then
				apt_get_update
				( set -x; sleep 3; apt-get install -y -q wget ca-certificates )
			fi

			if ! command_exists iptables; then
				apt_get_update
				( set -x; sleep 3; apt-get install -y -q iptables )
			fi
		;;
		fedora|centos|redhat|oraclelinux|photon)
			if [ "$lsb_dist" = "fedora" ] && [ "$dist_version" -ge "22" ]; then
				if ! command_exists wget; then
					( set -x; sleep 3; dnf -y -q install wget ca-certificates )
				fi

				if ! command_exists ip; then
					( set -x; sleep 3; dnf -y -q install iproute )
				fi

				if ! command_exists iptables; then
					( set -x; sleep 3; dnf -y -q install iptables )
				fi

			elif [ "$lsb_dist" = "photon" ]; then
				if ! command_exists wget; then
					( set -x; sleep 3; tdnf -y install wget ca-certificates )
				fi

				if ! command_exists iptables; then
					( set -x; sleep 3; tdnf -y install iptables )
				fi

			else
				if ! command_exists wget; then
					( set -x; sleep 3; yum -y -q install wget ca-certificates )
				fi

				if ! command_exists iptables; then
					( set -x; sleep 3; yum -y -q install iptables )
				fi

			fi
		;;
		*)
			cat >&2 <<-EOF
			暂时不支持当前系统：${lsb_dist} ${dist_version}
			EOF

			exit 1
		;;
	esac
}

download_file() {
	local url="$1"
	local file="$2"
	local verify="$3"
	local retry=0
	local verify_cmd=

	verify_file() {
		if [ -z "$verify_cmd" ] && [ -n "$verify" ]; then
			if [ "${#verify}" = "32" ]; then
				verify_cmd="md5sum"
			elif [ "${#verify}" = "40" ]; then
				verify_cmd="sha1sum"
			elif [ "${#verify}" = "64" ]; then
				verify_cmd="sha256sum"
			elif [ "${#verify}" = "128" ]; then
				verify_cmd="sha512sum"
			fi

			if [ -n "$verify_cmd" ] && ! command_exists "$verify_cmd"; then
				verify_cmd=
			fi
		fi

		if [ -s "$file" ] && [ -n "$verify_cmd" ]; then
			(
				set -x
				echo "${verify}  ${file}" | $verify_cmd -c
			)
			return $?
		fi

		return 1
	}

	download_file_to_path() {
		verify_file && return 0

		if [ $retry -ge 3 ]; then
			rm -f "$file"
			cat >&2 <<-EOF
			文件下载或校验失败! 请重试。
			URL: ${url}
			EOF

			if [ -n "$verify_cmd" ]; then
				cat >&2 <<-EOF
				如果下载多次失败，你可以手动下载文件:
				1. 下载文件 ${url}
				2. 将文件重命名为 $(basename "$file")
				3. 上传文件至目录 $(dirname "$file")
				4. 重新运行安装脚本

				注: 文件目录 . 表示当前目录，.. 表示当前目录的上级目录
				EOF
			fi
			exit 1
		fi

		( set -x; wget -O "$file" --no-check-certificate "$url" )
		if [ "$?" != "0" ] || [ -n "$verify_cmd" ] && ! verify_file; then
			retry=$(expr $retry + 1)
			download_file_to_path
		fi
	}

	download_file_to_path
}

set_config() {
	is_port() {
		local port=$1
		expr $port + 1 >/dev/null 2>&1 && \
			[ "$port" -ge "1" ] && [ "$port" -le "65535" ]
	}

	local input=

	if [ -z "$ACCELERATE_PORT" ] || ! is_port "$ACCELERATE_PORT"; then
		while :
		do
			read -p "请输入需要加速的端口 [1~65535]: " input
			echo
			if [ -n "$input" ] && is_port $input; then
					ACCELERATE_PORT="$input"
			else
				echo "输入有误, 请输入 1~65535 之间的数字!"
				continue
			fi
			break
		done
	fi

	cat >&2 <<-EOF
	---------------------------
	加速端口 = ${ACCELERATE_PORT}
	---------------------------
	EOF

	any_key_to_continue
}

generate_config() {
	cat >"$HAPROXY_CFG_FILE" <<-EOF
	# Config port to enable BBR
	#
	# bindadress bindport connectaddress connectport
	# eg. 0.0.0.0 443 0.0.0.0 443

	0.0.0.0 ${ACCELERATE_PORT} 0.0.0.0 ${ACCELERATE_PORT}

	# logging information
	# logfile /var/log/rinetd-bbr.log

	# uncomment the following line if you want web-server style logfile format
	# logcommon
	EOF
}
