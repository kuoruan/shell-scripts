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

# Haproxy-lkl 服务名称
SERVICE_NAME='haproxy-lkl'
# Haproxy-lkl 默认安装路径，修改之后需要同时修改服务启动文件
HAPROXY_LKL_DIR="/usr/local/$SERVICE_NAME"

BASE_URL='https://github.com/kuoruan/shell-scripts/raw/master/ovz-bbr'
HAPROXY_BIN_URL="${BASE_URL}/bin/haproxy.linux2628_x86_64"
HAPROXY_LKL_BIN_URL="${BASE_URL}/bin/haproxy-lkl.sh"
HAPROXY_LKL_SERVICE_FILE_DEBIAN_URL="${BASE_URL}/startup/haproxy-lkl.init.debain"
HAPROXY_LKL_SERVICE_FILE_REDHAT_URL="${BASE_URL}/startup/haproxy-lkl.init.redhat"
HAPROXY_LKL_SYSTEMD_FILE_URL="${BASE_URL}/startup/haproxy-lkl.systemd"
LKL_LIB_URL="${BASE_URL}/lib64/liblkl-hijack.so-20170724"
LKL_LIB_MD5='b50fc6a7ccfc70c76f44506814e7e18b'

# 需要 BBR 加速的端口
ACCELERATE_PORT=

clear

cat >&2 <<-'EOF'
#######################################################
# OpenVZ BBR 一键安装脚本                             #
# 该脚本用于在 OpenVZ 服务器上安装配置 Google BBR     #
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

check_root() {
	local user="$(id -un 2>/dev/null || true)"
	if [ "$user" != "root" ]; then
		cat >&2 <<-'EOF'
		权限错误, 请使用 root 用户运行此脚本!
		EOF
		exit 1
	fi
}

check_ovz() {
	if [ ! -d /proc/vz ]; then
		cat >&2 <<-'EOF'
		当前服务器好像不是 OpenVZ 架构，你可以直接更换内核以启用 BBR。
		当然，你也可以继续安装。
		EOF
		any_key_to_continue
	fi
}

check_ldd() {
	local ldd_version="$(ldd --version 2>/dev/null | grep 'ldd' | rev | cut -d ' ' -f1 | rev)"
	if [ -n "$ldd_version" ]; then
		if [ "${ldd_version%.*}" -eq "2" -a "${ldd_version#*.}" -lt "14" ] || \
		[ "${ldd_version%.*}" -lt "2" ]; then
			cat >&2 <<-EOF
			当前服务器的 glibc 版本为 $ldd_version。
			最低版本需求 2.14，低于这个版本无法正常使用。
			请先更新 glibc 之后再运行脚本。
			EOF
			exit 1
	  fi
	else
		cat >&2 <<-EOF
		获取 glibc 版本失败，请手动检查：
		    ldd --version
		最低版本需求 2.14，低于这个版本可能无法正常使用。
		EOF

		( set -x; ldd --version 2>/dev/null )
		any_key_to_continue
	fi
}

check_arch() {
	architecture=$(uname -m)
	case $architecture in
		amd64|x86_64)
			;;
		*)
			cat 1>&2 <<-EOF
			当前脚本仅支持 64 位系统，你的系统为: $architecture
			你可以尝试从源码编译安装 Linux Kernel Library
			    https://github.com/lkl/linux
			EOF
			exit 1
			;;
	esac
}

any_key_to_continue() {
	echo "请按任意键继续或 Ctrl + C 退出"
	local saved="$(stty -g)"
	stty -echo
	stty cbreak
	dd if=/dev/tty bs=1 count=1 2> /dev/null
	stty -raw
	stty echo
	stty $saved
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

	if [ -z "$lsb_dist" -o -z "$dist_version" ]; then
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

			if ! command_exists ip; then
				apt_get_update
				( set -x; sleep 3; apt-get install -y -q iproute )
			fi

			if ! command_exists timeout; then
				apt_get_update
				( set -x; sleep 3; apt-get install -y -q coreutils )
			fi

			if ! command_exists iptables; then
				apt_get_update
				( set -x; sleep 3; apt-get install -y -q iptables )
			fi

			if ! ip_support_tuntap; then
				apt_get_update
				( set -x; sleep 3; apt-get install -y -q uml-utilities )
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

				if ! command_exists timeout; then
					( set -x; sleep 3; dnf -y -q install coreutils )
				fi

				if ! command_exists iptables; then
					( set -x; sleep 3; dnf -y -q install iptables )
				fi

				if ! ip_support_tuntap && ! command_exists tunctl; then
					( set -x; sleep 3; dnf -y -q install tunctl )
				fi
			elif [ "$lsb_dist" = "photon" ]; then
				if ! command_exists wget; then
					( set -x; sleep 3; tdnf -y install wget ca-certificates )
				fi

				if ! command_exists ip; then
					( set -x; sleep 3; tdnf -y install iproute )
				fi

				if ! command_exists timeout; then
					( set -x; sleep 3; tdnf -y install coreutils )
				fi

				if ! command_exists iptables; then
					( set -x; sleep 3; tdnf -y install iptables )
				fi

				if ! ip_support_tuntap && ! command_exists tunctl; then
					( set -x; sleep 3; tdnf -y install tunctl )
				fi
			else
				if ! command_exists wget; then
					( set -x; sleep 3; yum -y -q install wget ca-certificates )
				fi

				if ! command_exists ip; then
					( set -x; sleep 3; yum -y -q install iproute )
				fi

				if ! command_exists timeout; then
					( set -x; sleep 3; yum -y -q install coreutils )
				fi

				if ! command_exists iptables firewall-cmd; then
					( set -x; sleep 3; yum -y -q install iptables )
				fi

				if ! ip_support_tuntap && ! command_exists tunctl; then
					( set -x; sleep 3; yum -y -q install tunctl )
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

check_nat_create() {
	if ( command_exists ip && ip tuntap >/dev/null 2>&1 ); then
		(
			set -x
			ip tuntap del dev lkl-tap-test mode tap >/dev/null 2>&1
			ip tuntap add dev lkl-tap-test mode tap
		)
	elif command_exists tunctl; then
		(
			set -x
			tunctl -d lkl-tap-test >/dev/null 2>&1
			tunctl -t lkl-tap-test
		)
	else
		cat >&2 <<-'EOF'
		无法找到已安装的 ip 命令(支持 tuntap) 或者 tunctl
		应该是脚本自动安装失败了。
		请手动安装 iproute 和 tunctl
		EOF
		exit 1
	fi

	if [ "$?" != "0" ]; then
		cat >&2 <<-'EOF'
		无法创建 NAT 网络。
		由于某些服务商的 VPS 无法创建 NAT 网络，
		所以不支持用此方法开启 BBR，安装脚本将会退出。
		EOF
		exit 1
	fi
}

download_file() {
	local url=$1
	local file=$2

	( set -x; wget -O "$file" --no-check-certificate "$url" )
	if [ "$?" != "0" ]; then
		cat >&2 <<-EOF
		一些文件下载失败！安装脚本需要能访问到 github.com，请检查服务器网络。
		注意: 一些国内服务器可能无法正常访问 github.com。
		EOF

		exit 1
	fi
}

install_haproxy() {
	(
		set -x
		mkdir -p "${HAPROXY_LKL_DIR}"/etc \
			"${HAPROXY_LKL_DIR}"/lib64 \
			"${HAPROXY_LKL_DIR}"/sbin
	)

	if ! grep -q '^haproxy:' '/etc/passwd'; then
		(
			set -x
			useradd -U -s '/usr/sbin/nologin' -d '/nonexistent' haproxy 2>/dev/null
		)
	fi

	local haproxy_bin="${HAPROXY_LKL_DIR}/sbin/haproxy"
	download_file "$HAPROXY_BIN_URL" "$haproxy_bin"
	chmod +x "$haproxy_bin"

	if ! ( $haproxy_bin -v 2>/dev/null | grep -q 'HA-Proxy' ); then
		cat >&2 <<-EOF
		HAproxy 可执行文件无法正常运行
		可能是 glibc 版本过低，或者文件不适用于你的系统。
		请联系脚本作者，寻求支持。
		EOF
		(
			set -x
			ldd --version
		)
		exit 1
	fi

	local haproxy_lkl_bin="${HAPROXY_LKL_DIR}/sbin/${SERVICE_NAME}"
	download_file "$HAPROXY_LKL_BIN_URL" "$haproxy_lkl_bin"

	sed -i -r "s#^HAPROXY_LKL_DIR=.*#HAPROXY_LKL_DIR='"${HAPROXY_LKL_DIR}"'#" \
		"$haproxy_lkl_bin"

	set_interface() {
		local has_vnet=0
		if command_exists ip; then
			ip -o link show | grep -q 'venet0'
			has_vnet=$?
		elif command_exists ifconfig; then
			ifconfig -s | grep -q 'venet0'
			has_vnet=$?
		fi

		if [ "$has_vnet" != 0 ]; then
			cat >&2 <<-EOF
			检测发现你的公网接口不是 venet0，需要你手动输入一下网络接口名称。
			我们会根据网络接口设置转发规则，如果网络接口名称设置不正确，
			外部网络将无法正常访问到内部服务端口。
			 * 网络接口是具有公网 IP 的接口名称。

			你可以从下面的信息中找到你的公网接口名称:
			EOF

			if command_exists ip; then
				ip addr show
			else
				ifconfig
			fi

			local input=
			while :
			do
				read -p "请输入你的网络接口名称(例如: eth0): " input
				echo
				if [ -n "$input" ]; then
					sed -i -r "s#^INTERFACE=.*#INTERFACE='"${input}"'#" "$haproxy_lkl_bin"
				else
					echo "输入信息不能为空，请重新输入！"
					continue
				fi

				break
			done
		fi
	}
	set_interface

	chmod +x "$haproxy_lkl_bin"

	local haproxy_lkl_startup_file=
	local haproxy_lkl_startup_file_url=

	if command_exists systemctl; then
		haproxy_lkl_startup_file="/lib/systemd/system/${SERVICE_NAME}.service"
		haproxy_lkl_startup_file_url="${HAPROXY_LKL_SYSTEMD_FILE_URL}"

		download_file "$haproxy_lkl_startup_file_url" "$haproxy_lkl_startup_file"
	elif command_exists service; then
		haproxy_lkl_startup_file="/etc/init.d/${SERVICE_NAME}"
		case "$lsb_dist" in
			ubuntu|debian|raspbian)
				haproxy_lkl_startup_file_url="${HAPROXY_LKL_SERVICE_FILE_DEBIAN_URL}"

				download_file "$haproxy_lkl_startup_file_url" "$haproxy_lkl_startup_file"
				chmod +x "$haproxy_lkl_startup_file"
			;;
			fedora|centos|redhat|oraclelinux|photon)
				haproxy_lkl_startup_file_url="${HAPROXY_LKL_SERVICE_FILE_REDHAT_URL}"

				download_file "$haproxy_lkl_startup_file_url" "$haproxy_lkl_startup_file"
				chmod +x "$haproxy_lkl_startup_file"
			;;
			*)
				echo "没有适合当前系统的服务启动脚本文件。"
				exit 1
			;;
		esac

	else
		cat >&2 <<-'EOF'
		当前服务器未安装 systemctl 或者 service 命令，无法配置服务。
		请先手动安装 systemd 或者 service 之后再运行脚本。
		EOF

		exit 1
	fi

	echo "$ACCELERATE_PORT" > "${HAPROXY_LKL_DIR}/etc/port-rules"
}

install_lkl_lib() {
	local lib_file="${HAPROXY_LKL_DIR}/lib64/liblkl-hijack.so"
	local retry=0
	download_lkl_lib() {
		download_file "$LKL_LIB_URL" "$lib_file"
		if command_exists md5sum; then
			(
				set -x
				echo "${LKL_LIB_MD5}  ${lib_file}" | md5sum -c
			)
			if [ "$?" != "0" ]; then
				if [ "$retry" -lt "3" ]; then
					echo "文件校验失败！3 秒后重新下载..."
					retry=`expr $retry + 1`
					sleep 3
					download_lkl_lib
				else
					cat >&2 <<-EOF
					Linux 内核文件校验失败。
					通常是网络原因造成文件下载不全。
					EOF
					exit 1
				fi
			fi
		fi
	}

	download_lkl_lib

	chmod +x "$lib_file"
}

enable_ip_forward() {
	local ip_forword="$(sysctl -n 'net.ipv4.ip_forward' 2>/dev/null)"
	if [ -z "$ip_forword" -o "$ip_forword" != "1" ]; then
		(
			set -x
			echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
			sysctl -p /etc/sysctl.conf 2>/dev/null
		)
	fi
}

set_config() {
	is_port() {
		local port=$1
		expr $port + 1 >/dev/null 2>&1 && \
			[ "$port" -ge "1" -a "$port" -le "65535" ]
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

is_running() {
	(
		set -x
		sleep 3
		# https://bugs.centos.org/view.php?id=12407
		# ping may not work with IPv4 under OpenVZ on CentOS 7

		# ping -q -c3 10.0.0.2 2>/dev/null
		timeout 2 bash -c "</dev/tcp/10.0.0.2/${ACCELERATE_PORT}" 2>/dev/null
	)
	return $?
}

enable_service() {
	if command_exists systemctl; then
		(
			set -x
			systemctl daemon-reload
			systemctl enable "${SERVICE_NAME}.service"
		)
	elif command_exists service; then
		case "$lsb_dist" in
			ubuntu|debian|raspbian)
				(
					set -x
					update-rc.d -f "${SERVICE_NAME}" defaults
				)
			;;
			fedora|centos|redhat|oraclelinux|photon)
				(
					set -x
					chkconfig --add "${SERVICE_NAME}"
					chkconfig "${SERVICE_NAME}" on
				)
			;;
		esac
	fi
}

start_service() {
	if command_exists systemctl; then
		(
			set -x
			sleep 3
			systemctl start "$SERVICE_NAME"
		)
	else
		(
			set -x
			sleep 3
			service "$SERVICE_NAME" start
		)
	fi

	if [ "$?" != "0" ] || ! is_running; then
		do_uninstall
		cat >&2 <<-EOF
		很遗憾，服务启动失败。
		你可以查看上面的日志来获取原因，
		或者，你可以到我们的群里反馈一下。
		EOF
		exit 1
	fi
}

end_install() {
	clear

	cat >&2 <<-EOF
	恭喜！BBR 安装完成并成功启动

	已加速的端口: ${ACCELERATE_PORT}

	你可以通过修改文件:
	    ${HAPROXY_LKL_DIR}/etc/port-rules

	来配置需要加速的端口或端口范围。
	EOF
	if command_exists systemctl; then

		cat >&2 <<-EOF

		请使用 systemctl {start|stop|restart} ${SERVICE_NAME}
		来 {开启|关闭|重启} 服务
		EOF
	else

		cat >&2 <<-EOF

		请使用 service ${SERVICE_NAME} {start|stop|restart}
		来 {开启|关闭|重启} 服务
		EOF
	fi
	cat >&2 <<-EOF

	服务已自动加入开机启动，请放心使用。

	如果这个脚本帮到了你，你可以请作者喝瓶可乐:
	  https://blog.kuoruan.com/donate

	享受加速的快感吧！
	EOF
}

do_uninstall() {
	check_root
	get_os_info

	if command_exists systemctl; then
		systemctl stop "${SERVICE_NAME}.service" 2>/dev/null
		(
			set -x
			systemctl disable "${SERVICE_NAME}.service" 2>/dev/null
			rm -f "/lib/systemd/system/${SERVICE_NAME}.service"
		)
	elif command_exists service; then
		service "${SERVICE_NAME}" stop 2>/dev/null
		case "$lsb_dist" in
			ubuntu|debian|raspbian)
				(
					set -x
					update-rc.d -f "${SERVICE_NAME}" remove 2>/dev/null
				)
			;;
			fedora|centos|redhat|oraclelinux|photon)
				(
					set -x
					chkconfig "${SERVICE_NAME}" off 2>/dev/null
					chkconfig --del "${SERVICE_NAME}" 2>/dev/null
				)
			;;
		esac
		(
			set -x
			rm -f "/etc/init.d/${SERVICE_NAME}"
		)
	fi

	(
		set -x
		${HAPROXY_LKL_DIR}/sbin/${SERVICE_NAME} -c 2>/dev/null
		rm -rf "${HAPROXY_LKL_DIR}"
	)
}

do_install() {
	check_root
	check_ovz
	check_ldd
	check_arch
	get_os_info
	set_config
	install_deps
	enable_ip_forward
	check_nat_create
	install_haproxy
	install_lkl_lib
	start_service
	enable_service
	end_install
}

action=${1:-"install"}
case "$action" in
	install|uninstall)
		do_${action}
	;;
	*)
		cat >&2 <<-EOF
		参数有误，请使用 $(basename $0) install|uninstall
		EOF
		exit 255
esac
