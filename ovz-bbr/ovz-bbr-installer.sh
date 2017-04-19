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

# Haproxy 服务名称
HAPROXY_BASENAME='haproxy-lkl'
# Haproxy 默认安装路径，修改之后需要同时修改服务启动文件
HAPROXY_DIR="/usr/local/$HAPROXY_BASENAME"

BASE_URL='https://raw.githubusercontent.com/kuoruan/shell-scripts/master/ovz-bbr'
HAPROXY_BIN_URL="${BASE_URL}/bin/haproxy.linux2628_x86_64"
HAPROXY_BIN_WRAPPER_URL="${BASE_URL}/bin/haproxy-systemd-wrapper.linux2628_x86_64"
HAPROXY_SERVICE_FILE_DEBIAN_URL="${BASE_URL}/startup/haproxy-lkl.init.debain"
HAPROXY_SERVICE_FILE_REDHAT_URL="${BASE_URL}/startup/haproxy-lkl.init.redhat"
HAPROXY_SYSTEMD_FILE_URL="${BASE_URL}/startup/haproxy-lkl.systemd"
LKL_LIB_URL="${BASE_URL}/lib64/liblkl-hijack.so-20170419"
LKL_LIB_MD5='08cccfcdfd106c76b39bc2af783d1c4e'

# Haproxy 的监听端口
HAPROXY_LISTEN_PORT=
# 需要 BBR 加速的端口
HAPROXY_TARGET_PORT=
# 创建的 tap 名称，修改后需要同时修改服务启动文件
LKL_TAP_NAME='lkl'

cat >&2 <<-'EOF'
#######################################################
# OpenVZ BBR 一键安装脚本                             #
# 该脚本用于在 OpenVZ 服务器上安装配置 Google BBR     #
# 脚本作者: Xingwang Liao <kuoruan@gmail.com>         #
# 作者博客: https://blog.kuoruan.com/                 #
# Github: https://github.com/kuoruan                  #
# QQ交流群: 43391448, 68133628                        #
#######################################################
EOF


command_exists() {
	command -v "$@" > /dev/null 2>&1
}

check_root() {
	if [ $EUID -ne 0 ]; then
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
	local ldd_version="$(ldd --version | grep 'ldd' | rev | cut -d ' ' -f1 | rev)"
	if [ -n "$ldd_version" ]; then
		if [ "${ldd_version%.*}" -eq "2" ] && [ "${ldd_version#*.}" \< "14" ] || \
		[ "${ldd_version%.*}" -lt "2" ]; then
			cat >&2 <<-EOF
			当前服务器的 glibc 版本为 $ldd_version。
			最低版本需求 2.14，低于这个版本可能无法正常使用。
			EOF

			exit 1
	  fi
	else
		cat >&2 <<-EOF
		获取 glibc 版本失败，请手动检查：
		    ldd --version
		最低版本需求 2.14，低于这个版本可能无法正常使用。
		EOF

		( set -x; ldd --version )
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
			你可以尝试从源码编译 Linux Kernel Library
			    https://github.com/lkl/linux
			EOF
			exit 1
			;;
	esac
}

any_key_to_continue() {
	echo "请按任意键继续或 Ctrl + C 退出"
	SAVEDSTTY=`stty -g`
	stty -echo
	stty cbreak
	dd if=/dev/tty bs=1 count=1 2> /dev/null
	stty -raw
	stty echo
	stty $SAVEDSTTY
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
			# need to switch lsb_dist to match yum repo URL
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
		EOF

		exit 1
	fi
}

install_deps() {
	case "$lsb_dist" in
		ubuntu|debian|raspbian)
			did_apt_get_update=
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
					(set -x; sleep 3; dnf -y -q install -y -q iproute)
				fi

				if ! command_exists iptables; then
					(set -x; sleep 3; dnf -y -q install iptables)
				fi
			elif [ "$lsb_dist" = "photon" ]; then
				if ! command_exists wget; then
					( set -x; sleep 3; tdnf -y install wget ca-certificates )
				fi
				if ! command_exists ip; then
					( set -x; sleep 3; tdnf -y install -y -q iproute )
				fi
				if ! command_exists iptables; then
					( set -x; sleep 3; tdnf -y install iptables )
				fi
			else
				if ! command_exists wget; then
					( set -x; sleep 3; yum -y -q install wget ca-certificates )
				fi
				if ! command_exists ip; then
					( set -x; sleep 3; tdnf -y install -y -q iproute )
				fi
				if ! command_exists iptables firewall-cmd; then
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
	local url=$1
	local file=$2

	(set -x; wget -O "$file" --no-check-certificate "$url")
	if [ "$?" -ne 0 ]; then
		cat >&2 <<-EOF
		一些文件下载失败！安装脚本需要能访问到 github.com，请检查服务器网络。
		注意: 一些国内服务器可能无法正常访问 github.com。
		EOF

		exit 1
	fi
}

install_haproxy() {
	set -x
	mkdir -p "${HAPROXY_DIR}"/{etc,lib64,sbin}
	useradd -U -s '/usr/sbin/nologin' -d '/nonexistent' haproxy 2>/dev/null
	set +x

	local haproxy_bin="${HAPROXY_DIR}/sbin/${HAPROXY_BASENAME}"

	download_file "$HAPROXY_BIN_URL" "$haproxy_bin"
	chmod +x "$haproxy_bin"

	check_haproxy_bin() {
		local bin=$1
		if ! $bin -v | grep -q 'HA-Proxy' 2>/dev/null; then
			cat >&2 <<-EOF
			HAproxy 可执行文件无法正常运行，请联系脚本作者，寻求支持。
			EOF

			exit 1
		fi
	}

	check_haproxy_bin "$haproxy_bin"

	local haproxy_startup_file=
	local haproxy_startup_file_url=
	download_startup_script() {
		if [ -n "$haproxy_startup_file" -a -n "$haproxy_startup_file_url" ]; then
			download_file "$haproxy_start_script_url" "$haproxy_start_script"
			chmod +x "$haproxy_start_script"
		fi
	}

	if command_exists systemctl; then
		local haproxy_bin_wrapper="${HAPROXY_DIR}/sbin/${HAPROXY_BASENAME}-systemd-wrapper"
		download_file "$HAPROXY_BIN_WRAPPER_URL" "$haproxy_bin_wrapper"

		chmod +x "$haproxy_bin_wrapper"
		check_haproxy_bin "$haproxy_bin_wrapper"

		haproxy_start_script="/lib/systemd/system/${SERVICE_NAME}.service"
		haproxy_start_script_url="${HAPROXY_SYSTEMD_FILE_URL}"

		download_startup_script
		set -x; systemctl enable "${SERVICE_NAME}.service"

	elif command_exists service; then
		haproxy_start_script="/etc/init.d/${SERVICE_NAME}"
		case "$lsb_dist" in
			ubuntu|debian|raspbian)
				haproxy_start_script_url="${HAPROXY_SERVICE_FILE_DEBIAN_URL}"

				download_startup_script
				(set -x; update-rc.d -f "${SERVICE_NAME}" defaults)
			;;
			fedora|centos|redhat|oraclelinux|photon)
				haproxy_start_script_url="${HAPROXY_SERVICE_FILE_REDHAT_URL}"

				download_startup_script
				(
					set -x
					chkconfig --add "${SERVICE_NAME}"
					chkconfig "${SERVICE_NAME}" on
				)
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

	cat > "${HAPROXY_DIR}/etc/haproxy.cfg"<<-EOF
	global
	    user haproxy
	    group haproxy
	defaults
	    mode tcp
	    timeout client 30s
	    timeout server 30s
	    timeout connect 5s
	listen tcp1
	    bind 10.0.0.2:${HAPROXY_LISTEN_PORT}
	    server server1 10.0.0.1:${HAPROXY_TARGET_PORT}
	EOF
}

install_lkl_lib() {
	local lib_file="${HAPROXY_DIR}/lib64/liblkl-hijack.so"
	local retry=0
	download_lkl_lib() {
		download_file "$LKL_LIB_URL" "$lib_file"
		if command_exists md5sum; then
			set -x
			echo "${HAPROXY_MD5} ${lib_file}" | md5sum -c
			set +x

			if [ "$?" -ne 0 ]; then
				if [ "$retry" -lt "3" ]; then
					echo "文件校验失败！3 秒后重新下载..."
					let retry++
					sleep 3
					download_lkl_lib
				else
					echo "Linux 内核文件下载校验失败。"
					exit 1
				fi
			fi
		fi
	}

	download_lkl_lib

	chmod +x "$lib_file"
}

set_network() {
	local ip_forword="$(sysctl -n 'net.ipv4.ip_forward 2>/dev/null')"
	if [ -z "$ip_forword" -o "$ip_forword" -ne "1" ]; then
		(
			set -x
			echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
			sysctl -p /etc/sysctl.conf 2>/dev/null
		)
	fi

	set -x
	ip tuntap add ${LKL_TAP_NAME} mode tap 2>/dev/null
	ip addr add 10.0.0.1/24 dev ${LKL_TAP_NAME} 2>/dev/null
	ip link set ${LKL_TAP_NAME} up 2>/dev/null

	iptables -P FORWARD ACCEPT 2>/dev/null

	if ! iptables -t nat -C POSTROUTING -o venet0 -j MASQUERADE 2>/dev/null; then
		iptables -t nat -A POSTROUTING -o venet0 -j MASQUERADE 2>/dev/null
	fi

	if [ -z "$HAPROXY_LISTEN_PORT" -o -z "$HAPROXY_TARGET_PORT" ]; then
		echo "HAproxy 监听端口和加速端口不能为空！"
		exit 1
	fi

	if ! iptables -t nat -C PREROUTING -i venet0 -p tcp \
		--dport ${HAPROXY_LISTEN_PORT} -j DNAT --to-destination 10.0.0.2 2>/dev/null; then
		iptables -t nat -A PREROUTING -i venet0 -p tcp \
			--dport ${HAPROXY_LISTEN_PORT} -j DNAT --to-destination 10.0.0.2 2>/dev/null
	fi

	if ! iptables -t nat -C PREROUTING -i venet0 -p udp \
		--dport ${HAPROXY_LISTEN_PORT} -j REDIRECT --to-port ${HAPROXY_TARGET_PORT} 2>/dev/null; then
		iptables -t nat -A PREROUTING -i venet0 -p udp \
			--dport ${HAPROXY_LISTEN_PORT} -j REDIRECT --to-port ${HAPROXY_TARGET_PORT} 2>/dev/null
	fi

	set +x
}

set_config() {
	is_number() {
		expr $1 + 1 >/dev/null 2>&1
	}

	local input=
	while :
	do
		read -p "请输入 HAproxy 运行端口 [1~65535]: " input
		echo
		if [ -n "$input" ]; then
			if is_number $input && [ "$input" -ge "1" -a "$input" -le "65535" ]; then
				HAPROXY_LISTEN_PORT="$input"
			else
				echo "输入有误, 请输入 1~65535 之间的数字!"
				continue
			fi
		else
			echo "端口不能为空!"
			continue
		fi

		input=
		cat >&2 <<-EOF
		---------------------------
		HAproxy 端口 = ${HAPROXY_LISTEN_PORT}
		---------------------------
		EOF
		break
	done

	while :
	do
		read -p "请输入需要加速的端口 [1~65535]: " input
		echo
		if [ -n "$input" ]; then
			if is_number $input && [ "$input" -ge "1" -a "$input" -le "65535" ]; then
				HAPROXY_TARGET_PORT="$input"
			else
				echo "输入有误, 请输入 1~65535 之间的数字!"
				continue
			fi
		else
			echo "端口不能为空!"
			continue
		fi

		cat >&2 <<-EOF
		---------------------------
		加速端口 = ${HAPROXY_TARGET_PORT}
		---------------------------
		EOF
		break
	done

	echo "配置完成。"
	any_key_to_continue
}

end_install() {
	cat >&2 <<-EOF
	BBR 安装完成！
	新端口: ${HAPROXY_LISTEN_PORT}
	原端口: ${HAPROXY_TARGET_PORT}
	EOF
	if command_exists systemctl; then
		systemctl start "$HAPROXY_BASENAME"
		cat >&2 <<-EOF

		请使用 systemctl {start|stop|restart} ${HAPROXY_BASENAME}
		来 {开启|关闭|重启} 服务
		EOF
	else
		service "$HAPROXY_BASENAME" start
		cat >&2 <<-EOF

		请使用 service ${HAPROXY_BASENAME} {start|stop|restart}
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

do_install() {
	check_root
	check_ovz
	check_ldd
	check_arch
	get_os_info

	set_config

	install_deps
	install_haproxy
	install_lkl_lib
	set_network
	start_haproxy
	end_install
}

do_install
