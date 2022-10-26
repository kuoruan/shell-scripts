#!/bin/sh

: <<-'EOF'
Copyright 2017-2019 Xingwang Liao <kuoruan@gmail.com>
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

# 版本信息，请勿修改
# =================
SHELL_VERSION=25
CONFIG_VERSION=6
INIT_VERSION=3
# =================

KCPTUN_INSTALL_DIR='/usr/local/kcptun'
KCPTUN_LOG_DIR='/var/log/kcptun'
KCPTUN_RELEASES_URL='https://api.github.com/repos/xtaci/kcptun/releases'
KCPTUN_LATEST_RELEASE_URL="${KCPTUN_RELEASES_URL}/latest"
KCPTUN_TAGS_URL='https://github.com/xtaci/kcptun/tags'

BASE_URL='https://github.com/kuoruan/shell-scripts/raw/master/kcptun'
SHELL_VERSION_INFO_URL="${BASE_URL}/version.json"

JQ_DOWNLOAD_URL="https://github.com/stedolan/jq/releases/download/jq-1.5/"
JQ_LINUX32_URL="${JQ_DOWNLOAD_URL}/jq-linux32"
JQ_LINUX64_URL="${JQ_DOWNLOAD_URL}/jq-linux64"
JQ_LINUX32_HASH='ab440affb9e3f546cf0d794c0058543eeac920b0cd5dff660a2948b970beb632'
JQ_LINUX64_HASH='c6b3a7d7d3e7b70c6f51b706a3b90bd01833846c54d32ca32f0027f00226ff6d'
JQ_BIN="${KCPTUN_INSTALL_DIR}/bin/jq"

SUPERVISOR_SERVICE_FILE_DEBIAN_URL="${BASE_URL}/startup/supervisord.init.debain"
SUPERVISOR_SERVICE_FILE_REDHAT_URL="${BASE_URL}/startup/supervisord.init.redhat"
SUPERVISOR_SYSTEMD_FILE_URL="${BASE_URL}/startup/supervisord.systemd"

# 默认参数
# =======================
D_LISTEN_PORT=29900
D_TARGET_ADDR='127.0.0.1'
D_TARGET_PORT=12984
D_KEY="very fast"
D_CRYPT='aes'
D_MODE='fast'
D_MTU=1350
D_SNDWND=512
D_RCVWND=512
D_DATASHARD=10
D_PARITYSHARD=3
D_DSCP=0
D_NOCOMP='false'
D_QUIET='false'
D_TCP='false'
D_SNMPPERIOD=60
D_PPROF='false'

# 隐藏参数
D_ACKNODELAY='false'
D_NODELAY=1
D_INTERVAL=20
D_RESEND=2
D_NC=1
D_SOCKBUF=4194304
D_SMUXBUF=4194304
D_KEEPALIVE=10
# ======================

# 当前选择的实例 ID
current_instance_id=""
run_user='kcptun'

clear

cat >&1 <<-'EOF'
#########################################################
# Kcptun 服务端一键安装脚本                             #
# 该脚本支持 Kcptun 服务端的安装、更新、卸载及配置      #
# 脚本作者: Index <kuoruan@gmail.com>                   #
# 作者博客: https://blog.kuoruan.com/                   #
# Github: https://github.com/kuoruan/shell-scripts      #
# QQ交流群: 43391448, 68133628                          #
#           633945405                                   #
#########################################################
EOF

# 打印帮助信息
usage() {
	cat >&1 <<-EOF

	请使用: $0 <option>

	可使用的参数 <option> 包括:

	    install          安装
	    uninstall        卸载
	    update           检查更新
	    manual           自定义 Kcptun 版本安装
	    help             查看脚本使用说明
	    add              添加一个实例, 多端口加速
	    reconfig <id>    重新配置实例
	    show <id>        显示实例详细配置
	    log <id>         显示实例日志
	    del <id>         删除一个实例

	注: 上述参数中的 <id> 可选, 代表的是实例的ID
	    可使用 1, 2, 3 ... 分别对应实例 kcptun, kcptun2, kcptun3 ...
	    若不指定 <id>, 则默认为 1

	Supervisor 命令:
	    service supervisord {start|stop|restart|status}
	                        {启动|关闭|重启|查看状态}
	Kcptun 相关命令:
	    supervisorctl {start|stop|restart|status} kcptun<id>
	                  {启动|关闭|重启|查看状态}
	EOF

	exit $1
}

# 判断命令是否存在
command_exists() {
	command -v "$@" >/dev/null 2>&1
}

# 判断输入内容是否为数字
is_number() {
	expr "$1" + 1 >/dev/null 2>&1
}

# 按任意键继续
any_key_to_continue() {
	echo "请按任意键继续或 Ctrl + C 退出"
	local saved=""
	saved="$(stty -g)"
	stty -echo
	stty cbreak
	dd if=/dev/tty bs=1 count=1 2>/dev/null
	stty -raw
	stty echo
	stty $saved
}

first_character() {
	if [ -n "$1" ]; then
		echo "$1" | cut -c1
	fi
}

# 检查是否具有 root 权限
check_root() {
	local user=""
	user="$(id -un 2>/dev/null || true)"
	if [ "$user" != "root" ]; then
		cat >&2 <<-'EOF'
		权限错误, 请使用 root 用户运行此脚本!
		EOF
		exit 1
	fi
}

# 获取服务器的IP地址
get_server_ip() {
	local server_ip=""
	local interface_info=""

	if command_exists ip; then
		interface_info="$(ip addr)"
	elif command_exists ifconfig; then
		interface_info="$(ifconfig)"
	fi

	server_ip=$(echo "$interface_info" | \
		grep -oE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | \
		grep -vE "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | \
		head -n 1)

	# 自动获取失败时，通过网站提供的 API 获取外网地址
	if [ -z "$server_ip" ]; then
		 server_ip="$(wget -qO- --no-check-certificate https://ipv4.icanhazip.com)"
	fi

	echo "$server_ip"
}

# 禁用 selinux
disable_selinux() {
	local selinux_config='/etc/selinux/config'
	if [ -s "$selinux_config" ]; then
		if grep -q "SELINUX=enforcing" "$selinux_config"; then
			sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' "$selinux_config"
			setenforce 0
		fi
	fi
}

# 获取当前操作系统信息
get_os_info() {
	lsb_dist=""
	dist_version=""
	if command_exists lsb_release; then
		lsb_dist="$(lsb_release -si)"
	fi

	if [ -z "$lsb_dist" ]; then
		[ -r /etc/lsb-release ] && lsb_dist="$(. /etc/lsb-release && echo "$DISTRIB_ID")"
		[ -r /etc/debian_version ] && lsb_dist='debian'
		[ -r /etc/fedora-release ] && lsb_dist='fedora'
		[ -r /etc/oracle-release ] && lsb_dist='oracleserver'
		[ -r /etc/centos-release ] && lsb_dist='centos'
		[ -r /etc/redhat-release ] && lsb_dist='redhat'
		[ -r /etc/photon-release ] && lsb_dist='photon'
		[ -r /etc/os-release ] && lsb_dist="$(. /etc/os-release && echo "$ID")"
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

# 获取服务器架构和 Kcptun 服务端文件后缀名
get_arch() {
	architecture="$(uname -m)"
	case "$architecture" in
		amd64|x86_64)
			spruce_type='linux-amd64'
			file_suffix='linux_amd64'
			;;
		i386|i486|i586|i686|x86)
			spruce_type='linux-386'
			file_suffix='linux_386'
			;;
		*)
			cat 1>&2 <<-EOF
			当前脚本仅支持 32 位 和 64 位系统
			你的系统为: $architecture
			EOF
			exit 1
			;;
	esac
}

# 获取 API 内容
get_content() {
	local url="$1"
	local retry=0

	local content=""
	get_network_content() {
		if [ $retry -ge 3 ]; then
			cat >&2 <<-EOF
			获取网络信息失败!
			URL: ${url}
			安装脚本需要能访问到 github.com，请检查服务器网络。
			注意: 一些国内服务器可能无法正常访问 github.com。
			EOF
			exit 1
		fi

		# 将所有的换行符替换为自定义标签，防止 jq 解析失败
		content="$(wget -qO- --no-check-certificate "$url" | sed -r 's/(\\r)?\\n/#br#/g')"

		if [ "$?" != "0" ] || [ -z "$content" ]; then
			retry=$(expr $retry + 1)
			get_network_content
		fi
	}

	get_network_content
	echo "$content"
}

# 下载文件， 默认重试 3 次
download_file() {
	local url="$1"
	local file="$2"
	local verify="$3"
	local retry=0
	local verify_cmd=""

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
				verify_cmd=""
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
		if verify_file; then
			return 0
		fi

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

# 安装 jq 用于解析和生成 json 文件
# jq 已进入大部分 Linux 发行版的软件仓库，
#  	URL: https://stedolan.github.io/jq/download/
# 但为了防止有些系统安装失败，还是通过脚本来提供了。
install_jq() {
	check_jq() {
		if [ ! -f "$JQ_BIN" ]; then
			return 1
		fi

		[ ! -x "$JQ_BIN" ] && chmod a+x "$JQ_BIN"

		if ( $JQ_BIN --help 2>/dev/null | grep -q "JSON" ); then
			is_checked_jq="true"
			return 0
		else
			rm -f "$JQ_BIN"
			return 1
		fi
	}

	if [ -z "$is_checked_jq" ] && ! check_jq; then
		local dir=""
		dir="$(dirname "$JQ_BIN")"
		if [ ! -d "$dir" ]; then
			(
				set -x
				mkdir -p "$dir"
			)
		fi

		if [ -z "$architecture" ]; then
			get_arch
		fi

		case "$architecture" in
			amd64|x86_64)
				download_file "$JQ_LINUX64_URL" "$JQ_BIN" "$JQ_LINUX64_HASH"
				;;
			i386|i486|i586|i686|x86)
				download_file "$JQ_LINUX32_URL" "$JQ_BIN" "$JQ_LINUX32_HASH"
				;;
		esac

		if ! check_jq; then
			cat >&2 <<-EOF
			未找到适用于当前系统的 JSON 解析软件 jq
			EOF
			exit 1
		fi

		return 0
	fi
}

# 读取 json 文件中某一项的值
get_json_string() {
	install_jq

	local content="$1"
	local selector="$2"
	local regex="$3"

	local str=""
	if [ -n "$content" ]; then
		str="$(echo "$content" | $JQ_BIN -r "$selector" 2>/dev/null)"

		if [ -n "$str" ] && [ -n "$regex" ]; then
			str="$(echo "$str" | grep -oE "$regex")"
		fi
	fi
	echo "$str"
}

# 获取当前实例的配置文件路径，传入参数：
# * config: kcptun 服务端配置文件
# * log: kcptun 日志文件路径
# * snmp: kcptun snmp 日志文件路径
# * supervisor: 实例的 supervisor 文件路径
get_current_file() {
	case "$1" in
		config)
			printf '%s/server-config%s.json' "$KCPTUN_INSTALL_DIR" "$current_instance_id"
			;;
		log)
			printf '%s/server%s.log' "$KCPTUN_LOG_DIR" "$current_instance_id"
			;;
		snmp)
			printf '%s/snmplog%s.log' "$KCPTUN_LOG_DIR" "$current_instance_id"
			;;
		supervisor)
			printf '/etc/supervisor/conf.d/kcptun%s.conf' "$current_instance_id"
			;;
	esac
}

# 获取实例数量
get_instance_count() {
	if [ -d '/etc/supervisor/conf.d/' ]; then
		ls -l '/etc/supervisor/conf.d/' | grep "^-" | awk '{print $9}' | grep -cP "^kcptun\d*\.conf$"
	else
		echo "0"
	fi
}

# 通过 API 获取对应版本号 Kcptun 的 release 信息
# 传入 Kcptun 版本号
get_kcptun_version_info() {
	local request_version="$1"

	local version_content=""
	if [ -n "$request_version" ]; then
		local json_content=""
		json_content="$(get_content "$KCPTUN_RELEASES_URL")"
		local version_selector=".[] | select(.tag_name == \"${request_version}\")"
		version_content="$(get_json_string "$json_content" "$version_selector")"
	else
		version_content="$(get_content "$KCPTUN_LATEST_RELEASE_URL")"
	fi

	if [ -z "$version_content" ]; then
		return 1
	fi

	if [ -z "$spruce_type" ]; then
		get_arch
	fi

	local url_selector=".assets[] | select(.name | contains(\"${spruce_type}\")) | .browser_download_url"
	kcptun_release_download_url="$(get_json_string "$version_content" "$url_selector")"

	if [ -z "$kcptun_release_download_url" ]; then
		return 1
	fi

	kcptun_release_tag_name="$(get_json_string "$version_content" '.tag_name')"
	kcptun_release_name="$(get_json_string "$version_content" '.name')"
	kcptun_release_prerelease="$(get_json_string "$version_content" '.prerelease')"
	kcptun_release_publish_time="$(get_json_string "$version_content" '.published_at')"
	kcptun_release_html_url="$(get_json_string "$version_content" '.html_url')"

	local body_content="$(get_json_string "$version_content" '.body')"
	local body="$(echo "$body_content" | sed 's/#br#/\n/g' | grep -vE '(^```)|(^>)|(^[[:space:]]*$)|(SUM$)')"

	kcptun_release_body="$(echo "$body" | grep -vE "[0-9a-zA-Z]{32,}")"

	local file_verify=""
	file_verify="$(echo "$body" | grep "$spruce_type")"

	if [ -n "$file_verify" ]; then
		local i="1"
		local split=""
		while true
		do
			split="$(echo "$file_verify" | cut -d ' ' -f$i)"

			if [ -n "$split" ] && ( echo "$split" | grep -qE "^[0-9a-zA-Z]{32,}$" ); then
				kcptun_release_verify="$split"
				break
			elif [ -z "$split" ]; then
				break
			fi

			i=$(expr $i + 1)
		done
	fi

	return 0
}

# 获取脚本版本信息
get_shell_version_info() {
	local shell_version_content=""
	shell_version_content="$(get_content "$SHELL_VERSION_INFO_URL")"
	if [ -z "$shell_version_content" ]; then
		return 1
	fi

	new_shell_version="$(get_json_string "$shell_version_content" '.shell_version' '[0-9]+')"
	new_config_version="$(get_json_string "$shell_version_content" '.config_version' '[0-9]+')"
	new_init_version="$(get_json_string "$shell_version_content" '.init_version' '[0-9]+')"

	shell_change_log="$(get_json_string "$shell_version_content" '.change_log')"
	config_change_log="$(get_json_string "$shell_version_content" '.config_change_log')"
	init_change_log="$(get_json_string "$shell_version_content" '.init_change_log')"
	new_shell_url="$(get_json_string "$shell_version_content" '.shell_url')"


	if [ -z "$new_shell_version" ]; then
		new_shell_version="0"
	fi
	if [ -z "$new_config_version" ]; then
		new_config_version="0"
	fi
	if [ -z "$new_init_version" ]; then
		new_init_version="0"
	fi

	return 0
}

# 下载并安装 Kcptun
install_kcptun() {
	if [ -z "$kcptun_release_download_url" ]; then
		get_kcptun_version_info "$1"

		if [ "$?" != "0" ]; then
			cat >&2 <<-'EOF'
			获取 Kcptun 版本信息或下载地址失败!
			可能是 GitHub 改版，或者从网络获取到的内容不正确。
			请联系脚本作者。
			EOF
			exit 1
		fi
	fi

	local kcptun_file_name="kcptun-${kcptun_release_tag_name}.tar.gz"
	download_file "$kcptun_release_download_url" "$kcptun_file_name" "$kcptun_release_verify"

	if [ ! -d "$KCPTUN_INSTALL_DIR" ]; then
		(
			set -x
			mkdir -p "$KCPTUN_INSTALL_DIR"
		)
	fi

	if [ ! -d "$KCPTUN_LOG_DIR" ]; then
		(
			set -x
			mkdir -p "$KCPTUN_LOG_DIR"
			chmod a+w "$KCPTUN_LOG_DIR"
		)
	fi

	(
		set -x
		tar -zxf "$kcptun_file_name" -C "$KCPTUN_INSTALL_DIR"
		sleep 3
	)

	local kcptun_server_file=""
	kcptun_server_file="$(get_kcptun_server_file)"

	if [ ! -f "$kcptun_server_file" ]; then
		cat >&2 <<-'EOF'
		未在解压文件中找到 Kcptun 服务端执行文件!
		通常这不会发生，可能的原因是 Kcptun 作者打包文件的时候更改了文件名。
		你可以尝试重新安装，或者联系脚本作者。
		EOF
		exit 1
	fi

	chmod a+x "$kcptun_server_file"

	if [ -z "$(get_installed_version)" ]; then
		cat >&2 <<-'EOF'
		无法找到适合当前服务器的 kcptun 可执行文件
		你可以尝试从源码编译。
		EOF
		exit 1
	fi

	rm -f "$kcptun_file_name" "${KCPTUN_INSTALL_DIR}/client_$file_suffix"
}

# 安装依赖软件
install_deps() {
	if [ -z "$lsb_dist" ]; then
		get_os_info
	fi

	case "$lsb_dist" in
		ubuntu|debian|raspbian)
			local did_apt_get_update=""
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

			if ! command_exists awk; then
				apt_get_update
				( set -x; sleep 3; apt-get install -y -q gawk )
			fi

			if ! command_exists tar; then
				apt_get_update
				( set -x; sleep 3; apt-get install -y -q tar )
			fi

			if ! command_exists pip; then
				apt_get_update
				( set -x; sleep 3; apt-get install -y -q python-pip || true )
			fi

			if ! command_exists python; then
				apt_get_update
				( set -x; sleep 3; apt-get install -y -q python )
			fi
			;;
		fedora|centos|redhat|oraclelinux|photon)
			if [ "$lsb_dist" = "fedora" ] && [ "$dist_version" -ge "22" ]; then
				if ! command_exists wget; then
					( set -x; sleep 3; dnf -y -q install wget ca-certificates )
				fi

				if ! command_exists awk; then
					( set -x; sleep 3; dnf -y -q install gawk )
				fi

				if ! command_exists tar; then
					( set -x; sleep 3; dnf -y -q install tar )
				fi

				if ! command_exists pip; then
					( set -x; sleep 3; dnf -y -q install python-pip || true )
				fi

				if ! command_exists python; then
					( set -x; sleep 3; dnf -y -q install python )
				fi
			elif [ "$lsb_dist" = "photon" ]; then
				if ! command_exists wget; then
					( set -x; sleep 3; tdnf -y install wget ca-certificates )
				fi

				if ! command_exists awk; then
					( set -x; sleep 3; tdnf -y install gawk )
				fi

				if ! command_exists tar; then
					( set -x; sleep 3; tdnf -y install tar )
				fi

				if ! command_exists pip; then
					( set -x; sleep 3; tdnf -y install python-pip || true )
				fi

				if ! command_exists python; then
					( set -x; sleep 3; tdnf -y install python )
				fi
			else
				if ! command_exists wget; then
					( set -x; sleep 3; yum -y -q install wget ca-certificates )
				fi

				if ! command_exists awk; then
					( set -x; sleep 3; yum -y -q install gawk )
				fi

				if ! command_exists tar; then
					( set -x; sleep 3; yum -y -q install tar )
				fi

				# CentOS 等红帽系操作系统的软件库中可能不包括 python-pip
				# 可以先安装 epel-release
				if ! command_exists pip; then
					( set -x; sleep 3; yum -y -q install python-pip || true )
				fi

				# 如果 python-pip 安装失败，检测是否已安装 python 环境
				if ! command_exists python; then
					( set -x; sleep 3; yum -y -q install python )
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

	# 这里判断了是否存在安装失败的软件包，但是默认不处理 python-pip 的安装失败，
	# 接下来会统一检测并再次安装 pip 命令
	if [ "$?" != 0 ]; then
		cat >&2 <<-'EOF'
		一些依赖软件安装失败，
		请查看日志检查错误。
		EOF
		exit 1
	fi

	install_jq
}

# 安装 supervisor
install_supervisor() {
	if [ -s /etc/supervisord.conf ] && command_exists supervisord; then
		cat >&2 <<-EOF
		检测到你曾经通过其他方式安装过 Supervisor , 这会和本脚本安装的 Supervisor 产生冲突
		推荐你备份当前 Supervisor 配置后卸载原有版本
		已安装的 Supervisor 配置文件路径为: /etc/supervisord.conf
		通过本脚本安装的 Supervisor 配置文件路径为: /etc/supervisor/supervisord.conf
		你可以使用以下命令来备份原有配置文件:

		    mv /etc/supervisord.conf /etc/supervisord.conf.bak
		EOF

		exit 1
	fi

	if ! command_exists python; then
		cat >&2 <<-'EOF'
		python 环境未安装，并且自动安装失败，请手动安装 python 环境。
		EOF

		exit 1
	fi

	local python_version="$(python -V 2>&1)"

	if [ "$?" != "0" ] || [ -z "$python_version" ]; then
		cat >&2 <<-'EOF'
		python 环境已损坏，无法通过 python -V 来获取版本号。
		请手动重装 python 环境。
		EOF

		exit 1
	fi

	local version_string="$(echo "$python_version" | cut -d' ' -f2 | head -n1)"
	local major_version="$(echo "$version_string" | cut -d'.' -f1)"
	local minor_version="$(echo "$version_string" | cut -d'.' -f2)"

	if [ -z "$major_version" ] || [ -z "$minor_version" ] || \
		! ( is_number "$major_version" ); then
		cat >&2 <<-EOF
		获取 python 大小版本号失败：${python_version}
		EOF

		exit 1
	fi

	local is_python_26="false"

	if [ "$major_version" -lt "2" ] || ( \
		[ "$major_version" = "2" ] && [ "$minor_version" -lt "6" ] ); then
		cat >&2 <<-EOF
		不支持的 python 版本 ${version_string}，当前仅支持 python 2.6 及以上版本的安装。
		EOF

		exit 1
	elif [ "$major_version" = "2" ] && [ "$minor_version" = "6" ]; then
		is_python_26="true"

		cat >&1 <<-EOF
		注意：当前服务器的 python 版本为 ${version_string},
		脚本对 python 2.6 及以下版本的支持可能会失效，
		请尽快升级 python 版本到 >= 2.7.9 或 >= 3.4。
		EOF

		any_key_to_continue
	fi

	if ! command_exists pip; then
		# 如果没有监测到 pip 命令，但当前服务器已经安装 python
		# 使用 get-pip.py 脚本来安装 pip 命令
		if [ "$is_python_26" = "true" ]; then
			(
				set -x
				wget -qO- --no-check-certificate https://bootstrap.pypa.io/2.6/get-pip.py | python
			)
		else
			(
				set -x
				wget -qO- --no-check-certificate https://bootstrap.pypa.io/get-pip.py | python
			)
		fi
	fi

	# 如果使用脚本安装依然失败，提示手动安装
	if ! command_exists pip; then
		cat >&2 <<-EOF
		未找到已安装的 pip 命令，请先手动安装 python-pip
		本脚本自 v21 版开始使用 pip 来安装 Supervisior。

		1. 对于 Debian 系的 Linux 系统，可以尝试使用：
		  sudo apt-get install -y python-pip 来进行安装

		2. 对于 Redhat 系的 Linux 系统，可以尝试使用：
		  sudo yum install -y python-pip 来进行安装
		  * 如果提示未找到，可以先尝试安装：epel-release 扩展软件库

		3. 如果以上方法都失败了，请使用以下命令来手动安装：
		  wget -qO- --no-check-certificate https://bootstrap.pypa.io/get-pip.py | python
		  * python 2.6 的用户请使用：
		    wget -qO- --no-check-certificate https://bootstrap.pypa.io/2.6/get-pip.py | python

		4. pip 安装完毕之后，先运行一下更新命令：
		  pip install --upgrade pip

		  再检查一下 pip 的版本：
		  pip -V

		一切无误后，请重新运行安装脚本。
		EOF
		exit 1
	fi

	if ! ( pip --version >/dev/null 2>&1 ); then
		cat >&2 <<-EOF
		检测到当前环境的 pip 命令已损坏，
		请检查你的 python 环境。
		EOF

		exit 1
	fi

	if [ "$is_python_26" != "true" ]; then
		# 已安装 pip 时先尝试更新一下，
		# 如果是 python 2.6，就不要更新了，更新会导致 pip 损坏
		# pip 只支持 python 2 >= 2.7.9
		# https://pip.pypa.io/en/stable/installing/
		(
			set -x
			pip install --upgrade pip || true
		)
	fi

	if [ "$is_python_26" = "true" ]; then
		(
			set -x
			pip install 'supervisor>=3.0.0,<4.0.0'
		)
	else
		(
			set -x
			pip install --upgrade supervisor
		)
	fi

	if [ "$?" != "0" ]; then
		cat >&2 <<-EOF
		错误: 安装 Supervisor 失败，
		请尝试使用
		  pip install supervisor
		来手动安装。
		Supervisor 从 4.0 开始已不支持 python 2.6 及以下版本
		python 2.6 的用户请使用：
		  pip install 'supervisor>=3.0.0,<4.0.0'
		EOF

		exit 1
	fi

	[ ! -d /etc/supervisor/conf.d ] && (
		set -x
		mkdir -p /etc/supervisor/conf.d
	)

	if [ ! -f '/usr/local/bin/supervisord' ]; then
		(
			set -x
			ln -s "$(command -v supervisord)" '/usr/local/bin/supervisord' 2>/dev/null
		)
	fi

	if [ ! -f '/usr/local/bin/supervisorctl' ]; then
		(
			set -x
			ln -s "$(command -v supervisorctl)" '/usr/local/bin/supervisorctl' 2>/dev/null
		)
	fi

	if [ ! -f '/usr/local/bin/pidproxy' ]; then
		(
			set -x
			ln -s "$(command -v pidproxy)" '/usr/local/bin/pidproxy' 2>/dev/null
		)
	fi

	local cfg_file='/etc/supervisor/supervisord.conf'

	local rvt="0"

	if [ ! -s "$cfg_file" ]; then
		if ! command_exists echo_supervisord_conf; then
			cat >&2 <<-'EOF'
			未找到 echo_supervisord_conf, 无法自动创建 Supervisor 配置文件!
			可能是当前安装的 supervisor 版本过低。
			EOF
			exit 1
		fi

		(
			set -x
			echo_supervisord_conf >"$cfg_file" 2>&1
		)
		rvt="$?"
	fi

	local cfg_content="$(cat "$cfg_file")"

	# Error with supervisor config file
	if ( echo "$cfg_content" | grep -q "Traceback (most recent call last)" ) ; then
		rvt="1"

		if ( echo "$cfg_content" | grep -q "DistributionNotFound: meld3" ); then
			# https://github.com/Supervisor/meld3/issues/23
			(
				set -x
				local temp="$(mktemp -d)"
				local pwd="$(pwd)"

				download_file 'https://pypi.python.org/packages/source/m/meld3/meld3-1.0.2.tar.gz' \
					"$temp/meld3.tar.gz"

				cd "$temp"
				tar -zxf "$temp/meld3.tar.gz" --strip=1
				python setup.py install
				cd "$pwd"
			)

			if [ "$?" = "0" ] ; then
				(
					set -x
					echo_supervisord_conf >"$cfg_file" 2>/dev/null
				)
				rvt="$?"
			fi
		fi
	fi

	if [ "$rvt" != "0" ]; then
		rm -f "$cfg_file"
		echo "创建 Supervisor 配置文件失败!"
		exit 1
	fi

	if ! grep -q '^files[[:space:]]*=[[:space:]]*/etc/supervisor/conf.d/\*\.conf$' "$cfg_file"; then
		if grep -q '^\[include\]$' "$cfg_file"; then
			sed -i '/^\[include\]$/a files = \/etc\/supervisor\/conf.d\/\*\.conf' "$cfg_file"
		else
			sed -i '$a [include]\nfiles = /etc/supervisor/conf.d/*.conf' "$cfg_file"
		fi
	fi

	download_startup_file
}

download_startup_file() {
	local supervisor_startup_file=""
	local supervisor_startup_file_url=""

	if command_exists systemctl; then
		supervisor_startup_file="/etc/systemd/system/supervisord.service"
		supervisor_startup_file_url="$SUPERVISOR_SYSTEMD_FILE_URL"

		download_file "$supervisor_startup_file_url" "$supervisor_startup_file"
		(
			set -x
			# 删除旧版 service 文件

			local old_service_file="/lib/systemd/system/supervisord.service"
			if [ -f "$old_service_file" ]; then
				rm -f "$old_service_file"
			fi
			systemctl daemon-reload >/dev/null 2>&1
		)
	elif command_exists service; then
		supervisor_startup_file='/etc/init.d/supervisord'

		if [ -z "$lsb_dist" ]; then
			get_os_info
		fi

		case "$lsb_dist" in
			ubuntu|debian|raspbian)
				supervisor_startup_file_url="$SUPERVISOR_SERVICE_FILE_DEBIAN_URL"
				;;
			fedora|centos|redhat|oraclelinux|photon)
				supervisor_startup_file_url="$SUPERVISOR_SERVICE_FILE_REDHAT_URL"
				;;
			*)
				echo "没有适合当前系统的服务启动脚本文件。"
				exit 1
				;;
		esac

		download_file "$supervisor_startup_file_url" "$supervisor_startup_file"
		(
			set -x
			chmod a+x "$supervisor_startup_file"
		)
	else
		cat >&2 <<-'EOF'
		当前服务器未安装 systemctl 或者 service 命令，无法配置服务。
		请先手动安装 systemd 或者 service 之后再运行脚本。
		EOF

		exit 1
	fi
}

start_supervisor() {
	( set -x; sleep 3 )
	if command_exists systemctl; then
		if systemctl status supervisord.service >/dev/null 2>&1; then
			systemctl restart supervisord.service
		else
			systemctl start supervisord.service
		fi
	elif command_exists service; then
		if service supervisord status >/dev/null 2>&1; then
			service supervisord restart
		else
			service supervisord start
		fi
	fi

	if [ "$?" != "0" ]; then
		cat >&2 <<-'EOF'
		启动 Supervisor 失败, Kcptun 无法正常工作!
		请反馈给脚本作者。
		EOF
		exit 1
	fi
}

enable_supervisor() {
	if command_exists systemctl; then
		(
			set -x
			systemctl enable "supervisord.service"
		)
	elif command_exists service; then
		if [ -z "$lsb_dist" ]; then
			get_os_info
		fi

		case "$lsb_dist" in
			ubuntu|debian|raspbian)
				(
					set -x
					update-rc.d -f supervisord defaults
				)
				;;
			fedora|centos|redhat|oraclelinux|photon)
				(
					set -x
					chkconfig --add supervisord
					chkconfig supervisord on
				)
				;;
			esac
	fi
}

set_kcptun_config() {
	is_port() {
		local port="$1"
		is_number "$port" && \
			[ $port -ge 1 ] && [ $port -le 65535 ]
	}

	port_using() {
		local port="$1"

		if command_exists netstat; then
			( netstat -ntul | grep -qE "[0-9:*]:${port}\s" )
		elif command_exists ss; then
			( ss -ntul | grep -qE "[0-9:*]:${port}\s" )
		else
			return 0
		fi

		return $?
	}

	local input=""
	local yn=""

	# 设置服务运行端口
	[ -z "$listen_port" ] && listen_port="$D_LISTEN_PORT"
	while true
	do
		cat >&1 <<-'EOF'
		请输入 Kcptun 服务端运行端口 [1~65535]
		这个端口就是 Kcptun 客户端连接的端口
		EOF
		read -p "(默认: ${listen_port}): " input
		if [ -n "$input" ]; then
			if is_port "$input"; then
				listen_port="$input"
			else
				echo "输入有误, 请输入 1~65535 之间的数字!"
				continue
			fi
		fi

		if port_using "$listen_port" && \
			[ "$listen_port" != "$current_listen_port" ]; then
			echo "端口已被占用, 请重新输入!"
			continue
		fi
		break
	done

	input=""
	cat >&1 <<-EOF
	---------------------------
	端口 = ${listen_port}
	---------------------------
	EOF

	[ -z "$target_addr" ] && target_addr="$D_TARGET_ADDR"
	cat >&1 <<-'EOF'
	请输入需要加速的地址
	可以输入主机名称、IPv4 地址或者 IPv6 地址
	EOF
	read -p "(默认: ${target_addr}): " input
	if [ -n "$input" ]; then
		target_addr="$input"
	fi

	input=""
	cat >&1 <<-EOF
	---------------------------
	加速地址 = ${target_addr}
	---------------------------
	EOF

	[ -z "$target_port" ] && target_port="$D_TARGET_PORT"
	while true
	do
		cat >&1 <<-'EOF'
		请输入需要加速的端口 [1~65535]
		EOF
		read -p "(默认: ${target_port}): " input
		if [ -n "$input" ]; then
			if is_port "$input"; then
				if [ "$input" = "$listen_port" ]; then
					echo "加速端口不能和 Kcptun 端口一致!"
					continue
				fi

				target_port="$input"
			else
				echo "输入有误, 请输入 1~65535 之间的数字!"
				continue
			fi
		fi

		if [ "$target_addr" = "127.0.0.1" ] && ! port_using "$target_port"; then
			read -p "当前没有软件使用此端口, 确定加速此端口? [y/n]: " yn
			if [ -n "$yn" ]; then
				case "$(first_character "$yn")" in
					y|Y)
						;;
					*)
						continue
						;;
				esac
			fi
		fi

		break
	done

	input=""
	yn=""
	cat >&1 <<-EOF
	---------------------------
	加速端口 = ${target_port}
	---------------------------
	EOF

	[ -z "$key" ] && key="$D_KEY"
	cat >&1 <<-'EOF'
	请设置 Kcptun 密码(key)
	该参数必须两端一致
	EOF
	read -p "(默认密码: ${key}): " input
	[ -n "$input" ] && key="$input"

	input=""
	cat >&1 <<-EOF
	---------------------------
	密码 = ${key}
	---------------------------
	EOF

	[ -z "$crypt" ] && crypt="$D_CRYPT"
	local crypt_list="aes aes-128 aes-192 salsa20 blowfish twofish cast5 3des tea xtea xor none"
	local i=0
	cat >&1 <<-'EOF'
	请选择加密方式(crypt)
	强加密对 CPU 要求较高，
	如果是在路由器上配置客户端，
	请尽量选择弱加密或者不加密。
	该参数必须两端一致
	EOF
	while true
	do

		for c in $crypt_list; do
			i=$(expr $i + 1)
			echo "(${i}) ${c}"
		done

		read -p "(默认: ${crypt}) 请选择 [1~$i]: " input
		if [ -n "$input" ]; then
			if is_number "$input" && [ $input -ge 1 ] && [ $input -le $i ]; then
				crypt=$(echo "$crypt_list" | cut -d' ' -f ${input})
			else
				echo "请输入有效数字 1~$i!"
				i=0
				continue
			fi
		fi
		break
	done

	input=""
	i=0
	cat >&1 <<-EOF
	-----------------------------
	加密方式 = ${crypt}
	-----------------------------
	EOF

	[ -z "$mode" ] && mode="$D_MODE"
	local mode_list="normal fast fast2 fast3 manual"
	i=0
	cat >&1 <<-'EOF'
	请选择加速模式(mode)
	加速模式和发送窗口大小共同决定了流量的损耗大小
	如果加速模式选择“手动(manual)”，
	将进入手动档隐藏参数的设置。
	EOF
	while true
	do

		for m in $mode_list; do
			i=$(expr $i + 1)
			echo "(${i}) ${m}"
		done

		read -p "(默认: ${mode}) 请选择 [1~$i]: " input
		if [ -n "$input" ]; then
			if is_number "$input" && [ $input -ge 1 ] && [ $input -le $i ]; then
				mode=$(echo "$mode_list" | cut -d ' ' -f ${input})
			else
				echo "请输入有效数字 1~$i!"
				i=0
				continue
			fi
		fi
		break
	done

	input=""
	i=0
	cat >&1 <<-EOF
	---------------------------
	加速模式 = ${mode}
	---------------------------
	EOF

	if [ "$mode" = "manual" ]; then
		set_manual_parameters
	else
		nodelay=""
		interval=""
		resend=""
		nc=""
	fi

	[ -z "$mtu" ] && mtu="$D_MTU"
	while true
	do
		cat >&1 <<-'EOF'
		请设置 UDP 数据包的 MTU (最大传输单元)值
		EOF
		read -p "(默认: ${mtu}): " input
		if [ -n "$input" ]; then
			if ! is_number "$input" || [ $input -le 0 ]; then
				echo "输入有误, 请输入大于0的数字!"
				continue
			fi

			mtu=$input
		fi
		break
	done

	input=""
	cat >&1 <<-EOF
	---------------------------
	MTU = ${mtu}
	---------------------------
	EOF

	[ -z "$sndwnd" ] && sndwnd="$D_SNDWND"
	while true
	do
		cat >&1 <<-'EOF'
		请设置发送窗口大小(sndwnd)
		发送窗口过大会浪费过多流量
		EOF
		read -p "(数据包数量, 默认: ${sndwnd}): " input
		if [ -n "$input" ]; then
			if ! is_number "$input" || [ $input -le 0 ]; then
				echo "输入有误, 请输入大于0的数字!"
				continue
			fi

			sndwnd=$input
		fi
		break
	done

	input=""
	cat >&1 <<-EOF
	---------------------------
	sndwnd = ${sndwnd}
	---------------------------
	EOF

	[ -z "$rcvwnd" ] && rcvwnd="$D_RCVWND"
	while true
	do
		cat >&1 <<-'EOF'
		请设置接收窗口大小(rcvwnd)
		EOF
		read -p "(数据包数量, 默认: ${rcvwnd}): " input
		if [ -n "$input" ]; then
			if ! is_number "$input" || [ $input -le 0 ]; then
				echo "输入有误, 请输入大于0的数字!"
				continue
			fi

			rcvwnd=$input
		fi
		break
	done

	input=""
	cat >&1 <<-EOF
	---------------------------
	rcvwnd = ${rcvwnd}
	---------------------------
	EOF

	[ -z "$datashard" ] && datashard="$D_DATASHARD"
	while true
	do
		cat >&1 <<-'EOF'
		请设置前向纠错 datashard
		该参数必须两端一致
		EOF
		read -p "(默认: ${datashard}): " input
		if [ -n "$input" ]; then
			if ! is_number "$input" || [ $input -lt 0 ]; then
				echo "输入有误, 请输入大于等于0的数字!"
				continue
			fi

			datashard=$input
		fi
		break
	done

	input=""
	cat >&1 <<-EOF
	---------------------------
	datashard = ${datashard}
	---------------------------
	EOF

	[ -z "$parityshard" ] && parityshard="$D_PARITYSHARD"
	while true
	do
		cat >&1 <<-'EOF'
		请设置前向纠错 parityshard
		该参数必须两端一致
		EOF
		read -p "(默认: ${parityshard}): " input
		if [ -n "$input" ]; then
			if ! is_number "$input" || [ $input -lt 0 ]; then
				echo "输入有误, 请输入大于等于0的数字!"
				continue
			fi

			parityshard=$input
		fi
		break
	done

	input=""
	cat >&1 <<-EOF
	---------------------------
	parityshard = ${parityshard}
	---------------------------
	EOF

	[ -z "$dscp" ] && dscp="$D_DSCP"
	while true
	do
		cat >&1 <<-'EOF'
		请设置差分服务代码点(DSCP)
		EOF
		read -p "(默认: ${dscp}): " input
		if [ -n "$input" ]; then
			if ! is_number "$input" || [ $input -lt 0 ]; then
				echo "输入有误, 请输入大于等于0的数字!"
				continue
			fi

			dscp=$input
		fi
		break
	done

	input=""
	cat >&1 <<-EOF
	---------------------------
	DSCP = ${dscp}
	---------------------------
	EOF

	[ -z "$nocomp" ] && nocomp="$D_NOCOMP"
	while true
	do
		cat >&1 <<-'EOF'
		是否关闭数据压缩?
		EOF
		read -p "(默认: ${nocomp}) [y/n]: " yn
		if [ -n "$yn" ]; then
			case "$(first_character "$yn")" in
				y|Y)
					nocomp='true'
					;;
				n|N)
					nocomp='false'
					;;
				*)
					echo "输入有误，请重新输入!"
					continue
					;;
			esac
		fi
		break
	done

	yn=""
	cat >&1 <<-EOF
	---------------------------
	nocomp = ${nocomp}
	---------------------------
	EOF

	[ -z "$quiet" ] && quiet="$D_QUIET"
	while true
	do
		cat >&1 <<-'EOF'
		是否屏蔽 open/close 日志输出?
		EOF
		read -p "(默认: ${quiet}) [y/n]: " yn
		if [ -n "$yn" ]; then
			case "$(first_character "$yn")" in
				y|Y)
					quiet='true'
					;;
				n|N)
					quiet='false'
					;;
				*)
					echo "输入有误，请重新输入!"
					continue
					;;
			esac
		fi
		break
	done

	yn=""
	cat >&1 <<-EOF
	---------------------------
	quiet = ${quiet}
	---------------------------
	EOF

	[ -z "$tcp" ] && tcp="$D_TCP"
	while true
	do
		cat >&1 <<-'EOF'
		是否使用 TCP 传输
		EOF
		read -p "(默认: ${tcp}) [y/n]: " yn
		if [ -n "$yn" ]; then
			case "$(first_character "$yn")" in
				y|Y)
					tcp='true'
					;;
				n|N)
					tcp='false'
					;;
				*)
					echo "输入有误，请重新输入!"
					continue
					;;
			esac
		fi
		break
	done

	if [ "$tcp" = "true" ]; then
		run_user="root"
	fi

	yn=""
	cat >&1 <<-EOF
	---------------------------
	tcp = ${tcp}
	---------------------------
	EOF

	unset_snmp() {
		snmplog=""
		snmpperiod=""
		cat >&1 <<-EOF
		---------------------------
		不记录 SNMP 日志
		---------------------------
		EOF
	}

	cat >&1 <<-EOF
	是否记录 SNMP 日志?
	EOF
	read -p "(默认: 否) [y/n]: " yn
	if [ -n "$yn" ]; then
		case "$(first_character "$yn")" in
			y|Y)
				set_snmp
				;;
			n|N|*)
				unset_snmp
				;;
		esac
		yn=""
	else
		unset_snmp
	fi

	[ -z "$pprof" ] && pprof="$D_PPROF"
	while true
	do
		cat >&1 <<-'EOF'
		是否开启 pprof 性能监控?
		地址: http://IP:6060/debug/pprof/
		EOF
		read -p "(默认: ${pprof}) [y/n]: " yn
		if [ -n "$yn" ]; then
			case "$(first_character "$yn")" in
				y|Y)
					pprof='true'
					;;
				n|N)
					pprof='false'
					;;
				*)
					echo "输入有误，请重新输入!"
					continue
					;;
			esac
		fi
		break
	done

	yn=""
	cat >&1 <<-EOF
	---------------------------
	pprof = ${pprof}
	---------------------------
	EOF

	unset_hidden_parameters() {
		acknodelay=""
		sockbuf=""
		smuxbuf=""
		keepalive=""
		cat >&1 <<-EOF
		---------------------------
		不配置隐藏参数
		---------------------------
		EOF
	}

	cat >&1 <<-'EOF'
	基础参数设置完成，是否设置额外的隐藏参数?
	通常情况下保持默认即可，不用额外设置
	EOF
	read -p "(默认: 否) [y/n]: " yn
	if [ -n "$yn" ]; then
		case "$(first_character "$yn")" in
			y|Y)
				set_hidden_parameters
				;;
			n|N|*)
				unset_hidden_parameters
				;;
		esac
	else
		unset_hidden_parameters
	fi

	if [ $listen_port -le 1024 ]; then
		run_user="root"
	fi

	echo "配置完成。"
	any_key_to_continue
}

set_snmp() {
	snmplog="$(get_current_file 'snmp')"

	local input=""
	[ -z "$snmpperiod" ] && snmpperiod="$D_SNMPPERIOD"
	while true
	do
		cat >&1 <<-'EOF'
		请设置 SNMP 记录间隔时间 snmpperiod
		EOF
		read -p "(默认: ${snmpperiod}): " input
		if [ -n "$input" ]; then
			if ! is_number "$input" || [ $input -lt 0 ]; then
				echo "输入有误, 请输入大于等于0的数字!"
				continue
			fi

			snmpperiod=$input
		fi
		break
	done

	cat >&1 <<-EOF
	---------------------------
	snmplog = ${snmplog}
	snmpperiod = ${snmpperiod}
	---------------------------
	EOF
}

set_manual_parameters() {
	echo "开始配置手动参数..."
	local input=""
	local yn=""

	[ -z "$nodelay" ] && nodelay="$D_NODELAY"
	while true
	do
		cat >&1 <<-'EOF'
		是否启用 nodelay 模式?
		(0) 不启用
		(1) 启用
		EOF
		read -p "(默认: ${nodelay}) [0/1]: " input
		if [ -n "$input" ]; then
			case "$(first_character "$input")" in
				1)
					nodelay=1
					;;
				0|*)
					nodelay=0
					;;
				*)
					echo "输入有误，请重新输入!"
					continue
					;;
			esac
		fi
		break
	done

	input=""
	cat >&1 <<-EOF
	---------------------------
	nodelay = ${nodelay}
	---------------------------
	EOF

	[ -z "$interval" ] && interval="$D_INTERVAL"
	while true
	do
		cat >&1 <<-'EOF'
		请设置协议内部工作的 interval
		EOF
		read -p "(单位: ms, 默认: ${interval}): " input
		if [ -n "$input" ]; then
			if ! is_number "$input" || [ $input -le 0 ]; then
				echo "输入有误, 请输入大于0的数字!"
				continue
			fi

			interval=$input
		fi
		break
	done

	input=""
	cat >&1 <<-EOF
	---------------------------
	interval = ${interval}
	---------------------------
	EOF

	[ -z "$resend" ] && resend="$D_RESEND"
	while true
	do
		cat >&1 <<-'EOF'
		是否启用快速重传模式(resend)?
		(0) 不启用
		(1) 启用
		(2) 2次ACK跨越将会直接重传
		EOF
		read -p "(默认: ${resend}) 请选择 [0~2]: " input
		if [ -n "$input" ]; then
			case "$(first_character "$input")" in
				0)
					resend=0
					;;
				1)
					resend=1
					;;
				2)
					resend=2
					;;
				*)
					echo "输入有误，请重新输入!"
					continue
					;;
			esac
		fi
		break
	done

	input=""
	cat >&1 <<-EOF
	---------------------------
	resend = ${resend}
	---------------------------
	EOF

	[ -z "$nc" ] && nc="$D_NC"
	while true
	do
		cat >&1 <<-'EOF'
		是否关闭流控(nc)?
		(0) 关闭
		(1) 开启
		EOF
		read -p "(默认: ${nc}) [0/1]: " input
		if [ -n "$input" ]; then
			case "$(first_character "$input")" in
				0)
					nc=0
					;;
				1)
					nc=1
					;;
				*)
					echo "输入有误，请重新输入!"
					continue
					;;
			esac
		fi
		break
	done
	cat >&1 <<-EOF
	---------------------------
	nc = ${nc}
	---------------------------
	EOF
}

set_hidden_parameters() {
	echo "开始设置隐藏参数..."
	local input=""
	local yn=""

	[ -z "$acknodelay" ] && acknodelay="$D_ACKNODELAY"
	while true
	do
		cat >&1 <<-'EOF'
		是否启用 acknodelay 模式?
		EOF
		read -p "(默认: ${acknodelay}) [y/n]: " yn
		if [ -n "$yn" ]; then
			case "$(first_character "$yn")" in
				y|Y)
					acknodelay="true"
					;;
				n|N)
					acknodelay="false"
					;;
				*)
					echo "输入有误，请重新输入!"
					continue
					;;
			esac
		fi
		break
	done

	yn=""
	cat >&1 <<-EOF
	---------------------------
	acknodelay = ${acknodelay}
	---------------------------
	EOF

	[ -z "$sockbuf" ] && sockbuf="$D_SOCKBUF"
	while true
	do
		cat >&1 <<-'EOF'
		请设置 UDP 收发缓冲区大小(sockbuf)
		EOF
		read -p "(单位: MB, 默认: $(expr ${sockbuf} / 1024 / 1024)): " input
		if [ -n "$input" ]; then
			if ! is_number "$input" || [ $input -le 0 ]; then
				echo "输入有误, 请输入大于0的数字!"
				continue
			fi

			sockbuf=$(expr $input \* 1024 \* 1024)
		fi
		break
	done

	input=""
	cat >&1 <<-EOF
	---------------------------
	sockbuf = ${sockbuf}
	---------------------------
	EOF

	[ -z "$smuxbuf" ] && smuxbuf="$D_SMUXBUF"
	while true
	do
		cat >&1 <<-'EOF'
		请设置 de-mux 缓冲区大小(smuxbuf)
		EOF
		read -p "(单位: MB, 默认: $(expr ${smuxbuf} / 1024 / 1024)): " input
		if [ -n "$input" ]; then
			if ! is_number "$input" || [ $input -le 0 ]; then
				echo "输入有误, 请输入大于0的数字!"
				continue
			fi

			smuxbuf=$(expr $input \* 1024 \* 1024)
		fi
		break
	done

	input=""
	cat >&1 <<-EOF
	---------------------------
	smuxbuf = ${smuxbuf}
	---------------------------
	EOF

	[ -z "$keepalive" ] && keepalive="$D_KEEPALIVE"
	while true
	do
		cat >&1 <<-'EOF'
		请设置 Keepalive 的间隔时间
		EOF
		read -p "(单位: s, 默认值: ${keepalive}, 前值: 5): " input
		if [ -n "$input" ]; then
			if ! is_number "$input" || [ $input -le 0 ]; then
				echo "输入有误, 请输入大于0的数字!"
				continue
			fi

			keepalive=$input
		fi
		break
	done

	cat >&1 <<-EOF
	---------------------------
	keepalive = ${keepalive}
	---------------------------
	EOF
}

# 生成 Kcptun 服务端配置文件
gen_kcptun_config() {
	mk_file_dir() {
		local dir=""
		dir="$(dirname "$1")"
		local mod=$2

		if [ ! -d "$dir" ]; then
			(
				set -x
				mkdir -p "$dir"
			)
		fi

		if [ -n "$mod" ]; then
			chmod $mod "$dir"
		fi
	}

	local config_file=""
	config_file="$(get_current_file 'config')"
	local supervisor_config_file=""
	supervisor_config_file="$(get_current_file 'supervisor')"

	mk_file_dir "$config_file"
	mk_file_dir "$supervisor_config_file"

	if [ -n "$snmplog" ]; then
		mk_file_dir "$snmplog" '777'
	fi

	if ( echo "$listen_addr" | grep -q ":" ); then
		listen_addr="[${listen_addr}]"
	fi

	if ( echo "$target_addr" | grep -q ":" ); then
		target_addr="[${target_addr}]"
	fi

	cat > "$config_file"<<-EOF
	{
	  "listen": "${listen_addr}:${listen_port}",
	  "target": "${target_addr}:${target_port}",
	  "key": "${key}",
	  "crypt": "${crypt}",
	  "mode": "${mode}",
	  "mtu": ${mtu},
	  "sndwnd": ${sndwnd},
	  "rcvwnd": ${rcvwnd},
	  "datashard": ${datashard},
	  "parityshard": ${parityshard},
	  "dscp": ${dscp},
	  "nocomp": ${nocomp},
	  "quiet": ${quiet},
	  "tcp": ${tcp}
	}
	EOF

	write_configs_to_file() {
		install_jq
		local k; local v

		local json=""
		json="$(cat "$config_file")"
		for k in "$@"; do
			v="$(eval echo "\$$k")"

			if [ -n "$v" ]; then
				if is_number "$v" || [ "$v" = "false" ] || [ "$v" = "true" ]; then
					json="$(echo "$json" | $JQ_BIN ".$k=$v")"
				else
					json="$(echo "$json" | $JQ_BIN ".$k=\"$v\"")"
				fi
			fi
		done

		if [ -n "$json" ] && [ "$json" != "$(cat "$config_file")" ]; then
			echo "$json" >"$config_file"
		fi
	}

	write_configs_to_file "snmplog" "snmpperiod" "pprof" "acknodelay" "nodelay" \
		"interval" "resend" "nc" "sockbuf" "smuxbuf" "keepalive"

	if ! grep -q "^${run_user}:" '/etc/passwd'; then
		(
			set -x
			useradd -U -s '/usr/sbin/nologin' -d '/nonexistent' "$run_user" 2>/dev/null
		)
	fi

	cat > "$supervisor_config_file"<<-EOF
	[program:kcptun${current_instance_id}]
	user=${run_user}
	directory=${KCPTUN_INSTALL_DIR}
	command=$(get_kcptun_server_file) -c "${config_file}"
	process_name=%(program_name)s
	autostart=true
	redirect_stderr=true
	stdout_logfile=$(get_current_file 'log')
	stdout_logfile_maxbytes=1MB
	stdout_logfile_backups=0
	EOF
}

# 设置防火墙开放端口
set_firewall() {
	if command_exists firewall-cmd; then
		if ! ( firewall-cmd --state >/dev/null 2>&1 ); then
			systemctl start firewalld >/dev/null 2>&1
		fi
		if [ "$?" = "0" ]; then
			if [ -n "$current_listen_port" ]; then
				firewall-cmd --zone=public --remove-port=${current_listen_port}/udp >/dev/null 2>&1
			fi

			if ! firewall-cmd --quiet --zone=public --query-port=${listen_port}/udp; then
				firewall-cmd --quiet --permanent --zone=public --add-port=${listen_port}/udp
				firewall-cmd --reload
			fi
		else
			cat >&1 <<-EOF
			警告: 自动添加 firewalld 规则失败
			如果有必要, 请手动添加端口 ${listen_port} 的防火墙规则:
			    firewall-cmd --permanent --zone=public --add-port=${listen_port}/udp
			    firewall-cmd --reload
			EOF
		fi
	elif command_exists iptables; then
		if ! ( service iptables status >/dev/null 2>&1 ); then
			service iptables start >/dev/null 2>&1
		fi

		if [ "$?" = "0" ]; then
			if [ -n "$current_listen_port" ]; then
				iptables -D INPUT -p udp --dport ${current_listen_port} -j ACCEPT >/dev/null 2>&1
			fi

			if ! iptables -C INPUT -p udp --dport ${listen_port} -j ACCEPT >/dev/null 2>&1; then
				iptables -I INPUT -p udp --dport ${listen_port} -j ACCEPT >/dev/null 2>&1
				service iptables save
				service iptables restart
			fi
		else
			cat >&1 <<-EOF
			警告: 自动添加 iptables 规则失败
			如有必要, 请手动添加端口 ${listen_port} 的防火墙规则:
			    iptables -I INPUT -p udp --dport ${listen_port} -j ACCEPT
			    service iptables save
			    service iptables restart
			EOF
		fi
	fi
}

# 选择一个实例
select_instance() {
	if [ "$(get_instance_count)" -gt 1 ]; then
		cat >&1 <<-'EOF'
		当前有多个 Kcptun 实例 (按最后修改时间排序):
		EOF

		local files=""
		files=$(ls -lt '/etc/supervisor/conf.d/' | grep "^-" | awk '{print $9}' | grep "^kcptun[0-9]*\.conf$")
		local i=0
		local array=""
		local id=""
		for file in $files; do
			id="$(echo "$file" | grep -oE "[0-9]+")"
			array="${array}${id}#"

			i=$(expr $i + 1)
			echo "(${i}) ${file%.*}"
		done

		local sel=""
		while true
		do
			read -p "请选择 [1~${i}]: " sel
			if [ -n "$sel" ]; then
				if ! is_number "$sel" || [ $sel -lt 1 ] || [ $sel -gt $i ]; then
					cat >&2 <<-EOF
					请输入有效数字 1~${i}!
					EOF
					continue
				fi
			else
				cat >&2 <<-EOF
				请输入不能为空！
				EOF
				continue
			fi

			current_instance_id=$(echo "$array" | cut -d '#' -f ${sel})
			break
		done
	fi
}

# 通过当前服务端环境获取 Kcptun 服务端文件名
get_kcptun_server_file() {
	if [ -z "$file_suffix" ]; then
		get_arch
	fi

	echo "${KCPTUN_INSTALL_DIR}/server_$file_suffix"
}

# 计算新实例的 ID
get_new_instance_id() {
	if [ -f "/etc/supervisor/conf.d/kcptun.conf" ]; then
		local i=2
		while [ -f "/etc/supervisor/conf.d/kcptun${i}.conf" ]
		do
			i=$(expr $i + 1)
		done
		echo "$i"
	fi
}

# 获取已安装的 Kcptun 版本
get_installed_version() {
	local server_file=""
	server_file="$(get_kcptun_server_file)"

	if [ -f "$server_file" ]; then
		if [ ! -x "$server_file" ]; then
			chmod a+x "$server_file"
		fi

		echo "$(${server_file} -v 2>/dev/null | awk '{print $3}')"
	fi
}

# 加载当前选择实例的配置文件
load_instance_config() {
	local config_file=""
	config_file="$(get_current_file 'config')"

	if [ ! -s "$config_file" ]; then
		cat >&2 <<-'EOF'
		实例配置文件不存在或为空, 请检查!
		EOF
		exit 1
	fi

	local config_content=""
	config_content="$(cat ${config_file})"

	if [ -z "$(get_json_string "$config_content" '.listen')" ]; then
		cat >&2 <<-EOF
		实例配置文件存在错误, 请检查!
		配置文件路径: ${config_file}
		EOF
		exit 1
	fi

	local lines=""
	lines="$(get_json_string "$config_content" 'to_entries | map("\(.key)=\(.value | @sh)") | .[]')"

	OLDIFS=$IFS
	IFS=$(printf '\n')
	for line in $lines; do
		eval "$line"
	done
	IFS=$OLDIFS

	if [ -n "$listen" ]; then
		listen_port="$(echo "$listen" | rev | cut -d ':' -f1 | rev)"
		listen_addr="$(echo "$listen" | sed "s/:${listen_port}$//" | grep -oE '[0-9a-fA-F\.:]*')"
		listen=""
	fi
	if [ -n "$target" ]; then
		target_port="$(echo "$target" | rev | cut -d ':' -f1 | rev)"
		target_addr="$(echo "$target" | sed "s/:${target_port}$//" | grep -oE '[0-9a-fA-F\.:]*')"
		target=""
	fi

	if [ -n "$listen_port" ]; then
		current_listen_port="$listen_port"
	fi
}

# 显示服务端 Kcptun 版本，和客户端文件的下载地址
show_version_and_client_url() {
	local version=""
	version="$(get_installed_version)"
	if [ -n "$version" ]; then
		cat >&1 <<-EOF

		当前安装的 Kcptun 版本为: ${version}
		EOF
	fi

	if [ -n "$kcptun_release_html_url" ]; then
		cat >&1 <<-EOF
		请自行前往:
		  ${kcptun_release_html_url}
		手动下载客户端文件
		EOF
	fi
}

# 显示当前选择实例的信息
show_current_instance_info() {
	local server_ip=""
	server_ip="$(get_server_ip)"

	printf '服务器IP: \033[41;37m %s \033[0m\n' "$server_ip"
	printf '端口: \033[41;37m %s \033[0m\n' "$listen_port"
	printf '加速地址: \033[41;37m %s:%s \033[0m\n' "$target_addr" "$target_port"

	show_configs() {
		local k; local v
		for k in "$@"; do
			v="$(eval echo "\$$k")"
			if [ -n "$v" ]; then
				printf '%s: \033[41;37m %s \033[0m\n' "$k" "$v"
			fi
		done
	}

	show_configs "key" "crypt" "mode" "mtu" "sndwnd" "rcvwnd" "datashard" \
		"parityshard" "dscp" "nocomp" "quiet" "tcp" "nodelay" "interval" "resend" \
		"nc" "acknodelay" "sockbuf" "smuxbuf" "keepalive"

	show_version_and_client_url

	install_jq
	local client_config=""

	# 这里输出的是客户端所使用的配置信息
	# 客户端的 *remoteaddr* 端口号为服务端的 *listen_port*
	# 客户端的 *localaddr* 端口号被设置为了服务端的加速端口
	client_config="$(cat <<-EOF
	{
	  "localaddr": ":${target_port}",
	  "remoteaddr": "${server_ip}:${listen_port}",
	  "key": "${key}"
	}
	EOF
	)"

	gen_client_configs() {
		local k; local v
		for k in "$@"; do
			if [ "$k" = "sndwnd" ]; then
				v="$rcvwnd"
			elif [ "$k" = "rcvwnd" ]; then
				v="$sndwnd"
			else
				v="$(eval echo "\$$k")"
			fi

			if [ -n "$v" ]; then
				if is_number "$v" || [ "$v" = "true" ] || [ "$v" = "false" ]; then
					client_config="$(echo "$client_config" | $JQ_BIN -r ".${k}=${v}")"
				else
					client_config="$(echo "$client_config" | $JQ_BIN -r ".${k}=\"${v}\"")"
				fi
			fi
		done
	}

	gen_client_configs "crypt" "mode" "mtu" "sndwnd" "rcvwnd" "datashard" \
		"parityshard" "dscp" "nocomp" "quiet" "tcp" "nodelay" "interval" "resend" \
		"nc" "acknodelay" "sockbuf" "smuxbuf" "keepalive"

	cat >&1 <<-EOF

	可使用的客户端配置文件为:
	${client_config}
	EOF

	local mobile_config="key=${key}"
	gen_mobile_configs() {
		local k; local v
		for k in "$@"; do
			if [ "$k" = "sndwnd" ]; then
				v="$rcvwnd"
			elif [ "$k" = "rcvwnd" ]; then
				v="$sndwnd"
			else
				v="$(eval echo "\$$k")"
			fi

			if [ -n "$v" ]; then
				if [ "$v" = "false" ]; then
					continue
				elif [ "$v" = "true" ]; then
					mobile_config="${mobile_config};${k}"
				else
					mobile_config="${mobile_config};${k}=${v}"
				fi
			fi
		done
	}

	gen_mobile_configs "crypt" "mode" "mtu" "sndwnd" "rcvwnd" "datashard" \
		"parityshard" "dscp" "nocomp" "quiet" "tcp" "nodelay" "interval" "resend" \
		"nc" "acknodelay" "sockbuf" "smuxbuf" "keepalive"

	cat >&1 <<-EOF

	手机端参数可以使用:
	  ${mobile_config}

	EOF
}

do_install() {
	check_root
	disable_selinux
	installed_check
	set_kcptun_config
	install_deps
	install_kcptun
	install_supervisor
	gen_kcptun_config
	set_firewall
	start_supervisor
	enable_supervisor

	cat >&1 <<-EOF

	恭喜! Kcptun 服务端安装成功。
	EOF

	show_current_instance_info

	cat >&1 <<-EOF
	Kcptun 安装目录: ${KCPTUN_INSTALL_DIR}

	已将 Supervisor 加入开机自启,
	Kcptun 服务端会随 Supervisor 的启动而启动

	更多使用说明: ${0} help

	如果这个脚本帮到了你，你可以请作者喝瓶可乐:
	  https://blog.kuoruan.com/donate

	享受加速的快感吧！
	EOF
}

# 卸载操作
do_uninstall() {
	check_root
	cat >&1 <<-'EOF'
	你选择了卸载 Kcptun 服务端
	EOF
	any_key_to_continue
	echo "正在卸载 Kcptun 服务端并停止 Supervisor..."

	if command_exists supervisorctl; then
		supervisorctl shutdown
	fi

	if command_exists systemctl; then
		systemctl stop supervisord.service
	elif command_exists serice; then
		service supervisord stop
	fi

	(
		set -x
		rm -f "/etc/supervisor/conf.d/kcptun*.conf"
		rm -rf "$KCPTUN_INSTALL_DIR"
		rm -rf "$KCPTUN_LOG_DIR"
	)

	cat >&1 <<-'EOF'
	是否同时卸载 Supervisor ?
	注意: Supervisor 的配置文件将同时被删除
	EOF

	read -p "(默认: 不卸载) 请选择 [y/n]: " yn
	if [ -n "$yn" ]; then
		case "$(first_character "$yn")" in
			y|Y)
				if command_exists systemctl; then
					systemctl disable supervisord.service
					rm -f "/lib/systemd/system/supervisord.service" \
						"/etc/systemd/system/supervisord.service"
				elif command_exists service; then
					if [ -z "$lsb_dist" ]; then
						get_os_info
					fi
					case "$lsb_dist" in
						ubuntu|debian|raspbian)
							(
								set -x
								update-rc.d -f supervisord remove
							)
							;;
						fedora|centos|redhat|oraclelinux|photon)
							(
								set -x
								chkconfig supervisord off
								chkconfig --del supervisord
							)
							;;
					esac
					rm -f '/etc/init.d/supervisord'
				fi

				(
					set -x
					# 新版使用 pip 卸载
					if command_exists pip; then
						pip uninstall -y supervisor 2>/dev/null || true
					fi

					# 旧版使用 easy_install 卸载
					if command_exists easy_install; then
						rm -rf "$(easy_install -mxN supervisor | grep 'Using.*supervisor.*\.egg' | awk '{print $2}')"
					fi

					rm -rf '/etc/supervisor/'
					rm -f '/usr/local/bin/supervisord' \
						'/usr/local/bin/supervisorctl' \
						'/usr/local/bin/pidproxy' \
						'/usr/local/bin/echo_supervisord_conf' \
						'/usr/bin/supervisord' \
						'/usr/bin/supervisorctl' \
						'/usr/bin/pidproxy' \
						'/usr/bin/echo_supervisord_conf'
				)
				;;
			n|N|*)
				start_supervisor
				;;
		esac
	fi

	cat >&1 <<-EOF
	卸载完成, 欢迎再次使用。
	注意: 脚本没有自动卸载 python-pip 和 python-setuptools（旧版脚本使用）
	如有需要, 你可以自行卸载。
	EOF
}

# 更新
do_update() {
	pre_ckeck

	cat >&1 <<-EOF
	你选择了检查更新, 正在开始操作...
	EOF

	if get_shell_version_info; then
		local shell_path=$0

		if [ $new_shell_version -gt $SHELL_VERSION ]; then
			cat >&1 <<-EOF
			发现一键安装脚本更新, 版本号: ${new_shell_version}
			更新说明:
			$(printf '%s\n' "$shell_change_log")
			EOF
			any_key_to_continue

			mv -f "$shell_path" "$shell_path".bak

			download_file "$new_shell_url" "$shell_path"
			chmod a+x "$shell_path"

			sed -i -r "s/^CONFIG_VERSION=[0-9]+/CONFIG_VERSION=${CONFIG_VERSION}/" "$shell_path"
			sed -i -r "s/^INIT_VERSION=[0-9]+/INIT_VERSION=${INIT_VERSION}/" "$shell_path"
			rm -f "$shell_path".bak

			clear
			cat >&1 <<-EOF
			安装脚本已更新到 v${new_shell_version}, 正在运行新的脚本...
			EOF

			bash "$shell_path" update
			exit 0
		fi

		if [ $new_config_version -gt $CONFIG_VERSION ]; then
			cat >&1 <<-EOF
			发现 Kcptun 配置更新, 版本号: v${new_config_version}
			更新说明:
			$(printf '%s\n' "$config_change_log")
			需要重新设置 Kcptun
			EOF
			any_key_to_continue

			instance_reconfig

			sed -i "s/^CONFIG_VERSION=${CONFIG_VERSION}/CONFIG_VERSION=${new_config_version}/" \
				"$shell_path"
		fi

		if [ $new_init_version -gt $INIT_VERSION ]; then
			cat >&1 <<-EOF
			发现服务启动脚本文件更新, 版本号: v${new_init_version}
			更新说明:
			$(printf '%s\n' "$init_change_log")
			EOF

			any_key_to_continue

			download_startup_file
			set -sed -i "s/^INIT_VERSION=${INIT_VERSION}/INIT_VERSION=${new_init_version}/" \
				"$shell_path"
		fi
	fi

	echo "开始获取 Kcptun 版本信息..."
	get_kcptun_version_info

	local cur_tag_name=""
	cur_tag_name="$(get_installed_version)"

	if [ -n "$cur_tag_name" ] && is_number "$cur_tag_name" && [ ${#cur_tag_name} -eq 8 ]; then
		cur_tag_name=v"$cur_tag_name"
	fi

	if [ -n "$kcptun_release_tag_name" ] && [ "$kcptun_release_tag_name" != "$cur_tag_name" ]; then
		cat >&1 <<-EOF
		发现 Kcptun 新版本 ${kcptun_release_tag_name}
		$([ "$kcptun_release_prerelease" = "true" ] && printf "\033[41;37m 注意: 该版本为预览版, 请谨慎更新 \033[0m")
		更新说明:
		$(printf '%s\n' "$kcptun_release_body")
		EOF
		any_key_to_continue

		install_kcptun
		start_supervisor

		show_version_and_client_url
	else
		cat >&1 <<-'EOF'
		未发现 Kcptun 更新...
		EOF
	fi
}

# 添加实例
instance_add() {
	pre_ckeck

	cat >&1 <<-'EOF'
	你选择了添加实例, 正在开始操作...
	EOF
	current_instance_id="$(get_new_instance_id)"

	set_kcptun_config
	gen_kcptun_config
	set_firewall
	start_supervisor

	cat >&1 <<-EOF
	恭喜, 实例 kcptun${current_instance_id} 添加成功!
	EOF
	show_current_instance_info
}

# 删除实例
instance_del() {
	pre_ckeck

	if [ -n "$1" ]; then
		if is_number "$1"; then
			if [ "$1" != "1" ]; then
				current_instance_id="$1"
			fi
		else
			cat >&2 <<-EOF
			参数有误, 请使用 $0 del <id>
			<id> 为实例ID, 当前共有 $(get_instance_count) 个实例
			EOF

			exit 1
		fi
	fi

	cat >&1 <<-EOF
	你选择了删除实例 kcptun${current_instance_id}
	注意: 实例删除后无法恢复
	EOF
	any_key_to_continue

	# 获取实例的 supervisor 配置文件
	supervisor_config_file="$(get_current_file 'supervisor')"
	if [ ! -f "$supervisor_config_file" ]; then
		echo "你选择的实例 kcptun${current_instance_id} 不存在!"
		exit 1
	fi

	current_config_file="$(get_current_file 'config')"
	current_log_file="$(get_current_file 'log')"
	current_snmp_log_file="$(get_current_file 'snmp')"

	(
		set -x
		rm -f "$supervisor_config_file" \
			"$current_config_file" \
			"$current_log_file" \
			"$current_snmp_log_file"
	)

	start_supervisor

	cat >&1 <<-EOF
	实例 kcptun${current_instance_id} 删除成功!
	EOF
}

# 显示实例信息
instance_show() {
	pre_ckeck

	if [ -n "$1" ]; then
		if is_number "$1"; then
			if [ "$1" != "1" ]; then
				current_instance_id="$1"
			fi
		else
			cat >&2 <<-EOF
			参数有误, 请使用 $0 show <id>
			<id> 为实例ID, 当前共有 $(get_instance_count) 个实例
			EOF

			exit 1
		fi
	fi

	echo "你选择了查看实例 kcptun${current_instance_id} 的配置, 正在读取..."

	load_instance_config

	echo "实例 kcptun${current_instance_id} 的配置信息如下:"
	show_current_instance_info
}

# 显示实例日志
instance_log() {
	pre_ckeck

	if [ -n "$1" ]; then
		if is_number "$1"; then
			if [ "$1" != "1" ]; then
				current_instance_id="$1"
			fi
		else
			cat >&2 <<-EOF

			参数有误, 请使用 $0 log <id>
			<id> 为实例ID, 当前共有 $(get_instance_count) 个实例
			EOF

			exit 1
		fi
	fi

	echo "你选择了查看实例 kcptun${current_instance_id} 的日志, 正在读取..."

	local log_file=""
	log_file="$(get_current_file 'log')"

	if [ -f "$log_file" ]; then
		cat >&1 <<-EOF
		实例 kcptun${current_instance_id} 的日志信息如下:
		注: 日志实时刷新, 按 Ctrl+C 退出日志查看
		EOF
		tail -n 20 -f "$log_file"
	else
		cat >&2 <<-EOF
		未找到实例 kcptun${current_instance_id} 的日志文件...
		EOF
		exit 1
	fi
}

# 重新配置实例
instance_reconfig() {
	pre_ckeck

	if [ -n "$1" ]; then
		if is_number "$1"; then
			if [ "$1" != "1" ]; then
				current_instance_id="$1"
			fi
		else
			cat >&2 <<-EOF
			参数有误, 请使用 $0 reconfig <id>
			<id> 为实例ID, 当前共有 $(get_instance_count) 个实例
			EOF

			exit 1
		fi
	fi

	cat >&1 <<-EOF
	你选择了重新配置实例 kcptun${current_instance_id}, 正在开始操作...
	EOF

	if [ ! -f "$(get_current_file 'supervisor')" ]; then
		cat >&2 <<-EOF
		你选择的实例 kcptun${current_instance_id} 不存在!
		EOF
		exit 1
	fi

	local sel=""
	cat >&1 <<-'EOF'
	请选择操作:
	(1) 重新配置实例所有选项
	(2) 直接修改实例配置文件
	EOF
	read -p "(默认: 1) 请选择: " sel
	echo
	[ -z "$sel" ] && sel="1"

	case "$(first_character "$sel")" in
		2)
			echo "正在打开配置文件, 请手动修改..."
			local config_file=""
			config_file="$(get_current_file 'config')"
			edit_config_file() {
				if [ ! -f "$config_file" ]; then
					return 1
				fi

				if command_exists vim; then
					vim "$config_file"
				elif command_exists vi; then
					vi "$config_file"
				elif command_exists gedit; then
					gedit "$config_file"
				else
					echo "未找到可用的编辑器, 正在进入全新配置..."
					return 1
				fi

				load_instance_config
			}

			if ! edit_config_file; then
				set_kcptun_config
			fi
			;;
		1|*)
			load_instance_config
			set_kcptun_config
			;;
	esac

	gen_kcptun_config
	set_firewall

	if command_exists supervisorctl; then
		supervisorctl restart "kcptun${current_instance_id}"

		if [ "$?" != "0" ]; then
			cat >&2 <<-'EOF'
			重启 Supervisor 失败, Kcptun 无法正常工作!
			请查看日志获取原因，或者反馈给脚本作者。
			EOF
			exit 1
		fi
	else
		start_supervisor
	fi

	cat >&1 <<-EOF

	恭喜, Kcptun 服务端配置已更新!
	EOF
	show_current_instance_info
}

#手动安装
manual_install() {
	pre_ckeck

	cat >&1 <<-'EOF'
	你选择了自定义版本安装, 正在开始操作...
	EOF

	local tag_name="$1"

	while true
	do
		if [ -z "$tag_name" ]; then
			cat >&1 <<-'EOF'
			请输入你想安装的 Kcptun 版本的完整 TAG
			EOF
			read -p "(例如: v20160904): " tag_name
			if [ -z "$tag_name" ]; then
				echo "输入无效, 请重新输入!"
				continue
			fi
		fi

		if [ "$tag_name" = "SNMP_Milestone" ]; then
			echo "不支持此版本, 请重新输入!"
			tag_name=""
			continue
		fi

		local version_num=""
		version_num=$(echo "$tag_name" | grep -oE "[0-9]+" || "0")
		if [ ${#version_num} -eq 8 ] && [ $version_num -le 20160826 ]; then
			echo "不支持安装 v20160826 及以前版本"
			tag_name=""
			continue
		fi

		echo "正在获取信息，请稍候..."
		get_kcptun_version_info "$tag_name"
		if [ "$?" != "0" ]; then
			cat >&2 <<-EOF
			未找到对应版本下载地址 (TAG: ${tag_name}), 请重新输入!
			你可以前往:
			  ${KCPTUN_TAGS_URL}
			查看所有可用 TAG
			EOF
			tag_name=""
			continue
		else
			cat >&1 <<-EOF
			已找到 Kcptun 版本信息, TAG: ${tag_name}
			EOF
			any_key_to_continue

			install_kcptun "$tag_name"
			start_supervisor
			show_version_and_client_url
			break
		fi
	done
}

pre_ckeck() {
	check_root

	if ! is_installed; then
		cat >&2 <<-EOF
		错误: 检测到你还没有安装 Kcptun，
		或者 Kcptun 程序文件已损坏，
		请运行脚本来重新安装 Kcptun 服务端。
		EOF

		exit 1
	fi
}

# 监测是否安装了 kcptun
is_installed() {
	if [ -d '/usr/share/kcptun' ]; then
		cat >&1 <<-EOF
		检测发现你由旧版升级到了新版
		新版中将默认安装目录设置为了 ${KCPTUN_INSTALL_DIR}
		脚本会自动将文件从旧版目录 /usr/share/kcptun
		移动到新版目录 ${KCPTUN_INSTALL_DIR}
		EOF
		any_key_to_continue
		(
			set -x
			cp -rf '/usr/share/kcptun' "$KCPTUN_INSTALL_DIR" && \
				rm -rf '/usr/share/kcptun'
		)
	fi

	if [ -d '/etc/supervisor/conf.d/' ] && [ -d "$KCPTUN_INSTALL_DIR" ] && \
		[ -n "$(get_installed_version)" ]; then
		return 0
	fi

	return 1
}

# 检查是否已经安装
installed_check() {
	local instance_count=""
	instance_count="$(get_instance_count)"
	if is_installed && [ $instance_count -gt 0 ]; then
		cat >&1 <<-EOF
		检测到你已安装 Kcptun 服务端, 已配置的实例个数为 ${instance_count} 个
		EOF
		while true
		do
			cat >&1 <<-'EOF'
			请选择你希望的操作:
			(1) 覆盖安装
			(2) 重新配置
			(3) 添加实例(多端口)
			(4) 检查更新
			(5) 查看配置
			(6) 查看日志输出
			(7) 自定义版本安装
			(8) 删除实例
			(9) 完全卸载
			(10) 退出脚本
			EOF
			read -p "(默认: 1) 请选择 [1~10]: " sel
			[ -z "$sel" ] && sel=1

			case $sel in
				1)
					echo "开始覆盖安装 Kcptun 服务端..."
					load_instance_config
					return 0
					;;
				2)
					select_instance
					instance_reconfig
					;;
				3)
					instance_add
					;;
				4)
					do_update
					;;
				5)
					select_instance
					instance_show
					;;
				6)
					select_instance
					instance_log
					;;
				7)
					manual_install
					;;
				8)
					select_instance
					instance_del
					;;
				9)
					do_uninstall
					;;
				10)
					;;
				*)
					echo "输入有误, 请输入有效数字 1~10!"
					continue
					;;
			esac

			exit 0
		done
	fi
}

action=${1:-"install"}
case "$action" in
	install|uninstall|update)
		do_${action}
		;;
	add|reconfig|show|log|del)
		instance_${action} "$2"
		;;
	manual)
		manual_install "$2"
		;;
	help)
		usage 0
		;;
	*)
		usage 1
		;;
esac
