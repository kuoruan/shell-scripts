# Linux Shell Scripts

一些 Linux 脚本

```sh
$ tree
├── kcptun
│   └── kcptun.sh # kcptun 一键安装脚本
└── ovz-bbr
    └── ovz-bbr-installer.sh # OpenVZ BBR 一键安装脚本
```

## Kcptun 一键安装脚本

* 安装命令：

```sh
wget --no-check-certificate -O kcptun.sh https://github.com/kuoruan/shell-scripts/raw/master/kcptun/kcptun.sh
sh kcptun.sh
```

* 帮助信息

```sh
# sh kcptun.sh help
请使用: kcptun.sh <option>

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
```

## OpenVZ BBR 一键安装脚本

* 安装命令：

```sh
wget --no-check-certificate -O ovz-bbr-installer.sh https://github.com/kuoruan/shell-scripts/raw/master/ovz-bbr/ovz-bbr-installer.sh
sh ovz-bbr-installer.sh
```

* 卸载命令

```sh
sh ovz-bbr-installer.sh uninstall
```
