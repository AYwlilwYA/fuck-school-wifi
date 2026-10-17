hotspot-ttl 归一化器 (TTL Normalizer) 安装包
================================================

内容
----
  hotspot-ttl-setup.exe   单文件安装器/卸载器 (内嵌程序 + WinDivert 驱动)
  install.cmd             一键安装
  uninstall.cmd           一键卸载
  README.txt              本文件

安装
----
  双击 install.cmd 或 hotspot-ttl-setup.exe（会自动请求管理员权限）。

  安装内容:
    - 程序文件释放到 D:\hotspot-ttl\bin\ (normalizer.exe + WinDivert64.dll/.sys)
    - 注册计划任务 TTL-Normalize（开机自启默认开: 开机 + 登录 + 休眠恢复 触发）
    - 立即启动主/副双进程
    - 登记"设置-应用"里的卸载入口, 并在 D:\hotspot-ttl\ 放"卸载.cmd"

可选参数
--------
  /dir <路径>      指定安装目录（默认 D:\hotspot-ttl）
  /ttl <1..255>    目标 TTL（默认 128）
  /no-autostart    不注册开机自启（默认注册）
  /uninstall       卸载

卸载
----
  三种方式任选:
    - 双击 D:\hotspot-ttl\卸载.cmd
    - 设置 - 应用 - 已安装的应用 - "hotspot-ttl 归一化器" - 卸载
    - 命令行: hotspot-ttl-setup.exe /uninstall

  卸载动作: 停止进程 → 删除计划任务 → 清理 WinDivert 驱动服务 → 程序文件进回收站。
  日志 (logs) 与文档 (doc) 保留。

许可
----
  本软件采用 GPL-3.0（许可证全文见随包 LICENSE.txt）。
  包含并动态加载 WinDivert 1.3.0 (LGPLv3, 版权 basil00,
  https://github.com/basil00/WinDivert)，其许可证全文见 LICENSES\WinDivert-LGPLv3.txt。

正常运行的标志
--------------
  D:\hotspot-ttl\logs\ 下最新的 ttl_normalize_*.log 里有:
    [SUP] 角色: 主进程 / [SUP] 已拉起同伴进程
  且同时有主日志与 *_standby.log 两份在写。
