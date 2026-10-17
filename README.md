# fuck-school-wifi

> 把自己开的热点流量"洗"干净的 Windows 小工具：TTL 归一化 + UA 改写 + 明文 DNS 窗口丢弃。
> 自用为主，公开供学习参考。

校园网 / 运营商会对"一机开热点、多机共用"做各种检测：TTL 逐跳递减、
HTTP User-Agent 里的手机特征、转发链上的明文 DNS 行为、以及各种转发流指纹。
本项目挂在 WinDivert 的 `NETWORK_FORWARD` 层，只处理**被本机转发出去**的包，
把它们整理成"像普通单设备直连"的样子。

## 功能

- **TTL 统一改写**：转发包 TTL 一律归一为目标值（默认 128），回程包按目的网段排除
- **明文 HTTP UA 等长改写**：能改成普通浏览器 UA 的改；带手机特征（`dalvik` / `miui` / `oppo` …）的丢；无 UA 头的放行
- **明文 DNS 窗口丢弃**：刚接入后的一小段窗口内，丢弃转发链上的明文 DNS（DoH / DoT 不受影响）
- **转发流指纹记录**（TSV，可关）：便于自查
- IPv6 不动、本机自发流量不碰，只在转发方向上做事

## 特性

- 单文件 C++（`src/normalizer.cpp`），WinDivert 1.3.0 动态加载（`LoadLibrary`，无 .lib 依赖），`/MT` 静态链接、零运行库依赖
- **双进程互救**：主进程持句柄处理包；副进程只监控。主死 / 卡死（心跳 >5s）→ 副进程约 1 秒接管并立即拉起新同伴，任何时刻保持一主一副
- 自带 53 条纯逻辑自检：`normalizer.exe --selftest`（不碰驱动，可离线跑）
- 自包含安装器：程序 + 驱动 + 计划任务（SYSTEM 身份、开机免登录启动、会话 0 完全无窗口）+ 一键卸载（程序文件进回收站、可还原）

## 目录结构

```
src/
  normalizer.cpp        主程序（全部逻辑，单文件）
  windivert.h           WinDivert 1.3.0 头（vendor，LGPLv3）
  build.ps1             编译脚本（MSVC）
  README-vendor.md      vendor 来源说明
  setup/
    Setup.cs            自包含安装器 / 卸载器（C#，单文件）
    app.manifest        管理员清单
    task-def.xml        计划任务 XML 模板（安装时按当前机器打补丁）
    build-setup.ps1     打包脚本（csc 编译 → 单 exe）
    README-dist.txt     分发包说明
```

## 构建

不想自己编译：直接下载 [Releases](https://github.com/AYwlilwYA/fuck-school-wifi/releases) 里的预编译安装包（内嵌驱动，双击即装）。

需要：Windows 10/11 x64、Visual Studio（MSVC）、管理员 PowerShell。

WinDivert 运行库（`WinDivert64.dll` / `WinDivert64.sys`，1.3.0）从官方 WinDivert 1.3.0
发行包获取（`pip install pydivert` 的包内也捆绑同一份官方二进制，可直接取用）。

```powershell
# 1) 编译主程序（按需修改脚本顶部路径）
pwsh -File src\build.ps1
# 2) 打包安装器（需要系统自带的 .NET Framework 4 csc.exe）
pwsh -File src\setup\build-setup.ps1
```

构建脚本里的路径按作者本机布局写死（源码 / 产物分盘），换机器时改脚本顶部变量即可。

## 使用

必须管理员运行：

```
normalizer.exe --ttl 128          正式运行（双进程互救）
normalizer.exe --dry-run          只统计不改写（单进程）
normalizer.exe --seconds 30       限时运行冒烟测试（单进程）
normalizer.exe --check            环境自检（不开驱动）
normalizer.exe --status           查看运行状态
normalizer.exe --stop             停止
normalizer.exe --selftest         纯逻辑自检（53 条）
```

安装器：

```
hotspot-ttl-setup.exe [/dir <路径>] [/ttl <1..255>] [/no-autostart] [/uninstall]
```

## 已知边界

- 只支持 IPv4；只在 `NETWORK_FORWARD` 层动包
- UA 改写只对明文 HTTP 生效；HTTPS 流量天然看不到 UA（也不处理）
- 目标场景是 Windows ICS 共享 / 移动热点的转发链

## 许可

- 本项目（normalizer、安装器等）采用 **GPL-3.0**，Copyright (C) 2026 AYwlilwYA，全文见 [LICENSE](LICENSE)。
- 本项目包含并以运行时动态加载（`LoadLibrary`）方式使用 [WinDivert](https://github.com/basil00/WinDivert) 1.3.0（`WinDivert64.dll` / `WinDivert64.sys`），版权归 basil00 所有，按 **LGPLv3** 使用，许可证全文见 [LICENSES/WinDivert-LGPLv3.txt](LICENSES/WinDivert-LGPLv3.txt)；DLL 与程序同目录放置，可自行替换为修改后的兼容版本。

## 免责声明

仅供个人学习与技术研究。请遵守当地法律法规以及所在地网络的使用条款；
因使用本工具产生的一切后果由使用者自行承担。

关键词：TTL, hotspot, WinDivert, NETWORK_FORWARD, UA, DNS, Windows
