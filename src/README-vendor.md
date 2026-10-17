# 第三方文件（vendor）

## windivert.h

- 来源：官方仓库 basil00/WinDivert，tag `v1.3.0`，路径 `include/windivert.h`
- 版本：与运行时 `WinDivert64.dll` / `WinDivert64.sys`（1.3.0，复用 pydivert 捆绑的官方二进制）配套
- 许可：LGPL v3（见文件头）
- 用途：只提供类型/常量/函数原型声明；函数通过 LoadLibrary + GetProcAddress 动态加载

关键词：windivert, vendor, LGPL, 1.3.0
