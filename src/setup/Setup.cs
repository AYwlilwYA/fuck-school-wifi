// hotspot-ttl-setup -- self-contained installer/uninstaller for the TTL normalizer.
// C# 5 compatible (Framework csc). UTF-8 source, compiled with /codepage:65001.
// License: GPL-3.0 (repo root LICENSE); Copyright (C) 2026 AYwlilwYA
// Uses WinDivert 1.3.0 (LGPLv3) at runtime; license text in LICENSES\WinDivert-LGPLv3.txt
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

static class Setup
{
    const string TaskName = "TTL-Normalize";
    const string AppRegKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\hotspot-ttl-normalizer";
    const string DefaultDirD = @"D:\hotspot-ttl";
    const string DefaultDirC = @"C:\hotspot-ttl";

    static string dir;
    static int ttl = 128;
    static bool uninstall = false;
    static bool noAutostart = false;
    static bool phase2 = false;

    static int Main(string[] args)
    {
        try { return MainCore(args); }
        catch (Exception e)
        {
            Console.WriteLine("错误: " + e.GetType().FullName + ": " + e.Message);
            return 1;
        }
    }

    static int MainCore(string[] args)
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        dir = Directory.Exists("D:\\") ? DefaultDirD : DefaultDirC;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i].ToLowerInvariant();
            if (a == "/install") { }
            else if (a == "/uninstall") uninstall = true;
            else if (a == "/dir") { if (i + 1 < args.Length) dir = args[++i]; }
            else if (a == "/ttl") { if (i + 1 < args.Length) int.TryParse(args[++i], out ttl); }
            else if (a == "/no-autostart") noAutostart = true;
            else if (a == "/phase2") phase2 = true;
            else if (a == "/?" || a == "/help" || a == "-h") { Usage(); return 0; }
            else { Console.WriteLine("未知参数: " + a); Usage(); return 2; }
        }
        if (ttl < 1 || ttl > 255) { Console.WriteLine("错误: /ttl 必须在 1..255"); return 2; }
        dir = dir.TrimEnd('\\');

        if (!IsAdmin())
        {
            Console.WriteLine("错误: 需要管理员权限, 请右键以管理员身份运行");
            return 5;
        }

        Console.WriteLine("=== hotspot-ttl normalizer " + (uninstall ? "卸载" : "安装") + " ===");
        Console.WriteLine("目标目录: " + dir);
        Console.WriteLine();
        return uninstall ? DoUninstall() : DoInstall();
    }

    static void Usage()
    {
        Console.WriteLine("用法: hotspot-ttl-setup.exe [选项]");
        Console.WriteLine("  (无参数)         安装 (默认)");
        Console.WriteLine("  /install         安装: 释放文件 + 注册计划任务(开机自启默认开) + 启动");
        Console.WriteLine("  /uninstall       卸载: 停止进程 + 删除任务 + 回收程序文件(日志保留)");
        Console.WriteLine("  /dir <path>      安装目录, 默认 D:\\hotspot-ttl");
        Console.WriteLine("  /ttl <n>         目标 TTL, 默认 128");
        Console.WriteLine("  /no-autostart    不注册开机自启 (默认注册 Boot+登录+休眠恢复 触发器)");
    }

    static bool IsAdmin()
    {
        WindowsPrincipal p = new WindowsPrincipal(WindowsIdentity.GetCurrent());
        return p.IsInRole(WindowsBuiltInRole.Administrator);
    }

    static string CurrentSid()
    {
        return WindowsIdentity.GetCurrent().User.Value;
    }

    // ---------- install ----------

    static int DoInstall()
    {
        string bin = Path.Combine(dir, "bin");
        string exe = Path.Combine(bin, "normalizer.exe");
        Directory.CreateDirectory(bin);
        Directory.CreateDirectory(Path.Combine(dir, "logs"));

        if (File.Exists(exe))
        {
            Console.WriteLine("[1/6] 停止现有实例...");
            Run(exe, "--stop", true, true);
            System.Threading.Thread.Sleep(800);
        }
        Run("sc.exe", "stop WinDivert1.3", true, false);
        System.Threading.Thread.Sleep(500);

        Console.WriteLine("[2/6] 释放文件到 " + bin);
        Extract("normalizer.exe", exe);
        Extract("WinDivert64.dll", Path.Combine(bin, "WinDivert64.dll"));
        Extract("WinDivert64.sys", Path.Combine(bin, "WinDivert64.sys"));

        Console.WriteLine("[3/6] 复制安装器自身 (供卸载/修复)");
        string me = Assembly.GetExecutingAssembly().Location;
        string selfDst = Path.Combine(bin, "setup.exe");
        if (!SamePath(me, selfDst)) File.Copy(me, selfDst, true);
        Console.WriteLine("      " + selfDst);

        Console.WriteLine("[4/6] 注册计划任务 (" + (noAutostart ? "不注册开机自启" : "开机自启: 开") + ")");
        string xml = ReadResourceText("task-def.xml");
        xml = xml.Replace("D:\\hotspot-ttl", dir);
        xml = xml.Replace("PLACEHOLDER-USER", CurrentSid());
        xml = xml.Replace("--ttl 128", "--ttl " + ttl);
        if (noAutostart)
        {
            xml = RemoveBlock(xml, "BootTrigger");
            xml = RemoveBlock(xml, "LogonTrigger");
        }
        string tmpXml = Path.Combine(Path.GetTempPath(), "httl-task-" + Guid.NewGuid().ToString("N") + ".xml");
        File.WriteAllText(tmpXml, xml, Encoding.Unicode);
        int rc = Run("schtasks.exe", "/Create /F /TN \"" + TaskName + "\" /XML \"" + tmpXml + "\"", true, false);
        try { File.Delete(tmpXml); } catch { }
        if (rc != 0) { Console.WriteLine("注册计划任务失败 (exit " + rc + ")"); return rc; }

        Console.WriteLine("[5/6] 写入卸载入口与卸载登记");
        string unLauncher = Path.Combine(dir, "卸载.cmd");
        File.WriteAllText(unLauncher,
            "@echo off\r\n\"%~dp0bin\\setup.exe\" /uninstall\r\npause\r\n", Encoding.Default);
        using (RegistryKey k = Registry.LocalMachine.CreateSubKey(AppRegKey))
        {
            k.SetValue("DisplayName", "hotspot-ttl 归一化器 (TTL Normalizer)");
            k.SetValue("DisplayVersion", "1.0.0");
            k.SetValue("Publisher", "hotspot-ttl");
            k.SetValue("InstallLocation", dir);
            k.SetValue("DisplayIcon", exe);
            k.SetValue("UninstallString", "\"" + selfDst + "\" /uninstall");
            k.SetValue("NoModify", 1, RegistryValueKind.DWord);
            k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
        }

        Console.WriteLine("[6/6] 启动");
        Run("schtasks.exe", "/Run /TN \"" + TaskName + "\"", true, false);
        System.Threading.Thread.Sleep(3000);
        if (File.Exists(exe)) Run(exe, "--status", true, true);

        Console.WriteLine();
        Console.WriteLine("安装完成。开机自动启动: " + (noAutostart ? "关" : "开"));
        Console.WriteLine("卸载: 双击 " + unLauncher + "  或  设置-应用 里卸载  或  " + selfDst + " /uninstall");
        return 0;
    }

    // ---------- uninstall ----------

    static int DoUninstall()
    {
        string bin = Path.Combine(dir, "bin");
        string me = Assembly.GetExecutingAssembly().Location;

        if (!phase2 && IsInside(me, bin))
        {
            string tmp = Path.Combine(Path.GetTempPath(), "httl-uninstall-" + Guid.NewGuid().ToString("N") + ".exe");
            File.Copy(me, tmp, true);
            ProcessStartInfo psi = new ProcessStartInfo(tmp, "/uninstall /phase2 /dir \"" + dir + "\"");
            psi.UseShellExecute = false;
            Process.Start(psi);
            Console.WriteLine("已启动卸载 (临时副本), 本窗口即将退出...");
            return 0;
        }

        if (phase2) System.Threading.Thread.Sleep(1500);

        string exe = Path.Combine(bin, "normalizer.exe");
        if (File.Exists(exe))
        {
            Console.WriteLine("[1/5] 停止实例...");
            Run(exe, "--stop", true, true);
            System.Threading.Thread.Sleep(800);
        }

        Console.WriteLine("[2/5] 删除计划任务");
        Run("schtasks.exe", "/Delete /F /TN \"" + TaskName + "\"", true, false);

        Console.WriteLine("[3/5] 清理 WinDivert 驱动服务");
        Run("sc.exe", "stop WinDivert1.3", true, false);
        Run("sc.exe", "delete WinDivert1.3", true, false);

        Console.WriteLine("[4/5] 移除卸载登记");
        try { Registry.LocalMachine.DeleteSubKeyTree(AppRegKey, false); } catch { }

        Console.WriteLine("[5/5] 回收程序文件 (进回收站)");
        string unLauncher = Path.Combine(dir, "卸载.cmd");
        if (File.Exists(unLauncher)) { if (!Recycle(unLauncher)) { try { File.Delete(unLauncher); } catch { } } }
        if (Directory.Exists(bin))
        {
            if (!Recycle(bin))
            {
                Console.WriteLine("      回收站失败, 改为直接删除");
                try { Directory.Delete(bin, true); } catch (Exception e) { Console.WriteLine("      删除失败: " + e.Message); }
            }
        }

        Console.WriteLine();
        Console.WriteLine("卸载完成。日志与文档保留在 " + dir + " (logs\\ doc\\)");

        if (phase2)
        {
            string self = me;
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe",
                "/c ping -n 3 127.0.0.1 >nul & del \"" + self + "\"");
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            try { Process.Start(psi); } catch { }
        }
        return 0;
    }

    // ---------- helpers ----------

    static void Extract(string res, string dst)
    {
        Assembly asm = Assembly.GetExecutingAssembly();
        Exception last = null;
        for (int attempt = 1; attempt <= 4; attempt++)
        {
            try
            {
                using (Stream s = asm.GetManifestResourceStream(res))
                {
                    if (s == null) throw new Exception("内嵌资源缺失: " + res);
                    byte[] buf = new byte[81920];
                    using (FileStream f = new FileStream(dst, FileMode.Create, FileAccess.Write))
                    {
                        int n;
                        while ((n = s.Read(buf, 0, buf.Length)) > 0) f.Write(buf, 0, n);
                    }
                }
                Console.WriteLine("      " + dst);
                return;
            }
            catch (Exception e)
            {
                last = e;
                System.Threading.Thread.Sleep(500);
            }
        }
        throw new Exception("写入失败 (文件被占用?): " + dst + " -- " + last.Message);
    }

    static string ReadResourceText(string res)
    {
        Assembly asm = Assembly.GetExecutingAssembly();
        using (Stream s = asm.GetManifestResourceStream(res))
        {
            if (s == null) throw new Exception("内嵌资源缺失: " + res);
            using (StreamReader r = new StreamReader(s, Encoding.UTF8, true))
                return r.ReadToEnd();
        }
    }

    static string RemoveBlock(string xml, string tag)
    {
        int a = xml.IndexOf("<" + tag + ">");
        if (a < 0) return xml;
        int b = xml.IndexOf("</" + tag + ">", a);
        if (b < 0) return xml;
        return xml.Remove(a, b - a + tag.Length + 3);
    }

    static bool SamePath(string a, string b)
    {
        return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase);
    }

    static bool IsInside(string file, string folder)
    {
        string f = Path.GetFullPath(folder).TrimEnd('\\').ToLowerInvariant() + "\\";
        string p = Path.GetFullPath(file).ToLowerInvariant();
        return p.StartsWith(f);
    }

    static int Run(string file, string args, bool tolerant, bool childUtf8)
    {
        ProcessStartInfo psi = new ProcessStartInfo(file, args);
        psi.UseShellExecute = false;
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.CreateNoWindow = true;
        if (childUtf8)
        {
            psi.StandardOutputEncoding = Encoding.UTF8;
            psi.StandardErrorEncoding = Encoding.UTF8;
        }
        Process p = Process.Start(psi);
        string o = p.StandardOutput.ReadToEnd();
        string e = p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (!string.IsNullOrEmpty(o)) Console.Write(o);
        if (!string.IsNullOrEmpty(e)) Console.Write(e);
        if (p.ExitCode != 0 && !tolerant)
            Console.WriteLine("      (" + file + " 退出码 " + p.ExitCode + ")");
        return p.ExitCode;
    }

    // ---------- recycle bin ----------

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct SHFILEOPSTRUCT
    {
        public IntPtr hwnd;
        public uint wFunc;
        public string pFrom;
        public string pTo;
        public ushort fFlags;
        public bool fAnyOperationsAborted;
        public IntPtr hNameMappings;
        public string lpszProgressTitle;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    static extern int SHFileOperation(ref SHFILEOPSTRUCT op);

    static bool Recycle(string path)
    {
        SHFILEOPSTRUCT op = new SHFILEOPSTRUCT();
        op.wFunc = 3; // FO_DELETE
        op.pFrom = Path.GetFullPath(path) + "\0\0";
        op.fFlags = (ushort)(0x0004 | 0x0040 | 0x0010); // ALLOWUNDO | NOCONFIRMATION | NOERRORUI
        try { return SHFileOperation(ref op) == 0; }
        catch { return false; }
    }
}
