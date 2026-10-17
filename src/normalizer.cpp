/*
 * normalizer.cpp — ICS 转发包 TTL 归一化器（C++ 版）
 *
 * 功能：
 *   - 挂 WinDivert NETWORK_FORWARD 层（filter "ip"），只处理被本机路由转发的 IPv4 包；
 *   - 转发方向包的 TTL 统一改写为目标值（默认 128）；回程包按目的网段排除；IPv6 不动；
 *   - 明文 HTTP 的 User-Agent 等长改写（能改的改、真有手机特征才丢、没 UA 头放行）；
 *   - "刚连上"窗口内丢弃明文 DNS；转发流指纹记录（TSV）；
 *   - 双进程互救：主进程持 WinDivert handle 处理包，副进程只监控；主死/僵死后副接管
 *     并立即拉起新同伴，任何时刻保持一主一副。
 *
 * 运行方式（必须管理员）：
 *   normalizer.exe --ttl 128            正式运行（双进程互救）
 *   normalizer.exe --dry-run            只统计不改写（单进程）
 *   normalizer.exe --seconds 30         限时运行（单进程，冒烟测试）
 *   normalizer.exe --check              环境自检，不开驱动
 *   normalizer.exe --stop | --status    停止 / 查看运行状态
 *   normalizer.exe --selftest           纯逻辑自检，不碰驱动
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <deque>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <cwchar>
#include <sddl.h>

#include "windivert.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// 命名对象安全属性：授权 SYSTEM 与管理员全权，供跨会话管理
static SECURITY_ATTRIBUTES* sa_all_access() {
    static SECURITY_ATTRIBUTES sa;
    static bool init_done = false;
    if (!init_done) {
        init_done = true;
        PSECURITY_DESCRIPTOR sd = NULL;
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd, NULL);
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = sd;
        sa.bInheritHandle = FALSE;
    }
    return sa.lpSecurityDescriptor ? &sa : NULL;
}

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------
static const char*  FILTER = "ip";
static const int    DEFAULT_TTL = 128;
static const uint8_t DEFAULT_HOTSPOT_PREFIX[3] = { 192, 168, 137 };

static const wchar_t* MUTEX_PRIMARY = L"Global\\hotspot_ttl_normalizer.primary";
static const wchar_t* MUTEX_STANDBY = L"Global\\hotspot_ttl_normalizer.standby";
static const wchar_t* STOP_EVENT    = L"Global\\hotspot_ttl_normalizer.stop";
static const wchar_t* SHARED_NAME   = L"Global\\hotspot_ttl_normalizer.state";

// ---------------------------------------------------------------------------
// 全局状态
// ---------------------------------------------------------------------------
static std::atomic<bool> g_stop(false);
static std::atomic<HANDLE> g_wd{ NULL };       // 当前 WinDivert handle（跨线程关闭用）
static std::atomic<bool>   g_ctrl_c{ false };  // Ctrl+C 已触发（退出日志补记用）
static std::vector<std::wstring> g_argv;       // 原始命令行参数（拉同伴时复用）

struct SharedState {
    volatile uint32_t magic;
    volatile uint32_t primary_pid;
    volatile uint32_t standby_pid;
    volatile uint64_t primary_hb;   // GetTickCount64
    volatile uint64_t standby_hb;
};
static SharedState* g_shared = nullptr;
static std::atomic<bool> g_peer_expected(false);
static volatile uint64_t g_spawnMark = 0;

// ---------------------------------------------------------------------------
// 基础工具
// ---------------------------------------------------------------------------
static std::wstring exe_path() {
    wchar_t buf[4096];
    DWORD n = GetModuleFileNameW(NULL, buf, 4096);
    return std::wstring(buf, n);
}

static std::wstring strip_last_component(const std::wstring& p) {
    size_t s = p.find_last_of(L"\\/");
    return (s == std::wstring::npos) ? p : p.substr(0, s);
}

static bool ieq(const std::wstring& a, const wchar_t* b) {
    if (a.size() != wcslen(b)) return false;
    for (size_t i = 0; i < a.size(); i++) {
        wchar_t x = a[i], y = b[i];
        if (x >= L'A' && x <= L'Z') x += 32;
        if (y >= L'A' && y <= L'Z') y += 32;
        if (x != y) return false;
    }
    return true;
}

static std::wstring exe_dir() { return strip_last_component(exe_path()); }

// 程序目录：exe 在 bin 子目录时向上取一级，保证 logs 落在项目根
static std::wstring base_dir() {
    std::wstring d = exe_dir();
    std::wstring last = d.substr(d.find_last_of(L"\\/") + 1);
    if (ieq(last, L"bin")) return strip_last_component(d);
    return d;
}

static std::string w2u(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

static std::wstring u2w(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static void create_dir_tree(const std::wstring& dir) {
    if (dir.empty()) return;
    if (GetFileAttributesW(dir.c_str()) != INVALID_FILE_ATTRIBUTES) return;
    size_t p = dir.find_last_of(L"\\/");
    if (p != std::wstring::npos && p > 0) create_dir_tree(dir.substr(0, p));
    CreateDirectoryW(dir.c_str(), NULL);
}

static void ensure_parent_dir(const std::string& utf8path) {
    std::wstring w = u2w(utf8path);
    size_t p = w.find_last_of(L"\\/");
    if (p != std::wstring::npos && p > 0) create_dir_tree(w.substr(0, p));
}

static double steady_now() {
    return std::chrono::duration<double>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

static void ts_hms(char* out /*>=9*/) {
    SYSTEMTIME st; GetLocalTime(&st);
    sprintf_s(out, 9, "%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
}

static std::string ts_file() {
    SYSTEMTIME st; GetLocalTime(&st);
    char t[32];
    sprintf_s(t, "%04u%02u%02u_%02u%02u%02u",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return t;
}

static std::string ts_full() {
    SYSTEMTIME st; GetLocalTime(&st);
    char t[32];
    sprintf_s(t, "%04u-%02u-%02u %02u:%02u:%02u",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return t;
}

static bool is_admin() {
    BOOL elevated = FALSE;
    HANDLE tok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION el; DWORD sz = 0;
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &sz))
            elevated = el.TokenIsElevated;
        CloseHandle(tok);
    }
    return elevated != FALSE;
}

static bool proc_alive(uint32_t pid) {
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h) return false;
    bool alive = (WaitForSingleObject(h, 0) != WAIT_OBJECT_0);
    CloseHandle(h);
    return alive;
}

// 独占控制台时隐藏窗口（共享控制台如终端里调试时不动）
static void hide_own_console() {
    HWND w = GetConsoleWindow();
    if (!w) return;
    DWORD pids[2] = { 0 };
    if (GetConsoleProcessList(pids, 2) == 1) ShowWindow(w, SW_HIDE);
}

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------
class Log {
public:
    void open(const std::string& path) {
        path_ = path;
        ensure_parent_dir(path);
        fp_ = _wfopen(u2w(path).c_str(), L"ab");
        DWORD mode = 0;
        HANDLE so = GetStdHandle(STD_OUTPUT_HANDLE);
        echo_ = (so != NULL && so != INVALID_HANDLE_VALUE && GetConsoleMode(so, &mode) != 0);
    }
    bool opened() const { return fp_ != nullptr; }
    const std::string& path() const { return path_; }

    void operator()(const char* fmt, ...) {
        char ts[16]; ts_hms(ts);
        char body[4096];
        va_list ap; va_start(ap, fmt);
        vsnprintf(body, sizeof(body), fmt, ap);
        va_end(ap);
        std::string line = std::string("[") + ts + "] " + body;
        std::lock_guard<std::mutex> lk(mu_);
        if (echo_) { fwrite(line.c_str(), 1, line.size(), stdout); fputc('\n', stdout); fflush(stdout); }
        if (fp_) { fwrite(line.c_str(), 1, line.size(), fp_); fwrite("\r\n", 1, 2, fp_); fflush(fp_); }
    }
    void close() { std::lock_guard<std::mutex> lk(mu_); if (fp_) { fclose(fp_); fp_ = nullptr; } }
    long long n_lines = 0;
private:
    FILE* fp_ = nullptr;
    bool echo_ = true;
    std::string path_;
    std::mutex mu_;
};

// ---------------------------------------------------------------------------
// WinDivert 动态加载
// ---------------------------------------------------------------------------
typedef HANDLE (WINAPI *fn_Open)(const char*, int, INT16, UINT64);
typedef BOOL   (WINAPI *fn_Recv)(HANDLE, PVOID, UINT, PWINDIVERT_ADDRESS, UINT*);
typedef BOOL   (WINAPI *fn_Send)(HANDLE, PVOID, UINT, PWINDIVERT_ADDRESS, UINT*);
typedef BOOL   (WINAPI *fn_Close)(HANDLE);
typedef UINT   (WINAPI *fn_Calc)(PVOID, UINT, UINT64);
typedef BOOL   (WINAPI *fn_Check)(const char*, int, const char**, UINT*);

static HMODULE  g_wdDll = NULL;
static fn_Open  wdOpen = NULL;
static fn_Recv  wdRecv = NULL;
static fn_Send  wdSend = NULL;
static fn_Close wdClose = NULL;
static fn_Calc  wdCalc = NULL;
static fn_Check wdCheck = NULL;

// 原子取出并关闭 handle, 保证多线程只关一次
static void wd_close_once() {
    HANDLE h = g_wd.exchange(NULL);
    if (h) wdClose(h);
}

static bool load_windivert(std::string* err) {
    std::wstring dll = exe_dir() + L"\\WinDivert64.dll";
    g_wdDll = LoadLibraryW(dll.c_str());
    if (!g_wdDll) {
        char t[64]; sprintf_s(t, "错误 %lu", GetLastError());
        *err = std::string("LoadLibrary 失败: ") + t + " (" + w2u(dll) + ")";
        return false;
    }
    wdOpen  = (fn_Open) GetProcAddress(g_wdDll, "WinDivertOpen");
    wdRecv  = (fn_Recv) GetProcAddress(g_wdDll, "WinDivertRecv");
    wdSend  = (fn_Send) GetProcAddress(g_wdDll, "WinDivertSend");
    wdClose = (fn_Close)GetProcAddress(g_wdDll, "WinDivertClose");
    wdCalc  = (fn_Calc) GetProcAddress(g_wdDll, "WinDivertHelperCalcChecksums");
    wdCheck = (fn_Check)GetProcAddress(g_wdDll, "WinDivertHelperCheckFilter");
    if (!wdOpen || !wdRecv || !wdSend || !wdClose || !wdCalc || !wdCheck) {
        *err = "GetProcAddress 失败（DLL 版本不匹配?）";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// IP / TCP 基础
// ---------------------------------------------------------------------------
static uint16_t rd16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }

// 重算 IPv4 头校验和：只扫 ihl 字节，不碰载荷
static void fix_ipv4_cksum(uint8_t* raw, int ihl) {
    raw[10] = 0; raw[11] = 0;
    uint32_t s = 0;
    for (int i = 0; i < ihl; i += 2) s += ((uint32_t)raw[i] << 8) | raw[i + 1];
    while (s > 0xFFFF) s = (s & 0xFFFF) + (s >> 16);
    uint16_t c = (uint16_t)((~s) & 0xFFFF);
    raw[10] = (uint8_t)(c >> 8);
    raw[11] = (uint8_t)(c & 0xFF);
}

// 目的地址是否落在热点网段 —— 是则说明这是回给客户端的包
static bool dst_in_hotspot(const uint8_t* raw, const uint8_t prefix[3]) {
    return raw[16] == prefix[0] && raw[17] == prefix[1] && raw[18] == prefix[2];
}

// 转发方向 TCP 四元组（含源 IP/端口、目的 IP/端口）拼成字节串，作流表键
static std::string flow_key_str(const uint8_t* raw, size_t ihl) {
    std::string k;
    k.append((const char*)raw + 12, 4);
    k.append((const char*)raw + ihl, 2);
    k.append((const char*)raw + 16, 4);
    k.append((const char*)raw + ihl + 2, 2);
    return k;
}

static std::string head_of(const uint8_t* raw, size_t start, size_t n) {
    std::string s;
    for (size_t i = start; i < start + n; i++) {
        uint8_t c = raw[i];
        s += (c >= 32 && c < 127) ? (char)c : '.';
    }
    return s;
}

static std::string ip_dot(const uint8_t* b) {
    char t[16];
    sprintf_s(t, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return t;
}

static std::string hex_dotted(const uint8_t* b, size_t n) {
    std::string s;
    for (size_t i = 0; i < n; i++) {
        char t[4]; sprintf_s(t, "%02x", b[i]);
        if (i) s += ".";
        s += t;
    }
    return s;
}

static std::string hex_nodot(const uint8_t* b, size_t n) {
    std::string s;
    for (size_t i = 0; i < n; i++) {
        char t[4]; sprintf_s(t, "%02x", b[i]);
        s += t;
    }
    return s;
}

// TCP 载荷区间（不含 TCP 头）；非 TCP / 分片非首片 / 头畸形 / 无载荷 → false
static bool tcp_span(const uint8_t* raw, size_t len, size_t ihl, int tot,
                     size_t* p0, size_t* p1) {
    if (len < 20 || raw[9] != 6) return false;
    if ((((raw[6] & 0x1F) << 8) | raw[7]) != 0) return false;
    int seg_end = (tot > 0 && tot <= (int)len) ? tot : (int)len;
    if ((int)ihl + 20 > seg_end) return false;
    int doff = (raw[ihl + 12] >> 4) * 4;
    if (doff < 20) return false;
    int start = (int)ihl + doff;
    if (start >= seg_end) return false;
    *p0 = (size_t)start;
    *p1 = (size_t)seg_end;
    return true;
}

// 是否是明文 DNS（源或目的端口 53）；只看首片
static bool is_dns(const uint8_t* raw, size_t len, size_t ihl) {
    if (raw[9] != 6 && raw[9] != 17) return false;
    if ((((raw[6] & 0x1F) << 8) | raw[7]) != 0) return false;
    if (ihl + 4 > len) return false;
    uint16_t sp = rd16(raw + ihl);
    uint16_t dp = rd16(raw + ihl + 2);
    return sp == 53 || dp == 53;
}

// "刚连上"窗口：静默 >= gap 秒算一次新连接，开窗 win 秒；窗口内不续命
static void epoch_tick(double last_act, double dns_until, double t_act,
                       double gap, double win,
                       double* nla, double* ndu, bool* opened) {
    if (t_act - last_act > gap) {
        *nla = t_act; *ndu = t_act + win; *opened = true;
    } else {
        *nla = t_act; *ndu = dns_until; *opened = false;
    }
}

// ---------------------------------------------------------------------------
// UA 改写（纯函数 + 策略层）
// ---------------------------------------------------------------------------
static const char* CANON_UA =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

static const char* UA_HTTP_METHODS[] = {
    "GET ", "POST", "HEAD", "PUT ", "DELE", "OPTI", "PATC", "CONN", "TRAC"
};

static const std::string UA_KEY = "user-agent:";
static const std::string HEAD_END = "\r\n\r\n";
static const int UA_MIN_LEN = 16;

static const char* PHONE_MARKERS[] = {
    // 移动系统 / 通用标识
    "dalvik", "android", "x11", "mobile", "iphone", "ipad", "ipod", "ios",
    "windows phone", "cfnetwork", "darwin",
    // 安卓 ROM / 厂商品牌
    "build/", "miui", "hyperos", "harmonyos", "openharmony", "arkweb",
    "emui", "magicos", "coloros", "funtouch", "originos",
    "oppo/", "oneplus", "xiaomi", "redmi", "huawei", "honor", "vivo", "iqoo", "realme",
    // WebView / 嵌入内核
    "wv)",
    // 非手机联网设备（电视 / 阅读器）
    "smart-tv", "smarttv", "roku", "appletv", "kindle", "silk/"
};

enum UaAct { UA_PASS, UA_REWRITE, UA_DROP };

static std::string ascii_lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    return r;
}

static bool starts_with(const std::string& s, const char* p) {
    size_t n = strlen(p);
    return s.size() >= n && memcmp(s.data(), p, n) == 0;
}

static bool starts_with_any_method(const std::string& s) {
    for (auto m : UA_HTTP_METHODS) if (starts_with(s, m)) return true;
    return false;
}

static bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

// 载荷里是否含真手机特征（全小写比对）
static bool has_phone_marker(const std::string& p) {
    std::string low = ascii_lower(p);
    for (auto m : PHONE_MARKERS) if (low.find(m) != std::string::npos) return true;
    return false;
}

// 是否"像文本"（>=90% 可打印 ASCII），用于把 TLS/二进制排除在特征扫描外
static bool mostly_printable(const std::string& p) {
    if (p.empty()) return false;
    size_t printable = 0;
    for (unsigned char c : p) {
        if ((c >= 0x20 && c < 0x7F) || c == 0x09 || c == 0x0A || c == 0x0D) printable++;
    }
    return printable * 10 >= p.size() * 9;
}

// 在头部里定位 User-Agent 值；跨段时 *vend = (size_t)-1
static bool ua_line(const std::string& p, size_t* vstart, size_t* vend) {
    size_t end = p.find(HEAD_END);
    std::string head = (end == std::string::npos) ? p : p.substr(0, end);
    size_t k = ascii_lower(head).find(UA_KEY);
    if (k == std::string::npos) return false;
    size_t v = k + UA_KEY.size();
    while (v < p.size() && p[v] == ' ') v++;
    size_t e = p.find("\r\n", v);
    *vstart = v;
    *vend = (e == std::string::npos) ? (size_t)-1 : e;
    return true;
}

static bool safe_already(const std::string& val, const std::vector<std::string>& skip) {
    if (val.empty()) return true;
    for (auto& m : skip) if (contains(val, m)) return true;
    return false;
}

// 等长改写 payload[vstart:vend]；改完与原来一致 → false（幂等）
static bool ua_rewrite_value(const std::string& p, size_t vs, size_t ve,
                             const std::string& canon, std::string* out) {
    std::string oldv = p.substr(vs, ve - vs);
    size_t n = oldv.size();
    std::string nv = (canon.size() >= n) ? canon.substr(0, n)
                                         : canon + std::string(n - canon.size(), ' ');
    if (nv == oldv) return false;
    *out = p.substr(0, vs) + nv + p.substr(ve);
    return true;
}

// 旧接口：只回答"这段能不能改"
static bool rewrite_request(const std::string& p, std::string* out,
                            const std::string& canon = std::string(CANON_UA),
                            const std::vector<std::string>& skip =
                                std::vector<std::string>{ "Windows NT" }) {
    if (p.empty() || p.size() < (size_t)UA_MIN_LEN) return false;
    if (!starts_with_any_method(p)) return false;
    size_t vs, ve;
    if (!ua_line(p, &vs, &ve) || ve == (size_t)-1) return false;
    if (safe_already(p.substr(vs, ve - vs), skip)) return false;
    return ua_rewrite_value(p, vs, ve, canon, out);
}

// 策略入口：能改的改、真有手机特征才丢、没 UA 头放行
static UaAct handle_request(const std::string& p, std::string* out,
                            const std::string& canon = std::string(CANON_UA),
                            const std::vector<std::string>& skip =
                                std::vector<std::string>{ "Windows NT" }) {
    if (p.empty()) return UA_PASS;

    // 响应（server→client）不碰；只有"头已结束且 User-Agent: 在 body 里"才是响应
    if (starts_with(p, "HTTP/")) {
        size_t he = p.find(HEAD_END);
        if (he != std::string::npos && ascii_lower(p).find(UA_KEY, he) != std::string::npos)
            return UA_PASS;
    }

    if (p.size() < 4)
        return has_phone_marker(p) ? UA_DROP : UA_PASS;

    bool starts_req = starts_with_any_method(p);
    bool starts_ua = p.size() >= UA_KEY.size() &&
                     ascii_lower(p.substr(0, UA_KEY.size())) == UA_KEY;
    if (!(starts_req || starts_ua)) {
        // 不是请求首包、也不是 UA 续段：像文本且有手机特征 → 丢
        if (mostly_printable(p) && has_phone_marker(p)) return UA_DROP;
        return UA_PASS;
    }

    if (p.size() < (size_t)UA_MIN_LEN)
        return has_phone_marker(p) ? UA_DROP : UA_PASS;

    size_t vs, ve;
    if (!ua_line(p, &vs, &ve))
        return has_phone_marker(p) ? UA_DROP : UA_PASS;

    if (ve == (size_t)-1)
        return has_phone_marker(p.substr(vs)) ? UA_DROP : UA_PASS;

    if (safe_already(p.substr(vs, ve - vs), skip)) return UA_PASS;

    if (ua_rewrite_value(p, vs, ve, canon, out)) return UA_REWRITE;
    return UA_PASS;
}

// 丢过包的流：整条流后续包一并丢，到期自动解禁
class FlowGuard {
public:
    explicit FlowGuard(double ttl = 60.0) : ttl_(ttl) {}
    void block(const std::string& k, double now) { until_[k] = now + ttl_; }
    bool blocked(const std::string& k, double now) {
        auto it = until_.find(k);
        if (it == until_.end()) return false;
        if (now >= it->second) { until_.erase(it); return false; }
        return true;
    }
    void purge(double now) {
        for (auto it = until_.begin(); it != until_.end();) {
            if (now >= it->second) it = until_.erase(it);
            else ++it;
        }
    }
    size_t size() const { return until_.size(); }
private:
    double ttl_;
    std::unordered_map<std::string, double> until_;
};

// ---------------------------------------------------------------------------
// 转发流指纹记录
// ---------------------------------------------------------------------------
static const char* FP_HTTP_METHODS[] = {
    "GET ", "POST", "HEAD", "PUT ", "DELE", "OPTI", "PATC", "CONN"
};

struct TcpOpts {
    bool has_mss = false; unsigned mss = 0;
    bool has_ws = false;  unsigned ws = 0;
    bool sack_ok = false;
    bool has_ts = false;  unsigned long long tsval = 0;
    std::string hex;
    std::string order;
};

static TcpOpts parse_tcp_opts(const uint8_t* opt, size_t n) {
    TcpOpts o;
    o.hex = hex_nodot(opt, n);
    size_t i = 0;
    bool first = true;
    auto app = [&](const std::string& s) {
        if (!first) o.order += "+";
        first = false;
        o.order += s;
    };
    while (i < n) {
        uint8_t k = opt[i];
        if (k == 0) { app("EOL"); break; }
        if (k == 1) { app("NOP"); i += 1; continue; }
        if (i + 1 >= n) break;
        size_t ln = opt[i + 1];
        if (ln < 2 || i + ln > n) break;
        const uint8_t* body = opt + i + 2;
        size_t blen = ln - 2;
        if (k == 2 && blen >= 2) {
            o.has_mss = true; o.mss = ((unsigned)body[0] << 8) | body[1]; app("MSS");
        } else if (k == 3 && blen >= 1) {
            o.has_ws = true; o.ws = body[0]; app("WS");
        } else if (k == 4) {
            o.sack_ok = true; app("SACKOK");
        } else if (k == 5) {
            app("SACK");
        } else if (k == 8 && blen >= 8) {
            o.has_ts = true;
            o.tsval = 0;
            for (int j = 0; j < 4; j++) o.tsval = (o.tsval << 8) | body[j];
            app("TS");
        } else {
            char t[16]; sprintf_s(t, "opt%u", (unsigned)k); app(t);
        }
        i += ln;
    }
    return o;
}

static std::string dns_name(const uint8_t* p, size_t n) {
    if (n < 13 || (p[2] & 0x80)) return "";
    size_t i = 12;
    std::string out;
    while (i < n) {
        size_t l = p[i];
        if (l == 0 || (l & 0xC0)) break;
        i += 1;
        if (i + l > n) break;
        if (!out.empty()) out += ".";
        for (size_t j = 0; j < l; j++) {
            uint8_t c = p[i + j];
            if (c < 0x80) out += (char)c;
            else out += "\xEF\xBF\xBD";
        }
        i += l;
    }
    return out;
}

// 等价 python str.strip(): 空白集 = 09-0D / 1C-1F / 20 / 85 / A0
static void py_strip(std::string& s) {
    auto is_ws = [](unsigned char c) {
        return c == ' ' || (c >= 0x09 && c <= 0x0D) ||
               (c >= 0x1C && c <= 0x1F) || c == 0x85 || c == 0xA0;
    };
    size_t a = 0, b = s.size();
    while (a < b && is_ws((unsigned char)s[a])) a++;
    while (b > a && is_ws((unsigned char)s[b - 1])) b--;
    s = s.substr(a, b - a);
}

// 明文 HTTP 请求头里的 Host / User-Agent；不是请求 → false
static bool http_hu(const std::string& data, std::string* host, std::string* ua) {
    bool is_req = false;
    for (auto m : FP_HTTP_METHODS) if (starts_with(data, m)) { is_req = true; break; }
    if (!is_req) return false;
    std::string txt = data.substr(0, std::min<size_t>(1800, data.size()));
    size_t he = txt.find(HEAD_END);
    std::string head = (he == std::string::npos) ? txt : txt.substr(0, he);
    // 按行扫描，跳过请求行
    size_t pos = head.find("\r\n");
    if (pos == std::string::npos) return true;
    pos += 2;
    while (pos < head.size()) {
        size_t e = head.find("\r\n", pos);
        std::string line = head.substr(pos, (e == std::string::npos ? head.size() : e) - pos);
        std::string low = ascii_lower(line);
        if (low.rfind("host:", 0) == 0) {
            *host = line.substr(5);
        } else if (low.rfind("user-agent:", 0) == 0) {
            *ua = line.substr(11);
        }
        if (e == std::string::npos) break;
        pos = e + 2;
    }
    // 去首尾空白（等价 python strip）
    py_strip(*host); py_strip(*ua);
    return true;
}

class FpRecorder {
public:
    bool open(const std::string& path) {
        ensure_parent_dir(path);
        fp_ = _wfopen(u2w(path).c_str(), L"wb");
        if (!fp_) return false;
        std::string hdr = "# ttl_normalize 转发包指纹  start=" + ts_full() + "\r\n";
        fwrite(hdr.data(), 1, hdr.size(), fp_);
        const char* cols = "time\tproto\tsrc:port\tdst:port\tttl_in\tipid\tdf\twin\tflags"
                           "\topts\torder\tmss\tws\tsack\ttsval\tlen\textra\r\n";
        fwrite(cols, 1, strlen(cols), fp_);
        fflush(fp_);
        return true;
    }
    void feed(const uint8_t* raw, size_t rawlen, size_t ihl, uint8_t ttl_in) {
        if (!fp_ || ihl > rawlen) return;
        uint8_t proto = raw[9];
        int ip_id = (raw[4] << 8) | raw[5];
        bool df = (raw[6] & 0x40) != 0;
        std::string src = ip_dot(raw + 12);
        std::string dst = ip_dot(raw + 16);
        int tot = (raw[2] << 8) | raw[3];
        size_t pstart = ihl;
        size_t pend = (tot > 0 && tot <= (int)rawlen) ? (size_t)tot : rawlen;
        if (pend < pstart) return;
        size_t plen = pend - pstart;
        char ts[16]; ts_hms(ts);

        if (proto == 6 && plen >= 20) {
            const uint8_t* pl = raw + pstart;
            uint16_t sport = rd16(pl), dport = rd16(pl + 2);
            size_t doff = ((size_t)(pl[12] >> 4)) * 4;
            if (doff < 20 || doff > plen) return;
            uint8_t flags = pl[13];
            uint16_t win = rd16(pl + 14);
            TcpOpts o = parse_tcp_opts(pl + 20, doff - 20);
            std::string fstr;
            { struct { int bit; const char* n; } fb[] = {
                {1,"F"},{2,"S"},{4,"R"},{8,"P"},{16,"A"},{32,"U"},{64,"E"},{128,"C"} };
              for (auto& x : fb) if (flags & x.bit) fstr += x.n; }
            if (fstr.empty()) fstr = "-";
            std::string h, u;
            http_hu(std::string((const char*)pl + doff, plen - doff), &h, &u);
            std::string extra;
            if (!h.empty() || !u.empty())
                extra = "HTTP host=" + (h.empty() ? std::string("-") : h) +
                        " ua=" + (u.empty() ? std::string("-") : u);
            std::string fk = "6|" + std::to_string(sport) + "|" + dst + "|" + std::to_string(dport);
            bool opts_truthy = o.has_mss || o.has_ws || o.sack_ok || o.has_ts;
            if (!(opts_truthy || !extra.empty() || flows_.find(fk) == flows_.end())) return;
            flows_[fk] = true;
            if (opts_truthy) {
                std::string sig = "TCP order=" + o.order +
                    " mss=" + (o.has_mss ? std::to_string(o.mss) : std::string("None")) +
                    " ws=" + (o.has_ws ? std::to_string(o.ws) : std::string("None")) +
                    " sack=" + (o.sack_ok ? std::string("True") : std::string("None")) +
                    " win=" + std::to_string(win) +
                    " ipid=" + (ip_id == 0 ? "id0" : "idnz");
                if (sigs_.emplace(sig, true).second) {
                    char t[64]; sprintf_s(t, "# ★ 新指纹 %s | ", ts);
                    std::string line = std::string(t) + sig + "\r\n";
                    fwrite(line.data(), 1, line.size(), fp_);
                }
            }
            std::string row = std::string(ts) + "\tTCP\t" + src + ":" + std::to_string(sport) +
                "\t" + dst + ":" + std::to_string(dport) +
                "\t" + std::to_string((unsigned)ttl_in) + "\t" + std::to_string(ip_id) +
                "\t" + (df ? "1" : "0") + "\t" + std::to_string(win) + "\t" + fstr +
                "\t" + o.hex + "\t" + o.order +
                "\t" + (o.has_mss ? std::to_string(o.mss) : std::string()) +
                "\t" + (o.has_ws ? std::to_string(o.ws) : std::string()) +
                "\t" + (o.sack_ok ? "1" : "0") +
                "\t" + (o.has_ts ? std::to_string(o.tsval) : std::string()) +
                "\t" + std::to_string((unsigned)tot) + "\t" + extra + "\r\n";
            fwrite(row.data(), 1, row.size(), fp_);
            n_++;
        } else if (proto == 17 && plen >= 8) {
            const uint8_t* pl = raw + pstart;
            uint16_t sport = rd16(pl), dport = rd16(pl + 2);
            std::string q;
            if (sport == 53 || dport == 53) q = dns_name(pl + 8, plen - 8);
            std::string fk = "17|" + std::to_string(sport) + "|" + dst + "|" + std::to_string(dport);
            if (!(!q.empty() || flows_.find(fk) == flows_.end())) return;
            flows_[fk] = true;
            std::string row = std::string(ts) + "\tUDP\t" + src + ":" + std::to_string(sport) +
                "\t" + dst + ":" + std::to_string(dport) +
                "\t" + std::to_string((unsigned)ttl_in) + "\t" + std::to_string(ip_id) +
                "\t" + (df ? "1" : "0") +
                "\t\t\t\t\t\t\t\t" +
                "\t" + std::to_string((unsigned)tot) + "\t" + q + "\r\n";
            fwrite(row.data(), 1, row.size(), fp_);
            n_++;
        }
    }
    void close() { if (fp_) { fflush(fp_); fclose(fp_); fp_ = nullptr; } }
    long long n_ = 0;
    size_t sig_count() const { return sigs_.size(); }
private:
    FILE* fp_ = nullptr;
    std::unordered_map<std::string, bool> flows_;
    std::unordered_map<std::string, bool> sigs_;
};

// ---------------------------------------------------------------------------
// 自检（纯逻辑，不碰驱动）
// ---------------------------------------------------------------------------
static int g_fail = 0;
static const char* g_cur_test = "";

#define T_ASSERT(cond)                                                        \
    do {                                                                      \
        if (!(cond)) {                                                        \
            g_fail++;                                                         \
            printf("  FAIL  %s (line %d): %s\n", g_cur_test, __LINE__, #cond);\
        }                                                                     \
    } while (0)

static const char* T_REAL_DALVIK =
    "Dalvik/2.1.0 (Linux; U; Android 15; DEVICE Build/AP3A.240617.008)";
static const char* T_REAL_X11 =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/60.0.3112.32 Safari/537.36";

static std::string T_REQ(const std::string& ua,
                         const std::string& host = "www.google.cn",
                         const std::string& extra = "",
                         const std::string& line = "GET /generate_204 HTTP/1.1\r\n") {
    return line + "Host: " + host + "\r\n" + "User-Agent: " + ua + "\r\n" + extra +
           "Accept: */*\r\n\r\n";
}

static std::string T_real_req() {
    return std::string("GET /generate_204 HTTP/1.1\r\n") +
           "Host: conn-service-cn-04.allawntech.com\r\n" +
           "User-Agent: " + T_REAL_DALVIK + "\r\n" +
           "Accept: */*\r\n\r\n";
}

static std::string T_ipv4(uint8_t proto, const std::string& payload,
                          int frag = 0, int ihl = 20, int ttl = 64) {
    std::string h(20, '\0');
    h[0] = 0x45;
    int tot = ihl + (int)payload.size();
    h[2] = (char)((tot >> 8) & 0xFF); h[3] = (char)(tot & 0xFF);
    int fr = frag & 0x1FFF;
    h[6] = (char)((fr >> 8) & 0xFF); h[7] = (char)(fr & 0xFF);
    h[8] = (char)ttl;
    h[9] = (char)proto;
    h[12] = (char)(unsigned char)192; h[13] = (char)(unsigned char)168;
    h[14] = (char)(unsigned char)137; h[15] = 22;
    h[16] = 8; h[17] = 8; h[18] = 8; h[19] = 8;
    return h + payload;
}

static std::string T_ports(uint16_t sp, uint16_t dp) {
    std::string s(4, '\0');
    s[0] = (char)(sp >> 8); s[1] = (char)(sp & 0xFF);
    s[2] = (char)(dp >> 8); s[3] = (char)(dp & 0xFF);
    return s;
}

static std::string T_tcp(uint16_t sport, uint16_t dport,
                         const std::string& payload = std::string(),
                         uint8_t flags = 0x18, uint16_t win = 64240,
                         const std::string& opts = std::string()) {
    std::string h(20, '\0');
    h[0] = (char)(sport >> 8); h[1] = (char)(sport & 0xFF);
    h[2] = (char)(dport >> 8); h[3] = (char)(dport & 0xFF);
    int doff = 20 + (int)opts.size();
    h[12] = (char)((doff / 4) << 4);
    h[13] = (char)flags;
    h[14] = (char)(win >> 8); h[15] = (char)(win & 0xFF);
    return h + opts + payload;
}

static std::string T_ua_of(const std::string& payload) {
    std::string low = ascii_lower(payload);
    size_t k = low.find(UA_KEY);
    size_t v = k + UA_KEY.size();
    while (v < payload.size() && payload[v] == ' ') v++;
    size_t e = payload.find("\r\n", v);
    return payload.substr(v, (e == std::string::npos ? payload.size() : e) - v);
}

static std::string T_stream(const std::vector<std::string>& segs, FlowGuard& g,
                            double now = 0.0, const std::string& key = "flow") {
    std::string out;
    for (auto& s : segs) {
        if (g.blocked(key, now)) continue;
        std::string np;
        UaAct act = handle_request(s, &np);
        if (act == UA_REWRITE) out += np;
        else if (act == UA_PASS) out += s;
        else g.block(key, now);
    }
    return out;
}

static std::string T_replace_first(const std::string& s, const std::string& what,
                                   const std::string& repl) {
    size_t p = s.find(what);
    if (p == std::string::npos) return s;
    return s.substr(0, p) + repl + s.substr(p + what.size());
}

// ---- ttl_normalize 部分 ----
static void t_udp_query_to_53_is_dns() {
    std::string p = T_ipv4(17, T_ports(53611, 53) + std::string("\x12\x34\x01\x00\x00\x01", 6) +
                               std::string(8, '\0'));
    T_ASSERT(is_dns((const uint8_t*)p.data(), p.size(), 20) == true);
}
static void t_udp_from_53_is_dns_too() {
    std::string p = T_ipv4(17, T_ports(53, 53611) + std::string(12, '\0'));
    T_ASSERT(is_dns((const uint8_t*)p.data(), p.size(), 20) == true);
}
static void t_tcp_53_is_dns() {
    std::string p = T_ipv4(6, T_ports(41000, 53) + std::string(20, '\0'));
    T_ASSERT(is_dns((const uint8_t*)p.data(), p.size(), 20) == true);
}
static void t_udp_other_ports_not_dns() {
    uint16_t dps[] = { 443, 853, 123, 5353, 53533 };
    for (auto dp : dps) {
        std::string p = T_ipv4(17, T_ports(40000, dp) + std::string(8, '\0'));
        T_ASSERT(is_dns((const uint8_t*)p.data(), p.size(), 20) == false);
    }
}
static void t_non_fragment_first_is_skipped() {
    std::string p = T_ipv4(17, T_ports(40000, 53) + std::string(8, '\0'), 0x0100);
    T_ASSERT(is_dns((const uint8_t*)p.data(), p.size(), 20) == false);
}
static void t_icmp_is_not_dns() {
    std::string p = T_ipv4(1, T_ports(0, 53) + std::string(8, '\0'));
    T_ASSERT(is_dns((const uint8_t*)p.data(), p.size(), 20) == false);
}
static void t_truncated_payload_is_safe() {
    std::string p = T_ipv4(17, std::string("\x00\x35", 2));
    T_ASSERT(is_dns((const uint8_t*)p.data(), p.size(), 20) == false);
}
static void t_epoch_first_packet_opens_window() {
    double nla, ndu; bool opened;
    epoch_tick(0.0, 0.0, 1000.0, 60.0, 45.0, &nla, &ndu, &opened);
    T_ASSERT(opened == true);
    T_ASSERT(nla == 1000.0 && ndu == 1045.0);
}
static void t_epoch_silence_opens_new_window() {
    double nla, ndu; bool opened;
    epoch_tick(1000.0, 1010.0, 1100.0, 60.0, 45.0, &nla, &ndu, &opened);
    T_ASSERT(opened == true);
    T_ASSERT(ndu == 1145.0);
}
static void t_epoch_busy_traffic_does_not_extend_window() {
    double nla, ndu; bool opened;
    epoch_tick(1000.0, 1045.0, 1044.0, 60.0, 45.0, &nla, &ndu, &opened);
    T_ASSERT(opened == false);
    T_ASSERT(ndu == 1045.0);
    T_ASSERT(nla == 1044.0);
}
static void t_epoch_boundary_exactly_gap() {
    double nla, ndu; bool opened;
    epoch_tick(1000.0, 0.0, 1060.0, 60.0, 45.0, &nla, &ndu, &opened);
    T_ASSERT(opened == false);
}
static void t_span_returns_payload_without_tcp_header() {
    std::string req = T_real_req();
    std::string pkt = T_ipv4(6, T_tcp(46988, 80, req));
    size_t p0, p1;
    bool ok = tcp_span((const uint8_t*)pkt.data(), pkt.size(), 20, (int)pkt.size(), &p0, &p1);
    T_ASSERT(ok);
    if (ok) T_ASSERT(pkt.substr(p0, p1 - p0) == req);
}
static void t_span_handles_tcp_options() {
    std::string req = T_real_req();
    std::string opts = std::string("\x01\x01\x08\x0a", 4) + std::string(8, '\0');
    std::string pkt = T_ipv4(6, T_tcp(46988, 80, req, 0x18, 64240, opts));
    size_t p0, p1;
    bool ok = tcp_span((const uint8_t*)pkt.data(), pkt.size(), 20, (int)pkt.size(), &p0, &p1);
    T_ASSERT(ok);
    if (ok) T_ASSERT(pkt.substr(p0, p1 - p0) == req);
}
static void t_span_none_when_no_payload() {
    std::string pkt = T_ipv4(6, T_tcp(46988, 80, std::string(), 0x10));
    size_t p0, p1;
    T_ASSERT(tcp_span((const uint8_t*)pkt.data(), pkt.size(), 20, (int)pkt.size(), &p0, &p1) == false);
}
static void t_span_none_for_non_tcp_and_fragments() {
    std::string u = T_ipv4(17, T_ports(1, 2) + std::string(8, 'x'));
    size_t p0, p1;
    T_ASSERT(tcp_span((const uint8_t*)u.data(), u.size(), 20, 40, &p0, &p1) == false);
    std::string f = T_ipv4(6, T_tcp(46988, 80, T_real_req()), 0x0100);
    T_ASSERT(tcp_span((const uint8_t*)f.data(), f.size(), 20, (int)f.size(), &p0, &p1) == false);
}
static void t_span_none_for_truncated_and_bogus_doff() {
    std::string t1 = T_ipv4(6, std::string("\x00", 1));
    size_t p0, p1;
    T_ASSERT(tcp_span((const uint8_t*)t1.data(), t1.size(), 20, 21, &p0, &p1) == false);
    std::string bad = T_ipv4(6, T_tcp(46988, 80, T_real_req()));
    bad[20 + 12] = 0x10;
    T_ASSERT(tcp_span((const uint8_t*)bad.data(), bad.size(), 20, (int)bad.size(), &p0, &p1) == false);
}
static void t_wrong_slice_is_exactly_why_it_never_fired() {
    std::string pkt = T_ipv4(6, T_tcp(46988, 80, T_real_req()));
    std::string wrong = pkt.substr(20);
    T_ASSERT(wrong.size() >= 4);
    T_ASSERT((uint8_t)wrong[0] == 0xB7 && (uint8_t)wrong[1] == 0x8C &&
             (uint8_t)wrong[2] == 0x00 && (uint8_t)wrong[3] == 0x50);
    std::string np;
    T_ASSERT(handle_request(wrong, &np) != UA_REWRITE);
}
static void t_full_packet_rewrite_end_to_end() {
    std::string pkt = T_ipv4(6, T_tcp(46988, 80, T_real_req()), 0, 20, 63);
    size_t before_len = pkt.size();
    int tot = (pkt[2] << 8) | pkt[3];
    size_t p0, p1;
    T_ASSERT(tcp_span((const uint8_t*)pkt.data(), pkt.size(), 20, tot, &p0, &p1));
    std::string payload = pkt.substr(p0, p1 - p0);
    std::string np;
    UaAct act = handle_request(payload, &np);
    T_ASSERT(act == UA_REWRITE);
    if (act == UA_REWRITE && np.size() == payload.size())
        memcpy(&pkt[p0], np.data(), np.size());
    T_ASSERT(pkt.find("Dalvik") == std::string::npos);
    T_ASSERT(pkt.find("Android") == std::string::npos);
    T_ASSERT(pkt.find("Linux") == std::string::npos);
    T_ASSERT(pkt.size() == before_len);
    T_ASSERT(pkt.substr(20, 20) == T_tcp(46988, 80).substr(0, 20));
    T_ASSERT(pkt.find("User-Agent: Mozilla/5.0 (Windows NT") != std::string::npos);
}
static void t_full_packet_drops_unrewritable() {
    std::string split = T_real_req().substr(0, 90);
    T_ASSERT(split.find("Dalvik") != std::string::npos);
    std::string pkt = T_ipv4(6, T_tcp(46988, 80, split));
    int tot = (pkt[2] << 8) | pkt[3];
    size_t p0, p1;
    T_ASSERT(tcp_span((const uint8_t*)pkt.data(), pkt.size(), 20, tot, &p0, &p1));
    std::string np;
    T_ASSERT(handle_request(pkt.substr(p0, p1 - p0), &np) == UA_DROP);
}
static void t_full_packet_passes_unrewritable_without_marker() {
    std::string split = T_real_req().substr(0, 60);
    T_ASSERT(split.find("Dalvik") == std::string::npos);
    T_ASSERT(split.find("Android") == std::string::npos);
    std::string pkt = T_ipv4(6, T_tcp(46988, 80, split));
    int tot = (pkt[2] << 8) | pkt[3];
    size_t p0, p1;
    T_ASSERT(tcp_span((const uint8_t*)pkt.data(), pkt.size(), 20, tot, &p0, &p1));
    std::string np;
    T_ASSERT(handle_request(pkt.substr(p0, p1 - p0), &np) == UA_PASS);
}

// ---- ua_rewrite 部分 ----
static void t_real_dalvik_gets_rewritten() {
    std::string p = T_REQ(T_REAL_DALVIK, "conn-service-cn-05.allawntech.com");
    std::string out;
    T_ASSERT(rewrite_request(p, &out));
    if (out.empty()) return;
    T_ASSERT(out.size() == p.size());
    std::string nw = T_ua_of(out);
    T_ASSERT(nw.find("Dalvik") == std::string::npos && nw.find("Android") == std::string::npos);
    T_ASSERT(starts_with(nw, "Mozilla/5.0 (Windows NT"));
    T_ASSERT(T_replace_first(out, nw, "") == T_replace_first(p, T_REAL_DALVIK, ""));
}
static void t_real_x11_chrome_gets_rewritten() {
    std::string p = T_REQ(T_REAL_X11);
    std::string out;
    T_ASSERT(rewrite_request(p, &out));
    if (out.empty()) return;
    T_ASSERT(out.size() == p.size());
    std::string nw = T_ua_of(out);
    T_ASSERT(nw.find("X11") == std::string::npos && nw.find("Linux") == std::string::npos);
    T_ASSERT(starts_with(nw, "Mozilla/5.0 (Windows NT"));
}
static void t_length_always_preserved_across_widths() {
    for (int n = 1; n < 200; n++) {
        std::string ua(n, 'A');
        std::string p = T_REQ(ua);
        std::string out;
        T_ASSERT(rewrite_request(p, &out));
        if (out.empty()) return;
        T_ASSERT(out.size() == p.size());
        T_ASSERT(T_ua_of(out).size() == (size_t)n);
    }
}
static void t_idempotent() {
    std::string out1;
    T_ASSERT(rewrite_request(T_REQ(T_REAL_DALVIK), &out1));
    std::string out2;
    T_ASSERT(rewrite_request(out1, &out2) == false);
}
static void t_already_windows_is_left_alone() {
    std::string out;
    T_ASSERT(rewrite_request(T_REQ(CANON_UA), &out) == false);
}
static void t_tls_clienthello_untouched() {
    std::string ch = std::string("\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03", 12) +
                     std::string(32, '\0') + std::string("\x20", 1) + std::string(32, '\0') +
                     std::string("\x00\x1e\x13\x01\x13\x02\x13\x03", 8);
    std::string out;
    T_ASSERT(rewrite_request(ch, &out) == false);
    std::string np;
    T_ASSERT(handle_request(ch, &np) == UA_PASS);
}
static void t_non_request_payload_untouched() {
    std::string body = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nUser-Agent: Dalvik/2.1.0\r\n";
    std::string out;
    T_ASSERT(rewrite_request(body, &out) == false);
}
static void t_no_ua_header_untouched() {
    std::string p = "GET /x HTTP/1.1\r\nHost: a.b\r\nAccept: */*\r\n\r\n";
    std::string out;
    T_ASSERT(rewrite_request(p, &out) == false);
}
static void t_split_header_untouched() {
    std::string p = "GET /x HTTP/1.1\r\nHost: a.b\r\nUser-Agent: Dalvik/2.1.0 (Linux; U; Andro";
    std::string out;
    T_ASSERT(rewrite_request(p, &out) == false);
}
static void t_tiny_and_empty() {
    const char* ps[] = { "", "GET", "GET /" };
    for (auto s : ps) { std::string out; T_ASSERT(rewrite_request(s, &out) == false); }
    std::string z(8, '\0');
    std::string out;
    T_ASSERT(rewrite_request(z, &out) == false);
}
static void t_other_methods() {
    const char* ms[] = { "POST", "HEAD", "PUT ", "OPTI", "DELE" };
    for (auto m : ms) {
        std::string p = T_REQ(T_REAL_DALVIK, "www.google.cn", "",
                              std::string(m) + " /x HTTP/1.1\r\n");
        std::string out;
        T_ASSERT(rewrite_request(p, &out));
    }
}
static void t_custom_canon_and_skip() {
    std::string p = T_REQ(T_REAL_DALVIK);
    std::string out;
    T_ASSERT(rewrite_request(p, &out, "X", {}));
    if (out.empty()) return;
    T_ASSERT(out.size() == p.size());
    std::string expect = std::string("X") + std::string(strlen(T_REAL_DALVIK) - 1, ' ');
    T_ASSERT(T_ua_of(out) == expect);
    std::string out2;
    T_ASSERT(rewrite_request(p, &out2, std::string(CANON_UA),
                             std::vector<std::string>{ "Dalvik" }) == false);
}
static void t_handle_rewrites_real_dalvik() {
    std::string p = T_REQ(T_REAL_DALVIK, "conn-service-cn-05.allawntech.com");
    std::string np;
    UaAct act = handle_request(p, &np);
    T_ASSERT(act == UA_REWRITE);
    if (act != UA_REWRITE) return;
    T_ASSERT(np.size() == p.size());
    const char* ms[] = { "Dalvik", "Android", "X11", "Linux" };
    for (auto m : ms) T_ASSERT(np.find(m) == std::string::npos);
}
static void t_handle_rewrites_real_x11() {
    std::string p = T_REQ(T_REAL_X11);
    std::string np;
    UaAct act = handle_request(p, &np);
    T_ASSERT(act == UA_REWRITE && np.size() == p.size());
    const char* ms[] = { "Dalvik", "Android", "X11", "Linux" };
    for (auto m : ms) T_ASSERT(np.find(m) == std::string::npos);
}
static void t_handle_drops_split_ua_value() {
    std::string p = "GET /x HTTP/1.1\r\nHost: a.b\r\nUser-Agent: Dalvik/2.1.0 (Linux; U; Andro";
    std::string np;
    T_ASSERT(handle_request(p, &np) == UA_DROP);
}
static void t_handle_passes_head_that_ends_before_ua() {
    std::string p = "GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n";
    std::string np;
    T_ASSERT(handle_request(p, &np) == UA_PASS);
}
static void t_handle_passes_complete_head_without_ua() {
    std::string p = "GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n\r\n";
    std::string np;
    T_ASSERT(handle_request(p, &np) == UA_PASS);
}
static void t_handle_drops_complete_head_without_ua_but_with_marker() {
    std::string p = "GET /x HTTP/1.1\r\nHost: a.b\r\nX-Android: 1\r\n\r\nDalvik/2.1.0 (Linux; U; Android 15)";
    std::string np;
    T_ASSERT(handle_request(p, &np) == UA_DROP);
}
static void t_handle_rewrites_ua_continuation_segment() {
    std::string p = std::string("User-Agent: ") + T_REAL_DALVIK + "\r\nAccept: */*\r\n\r\n";
    std::string np;
    UaAct act = handle_request(p, &np);
    T_ASSERT(act == UA_REWRITE);
    if (act != UA_REWRITE) return;
    T_ASSERT(np.size() == p.size());
    const char* ms[] = { "Dalvik", "Android", "X11", "Linux" };
    for (auto m : ms) T_ASSERT(np.find(m) == std::string::npos);
}
static void t_handle_drops_ua_continuation_without_crlf() {
    std::string p = "User-Agent: Dalvik/2.1.0 (Linux; U; Andro";
    std::string np;
    T_ASSERT(handle_request(p, &np) == UA_DROP);
}
static void t_handle_passes_ambiguous_short_stubs() {
    const char* ps[] = { "G", "GE", "GET", "P", "PO", "CON", "TRA" };
    for (auto s : ps) {
        std::string np;
        T_ASSERT(handle_request(s, &np) == UA_PASS);
    }
}
static void t_handle_drops_short_stub_with_marker() {
    std::string np;
    T_ASSERT(handle_request("X11", &np) == UA_DROP);
    T_ASSERT(handle_request("ios", &np) == UA_DROP);
    T_ASSERT(handle_request("Dal", &np) == UA_PASS);
}
static void t_handle_extended_marker_coverage() {
    std::string np;
    T_ASSERT(handle_request("harmonyos", &np) == UA_DROP);
    T_ASSERT(handle_request("cfnetwork", &np) == UA_DROP);
    T_ASSERT(handle_request("smarttv", &np) == UA_DROP);
    T_ASSERT(handle_request("OriginOS", &np) == UA_DROP);
    std::string harmony = "Mozilla/5.0 (Phone; OpenHarmony 5.0) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 ArkWeb/4.1.6.1 Mobile";
    T_ASSERT(handle_request(harmony, &np) == UA_DROP);
    std::string cfnet = "MyApp/2.3.1 CFNetwork/1410.0.3 Darwin/22.6.0";
    T_ASSERT(handle_request(cfnet, &np) == UA_DROP);
    std::string desktop = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    T_ASSERT(handle_request(desktop, &np) == UA_PASS);
}
static void t_handle_passes_non_http() {
    std::string a;
    T_ASSERT(handle_request("", &a) == UA_PASS);
    std::string b = std::string("\x16\x03\x01\x02\x00", 5);
    T_ASSERT(handle_request(b, &a) == UA_PASS);
    std::string c(8, '\0');
    T_ASSERT(handle_request(c, &a) == UA_PASS);
    std::string d = std::string("\x17\x03\x03", 3) + std::string(40, '\xff');
    T_ASSERT(handle_request(d, &a) == UA_PASS);
}
static void t_handle_passes_response_payload() {
    std::string body = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nUser-Agent: Dalvik/2.1.0\r\n";
    std::string np;
    T_ASSERT(handle_request(body, &np) == UA_PASS);
}
static void t_handle_passes_already_windows() {
    std::string np;
    T_ASSERT(handle_request(T_REQ(CANON_UA), &np) == UA_PASS);
}
static void t_handle_passes_idempotent() {
    std::string np;
    T_ASSERT(handle_request(T_REQ(T_REAL_DALVIK), &np) == UA_REWRITE);
    std::string np2;
    T_ASSERT(handle_request(np, &np2) == UA_PASS);
}
static void t_never_leaks_under_any_split() {
    std::string base = T_REQ(T_REAL_DALVIK, "conn-service-cn-05.allawntech.com");
    const char* ms[] = { "Dalvik", "Android", "X11", "Linux" };
    for (size_t k = 0; k <= base.size(); k++) {
        FlowGuard g;
        std::string out = T_stream({ base.substr(0, k), base.substr(k) }, g);
        for (auto m : ms) T_ASSERT(out.find(m) == std::string::npos);
    }
}
static void t_never_leaks_under_three_way_split() {
    std::string base = T_REQ(T_REAL_X11, "www.googleapis.cn");
    size_t n = base.size();
    const char* ms[] = { "Dalvik", "Android", "X11", "Linux" };
    for (size_t a = 0; a < n; a += 3) {
        for (size_t b = a; b < n; b += 3) {
            FlowGuard g;
            std::string out = T_stream({ base.substr(0, a), base.substr(a, b - a), base.substr(b) }, g);
            for (auto m : ms) T_ASSERT(out.find(m) == std::string::npos);
        }
    }
}
static void t_flow_guard_blocks_then_expires() {
    FlowGuard g(10.0);
    T_ASSERT(!g.blocked("k", 0.0));
    g.block("k", 0.0);
    T_ASSERT(g.blocked("k", 9.9));
    T_ASSERT(g.size() == 1);
    T_ASSERT(!g.blocked("k", 10.0));
    T_ASSERT(g.size() == 0);
    g.block("k1", 0.0);
    g.block("k2", 0.0);
    g.purge(5.0);
    T_ASSERT(g.size() == 2);
    g.purge(10.0);
    T_ASSERT(g.size() == 0);
}
static void t_ipv4_cksum_header_sum_valid() {
    std::string h(20, '\0');
    h[0] = 0x45; h[2] = 0; h[3] = 20; h[8] = 64; h[9] = 6;
    h[12] = (char)(unsigned char)192; h[13] = (char)(unsigned char)168; h[14] = 1; h[15] = 2;
    h[16] = 8; h[17] = 8; h[18] = 8; h[19] = 8;
    fix_ipv4_cksum((uint8_t*)&h[0], 20);
    uint32_t s = 0;
    for (int i = 0; i < 20; i += 2) s += ((uint32_t)(uint8_t)h[i] << 8) | (uint8_t)h[i + 1];
    while (s > 0xFFFF) s = (s & 0xFFFF) + (s >> 16);
    T_ASSERT(s == 0xFFFF);
}
static void t_dst_in_hotspot() {
    std::string p1 = T_ipv4(6, std::string());
    T_ASSERT(dst_in_hotspot((const uint8_t*)p1.data(), DEFAULT_HOTSPOT_PREFIX) == false);
    std::string p2 = p1;
    p2[16] = (char)(unsigned char)192; p2[17] = (char)(unsigned char)168;
    p2[18] = (char)(unsigned char)137; p2[19] = 9;
    T_ASSERT(dst_in_hotspot((const uint8_t*)p2.data(), DEFAULT_HOTSPOT_PREFIX) == true);
}
static void t_hex_dotted_format() {
    uint8_t b[4] = { 0xC0, 0xA8, 0x89, 0x16 };
    T_ASSERT(hex_dotted(b, 4) == "c0.a8.89.16");
    T_ASSERT(hex_nodot(b, 2) == "c0a8");
}

static int run_selftest() {
    struct T { const char* name; void (*fn)(); };
    static const T tests[] = {
        {"test_udp_query_to_53_is_dns", t_udp_query_to_53_is_dns},
        {"test_udp_from_53_is_dns_too", t_udp_from_53_is_dns_too},
        {"test_tcp_53_is_dns", t_tcp_53_is_dns},
        {"test_udp_other_ports_not_dns", t_udp_other_ports_not_dns},
        {"test_non_fragment_first_is_skipped", t_non_fragment_first_is_skipped},
        {"test_icmp_is_not_dns", t_icmp_is_not_dns},
        {"test_truncated_payload_is_safe", t_truncated_payload_is_safe},
        {"test_epoch_first_packet_opens_window", t_epoch_first_packet_opens_window},
        {"test_epoch_silence_opens_new_window", t_epoch_silence_opens_new_window},
        {"test_epoch_busy_traffic_does_not_extend_window", t_epoch_busy_traffic_does_not_extend_window},
        {"test_epoch_boundary_exactly_gap", t_epoch_boundary_exactly_gap},
        {"test_span_returns_payload_without_tcp_header", t_span_returns_payload_without_tcp_header},
        {"test_span_handles_tcp_options", t_span_handles_tcp_options},
        {"test_span_none_when_no_payload", t_span_none_when_no_payload},
        {"test_span_none_for_non_tcp_and_fragments", t_span_none_for_non_tcp_and_fragments},
        {"test_span_none_for_truncated_and_bogus_doff", t_span_none_for_truncated_and_bogus_doff},
        {"test_wrong_slice_is_exactly_why_it_never_fired", t_wrong_slice_is_exactly_why_it_never_fired},
        {"test_full_packet_rewrite_end_to_end", t_full_packet_rewrite_end_to_end},
        {"test_full_packet_drops_unrewritable", t_full_packet_drops_unrewritable},
        {"test_full_packet_passes_unrewritable_without_marker", t_full_packet_passes_unrewritable_without_marker},
        {"test_real_dalvik_gets_rewritten", t_real_dalvik_gets_rewritten},
        {"test_real_x11_chrome_gets_rewritten", t_real_x11_chrome_gets_rewritten},
        {"test_length_always_preserved_across_widths", t_length_always_preserved_across_widths},
        {"test_idempotent", t_idempotent},
        {"test_already_windows_is_left_alone", t_already_windows_is_left_alone},
        {"test_tls_clienthello_untouched", t_tls_clienthello_untouched},
        {"test_non_request_payload_untouched", t_non_request_payload_untouched},
        {"test_no_ua_header_untouched", t_no_ua_header_untouched},
        {"test_split_header_untouched", t_split_header_untouched},
        {"test_tiny_and_empty", t_tiny_and_empty},
        {"test_other_methods", t_other_methods},
        {"test_custom_canon_and_skip", t_custom_canon_and_skip},
        {"test_handle_rewrites_real_dalvik", t_handle_rewrites_real_dalvik},
        {"test_handle_rewrites_real_x11", t_handle_rewrites_real_x11},
        {"test_handle_drops_split_ua_value", t_handle_drops_split_ua_value},
        {"test_handle_passes_head_that_ends_before_ua", t_handle_passes_head_that_ends_before_ua},
        {"test_handle_passes_complete_head_without_ua", t_handle_passes_complete_head_without_ua},
        {"test_handle_drops_complete_head_without_ua_but_with_marker", t_handle_drops_complete_head_without_ua_but_with_marker},
        {"test_handle_rewrites_ua_continuation_segment", t_handle_rewrites_ua_continuation_segment},
        {"test_handle_drops_ua_continuation_without_crlf", t_handle_drops_ua_continuation_without_crlf},
        {"test_handle_passes_ambiguous_short_stubs", t_handle_passes_ambiguous_short_stubs},
        {"test_handle_drops_short_stub_with_marker", t_handle_drops_short_stub_with_marker},
        {"test_handle_extended_marker_coverage", t_handle_extended_marker_coverage},
        {"test_handle_passes_non_http", t_handle_passes_non_http},
        {"test_handle_passes_response_payload", t_handle_passes_response_payload},
        {"test_handle_passes_already_windows", t_handle_passes_already_windows},
        {"test_handle_passes_idempotent", t_handle_passes_idempotent},
        {"test_never_leaks_under_any_split", t_never_leaks_under_any_split},
        {"test_never_leaks_under_three_way_split", t_never_leaks_under_three_way_split},
        {"test_flow_guard_blocks_then_expires", t_flow_guard_blocks_then_expires},
        {"test_ipv4_cksum_header_sum_valid", t_ipv4_cksum_header_sum_valid},
        {"test_dst_in_hotspot", t_dst_in_hotspot},
        {"test_hex_dotted_format", t_hex_dotted_format},
    };
    int ntests = (int)(sizeof(tests) / sizeof(tests[0]));
    int bad = 0;
    for (auto& t : tests) {
        g_cur_test = t.name;
        int before = g_fail;
        t.fn();
        if (g_fail == before) printf("  OK    %s\n", t.name);
        else bad++;
    }
    printf("\n%d/%d 通过\n", ntests - bad, ntests);
    return bad ? 1 : 0;
}

// ---------------------------------------------------------------------------
// 配置与主副双进程互救
// ---------------------------------------------------------------------------
struct Config {
    int ttl = DEFAULT_TTL;
    bool no_ua = false, no_dns = false, dry_run = false;
    double dns_gap = 60.0, dns_win = 45.0;
    int stats = 10;
    int seconds = 0;
    std::string log_path;
    bool no_log = false;
    bool no_fp = false;
    std::string fp_path;
    bool mode_check = false, mode_stop = false, mode_status = false,
         mode_selftest = false, mode_help = false;
};

static uint64_t now_ms() { return GetTickCount64(); }

static std::string hist_repr(const std::map<std::string, long long>& h) {
    std::string s = "{";
    bool first = true;
    for (auto& kv : h) {
        if (!first) s += ", ";
        first = false;
        s += "'" + kv.first + "': " + std::to_string(kv.second);
    }
    s += "}";
    return s;
}

static std::wstring quote_arg(const std::wstring& a) {
    if (!a.empty() && a.find_first_of(L" \t\"") == std::wstring::npos) return a;
    std::wstring out = L"\"";
    size_t bs = 0;
    for (wchar_t c : a) {
        if (c == L'\\') { bs++; out += c; }
        else if (c == L'"') { out.append(bs, L'\\'); out += L'\\'; out += L'"'; bs = 0; }
        else { bs = 0; out += c; }
    }
    out.append(bs, L'\\');
    out += L'"';
    return out;
}

static bool start_peer(Log& log) {
    if (g_stop) return false;
    if (g_argv.empty()) return false;
    std::wstring exe = exe_path();
    std::wstring cmd = L"\"" + exe + L"\"";
    for (size_t i = 1; i < g_argv.size(); i++) cmd += L" " + quote_arg(g_argv[i]);
    g_shared->standby_pid = 0;
    g_shared->standby_hb = 0;
    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));
    std::wstring cwd = exe_dir();
    const DWORD base_flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    BOOL ok = CreateProcessW(exe.c_str(), &cmd[0], NULL, NULL, FALSE,
                             base_flags | CREATE_BREAKAWAY_FROM_JOB,
                             NULL, cwd.c_str(), &si, &pi);
    DWORD err = GetLastError();
    if (!ok && err == ERROR_ACCESS_DENIED) {
        ok = CreateProcessW(exe.c_str(), &cmd[0], NULL, NULL, FALSE,
                            base_flags, NULL, cwd.c_str(), &si, &pi);
        err = GetLastError();
    }
    if (!ok) {
        log("[SUP] 拉起同伴失败 (错误 %lu)", err);
        return false;
    }
    log("[SUP] 已拉起同伴进程 (PID %lu)", pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    g_spawnMark = now_ms();
    return true;
}

static void respawn_peer(Log& log) {
    static std::deque<uint64_t> spawn_ms;
    static uint64_t backoff_until = 0;
    uint64_t now = now_ms();
    while (!spawn_ms.empty() && now - spawn_ms.front() > 60000) spawn_ms.pop_front();
    if (now < backoff_until) return;
    if (spawn_ms.size() >= 5) {
        backoff_until = now + 30000;
        log("[SUP] 副进程短时间内反复退出, 退避 30 秒");
        return;
    }
    spawn_ms.push_back(now);
    start_peer(log);
}

static void primary_watchdog(Log* log, HANDLE stop_ev) {
    uint64_t last_check = 0;
    for (;;) {
        if (g_stop) break;
        g_shared->primary_hb = now_ms();
        g_shared->primary_pid = GetCurrentProcessId();
        if (stop_ev && WaitForSingleObject(stop_ev, 0) == WAIT_OBJECT_0) {
            (*log)("收到停止事件, 主进程退出");
            g_stop = true;
            wd_close_once();
            break;
        }
        uint64_t now = now_ms();
        if (g_peer_expected && now - last_check >= 2000) {
            last_check = now;
            uint32_t spid = g_shared->standby_pid;
            uint64_t shb = g_shared->standby_hb;
            bool need = false;
            const char* why = "";
            if (spid == 0) {
                if (now - g_spawnMark >= 15000) { need = true; why = "副进程未注册"; }
            } else {
                HANDLE ph = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, spid);
                if (!ph) { need = true; why = "副进程已退出"; }
                else {
                    if (WaitForSingleObject(ph, 0) == WAIT_OBJECT_0) {
                        need = true; why = "副进程已退出";
                    } else if ((shb != 0 && now - shb > 5000) ||
                               (shb == 0 && now - g_spawnMark > 15000)) {
                        TerminateProcess(ph, 1);
                        need = true; why = "副进程僵死";
                    }
                    CloseHandle(ph);
                }
            }
            if (need) {
                (*log)("[SUP] %s, 重新拉起同伴", why);
                respawn_peer(*log);
            }
        }
        Sleep(250);
    }
}

static bool standby_loop(Log& log, HANDLE stop_ev) {
    uint64_t last_note = now_ms();
    for (;;) {
        if (g_stop) return false;
        if (stop_ev && WaitForSingleObject(stop_ev, 500) == WAIT_OBJECT_0) {
            log("收到停止事件, 副进程退出");
            g_stop = true;
            return false;
        }
        g_shared->standby_hb = now_ms();
        g_shared->standby_pid = GetCurrentProcessId();
        uint32_t ppid = g_shared->primary_pid;
        if (ppid != 0) {
            HANDLE ph = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, FALSE, ppid);
            if (!ph) return true;
            bool dead = (WaitForSingleObject(ph, 0) == WAIT_OBJECT_0);
            if (!dead) {
                uint64_t hb = g_shared->primary_hb;
                if (hb != 0 && now_ms() - hb > 5000) {
                    log("[SUP] 主进程心跳停止超过 5 秒, 判定僵死, 强制接管");
                    if (!TerminateProcess(ph, 1)) {
                        log("[SUP] 强杀失败 (错误 %lu), 等待其自行退出", GetLastError());
                        if (WaitForSingleObject(ph, 10000) != WAIT_OBJECT_0) {
                            CloseHandle(ph);
                            continue;
                        }
                    }
                    dead = true;
                }
            }
            CloseHandle(ph);
            if (dead) return true;
            uint64_t now = now_ms();
            if (now - last_note > 300000) {
                last_note = now;
                log("[SUP] 监控中: 主进程 PID %u 存活", ppid);
            }
        }
    }
}

enum RoleKind { ROLE_PRIMARY, ROLE_STANDBY, ROLE_DUP, ROLE_ERROR };
struct Role { RoleKind kind; HANDLE mutex; };

// 争角色：抢到主锁 = 主进程；主锁被占再抢副锁 = 副进程；两个都被占 = 已有完整一对
static Role acquire_role() {
    SetLastError(0);
    HANDLE hp = CreateMutexW(sa_all_access(), FALSE, MUTEX_PRIMARY);
    DWORD ep = GetLastError();
    if (hp && ep != ERROR_ALREADY_EXISTS) return { ROLE_PRIMARY, hp };
    SetLastError(0);
    HANDLE hs = CreateMutexW(sa_all_access(), FALSE, MUTEX_STANDBY);
    DWORD es = GetLastError();
    if (hs && es != ERROR_ALREADY_EXISTS) {
        if (hp) CloseHandle(hp);
        return { ROLE_STANDBY, hs };
    }
    if (hp) CloseHandle(hp);
    if (hs) CloseHandle(hs);
    if (!hp && !hs) return { ROLE_ERROR, NULL };
    return { ROLE_DUP, NULL };
}

static bool run_core(const Config& cfg, Log& log, bool dual);

static int run_primary(HANDLE mutex, Log& log, const Config& cfg, HANDLE stop_ev) {
    g_shared->primary_pid = GetCurrentProcessId();
    g_shared->primary_hb = now_ms();
    std::thread th(primary_watchdog, &log, stop_ev);
    th.detach();
    bool ok = run_core(cfg, log, true);
    g_stop = true;
    Sleep(700);
    CloseHandle(mutex);
    return ok ? 0 : 1;
}

// ---------------------------------------------------------------------------
// 主循环
// ---------------------------------------------------------------------------
static bool run_core(const Config& cfg, Log& log, bool dual) {
    uint8_t prefix[3];
    {
        bool got = false;
        HKEY k;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters",
                          0, KEY_READ, &k) == ERROR_SUCCESS) {
            wchar_t buf[64] = { 0 };
            DWORD sz = sizeof(buf) - 2;
            DWORD type = 0;
            if (RegQueryValueExW(k, L"ScopeAddress", NULL, &type, (LPBYTE)buf, &sz) == ERROR_SUCCESS) {
                unsigned a = 0, b = 0, c = 0, d = 0;
                if (swscanf_s(buf, L"%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
                    prefix[0] = (uint8_t)a; prefix[1] = (uint8_t)b; prefix[2] = (uint8_t)c;
                    got = true;
                }
            }
            RegCloseKey(k);
        }
        if (!got) memcpy(prefix, DEFAULT_HOTSPOT_PREFIX, 3);
    }

    const bool do_ua = !cfg.no_ua;
    const bool do_dns = !cfg.no_dns && !cfg.dry_run;
    const bool guard_on = do_ua && !cfg.dry_run;

    FlowGuard guard(60.0);
    double last_act = 0.0, dns_until = 0.0;

    FpRecorder fp;
    bool fp_on = false;
    if (!cfg.no_fp) {
        std::string fp_path = cfg.fp_path.empty()
            ? w2u(base_dir()) + "\\logs\\fingerprint\\fwd_" + ts_file() + ".tsv"
            : cfg.fp_path;
        if (fp.open(fp_path)) {
            fp_on = true;
            log("指纹记录    : %s", fp_path.c_str());
        } else {
            log("指纹记录    : 打不开 (%s), 本次不记", fp_path.c_str());
        }
    }

    log("UA 改写     : %s", do_ua ? "开（能改的改；真有手机特征才丢；没 UA 头放行）" : "关");
    if (do_dns)
        log("明文 DNS    : 开（静默 %.0fs 判为新连接，其后 %.0fs 内一律丢）",
            cfg.dns_gap, cfg.dns_win);
    else
        log("明文 DNS    : 关");
    log("热点网段    : %u.%u.%u.0/24 (回程包按此排除)",
        (unsigned)prefix[0], (unsigned)prefix[1], (unsigned)prefix[2]);
    log("过滤器      : 'ip' (只 IPv4; IPv6 一律不动)");

    for (int attempt = 1;; attempt++) {
        HANDLE h = wdOpen(FILTER, WINDIVERT_LAYER_NETWORK_FORWARD, 0, 0);
        if (h) { g_wd = h; break; }
        DWORD e = GetLastError();
        if (attempt == 1 || attempt % 12 == 0)
            log("打开 WinDivert 失败 (错误 %lu), 5 秒后重试", e);
        if (!dual) {
            log("打开/运行 WinDivert 失败: 错误 %lu", e);
            log("常见原因: 没用管理员运行 (winerror 5), 或驱动被安全软件拦截");
            if (fp_on) fp.close();
            return false;
        }
        if (g_stop) { if (fp_on) fp.close(); return false; }
        for (int i = 0; i < 20 && !g_stop; i++) Sleep(250);
    }
    log("handle 已打开, 开始%s (目标 TTL=%d)", cfg.dry_run ? "统计" : "改写", cfg.ttl);

    if (cfg.seconds > 0) {
        log("将在 %d 秒后自动停止", cfg.seconds);
        int seconds = cfg.seconds;
        std::thread([seconds] {
            uint64_t t0 = now_ms();
            while (!g_stop && now_ms() - t0 < (uint64_t)seconds * 1000) Sleep(250);
            if (!g_stop) {
                g_stop = true;
                wd_close_once();
            }
        }).detach();
    }

    if (dual) {
        g_peer_expected = true;
        start_peer(log);
    }

    long long n_recv = 0, n_changed = 0, n_skip = 0, n_bad = 0;
    long long n_ua = 0, n_drop = 0, n_dns = 0;
    std::map<std::string, long long> hist;
    double last_report = steady_now();

    std::vector<uint8_t> buf(65535 + 64);
    for (;;) {
        if (g_stop) break;
        UINT rlen = 0;
        WINDIVERT_ADDRESS addr;
        ZeroMemory(&addr, sizeof(addr));
        if (!wdRecv(g_wd.load(), buf.data(), (UINT)buf.size(), &addr, &rlen)) {
            DWORD e = GetLastError();
            if (g_stop) break;
            log("WinDivertRecv 失败 (错误 %lu), %s", e, dual ? "进程退出等待接管" : "进程退出");
            wd_close_once();
            if (fp_on) fp.close();
            return false;
        }
        n_recv++;
        uint8_t* raw = buf.data();
        bool changed = false, ua_changed = false, drop_it = false;
        double t_act = 0.0;

        if (rlen >= 20 && (raw[0] >> 4) == 4) {
            size_t ihl = (size_t)(raw[0] & 0x0F) * 4;
            if (ihl >= 20 && ihl <= rlen) {
                uint8_t old_ttl = raw[8];
                if (dst_in_hotspot(raw, prefix)) {
                    n_skip++;
                    hist[std::to_string((unsigned)old_ttl) + "->跳过"]++;
                } else {
                    hist[std::to_string((unsigned)old_ttl) + "->改"]++;
                    t_act = steady_now();
                    if (do_dns) {
                        double gap = t_act - last_act;
                        bool first = (last_act == 0.0);
                        double nla, ndu; bool opened;
                        epoch_tick(last_act, dns_until, t_act, cfg.dns_gap, cfg.dns_win,
                                   &nla, &ndu, &opened);
                        last_act = nla; dns_until = ndu;
                        if (opened)
                            log("★ 转发流%s(静默 %.0fs) → 开启 DNS 丢弃窗口 %.0fs",
                                first ? "首次出现" : "恢复", first ? 0.0 : gap, cfg.dns_win);
                    }
                    if (fp_on) fp.feed(raw, rlen, ihl, old_ttl);
                    if (old_ttl != (uint8_t)cfg.ttl) {
                        if (!cfg.dry_run) {
                            raw[8] = (uint8_t)cfg.ttl;
                            fix_ipv4_cksum(raw, (int)ihl);
                        }
                        changed = true;
                    }
                    if (guard_on && raw[9] == 6) {
                        int tot = (raw[2] << 8) | raw[3];
                        size_t p0 = 0, p1 = 0;
                        if (tcp_span(raw, rlen, ihl, tot, &p0, &p1)) {
                            std::string key = flow_key_str(raw, ihl);
                            double now = steady_now();
                            if (guard.blocked(key, now)) {
                                n_drop++; drop_it = true;
                            } else {
                                std::string payload((const char*)raw + p0, p1 - p0);
                                std::string np;
                                UaAct act = handle_request(payload, &np);
                                if (act == UA_REWRITE) {
                                    if (np.size() == p1 - p0) {
                                        memcpy(raw + p0, np.data(), np.size());
                                        ua_changed = true;
                                    }
                                } else if (act == UA_DROP) {
                                    guard.block(key, now);
                                    n_drop++;
                                    drop_it = true;
                                    if (n_drop <= 20) {
                                        log("丢弃手机特征明文 HTTP: %s:%s -> %s:%s | %s",
                                            hex_dotted(raw + 12, 4).c_str(),
                                            hex_nodot(raw + ihl, 2).c_str(),
                                            hex_dotted(raw + 16, 4).c_str(),
                                            hex_nodot(raw + ihl + 2, 2).c_str(),
                                            head_of(raw, p0, std::min<size_t>(110, rlen - p0)).c_str());
                                    }
                                }
                            }
                        }
                    }
                    if (do_dns && t_act < dns_until && is_dns(raw, rlen, ihl)) {
                        n_dns++; drop_it = true;
                        if (n_dns <= 20) {
                            std::string q = (raw[9] == 17 && ihl + 8 <= rlen)
                                ? dns_name(raw + ihl + 8, rlen - ihl - 8)
                                : std::string(raw[9] == 17 ? "" : "TCP/53");
                            log("丢弃窗口内明文 DNS: %s", q.c_str());
                        }
                    }
                }
            } else {
                n_bad++;
            }
        } else if (rlen >= 40 && (raw[0] >> 4) == 6) {
            n_skip++;
            hist["v6->跳过"]++;
        } else {
            n_bad++;
        }

        if (changed) n_changed++;
        if (ua_changed) n_ua++;

        if (!drop_it) {
            if (ua_changed) wdCalc(buf.data(), rlen, 0);
            UINT wl = 0;
            if (!wdSend(g_wd.load(), buf.data(), rlen, &addr, &wl)) {
                DWORD e = GetLastError();
                log("WinDivertSend 失败 (错误 %lu), %s", e, dual ? "进程退出等待接管" : "进程退出");
                wd_close_once();
                if (fp_on) fp.close();
                return false;
            }
        }

        if (cfg.stats > 0) {
            double now = steady_now();
            if (now - last_report >= (double)cfg.stats) {
                last_report = now;
                if (guard_on) guard.purge(now);
                log("收包 %lld | 改写 %lld | UA改写 %lld | 丢弃 %lld | DNS丢 %lld | 跳过 %lld | 畸形 %lld | TTL 分布 %s",
                    n_recv, n_changed, n_ua, n_drop, n_dns, n_skip, n_bad,
                    hist_repr(hist).c_str());
            }
        }
    }

    if (g_ctrl_c) log("收到 Ctrl+C, 退出中");
    if (g_wd) { wd_close_once(); log("handle 已关闭, 转发恢复正常"); }
    log("本段 UA 等长改写: %lld 个包 | 改不了而丢弃: %lld 个包 | 窗口内 DNS 丢弃: %lld 个包",
        n_ua, n_drop, n_dns);
    if (fp_on) {
        log("指纹记录    : 写入 %lld 行, 识别出 %d 种指纹", fp.n_, (int)fp.sig_count());
        fp.close();
    }
    log("=== 汇总 ===");
    log("收包 %lld, 需改写 %lld, 跳过 %lld, 畸形 %lld", n_recv, n_changed, n_skip, n_bad);
    if (do_ua) log("明文 HTTP: UA 等长改写 %lld 个包, 真手机特征丢弃 %lld 个包", n_ua, n_drop);
    if (do_dns) log("明文 DNS : 窗口内丢弃 %lld 个包", n_dns);
    log("改写前 TTL 分布 %s", hist_repr(hist).c_str());
    if (cfg.dry_run) log("(dry-run: 未做任何改写)");
    return true;
}

// ---------------------------------------------------------------------------
// 环境自检
// ---------------------------------------------------------------------------
static bool env_check(Log& log) {
    bool ok = true;
    std::string err;
    bool dll_ok = (g_wdDll != NULL) || load_windivert(&err);
    log("normalizer  : C++ (WinDivert 1.3.0)");
    log("脚本目录    : %s", w2u(base_dir()).c_str());
    if (dll_ok)
        log("WinDivert dll: %s (加载成功)", w2u(exe_dir() + L"\\WinDivert64.dll").c_str());
    else {
        log("WinDivert dll: 加载失败: %s", err.c_str());
        ok = false;
    }
    log("NETWORK_FORWARD 层常量: 1");
    bool admin = is_admin();
    log("管理员权限  : %s", admin ? "是" : "否 (必须用管理员运行)");
    if (!admin) ok = false;
    if (dll_ok) {
        const char* errstr = NULL;
        UINT errpos = 0;
        BOOL res = wdCheck(FILTER, WINDIVERT_LAYER_NETWORK_FORWARD, &errstr, &errpos);
        if (res) log("过滤器校验  : OK  'ip'");
        else {
            log("过滤器校验  : FAIL 'ip' -> %s (pos=%u)", errstr ? errstr : "?", errpos);
            ok = false;
        }
    } else {
        log("过滤器校验  : 跳过 (DLL 未加载)");
        ok = false;
    }
    return ok;
}

// ---------------------------------------------------------------------------
// 停止 / 状态
// ---------------------------------------------------------------------------
static bool mutex_exists(const wchar_t* name) {
    HANDLE h = OpenMutexW(SYNCHRONIZE, FALSE, name);
    if (h) { CloseHandle(h); return true; }
    return false;
}

static int cmd_stop(Log& log) {
    bool running = mutex_exists(MUTEX_PRIMARY) || mutex_exists(MUTEX_STANDBY);
    uint32_t ppid = 0, spid = 0;
    HANDLE map = OpenFileMappingW(FILE_MAP_READ, FALSE, SHARED_NAME);
    if (map) {
        SharedState* s = (SharedState*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, sizeof(SharedState));
        if (s) { ppid = s->primary_pid; spid = s->standby_pid; UnmapViewOfFile(s); }
        CloseHandle(map);
    }
    running = running || proc_alive(ppid) || proc_alive(spid);
    if (!running) {
        log("未发现运行中的实例");
        return 0;
    }
    HANDLE ev = CreateEventW(sa_all_access(), TRUE, FALSE, STOP_EVENT);
    if (!ev) {
        log("打不开停止事件 (错误 %lu)", GetLastError());
        return 1;
    }
    SetEvent(ev);
    log("已发出停止事件 (主 PID=%u, 副 PID=%u), 等待退出...", ppid, spid);
    bool clean = false;
    for (int i = 0; i < 32; i++) {
        Sleep(250);
        bool any = proc_alive(ppid) || proc_alive(spid);
        if (!any && !mutex_exists(MUTEX_PRIMARY) && !mutex_exists(MUTEX_STANDBY)) {
            clean = true;
            break;
        }
    }
    if (!clean) {
        log("等待超时, 强制结束进程");
        for (int round = 0; round < 4; round++) {
            SetEvent(ev);
            // 重读共享内存里的 pid 快照
            uint32_t p2 = 0, s2 = 0;
            HANDLE m2 = OpenFileMappingW(FILE_MAP_READ, FALSE, SHARED_NAME);
            if (m2) {
                SharedState* s = (SharedState*)MapViewOfFile(m2, FILE_MAP_READ, 0, 0, sizeof(SharedState));
                if (s) { p2 = s->primary_pid; s2 = s->standby_pid; UnmapViewOfFile(s); }
                CloseHandle(m2);
            }
            uint32_t targets[4] = { ppid, spid, p2, s2 };
            for (uint32_t pid : targets) {
                if (pid && pid != GetCurrentProcessId() && proc_alive(pid)) {
                    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                    if (h) { TerminateProcess(h, 1); CloseHandle(h); }
                }
            }
            // 按镜像名兜底清理 normalizer.exe（排除本进程）
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
                if (Process32FirstW(snap, &pe)) {
                    do {
                        if (pe.th32ProcessID != GetCurrentProcessId() &&
                            _wcsicmp(pe.szExeFile, L"normalizer.exe") == 0) {
                            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                            if (h) { TerminateProcess(h, 1); CloseHandle(h); }
                        }
                    } while (Process32NextW(snap, &pe));
                }
                CloseHandle(snap);
            }
            Sleep(600);
            if (!mutex_exists(MUTEX_PRIMARY) && !mutex_exists(MUTEX_STANDBY)) break;
        }
        if (!mutex_exists(MUTEX_PRIMARY) && !mutex_exists(MUTEX_STANDBY))
            log("已强制结束");
        else
            log("仍有实例未退出, 请检查");
    } else {
        log("已全部退出");
    }
    return 0;
}

static int cmd_status(Log& log) {
    bool p_mutex = mutex_exists(MUTEX_PRIMARY);
    bool s_mutex = mutex_exists(MUTEX_STANDBY);
    uint32_t ppid = 0, spid = 0;
    uint64_t phb = 0, shb = 0;
    HANDLE map = OpenFileMappingW(FILE_MAP_READ, FALSE, SHARED_NAME);
    if (map) {
        SharedState* s = (SharedState*)MapViewOfFile(map, FILE_MAP_READ, 0, 0, sizeof(SharedState));
        if (s) { ppid = s->primary_pid; spid = s->standby_pid; phb = s->primary_hb; shb = s->standby_hb; UnmapViewOfFile(s); }
        CloseHandle(map);
    }
    log("主进程锁  : %s", p_mutex ? "持有" : "空闲");
    if (ppid) {
        std::string hb = phb ? (std::to_string(now_ms() - phb) + " ms 前") : std::string("无");
        log("主进程 PID: %u (%s), 心跳: %s", ppid, proc_alive(ppid) ? "存活" : "已退出", hb.c_str());
    } else {
        log("主进程 PID: 无记录");
    }
    log("副进程锁  : %s", s_mutex ? "持有" : "空闲");
    if (spid) {
        std::string hb = shb ? (std::to_string(now_ms() - shb) + " ms 前") : std::string("无");
        log("副进程 PID: %u (%s), 心跳: %s", spid, proc_alive(spid) ? "存活" : "已退出", hb.c_str());
    } else {
        log("副进程 PID: 无记录");
    }
    if (!p_mutex && !s_mutex && !ppid && !spid) log("结论      : 未运行");
    return 0;
}

// ---------------------------------------------------------------------------
// 主入口
// ---------------------------------------------------------------------------
static BOOL WINAPI ctrl_handler(DWORD t) {
    if (t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT || t == CTRL_CLOSE_EVENT) {
        g_stop = true;
        g_ctrl_c = true;
        wd_close_once();
        return TRUE;
    }
    return FALSE;
}

static void usage() {
    fprintf(stderr,
        "用法: normalizer.exe [选项]\n"
        "  --ttl N           目标 TTL, 默认 128\n"
        "  --no-ua           关掉明文 HTTP 的 UA 等长改写\n"
        "  --no-dns          关掉'刚连上'窗口内的明文 DNS 丢弃\n"
        "  --dns-gap F       转发流静默超过 F 秒算新连接, 默认 60\n"
        "  --dns-win F       新连接之后丢明文 DNS 的窗口秒数, 默认 45\n"
        "  --dry-run         只统计不改写（单进程）\n"
        "  --stats N         统计输出间隔秒数, 0=不输出, 默认 10\n"
        "  --seconds N       运行 N 秒后自动停止（单进程）\n"
        "  --log PATH        日志文件路径\n"
        "  --no-log          关闭文件日志\n"
        "  --no-fingerprint  关掉指纹 TSV 记录\n"
        "  --fp-log PATH     指纹 TSV 路径\n"
        "  --check           环境自检, 不打开驱动\n"
        "  --stop            停止运行中的实例\n"
        "  --status          查看运行状态\n"
        "  --selftest        纯逻辑自检\n");
}

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    g_argv.assign(argv, argv + argc);

    Config cfg;
    auto parse_int = [](const wchar_t* s, int* out) -> bool {
        if (!s || !*s) return false;
        wchar_t* end = NULL;
        long v = wcstol(s, &end, 10);
        if (!end || *end) return false;
        *out = (int)v;
        return true;
    };
    auto parse_dbl = [](const wchar_t* s, double* out) -> bool {
        if (!s || !*s) return false;
        wchar_t* end = NULL;
        double v = wcstod(s, &end);
        if (!end || *end) return false;
        *out = v;
        return true;
    };
    for (int i = 1; i < argc; i++) {
        std::wstring a = argv[i];
        std::wstring inline_val;
        bool has_inline = false;
        if (a.size() > 2 && a[0] == L'-' && a[1] == L'-') {
            size_t eq = a.find(L'=');
            if (eq != std::wstring::npos) {
                inline_val = a.substr(eq + 1);
                a = a.substr(0, eq);
                has_inline = true;
            }
        }
        auto take_val = [&]() -> const wchar_t* {
            if (has_inline) return inline_val.c_str();
            if (i + 1 >= argc) { fprintf(stderr, "参数 %ls 缺少取值\n", a.c_str()); exit(2); }
            return argv[++i];
        };
        auto bad_val = [&](const wchar_t* v) {
            fprintf(stderr, "参数 %ls 取值无效: %ls\n", a.c_str(), v);
            exit(2);
        };
        if (a == L"--ttl") { const wchar_t* v = take_val(); if (!parse_int(v, &cfg.ttl)) bad_val(v); }
        else if (a == L"--no-ua") cfg.no_ua = true;
        else if (a == L"--no-dns") cfg.no_dns = true;
        else if (a == L"--dns-gap") { const wchar_t* v = take_val(); if (!parse_dbl(v, &cfg.dns_gap)) bad_val(v); }
        else if (a == L"--dns-win") { const wchar_t* v = take_val(); if (!parse_dbl(v, &cfg.dns_win)) bad_val(v); }
        else if (a == L"--dry-run") cfg.dry_run = true;
        else if (a == L"--stats") { const wchar_t* v = take_val(); if (!parse_int(v, &cfg.stats)) bad_val(v); }
        else if (a == L"--seconds") { const wchar_t* v = take_val(); if (!parse_int(v, &cfg.seconds)) bad_val(v); }
        else if (a == L"--log") { cfg.log_path = w2u(take_val()); }
        else if (a == L"--no-log") cfg.no_log = true;
        else if (a == L"--no-fingerprint") cfg.no_fp = true;
        else if (a == L"--fp-log") { cfg.fp_path = w2u(take_val()); }
        else if (a == L"--check") cfg.mode_check = true;
        else if (a == L"--stop") cfg.mode_stop = true;
        else if (a == L"--status") cfg.mode_status = true;
        else if (a == L"--selftest") cfg.mode_selftest = true;
        else if (a == L"--help" || a == L"-h") cfg.mode_help = true;
        else { fprintf(stderr, "未知参数: %ls\n", a.c_str()); usage(); return 2; }
    }
    if (cfg.mode_help) { usage(); return 0; }
    if (cfg.ttl < 1 || cfg.ttl > 255) {
        fprintf(stderr, "--ttl 必须在 1..255\n");
        return 2;
    }
    if (cfg.mode_selftest) return run_selftest();
    if (cfg.mode_check) {
        Log log;
        if (!cfg.no_log) {
            std::string p = cfg.log_path.empty()
                ? w2u(base_dir()) + "\\logs\\ttl_normalize_" + ts_file() + ".log"
                : cfg.log_path;
            log.open(p);
            if (log.opened()) log("日志文件: %s", p.c_str());
        }
        bool ok = env_check(log);
        log("自检结束: %s", ok ? "通过" : "有问题");
        log.close();
        return ok ? 0 : 1;
    }
    if (cfg.mode_stop) { Log log; return cmd_stop(log); }
    if (cfg.mode_status) { Log log; return cmd_status(log); }

    const bool single = cfg.dry_run || cfg.seconds > 0;
    HANDLE stop_ev = CreateEventW(sa_all_access(), TRUE, FALSE, STOP_EVENT);
    if (stop_ev && !single && WaitForSingleObject(stop_ev, 0) == WAIT_OBJECT_0) {
        fprintf(stderr, "检测到停止事件已置位（上一次 --stop 进行中）, 本进程退出\n");
        return 0;
    }

    Log log;

    if (single) {
        if (!cfg.no_log) {
            std::string p = cfg.log_path.empty()
                ? w2u(base_dir()) + "\\logs\\ttl_normalize_" + ts_file() + ".log"
                : cfg.log_path;
            log.open(p);
            if (log.opened()) log("日志文件: %s", p.c_str());
        }
        SetConsoleCtrlHandler(ctrl_handler, TRUE);
        bool ok = env_check(log);
        if (!ok) {
            log("环境自检未通过, 拒绝打开驱动");
            log.close();
            return 1;
        }
        bool done = run_core(cfg, log, false);
        log.close();
        return done ? 0 : 1;
    }

    // 双进程模式：主/副互救
    if (!is_admin()) {
        fprintf(stderr, "必须用管理员运行\n");
        return 1;
    }
    hide_own_console();
    SetLastError(0);
    HANDLE map = CreateFileMappingW(INVALID_HANDLE_VALUE, sa_all_access(), PAGE_READWRITE, 0,
                                    (DWORD)sizeof(SharedState), SHARED_NAME);
    DWORD map_err = GetLastError();
    if (!map) {
        fprintf(stderr, "创建共享内存失败 (错误 %lu)\n", map_err);
        return 1;
    }
    bool existed = (map_err == ERROR_ALREADY_EXISTS);
    g_shared = (SharedState*)MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedState));
    if (!g_shared) {
        fprintf(stderr, "映射共享内存失败 (错误 %lu)\n", GetLastError());
        return 1;
    }
    if (!existed) ZeroMemory((void*)g_shared, sizeof(SharedState));

    SetConsoleCtrlHandler(ctrl_handler, TRUE);
    bool log_open = false;
    bool env_checked = false;
    for (;;) {
        Role r = acquire_role();
        if (r.kind == ROLE_ERROR) {
            fprintf(stderr, "创建互斥体失败 (错误 %lu)\n", GetLastError());
            return 1;
        }
        if (!log_open) {
            if (!cfg.no_log) {
                std::string suffix = (r.kind == ROLE_STANDBY) ? "_standby" : "";
                std::string p;
                if (cfg.log_path.empty()) {
                    p = w2u(base_dir()) + "\\logs\\ttl_normalize_" + ts_file() + suffix + ".log";
                } else {
                    p = cfg.log_path;
                    if (!suffix.empty()) {
                        size_t dot = p.find_last_of('.');
                        p = (dot == std::string::npos)
                            ? p + suffix
                            : p.substr(0, dot) + suffix + p.substr(dot);
                    }
                }
                log.open(p);
                if (log.opened()) log("日志文件: %s", p.c_str());
            }
            log_open = true;
        }
        if (r.kind == ROLE_DUP) {
            log("[SUP] 已有完整主副对, 本进程退出 (PID %u)", GetCurrentProcessId());
            log.close();
            return 0;
        }
        if (!env_checked) {
            bool ok = env_check(log);
            if (!ok) {
                log("环境自检未通过, 拒绝打开驱动");
                log.close();
                return 1;
            }
            env_checked = true;
        }
        if (r.kind == ROLE_PRIMARY) {
            log("[SUP] 角色: 主进程 (PID %u)", GetCurrentProcessId());
            int rc = run_primary(r.mutex, log, cfg, stop_ev);
            log.close();
            return rc;
        }
        log("[SUP] 角色: 副进程 (PID %u), 只监控不接管 handle", GetCurrentProcessId());
        bool takeover = standby_loop(log, stop_ev);
        CloseHandle(r.mutex);
        if (!takeover) {
            log.close();
            return 0;
        }
        log("[SUP] 主进程失联, 本进程接管为新的主进程");
    }
}
