/*
 * NAThelper - NAT 穿透端口映射助手（三个构建共用这一份源码）
 *
 * 目标平台: 64 位  NAThelper   Windows Vista SP2 x64 及以上   build.bat
 *           32 位  NAThelp32   Windows NT 4.0 SP5+ 32 位全部   build32.bat
 *           9x     NAThelp9X   Windows 95 / 98 / Me            build9x.bat
 *
 * 9x 构建的特殊性：95/98/Me 的 user32/kernel32/gdi32/comctl32 没有任何 *W
 * 入口点，所以用 -DNATHELPER_ANSI=1 编译：界面 API 全部走 ANSI，程序内部
 * 仍然使用 UTF-16，只在进出系统 API 的边界按 ACP（中文 Windows = GBK）转码。
 * 编译工具: w64devkit / MinGW-w64 GCC
 *
 * 工作方式:
 *   1. 在本机绑定一个端口（用户指定，或随机 1024-65535）。
 *   2. 从这个端口向 STUN 服务器发送 Binding Request，取得 NAT 公网映射。
 *   3. UDP: 该端口继续接收公网数据，按外部来源建立本地服务会话并双向转发。
 *      TCP: 在该端口监听，把入站连接转发到本地服务端口；同时用同一本地端口
 *           连一条长期连接(keeper, 目标 TCP_KEEPER_HOST)挂住 NAT 映射，
 *           映射不被回收，公网端口就不会变。STUN 只用来查询端点：
 *           每次另开一条同端口临时连接，问完即关。
 *   4. UDP 每 30 秒、TCP 每 30 秒从映射端口向 STUN 保活(同一端口问，结果才对)。
 *      TCP 间隔必须远小于 60 秒：STUN 服务器对空闲 60 秒的连接会直接 RST，
 *      而 RST 会让运营商 NAT 立刻删表，公网端口就变了。
 *      TCP 可选用 PROXY protocol(v2 二进制/ v1 文本)把真实来源写进数据流最前面，
 *      让只看到 127.0.0.1 的本地服务也能还原源 IP（需服务端同时开启）。
 *   5. 默认启用 UPnP（SSDP 发现网关 -> SOAP AddPortMapping），
 *      用路由器端口映射取得稳定的公网地址；网关不支持时自动改用 STUN。
 *      映射租期 3600 秒，每 25 分钟自动续约，停止时删除映射。
 *   6. 黑名单：按 IPv4 网段、前缀（113.75.*.*）、起止地址或 CIDR
 *      屏蔽来源。TCP 在 accept 后立刻回 RST，UDP 在新建会话前直接丢弃。
 *      只在新连接建立时查一次表，已建立的连接不再检查，避免逐包开销。
 *
 * 说明: 本程序不做 NAT 类型检测。仅适用于映射行为与过滤行为
 *       均为 EndpointIndependent 的无公网 IP 用户。
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WINVER
#define WINVER 0x0600
#endif
#ifndef FD_SETSIZE
#define FD_SETSIZE 256
#endif

/* 32 位兼容构建（Windows NT4 SP5 及以上 32 位系统，直到 Windows 11 x86）：
   用 -DNATHELPER_LEGACY=1 -D_WIN32_WINNT=0x0400 编译。该构建不引用任何
   NT4 之后才出现的 API，才能被 NT4 的加载器接受；64 位构建保持原样。 */
#if (defined(NATHELPER_LEGACY) && NATHELPER_LEGACY) || \
    (defined(_WIN32_WINNT) && _WIN32_WINNT < 0x0500)
#  define NAT_LEGACY 1
#else
#  define NAT_LEGACY 0
#endif

/* Windows 95/98/Me 构建：这三个系统的 kernel32/user32/gdi32/comctl32 只有
   ANSI 版本，CreateWindowExW 这一整套入口点根本不存在，静态引用会让 exe
   在 9x 上加载失败（"无法定位程序输入点 ... 于 USER32.dll"）。
   用 -DNATHELPER_ANSI=1 编译时，内部仍全部是 UTF-16 字符串，只在进出系统
   API 的边界按系统 ANSI 代码页（中文 Windows = GBK）转码，见下面的兼容层。 */
#if defined(NATHELPER_ANSI) && NATHELPER_ANSI
#  define NAT_ANSI 1
#else
#  define NAT_ANSI 0
#endif

/* LVS_EX_DOUBLEBUFFER 是 comctl32 6.0 才有的扩展样式；老系统会忽略
   未知位，但编译期必须有定义。 */
#ifndef LVS_EX_DOUBLEBUFFER
#define LVS_EX_DOUBLEBUFFER 0x00010000
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#if !NAT_LEGACY
#include <iphlpapi.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include <time.h>

#ifndef EM_SETCUEBANNER
#define EM_SETCUEBANNER 0x1501
#endif

/* ------------------------------------------------------------------ */
/* ANSI 兼容层（Windows 95/98/Me 构建专用）                            */
/* ------------------------------------------------------------------ */
/* 9x 的 kernel32/user32/gdi32/comctl32 只有 ANSI 版本：CreateWindowExW
   这一整套入口点根本不存在，静态引用会让 exe 在 9x 上加载失败（"无法定位
   程序输入点 ... 于 USER32.dll"）。这里把源码里的 W 入口在编译期重定向到
   下面的包装：内部仍是 UTF-16，只在进出系统 API 的边界按 ACP（中文 Windows
   = GBK）转码。NT4/64 位构建完全不经过这些代码。 */

#if NAT_ANSI

#define NAT_ABUF 8192

static void NatWtoA(const WCHAR *src, char *dst, int cap)
{
    if (dst == NULL || cap <= 0)
        return;
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    if (WideCharToMultiByte(CP_ACP, 0, src, -1, dst, cap, NULL, NULL) <= 0)
        dst[0] = '\0';
}

static void NatAtoW(const char *src, WCHAR *dst, int cch)
{
    if (dst == NULL || cch <= 0)
        return;
    if (src == NULL) {
        dst[0] = L'\0';
        return;
    }
    if (MultiByteToWideChar(CP_ACP, 0, src, -1, dst, cch) <= 0)
        dst[0] = L'\0';
}

static BOOL NatSetWindowText(HWND hwnd, const WCHAR *text)
{
    char buf[NAT_ABUF];

    NatWtoA(text, buf, NAT_ABUF);
    return SetWindowTextA(hwnd, buf);
}

static int NatGetWindowText(HWND hwnd, WCHAR *text, int cch)
{
    char buf[NAT_ABUF];

    buf[0] = '\0';
    GetWindowTextA(hwnd, buf, NAT_ABUF);
    NatAtoW(buf, text, cch);
    return (int)wcslen(text);
}

static int NatGetWindowTextLength(HWND hwnd)
{
    return GetWindowTextLengthA(hwnd);
}

static int NatMessageBox(HWND hwnd, const WCHAR *text, const WCHAR *caption,
                         UINT type)
{
    char t[NAT_ABUF];
    char c[256];

    NatWtoA(text, t, NAT_ABUF);
    NatWtoA(caption, c, sizeof(c));
    return MessageBoxA(hwnd, t, c, type);
}

static HWND NatCreateWindowEx(DWORD exStyle, const WCHAR *className,
                              const WCHAR *text, DWORD style, int x, int y,
                              int w, int h, HWND parent, HMENU menu,
                              HINSTANCE inst, void *param)
{
    char cls[128];

    NatWtoA(className, cls, sizeof(cls));
    if (text != NULL) {
        char txt[NAT_ABUF];

        NatWtoA(text, txt, NAT_ABUF);
        return CreateWindowExA(exStyle, cls, txt, style, x, y, w, h,
                               parent, menu, inst, param);
    }
    return CreateWindowExA(exStyle, cls, NULL, style, x, y, w, h,
                           parent, menu, inst, param);
}

static ATOM NatRegisterClassEx(const WNDCLASSEXW *wc)
{
    WNDCLASSEXA a;
    char cls[128];
    char menu[128];

    ZeroMemory(&a, sizeof(a));
    a.cbSize = sizeof(a);
    a.style = wc->style;
    a.lpfnWndProc = wc->lpfnWndProc;
    a.cbClsExtra = wc->cbClsExtra;
    a.cbWndExtra = wc->cbWndExtra;
    a.hInstance = wc->hInstance;
    a.hIcon = wc->hIcon;
    a.hCursor = wc->hCursor;
    a.hbrBackground = wc->hbrBackground;
    a.lpszMenuName = NULL;
    if (wc->lpszMenuName != NULL) {
        NatWtoA(wc->lpszMenuName, menu, sizeof(menu));
        a.lpszMenuName = menu;
    }
    NatWtoA(wc->lpszClassName, cls, sizeof(cls));
    a.lpszClassName = cls;
    a.hIconSm = wc->hIconSm;
    return RegisterClassExA(&a);
}

static int NatDrawText(HDC dc, const WCHAR *text, int cch, RECT *rc, UINT fmt)
{
    char buf[NAT_ABUF];

    (void)cch;
    NatWtoA(text, buf, NAT_ABUF);
    return DrawTextA(dc, buf, -1, rc, fmt);
}

static DWORD NatFormatMessage(DWORD flags, LPCVOID source, DWORD msgId,
                              DWORD langId, LPWSTR buffer, DWORD size,
                              va_list *args)
{
    LPSTR tmp = NULL;
    DWORD r;

    (void)size;
    r = FormatMessageA((flags & ~FORMAT_MESSAGE_ALLOCATE_BUFFER) |
                       FORMAT_MESSAGE_ALLOCATE_BUFFER,
                       source, msgId, langId, (LPSTR)&tmp, 0, args);
    if (r == 0 || tmp == NULL) {
        if (buffer != NULL)
            *(LPWSTR *)buffer = NULL;
        return 0;
    }
    {
        int wlen = MultiByteToWideChar(CP_ACP, 0, tmp, -1, NULL, 0);
        LPWSTR w = NULL;

        if (wlen > 0)
            w = (LPWSTR)LocalAlloc(LPTR, (SIZE_T)wlen * sizeof(WCHAR));
        if (w != NULL) {
            MultiByteToWideChar(CP_ACP, 0, tmp, -1, w, wlen);
            LocalFree(tmp);
            *(LPWSTR *)buffer = w;
            return (DWORD)(wlen - 1);
        }
    }
    LocalFree(tmp);
    if (buffer != NULL)
        *(LPWSTR *)buffer = NULL;
    return 0;
}

static LONG NatRegOpenKeyEx(HKEY key, const WCHAR *sub, DWORD options,
                            REGSAM sam, PHKEY out)
{
    char buf[512];

    NatWtoA(sub, buf, sizeof(buf));
    return RegOpenKeyExA(key, buf, options, sam, out);
}

static LONG NatRegEnumKeyEx(HKEY key, DWORD index, WCHAR *name, LPDWORD cch,
                            LPDWORD reserved, WCHAR *classBuf, LPDWORD classCch,
                            void *lastWrite)
{
    char buf[256];
    DWORD cb = (DWORD)sizeof(buf);
    LONG r;

    (void)classBuf;
    (void)classCch;
    (void)lastWrite;
    r = RegEnumKeyExA(key, index, buf, &cb, reserved, NULL, NULL, NULL);
    if (r == ERROR_SUCCESS) {
        NatAtoW(buf, name, 128);
        if (cch != NULL)
            *cch = (DWORD)wcslen(name);
    }
    return r;
}

static LONG NatRegQueryValueEx(HKEY key, const WCHAR *name, LPDWORD reserved,
                               LPDWORD type, LPBYTE data, LPDWORD cb)
{
    char nm[128];
    BYTE tmp[1024];
    DWORD cbTmp = (DWORD)sizeof(tmp);
    LONG r;

    NatWtoA(name, nm, sizeof(nm));
    r = RegQueryValueExA(key, nm, reserved, type, tmp, &cbTmp);
    if (r != ERROR_SUCCESS)
        return r;
    if ((*type == REG_SZ || *type == REG_MULTI_SZ) && cb != NULL) {
        const char *p = (const char *)tmp;
        const char *end = (const char *)tmp + cbTmp;
        WCHAR w[512];
        DWORD wused = 0;
        DWORD bytes;

        while (p < end && wused + 2 < (DWORD)(sizeof(w) / sizeof(w[0]))) {
            int n = MultiByteToWideChar(CP_ACP, 0, p, -1, w + wused,
                                        (int)((sizeof(w) / sizeof(w[0])) - wused));

            if (n <= 0)
                break;
            wused += (DWORD)n;
            p += strlen(p) + 1;
        }
        if (wused == 0)
            w[wused++] = L'\0';
        bytes = wused * (DWORD)sizeof(WCHAR);
        if (bytes > *cb)
            bytes = *cb;
        memcpy(data, w, bytes);
        *cb = bytes;
    } else {
        if (cbTmp > *cb)
            cbTmp = *cb;
        memcpy(data, tmp, cbTmp);
        *cb = cbTmp;
    }
    return ERROR_SUCCESS;
}

/* LVITEMW/LVITEMV 与 A 版布局完全一致，只有 pszText 的字符宽度不同，
   所以整体复制结构、再替换 pszText 指针即可。 */
static LRESULT NatSendMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_SETTEXT:
        {
            char buf[NAT_ABUF];

            NatWtoA((const WCHAR *)lParam, buf, NAT_ABUF);
            return SendMessageA(hwnd, msg, wParam, (LPARAM)buf);
        }
    case WM_GETTEXT:
        {
            char buf[NAT_ABUF];

            buf[0] = '\0';
            SendMessageA(hwnd, msg, (WPARAM)NAT_ABUF, (LPARAM)buf);
            NatAtoW(buf, (WCHAR *)lParam, (int)wParam);
            return (LRESULT)wcslen((WCHAR *)lParam);
        }
    case CB_ADDSTRING:
    case CB_INSERTSTRING:
        {
            char buf[NAT_ABUF];

            NatWtoA((const WCHAR *)lParam, buf, NAT_ABUF);
            return SendMessageA(hwnd, msg, wParam, (LPARAM)buf);
        }
    case CB_GETLBTEXT:
        {
            char buf[NAT_ABUF];
            LRESULT r;

            buf[0] = '\0';
            r = SendMessageA(hwnd, msg, wParam, (LPARAM)buf);
            NatAtoW(buf, (WCHAR *)lParam, 256);
            return r;
        }
    case EM_REPLACESEL:
        {
            char buf[NAT_ABUF];

            NatWtoA((const WCHAR *)lParam, buf, NAT_ABUF);
            return SendMessageA(hwnd, msg, wParam, (LPARAM)buf);
        }
    case LVM_INSERTITEMW:
    case LVM_SETITEMW:
        {
            const LVITEMW *iw = (const LVITEMW *)lParam;
            LVITEMA ia;
            char tb[1024];

            ZeroMemory(&ia, sizeof(ia));
            memcpy(&ia, iw, sizeof(ia));
            tb[0] = '\0';
            if (iw->pszText != NULL) {
                NatWtoA(iw->pszText, tb, sizeof(tb));
                ia.pszText = tb;
            }
            return SendMessageA(hwnd,
                                msg == LVM_INSERTITEMW ? LVM_INSERTITEMA
                                                       : LVM_SETITEMA,
                                wParam, (LPARAM)&ia);
        }
    case LVM_GETITEMW:
        {
            LVITEMW *iw = (LVITEMW *)lParam;
            LVITEMA ia;
            char tb[1024];
            LPWSTR dst = iw->pszText;
            int dstCch = iw->cchTextMax;
            LRESULT r;

            ZeroMemory(&ia, sizeof(ia));
            memcpy(&ia, iw, sizeof(ia));
            tb[0] = '\0';
            if (dst != NULL) {
                ia.pszText = tb;
                ia.cchTextMax = (int)sizeof(tb);
            }
            r = SendMessageA(hwnd, LVM_GETITEMA, wParam, (LPARAM)&ia);
            /* 必须把 A 版回填的整块结构拷回去：只回填 pszText 的话，
               lParam/state/iImage 全是调用方传进来的原值（通常是 0），
               ListView_GetItem(LVIF_PARAM) 就永远拿到 NULL，列表项会被
               RefreshList 当成野指针当场删掉——9x 上"加完映射列表空白"
               就是这个原因。 */
            memcpy(iw, &ia, sizeof(ia));
            iw->pszText = dst;
            iw->cchTextMax = dstCch;
            if (dst != NULL)
                NatAtoW(tb, dst, dstCch > 0 ? dstCch : 1024);
            return r;
        }
    case LVM_SETITEMTEXTW:
        {
            const LVITEMW *iw = (const LVITEMW *)lParam;
            LVITEMA ia;
            char tb[1024];

            ZeroMemory(&ia, sizeof(ia));
            ia.iSubItem = iw->iSubItem;
            tb[0] = '\0';
            NatWtoA(iw->pszText, tb, sizeof(tb));
            ia.pszText = tb;
            return SendMessageA(hwnd, LVM_SETITEMTEXTA, wParam, (LPARAM)&ia);
        }
    case LVM_GETITEMTEXTW:
        {
            LVITEMW *iw = (LVITEMW *)lParam;
            LVITEMA ia;
            char tb[1024];
            LRESULT r;

            ZeroMemory(&ia, sizeof(ia));
            ia.iSubItem = iw->iSubItem;
            tb[0] = '\0';
            ia.pszText = tb;
            ia.cchTextMax = (int)sizeof(tb);
            r = SendMessageA(hwnd, LVM_GETITEMTEXTA, wParam, (LPARAM)&ia);
            if (iw->pszText != NULL)
                NatAtoW(tb, iw->pszText, iw->cchTextMax > 0 ? iw->cchTextMax : 1024);
            return r;
        }
    case LVM_INSERTCOLUMNW:
    case LVM_SETCOLUMNW:
        {
            const LVCOLUMNW *cw = (const LVCOLUMNW *)lParam;
            LVCOLUMNA ca;
            char tb[256];

            ZeroMemory(&ca, sizeof(ca));
            memcpy(&ca, cw, sizeof(ca));
            if (cw->pszText != NULL) {
                tb[0] = '\0';
                NatWtoA(cw->pszText, tb, sizeof(tb));
                ca.pszText = tb;
            }
            return SendMessageA(hwnd,
                                msg == LVM_INSERTCOLUMNW ? LVM_INSERTCOLUMNA
                                                         : LVM_SETCOLUMNA,
                                wParam, (LPARAM)&ca);
        }
    }
    return SendMessageA(hwnd, msg, wParam, lParam);
}

#define SendMessageW            NatSendMessage
#define SetWindowTextW          NatSetWindowText
#define GetWindowTextW          NatGetWindowText
#define GetWindowTextLengthW    NatGetWindowTextLength
#define MessageBoxW             NatMessageBox
#define CreateWindowExW         NatCreateWindowEx
#define RegisterClassExW        NatRegisterClassEx
#define DefWindowProcW          DefWindowProcA
/* Win98 的 USER32 确实导出了 PostMessageW（所以 exe 能加载），但这个函数
   投递出去的消息永远不会到达窗口过程——实测 PostMessageA 到达、
   PostMessageW 不到达。日志唤醒、状态刷新都靠 PostMessage，9x 上必须走 A。 */
#define PostMessageW            PostMessageA
/* UNICODE 编译下 IDI_APPLICATION/IDC_ARROW 是 MAKEINTRESOURCEW，
   直接传给 A 版函数类型不匹配，这里统一强转一次。 */
#define LoadIconW(h, name)      LoadIconA((h), (LPCSTR)(name))
#define LoadCursorW(h, name)    LoadCursorA((h), (LPCSTR)(name))
#define CreateEventW            CreateEventA
#define GetMessageW             GetMessageA
#define IsDialogMessageW        IsDialogMessageA
#define DispatchMessageW        DispatchMessageA
#define DrawTextW               NatDrawText
#define FormatMessageW          NatFormatMessage
#define RegOpenKeyExW           NatRegOpenKeyEx
#define RegEnumKeyExW           NatRegEnumKeyEx
#define RegQueryValueExW        NatRegQueryValueEx

#endif  /* NAT_ANSI */

/* 三个构建各自的产品名：界面标题、窗口类名、User-Agent、UPnP 映射描述
   都取自这里，避免出现"改一处漏一处"。 */
#if NAT_ANSI
#  define NAT_PRODUCT       L"NAThelp9X"
#  define NAT_PRODUCT_A     "NAThelp9X"
#  define NAT_PLATFORM_NOTE L"本版本适用于 Windows 95+（95 / 98 / Me）。"
#elif NAT_LEGACY
#  define NAT_PRODUCT       L"NAThelp32"
#  define NAT_PRODUCT_A     "NAThelp32"
#  define NAT_PLATFORM_NOTE L"本版本适用于 Windows NT4 SP5+（32 位）。"
#else
#  define NAT_PRODUCT       L"NAThelper"
#  define NAT_PRODUCT_A     "NAThelper"
#  define NAT_PLATFORM_NOTE L"本版本适用于 Windows Vista x64+。"
#endif

#define APP_NAME            NAT_PRODUCT
#define APP_VERSION         L"1.1.0"
#define APP_TITLE           NAT_PRODUCT L" - NAT 穿透映射助手"

#define NAT_WNDCLASS_MAIN   NAT_PRODUCT L"WindowClass"
#define NAT_WNDCLASS_CONN   NAT_PRODUCT L"ConnWindowClass"
#define NAT_WNDCLASS_BLACK  NAT_PRODUCT L"BlackWindowClass"
#define DEFAULT_STUN_TEXT   L"106.55.38.133:60887"
#define DEFAULT_STUN_HOST   L"106.55.38.133"
#define DEFAULT_STUN_PORT   60887
#define DEFAULT_BACKEND_HOST L"127.0.0.1"

#define UDP_KEEPALIVE_MS    30000ULL
/* 实测 STUN 服务器在空闲 60 秒后回 RST；RST 一到运营商 NAT 立刻删映射、
   公网端口随即变化。所以 TCP 保活必须比 60 秒短得多，取 30 秒。 */
#define TCP_KEEPALIVE_MS    30000ULL
#define KEEPALIVE_RETRY_MS   5000ULL
/* TCP 的监听 socket 和保活连接共用同一个本地端口，两者都开 SO_REUSEADDR
   （Windows 上这是两个 socket 绑同一端口的前提）。保活连接是一条常驻的
   STUN 长连接，每 TCP_KEEPALIVE_MS 在它上面刷新一次：运营商 NAT 上的映射
   自始至终不重建，公网端口因此保持稳定。
   旧方案是每轮先关监听、再独占端口打洞、最后 RST 关闭——RST 会让 NAT
   立刻删掉这条映射，于是每次都拿到新的公网端口，表现为"公网端点每分钟
   变一次"。现在监听全程不关闭，也不再有 RST。 */
/* TCP 保活目标：一条长期挂住的 HTTP 连接。
   为什么不用 STUN 服务器保活：实测 106.55.38.133:60887 对每条 TCP 连接都固定
   ~60 秒后回 RST，连接一断运营商 NAT 立刻删表，公网端口就变了（表现为"公网
   端点每分钟变一次"）。HTTP 服务器只要定期发个 HEAD 就会一直保持，映射因此
   稳定。STUN 只负责"查询"公网端点：每次另开一条同端口的临时连接，问完就关。 */
#define TCP_KEEPER_HOST     L"www.baidu.com"
#define TCP_KEEPER_HOST_A   "www.baidu.com"
#define TCP_KEEPER_PORT     80
/* 保活目标要走一次 DNS 解析 + 公网 TCP 握手，4 秒对弱网太紧，单独放宽 */
#define KEEPER_CONNECT_TIMEOUT_MS 8000
#define TCP_RELAY_CAP        32768      /* 每个方向的中转队列上限 */
#define TCP_RELAY_STALL_MS   5000ULL    /* 数据发不动超过这么久就断开 */
#define TCP_BACKEND_TIMEOUT_MS 5000     /* 连接本地服务的超时 */
#define TCP_ACCEPT_BATCH     16         /* 每轮最多 accept 的连接数 */
#define STUN_CONNECT_TIMEOUT_MS 4000
#define STUN_STREAM_TIMEOUT_MS  4000
#define STOP_WAIT_MS         8000
#define UDP_SESSION_IDLE_MS  300000ULL
#define UDP_SESSION_EVICT_MS  30000ULL   /* 只有闲置超过这么久才允许被回收 */
#define MAX_MAPPINGS         32
#define MAX_UDP_SESSIONS     96
#define MAX_TCP_CONNS        64
#define MAX_TOTAL_TCP_CONNS  (MAX_TCP_CONNS * 4)   /* 全进程连接总数上限 */
/* 日志控件本身有字符上限，一旦填满 EM_REPLACESEL 就会被静默丢弃，
   表现为"日志不再更新"。所以留出余量，在到达上限前主动清空。 */
#define LOG_MAX_CHARS        100000
#define APP_TIMER_ID         1

#define WM_APP_LOG          (WM_APP + 1)
#define WM_APP_REFRESH      (WM_APP + 2)

#define IDC_HINT            1001
#define IDC_STUN_LABEL      1002
#define IDC_STUN            1003
#define IDC_STUN_FORMAT     1004
#define IDC_KEEPINFO        1005
#define IDC_GROUP           1006
#define IDC_PROTO_LABEL     1007
#define IDC_PROTO           1008
#define IDC_LOCAL_LABEL     1009
#define IDC_LOCAL           1010
#define IDC_LOCAL_HINT      1011
#define IDC_BACKHOST_LABEL  1012
#define IDC_BACKHOST        1013
#define IDC_BACKPORT_LABEL  1014
#define IDC_BACKPORT        1015
#define IDC_NAME_LABEL      1016
#define IDC_NAME            1017
#define IDC_ADD             1018
#define IDC_ADD_HINT        1019
#define IDC_LIST            1020
#define IDC_START           1021
#define IDC_STOP            1022
#define IDC_DELETE          1023
#define IDC_STOPALL         1024
#define IDC_CLEARLOG        1025
#define IDC_LOGLABEL        1026
#define IDC_LOG             1027
#define IDC_STATUS          1028
#define IDC_UPNP            1029
#define IDC_PROXY           1030
#define IDC_PROXY_V1        1031
#define IDC_PROXY_HINT      1032
#define IDC_CONNTABLE       1033
#define IDC_CONNLIST        1034
#define IDC_CONNINFO        1035
#define CONN_TIMER_ID       2
#define IDC_BLACKLIST       1036
#define IDC_BLACKINFO       1037
#define IDC_BLACKEDIT       1038
#define IDC_BLACKADD        1039
#define IDC_BLACKDEL        1040
#define IDC_BLACKCLEAR      1041
#define IDC_BLACKRULELIST   1042
#define IDC_BLACKSTATUS     1043
#define BLACK_TIMER_ID      3

typedef enum _MAP_PROTO {
    PROTO_UDP = 0,
    PROTO_TCP = 1
} MAP_PROTO;

typedef struct _STUN_RESULT {
    unsigned char ip[4];
    unsigned short port;
} STUN_RESULT;

/* 连接表里的一条记录快照（UDP 线程每秒发布一次，受 g_cs 保护） */
typedef struct _CONN_VIEW {
    SOCKADDR_IN peer;
    ULONGLONG start;
    ULONGLONG last_active;
    ULONGLONG bytes_in;
    ULONGLONG bytes_out;
} CONN_VIEW;

typedef struct _TCP_CONN TCP_CONN;
typedef struct _NAT_MAPPING NAT_MAPPING;

struct _TCP_CONN {
    TCP_CONN *next;
    NAT_MAPPING *owner;
    SOCKET client;
    SOCKET backend;
    SOCKADDR_IN backend_addr;   /* 本地服务地址（中继线程里连接） */
    SOCKADDR_IN peer_addr;      /* 对端原始地址（写 PROXY 头用） */
    USHORT local_port;          /* 映射的本地端口（写 PROXY 头用） */
    HANDLE thread;
    volatile LONG closing;
    int head_sent;          /* 等待注入的字节已全部发出 */
    char pending[512];
    int pending_len;
    WCHAR peer[64];
    ULONGLONG start;        /* 建立时刻（NowMs64） */
    ULONGLONG last_active;  /* 最近一次有数据往来，受 g_cs 保护 */
    ULONGLONG bytes_in;     /* 对端 -> 服务，受 g_cs 保护 */
    ULONGLONG bytes_out;    /* 服务 -> 对端，受 g_cs 保护 */
};

struct _NAT_MAPPING {
    NAT_MAPPING *next;
    int id;
    WCHAR name[64];
    MAP_PROTO proto;
    int auto_port;
    USHORT local_port;              /* 0 = 尚未选择 */
    WCHAR backend_host[128];
    USHORT backend_port;
    WCHAR stun_host[128];
    USHORT stun_port;
    HANDLE thread;
    volatile LONG stop;
    volatile LONG running;
    WCHAR status[192];
    WCHAR public_addr[64];
    ULONGLONG last_keepalive;
    ULONGLONG start_time;
    ULONGLONG bytes_in;
    ULONGLONG bytes_out;
    unsigned long pkts_in;
    unsigned long pkts_out;
    unsigned long stun_ok_count;
    unsigned long stun_fail_count;
    int mapping_ok;
    int proxy_protocol;             /* 向服务传递真实源地址 */
    int proxy_v1;                   /* 同时写一份 v1 文本头（给老服务用） */
    int use_upnp;                   /* 创建时是否勾选 UPnP */
    int upnp_mapped;                /* UPnP 映射已建立（受 g_cs 保护） */
    USHORT upnp_ext_port;           /* UPnP 外部端口（受 g_cs 保护） */
    WCHAR upnp_ext_ip[64];          /* UPnP 外部 IP（受 g_cs 保护） */
    TCP_CONN *conns;                /* 受 g_cs 保护 */
    int conn_count;                 /* 受 g_cs 保护 */
    CONN_VIEW udp_view[MAX_UDP_SESSIONS]; /* UDP 会话快照，受 g_cs 保护 */
    int udp_view_count;             /* 受 g_cs 保护 */
};

typedef struct _UDP_SESSION {
    int used;
    SOCKET s;
    SOCKADDR_IN client;
    ULONGLONG last_active;
    ULONGLONG start;
    ULONGLONG bytes_in;             /* 对端 -> 服务 */
    ULONGLONG bytes_out;            /* 服务 -> 对端 */
} UDP_SESSION;

typedef struct _MAP_ROW {
    NAT_MAPPING *m;
    WCHAR name[64];
    WCHAR proto[8];
    WCHAR local[24];
    WCHAR service[192];
    WCHAR public_addr[64];
    WCHAR status[192];
    WCHAR keep[32];
    WCHAR traffic[80];
} MAP_ROW;

/* ------------------------------------------------------------------ */
/* 全局状态                                                            */
/* ------------------------------------------------------------------ */

static HINSTANCE g_hInst = NULL;
static HWND g_hwndMain = NULL;
static HWND g_hwndHint = NULL;
static HWND g_hwndStunLabel = NULL;
static HWND g_hwndStun = NULL;
static HWND g_hwndStunFormat = NULL;
static HWND g_hwndUpnp = NULL;
static HWND g_hwndKeepInfo = NULL;
static HWND g_hwndGroup = NULL;
static HWND g_hwndProtoLabel = NULL;
static HWND g_hwndProto = NULL;
static HWND g_hwndLocalLabel = NULL;
static HWND g_hwndLocal = NULL;
static HWND g_hwndLocalHint = NULL;
static HWND g_hwndBackHostLabel = NULL;
static HWND g_hwndBackHost = NULL;
static HWND g_hwndBackPortLabel = NULL;
static HWND g_hwndBackPort = NULL;
static HWND g_hwndProxy = NULL;
static HWND g_hwndProxyV1 = NULL;
static HWND g_hwndProxyHint = NULL;
static HWND g_hwndNameLabel = NULL;
static HWND g_hwndName = NULL;
static HWND g_hwndAdd = NULL;
static HWND g_hwndAddHint = NULL;
static HWND g_hwndList = NULL;
static HWND g_hwndStart = NULL;
static HWND g_hwndStop = NULL;
static HWND g_hwndDelete = NULL;
static HWND g_hwndStopAll = NULL;
static HWND g_hwndClearLog = NULL;
static HWND g_hwndLogLabel = NULL;
static HWND g_hwndLog = NULL;
static HWND g_hwndStatus = NULL;
static HWND g_hwndConnTable = NULL;
static HWND g_hwndConn = NULL;
static HWND g_hwndConnList = NULL;
static HWND g_hwndConnInfo = NULL;
static NAT_MAPPING *g_connMapping = NULL;
static HWND g_hwndBlackBtn = NULL;      /* 主窗口上的“黑名单”按钮 */
static HWND g_hwndBlack = NULL;
static HWND g_hwndBlackInfo = NULL;
static HWND g_hwndBlackEdit = NULL;
static HWND g_hwndBlackAdd = NULL;
static HWND g_hwndBlackDel = NULL;
static HWND g_hwndBlackClear = NULL;
static HWND g_hwndBlackRuleList = NULL;
static HWND g_hwndBlackStatus = NULL;

static HFONT g_hFont = NULL;
static int g_fontOwned = 0;
static HBRUSH g_bgBrush = NULL;
static CRITICAL_SECTION g_cs;
static NAT_MAPPING *g_maps = NULL;
static int g_mapCount = 0;
static int g_nextId = 0;
static volatile LONG g_appStop = 0;
static volatile LONG g_appStopping = 0;   /* 窗口已开始销毁，不再接收新日志 */
static volatile LONG g_totalTcpConns = 0; /* 全进程 TCP 中继线程总数上限保护 */

/* ------------------------------------------------------------------ */
/* 基础工具                                                            */
/* ------------------------------------------------------------------ */

#if NAT_LEGACY
/* NT4 的 msvcrt 不一定导出 _vsnwprintf；一旦缺这个导入，exe 在加载阶段
   就会直接失败。所以 32 位构建改为运行期取地址，取不到就用下面的内置
   格式化，覆盖本程序实际用到的转换符（d i u x X c s p f I64）。 */
typedef int (__cdecl *NAT_VSNWPRINTF)(WCHAR *, size_t, const WCHAR *, va_list);

static NAT_VSNWPRINTF g_vsnwprintf;
static BOOL g_printfInit;

static void WPutCh(WCHAR *buf, size_t cch, size_t *used, WCHAR c)
{
    if (*used + 1 < cch) {
        buf[*used] = c;
        ++*used;
        buf[*used] = L'\0';
    }
}

static int WIntToStr(WCHAR *out, ULONGLONG v, unsigned base, BOOL upper)
{
    static const WCHAR lowDigits[] = L"0123456789abcdef";
    static const WCHAR upDigits[] = L"0123456789ABCDEF";
    const WCHAR *digits = upper ? upDigits : lowDigits;
    WCHAR tmp[24];
    int n = 0;
    int i;

    do {
        tmp[n++] = digits[(unsigned)(v % base)];
        v /= base;
    } while (v != 0);
    for (i = 0; i < n; ++i)
        out[i] = tmp[n - 1 - i];
    out[n] = L'\0';
    return n;
}

static void WEmitInt(WCHAR *buf, size_t cch, size_t *used, ULONGLONG mag,
                     BOOL neg, unsigned base, BOOL upper,
                     int width, BOOL zero, BOOL left)
{
    WCHAR num[24];
    int n = WIntToStr(num, mag, base, upper);
    int total = n + (neg ? 1 : 0);
    int pad = (width > total) ? width - total : 0;
    int i;

    if (!left && zero) {
        if (neg)
            WPutCh(buf, cch, used, L'-');
        for (i = 0; i < pad; ++i)
            WPutCh(buf, cch, used, L'0');
        for (i = 0; i < n; ++i)
            WPutCh(buf, cch, used, num[i]);
        return;
    }
    if (!left) {
        for (i = 0; i < pad; ++i)
            WPutCh(buf, cch, used, L' ');
    }
    if (neg)
        WPutCh(buf, cch, used, L'-');
    for (i = 0; i < n; ++i)
        WPutCh(buf, cch, used, num[i]);
    if (left) {
        for (i = 0; i < pad; ++i)
            WPutCh(buf, cch, used, L' ');
    }
}

static void WEmitStr(WCHAR *buf, size_t cch, size_t *used, const WCHAR *s,
                     int prec, int width, BOOL left)
{
    int len = 0;
    int pad;
    int i;

    if (s == NULL)
        s = L"(null)";
    while (s[len] != L'\0' && (prec < 0 || len < prec))
        ++len;
    pad = (width > len) ? width - len : 0;
    if (!left) {
        for (i = 0; i < pad; ++i)
            WPutCh(buf, cch, used, L' ');
    }
    for (i = 0; i < len; ++i)
        WPutCh(buf, cch, used, s[i]);
    if (left) {
        for (i = 0; i < pad; ++i)
            WPutCh(buf, cch, used, L' ');
    }
}

static void WFormatV(WCHAR *buf, size_t cch, const WCHAR *fmt, va_list ap)
{
    size_t used = 0;
    const WCHAR *p;

    if (buf == NULL || cch == 0)
        return;
    buf[0] = L'\0';
    if (fmt == NULL)
        return;

    for (p = fmt; *p != L'\0'; ++p) {
        BOOL left = FALSE;
        BOOL zero = FALSE;
        BOOL is64 = FALSE;
        int width = 0;
        int prec = -1;
        WCHAR conv;

        if (*p != L'%') {
            WPutCh(buf, cch, &used, *p);
            continue;
        }
        ++p;
        if (*p == L'%') {
            WPutCh(buf, cch, &used, L'%');
            continue;
        }
        for (;;) {
            if (*p == L'-') {
                left = TRUE;
                ++p;
            } else if (*p == L'0') {
                zero = TRUE;
                ++p;
            } else {
                break;
            }
        }
        while (*p >= L'0' && *p <= L'9') {
            width = width * 10 + (int)(*p - L'0');
            ++p;
        }
        if (*p == L'.') {
            ++p;
            prec = 0;
            while (*p >= L'0' && *p <= L'9') {
                prec = prec * 10 + (int)(*p - L'0');
                ++p;
            }
        }
        if (p[0] == L'I' && p[1] == L'6' && p[2] == L'4') {
            is64 = TRUE;
            p += 3;
        } else if (*p == L'l' || *p == L'h') {
            ++p;
        }
        conv = *p;
        if (conv == L'\0')
            break;

        switch (conv) {
        case L'd':
        case L'i': {
            LONGLONG v = is64 ? va_arg(ap, LONGLONG)
                              : (LONGLONG)va_arg(ap, int);
            BOOL neg = (v < 0) ? TRUE : FALSE;
            ULONGLONG mag = neg ? (ULONGLONG)(-(v + 1)) + 1 : (ULONGLONG)v;

            WEmitInt(buf, cch, &used, mag, neg, 10, FALSE, width, zero, left);
            break;
        }
        case L'u':
        case L'x':
        case L'X': {
            ULONGLONG v = is64 ? va_arg(ap, ULONGLONG)
                               : (ULONGLONG)va_arg(ap, unsigned int);

            WEmitInt(buf, cch, &used, v, FALSE,
                     (conv == L'u') ? 10u : 16u,
                     (conv == L'X') ? TRUE : FALSE,
                     width, zero, left);
            break;
        }
        case L'p': {
            ULONGLONG v = (ULONGLONG)(ULONG_PTR)va_arg(ap, void *);

            WEmitInt(buf, cch, &used, v, FALSE, 16, TRUE,
                     (width > 0) ? width : 8, TRUE, left);
            break;
        }
        case L'f': {
            char nb[80];
            WCHAR wb[80];
            double d = va_arg(ap, double);
            int i;

            _snprintf(nb, sizeof(nb), "%.*f", (prec < 0) ? 6 : prec, d);
            nb[sizeof(nb) - 1] = '\0';
            for (i = 0; i < (int)sizeof(wb) - 1 && nb[i] != '\0'; ++i)
                wb[i] = (WCHAR)(unsigned char)nb[i];
            wb[i] = L'\0';
            WEmitStr(buf, cch, &used, wb, -1, width, left);
            break;
        }
        case L'c': {
            WCHAR cbuf[2];

            cbuf[0] = (WCHAR)va_arg(ap, int);
            cbuf[1] = L'\0';
            WEmitStr(buf, cch, &used, cbuf, -1, width, left);
            break;
        }
        case L's': {
            const WCHAR *s = va_arg(ap, const WCHAR *);

            WEmitStr(buf, cch, &used, s, prec, width, left);
            break;
        }
        default:
            WPutCh(buf, cch, &used, L'%');
            WPutCh(buf, cch, &used, conv);
            break;
        }
    }
}
#endif

static void VWPrintf(WCHAR *buf, size_t cch, const WCHAR *fmt, va_list ap)
{
    if (buf == NULL || cch == 0)
        return;
    buf[0] = L'\0';
#if NAT_LEGACY
    if (!g_printfInit) {
        HMODULE hMod;

        g_printfInit = TRUE;
        hMod = GetModuleHandleA("msvcrt.dll");
        if (hMod == NULL)
            hMod = LoadLibraryA("msvcrt.dll");
        if (hMod != NULL)
            g_vsnwprintf = (NAT_VSNWPRINTF)(void *)
                           GetProcAddress(hMod, "_vsnwprintf");
    }
    if (g_vsnwprintf != NULL)
        g_vsnwprintf(buf, cch - 1, fmt, ap);
    else
        WFormatV(buf, cch, fmt, ap);
#else
    _vsnwprintf(buf, cch - 1, fmt, ap);
#endif
    buf[cch - 1] = L'\0';
}

static void WPrintf(WCHAR *buf, size_t cch, const WCHAR *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    VWPrintf(buf, cch, fmt, ap);
    va_end(ap);
}

/* 单调毫秒时钟。64 位构建直接用 GetTickCount64；NT4 没有这个函数，
   改用 GetTickCount 扩成 64 位，并处理 49.7 天一次的 32 位回绕。
   所有调用点只做差值比较，基准从 0 起算不影响任何逻辑。 */
static ULONGLONG NowMs64(void)
{
#if NAT_LEGACY
    static volatile LONG s_lock = 0;
    static BOOL started = FALSE;
    static DWORD last = 0;
    static ULONGLONG base = 0;
    DWORD t;
    ULONGLONG r;

    while (InterlockedCompareExchange(&s_lock, 1, 0) != 0)
        Sleep(0);
    t = GetTickCount();
    if (!started) {
        started = TRUE;
        last = t;
    } else if (t < last && (DWORD)(last - t) > 0x7FFFFFFFu) {
        base += 0x100000000ULL;
        last = t;
    } else if (t >= last) {
        last = t;
    }
    r = base + t;
    InterlockedExchange(&s_lock, 0);
    return r;
#else
    return GetTickCount64();
#endif
}

static unsigned int NextRand(void)
{
    static volatile LONG counter = 0;
    unsigned int x = (unsigned int)NowMs64();
    unsigned int n = (unsigned int)InterlockedIncrement(&counter);

    x ^= (unsigned int)GetCurrentThreadId() * 2654435761u;
    x ^= n * 2246822519u;
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return x;
}

static unsigned short RandomPort(void)
{
    return (unsigned short)(1024u + (NextRand() % (65535u - 1024u + 1u)));
}

static WCHAR *TrimW(WCHAR *s)
{
    WCHAR *p;
    size_t n;

    if (s == NULL)
        return NULL;
    p = s;
    while (*p != L'\0' && iswspace(*p))
        ++p;
    if (p != s)
        memmove(s, p, (wcslen(p) + 1) * sizeof(WCHAR));
    n = wcslen(s);
    while (n > 0 && iswspace(s[n - 1]))
        s[--n] = L'\0';
    return s;
}

static void CopyW(WCHAR *dst, size_t cch, const WCHAR *src)
{
    size_t n;

    if (dst == NULL || cch == 0)
        return;
    if (src == NULL) {
        dst[0] = L'\0';
        return;
    }
    n = wcslen(src);
    if (n >= cch)
        n = cch - 1;
    memcpy(dst, src, n * sizeof(WCHAR));
    dst[n] = L'\0';
}

static void FormatSystemError(DWORD code, WCHAR *buf, size_t cch)
{
    WCHAR *msg = NULL;
    DWORD n;

    n = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                       FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, code, 0, (LPWSTR)&msg, 0, NULL);
    if (n != 0 && msg != NULL) {
        WCHAR *p = msg;
        size_t len;
        while (*p != L'\0' && iswspace(*p))
            ++p;
        len = wcslen(p);
        while (len > 0 && (p[len - 1] == L'\r' || p[len - 1] == L'\n' ||
                           p[len - 1] == L' ' || p[len - 1] == L'\t'))
            p[--len] = L'\0';
        WPrintf(buf, cch, L"%s", p);
        LocalFree(msg);
    } else {
        WPrintf(buf, cch, L"系统错误 %lu", (unsigned long)code);
    }
}

static void FormatWsaError(int code, WCHAR *buf, size_t cch)
{
    WCHAR tmp[256];

    FormatSystemError((DWORD)code, tmp, sizeof(tmp) / sizeof(tmp[0]));
    WPrintf(buf, cch, L"%s (WSA %d)", tmp, code);
}

static void FormatEndpointW(const STUN_RESULT *r, WCHAR *buf, size_t cch)
{
    WPrintf(buf, cch, L"%u.%u.%u.%u:%u",
            (unsigned)r->ip[0], (unsigned)r->ip[1],
            (unsigned)r->ip[2], (unsigned)r->ip[3],
            (unsigned)r->port);
}

static void FormatSockAddrW(const SOCKADDR_IN *a, WCHAR *buf, size_t cch)
{
    const unsigned char *p = (const unsigned char *)&a->sin_addr.s_addr;

    WPrintf(buf, cch, L"%u.%u.%u.%u:%u",
            (unsigned)p[0], (unsigned)p[1], (unsigned)p[2], (unsigned)p[3],
            (unsigned)ntohs(a->sin_port));
}

static BOOL IsLoopbackIPv4(ULONG addr)
{
    return (BOOL)((ntohl(addr) >> 24) == 127UL);
}

/* 界面上填的地址是不是本机回环：整个 127.0.0.0/8 和 localhost 都算 */
static BOOL IsLoopbackHostText(const WCHAR *host)
{
    char ascii[64];
    IN_ADDR a;

    if (host == NULL)
        return FALSE;
    if (_wcsicmp(host, L"localhost") == 0)
        return TRUE;
    if (WideCharToMultiByte(CP_UTF8, 0, host, -1, ascii, (int)sizeof(ascii),
                            NULL, NULL) <= 0)
        return FALSE;
    a.s_addr = inet_addr(ascii);
    if (a.s_addr == INADDR_NONE)
        return FALSE;
    return IsLoopbackIPv4(a.s_addr);
}

static void AppendLogText(const WCHAR *text);

/* 日志用线程安全队列传递，消息本身只作为"有新日志"的唤醒信号。
   这样即使窗口已经销毁、消息还留在队列里，也不会漏掉 malloc 出来的字符串。 */
typedef struct _LOG_NODE {
    struct _LOG_NODE *next;
    WCHAR text[1];
} LOG_NODE;

static LOG_NODE *g_logHead = NULL;
static LOG_NODE *g_logTail = NULL;
static volatile LONG g_logPosted = 0;

static void FreeLogQueue(void)
{
    LOG_NODE *node;

    EnterCriticalSection(&g_cs);
    node = g_logHead;
    g_logHead = NULL;
    g_logTail = NULL;
    LeaveCriticalSection(&g_cs);

    while (node != NULL) {
        LOG_NODE *next = node->next;
        free(node);
        node = next;
    }
    InterlockedExchange(&g_logPosted, 0);
}

static void AddLog(const WCHAR *fmt, ...)
{
    WCHAR line[2048];
    SYSTEMTIME st;
    size_t used;
    LOG_NODE *node;
    va_list ap;

    if (g_hwndMain == NULL || g_appStopping)
        return;

    GetLocalTime(&st);
    WPrintf(line, 64, L"[%02u:%02u:%02u] ",
            (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond);
    used = wcslen(line);
    va_start(ap, fmt);
    VWPrintf(line + used, (sizeof(line) / sizeof(line[0])) - used - 3, fmt, ap);
    va_end(ap);
    line[(sizeof(line) / sizeof(line[0])) - 3] = L'\0';
    used = wcslen(line);
    if (used + 2 < (sizeof(line) / sizeof(line[0]))) {
        line[used++] = L'\r';
        line[used++] = L'\n';
        line[used] = L'\0';
    }

    node = (LOG_NODE *)malloc(sizeof(LOG_NODE) + wcslen(line) * sizeof(WCHAR));
    if (node == NULL)
        return;
    node->next = NULL;
    wcscpy(node->text, line);

    EnterCriticalSection(&g_cs);
    if (g_logTail != NULL)
        g_logTail->next = node;
    else
        g_logHead = node;
    g_logTail = node;
    LeaveCriticalSection(&g_cs);

    if (InterlockedExchange(&g_logPosted, 1) == 0) {
        if (!PostMessageW(g_hwndMain, WM_APP_LOG, 0, 0))
            InterlockedExchange(&g_logPosted, 0);
    }
}

/* 只在 GUI 线程调用：把队列里的日志全部搬进编辑框 */
static void DrainLogQueue(void)
{
    for (;;) {
        LOG_NODE *node;

        EnterCriticalSection(&g_cs);
        node = g_logHead;
        if (node != NULL) {
            g_logHead = node->next;
            if (g_logHead == NULL)
                g_logTail = NULL;
        }
        LeaveCriticalSection(&g_cs);

        if (node == NULL)
            break;
        AppendLogText(node->text);
        free(node);
    }

    InterlockedExchange(&g_logPosted, 0);

    /* 清空队列期间线程可能又写了新行，补一次唤醒 */
    EnterCriticalSection(&g_cs);
    if (g_logHead != NULL)
        InterlockedExchange(&g_logPosted, 1);
    LeaveCriticalSection(&g_cs);
    if (InterlockedCompareExchange(&g_logPosted, 0, 0) != 0 &&
        g_hwndMain != NULL)
        PostMessageW(g_hwndMain, WM_APP_LOG, 0, 0);
}

static void SetStatus(NAT_MAPPING *m, const WCHAR *fmt, ...)
{
    WCHAR buf[192];
    va_list ap;

    va_start(ap, fmt);
    VWPrintf(buf, sizeof(buf) / sizeof(buf[0]), fmt, ap);
    va_end(ap);
    buf[(sizeof(buf) / sizeof(buf[0])) - 1] = L'\0';

    EnterCriticalSection(&g_cs);
    CopyW(m->status, sizeof(m->status) / sizeof(m->status[0]), buf);
    LeaveCriticalSection(&g_cs);
}

static void NoteStunOk(NAT_MAPPING *m)
{
    EnterCriticalSection(&g_cs);
    m->mapping_ok = 1;
    m->stun_ok_count++;
    m->stun_fail_count = 0;
    LeaveCriticalSection(&g_cs);
}

/* 写入公网地址文本（STUN 与 UPnP 共用）；首次建立或地址变化时写日志 */
static BOOL SetPublicAddressText(NAT_MAPPING *m, const WCHAR *addr)
{
    BOOL changed = FALSE;
    BOOL wasMapped;
    WCHAR oldAddr[64];

    EnterCriticalSection(&g_cs);
    wasMapped = (m->mapping_ok != 0);
    CopyW(oldAddr, sizeof(oldAddr) / sizeof(oldAddr[0]), m->public_addr);
    if (wcscmp(m->public_addr, addr) != 0) {
        CopyW(m->public_addr, sizeof(m->public_addr) / sizeof(m->public_addr[0]), addr);
        changed = TRUE;
    }
    m->mapping_ok = 1;
    LeaveCriticalSection(&g_cs);

    if (changed) {
        if (wasMapped) {
            AddLog(L"[%s] 公网端点已变化: %s -> %s（本地端口没变，是运营商 NAT "
                   L"重新分配了公网端口，旧地址已失效）", m->name, oldAddr, addr);
        } else {
            AddLog(L"[%s] 公网映射已建立: %s", m->name, addr);
        }
    }
    return changed;
}

static BOOL UpdatePublicAddress(NAT_MAPPING *m, const STUN_RESULT *r, WCHAR *addr, size_t addrCch)
{
    FormatEndpointW(r, addr, addrCch);

    EnterCriticalSection(&g_cs);
    m->stun_ok_count++;
    m->stun_fail_count = 0;
    LeaveCriticalSection(&g_cs);

    return SetPublicAddressText(m, addr);
}

/* msvcrt 的 _vsnwprintf 不支持 %llu，用 %I64u 才能安全输出 64 位流量 */
#define FMT_U64 L"%I64u"

/* 自适应单位：不足 1KB 用 B，之后 KB/MB/GB/TB，数字始终控制在几个字符内，
   列表列宽就不会被大流量撑爆或吞掉。 */
static void FormatBytesW(WCHAR *buf, size_t cch, ULONGLONG v)
{
    if (v < 1024ULL) {
        WPrintf(buf, cch, FMT_U64 L" B", (unsigned long long)v);
    } else if (v < 1024ULL * 1024ULL) {
        WPrintf(buf, cch, L"%.1f KB", (double)v / 1024.0);
    } else if (v < 1024ULL * 1024ULL * 1024ULL) {
        WPrintf(buf, cch, L"%.2f MB", (double)v / (1024.0 * 1024.0));
    } else if (v < 1024ULL * 1024ULL * 1024ULL * 1024ULL) {
        WPrintf(buf, cch, L"%.2f GB", (double)v / (1024.0 * 1024.0 * 1024.0));
    } else {
        WPrintf(buf, cch, L"%.2f TB",
                (double)v / (1024.0 * 1024.0 * 1024.0 * 1024.0));
    }
}

static void FormatTraffic(ULONGLONG inBytes, ULONGLONG outBytes, WCHAR *buf, size_t cch)
{
    WCHAR a[32];
    WCHAR b[32];

    FormatBytesW(a, sizeof(a) / sizeof(a[0]), inBytes);
    FormatBytesW(b, sizeof(b) / sizeof(b[0]), outBytes);
    WPrintf(buf, cch, L"入 %s / 出 %s", a, b);
}

/* ------------------------------------------------------------------ */
/* 字符串 / 参数解析                                                   */
/* ------------------------------------------------------------------ */

static BOOL ParsePortText(const WCHAR *text, USHORT *port)
{
    WCHAR tmp[32];
    WCHAR *end = NULL;
    unsigned long v;

    if (text == NULL)
        return FALSE;
    CopyW(tmp, sizeof(tmp) / sizeof(tmp[0]), text);
    TrimW(tmp);
    if (tmp[0] == L'\0')
        return FALSE;
    v = wcstoul(tmp, &end, 10);
    if (end == tmp)
        return FALSE;
    while (*end != L'\0' && iswspace(*end))
        ++end;
    if (*end != L'\0' || v < 1UL || v > 65535UL)
        return FALSE;
    *port = (USHORT)v;
    return TRUE;
}

static BOOL ParseStunEndpoint(const WCHAR *text, WCHAR *host, size_t hostCch,
                              USHORT *port, WCHAR *err, size_t errCch)
{
    WCHAR tmp[192];
    WCHAR *colon;
    WCHAR *firstColon;
    WCHAR portText[32];

    if (text == NULL || host == NULL || port == NULL)
        return FALSE;
    CopyW(tmp, sizeof(tmp) / sizeof(tmp[0]), text);
    TrimW(tmp);
    if (tmp[0] == L'\0') {
        WPrintf(err, errCch, L"STUN 服务器不能为空");
        return FALSE;
    }

    firstColon = wcschr(tmp, L':');
    colon = wcsrchr(tmp, L':');
    if (colon != NULL) {
        if (firstColon != colon) {
            WPrintf(err, errCch, L"暂不支持 IPv6 形式的 STUN 地址，请使用 IPv4:端口");
            return FALSE;
        }
        CopyW(portText, sizeof(portText) / sizeof(portText[0]), colon + 1);
        *colon = L'\0';
        TrimW(tmp);
        if (!ParsePortText(portText, port)) {
            WPrintf(err, errCch, L"STUN 端口无效（应为 1-65535）");
            return FALSE;
        }
    } else {
        *port = DEFAULT_STUN_PORT;
    }

    if (tmp[0] == L'\0') {
        WPrintf(err, errCch, L"STUN 服务器地址不能为空");
        return FALSE;
    }
    if (wcslen(tmp) >= hostCch) {
        WPrintf(err, errCch, L"STUN 服务器地址过长");
        return FALSE;
    }
    wcscpy(host, tmp);
    return TRUE;
}

/* 主机名/点分十进制 -> IPv4。64 位构建走 getaddrinfo；32 位兼容构建
   没有 getaddrinfo（XP 起才有），退回 inet_addr + gethostbyname。
   返回 0 表示成功，-2 表示解析到主机但没有 IPv4 地址，其余为错误码。 */
static int ResolveV4(const char *host, USHORT port, SOCKADDR_IN *out)
{
    if (host == NULL || host[0] == '\0' || out == NULL)
        return -1;
#if NAT_LEGACY
    {
        struct hostent *he;
        unsigned long addr = inet_addr(host);

        if (addr == INADDR_NONE) {
            he = gethostbyname(host);
            if (he == NULL)
                return (int)WSAGetLastError();
            if (he->h_addrtype != AF_INET || he->h_length != 4 ||
                he->h_addr_list == NULL || he->h_addr_list[0] == NULL)
                return -2;
            memcpy(&addr, he->h_addr_list[0], 4);
        }
        ZeroMemory(out, sizeof(*out));
        out->sin_family = AF_INET;
        out->sin_addr.s_addr = addr;
        out->sin_port = htons(port);
        return 0;
    }
#else
    {
        ADDRINFOA hints;
        PADDRINFOA result = NULL;
        int rc;

        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = 0;
        hints.ai_protocol = 0;
        rc = getaddrinfo(host, NULL, &hints, &result);
        if (rc != 0 || result == NULL) {
            if (result != NULL)
                freeaddrinfo(result);
            return (rc != 0) ? rc : -1;
        }
        if (result->ai_addr == NULL ||
            result->ai_addrlen < (int)sizeof(SOCKADDR_IN)) {
            freeaddrinfo(result);
            return -2;
        }
        ZeroMemory(out, sizeof(*out));
        memcpy(out, result->ai_addr, sizeof(SOCKADDR_IN));
        out->sin_family = AF_INET;
        out->sin_port = htons(port);
        freeaddrinfo(result);
        return 0;
    }
#endif
}

static BOOL ResolveIPv4(const WCHAR *host, USHORT port, SOCKADDR_IN *out,
                        WCHAR *err, size_t errCch)
{
    char ahost[512];
    int rc;

    if (host == NULL || host[0] == L'\0') {
        WPrintf(err, errCch, L"地址为空");
        return FALSE;
    }
    /* 用 UTF-8 转换，国际化域名（IDN）不会在 CP_ACP 下变成问号 */
    if (WideCharToMultiByte(CP_UTF8, 0, host, -1, ahost, (int)sizeof(ahost),
                            NULL, NULL) == 0) {
        WPrintf(err, errCch, L"地址转换失败（UTF-8）");
        return FALSE;
    }

    rc = ResolveV4(ahost, port, out);
    if (rc != 0) {
        if (rc == -2)
            WPrintf(err, errCch, L"主机 %s 没有可用的 IPv4 地址", host);
        else
            WPrintf(err, errCch, L"无法解析主机 %s（错误 %d）", host, rc);
        return FALSE;
    }
    return TRUE;
}


/* ------------------------------------------------------------------ */
/* STUN (RFC 5389 Binding Request)                                    */
/* ------------------------------------------------------------------ */

static int BuildStunRequest(unsigned char *buf, unsigned char tid[12])
{
    int i;

    ZeroMemory(buf, 20);
    buf[0] = 0x00;
    buf[1] = 0x01;              /* Binding Request */
    buf[2] = 0x00;
    buf[3] = 0x00;              /* 无属性 */
    buf[4] = 0x21;
    buf[5] = 0x12;
    buf[6] = 0xA4;
    buf[7] = 0x42;              /* Magic Cookie */
    for (i = 0; i < 12; ++i)
        tid[i] = (unsigned char)(NextRand() & 0xffu);
    memcpy(buf + 8, tid, 12);
    return 20;
}

static BOOL ParseStunResponse(const unsigned char *buf, int len,
                              const unsigned char *expectedTid,
                              STUN_RESULT *out, WCHAR *err, size_t errCch)
{
    const unsigned char cookie[4] = { 0x21, 0x12, 0xA4, 0x42 };
    int msgLen;
    int off;
    int foundIpv4 = 0;
    int foundIpv6 = 0;
    int errorCode = 0;

    if (err != NULL && errCch > 0)
        err[0] = L'\0';
    if (buf == NULL || out == NULL)
        return FALSE;
    if (len < 20) {
        WPrintf(err, errCch, L"STUN 响应过短");
        return FALSE;
    }
    if (memcmp(buf + 4, cookie, 4) != 0) {
        WPrintf(err, errCch, L"STUN Magic Cookie 不匹配");
        return FALSE;
    }
    if (expectedTid != NULL && memcmp(buf + 8, expectedTid, 12) != 0) {
        WPrintf(err, errCch, L"STUN 事务 ID 不匹配");
        return FALSE;
    }
    if (buf[0] == 0x01 && buf[1] == 0x11) {
        WPrintf(err, errCch, L"STUN 服务器返回错误响应");
        return FALSE;
    }
    if (buf[0] != 0x01 || buf[1] != 0x01) {
        WPrintf(err, errCch, L"不是 STUN Binding Success 响应");
        return FALSE;
    }

    msgLen = ((int)buf[2] << 8) | (int)buf[3];
    if (msgLen < 0 || msgLen > len - 20)
        msgLen = len - 20;

    off = 20;
    while (off + 4 <= 20 + msgLen) {
        unsigned int attrType = ((unsigned int)buf[off] << 8) | buf[off + 1];
        unsigned int attrLen = ((unsigned int)buf[off + 2] << 8) | buf[off + 3];
        const unsigned char *v = buf + off + 4;

        if (attrLen > (unsigned int)(len - off - 4))
            break;

        if (attrType == 0x0020 || attrType == 0x0001) {
            if (attrLen >= 8 && v[1] == 0x01) {
                unsigned int p = ((unsigned int)v[2] << 8) | v[3];
                unsigned char ip0 = v[4];
                unsigned char ip1 = v[5];
                unsigned char ip2 = v[6];
                unsigned char ip3 = v[7];

                if (attrType == 0x0020) {
                    p ^= 0x2112u;
                    ip0 ^= 0x21;
                    ip1 ^= 0x12;
                    ip2 ^= 0xA4;
                    ip3 ^= 0x42;
                    out->ip[0] = ip0;
                    out->ip[1] = ip1;
                    out->ip[2] = ip2;
                    out->ip[3] = ip3;
                    out->port = (unsigned short)p;
                    foundIpv4 = 1;
                    break;              /* XOR-MAPPED 优先 */
                } else if (!foundIpv4) {
                    out->ip[0] = ip0;
                    out->ip[1] = ip1;
                    out->ip[2] = ip2;
                    out->ip[3] = ip3;
                    out->port = (unsigned short)p;
                    foundIpv4 = 1;
                }
            } else if (attrLen >= 20 && v[1] == 0x02) {
                foundIpv6 = 1;
            }
        } else if (attrType == 0x0009 && attrLen >= 4) {
            errorCode = ((int)(v[2] & 0x07) * 100) + (int)v[3];
        }

        off += 4 + (int)((attrLen + 3u) & ~3u);
    }

    if (!foundIpv4) {
        if (foundIpv6)
            WPrintf(err, errCch, L"STUN 返回 IPv6 地址，本程序仅支持 IPv4");
        else if (errorCode != 0)
            WPrintf(err, errCch, L"STUN 错误码 %d", errorCode);
        else
            WPrintf(err, errCch, L"STUN 响应中没有映射地址");
        return FALSE;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Winsock 辅助                                                        */
/* ------------------------------------------------------------------ */

static BOOL SetNonBlocking(SOCKET s, BOOL nonBlocking)
{
    u_long mode = nonBlocking ? 1UL : 0UL;

    if (s == INVALID_SOCKET)
        return FALSE;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
}

/* 完整发送。WSAENOBUFS（内核缓冲暂时不足）和 WSAEWOULDBLOCK 都属于
   "暂时发不出去"，用 select 等可写后重试，超过 deadline 才判定失败，
   避免把临时拥塞当成连接错误。 */
static BOOL SendAllTimeout(SOCKET s, const char *buf, int len, DWORD timeoutMs)
{
    int sent = 0;
    ULONGLONG deadline = NowMs64() + timeoutMs;

    while (sent < len) {
        int n = send(s, buf + sent, len - sent, 0);
        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();

            if (e == WSAEINTR)
                continue;
            if (e == WSAEWOULDBLOCK || e == WSAENOBUFS) {
                fd_set wfds;
                struct timeval tv;
                int sel;

                if (NowMs64() >= deadline)
                    return FALSE;
                FD_ZERO(&wfds);
                FD_SET(s, &wfds);
                tv.tv_sec = 0;
                tv.tv_usec = 100000;
                sel = select(0, NULL, &wfds, NULL, &tv);
                if (sel == SOCKET_ERROR) {
                    int se = WSAGetLastError();
                    if (se != WSAEINTR)
                        return FALSE;
                }
                continue;
            }
            return FALSE;
        }
        if (n <= 0)
            return FALSE;
        sent += n;
    }
    return TRUE;
}

/* 常规发送：沿用 5 秒上限，任何一端卡死都不会把中继线程永久挂住 */
static BOOL SendAll(SOCKET s, const char *buf, int len)
{
    return SendAllTimeout(s, buf, len, 5000);
}

static int RecvExact(SOCKET s, char *buf, int len)
{
    int got = 0;

    while (got < len) {
        int n = recv(s, buf + got, len - got, 0);
        if (n == 0)
            return 0;
        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEINTR)
                continue;
            return -1;
        }
        if (n < 0)
            return -1;
        got += n;
    }
    return got;
}

static BOOL ConnectWithTimeout(SOCKET s, const SOCKADDR_IN *addr,
                               int timeoutMs, volatile LONG *stop)
{
    int rc;
    int elapsed = 0;
    u_long nonBlocking = 1;
    BOOL ok = FALSE;

    /* 非阻塞设置失败就没法做超时控制，直接放弃本次连接，不能按成功路径继续 */
    if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0)
        return FALSE;
    rc = connect(s, (const SOCKADDR *)addr, (int)sizeof(*addr));
    if (rc == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS && e != WSAEALREADY) {
            SetNonBlocking(s, FALSE);
            return FALSE;
        }
        while (elapsed < timeoutMs) {
            fd_set wfds;
            struct timeval tv;
            int sel;

            if (stop != NULL && InterlockedCompareExchange(stop, 0, 0) != 0) {
                SetNonBlocking(s, FALSE);
                return FALSE;
            }
            FD_ZERO(&wfds);
            FD_SET(s, &wfds);
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            sel = select(0, NULL, &wfds, NULL, &tv);
            if (sel > 0) {
                int soError = 0;
                int soLen = (int)sizeof(soError);
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soError, &soLen) == 0 &&
                    soError == 0) {
                    ok = TRUE;
                }
                break;
            }
            if (sel == SOCKET_ERROR) {
                int selErr = WSAGetLastError();
                if (selErr != WSAEINTR)
                    break;
            }
            elapsed += 100;
        }
    } else {
        ok = TRUE;
    }

    nonBlocking = 0;
    if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0)
        ok = FALSE;   /* 无法恢复阻塞模式，调用方按失败处理并关闭 */
    return ok;
}

static BOOL TcpStunExchange(SOCKET s, STUN_RESULT *out, WCHAR *err, size_t errCch)
{
    unsigned char req[20];
    unsigned char tid[12];
    unsigned char hdr[20];
    unsigned char *msg = NULL;
    int msgLen;
    int got;
    BOOL ok = FALSE;
    DWORD timeout = STUN_STREAM_TIMEOUT_MS;

    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

    BuildStunRequest(req, tid);
    if (!SendAll(s, (const char *)req, (int)sizeof(req))) {
        WPrintf(err, errCch, L"向 STUN 发送 TCP 请求失败");
        return FALSE;
    }

    got = RecvExact(s, (char *)hdr, (int)sizeof(hdr));
    if (got != (int)sizeof(hdr)) {
        WPrintf(err, errCch, L"读取 STUN TCP 响应头失败");
        return FALSE;
    }
    msgLen = ((int)hdr[2] << 8) | (int)hdr[3];
    if (msgLen < 0 || msgLen > 4096) {
        WPrintf(err, errCch, L"STUN TCP 响应长度异常");
        return FALSE;
    }

    msg = (unsigned char *)malloc((size_t)(20 + msgLen));
    if (msg == NULL) {
        WPrintf(err, errCch, L"内存不足");
        return FALSE;
    }
    memcpy(msg, hdr, 20);
    if (msgLen > 0) {
        if (RecvExact(s, (char *)msg + 20, msgLen) != msgLen) {
            WPrintf(err, errCch, L"读取 STUN TCP 响应体失败");
            free(msg);
            return FALSE;
        }
    }

    ok = ParseStunResponse(msg, 20 + msgLen, tid, out, err, errCch);
    free(msg);
    return ok;
}

/* 绑定本地端口。
   shared=FALSE：SO_EXCLUSIVEADDRUSE 独占，用于选端口阶段的可用性验证；
   shared=TRUE ：SO_REUSEADDR 共享，监听 socket 与保活连接必须同时占用
                 同一个本地端口（Windows 上这是两个 socket 共存的前提），
                 也只有这样 NAT 上的映射才不会被反复拆掉重建。 */
static SOCKET TcpBindPort(USHORT port, BOOL shared, WCHAR *err, size_t errCch)
{
    SOCKET s;
    SOCKADDR_IN local;
    BOOL exclusive = TRUE;
    BOOL reuse = TRUE;
    WCHAR e[128];

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        FormatWsaError(WSAGetLastError(), e, sizeof(e) / sizeof(e[0]));
        WPrintf(err, errCch, L"创建 TCP socket 失败: %s", e);
        return INVALID_SOCKET;
    }

    if (!shared) {
        /* 独占端口：别的进程（包括本进程）再用 SO_REUSEADDR 也抢不走 */
        if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                       (const char *)&exclusive, sizeof(exclusive)) == SOCKET_ERROR) {
#if NAT_LEGACY
            /* NT4 SP5 的 winsock 支持这个选项；更老的实现不认它时，
               端口独占性差一点，但绑定本身照常可用，不算失败。 */
#else
            FormatWsaError(WSAGetLastError(), e, sizeof(e) / sizeof(e[0]));
            WPrintf(err, errCch, L"设置端口独占失败: %s", e);
            closesocket(s);
            return INVALID_SOCKET;
#endif
        }
    } else {
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                       (const char *)&reuse, sizeof(reuse)) == SOCKET_ERROR) {
            FormatWsaError(WSAGetLastError(), e, sizeof(e) / sizeof(e[0]));
            WPrintf(err, errCch, L"设置端口共享失败: %s", e);
            closesocket(s);
            return INVALID_SOCKET;
        }
    }

    ZeroMemory(&local, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(s, (const SOCKADDR *)&local, (int)sizeof(local)) == SOCKET_ERROR) {
        FormatWsaError(WSAGetLastError(), e, sizeof(e) / sizeof(e[0]));
        WPrintf(err, errCch, L"绑定本地端口 %u 失败: %s", (unsigned)port, e);
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static SOCKET TcpBindExclusive(USHORT port, WCHAR *err, size_t errCch)
{
    return TcpBindPort(port, FALSE, err, errCch);
}

/* 只验证端口能否独占绑定，不向 STUN 发任何东西；验证完立刻释放端口。
   选好端口后马上会被监听 socket（共享模式）接管，空窗只有毫秒级。 */
static BOOL TcpProbePort(USHORT port, WCHAR *err, size_t errCch)
{
    SOCKET s = TcpBindExclusive(port, err, errCch);

    if (s == INVALID_SOCKET)
        return FALSE;
    closesocket(s);
    return TRUE;
}

/* 立即释放连接：用 linger=0 直接发 RST，避免四元组进入 TIME_WAIT。
   端口上只要还留着 TIME_WAIT 的连接，监听 socket 就绑不上同一个端口
   （除非再开 SO_REUSEADDR，而那正是要避免的东西）。 */
static void TcpPunchClose(SOCKET *psock)
{
    struct linger lg;

    if (psock == NULL || *psock == INVALID_SOCKET)
        return;
    lg.l_onoff = 1;
    lg.l_linger = 0;
    setsockopt(*psock, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof(lg));
    closesocket(*psock);
    *psock = INVALID_SOCKET;
}

/* ------------------------------------------------------------------ */
/* 黑名单                                                              */
/* ------------------------------------------------------------------ */
/* 只在“连接建立”时查一次：TCP 在 accept 之后、UDP 在新建会话之前。
   命中后 TCP 用 linger=0 的 closesocket 立刻发 RST（对方看到连接被重置），
   UDP 直接把数据报丢掉，两者都不再转发给本地服务。已经建立的连接不再复查：
   逐包进临界区查表既费性能，也改变不了“会话已经建立”的事实。

   规则统一解析成 lo/hi 闭区间，地址按网络字节序逐字节比较（等价于数值比较）：
     113.75.1.10                 单个地址
     113.75.*.*                  前缀，等价于 113.75.0.0/16
     113.75                      只写开头，同样按前缀处理（/16）
     113.75.1.0/24               网段
     113.75.1.10-113.75.1.200    起止地址
   只有 IPv4：本程序的映射、STUN、保活全部是 IPv4，没必要留 IPv6 分支。 */
#define BLACK_MAX_RULES  256
#define BLACK_TEXT_CCH   96

typedef struct _BLACK_RULE {
    unsigned char lo[4];            /* 闭区间起点（网络序） */
    unsigned char hi[4];            /* 闭区间终点 */
    WCHAR text[BLACK_TEXT_CCH];     /* 用户输入原文，列表里原样显示 */
    unsigned long hits;             /* 命中次数（受 g_cs 保护） */
} BLACK_RULE;

static BLACK_RULE g_black[BLACK_MAX_RULES];
static int g_blackCount = 0;
static volatile LONG g_blackVersion = 0;  /* 增删后 +1，界面据此决定是否重建列表 */

static void SetBlackError(WCHAR *buf, size_t cch, const WCHAR *msg)
{
    if (buf != NULL && cch > 0)
        CopyW(buf, cch, msg);
}

/* 严格点分十进制：必须正好四段，每段 0-255 */
static BOOL ParseIpv4Strict(const WCHAR *s, unsigned char out[4])
{
    int i;

    for (i = 0; i < 4; ++i) {
        int v = 0;
        int digits = 0;

        while (*s >= L'0' && *s <= L'9') {
            if (digits >= 3)
                return FALSE;
            v = v * 10 + (int)(*s - L'0');
            ++digits;
            ++s;
        }
        if (digits == 0 || v > 255)
            return FALSE;
        out[i] = (unsigned char)v;
        if (i < 3) {
            if (*s != L'.')
                return FALSE;
            ++s;
        }
    }
    return (*s == L'\0') ? TRUE : FALSE;
}

/* 把“前缀 + 位数”展开成闭区间：前缀位保持原样，其余位 0..全 1 */
static void ApplyPrefixRange(unsigned char lo[4], unsigned char hi[4],
                             const unsigned char base[4], int bits)
{
    int i;

    for (i = 0; i < 4; ++i) {
        int remain = bits - i * 8;

        if (remain >= 8) {
            lo[i] = base[i];
            hi[i] = base[i];
        } else if (remain <= 0) {
            lo[i] = 0x00;
            hi[i] = 0xFF;
        } else {
            unsigned char mask = (unsigned char)(0xFFu << (8 - remain));
            unsigned char keep = (unsigned char)(base[i] & mask);

            lo[i] = keep;
            hi[i] = (unsigned char)(keep | (unsigned char)(~mask & 0xFF));
        }
    }
}

/* 把一条用户输入解析成 lo/hi；失败时把原因写进 err */
static BOOL ParseBlackRule(const WCHAR *rule, unsigned char lo[4],
                           unsigned char hi[4], WCHAR *err, size_t errCch)
{
    WCHAR text[BLACK_TEXT_CCH * 2];
    WCHAR left[BLACK_TEXT_CCH * 2];
    WCHAR right[BLACK_TEXT_CCH * 2];
    unsigned char base[4];
    size_t i;
    size_t len;

    SetBlackError(err, errCch, L"规则无法识别");
    if (rule == NULL)
        return FALSE;

    CopyW(text, sizeof(text) / sizeof(text[0]), rule);
    /* 中文输入法可能打出全角符号（＊ ／ ．），先统一成半角再解析 */
    for (i = 0; text[i] != L'\0'; ++i) {
        if (text[i] >= 0xFF01 && text[i] <= 0xFF5E)
            text[i] = (WCHAR)(text[i] - 0xFEE0);
        else if (text[i] == 0x3000)
            text[i] = L' ';
    }
    TrimW(text);
    if (text[0] == L'\0') {
        SetBlackError(err, errCch, L"规则为空");
        return FALSE;
    }

    /* 本程序的映射、STUN、保活全是 IPv4，规则也只认 IPv4：
       带冒号的输入一看就是 IPv6，直接给一句明确的提示 */
    if (wcschr(text, L':') != NULL ||
        wcscmp(text, L"****") == 0) {
        SetBlackError(err, errCch,
                      L"只支持 IPv4 网段，例如 113.75.*.*；屏蔽全部写 0.0.0.0/0");
        return FALSE;
    }

    /* 1. 起止地址 113.75.1.10-113.75.1.200 */
    {
        const WCHAR *dash = wcschr(text, L'-');

        if (dash != NULL) {
            if (wcschr(text, L'/') != NULL) {
                SetBlackError(err, errCch, L"范围里不能再带 /");
                return FALSE;
            }
            len = (size_t)(dash - text);
            if (len >= sizeof(left) / sizeof(left[0])) {
                SetBlackError(err, errCch, L"规则太长");
                return FALSE;
            }
            memcpy(left, text, len * sizeof(WCHAR));
            left[len] = L'\0';
            CopyW(right, sizeof(right) / sizeof(right[0]), dash + 1);
            TrimW(left);
            TrimW(right);
            if (left[0] == L'\0' || right[0] == L'\0') {
                SetBlackError(err, errCch, L"范围的起止地址都要写全");
                return FALSE;
            }
            if (!ParseIpv4Strict(left, lo) || !ParseIpv4Strict(right, hi)) {
                SetBlackError(err, errCch, L"IPv4 地址格式错误（范围两端都要写全）");
                return FALSE;
            }
            if (memcmp(lo, hi, 4) > 0) {
                SetBlackError(err, errCch, L"范围起点不能大于终点");
                return FALSE;
            }
            return TRUE;
        }
    }

    /* 2. 网段 113.75.1.0/24 */
    {
        const WCHAR *slash = wcschr(text, L'/');

        if (slash != NULL) {
            long bits = 0;
            int digits = 0;
            const WCHAR *q;

            len = (size_t)(slash - text);
            if (len >= sizeof(left) / sizeof(left[0])) {
                SetBlackError(err, errCch, L"规则太长");
                return FALSE;
            }
            memcpy(left, text, len * sizeof(WCHAR));
            left[len] = L'\0';
            TrimW(left);
            for (q = slash + 1; *q != L'\0'; ++q) {
                if (*q < L'0' || *q > L'9' || digits >= 3) {
                    SetBlackError(err, errCch, L"/ 后面只能是 0-32 的数字");
                    return FALSE;
                }
                bits = bits * 10 + (long)(*q - L'0');
                ++digits;
            }
            if (digits == 0 || bits > 32) {
                SetBlackError(err, errCch, L"IPv4 前缀长度必须在 0-32 之间");
                return FALSE;
            }
            if (!ParseIpv4Strict(left, base)) {
                SetBlackError(err, errCch, L"IPv4 地址格式错误");
                return FALSE;
            }
            ApplyPrefixRange(lo, hi, base, (int)bits);
            return TRUE;
        }
    }

    /* 3. 只写开头 / 通配：113.75.*.* 与 113.75 都按 /16 处理 */
    {
        const WCHAR *q = text;
        int parts = 0;
        int wildcard = 0;

        ZeroMemory(base, sizeof(base));
        for (;;) {
            const WCHAR *end = q;
            int v = 0;
            int digits = 0;

            while (*end != L'\0' && *end != L'.')
                ++end;
            if (*q == L'*') {
                if (end != q + 1) {
                    SetBlackError(err, errCch, L"* 必须单独占一段，例如 113.75.*.*");
                    return FALSE;
                }
                wildcard = 1;
            } else {
                const WCHAR *t = q;

                if (wildcard) {
                    SetBlackError(err, errCch, L"* 只能出现在末尾，例如 113.75.*.*");
                    return FALSE;
                }
                while (t < end && *t >= L'0' && *t <= L'9') {
                    v = v * 10 + (int)(*t - L'0');
                    ++digits;
                    ++t;
                }
                if (t != end) {
                    SetBlackError(err, errCch, L"IPv4 规则里只能有数字、点和 *");
                    return FALSE;
                }
                if (digits == 0) {
                    SetBlackError(err, errCch, L"IPv4 地址里有一段是空的");
                    return FALSE;
                }
                if (v > 255 || digits > 3) {
                    SetBlackError(err, errCch, L"IPv4 每段必须在 0-255 之间");
                    return FALSE;
                }
                if (parts >= 4) {
                    SetBlackError(err, errCch, L"IPv4 地址最多四段");
                    return FALSE;
                }
                base[parts] = (unsigned char)v;
                ++parts;
            }
            q = end;
            if (*q == L'\0')
                break;
            ++q;                    /* 跳过 '.' */
            if (*q == L'\0') {
                SetBlackError(err, errCch, L"结尾多了一个点");
                return FALSE;
            }
        }
        ApplyPrefixRange(lo, hi, base, parts * 8);
        return TRUE;
    }
}

/* 连接建立时调用一次。命中返回 TRUE，并给对应规则累加命中数 */
static BOOL BlacklistMatchAddress(const void *addr)
{
    const unsigned char *a = (const unsigned char *)addr;
    int i;
    BOOL hit = FALSE;

    if (a == NULL)
        return FALSE;
    EnterCriticalSection(&g_cs);
    for (i = 0; i < g_blackCount; ++i) {
        BLACK_RULE *r = &g_black[i];

        if (memcmp(a, r->lo, 4) < 0)
            continue;
        if (memcmp(a, r->hi, 4) > 0)
            continue;
        r->hits++;
        hit = TRUE;
        break;
    }
    LeaveCriticalSection(&g_cs);
    return hit;
}

/* 保活连接：和监听 socket 共享同一个本地端口（SO_REUSEADDR），
   连到 TCP_KEEPER_HOST 长期挂着。运营商 NAT 上的映射由这条连接持有，
   只要它不断，公网端口就不会变。 */
static SOCKET TcpOpenKeeper(USHORT port, volatile LONG *stop,
                            WCHAR *err, size_t errCch)
{
    SOCKET s;
    WCHAR e[128];
    SOCKADDR_IN target;
    char hostA[64];
    int rc;

    if (WideCharToMultiByte(CP_UTF8, 0, TCP_KEEPER_HOST, -1, hostA,
                            (int)sizeof(hostA), NULL, NULL) <= 0) {
        WPrintf(err, errCch, L"保活目标地址无效");
        return INVALID_SOCKET;
    }
    rc = ResolveV4(hostA, TCP_KEEPER_PORT, &target);
    if (rc != 0) {
        WPrintf(err, errCch, L"解析保活目标 %s 失败（%d）", TCP_KEEPER_HOST, rc);
        return INVALID_SOCKET;
    }

    s = TcpBindPort(port, TRUE, err, errCch);
    if (s == INVALID_SOCKET)
        return INVALID_SOCKET;

    if (!ConnectWithTimeout(s, &target, KEEPER_CONNECT_TIMEOUT_MS, stop)) {
        int code = WSAGetLastError();

        if (code != 0) {
            FormatWsaError(code, e, sizeof(e) / sizeof(e[0]));
            WPrintf(err, errCch, L"连接保活目标 %s:%d 失败: %s",
                    TCP_KEEPER_HOST, TCP_KEEPER_PORT, e);
        } else {
            /* 超时路径上 select 不一定设置错误码，别显示成"操作成功完成" */
            WPrintf(err, errCch, L"连接保活目标 %s:%d 超时",
                    TCP_KEEPER_HOST, TCP_KEEPER_PORT);
        }
        TcpPunchClose(&s);
        return INVALID_SOCKET;
    }
    return s;
}

/* 从本地端口拉起监听。必须用共享绑定，才能和保活连接同时占用这个端口；
   端口刚被探测 socket 释放时系统偶尔延迟回收，所以短暂重试。 */
static SOCKET TcpOpenListener(USHORT port, WCHAR *err, size_t errCch)
{
    int attempt;

    for (attempt = 0; attempt < 20; ++attempt) {
        SOCKET s = TcpBindPort(port, TRUE, err, errCch);

        if (s != INVALID_SOCKET) {
            if (listen(s, SOMAXCONN) == SOCKET_ERROR) {
                WCHAR e[128];

                FormatWsaError(WSAGetLastError(), e, sizeof(e) / sizeof(e[0]));
                WPrintf(err, errCch, L"listen 失败: %s", e);
                closesocket(s);
                return INVALID_SOCKET;
            }
            if (!SetNonBlocking(s, TRUE)) {
                WCHAR e[128];

                FormatWsaError(WSAGetLastError(), e, sizeof(e) / sizeof(e[0]));
                WPrintf(err, errCch, L"设置非阻塞失败: %s", e);
                closesocket(s);
                return INVALID_SOCKET;
            }
            return s;
        }
        Sleep(50);
    }
    return INVALID_SOCKET;
}

/* 在保活连接上发一次 HTTP HEAD：定期有报文往返，HTTP 服务器和应用层都
   不会把这条空闲连接掐掉，NAT 映射因此长期不被回收。 */
static BOOL TcpKeeperPing(SOCKET s)
{
    char req[192];
    char buf[512];
    int len;
    int i;

    len = _snprintf(req, sizeof(req),
                    "HEAD / HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "Connection: keep-alive\r\n"
                    "User-Agent: " NAT_PRODUCT_A "\r\n\r\n",
                    TCP_KEEPER_HOST_A);
    if (len <= 0)
        return FALSE;
    if (!SendAllTimeout(s, req, len, 3000))
        return FALSE;

    /* 把响应读干净（HEAD 没有正文，几 K 以内），避免接收队列越堆越满 */
    for (i = 0; i < 8; ++i) {
        fd_set rfds;
        struct timeval tv;
        int sel;
        int n;

        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        sel = select(0, &rfds, NULL, NULL, &tv);
        if (sel <= 0)
            break;
        n = recv(s, buf, (int)sizeof(buf), 0);
        if (n <= 0)
            return FALSE;   /* 对端关闭或出错：交给调用方重连 */
        if (n < (int)sizeof(buf))
            break;
    }
    return TRUE;
}

/* 用一条临时连接查询公网端点：和监听/保活连接共享同一本地端口。
   运营商 NAT 是端点无关映射，所以这条连接看到的公网端口就是整条映射的端口；
   查完正常关闭（只发 FIN 不发 RST），不影响 keeper 持有的映射。 */
static BOOL TcpStunQueryShared(USHORT port, const SOCKADDR_IN *stun,
                               STUN_RESULT *out, WCHAR *err, size_t errCch)
{
    SOCKET s;
    BOOL ok;

    s = TcpBindPort(port, TRUE, err, errCch);
    if (s == INVALID_SOCKET)
        return FALSE;
    if (!ConnectWithTimeout(s, stun, STUN_CONNECT_TIMEOUT_MS, NULL)) {
        int code = WSAGetLastError();

        if (code != 0) {
            WCHAR e[128];

            FormatWsaError(code, e, sizeof(e) / sizeof(e[0]));
            WPrintf(err, errCch, L"连接 STUN 服务器失败: %s", e);
        } else {
            WPrintf(err, errCch, L"连接 STUN 服务器超时");
        }
        closesocket(s);
        return FALSE;
    }
    ok = TcpStunExchange(s, out, err, errCch);
    closesocket(s);
    return ok;
}

/* ------------------------------------------------------------------ */
/* UPnP IGD（Internet Gateway Device）自动端口映射                     */
/*                                                                     */
/* 流程: SSDP 搜索网关 -> 读取设备描述 -> SOAP AddPortMapping/续约/删除 */
/* 说明: 只处理 IGD:1 的 WANIPConnection / WANPPPConnection 服务。      */
/* ------------------------------------------------------------------ */

#define UPNP_SSDP_ADDR          "239.255.255.250"
#define UPNP_SSDP_PORT          1900
#define UPNP_LEASE_SECONDS      3600
#define UPNP_RENEW_MS           (1500ULL * 1000ULL)   /* 25 分钟续约一次 */
#define UPNP_RETRY_MS           (60ULL * 1000ULL)     /* 失败 1 分钟后重试 */
#define UPNP_SCAN_MS            (300ULL * 1000ULL)    /* 网关信息 5 分钟内复用 */
#define UPNP_HTTP_TIMEOUT_MS    4000
#define UPNP_XML_MAX            65536
#define UPNP_RESP_MAX           8192

typedef struct _UPNP_GATEWAY {
    int available;
    ULONGLONG scanned_at;
    ULONGLONG last_fail_at;
    char control_url[512];
    char service_type[160];
    char external_ip[64];
    WCHAR last_err[192];
} UPNP_GATEWAY;

static UPNP_GATEWAY g_upnp;
static HANDLE g_upnp_lock = NULL;

static HANDLE UpnpLockHandle(void)
{
    /* 自动复位事件当作互斥量使用；用 g_cs 保护惰性创建 */
    if (g_upnp_lock == NULL) {
        EnterCriticalSection(&g_cs);
        if (g_upnp_lock == NULL)
            g_upnp_lock = CreateEventW(NULL, FALSE, TRUE, NULL);
        LeaveCriticalSection(&g_cs);
    }
    return g_upnp_lock;
}

/* 拿不到锁要明确失败：以前拿不到也照常往下走，等于同时有两个线程
   在改网关状态，Add/Delete 会互相覆盖。 */
static BOOL UpnpLock(void)
{
    HANDLE h = UpnpLockHandle();

    if (h == NULL)
        return FALSE;
    return (WaitForSingleObject(h, 20000) == WAIT_OBJECT_0) ? TRUE : FALSE;
}

static void UpnpUnlock(void)
{
    if (g_upnp_lock != NULL)
        SetEvent(g_upnp_lock);
}

static void CopyAscii(char *dst, size_t cch, const char *src)
{
    size_t i = 0;

    if (dst == NULL || cch == 0)
        return;
    if (src != NULL) {
        while (src[i] != '\0' && i + 1 < cch) {
            dst[i] = src[i];
            ++i;
        }
    }
    dst[i] = '\0';
}

static void AsciiToW(const char *s, WCHAR *out, size_t cch)
{
    size_t i = 0;

    if (out == NULL || cch == 0)
        return;
    if (s != NULL) {
        while (s[i] != '\0' && i + 1 < cch) {
            out[i] = (WCHAR)(unsigned char)s[i];
            ++i;
        }
    }
    out[i] = L'\0';
}

/* _snprintf 在被截断时返回负数、且不保证写结尾 NUL。统一走这个包装：
   截断就返回 FALSE，调用方按"内容超长"处理，不再发出半截请求。 */
static BOOL SnprintfA(char *buf, size_t cch, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (buf == NULL || cch == 0)
        return FALSE;
    va_start(ap, fmt);
    n = _vsnprintf(buf, cch, fmt, ap);
    va_end(ap);
    buf[cch - 1] = '\0';
    return (n >= 0 && (size_t)n < cch) ? TRUE : FALSE;
}

typedef struct _HTTP_URL {
    char host[256];
    USHORT port;
    char path[512];
} HTTP_URL;

static BOOL ParseHttpUrl(const char *url, HTTP_URL *out)
{
    const char *p;
    const char *slash;
    char *colon;
    size_t host_len;

    if (url == NULL || out == NULL)
        return FALSE;
    ZeroMemory(out, sizeof(*out));
    if (_strnicmp(url, "http://", 7) != 0)
        return FALSE;
    p = url + 7;
    slash = strchr(p, '/');
    host_len = (slash != NULL) ? (size_t)(slash - p) : strlen(p);
    if (host_len == 0 || host_len >= sizeof(out->host))
        return FALSE;
    memcpy(out->host, p, host_len);
    out->host[host_len] = '\0';
    out->port = 80;
    colon = strchr(out->host, ':');
    if (colon != NULL) {
        int v = atoi(colon + 1);
        *colon = '\0';
        if (v > 0 && v <= 65535)
            out->port = (USHORT)v;
    }
    if (slash != NULL) {
        if (strlen(slash) >= sizeof(out->path))
            return FALSE;
        strcpy(out->path, slash);
    } else {
        strcpy(out->path, "/");
    }
    return TRUE;
}

static BOOL ResolveHostA(const char *host, USHORT port, SOCKADDR_IN *out)
{
    return ResolveV4(host, port, out) == 0;
}

static BOOL FindHeader(const char *resp, const char *name, char *out, size_t cch);

static int HttpExchange(const char *url, const char *request, char *resp,
                        size_t resp_cch, WCHAR *err, size_t err_cch)
{
    HTTP_URL u;
    SOCKADDR_IN addr;
    SOCKET s;
    DWORD timeout = UPNP_HTTP_TIMEOUT_MS;
    int total = 0;
    int status = -1;

    if (resp_cch < 2)
        return -1;
    resp[0] = '\0';
    if (!ParseHttpUrl(url, &u)) {
        WPrintf(err, err_cch, L"UPnP 控制地址无效");
        return -1;
    }
    if (!ResolveHostA(u.host, u.port, &addr)) {
        WPrintf(err, err_cch, L"无法解析 UPnP 网关地址");
        return -1;
    }
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        WPrintf(err, err_cch, L"创建 UPnP socket 失败");
        return -1;
    }
    if (!ConnectWithTimeout(s, &addr, UPNP_HTTP_TIMEOUT_MS, NULL)) {
        closesocket(s);
        WPrintf(err, err_cch, L"连接 UPnP 网关失败");
        return -1;
    }
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    if (!SendAll(s, request, (int)strlen(request))) {
        closesocket(s);
        WPrintf(err, err_cch, L"向 UPnP 网关发送请求失败");
        return -1;
    }
    /* 有 Content-Length 就按它收够为止；没有才读到对端关闭。
       以前一律读到关闭，遇到 keep-alive 网关会一直等到超时。 */
    {
        int headerLen = 0;
        int contentLen = -1;
        int scanned = 0;

        for (;;) {
            int room = (int)resp_cch - 1 - total;
            int n;

            if (room <= 0)
                break;
            n = recv(s, resp + total, room, 0);
            if (n == SOCKET_ERROR) {
                int e = WSAGetLastError();
                if (e == WSAEINTR)
                    continue;
                break;
            }
            if (n <= 0)
                break;
            total += n;
            resp[total] = '\0';

            if (headerLen == 0 && total >= scanned) {
                char *sep = strstr(resp, "\r\n\r\n");

                if (sep != NULL) {
                    char cl[32];

                    headerLen = (int)(sep - resp) + 4;
                    if (FindHeader(resp, "Content-Length", cl, sizeof(cl))) {
                        contentLen = atoi(cl);
                        if (contentLen < 0)
                            contentLen = -1;
                    }
                } else if (total > 32768) {
                    break;      /* 头部过长，明显不是正常的 IGD 响应 */
                }
            }
            scanned = total;
            if (headerLen > 0 && contentLen >= 0 && total >= headerLen + contentLen)
                break;
        }
    }
    closesocket(s);
    resp[total] = '\0';
    if (total == 0) {
        WPrintf(err, err_cch, L"UPnP 网关无响应");
        return -1;
    }
    if (total > 12 && _strnicmp(resp, "HTTP/", 5) == 0)
        status = atoi(resp + 9);
    return status;
}

static char *HttpBody(char *resp)
{
    char *p = strstr(resp, "\r\n\r\n");

    if (p == NULL)
        return NULL;
    return p + 4;
}

static BOOL FindHeader(const char *resp, const char *name, char *out, size_t cch)
{
    const char *p = resp;
    size_t name_len = strlen(name);

    if (out != NULL && cch > 0)
        out[0] = '\0';
    if (resp == NULL || name_len == 0 || cch == 0)
        return FALSE;
    while (p != NULL && *p != '\0') {
        const char *eol = strchr(p, '\n');
        size_t line_len = (eol != NULL) ? (size_t)(eol - p) : strlen(p);
        const char *line = p;

        if (line_len > 0 && line[line_len - 1] == '\r')
            --line_len;
        if (line_len > name_len && _strnicmp(line, name, name_len) == 0 &&
            line[name_len] == ':') {
            const char *v = line + name_len + 1;
            const char *vend = line + line_len;
            size_t vlen;

            while (v < vend && (*v == ' ' || *v == '\t'))
                ++v;
            while (vend > v && (vend[-1] == ' ' || vend[-1] == '\t' ||
                                vend[-1] == '\r'))
                --vend;
            vlen = (size_t)(vend - v);
            if (vlen >= cch)
                vlen = cch - 1;
            memcpy(out, v, vlen);
            out[vlen] = '\0';
            return TRUE;
        }
        p = (eol != NULL) ? eol + 1 : NULL;
    }
    return FALSE;
}

/* 到指定目的地址（网络字节序）所用的本机地址，用来锁定组播出接口 */
static ULONG LocalAddressForDest(ULONG dest_net)
{
    SOCKET s;
    SOCKADDR_IN dst;
    SOCKADDR_IN me;
    int len = (int)sizeof(me);
    ULONG result = 0;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
        return 0;
    ZeroMemory(&dst, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    dst.sin_addr.s_addr = dest_net;
    if (connect(s, (const SOCKADDR *)&dst, (int)sizeof(dst)) == 0 &&
        getsockname(s, (SOCKADDR *)&me, &len) == 0)
        result = me.sin_addr.s_addr;
    closesocket(s);
    return result;
}

#if NAT_LEGACY
/* NT4 没有 iphlpapi.dll（GetBestRoute 是 2000 才有的），改从 TCP/IP 参数
   注册表键里读默认网关。多网卡/VPN 时优先挑与本机同子网的那个，避免把
   组播和单播探针发到错误的网卡上。 */
static BOOL GatewayFromRegistry(ULONG preferred, ULONG *out)
{
    HKEY hk;
    DWORD index;
    BOOL found = FALSE;
    ULONG first = 0;
    WCHAR sub[256];

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
                      0, KEY_READ, &hk) != ERROR_SUCCESS)
        return FALSE;

    for (index = 0; !found; ++index) {
        DWORD cch = (DWORD)(sizeof(sub) / sizeof(sub[0]));
        HKEY hsub;
        static const WCHAR *const names[2] = {
            L"DhcpDefaultGateway", L"DefaultGateway"
        };
        int n;

        if (RegEnumKeyExW(hk, index, sub, &cch, NULL, NULL, NULL, NULL)
                != ERROR_SUCCESS)
            break;
        if (RegOpenKeyExW(hk, sub, 0, KEY_READ, &hsub) != ERROR_SUCCESS)
            continue;
        for (n = 0; n < 2 && !found; ++n) {
            BYTE data[512];
            DWORD cb = (DWORD)sizeof(data);
            DWORD type = 0;

            if (RegQueryValueExW(hsub, names[n], NULL, &type, data, &cb)
                    != ERROR_SUCCESS)
                continue;
            if (type != REG_MULTI_SZ && type != REG_SZ)
                continue;
            {
                const WCHAR *p = (const WCHAR *)data;
                const WCHAR *end = (const WCHAR *)(data + cb);

                while (p < end && *p != L'\0') {
                    char a[32];
                    int k = 0;
                    ULONG addr;

                    while (k < (int)sizeof(a) - 1 && p[k] != L'\0') {
                        a[k] = (char)p[k];
                        ++k;
                    }
                    a[k] = '\0';
                    addr = (ULONG)inet_addr(a);
                    if (addr != INADDR_NONE && addr != 0) {
                        if ((addr & 0xFFFFFF00UL) ==
                            (preferred & 0xFFFFFF00UL)) {
                            *out = addr;
                            found = TRUE;
                            break;
                        }
                        if (first == 0)
                            first = addr;
                    }
                    p += k + 1;
                }
            }
        }
        RegCloseKey(hsub);
    }
    RegCloseKey(hk);
    if (!found && first != 0) {
        *out = first;
        found = TRUE;
    }
    return found;
}
#endif

static BOOL GetDefaultGatewayIPv4(ULONG dest_net, ULONG *out)
{
#if NAT_LEGACY
    ULONG local;

    if (out == NULL)
        return FALSE;
    *out = 0;
    local = LocalAddressForDest(dest_net);
    return GatewayFromRegistry(local, out);
#else
    MIB_IPFORWARDROW row;
    DWORD rc;

    if (out == NULL)
        return FALSE;
    *out = 0;
    ZeroMemory(&row, sizeof(row));
    rc = GetBestRoute(dest_net, 0, &row);
    if (rc == NO_ERROR && row.dwForwardNextHop != 0) {
        *out = row.dwForwardNextHop;
        return TRUE;
    }
    return FALSE;
#endif
}

/* 只信任局域网内的 SSDP 响应：公网上任何人都能给 239.255.255.250 回包，
   不校验来源就等于让外部主机指定我们的 UPnP 控制地址。 */
static BOOL IsPrivateIPv4(ULONG addr_net)
{
    ULONG v = ntohl(addr_net);
    unsigned a = (unsigned)((v >> 24) & 0xFF);
    unsigned b = (unsigned)((v >> 16) & 0xFF);

    if (a == 10 || a == 127)
        return TRUE;
    if (a == 172 && b >= 16 && b <= 31)
        return TRUE;
    if (a == 192 && b == 168)
        return TRUE;
    if (a == 169 && b == 254)
        return TRUE;
    if (a == 100 && b >= 64 && b <= 127)
        return TRUE;
    return FALSE;
}

static BOOL SsdpSourceTrusted(const SOCKADDR_IN *from, const SOCKADDR_IN *dst,
                              ULONG local_addr, ULONG gateway)
{
    ULONG a = from->sin_addr.s_addr;

    if (a == 0 || a == INADDR_BROADCAST || a == INADDR_NONE)
        return FALSE;
    if (dst->sin_addr.s_addr != inet_addr(UPNP_SSDP_ADDR))
        return (a == dst->sin_addr.s_addr) ? TRUE : FALSE;   /* 单播：只认网关 */
    if (gateway != 0 && a == gateway)
        return TRUE;
    if (IsPrivateIPv4(a))
        return TRUE;
    return FALSE;
}

/* 发出 M-SEARCH 并收集响应；返回是否找到 LOCATION */
static BOOL SsdpProbe(SOCKET s, const SOCKADDR_IN *dst, const char *host_text,
                      const char *st, ULONGLONG wait_ms, char *location, size_t cch,
                      int *sent, int *received, int *send_error,
                      ULONG local_addr, ULONG gateway)
{
    char req[512];
    ULONGLONG deadline;
    int i;

    if (!SnprintfA(req, sizeof(req),
                   "M-SEARCH * HTTP/1.1\r\n"
                   "HOST: %s:%u\r\n"
                   "MAN: \"ssdp:discover\"\r\n"
                   "MX: 2\r\n"
                   "ST: %s\r\n"
                   "\r\n",
                   host_text, (unsigned)UPNP_SSDP_PORT, st)) {
        *send_error = WSAEMSGSIZE;
        return FALSE;
    }

    for (i = 0; i < 3; ++i) {
        if (sendto(s, req, (int)strlen(req), 0, (const SOCKADDR *)dst,
                   (int)sizeof(*dst)) == SOCKET_ERROR) {
            *send_error = WSAGetLastError();
        } else {
            ++(*sent);
        }
    }

    deadline = NowMs64() + wait_ms;
    while (NowMs64() < deadline) {
        fd_set rfds;
        struct timeval tv;
        int sel;

        FD_ZERO(&rfds);
        FD_SET(s, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        sel = select(0, &rfds, NULL, NULL, &tv);
        if (sel <= 0)
            continue;
        if (FD_ISSET(s, &rfds)) {
            char buf[2048];
            SOCKADDR_IN from;
            int from_len = (int)sizeof(from);
            int n = recvfrom(s, buf, (int)sizeof(buf) - 1, 0,
                             (SOCKADDR *)&from, &from_len);
            if (n <= 0)
                continue;
            ++(*received);
            buf[n] = '\0';
            if (!SsdpSourceTrusted(&from, dst, local_addr, gateway))
                continue;
            if (FindHeader(buf, "LOCATION", location, cch) &&
                location[0] != '\0' &&
                _strnicmp(location, "http://", 7) == 0)
                return TRUE;
        }
    }
    return FALSE;
}

static BOOL SsdpFindLocation(char *location, size_t cch, WCHAR *err, size_t err_cch)
{
    const char *targets[2];
    SOCKET s;
    int t;
    BOOL found = FALSE;
    int sent = 0;
    int received = 0;
    int send_error = 0;
    SOCKADDR_IN mcast;
    ULONG local_addr;
    ULONG gateway = 0;

    targets[0] = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
    targets[1] = "upnp:rootdevice";

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        WPrintf(err, err_cch, L"创建 SSDP socket 失败");
        return FALSE;
    }
    {
        SOCKADDR_IN local;
        ZeroMemory(&local, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = 0;
        if (bind(s, (const SOCKADDR *)&local, (int)sizeof(local)) != 0) {
            closesocket(s);
            WPrintf(err, err_cch, L"绑定 SSDP 端口失败");
            return FALSE;
        }
    }
    SetNonBlocking(s, TRUE);   /* 失败也没关系：select 已经保证了读超时 */

    /* 多网卡（VPN / Hyper-V / WSL）时组播默认可能走错网卡，
       这里锁定到“能到达公网的那个本地地址”。 */
    local_addr = LocalAddressForDest(inet_addr("8.8.8.8"));
    if (local_addr != 0)
        setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,
                   (const char *)&local_addr, sizeof(local_addr));
    GetDefaultGatewayIPv4(inet_addr("8.8.8.8"), &gateway);

    ZeroMemory(&mcast, sizeof(mcast));
    mcast.sin_family = AF_INET;
    mcast.sin_port = htons(UPNP_SSDP_PORT);
    mcast.sin_addr.s_addr = inet_addr(UPNP_SSDP_ADDR);

    for (t = 0; t < 2 && !found; ++t) {
        found = SsdpProbe(s, &mcast, UPNP_SSDP_ADDR, targets[t], 1500,
                          location, cch, &sent, &received, &send_error,
                          local_addr, gateway);
    }

    /* 有些路由器（固件）只回应单播 M-SEARCH，组播一律不理。 */
    if (!found && gateway != 0 && gateway != local_addr) {
        SOCKADDR_IN unicast;
        char gw_text[32];
        const unsigned char *gp = (const unsigned char *)&gateway;

        SnprintfA(gw_text, sizeof(gw_text), "%u.%u.%u.%u",
                  (unsigned)gp[0], (unsigned)gp[1], (unsigned)gp[2],
                  (unsigned)gp[3]);
        ZeroMemory(&unicast, sizeof(unicast));
        unicast.sin_family = AF_INET;
        unicast.sin_port = htons(UPNP_SSDP_PORT);
        unicast.sin_addr.s_addr = gateway;
        for (t = 0; t < 2 && !found; ++t) {
            found = SsdpProbe(s, &unicast, gw_text, targets[t], 1000,
                              location, cch, &sent, &received, &send_error,
                              local_addr, gateway);
        }
    }
    closesocket(s);
    if (!found) {
        if (sent == 0)
            WPrintf(err, err_cch, L"SSDP 请求发送失败（WSA %d）", send_error);
        else
            WPrintf(err, err_cch,
                    L"SSDP 未发现 UPnP 网关（发送 %d 次，收到 %d 个响应）",
                    sent, received);
    }
    return found;
}

/* 找开始标签：允许带命名空间前缀（<u:NewInternalPort>、<ns0:...>），
   否则各家固件的 SOAP 响应会有一半解析不出来。 */
static const char *FindTagCI(const char *buf, const char *end, const char *tag)
{
    size_t tag_len;
    const char *p;

    if (buf == NULL || end == NULL || tag == NULL)
        return NULL;
    tag_len = strlen(tag);
    if (tag_len == 0)
        return NULL;

    for (p = buf; p + 1 < end; ++p) {
        const char *q;
        char c;

        if (*p != '<')
            continue;
        q = p + 1;
        while (q < end && (isalnum((unsigned char)*q) || *q == '_' ||
                           *q == '-' || *q == '.'))
            ++q;
        if (q < end && *q == ':')
            ++q;                      /* 跳过前缀 */
        else
            q = p + 1;                /* 没有前缀，回到标签本身 */

        if ((size_t)(end - q) < tag_len + 1)
            continue;
        if (_strnicmp(q, tag, tag_len) != 0)
            continue;
        c = q[tag_len];
        if (c == '>' || c == '/' || c == ' ' || c == '\t' || c == '\r' || c == '\n')
            return p;
    }
    return NULL;
}

/* 取标签文本：支持 <![CDATA[...]]>，并把 &amp; 等实体还原。 */
static BOOL XmlGetText(const char *tag, const char *end, char *out, size_t cch)
{
    const char *gt;
    const char *lt;
    size_t n;
    size_t i;
    size_t o = 0;

    if (tag == NULL || end == NULL || out == NULL || cch == 0)
        return FALSE;
    out[0] = '\0';
    gt = memchr(tag, '>', (size_t)(end - tag));
    if (gt == NULL)
        return FALSE;
    ++gt;
    /* CDATA：gt 正好指向 "<![CDATA["，内容到 "]]>" 为止 */
    if ((size_t)(end - gt) >= 9 && memcmp(gt, "<![CDATA[", 9) == 0) {
        const char *cd = gt + 9;
        const char *cdEnd = NULL;

        while (cd + 3 <= end) {
            if (cd[0] == ']' && cd[1] == ']' && cd[2] == '>') {
                cdEnd = cd;
                break;
            }
            ++cd;
        }
        if (cdEnd == NULL)
            return FALSE;
        gt += 9;
        lt = cdEnd;
    } else {
        lt = memchr(gt, '<', (size_t)(end - gt));
        if (lt == NULL)
            return FALSE;
    }

    while (gt < lt && (*gt == ' ' || *gt == '\t' || *gt == '\r' || *gt == '\n'))
        ++gt;
    while (lt > gt && (lt[-1] == ' ' || lt[-1] == '\t' || lt[-1] == '\r' ||
                       lt[-1] == '\n'))
        --lt;
    n = (size_t)(lt - gt);
    if (n == 0)
        return FALSE;

    for (i = 0; i < n && o + 1 < cch; ++i) {
        if (gt[i] == '&') {
            if (n - i >= 5 && memcmp(gt + i, "&amp;", 5) == 0) {
                out[o++] = '&';
                i += 4;
            } else if (n - i >= 4 && memcmp(gt + i, "&lt;", 4) == 0) {
                out[o++] = '<';
                i += 3;
            } else if (n - i >= 4 && memcmp(gt + i, "&gt;", 4) == 0) {
                out[o++] = '>';
                i += 3;
            } else if (n - i >= 6 && memcmp(gt + i, "&quot;", 6) == 0) {
                out[o++] = '"';
                i += 5;
            } else if (n - i >= 6 && memcmp(gt + i, "&apos;", 6) == 0) {
                out[o++] = '\'';
                i += 5;
            } else {
                out[o++] = gt[i];
            }
        } else {
            out[o++] = gt[i];
        }
    }
    out[o] = '\0';
    return o > 0;
}

static BOOL ParseIgdDescription(const char *xml, size_t xml_len,
                                char *control_url, size_t url_cch,
                                char *service_type, size_t type_cch,
                                WCHAR *err, size_t err_cch)
{
    const char *end = xml + xml_len;
    const char *p = xml;

    while ((p = FindTagCI(p, end, "serviceType")) != NULL) {
        char type[192];
        char ctl[400];
        const char *block_end;
        const char *cu;

        if (!XmlGetText(p, end, type, sizeof(type))) {
            ++p;
            continue;
        }
        if (strstr(type, "WANIPConnection") == NULL &&
            strstr(type, "WANPPPConnection") == NULL) {
            ++p;
            continue;
        }
        block_end = FindTagCI(p, end, "/service");
        if (block_end == NULL)
            block_end = end;
        cu = FindTagCI(p, block_end, "controlURL");
        if (cu == NULL || !XmlGetText(cu, block_end, ctl, sizeof(ctl))) {
            p = block_end;
            continue;
        }
        if (strlen(ctl) >= url_cch || strlen(type) >= type_cch)
            return FALSE;
        strcpy(control_url, ctl);
        strcpy(service_type, type);
        return TRUE;
    }
    WPrintf(err, err_cch, L"网关描述中没有 WANIPConnection 服务");
    return FALSE;
}

static BOOL BuildAbsoluteUrl(const char *description_url, const char *url_base,
                             const char *control_url, char *out, size_t cch)
{
    HTTP_URL base;
    char origin[320];

    if (control_url == NULL || control_url[0] == '\0')
        return FALSE;
    if (_strnicmp(control_url, "http://", 7) == 0) {
        if (strlen(control_url) >= cch)
            return FALSE;
        strcpy(out, control_url);
        return TRUE;
    }
    if (url_base != NULL && _strnicmp(url_base, "http://", 7) == 0) {
        if (!ParseHttpUrl(url_base, &base))
            return FALSE;
    } else if (!ParseHttpUrl(description_url, &base)) {
        return FALSE;
    }
    if (base.port == 80) {
        if (!SnprintfA(origin, sizeof(origin), "http://%s", base.host))
            return FALSE;
    } else {
        if (!SnprintfA(origin, sizeof(origin), "http://%s:%u", base.host,
                       (unsigned)base.port))
            return FALSE;
    }

    if (control_url[0] == '/') {
        if (strlen(origin) + strlen(control_url) >= cch)
            return FALSE;
        strcpy(out, origin);
        strcat(out, control_url);
        return TRUE;
    }
    {
        char dir[512];
        char *slash;

        CopyAscii(dir, sizeof(dir), base.path);
        slash = strrchr(dir, '/');
        if (slash != NULL)
            slash[1] = '\0';
        else
            CopyAscii(dir, sizeof(dir), "/");
        if (strlen(origin) + strlen(dir) + strlen(control_url) + 2 >= cch)
            return FALSE;
        strcpy(out, origin);
        strcat(out, dir);
        strcat(out, control_url);
    }
    return TRUE;
}

static BOOL UpnpDiscover(UPNP_GATEWAY *gw, WCHAR *err, size_t err_cch)
{
    char location[512];
    char url_base[512];
    char *xml;
    char *body;
    int status;
    size_t body_len;

    ZeroMemory(gw, sizeof(*gw));
    if (!SsdpFindLocation(location, sizeof(location), err, err_cch))
        return FALSE;

    xml = (char *)malloc(UPNP_XML_MAX);
    if (xml == NULL) {
        WPrintf(err, err_cch, L"内存不足");
        return FALSE;
    }
    {
        HTTP_URL du;
        char req[1024];

        if (!ParseHttpUrl(location, &du)) {
            free(xml);
            WPrintf(err, err_cch, L"网关描述地址无效");
            return FALSE;
        }
        if (!SnprintfA(req, sizeof(req),
                       "GET %s HTTP/1.1\r\n"
                       "Host: %s:%u\r\n"
                       "User-Agent: " NAT_PRODUCT_A "/1.0 UPnP/1.1\r\n"
                       "Connection: close\r\n"
                       "\r\n",
                       du.path, du.host, (unsigned)du.port)) {
            free(xml);
            WPrintf(err, err_cch, L"网关描述请求过长");
            return FALSE;
        }
        status = HttpExchange(location, req, xml, UPNP_XML_MAX, err, err_cch);
    }
    if (status != 200) {
        free(xml);
        if (status > 0)
            WPrintf(err, err_cch, L"网关描述请求失败（HTTP %d）", status);
        return FALSE;
    }
    body = HttpBody(xml);
    if (body == NULL) {
        free(xml);
        WPrintf(err, err_cch, L"网关描述内容为空");
        return FALSE;
    }
    body_len = strlen(body);
    if (!ParseIgdDescription(body, body_len, gw->control_url,
                             sizeof(gw->control_url), gw->service_type,
                             sizeof(gw->service_type), err, err_cch)) {
        free(xml);
        return FALSE;
    }

    url_base[0] = '\0';
    {
        const char *ub = FindTagCI(body, body + body_len, "URLBase");
        if (ub != NULL)
            XmlGetText(ub, body + body_len, url_base, sizeof(url_base));
    }
    {
        char abs_url[1024];

        if (!BuildAbsoluteUrl(location, url_base[0] ? url_base : NULL,
                              gw->control_url, abs_url, sizeof(abs_url))) {
            free(xml);
            WPrintf(err, err_cch, L"网关控制地址无效");
            return FALSE;
        }
        CopyAscii(gw->control_url, sizeof(gw->control_url), abs_url);
    }
    free(xml);
    gw->available = 1;
    return TRUE;
}

static int SoapCall(const UPNP_GATEWAY *gw, const char *action,
                    const char *body_xml, char *resp, size_t resp_cch,
                    int *error_code, WCHAR *err, size_t err_cch)
{
    HTTP_URL u;
    char req[8192];
    char env[4096];
    int status;
    int len;

    if (error_code != NULL)
        *error_code = 0;
    if (!ParseHttpUrl(gw->control_url, &u)) {
        WPrintf(err, err_cch, L"UPnP 控制地址无效");
        return 0;
    }
    if (!SnprintfA(env, sizeof(env),
                   "<?xml version=\"1.0\"?>"
                   "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                   "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                   "<s:Body>%s</s:Body></s:Envelope>", body_xml)) {
        WPrintf(err, err_cch, L"UPnP 请求内容过长");
        return 0;
    }
    len = (int)strlen(env);
    if (!SnprintfA(req, sizeof(req),
              "POST %s HTTP/1.1\r\n"
              "Host: %s:%u\r\n"
              "Content-Type: text/xml; charset=\"utf-8\"\r\n"
              "SOAPACTION: \"%s#%s\"\r\n"
              "Content-Length: %d\r\n"
              "Connection: close\r\n"
              "User-Agent: " NAT_PRODUCT_A "/1.0 UPnP/1.1\r\n"
              "\r\n%s",
                  u.path, u.host, (unsigned)u.port, gw->service_type, action, len, env)) {
        WPrintf(err, err_cch, L"UPnP 请求头部过长");
        return 0;
    }

    status = HttpExchange(gw->control_url, req, resp, resp_cch, err, err_cch);
    if (status == 200)
        return 1;
    if (status > 0) {
        int code = 0;
        char *b = HttpBody(resp);

        if (b != NULL) {
            size_t blen = strlen(b);
            const char *ec = FindTagCI(b, b + blen, "errorCode");

            if (ec != NULL) {
                char val[32];

                if (XmlGetText(ec, b + blen, val, sizeof(val)))
                    code = atoi(val);
            }
        }
        if (error_code != NULL)
            *error_code = code;
        if (code != 0)
            WPrintf(err, err_cch, L"UPnP 错误码 %d（HTTP %d）", code, status);
        else
            WPrintf(err, err_cch, L"UPnP 请求被网关拒绝（HTTP %d）", status);
    }
    return 0;
}

static BOOL UpnpGetExternalIp(UPNP_GATEWAY *gw, char *out, size_t cch,
                              WCHAR *err, size_t err_cch)
{
    char body[1024];
    char resp[UPNP_RESP_MAX];

    if (cch > 0)
        out[0] = '\0';
    if (!SnprintfA(body, sizeof(body),
                   "<u:GetExternalIPAddress xmlns:u=\"%s\"></u:GetExternalIPAddress>",
                   gw->service_type)) {
        WPrintf(err, err_cch, L"UPnP 服务类型过长");
        return FALSE;
    }
    if (!SoapCall(gw, "GetExternalIPAddress", body, resp, sizeof(resp), NULL,
                  err, err_cch))
        return FALSE;
    {
        char *b = HttpBody(resp);
        const char *tag;
        char ip[64];
        size_t blen;

        if (b == NULL)
            return FALSE;
        blen = strlen(b);
        tag = FindTagCI(b, b + blen, "NewExternalIPAddress");
        if (tag == NULL || !XmlGetText(tag, b + blen, ip, sizeof(ip)))
            return FALSE;
        if (ip[0] == '\0' || strcmp(ip, "0.0.0.0") == 0)
            return FALSE;
        CopyAscii(out, cch, ip);
        CopyAscii(gw->external_ip, sizeof(gw->external_ip), ip);
    }
    return TRUE;
}

static BOOL UpnpAddPortMapping(UPNP_GATEWAY *gw, BOOL tcp, USHORT ext_port,
                               USHORT int_port, const char *local_ip,
                               int *error_code, WCHAR *err, size_t err_cch)
{
    char body[2048];
    char resp[UPNP_RESP_MAX];

    if (!SnprintfA(body, sizeof(body),
                   "<u:AddPortMapping xmlns:u=\"%s\">"
              "<NewRemoteHost></NewRemoteHost>"
              "<NewExternalPort>%u</NewExternalPort>"
              "<NewProtocol>%s</NewProtocol>"
              "<NewInternalPort>%u</NewInternalPort>"
              "<NewInternalClient>%s</NewInternalClient>"
              "<NewEnabled>1</NewEnabled>"
              "<NewPortMappingDescription>" NAT_PRODUCT_A "</NewPortMappingDescription>"
                   "<NewLeaseDuration>%u</NewLeaseDuration>"
                   "</u:AddPortMapping>",
                   gw->service_type, (unsigned)ext_port, tcp ? "TCP" : "UDP",
                   (unsigned)int_port, local_ip, (unsigned)UPNP_LEASE_SECONDS)) {
        WPrintf(err, err_cch, L"UPnP 映射请求过长");
        return FALSE;
    }
    return SoapCall(gw, "AddPortMapping", body, resp, sizeof(resp), error_code,
                    err, err_cch) ? TRUE : FALSE;
}

/* 回读网关上的映射条目，确认 AddPortMapping 真的生效（部分网关会静默丢弃）。
   返回值：1 = 校验通过，0 = 明确不一致（该删掉这条坏规则），-1 = 无法校验
   （网关不支持回读或网络失败，不能据此判定映射失败）。 */
static int UpnpVerifyPortMapping(UPNP_GATEWAY *gw, BOOL tcp, USHORT ext_port,
                                 USHORT int_port, const char *local_ip)
{
    char body[1024];
    char resp[UPNP_RESP_MAX];
    WCHAR e[160];
    char *b;
    const char *tag;
    char val[64];
    size_t blen;

    SnprintfA(body, sizeof(body),
              "<u:GetSpecificPortMappingEntry xmlns:u=\"%s\">"
              "<NewRemoteHost></NewRemoteHost>"
              "<NewExternalPort>%u</NewExternalPort>"
              "<NewProtocol>%s</NewProtocol>"
              "</u:GetSpecificPortMappingEntry>",
              gw->service_type, (unsigned)ext_port, tcp ? "TCP" : "UDP");
    e[0] = L'\0';
    if (!SoapCall(gw, "GetSpecificPortMappingEntry", body, resp, sizeof(resp),
                  NULL, e, sizeof(e) / sizeof(e[0])))
        return -1;
    b = HttpBody(resp);
    if (b == NULL)
        return -1;
    blen = strlen(b);

    /* 外部端口：必须就是刚申请的那个 */
    tag = FindTagCI(b, b + blen, "NewExternalPort");
    if (tag == NULL || !XmlGetText(tag, b + blen, val, sizeof(val)))
        return -1;
    if ((unsigned int)atoi(val) != (unsigned int)ext_port)
        return 0;

    /* 内部端口/内部地址：必须指向本机的这个端口 */
    tag = FindTagCI(b, b + blen, "NewInternalPort");
    if (tag == NULL || !XmlGetText(tag, b + blen, val, sizeof(val)))
        return -1;
    if ((unsigned int)atoi(val) != (unsigned int)int_port)
        return 0;
    if (local_ip != NULL && local_ip[0] != '\0') {
        tag = FindTagCI(b, b + blen, "NewInternalClient");
        if (tag == NULL || !XmlGetText(tag, b + blen, val, sizeof(val)))
            return -1;
        if (strcmp(val, local_ip) != 0)
            return 0;
    }

    /* 协议和启用状态也必须对得上（有的网关会忽略 NewEnabled=0 的条目） */
    tag = FindTagCI(b, b + blen, "NewProtocol");
    if (tag != NULL && XmlGetText(tag, b + blen, val, sizeof(val))) {
        if (_stricmp(val, tcp ? "TCP" : "UDP") != 0)
            return 0;
    }
    tag = FindTagCI(b, b + blen, "NewEnabled");
    if (tag != NULL && XmlGetText(tag, b + blen, val, sizeof(val))) {
        if (!(strcmp(val, "1") == 0 || _stricmp(val, "true") == 0))
            return 0;
    }
    return 1;
}

static BOOL UpnpDeletePortMapping(UPNP_GATEWAY *gw, BOOL tcp, USHORT ext_port,
                                  WCHAR *err, size_t err_cch)
{
    char body[1024];
    char resp[UPNP_RESP_MAX];

    if (!SnprintfA(body, sizeof(body),
                   "<u:DeletePortMapping xmlns:u=\"%s\">"
                   "<NewRemoteHost></NewRemoteHost>"
                   "<NewExternalPort>%u</NewExternalPort>"
                   "<NewProtocol>%s</NewProtocol>"
                   "</u:DeletePortMapping>",
                   gw->service_type, (unsigned)ext_port, tcp ? "TCP" : "UDP")) {
        WPrintf(err, err_cch, L"UPnP 删除请求过长");
        return FALSE;
    }
    return SoapCall(gw, "DeletePortMapping", body, resp, sizeof(resp), NULL,
                    err, err_cch) ? TRUE : FALSE;
}

static BOOL UpnpGatewayCopy(UPNP_GATEWAY *out)
{
    BOOL ok;

    if (out == NULL)
        return FALSE;
    ZeroMemory(out, sizeof(*out));
    if (!UpnpLock())
        return FALSE;
    *out = g_upnp;
    UpnpUnlock();
    ok = (out->available != 0) && out->control_url[0] != '\0';
    return ok;
}

/* 网关发现全程持锁：多个映射同时启动时，只会有第一个真的去搜网关，
   后面的在锁上等着，醒来直接复用结果，不会同时发出几轮 SSDP。 */
static BOOL UpnpEnsureGateway(void)
{
    UPNP_GATEWAY local;
    ULONGLONG now;
    WCHAR err[192];
    BOOL ok;

    if (!UpnpLock())
        return FALSE;

    now = NowMs64();
    if (g_upnp.available && now - g_upnp.scanned_at < UPNP_SCAN_MS) {
        UpnpUnlock();
        return TRUE;
    }
    if (!g_upnp.available && g_upnp.last_fail_at != 0 &&
        now - g_upnp.last_fail_at < UPNP_RETRY_MS) {
        UpnpUnlock();
        return FALSE;
    }

    err[0] = L'\0';
    ok = UpnpDiscover(&local, err, sizeof(err) / sizeof(err[0]));
    local.available = ok ? 1 : 0;
    local.scanned_at = NowMs64();
    local.last_fail_at = ok ? 0 : local.scanned_at;
    /* 记住失败原因，供后续映射复用，避免每次重新发现网关 */
    CopyW(local.last_err, sizeof(local.last_err) / sizeof(local.last_err[0]),
          ok ? L"" : err);
    g_upnp = local;
    UpnpUnlock();

    if (!ok)
        AddLog(L"UPnP 网关发现失败: %s", err);
    return ok;
}

/* 是否是真正的公网 IPv4（排除私有地址、CGNAT 100.64/10、链路本地等） */
static BOOL IsPublicIPv4Text(const char *ip)
{
    unsigned int o[4];
    unsigned int a;
    unsigned int b;
    int consumed = 0;

    if (ip == NULL)
        return FALSE;
    /* %n 用来确认整串都是合法点分十进制，末尾不能有多余字符 */
    if (sscanf(ip, "%u.%u.%u.%u%n", &o[0], &o[1], &o[2], &o[3], &consumed) != 4)
        return FALSE;
    if (consumed <= 0 || ip[consumed] != '\0')
        return FALSE;
    if (o[0] > 255 || o[1] > 255 || o[2] > 255 || o[3] > 255)
        return FALSE;

    a = o[0];
    b = o[1];
    if (a == 0 || a == 10 || a == 127 || a >= 224)   /* 本网/私网/回环/组播/保留 */
        return FALSE;
    if (a == 255 || (a == 255 && b == 255))           /* 255.255.255.255 */
        return FALSE;
    if (a == 172 && b >= 16 && b <= 31)               /* 172.16/12 */
        return FALSE;
    if (a == 192 && b == 168)                         /* 192.168/16 */
        return FALSE;
    if (a == 169 && b == 254)                         /* 链路本地 169.254/16 */
        return FALSE;
    if (a == 100 && b >= 64 && b <= 127)              /* CGNAT 100.64/10 */
        return FALSE;
    if (a == 198 && (b == 18 || b == 19))             /* 基准测试 198.18/15 */
        return FALSE;
    if (a == 192 && b == 0 && o[2] == 0)              /* 192.0.0/24 */
        return FALSE;
    if (a == 192 && b == 0 && o[2] == 2)              /* TEST-NET-1 */
        return FALSE;
    if (a == 192 && b == 88 && o[2] == 99)            /* 6to4 中继 192.88.99/24 */
        return FALSE;
    if (a == 198 && b == 51 && o[2] == 100)           /* TEST-NET-2 */
        return FALSE;
    if (a == 203 && b == 0 && o[2] == 113)            /* TEST-NET-3 */
        return FALSE;
    if (a >= 240)                                     /* 240/4 保留（含 255.255.255.255） */
        return FALSE;
    return TRUE;
}

static BOOL LocalIpv4ForRoute(const SOCKADDR_IN *peer, char *out, size_t cch)
{
    SOCKET s;
    SOCKADDR_IN local;
    int len = (int)sizeof(local);
    const unsigned char *p;

    if (out == NULL || cch == 0)
        return FALSE;
    out[0] = '\0';
    if (peer == NULL)
        return FALSE;
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
        return FALSE;
    if (connect(s, (const SOCKADDR *)peer, (int)sizeof(*peer)) == 0 &&
        getsockname(s, (SOCKADDR *)&local, &len) == 0) {
        p = (const unsigned char *)&local.sin_addr.s_addr;
        SnprintfA(out, cch, "%u.%u.%u.%u", (unsigned)p[0], (unsigned)p[1],
                  (unsigned)p[2], (unsigned)p[3]);
    }
    closesocket(s);
    if (out[0] == '\0' || strcmp(out, "0.0.0.0") == 0)
        return FALSE;
    return TRUE;
}

static void UpnpRememberError(const WCHAR *msg)
{
    size_t i = 0;
    size_t cap = sizeof(g_upnp.last_err) / sizeof(g_upnp.last_err[0]);

    if (msg == NULL)
        msg = L"";
    if (!UpnpLock())
        return;
    while (msg[i] != L'\0' && i + 1 < cap) {
        g_upnp.last_err[i] = msg[i];
        ++i;
    }
    g_upnp.last_err[i] = L'\0';
    UpnpUnlock();
}

static BOOL UpnpMapPortInner(BOOL tcp, USHORT internal_port,
                             const SOCKADDR_IN *route_to, char *ext_ip,
                             size_t ext_ip_cch, USHORT *ext_port, WCHAR *err,
                             size_t err_cch)
{
    UPNP_GATEWAY gw;
    char local_ip[64];
    USHORT candidate;
    int attempt;

    if (err != NULL && err_cch > 0)
        err[0] = L'\0';
    if (ext_ip != NULL && ext_ip_cch > 0)
        ext_ip[0] = '\0';

    if (!UpnpEnsureGateway()) {
        WCHAR cached[192];

        /* 复用上次失败原因（例如网关外部 IP 不是公网地址） */
        cached[0] = L'\0';
        UpnpLock();
        CopyW(cached, sizeof(cached) / sizeof(cached[0]), g_upnp.last_err);
        UpnpUnlock();
        if (cached[0] != L'\0')
            WPrintf(err, err_cch, L"%s", cached);
        else
            WPrintf(err, err_cch, L"未发现可用的 UPnP 网关");
        return FALSE;
    }
    if (!UpnpGatewayCopy(&gw)) {
        WPrintf(err, err_cch, L"UPnP 网关不可用");
        return FALSE;
    }
    if (!LocalIpv4ForRoute(route_to, local_ip, sizeof(local_ip))) {
        WPrintf(err, err_cch, L"无法取得本机局域网地址");
        return FALSE;
    }
    {
        WCHAR iperr[160];
        char extIp[64];

        /* 不能把 gw.external_ip 当输出参数传进去（会和 gw 结构体重叠），
           先用独立的缓冲区，成功后再写回网关信息。 */
        iperr[0] = L'\0';
        extIp[0] = '\0';
        if (!UpnpGetExternalIp(&gw, extIp, sizeof(extIp), iperr,
                               sizeof(iperr) / sizeof(iperr[0]))) {
            WPrintf(err, err_cch, L"无法读取网关外部 IP%s%s",
                    iperr[0] != L'\0' ? L": " : L"", iperr);
            return FALSE;
        }
        CopyAscii(gw.external_ip, sizeof(gw.external_ip), extIp);
    }

    candidate = (ext_port != NULL && *ext_port != 0) ? *ext_port : internal_port;
    for (attempt = 0; attempt < 4; ++attempt) {
        WCHAR aerr[160];
        int code = 0;

        aerr[0] = L'\0';
        if (UpnpAddPortMapping(&gw, tcp, candidate, internal_port, local_ip, &code,
                               aerr, sizeof(aerr) / sizeof(aerr[0]))) {
            /* 回读校验：确认映射真的写进了网关，而不是被静默丢弃 */
            int vr = UpnpVerifyPortMapping(&gw, tcp, candidate, internal_port,
                                           local_ip);

            if (vr == 0) {
                WCHAR derr[160];

                /* 明确不一致：这条坏规则会占着公网端口，必须删掉 */
                derr[0] = L'\0';
                if (!UpnpDeletePortMapping(&gw, tcp, candidate, derr,
                                           sizeof(derr) / sizeof(derr[0])))
                    AddLog(L"UPnP 回读校验不一致，删除端口 %u 的无效映射失败: %s",
                           (unsigned)candidate, derr);
                else
                    AddLog(L"UPnP 回读校验不一致，已删除端口 %u 的无效映射",
                           (unsigned)candidate);
                WPrintf(err, err_cch,
                        L"网关回读校验不一致（端口 %u），该映射已删除",
                        (unsigned)candidate);
                return FALSE;
            }
            if (vr < 0) {
                /* 网关不支持回读或这一问失败：不能据此判定映射失败 */
                AddLog(L"UPnP 映射已下发，但网关未提供回读校验（端口 %u），按已建立处理",
                       (unsigned)candidate);
            }
            if (ext_port != NULL)
                *ext_port = candidate;
            if (ext_ip != NULL && ext_ip_cch > 0)
                CopyAscii(ext_ip, ext_ip_cch, gw.external_ip);
            return TRUE;
        }
        WPrintf(err, err_cch, L"%s", aerr);
        if (code != 718) {
            /* 不是“端口冲突”，换端口也不会成功 */
            return FALSE;
        }
        candidate = (USHORT)(49152 + (NextRand() % 16000));
    }
    return FALSE;
}

/* 对外的 UPnP 映射入口：记录失败原因，后续映射直接复用同一结论，
   避免每个映射都重新发现网关、重复等待 */
static BOOL UpnpMapPort(BOOL tcp, USHORT internal_port,
                        const SOCKADDR_IN *route_to, char *ext_ip,
                        size_t ext_ip_cch, USHORT *ext_port, WCHAR *err,
                        size_t err_cch)
{
    BOOL ok = UpnpMapPortInner(tcp, internal_port, route_to, ext_ip,
                               ext_ip_cch, ext_port, err, err_cch);

    if (ok) {
        UpnpRememberError(NULL);
    } else if (err != NULL && err[0] != L'\0') {
        UpnpRememberError(err);
    }
    return ok;
}

static void UpnpRemoveMappedPort(BOOL tcp, USHORT ext_port)
{
    UPNP_GATEWAY gw;
    WCHAR err[160];
    int attempt;

    if (ext_port == 0)
        return;
    if (!UpnpGatewayCopy(&gw)) {
        AddLog(L"删除 UPnP 端口映射 %u 失败: 网关信息不可用（规则会在租期到期后自动失效）",
               (unsigned)ext_port);
        return;
    }

    /* 网关偶发丢包很常见，删两次；仍失败就明确写清楚，别静默留下规则 */
    for (attempt = 0; attempt < 2; ++attempt) {
        err[0] = L'\0';
        if (UpnpDeletePortMapping(&gw, tcp, ext_port, err,
                                  sizeof(err) / sizeof(err[0])))
            return;
        if (attempt == 0)
            AddLog(L"删除 UPnP 端口映射 %u 失败: %s（正在重试）",
                   (unsigned)ext_port, err);
        Sleep(300);
    }
    AddLog(L"删除 UPnP 端口映射 %u 最终失败: %s（规则会在租期到期后自动失效）",
           (unsigned)ext_port, err);
}

/* 状态栏文案：只反映"UPnP 映射是否建立成功"。
   网关外部地址是不是公网与本程序行为无关，不再据此下结论。 */
static const WCHAR *UpnpStatusText(BOOL mapped)
{
    return mapped ? L"运行中 · UPnP" : L"运行中";
}

/* ------------------------------------------------------------------ */
/* UDP 映射线程                                                        */
/* ------------------------------------------------------------------ */

static SOCKET BindUdpSocket(NAT_MAPPING *m, const SOCKADDR_IN *backend,
                            USHORT *actualPort, WCHAR *err, size_t errCch)
{
    USHORT desired;
    USHORT firstDesired;
    int attempt;

    EnterCriticalSection(&g_cs);
    desired = m->local_port;
    LeaveCriticalSection(&g_cs);
    firstDesired = desired;

    for (attempt = 0; attempt < (m->auto_port ? 100 : 1); ++attempt) {
        SOCKET s;
        SOCKADDR_IN local;
        BOOL exclusive = TRUE;
        USHORT candidate;

        if (m->auto_port) {
            if (attempt == 0 && desired != 0)
                candidate = desired;
            else
                candidate = RandomPort();
            if (candidate == m->backend_port && IsLoopbackIPv4(backend->sin_addr.s_addr))
                continue;
        } else {
            candidate = desired;
            if (candidate == m->backend_port && IsLoopbackIPv4(backend->sin_addr.s_addr)) {
                WPrintf(err, errCch,
                        L"本地端口不能与本地服务端口相同（会形成回环）");
                return INVALID_SOCKET;
            }
        }

        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) {
            WPrintf(err, errCch, L"创建 UDP socket 失败");
            return INVALID_SOCKET;
        }
        setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&exclusive,
                   sizeof(exclusive));

        ZeroMemory(&local, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = htons(candidate);
        if (bind(s, (const SOCKADDR *)&local, (int)sizeof(local)) == 0) {
            *actualPort = candidate;
            EnterCriticalSection(&g_cs);
            m->local_port = candidate;
            LeaveCriticalSection(&g_cs);
            return s;
        }

        {
            int bindError = WSAGetLastError();
            closesocket(s);
            if (!m->auto_port) {
                WCHAR e[128];
                FormatWsaError(bindError, e, sizeof(e) / sizeof(e[0]));
                WPrintf(err, errCch, L"绑定 UDP 端口 %u 失败: %s",
                        (unsigned)candidate, e);
                return INVALID_SOCKET;
            }
        }
        if (attempt == 0 && desired == firstDesired)
            desired = 0;
    }

    WPrintf(err, errCch, L"无法找到可用的 UDP 本地端口");
    return INVALID_SOCKET;
}

static UDP_SESSION *FindUdpSession(UDP_SESSION *sessions, int count,
                                    const SOCKADDR_IN *client)
{
    int i;
    for (i = 0; i < count; ++i) {
        if (sessions[i].used &&
            sessions[i].client.sin_addr.s_addr == client->sin_addr.s_addr &&
            sessions[i].client.sin_port == client->sin_port)
            return &sessions[i];
    }
    return NULL;
}

static void CloseUdpSession(UDP_SESSION *session)
{
    if (session->used && session->s != INVALID_SOCKET)
        closesocket(session->s);
    session->used = 0;
    session->s = INVALID_SOCKET;
    ZeroMemory(&session->client, sizeof(session->client));
    session->last_active = 0;
}

static UDP_SESSION *CreateUdpSession(UDP_SESSION *sessions, int count,
                                      const SOCKADDR_IN *client,
                                      const SOCKADDR_IN *backend,
                                      ULONGLONG now)
{
    int i;
    int slot = -1;
    SOCKET s;
    UDP_SESSION *session;

    for (i = 0; i < count; ++i) {
        if (!sessions[i].used) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        int oldest = -1;
        ULONGLONG oldestIdle = 0;

        /* 表满时只回收长时间没动静的会话；都在活跃期就拒绝新会话，
           不能为了接新客户端而掐断正在用的会话。 */
        for (i = 0; i < count; ++i) {
            ULONGLONG idle = now - sessions[i].last_active;

            if (oldest < 0 || idle > oldestIdle) {
                oldest = i;
                oldestIdle = idle;
            }
        }
        if (oldest < 0 || oldestIdle < UDP_SESSION_EVICT_MS)
            return NULL;
        CloseUdpSession(&sessions[oldest]);
        slot = oldest;
    }

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
        return NULL;
    if (!SetNonBlocking(s, TRUE)) {
        closesocket(s);
        return NULL;
    }
    if (connect(s, (const SOCKADDR *)backend, (int)sizeof(*backend)) == SOCKET_ERROR) {
        closesocket(s);
        return NULL;
    }

    session = &sessions[slot];
    session->used = 1;
    session->s = s;
    session->client = *client;
    session->last_active = now;
    session->start = now;
    session->bytes_in = 0;
    session->bytes_out = 0;
    return session;
}

static DWORD WINAPI UdpMappingThread(LPVOID param)
{
    NAT_MAPPING *m = (NAT_MAPPING *)param;
    SOCKADDR_IN stunAddr;
    SOCKADDR_IN backendAddr;
    SOCKET us = INVALID_SOCKET;
    USHORT actualPort = 0;
    WCHAR err[256];
    WCHAR publicAddr[64];
    unsigned char lastTid[12];
    int haveTid = 0;
    BOOL haveMapping = FALSE;
    ULONGLONG nextKeepalive = 0;
    ULONGLONG lastRx = 0;
    ULONGLONG lastWarning = 0;
    ULONGLONG lastRejectLog = 0;
    ULONGLONG lastBlackLog = 0;      /* 黑名单命中的日志限频 */
    ULONGLONG lastStatsFlush = 0;
    unsigned long blackDropped = 0;  /* 被黑名单丢弃的数据报累计 */
    ULONGLONG localIn = 0;
    ULONGLONG localOut = 0;
    unsigned long localPktsIn = 0;
    unsigned long localPktsOut = 0;
    UDP_SESSION sessions[MAX_UDP_SESSIONS];
    unsigned char *buf = NULL;
    int sessionLogs = 0;
    int i;
    char upnpExtIp[64];
    USHORT upnpExtPort = 0;
    BOOL upnpMapped = FALSE;
    BOOL upnpPublicAddr = FALSE;
    ULONGLONG upnpNextAct = 0;

    ZeroMemory(err, sizeof(err));
    ZeroMemory(publicAddr, sizeof(publicAddr));
    ZeroMemory(upnpExtIp, sizeof(upnpExtIp));
    ZeroMemory(lastTid, sizeof(lastTid));
    ZeroMemory(sessions, sizeof(sessions));
    for (i = 0; i < MAX_UDP_SESSIONS; ++i)
        sessions[i].s = INVALID_SOCKET;

    AddLog(L"[%s] 启动 UDP 映射，STUN=%s:%u，服务=%s:%u",
           m->name, m->stun_host, (unsigned)m->stun_port,
           m->backend_host, (unsigned)m->backend_port);

    if (!ResolveIPv4(m->stun_host, m->stun_port, &stunAddr, err,
                     sizeof(err) / sizeof(err[0]))) {
        SetStatus(m, L"错误: STUN 服务器解析失败");
        AddLog(L"[%s] %s", m->name, err);
        goto cleanup;
    }
    if (!ResolveIPv4(m->backend_host, m->backend_port, &backendAddr, err,
                     sizeof(err) / sizeof(err[0]))) {
        SetStatus(m, L"错误: 服务地址解析失败");
        AddLog(L"[%s] %s", m->name, err);
        goto cleanup;
    }

    us = BindUdpSocket(m, &backendAddr, &actualPort, err,
                       sizeof(err) / sizeof(err[0]));
    if (us == INVALID_SOCKET) {
        SetStatus(m, L"错误: %s", err);
        AddLog(L"[%s] %s", m->name, err);
        goto cleanup;
    }
    if (!SetNonBlocking(us, TRUE)) {
        WCHAR e[128];

        FormatWsaError(WSAGetLastError(), e, sizeof(e) / sizeof(e[0]));
        SetStatus(m, L"错误: UDP 设置非阻塞失败");
        AddLog(L"[%s] UDP 设置非阻塞失败: %s", m->name, e);
        goto cleanup;
    }
    SetStatus(m, L"UDP 已绑定 %u，正在获取公网映射…", (unsigned)actualPort);
    AddLog(L"[%s] UDP 已绑定本地端口 %u", m->name, (unsigned)actualPort);

    if (m->use_upnp) {
        WCHAR uerr[192];

        uerr[0] = L'\0';
        if (UpnpMapPort(FALSE, actualPort, &stunAddr, upnpExtIp,
                        sizeof(upnpExtIp), &upnpExtPort, uerr,
                        sizeof(uerr) / sizeof(uerr[0]))) {
            WCHAR wip[64];
            WCHAR text[96];

            upnpMapped = TRUE;
            upnpPublicAddr = IsPublicIPv4Text(upnpExtIp) ? TRUE : FALSE;
            AsciiToW(upnpExtIp, wip, sizeof(wip) / sizeof(wip[0]));
            WPrintf(text, sizeof(text) / sizeof(text[0]), L"%s:%u", wip,
                    (unsigned)upnpExtPort);
            EnterCriticalSection(&g_cs);
            m->upnp_mapped = 1;
            m->upnp_ext_port = upnpExtPort;
            CopyW(m->upnp_ext_ip, sizeof(m->upnp_ext_ip) / sizeof(m->upnp_ext_ip[0]), wip);
            LeaveCriticalSection(&g_cs);
            if (IsPublicIPv4Text(upnpExtIp)) {
                SetPublicAddressText(m, text);
                AddLog(L"[%s] UPnP 端口映射已建立并校验通过: 公网 %s -> 本地 %u（租期 %u 秒，自动续约）",
                       m->name, text, (unsigned)actualPort, (unsigned)UPNP_LEASE_SECONDS);
            } else {
                AddLog(L"[%s] UPnP 端口映射已建立并校验通过: 网关 %s -> 本地 %u（租期 %u 秒，自动续约）",
                       m->name, text, (unsigned)actualPort, (unsigned)UPNP_LEASE_SECONDS);
                AddLog(L"[%s] 外部仍连不进来时，先检查 Windows 防火墙是否放行本程序："
                       L"本程序是绿色单文件，入站规则必须指向实际运行的 exe 路径",
                       m->name);
            }
            SetStatus(m, UpnpStatusText(upnpMapped));
            upnpNextAct = NowMs64() + UPNP_RENEW_MS;
        } else {
            AddLog(L"[%s] UPnP 不可用（%s），改用 STUN 获取公网映射", m->name, uerr);
            SetStatus(m, L"UPnP 不可用，正在用 STUN 获取公网映射…");
            upnpNextAct = NowMs64() + UPNP_RETRY_MS * 5;
        }
    }

    buf = (unsigned char *)malloc(65536);
    if (buf == NULL) {
        SetStatus(m, L"错误: 内存不足");
        goto cleanup;
    }

    nextKeepalive = 0;
    while (InterlockedCompareExchange(&m->stop, 0, 0) == 0 &&
           InterlockedCompareExchange(&g_appStop, 0, 0) == 0) {
        ULONGLONG now = NowMs64();
        int sel;
        fd_set rfds;
        struct timeval tv;

        if (now >= nextKeepalive) {
            unsigned char req[20];
            unsigned char tid[12];
            int sent = SOCKET_ERROR;

            BuildStunRequest(req, tid);
            sent = sendto(us, (const char *)req, 20, 0,
                          (const SOCKADDR *)&stunAddr, (int)sizeof(stunAddr));
            if (sent == 20) {
                memcpy(lastTid, tid, 12);
                haveTid = 1;
                EnterCriticalSection(&g_cs);
                m->last_keepalive = now;
                LeaveCriticalSection(&g_cs);
            } else {
                EnterCriticalSection(&g_cs);
                m->stun_fail_count++;
                LeaveCriticalSection(&g_cs);
                if (now - lastWarning > 30000) {
                    SetStatus(m, L"运行中 · STUN 发送失败");
                    lastWarning = now;
                }
            }
            nextKeepalive = now + (haveMapping ? UDP_KEEPALIVE_MS : KEEPALIVE_RETRY_MS);
        }

        FD_ZERO(&rfds);
        FD_SET(us, &rfds);
        for (i = 0; i < MAX_UDP_SESSIONS; ++i) {
            if (sessions[i].used)
                FD_SET(sessions[i].s, &rfds);
        }
        tv.tv_sec = 0;
        tv.tv_usec = 250000;
        sel = select(0, &rfds, NULL, NULL, &tv);
        if (sel == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEINTR)
                continue;
            SetStatus(m, L"错误: select 失败");
            AddLog(L"[%s] UDP select 失败: %d", m->name, e);
            break;
        }

        if (sel > 0 && FD_ISSET(us, &rfds)) {
            int k;
            for (k = 0; k < 32; ++k) {
                SOCKADDR_IN from;
                int fromLen = (int)sizeof(from);
                int n = recvfrom(us, (char *)buf, 65536, 0,
                                 (SOCKADDR *)&from, &fromLen);
                if (n == SOCKET_ERROR) {
                    int e = WSAGetLastError();
                    if (e == WSAEWOULDBLOCK)
                        break;
                    if (e == WSAEINTR || e == WSAECONNRESET)
                        continue;
                    break;
                }
                if (n <= 0)
                    continue;

                if (from.sin_addr.s_addr == stunAddr.sin_addr.s_addr &&
                    from.sin_port == stunAddr.sin_port) {
                    STUN_RESULT sr;
                    WCHAR perr[160];

                    /* 只要收到 STUN 的回包，就说明这条映射的链路是通的；
                       解析失败是内容问题，不能当成"没连通"。 */
                    lastRx = now;
                    perr[0] = L'\0';
                    if (ParseStunResponse(buf, n, haveTid ? lastTid : NULL,
                                          &sr, perr, sizeof(perr) / sizeof(perr[0]))) {
                        if (upnpMapped && upnpPublicAddr) {
                            /* UPnP 外部地址是公网时优先显示，STUN 只用来保活 */
                            NoteStunOk(m);
                        } else {
                            UpdatePublicAddress(m, &sr, publicAddr,
                                                sizeof(publicAddr) / sizeof(publicAddr[0]));
                        }
                        haveMapping = TRUE;
                        SetStatus(m, UpnpStatusText(upnpMapped));
                    } else if (now - lastWarning > 30000) {
                        AddLog(L"[%s] 收到 STUN 响应但解析失败: %s（%d 字节）",
                               m->name, perr, n);
                        lastWarning = now;
                    }
                    continue;
                }

                {
                    UDP_SESSION *session = FindUdpSession(sessions, MAX_UDP_SESSIONS, &from);
                    BOOL created = FALSE;
                    if (session == NULL) {
                        /* 只在新建会话时查一次；命中就整包丢弃，不回任何东西 */
                        if (BlacklistMatchAddress(&from.sin_addr)) {
                            blackDropped++;
                            if (lastBlackLog == 0 || now - lastBlackLog >= 30000) {
                                WCHAR peerText[64];

                                FormatSockAddrW(&from, peerText,
                                                sizeof(peerText) / sizeof(peerText[0]));
                                AddLog(L"[%s] UDP 来自 %s 的数据命中黑名单，已丢弃"
                                       L"（累计 %lu 次）",
                                       m->name, peerText, blackDropped);
                                lastBlackLog = now;
                            }
                            continue;
                        }
                        session = CreateUdpSession(sessions, MAX_UDP_SESSIONS,
                                                   &from, &backendAddr, now);
                        created = (session != NULL);
                        if (!created && now - lastRejectLog > 30000) {
                            WCHAR peer[64];

                            FormatSockAddrW(&from, peer, sizeof(peer) / sizeof(peer[0]));
                            AddLog(L"[%s] UDP 会话表已满且没有可回收的空闲会话，"
                                   L"暂时丢弃来自 %s 的数据",
                                   m->name, peer);
                            lastRejectLog = now;
                        }
                    }
                    if (session != NULL) {
                        int sn = send(session->s, (const char *)buf, n, 0);
                        if (sn == n) {
                            session->last_active = now;
                            session->bytes_in += (ULONGLONG)n;
                            localIn += (ULONGLONG)n;
                            localPktsIn++;
                            if (created && sessionLogs < 30) {
                                WCHAR peer[64];
                                FormatSockAddrW(&from, peer, sizeof(peer) / sizeof(peer[0]));
                                AddLog(L"[%s] UDP 新会话 %s", m->name, peer);
                                sessionLogs++;
                            }
                        } else {
                            int e = WSAGetLastError();
                            if (e != WSAEWOULDBLOCK) {
                                CloseUdpSession(session);
                            }
                        }
                    }
                }
            }
        }

        for (i = 0; i < MAX_UDP_SESSIONS; ++i) {
            if (!sessions[i].used)
                continue;
            if (FD_ISSET(sessions[i].s, &rfds)) {
                int k;
                for (k = 0; k < 32; ++k) {
                    int n = recv(sessions[i].s, (char *)buf, 65536, 0);
                    if (n == SOCKET_ERROR) {
                        int e = WSAGetLastError();
                        if (e == WSAEWOULDBLOCK)
                            break;
                        if (e == WSAEINTR)
                            continue;
                        CloseUdpSession(&sessions[i]);
                        break;
                    }
                    if (n <= 0) {
                        CloseUdpSession(&sessions[i]);
                        break;
                    }
                    {
                        int sn = sendto(us, (const char *)buf, n, 0,
                                        (const SOCKADDR *)&sessions[i].client,
                                        (int)sizeof(sessions[i].client));

                        if (sn == n) {
                            sessions[i].last_active = now;
                            sessions[i].bytes_out += (ULONGLONG)n;
                            localOut += (ULONGLONG)n;
                            localPktsOut++;
                        } else if (sn == SOCKET_ERROR) {
                            int e = WSAGetLastError();

                            /* 本地发送缓冲满时丢一个包是 UDP 的正常行为，
                               其它错误才值得记录 */
                            if (e != WSAEWOULDBLOCK && e != WSAENOBUFS &&
                                now - lastWarning > 30000) {
                                AddLog(L"[%s] UDP 回包发送失败: WSA %d",
                                       m->name, e);
                                lastWarning = now;
                            }
                        }
                    }
                }
            }
        }

        if (now - lastStatsFlush >= 1000) {
            EnterCriticalSection(&g_cs);
            m->bytes_in += localIn;
            m->bytes_out += localOut;
            m->pkts_in += localPktsIn;
            m->pkts_out += localPktsOut;
            /* 把当前活跃的 UDP 会话发布给连接表窗口 */
            m->udp_view_count = 0;
            for (i = 0; i < MAX_UDP_SESSIONS; ++i) {
                CONN_VIEW *v;

                if (!sessions[i].used)
                    continue;
                v = &m->udp_view[m->udp_view_count++];
                v->peer = sessions[i].client;
                v->start = sessions[i].start;
                v->last_active = sessions[i].last_active;
                v->bytes_in = sessions[i].bytes_in;
                v->bytes_out = sessions[i].bytes_out;
            }
            LeaveCriticalSection(&g_cs);
            localIn = 0;
            localOut = 0;
            localPktsIn = 0;
            localPktsOut = 0;
            lastStatsFlush = now;
        }

        for (i = 0; i < MAX_UDP_SESSIONS; ++i) {
            if (sessions[i].used && now - sessions[i].last_active > UDP_SESSION_IDLE_MS)
                CloseUdpSession(&sessions[i]);
        }

        if (m->use_upnp && now >= upnpNextAct) {
            WCHAR uerr[192];
            char ip[64];
            USHORT ep = upnpMapped ? upnpExtPort : 0;
            BOOL ok;

            uerr[0] = L'\0';
            ok = UpnpMapPort(FALSE, actualPort, &stunAddr, ip, sizeof(ip), &ep,
                             uerr, sizeof(uerr) / sizeof(uerr[0]));
            if (ok) {
                WCHAR wip[64];
                WCHAR text[96];

                AsciiToW(ip, wip, sizeof(wip) / sizeof(wip[0]));
                WPrintf(text, sizeof(text) / sizeof(text[0]), L"%s:%u", wip,
                        (unsigned)ep);
                upnpPublicAddr = IsPublicIPv4Text(ip) ? TRUE : FALSE;
                if (upnpPublicAddr)
                    SetPublicAddressText(m, text);
                upnpExtPort = ep;
                CopyAscii(upnpExtIp, sizeof(upnpExtIp), ip);
                if (!upnpMapped) {
                    upnpMapped = TRUE;
                    EnterCriticalSection(&g_cs);
                    m->upnp_mapped = 1;
                    m->upnp_ext_port = ep;
                    CopyW(m->upnp_ext_ip,
                          sizeof(m->upnp_ext_ip) / sizeof(m->upnp_ext_ip[0]), wip);
                    LeaveCriticalSection(&g_cs);
                    AddLog(L"[%s] UPnP 端口映射已建立: %s %s -> 本地 %u",
                           m->name, upnpPublicAddr ? L"公网" : L"网关（非公网）",
                           text, (unsigned)actualPort);
                    SetStatus(m, UpnpStatusText(upnpMapped));
                }
                upnpNextAct = now + UPNP_RENEW_MS;
            } else if (upnpMapped) {
                /* 续约失败：网关上的规则可能已经失效，不能再声称 UPnP 可用，
                   立刻把公网地址交还给 STUN 结果，避免显示一个连不上的地址 */
                AddLog(L"[%s] UPnP 续约失败: %s（改用 STUN 结果，%u 秒后重试 UPnP）",
                       m->name, uerr, (unsigned)(UPNP_RETRY_MS / 1000ULL));
                upnpMapped = FALSE;
                upnpPublicAddr = FALSE;
                EnterCriticalSection(&g_cs);
                m->upnp_mapped = 0;
                LeaveCriticalSection(&g_cs);
                SetStatus(m, L"运行中 · UPnP 续约失败，以 STUN 为准");
                upnpNextAct = now + UPNP_RETRY_MS;
            } else {
                AddLog(L"[%s] UPnP 仍不可用: %s", m->name, uerr);
                upnpNextAct = now + UPNP_RETRY_MS * 5;
            }
        }

        if (haveMapping && lastRx != 0 && now - lastRx > 90000ULL &&
            now - lastWarning > 30000ULL) {
            SetStatus(m, L"运行中 · STUN 保活异常");
            AddLog(L"[%s] 警告: STUN 已超过 90 秒无响应，仍继续重试", m->name);
            lastWarning = now;
        }
    }

cleanup:
    if (localIn != 0 || localOut != 0) {
        EnterCriticalSection(&g_cs);
        m->bytes_in += localIn;
        m->bytes_out += localOut;
        m->pkts_in += localPktsIn;
        m->pkts_out += localPktsOut;
        LeaveCriticalSection(&g_cs);
    }
    for (i = 0; i < MAX_UDP_SESSIONS; ++i) {
        if (sessions[i].used)
            CloseUdpSession(&sessions[i]);
    }
    EnterCriticalSection(&g_cs);
    m->udp_view_count = 0;
    LeaveCriticalSection(&g_cs);
    if (us != INVALID_SOCKET)
        closesocket(us);
    free(buf);
    /* 续约失败时 upnpMapped 已经是 FALSE，但网关上的规则仍要清掉 */
    EnterCriticalSection(&g_cs);
    m->upnp_mapped = 0;
    LeaveCriticalSection(&g_cs);
    if (upnpExtPort != 0)
        UpnpRemoveMappedPort(FALSE, upnpExtPort);
    SetStatus(m, L"已停止");
    AddLog(L"[%s] UDP 映射已停止", m->name);
    InterlockedExchange(&m->running, 0);
    return 0;
}

/* ------------------------------------------------------------------ */
/* TCP 映射线程                                                        */
/* ------------------------------------------------------------------ */

static void WipToAscii(const SOCKADDR_IN *a, char *out, size_t cch)
{
    const unsigned char *p;
    WCHAR w[32];
    size_t i;

    if (out == NULL || cch == 0)
        return;
    out[0] = '\0';
    if (a == NULL)
        return;
    p = (const unsigned char *)&a->sin_addr.s_addr;
    WPrintf(w, sizeof(w) / sizeof(w[0]), L"%u.%u.%u.%u",
            (unsigned)p[0], (unsigned)p[1], (unsigned)p[2], (unsigned)p[3]);
    /* 循环结束时 i 一定落在 cch-1 以内，保证截断时也写 NUL */
    for (i = 0; w[i] != L'\0' && i + 1 < cch; ++i)
        out[i] = (char)(w[i] & 0x7F);
    out[i] = '\0';
}

/* 把 "1.2.3.4:5678" 这样的宽字符串解析成 SOCKADDR_IN；失败返回 FALSE */
static BOOL ParseIpv4PortW(const WCHAR *s, SOCKADDR_IN *out)
{
    const WCHAR *p = s;
    unsigned o[4];
    unsigned port = 0;
    int i;

    if (s == NULL || s[0] == L'\0')
        return FALSE;
    for (i = 0; i < 4; ++i) {
        unsigned v = 0;
        int digits = 0;

        while (*p >= L'0' && *p <= L'9') {
            v = v * 10 + (unsigned)(*p - L'0');
            p++;
            if (++digits > 3 || v > 255)
                return FALSE;
        }
        if (digits == 0)
            return FALSE;
        o[i] = v;
        if (i < 3) {
            if (*p != L'.')
                return FALSE;
            p++;
        }
    }
    if (*p != L':')
        return FALSE;
    p++;
    {
        int digits = 0;

        while (*p >= L'0' && *p <= L'9') {
            port = port * 10 + (unsigned)(*p - L'0');
            p++;
            if (++digits > 5 || port > 65535)
                return FALSE;
        }
        if (digits == 0 || port == 0)
            return FALSE;
    }
    if (*p != L'\0')
        return FALSE;
    ZeroMemory(out, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((u_short)port);
    out->sin_addr.s_addr = htonl((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]);
    return TRUE;
}

/* 源地址传递（PROXY protocol）：NAThelper 到本地服务这一段是本地回环，
   服务看到的对端永远是 127.0.0.1。要让服务拿到真实来源，只能把来源地址
   写进数据流最前面——这正是 haproxy/nginx/Steam 等通用的 PROXY protocol。 */
#define TCP_PROXY_WAIT_MS       200ULL          /* 最多等服务先开口这么久 */
#define PP_V2_SIG               "\r\n\r\n\x00\r\nQUIT\n"
#define PP_V2_SIG_LEN           12
#define PP_V2_CMD_PROXY         0x21
#define PP_V2_FAM_TCP4          0x11

/* 只支持 TCP4：之前那段 IPv6 分支把 4 字节地址写进 16 字节字段、
   长度也算错，是错的；本工具的映射本身也只有 IPv4。 */
static int BuildProxyV2(char *out, int outCch, const SOCKADDR_IN *peer,
                        const SOCKADDR_IN *local4)
{
    char *p = out;

    if (out == NULL || peer == NULL || local4 == NULL || outCch < 28)
        return 0;
    p[0] = '\r';
    p[1] = '\n';
    p[2] = '\r';
    p[3] = '\n';
    p[4] = 0x00;
    p[5] = '\r';
    p[6] = '\n';
    p[7] = 'Q';
    p[8] = 'U';
    p[9] = 'I';
    p[10] = 'T';
    p[11] = '\n';
    p += PP_V2_SIG_LEN;
    *p++ = PP_V2_CMD_PROXY;
    *p++ = PP_V2_FAM_TCP4;
    *p++ = 0x00;
    *p++ = 12;                                  /* 4+4+2+2 */
    memcpy(p, &peer->sin_addr, 4);
    memcpy(p + 4, &local4->sin_addr, 4);
    p += 8;
    memcpy(p, &peer->sin_port, 2);
    memcpy(p + 2, &local4->sin_port, 2);
    p += 4;
    return (int)(p - out);
}

static int BuildProxyV1(char *out, int outCch, const SOCKADDR_IN *peer,
                        const SOCKADDR_IN *local4)
{
    char a[24], b[24];
    char line[128];
    int n;

    WipToAscii(peer, a, sizeof(a));
    WipToAscii(local4, b, sizeof(b));
    WCHAR w[160];
    WCHAR wa[24];
    WCHAR wb[24];

    AsciiToW(a, wa, sizeof(wa) / sizeof(wa[0]));
    AsciiToW(b, wb, sizeof(wb) / sizeof(wb[0]));
    WPrintf(w, sizeof(w) / sizeof(w[0]), L"PROXY TCP4 %s %s %u %u\r\n",
            wa, wb, (unsigned)ntohs(peer->sin_port),
            (unsigned)ntohs(local4->sin_port));
    for (n = 0; w[n] != L'\0' && n + 1 < (int)sizeof(line); ++n)
        line[n] = (char)w[n];
    line[n] = '\0';
    if (n <= 0 || n >= outCch)
        return 0;
    memcpy(out, line, (size_t)n);
    return n;
}

/* 一个 TCP 中转连接：client 是外部进来的连接，backend 是本地服务。
   两个方向各有一个发送队列，select 同时盯着读写：
   - 任何一侧 recv 返回 0 表示这个方向结束，等队列发空后对另一侧
     shutdown(SD_SEND) 做半关闭，反方向的数据仍然可以继续传；
   - 队列满就不再读那一侧，形成自然背压，不会无限吃内存；
   - 所有 socket 都是非阻塞的，不会被对端卡死。 */
static DWORD WINAPI TcpRelayThread(LPVOID param)
{
    TCP_CONN *conn = (TCP_CONN *)param;
    NAT_MAPPING *m = conn->owner;
    char c2b[TCP_RELAY_CAP];        /* 客户端 -> 服务 */
    char b2c[TCP_RELAY_CAP];        /* 服务 -> 客户端 */
    int c2bLen = 0, b2cLen = 0;     /* 队列里的字节数 */
    int c2bOff = 0, b2cOff = 0;     /* 已经发走的字节数 */
    int c2bEof = 0, b2cEof = 0;     /* 该方向已读到 EOF */
    int c2bDone = 0, b2cDone = 0;   /* 该方向已收尾 */
    ULONGLONG inBytes = 0, outBytes = 0;
    ULONGLONG pubIn = 0, pubOut = 0;
    unsigned long inPkts = 0, outPkts = 0;
    unsigned long pubInPkts = 0, pubOutPkts = 0;
    ULONGLONG now = NowMs64();
    ULONGLONG lastFlush = now;
    ULONGLONG lastProgress = now;
    WCHAR e[128];

    /* 连接本地服务放在这个线程里做：accept 循环不能再被最长 5 秒的
       连接过程堵住，否则一个慢服务就能让整个映射收不到新连接。 */
    conn->backend = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (conn->backend == INVALID_SOCKET) {
        FormatWsaError(WSAGetLastError(), e, sizeof(e) / sizeof(e[0]));
        AddLog(L"[%s] TCP 创建到本地服务的 socket 失败: %s", m->name, e);
        goto done;
    }
    if (!ConnectWithTimeout(conn->backend, &conn->backend_addr,
                            TCP_BACKEND_TIMEOUT_MS, &m->stop)) {
        EnterCriticalSection(&g_cs);
        FormatWsaError(WSAGetLastError(), e, sizeof(e) / sizeof(e[0]));
        LeaveCriticalSection(&g_cs);
        AddLog(L"[%s] TCP 连接本地服务 %s:%u 失败: %s", m->name,
               m->backend_host, (unsigned)m->backend_port, e);
        goto done;
    }
    if (InterlockedCompareExchange(&conn->closing, 0, 0) != 0)
        goto done;

    {
        int one = 1;

        setsockopt(conn->backend, IPPROTO_TCP, TCP_NODELAY,
                   (const char *)&one, sizeof(one));
        setsockopt(conn->client, IPPROTO_TCP, TCP_NODELAY,
                   (const char *)&one, sizeof(one));
    }
    if (!SetNonBlocking(conn->backend, TRUE) ||
        !SetNonBlocking(conn->client, TRUE)) {
        FormatWsaError(WSAGetLastError(), e, sizeof(e) / sizeof(e[0]));
        AddLog(L"[%s] TCP 设置非阻塞失败: %s", m->name, e);
        goto done;
    }

    /* 需要传递源地址时，先给服务写一份 PROXY protocol 头。
       公网地址要加锁读，避免和映射线程的更新打架。 */
    if (m->proxy_protocol) {
        SOCKADDR_IN lstLocal;
        SOCKADDR_IN pubLocal;
        int lstLen = (int)sizeof(lstLocal);
        int hl;

        ZeroMemory(&lstLocal, sizeof(lstLocal));
        lstLocal.sin_family = AF_INET;
        lstLocal.sin_port = htons(conn->local_port);
        lstLocal.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (getsockname(conn->client, (SOCKADDR *)&lstLocal, &lstLen) == SOCKET_ERROR)
            lstLocal.sin_port = htons(conn->local_port);
        {
            WCHAR pub[64];

            pub[0] = L'\0';
            EnterCriticalSection(&g_cs);
            CopyW(pub, sizeof(pub) / sizeof(pub[0]), m->public_addr);
            LeaveCriticalSection(&g_cs);
            if (ParseIpv4PortW(pub, &pubLocal))
                lstLocal = pubLocal;
        }

        if (m->proxy_v1)
            hl = BuildProxyV1(c2b, TCP_RELAY_CAP, &conn->peer_addr, &lstLocal);
        else
            hl = BuildProxyV2(c2b, TCP_RELAY_CAP, &conn->peer_addr, &lstLocal);
        if (hl > 0) {
            c2bLen = hl;
        } else {
            AddLog(L"[%s] 生成 PROXY 协议头失败，本条连接按不带头发送", m->name);
        }
    }

    for (;;) {
        fd_set rfds;
        fd_set wfds;
        struct timeval tv;
        int sel;

        if (InterlockedCompareExchange(&conn->closing, 0, 0) != 0)
            break;

        now = NowMs64();
        if (now - lastFlush >= 1000) {
            ULONGLONG dIn = inBytes - pubIn;
            ULONGLONG dOut = outBytes - pubOut;

            if (dIn != 0 || dOut != 0) {
                EnterCriticalSection(&g_cs);
                conn->bytes_in += dIn;
                conn->bytes_out += dOut;
                conn->last_active = now;
                if (conn->owner != NULL) {
                    conn->owner->bytes_in += dIn;
                    conn->owner->bytes_out += dOut;
                    conn->owner->pkts_in += inPkts - pubInPkts;
                    conn->owner->pkts_out += outPkts - pubOutPkts;
                }
                LeaveCriticalSection(&g_cs);
                pubIn = inBytes;
                pubOut = outBytes;
                pubInPkts = inPkts;
                pubOutPkts = outPkts;
            }
            lastFlush = now;
        }

        if (c2bDone && b2cDone)
            break;

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        if (!c2bEof && c2bLen < TCP_RELAY_CAP)
            FD_SET(conn->client, &rfds);
        if (!b2cEof && b2cLen < TCP_RELAY_CAP)
            FD_SET(conn->backend, &rfds);
        if (c2bLen > 0)
            FD_SET(conn->backend, &wfds);
        if (b2cLen > 0)
            FD_SET(conn->client, &wfds);

        tv.tv_sec = 0;
        tv.tv_usec = 250000;
        sel = select(0, &rfds, &wfds, NULL, &tv);
        if (sel == SOCKET_ERROR) {
            int err = WSAGetLastError();

            if (err == WSAEINTR)
                continue;
            FormatWsaError(err, e, sizeof(e) / sizeof(e[0]));
            AddLog(L"[%s] TCP 中继 select 失败: %s", m->name, e);
            break;
        }

        /* 数据发不动超过 5 秒（对端不读），直接断开，避免连接永远挂着 */
        if (sel == 0) {
            if ((c2bLen > 0 || b2cLen > 0) &&
                now - lastProgress >= TCP_RELAY_STALL_MS) {
                AddLog(L"[%s] TCP 中继连续 %u 毫秒发不出数据，断开连接 %s",
                       m->name, (unsigned)TCP_RELAY_STALL_MS, conn->peer);
                break;
            }
            continue;
        }

        if (FD_ISSET(conn->client, &rfds)) {
            int n = recv(conn->client, c2b + c2bLen, TCP_RELAY_CAP - c2bLen, 0);

            if (n > 0) {
                c2bLen += n;
                inBytes += (ULONGLONG)n;
                inPkts++;
            } else if (n == 0) {
                c2bEof = 1;
            } else {
                int err = WSAGetLastError();

                if (err != WSAEWOULDBLOCK && err != WSAEINTR) {
                    FormatWsaError(err, e, sizeof(e) / sizeof(e[0]));
                    AddLog(L"[%s] TCP 读取对端数据失败: %s", m->name, e);
                    break;
                }
            }
        }

        if (FD_ISSET(conn->backend, &rfds)) {
            int n = recv(conn->backend, b2c + b2cLen, TCP_RELAY_CAP - b2cLen, 0);

            if (n > 0) {
                b2cLen += n;
                outBytes += (ULONGLONG)n;
                outPkts++;
            } else if (n == 0) {
                b2cEof = 1;
            } else {
                int err = WSAGetLastError();

                if (err != WSAEWOULDBLOCK && err != WSAEINTR) {
                    FormatWsaError(err, e, sizeof(e) / sizeof(e[0]));
                    AddLog(L"[%s] TCP 读取本地服务数据失败: %s", m->name, e);
                    break;
                }
            }
        }

        if (FD_ISSET(conn->backend, &wfds) && c2bLen > c2bOff) {
            int n = send(conn->backend, c2b + c2bOff, c2bLen - c2bOff, 0);

            if (n > 0) {
                c2bOff += n;
                lastProgress = now;
            } else if (n == SOCKET_ERROR) {
                int err = WSAGetLastError();

                if (err != WSAEWOULDBLOCK && err != WSAEINTR) {
                    FormatWsaError(err, e, sizeof(e) / sizeof(e[0]));
                    AddLog(L"[%s] TCP 发送到本地服务失败: %s", m->name, e);
                    break;
                }
            }
        }

        if (FD_ISSET(conn->client, &wfds) && b2cLen > b2cOff) {
            int n = send(conn->client, b2c + b2cOff, b2cLen - b2cOff, 0);

            if (n > 0) {
                b2cOff += n;
                lastProgress = now;
            } else if (n == SOCKET_ERROR) {
                int err = WSAGetLastError();

                if (err != WSAEWOULDBLOCK && err != WSAEINTR) {
                    FormatWsaError(err, e, sizeof(e) / sizeof(e[0]));
                    AddLog(L"[%s] TCP 发送到对端失败: %s", m->name, e);
                    break;
                }
            }
        }

        if (c2bOff > 0) {
            if (c2bOff >= c2bLen) {
                c2bOff = 0;
                c2bLen = 0;
            } else {
                memmove(c2b, c2b + c2bOff, (size_t)(c2bLen - c2bOff));
                c2bLen -= c2bOff;
                c2bOff = 0;
            }
        }
        if (b2cOff > 0) {
            if (b2cOff >= b2cLen) {
                b2cOff = 0;
                b2cLen = 0;
            } else {
                memmove(b2c, b2c + b2cOff, (size_t)(b2cLen - b2cOff));
                b2cLen -= b2cOff;
                b2cOff = 0;
            }
        }

        /* 一个方向读完了：把队列发空后对另一侧做半关闭 */
        if (c2bEof && !c2bDone && c2bLen == 0) {
            shutdown(conn->backend, SD_SEND);
            c2bDone = 1;
        }
        if (b2cEof && !b2cDone && b2cLen == 0) {
            shutdown(conn->client, SD_SEND);
            b2cDone = 1;
        }
    }

done:
    InterlockedExchange(&conn->closing, 1);
    {
        ULONGLONG dIn = inBytes - pubIn;
        ULONGLONG dOut = outBytes - pubOut;

        EnterCriticalSection(&g_cs);
        if (conn->client != INVALID_SOCKET) {
            SOCKET s = conn->client;

            conn->client = INVALID_SOCKET;
            shutdown(s, SD_BOTH);
            closesocket(s);
        }
        if (conn->backend != INVALID_SOCKET) {
            SOCKET s = conn->backend;

            conn->backend = INVALID_SOCKET;
            shutdown(s, SD_BOTH);
            closesocket(s);
        }
        conn->bytes_in += dIn;
        conn->bytes_out += dOut;
        if (conn->owner != NULL) {
            conn->owner->bytes_in += dIn;
            conn->owner->bytes_out += dOut;
            conn->owner->pkts_in += inPkts - pubInPkts;
            conn->owner->pkts_out += outPkts - pubOutPkts;
        }
        LeaveCriticalSection(&g_cs);
    }
    InterlockedDecrement(&g_totalTcpConns);

    /* 映射已经被回收（等它退出等超时了）：这条连接自己收尾，不再碰 m */
    if (conn->owner == NULL) {
        if (conn->thread != NULL) {
            CloseHandle(conn->thread);
            conn->thread = NULL;
        }
        free(conn);
    }
    return 0;
}

static void ReapTcpConnections(NAT_MAPPING *m)
{
    TCP_CONN **pp;

    EnterCriticalSection(&g_cs);
    pp = &m->conns;
    while (*pp != NULL) {
        TCP_CONN *conn = *pp;

        if (conn->thread != NULL &&
            WaitForSingleObject(conn->thread, 0) == WAIT_OBJECT_0) {
            *pp = conn->next;
            CloseHandle(conn->thread);
            free(conn);
            if (m->conn_count > 0)
                m->conn_count--;
        } else {
            pp = &conn->next;
        }
    }
    LeaveCriticalSection(&g_cs);
}

/* 停止时先让所有中继线程自己退出；等不到就与映射脱钩，
   剩下的收尾工作交给线程自己完成，避免释放映射后还被旧线程访问。 */
static void AbortAllTcpConnections(NAT_MAPPING *m)
{
    ULONGLONG deadline;
    int orphans = 0;
    TCP_CONN *conn;

    EnterCriticalSection(&g_cs);
    for (conn = m->conns; conn != NULL; conn = conn->next) {
        InterlockedExchange(&conn->closing, 1);
        if (conn->client != INVALID_SOCKET)
            shutdown(conn->client, SD_BOTH);
        if (conn->backend != INVALID_SOCKET)
            shutdown(conn->backend, SD_BOTH);
    }
    LeaveCriticalSection(&g_cs);

    deadline = NowMs64() + STOP_WAIT_MS;
    for (;;) {
        BOOL any;

        ReapTcpConnections(m);
        EnterCriticalSection(&g_cs);
        any = (m->conns != NULL);
        LeaveCriticalSection(&g_cs);
        if (!any)
            return;
        if (NowMs64() >= deadline) {
            TCP_CONN **pp;

            EnterCriticalSection(&g_cs);
            pp = &m->conns;
            while (*pp != NULL) {
                TCP_CONN *c = *pp;

                *pp = c->next;
                c->next = NULL;
                c->owner = NULL;
                orphans++;
            }
            m->conns = NULL;
            m->conn_count = 0;
            LeaveCriticalSection(&g_cs);
            AddLog(L"[%s] 等待 TCP 中继线程退出超时，%d 条连接转由线程自行清理",
                   m->name, orphans);
            return;
        }
        Sleep(20);
    }
}

/* ------------------------------------------------------------------ */
/* TCP 映射线程                                                        */
/*                                                                     */
/* 本地端口由多个 socket 共享（都开 SO_REUSEADDR）：                   */
/*   - 监听 socket：全程常开，负责 accept 入站连接；                    */
/*   - 保活 socket(keeper)：连到 TCP_KEEPER_HOST，每 TCP_KEEPALIVE_MS   */
/*     发一次 HTTP HEAD，让连接和 NAT 映射都保持存活；                  */
/*   - STUN 查询 socket：每次保活时临时开一条同端口连接，问完立即关闭， */
/*     只用来更新公网端点显示。                                        */
/* 选端口时仍然先用 SO_EXCLUSIVEADDRUSE 独占验证一遍，确保端口没有被   */
/* 别的进程占着；验证通过才交给共享模式，空窗只有毫秒级。              */
/* ------------------------------------------------------------------ */
static DWORD WINAPI TcpMappingThread(LPVOID param)
{
    NAT_MAPPING *m = (NAT_MAPPING *)param;
    SOCKADDR_IN stunAddr;
    SOCKADDR_IN backendAddr;
    SOCKET listener = INVALID_SOCKET;
    SOCKET keeper = INVALID_SOCKET;      /* 与 STUN 的长连接，负责保活/取公网端点 */
    USHORT port = 0;
    WCHAR err[256];
    WCHAR publicAddr[64];
    BOOL haveMapping = FALSE;
    char upnpExtIp[64];
    USHORT upnpExtPort = 0;
    BOOL upnpMapped = FALSE;
    BOOL upnpPublicAddr = FALSE;
    ULONGLONG upnpNextAct = 0;
    ULONGLONG nextPunchAt;
    ULONGLONG lastRejectLog = 0;
    ULONGLONG lastBlackLog = 0;      /* 黑名单命中的日志限频 */
    int listenFailStreak = 0;
    unsigned long blackRejected = 0; /* 被黑名单拒绝的连接累计 */

    ZeroMemory(err, sizeof(err));
    ZeroMemory(publicAddr, sizeof(publicAddr));
    ZeroMemory(upnpExtIp, sizeof(upnpExtIp));

    AddLog(L"[%s] 启动 TCP 映射，STUN=%s:%u，服务=%s:%u",
           m->name, m->stun_host, (unsigned)m->stun_port,
           m->backend_host, (unsigned)m->backend_port);

    if (!ResolveIPv4(m->stun_host, m->stun_port, &stunAddr, err,
                     sizeof(err) / sizeof(err[0]))) {
        SetStatus(m, L"错误: STUN 服务器解析失败");
        AddLog(L"[%s] %s", m->name, err);
        goto cleanup;
    }
    if (!ResolveIPv4(m->backend_host, m->backend_port, &backendAddr, err,
                     sizeof(err) / sizeof(err[0]))) {
        SetStatus(m, L"错误: 服务地址解析失败");
        AddLog(L"[%s] %s", m->name, err);
        goto cleanup;
    }

    if (!m->auto_port &&
        m->local_port == m->backend_port &&
        IsLoopbackIPv4(backendAddr.sin_addr.s_addr)) {
        SetStatus(m, L"错误: 本地端口与服务端口相同");
        AddLog(L"[%s] 本地端口不能与本地服务端口相同（会形成回环）", m->name);
        goto cleanup;
    }

    /* 选端口：只用独占 socket 验证端口能否绑定，验证完立刻释放；
       STUN 探测交给后面的保活连接做，整条映射自始至终只建立一次
       NAT 映射，公网端口不会因为反复探测而漂移。 */
    {
        USHORT desired;
        int attempt;
        int tries;
        BOOL gotPort = FALSE;

        EnterCriticalSection(&g_cs);
        desired = m->local_port;
        LeaveCriticalSection(&g_cs);

        tries = m->auto_port ? 100 : 1;
        for (attempt = 0; attempt < tries; ++attempt) {
            USHORT candidate;

            if (InterlockedCompareExchange(&m->stop, 0, 0) != 0 ||
                InterlockedCompareExchange(&g_appStop, 0, 0) != 0)
                goto cleanup;

            if (m->auto_port)
                candidate = (attempt == 0 && desired != 0) ? desired
                                                           : (USHORT)RandomPort();
            else
                candidate = desired;

            if (m->auto_port && candidate == m->backend_port &&
                IsLoopbackIPv4(backendAddr.sin_addr.s_addr)) {
                desired = 0;
                continue;
            }

            err[0] = L'\0';
            if (TcpProbePort(candidate, err, sizeof(err) / sizeof(err[0]))) {
                port = candidate;
                gotPort = TRUE;
                break;
            }

            if (!m->auto_port) {
                SetStatus(m, L"错误: 本地端口绑定失败");
                AddLog(L"[%s] TCP 本地端口 %u 绑定失败: %s",
                       m->name, (unsigned)candidate, err);
                goto cleanup;
            }
            desired = 0;
        }

        if (!gotPort) {
            SetStatus(m, L"错误: 无法找到可用的 TCP 本地端口");
            AddLog(L"[%s] 无法找到可用的 TCP 本地端口", m->name);
            goto cleanup;
        }

        EnterCriticalSection(&g_cs);
        m->local_port = port;
        LeaveCriticalSection(&g_cs);
    }

    /* 先把监听立起来：端口一旦由监听 socket（共享模式）持有，
       后面的保活连接就能直接绑同一个端口，不再需要"关监听再打洞"。 */
    listener = TcpOpenListener(port, err, sizeof(err) / sizeof(err[0]));
    if (listener == INVALID_SOCKET) {
        SetStatus(m, L"错误: TCP 监听端口绑定失败");
        AddLog(L"[%s] TCP 监听端口 %u 打开失败: %s",
               m->name, (unsigned)port, err);
        goto cleanup;
    }

    if (m->use_upnp) {
        WCHAR uerr[192];

        uerr[0] = L'\0';
        if (UpnpMapPort(TRUE, port, &stunAddr, upnpExtIp,
                        sizeof(upnpExtIp), &upnpExtPort, uerr,
                        sizeof(uerr) / sizeof(uerr[0]))) {
            WCHAR wip[64];

            upnpMapped = TRUE;
            upnpPublicAddr = IsPublicIPv4Text(upnpExtIp) ? TRUE : FALSE;
            AsciiToW(upnpExtIp, wip, sizeof(wip) / sizeof(wip[0]));
            EnterCriticalSection(&g_cs);
            m->upnp_mapped = 1;
            m->upnp_ext_port = upnpExtPort;
            CopyW(m->upnp_ext_ip,
                  sizeof(m->upnp_ext_ip) / sizeof(m->upnp_ext_ip[0]), wip);
            LeaveCriticalSection(&g_cs);
            if (upnpPublicAddr) {
                WPrintf(publicAddr, sizeof(publicAddr) / sizeof(publicAddr[0]),
                        L"%s:%u", wip, (unsigned)upnpExtPort);
                SetPublicAddressText(m, publicAddr);
                AddLog(L"[%s] UPnP 端口映射已建立并校验通过: 公网 %s -> 本地 %u（租期 %u 秒，自动续约）",
                       m->name, publicAddr, (unsigned)port,
                       (unsigned)UPNP_LEASE_SECONDS);
            } else {
                WCHAR gwText[96];

                WPrintf(gwText, sizeof(gwText) / sizeof(gwText[0]), L"%s:%u",
                        wip, (unsigned)upnpExtPort);
                AddLog(L"[%s] UPnP 端口映射已建立并校验通过: 网关 %s -> 本地 %u（租期 %u 秒，自动续约）",
                       m->name, gwText, (unsigned)port,
                       (unsigned)UPNP_LEASE_SECONDS);
                AddLog(L"[%s] 外部仍连不进来时，先检查 Windows 防火墙是否放行本程序："
                       L"本程序是绿色单文件，入站规则必须指向实际运行的 exe 路径",
                       m->name);
            }
            upnpNextAct = NowMs64() + UPNP_RENEW_MS;
        } else {
            AddLog(L"[%s] UPnP 不可用（%s），改用 STUN 获取公网映射",
                   m->name, uerr);
            upnpNextAct = NowMs64() + UPNP_RETRY_MS * 5;
        }
    }

    /* 先用一条长期连接把 NAT 映射钉住（连 HTTP 目标，定期发 HEAD 保活），
       再用临时连接问 STUN 要公网端点。两者共用同一个本地端口，所以问到的
       就是这条映射真正的端点，而且映射不会被 STUN 服务器的 60 秒 RST 打断。 */
    {
        STUN_RESULT sr;
        WCHAR e[192];

        ZeroMemory(&sr, sizeof(sr));
        e[0] = L'\0';

        keeper = TcpOpenKeeper(port, &m->stop, e, sizeof(e) / sizeof(e[0]));
        if (keeper == INVALID_SOCKET)
            AddLog(L"[%s] 保活连接建立失败: %s（5 秒后重试；期间公网端口可能不稳定）",
                   m->name, e);

        if (TcpStunQueryShared(port, &stunAddr, &sr, e, sizeof(e) / sizeof(e[0]))) {
            haveMapping = TRUE;
            if (upnpMapped && upnpPublicAddr) {
                WCHAR stunText[64];

                FormatEndpointW(&sr, stunText,
                                sizeof(stunText) / sizeof(stunText[0]));
                AddLog(L"[%s] STUN 结果 %s（对外仍用 UPnP 的公网地址）",
                       m->name, stunText);
                NoteStunOk(m);
            } else {
                UpdatePublicAddress(m, &sr, publicAddr,
                                    sizeof(publicAddr) / sizeof(publicAddr[0]));
            }
        } else {
            AddLog(L"[%s] STUN 首次查询失败: %s（监听已在工作，稍后重试）",
                   m->name, e);
        }
        if (haveMapping) {
            EnterCriticalSection(&g_cs);
            m->last_keepalive = NowMs64();
            LeaveCriticalSection(&g_cs);
        }
    }

    if (haveMapping) {
        SetStatus(m, UpnpStatusText(upnpMapped));
        AddLog(L"[%s] TCP 映射建立: 公网 %s -> 本地端口 %u -> 服务 %s:%u",
               m->name, publicAddr, (unsigned)port,
               m->backend_host, (unsigned)m->backend_port);
    } else {
        SetStatus(m, L"TCP 监听 %u，等待 STUN 响应…", (unsigned)port);
        AddLog(L"[%s] TCP 正在监听本地端口 %u", m->name, (unsigned)port);
    }

    /* keeper 没建立成功时快点重试，别拖到 30 秒后 */
    nextPunchAt = NowMs64() +
                  ((haveMapping && keeper != INVALID_SOCKET) ? TCP_KEEPALIVE_MS
                                                             : KEEPALIVE_RETRY_MS);

    for (;;) {
        ULONGLONG now;
        fd_set rfds;
        struct timeval tv;
        int sel;

        if (InterlockedCompareExchange(&m->stop, 0, 0) != 0 ||
            InterlockedCompareExchange(&g_appStop, 0, 0) != 0)
            break;

        ReapTcpConnections(m);
        now = NowMs64();

        /* 1) 先给保活连接发个 HEAD：它持续持有 NAT 映射，断了就立刻重连
               （重连会换新的映射，公网端口可能变，所以要退避、别频繁重连）。
           2) 再用临时连接问一次 STUN：映射由 keeper 持有，所以结果稳定；
              这一步只负责更新列表里的公网端点显示。 */
        if (now >= nextPunchAt) {
            STUN_RESULT sr;
            WCHAR e[192];
            BOOL ok = FALSE;
            BOOL keeperOk = TRUE;

            ZeroMemory(&sr, sizeof(sr));
            e[0] = L'\0';

            if (keeper == INVALID_SOCKET) {
                keeperOk = FALSE;
            } else if (!TcpKeeperPing(keeper)) {
                closesocket(keeper);
                keeper = INVALID_SOCKET;
                keeperOk = FALSE;
            }
            if (!keeperOk) {
                WCHAR ke[192];

                ke[0] = L'\0';
                keeper = TcpOpenKeeper(port, &m->stop, ke,
                                       sizeof(ke) / sizeof(ke[0]));
                if (keeper == INVALID_SOCKET)
                    WPrintf(e, sizeof(e) / sizeof(e[0]),
                            L"保活连接不可用: %s", ke);
            }

            if (keeper != INVALID_SOCKET)
                ok = TcpStunQueryShared(port, &stunAddr, &sr, e,
                                        sizeof(e) / sizeof(e[0]));

            if (ok) {
                haveMapping = TRUE;
                EnterCriticalSection(&g_cs);
                m->last_keepalive = now;
                LeaveCriticalSection(&g_cs);
                if (upnpMapped && upnpPublicAddr)
                    NoteStunOk(m);
                else
                    UpdatePublicAddress(m, &sr, publicAddr,
                                        sizeof(publicAddr) / sizeof(publicAddr[0]));
                SetStatus(m, UpnpStatusText(upnpMapped));
                nextPunchAt = now + TCP_KEEPALIVE_MS;
            } else {
                ULONGLONG retry;
                unsigned long fails;

                if (e[0] == L'\0')
                    WPrintf(e, sizeof(e) / sizeof(e[0]), L"STUN 服务器无响应");
                EnterCriticalSection(&g_cs);
                fails = ++m->stun_fail_count;
                LeaveCriticalSection(&g_cs);
                /* 失败越多等得越久，避免网络抖动时反复换端口、刷满日志 */
                retry = KEEPALIVE_RETRY_MS * (fails >= 3 ? 4ULL
                                              : (fails == 2 ? 2ULL : 1ULL));
                if (retry > TCP_KEEPALIVE_MS)
                    retry = TCP_KEEPALIVE_MS;
                if (fails == 1 || (fails % 10UL) == 0)
                    AddLog(L"[%s] TCP 保活异常: %s（%lu 秒后重试）",
                           m->name, e, (unsigned long)(retry / 1000ULL));
                SetStatus(m, L"运行中 · STUN 保活异常");
                nextPunchAt = now + retry;
            }
            continue;
        }

        if (listener == INVALID_SOCKET) {
            listener = TcpOpenListener(port, err, sizeof(err) / sizeof(err[0]));
            if (listener == INVALID_SOCKET) {
                if (listenFailStreak == 0)
                    AddLog(L"[%s] TCP 监听端口 %u 重新打开失败: %s",
                           m->name, (unsigned)port, err);
                listenFailStreak++;
                Sleep(500);
                continue;
            }
            listenFailStreak = 0;
        }

        FD_ZERO(&rfds);
        FD_SET(listener, &rfds);
        tv.tv_sec = 0;
        tv.tv_usec = 250000;
        sel = select(0, &rfds, NULL, NULL, &tv);
        if (sel == SOCKET_ERROR) {
            int selErr = WSAGetLastError();
            WCHAR e[128];

            if (selErr == WSAEINTR)
                continue;
            FormatWsaError(selErr, e, sizeof(e) / sizeof(e[0]));
            SetStatus(m, L"错误: select 失败");
            AddLog(L"[%s] TCP select 失败: %s", m->name, e);
            break;
        }

        if (sel > 0 && FD_ISSET(listener, &rfds)) {
            int accepted = 0;

            while (accepted < TCP_ACCEPT_BATCH) {
                SOCKADDR_IN peer;
                int peerLen = (int)sizeof(peer);
                SOCKET client;
                TCP_CONN *conn;
                int canAccept;
                int newCount;

                client = accept(listener, (SOCKADDR *)&peer, &peerLen);
                if (client == INVALID_SOCKET) {
                    int accErr = WSAGetLastError();

                    if (accErr != WSAEWOULDBLOCK && accErr != WSAEINTR) {
                        WCHAR e[128];

                        FormatWsaError(accErr, e, sizeof(e) / sizeof(e[0]));
                        AddLog(L"[%s] TCP accept 失败: %s", m->name, e);
                    }
                    break;
                }
                accepted++;

                /* 黑名单只在这里查一次：命中立刻用 RST 断开，不建立中继线程。
                   已建立的连接不受影响。 */
                if (BlacklistMatchAddress(&peer.sin_addr)) {
                    blackRejected++;
                    if (lastBlackLog == 0 || now - lastBlackLog >= 5000) {
                        WCHAR peerText[64];

                        FormatSockAddrW(&peer, peerText,
                                        sizeof(peerText) / sizeof(peerText[0]));
                        AddLog(L"[%s] TCP 入站 %s 命中黑名单，已回复 RST（累计 %lu 次）",
                               m->name, peerText, blackRejected);
                        lastBlackLog = now;
                    }
                    TcpPunchClose(&client);
                    continue;
                }

                EnterCriticalSection(&g_cs);
                canAccept = (m->conn_count < MAX_TCP_CONNS &&
                             g_totalTcpConns < MAX_TOTAL_TCP_CONNS);
                newCount = m->conn_count + 1;
                LeaveCriticalSection(&g_cs);
                if (!canAccept) {
                    if (lastRejectLog == 0 || now - lastRejectLog >= 5000) {
                        AddLog(L"[%s] TCP 连接数已达上限（本映射最多 %d 条，全局最多 %d 条），"
                               L"暂时拒绝新连接",
                               m->name, MAX_TCP_CONNS, MAX_TOTAL_TCP_CONNS);
                        lastRejectLog = now;
                    }
                    closesocket(client);
                    continue;
                }

                {
                    int one = 1;

                    setsockopt(client, IPPROTO_TCP, TCP_NODELAY,
                               (const char *)&one, sizeof(one));
                }

                conn = (TCP_CONN *)calloc(1, sizeof(TCP_CONN));
                if (conn == NULL) {
                    closesocket(client);
                    continue;
                }
                conn->owner = m;
                conn->client = client;
                conn->backend = INVALID_SOCKET;
                conn->backend_addr = backendAddr;
                conn->peer_addr = peer;
                conn->local_port = port;
                conn->start = NowMs64();
                conn->last_active = conn->start;
                FormatSockAddrW(&peer, conn->peer,
                                sizeof(conn->peer) / sizeof(conn->peer[0]));

                /* 先挂起创建、挂进链表后再放行，保证 Abort 一定能看到它 */
                conn->thread = CreateThread(NULL, 0, TcpRelayThread, conn,
                                            CREATE_SUSPENDED, NULL);
                if (conn->thread == NULL) {
                    closesocket(client);
                    free(conn);
                    continue;
                }

                EnterCriticalSection(&g_cs);
                conn->next = m->conns;
                m->conns = conn;
                m->conn_count++;
                InterlockedIncrement(&g_totalTcpConns);
                newCount = m->conn_count;
                LeaveCriticalSection(&g_cs);
                ResumeThread(conn->thread);

                if (newCount < 20 || (newCount % 10) == 0)
                    AddLog(L"[%s] TCP 入站连接 %s（当前 %d 条）",
                           m->name, conn->peer, newCount);
            }
        }

        if (m->use_upnp && now >= upnpNextAct) {
            WCHAR uerr[192];
            char ip[64];
            USHORT ep = upnpMapped ? upnpExtPort : 0;
            BOOL ok;

            uerr[0] = L'\0';
            ok = UpnpMapPort(TRUE, port, &stunAddr, ip, sizeof(ip), &ep,
                             uerr, sizeof(uerr) / sizeof(uerr[0]));
            if (ok) {
                WCHAR wip[64];

                AsciiToW(ip, wip, sizeof(wip) / sizeof(wip[0]));
                WPrintf(publicAddr, sizeof(publicAddr) / sizeof(publicAddr[0]),
                        L"%s:%u", wip, (unsigned)ep);
                upnpPublicAddr = IsPublicIPv4Text(ip) ? TRUE : FALSE;
                if (upnpPublicAddr)
                    SetPublicAddressText(m, publicAddr);
                upnpExtPort = ep;
                CopyAscii(upnpExtIp, sizeof(upnpExtIp), ip);
                if (!upnpMapped) {
                    upnpMapped = TRUE;
                    EnterCriticalSection(&g_cs);
                    m->upnp_mapped = 1;
                    m->upnp_ext_port = ep;
                    CopyW(m->upnp_ext_ip,
                          sizeof(m->upnp_ext_ip) / sizeof(m->upnp_ext_ip[0]), wip);
                    LeaveCriticalSection(&g_cs);
                    AddLog(L"[%s] UPnP 端口映射已建立: %s %s -> 本地 %u",
                           m->name, upnpPublicAddr ? L"公网" : L"网关（非公网）",
                           publicAddr, (unsigned)port);
                    SetStatus(m, UpnpStatusText(upnpMapped));
                }
                upnpNextAct = now + UPNP_RENEW_MS;
            } else if (upnpMapped) {
                /* 续约失败：网关上的规则可能已经失效，不能再声称 UPnP 可用，
                   立刻把公网地址交还给 STUN 结果，避免显示一个连不上的地址 */
                AddLog(L"[%s] UPnP 续约失败: %s（改用 STUN 结果，%u 秒后重试 UPnP）",
                       m->name, uerr, (unsigned)(UPNP_RETRY_MS / 1000ULL));
                upnpMapped = FALSE;
                upnpPublicAddr = FALSE;
                EnterCriticalSection(&g_cs);
                m->upnp_mapped = 0;
                LeaveCriticalSection(&g_cs);
                SetStatus(m, L"运行中 · UPnP 续约失败，以 STUN 为准");
                upnpNextAct = now + UPNP_RETRY_MS;
            } else {
                AddLog(L"[%s] UPnP 仍不可用: %s", m->name, uerr);
                upnpNextAct = now + UPNP_RETRY_MS * 5;
            }
        }
    }

cleanup:
    if (keeper != INVALID_SOCKET) {
        closesocket(keeper);
        keeper = INVALID_SOCKET;
    }
    if (listener != INVALID_SOCKET) {
        closesocket(listener);
        listener = INVALID_SOCKET;
    }
    AbortAllTcpConnections(m);
    EnterCriticalSection(&g_cs);
    m->upnp_mapped = 0;
    LeaveCriticalSection(&g_cs);
    if (upnpExtPort != 0)
        UpnpRemoveMappedPort(TRUE, upnpExtPort);
    SetStatus(m, L"已停止");
    AddLog(L"[%s] TCP 映射已停止", m->name);
    InterlockedExchange(&m->running, 0);
    return 0;
}

/* ------------------------------------------------------------------ */
/* 映射生命周期                                                        */
/* ------------------------------------------------------------------ */

static NAT_MAPPING *FindMappingByListParam(LPARAM param)
{
    NAT_MAPPING *m;
    for (m = g_maps; m != NULL; m = m->next) {
        if ((LPARAM)m == param)
            return m;
    }
    return NULL;
}

static BOOL StartMapping(NAT_MAPPING *m)
{
    DWORD tid = 0;

    if (InterlockedCompareExchange(&m->running, 0, 0) != 0)
        return FALSE;

    if (m->thread != NULL) {
        if (WaitForSingleObject(m->thread, 0) != WAIT_OBJECT_0)
            return FALSE;
        CloseHandle(m->thread);
        m->thread = NULL;
    }

    InterlockedExchange(&m->stop, 0);
    EnterCriticalSection(&g_cs);
    m->status[0] = L'\0';
    m->public_addr[0] = L'\0';
    m->mapping_ok = 0;
    m->upnp_mapped = 0;
    m->upnp_ext_port = 0;
    m->upnp_ext_ip[0] = L'\0';
    m->last_keepalive = 0;
    m->stun_ok_count = 0;
    m->stun_fail_count = 0;
    m->bytes_in = 0;
    m->bytes_out = 0;
    m->pkts_in = 0;
    m->pkts_out = 0;
    LeaveCriticalSection(&g_cs);
    SetStatus(m, L"启动中…");

    InterlockedExchange(&m->running, 1);
    m->thread = CreateThread(NULL, 0,
                             m->proto == PROTO_TCP ? TcpMappingThread : UdpMappingThread,
                             m, 0, &tid);
    if (m->thread == NULL) {
        InterlockedExchange(&m->running, 0);
        SetStatus(m, L"错误: 创建线程失败");
        AddLog(L"[%s] 创建映射线程失败: %lu", m->name, (unsigned long)GetLastError());
        return FALSE;
    }
    return TRUE;
}

static BOOL StopMapping(NAT_MAPPING *m)
{
    DWORD waitResult;

    if (m->thread == NULL) {
        InterlockedExchange(&m->running, 0);
        if (!m->status[0])
            SetStatus(m, L"已停止");
        return TRUE;
    }

    InterlockedExchange(&m->stop, 1);
    waitResult = WaitForSingleObject(m->thread, STOP_WAIT_MS);
    if (waitResult == WAIT_OBJECT_0) {
        CloseHandle(m->thread);
        m->thread = NULL;
        InterlockedExchange(&m->running, 0);
        SetStatus(m, L"已停止");
        return TRUE;
    }

    AddLog(L"[%s] 停止超时，线程仍在退出中", m->name);
    return FALSE;
}

static void FreeMapping(NAT_MAPPING *m)
{
    if (m == NULL)
        return;

    /* 线程活着就绝对不能释放：它还在往 m 里写状态、统计和 UPnP 字段。
       正常情况下调用前已经 StopMapping 成功，这里只是最后一道保险。 */
    if (m->thread != NULL) {
        if (WaitForSingleObject(m->thread, 0) != WAIT_OBJECT_0) {
            AddLog(L"[%s] 映射线程尚未退出，暂不释放该映射", m->name);
            return;
        }
        CloseHandle(m->thread);
        m->thread = NULL;
    }
    free(m);
}

/* ------------------------------------------------------------------ */
/* 日志与列表                                                          */
/* ------------------------------------------------------------------ */

/* 日志满了就整段清空再继续写。
   注意：编辑框自身有字符上限，写满之后 EM_REPLACESEL 会被静默丢弃，
   GetWindowTextLengthW 也不再增长——看上去就是"日志卡住不动"。
   所以这里既在接近上限时主动清空，也在追加后校验长度，被拒就重来一次。 */
static void AppendLogText(const WCHAR *text)
{
    int len;
    int add;
    int after;

    if (g_hwndLog == NULL || text == NULL)
        return;

    add = (int)wcslen(text);
    if (add <= 0)
        return;

    len = GetWindowTextLengthW(g_hwndLog);
    if (len < 0)
        len = 0;

    if (len + add + 64 >= LOG_MAX_CHARS) {
        SetWindowTextW(g_hwndLog, L"");
        SendMessageW(g_hwndLog, EM_SETSEL, 0, 0);
        SendMessageW(g_hwndLog, EM_REPLACESEL, FALSE,
                     (LPARAM)L"[日志已达上限，已自动清空，继续记录新内容]\r\n");
        len = GetWindowTextLengthW(g_hwndLog);
        if (len < 0)
            len = 0;
    }

    /* 只追加新行：不重设整段文本，滚动时不会出现文字重影 */
    SendMessageW(g_hwndLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_hwndLog, EM_REPLACESEL, FALSE, (LPARAM)text);

    after = GetWindowTextLengthW(g_hwndLog);
    if (after <= len) {
        /* 追加被控件拒绝（已到上限或状态异常）：清空后重试 */
        SetWindowTextW(g_hwndLog, L"");
        SendMessageW(g_hwndLog, EM_SETSEL, 0, 0);
        SendMessageW(g_hwndLog, EM_REPLACESEL, FALSE, (LPARAM)text);
    }
    SendMessageW(g_hwndLog, EM_SCROLLCARET, 0, 0);
}

static void SetListSubItem(int item, int subItem, const WCHAR *text)
{
    WCHAR old[512];

    if (g_hwndList == NULL)
        return;
    old[0] = L'\0';
    ListView_GetItemText(g_hwndList, item, subItem, old,
                         (int)(sizeof(old) / sizeof(old[0])));
    if (wcscmp(old, text) != 0)
        ListView_SetItemText(g_hwndList, item, subItem, (LPWSTR)text);
}

static int FindListIndexByMapping(NAT_MAPPING *m)
{
    int count;
    int i;

    if (g_hwndList == NULL)
        return -1;
    count = ListView_GetItemCount(g_hwndList);
    for (i = 0; i < count; ++i) {
        LVITEMW item;
        ZeroMemory(&item, sizeof(item));
        item.mask = LVIF_PARAM;
        item.iItem = i;
        if (ListView_GetItem(g_hwndList, &item) && (NAT_MAPPING *)item.lParam == m)
            return i;
    }
    return -1;
}

static int InsertMappingListItem(NAT_MAPPING *m)
{
    LVITEMW item;
    int idx;

    if (g_hwndList == NULL)
        return -1;
    ZeroMemory(&item, sizeof(item));
    item.mask = LVIF_TEXT | LVIF_PARAM;
    item.iItem = ListView_GetItemCount(g_hwndList);
    item.pszText = m->name;
    item.lParam = (LPARAM)m;
    idx = ListView_InsertItem(g_hwndList, &item);
    if (idx >= 0) {
        SetListSubItem(idx, 1, m->proto == PROTO_TCP ? L"TCP" : L"UDP");
        SetListSubItem(idx, 2, m->local_port == 0 ? L"随机中" : L"");
        SetListSubItem(idx, 3, m->backend_host);
        SetListSubItem(idx, 4, L"—");
        SetListSubItem(idx, 5, L"启动中…");
        SetListSubItem(idx, 6, L"—");
        SetListSubItem(idx, 7, L"入 0KB / 出 0KB");
    }
    return idx;
}

static BOOL SnapshotMapping(NAT_MAPPING *m, MAP_ROW *row)
{
    ULONGLONG now = NowMs64();

    ZeroMemory(row, sizeof(*row));
    row->m = m;

    EnterCriticalSection(&g_cs);
    CopyW(row->name, sizeof(row->name) / sizeof(row->name[0]), m->name);
    CopyW(row->status, sizeof(row->status) / sizeof(row->status[0]), m->status);
    if (m->proxy_protocol) {
        size_t cap = sizeof(row->status) / sizeof(row->status[0]);
        size_t n = wcslen(row->status);

        if (n + 8 < cap)
            wcscpy(row->status + n, L" · PROXY");
    }
    CopyW(row->public_addr, sizeof(row->public_addr) / sizeof(row->public_addr[0]),
          m->public_addr);
    CopyW(row->proto, sizeof(row->proto) / sizeof(row->proto[0]),
          m->proto == PROTO_TCP ? L"TCP" : L"UDP");
    if (m->local_port == 0)
        WPrintf(row->local, sizeof(row->local) / sizeof(row->local[0]), L"随机中");
    else
        WPrintf(row->local, sizeof(row->local) / sizeof(row->local[0]), L"%u",
                (unsigned)m->local_port);
    WPrintf(row->service, sizeof(row->service) / sizeof(row->service[0]), L"%s:%u",
            m->backend_host, (unsigned)m->backend_port);
    if (m->last_keepalive == 0) {
        WPrintf(row->keep, sizeof(row->keep) / sizeof(row->keep[0]), L"—");
    } else {
        ULONGLONG elapsed = (now > m->last_keepalive) ? (now - m->last_keepalive) : 0;
        if (elapsed < 1000)
            WPrintf(row->keep, sizeof(row->keep) / sizeof(row->keep[0]), L"刚刚");
        else
            WPrintf(row->keep, sizeof(row->keep) / sizeof(row->keep[0]), L"%lu 秒前",
                    (unsigned long)(elapsed / 1000ULL));
    }
    FormatTraffic(m->bytes_in, m->bytes_out, row->traffic,
                  sizeof(row->traffic) / sizeof(row->traffic[0]));
    LeaveCriticalSection(&g_cs);
    return TRUE;
}

static void RefreshList(void)
{
    int count;
    int i;

    if (g_hwndList == NULL)
        return;
    count = ListView_GetItemCount(g_hwndList);
    for (i = 0; i < count; ) {
        LVITEMW item;
        NAT_MAPPING *m;
        MAP_ROW row;

        ZeroMemory(&item, sizeof(item));
        item.mask = LVIF_PARAM;
        item.iItem = i;
        if (!ListView_GetItem(g_hwndList, &item)) {
            ++i;
            continue;
        }
        m = (NAT_MAPPING *)item.lParam;
        if (m == NULL || FindMappingByListParam((LPARAM)m) == NULL) {
            ListView_DeleteItem(g_hwndList, i);
            continue;
        }
        if (!SnapshotMapping(m, &row)) {
            ++i;
            continue;
        }
        SetListSubItem(i, 0, row.name);
        SetListSubItem(i, 1, row.proto);
        SetListSubItem(i, 2, row.local);
        SetListSubItem(i, 3, row.service);
        SetListSubItem(i, 4, row.public_addr[0] ? row.public_addr : L"—");
        SetListSubItem(i, 5, row.status[0] ? row.status : L"—");
        SetListSubItem(i, 6, row.keep);
        SetListSubItem(i, 7, row.traffic);
        ++i;
    }
}

static void UpdateStatusBar(void)
{
    int total = 0;
    int running = 0;
    WCHAR buf[256];
    NAT_MAPPING *m;

    EnterCriticalSection(&g_cs);
    for (m = g_maps; m != NULL; m = m->next) {
        total++;
        if (InterlockedCompareExchange(&m->running, 0, 0) != 0)
            running++;
    }
    LeaveCriticalSection(&g_cs);

    WPrintf(buf, sizeof(buf) / sizeof(buf[0]),
            L"映射 %d 个 · 运行 %d 个 · UDP 保活 30 秒 / TCP 保活 30 秒 · UPnP %s",
            total, running,
            (g_hwndUpnp != NULL &&
             SendMessageW(g_hwndUpnp, BM_GETCHECK, 0, 0) == BST_CHECKED)
                ? L"开" : L"关");
    SetWindowTextW(g_hwndStatus, buf);
}

/* ------------------------------------------------------------------ */
/* GUI 布局与控件                                                      */
/* ------------------------------------------------------------------ */

static HWND MakeControl(const WCHAR *className, const WCHAR *text, DWORD style,
                        DWORD exStyle, int id, HWND parent)
{
    return CreateWindowExW(exStyle, className, text,
                           WS_CHILD | WS_VISIBLE | style,
                           0, 0, 10, 10, parent, (HMENU)(INT_PTR)id,
                           g_hInst, NULL);
}

static BOOL CALLBACK ApplyFontProc(HWND hwnd, LPARAM lParam)
{
    SendMessageW(hwnd, WM_SETFONT, (WPARAM)lParam, TRUE);
    return TRUE;
}

static void CreateFonts(HWND hwnd)
{
#if NAT_ANSI
    NONCLIENTMETRICSA ncm;

    ZeroMemory(&ncm, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoA(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
        g_hFont = CreateFontIndirectA(&ncm.lfMessageFont);
        if (g_hFont != NULL)
            g_fontOwned = 1;
    }
#else
    NONCLIENTMETRICSW ncm;

    ZeroMemory(&ncm, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0)) {
        g_hFont = CreateFontIndirectW(&ncm.lfMessageFont);
        if (g_hFont != NULL)
            g_fontOwned = 1;
    }
#endif
    if (g_hFont == NULL)
        g_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    (void)hwnd;
}

static void ApplyFonts(HWND parent)
{
    if (g_hFont != NULL)
        EnumChildWindows(parent, ApplyFontProc, (LPARAM)g_hFont);
}

/* PROXY protocol 只对 TCP 有意义；没勾选"传递源地址"时 v1 也不可选 */
static void UpdateProxyEnable(void)
{
    int sel;
    BOOL tcp;
    BOOL on;

    if (g_hwndProxy == NULL || g_hwndProto == NULL)
        return;
    sel = (int)SendMessageW(g_hwndProto, CB_GETCURSEL, 0, 0);
    tcp = (sel == 1) ? TRUE : FALSE;
    on = (tcp && SendMessageW(g_hwndProxy, BM_GETCHECK, 0, 0) == BST_CHECKED)
             ? TRUE : FALSE;
    EnableWindow(g_hwndProxy, tcp);
    if (g_hwndProxyV1 != NULL)
        EnableWindow(g_hwndProxyV1, on);
}

static void CreateControls(HWND hwnd)
{
    g_hwndHint = MakeControl(L"STATIC",
        L"适合映射行为和过滤行为均为 EndpointIndependent 的无公网 IP 用户；已默认启用 UPnP 自动端口映射。\r\n"
        L"本工具不提供 NAT 类型检测（默认 STUN 服务器不支持该功能）。\r\n"
        NAT_PLATFORM_NOTE,
        SS_LEFT, 0, IDC_HINT, hwnd);

    g_hwndStunLabel = MakeControl(L"STATIC", L"STUN 服务器:", SS_LEFT, 0,
                                  IDC_STUN_LABEL, hwnd);
    g_hwndStun = MakeControl(L"EDIT", DEFAULT_STUN_TEXT,
        WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, IDC_STUN, hwnd);
    SendMessageW(g_hwndStun, EM_SETLIMITTEXT, 160, 0);
    g_hwndStunFormat = MakeControl(L"STATIC", L"格式 IP:端口", SS_LEFT, 0,
                                   IDC_STUN_FORMAT, hwnd);
    g_hwndKeepInfo = MakeControl(L"STATIC", L"UDP 保活 30 秒 / TCP 保活 30 秒",
                                 SS_RIGHT, 0, IDC_KEEPINFO, hwnd);
    g_hwndUpnp = MakeControl(L"BUTTON", L"启用 UPnP 自动端口映射（推荐）",
        WS_TABSTOP | BS_AUTOCHECKBOX, 0, IDC_UPNP, hwnd);
    SendMessageW(g_hwndUpnp, BM_SETCHECK, BST_CHECKED, 0);

    g_hwndGroup = MakeControl(L"BUTTON", L"新建映射（自动启动并保持）",
                              BS_GROUPBOX, 0, IDC_GROUP, hwnd);

    g_hwndProtoLabel = MakeControl(L"STATIC", L"协议:", SS_LEFT, 0,
                                   IDC_PROTO_LABEL, hwnd);
    g_hwndProto = MakeControl(L"COMBOBOX", NULL,
        WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, 0, IDC_PROTO, hwnd);
    SendMessageW(g_hwndProto, CB_ADDSTRING, 0, (LPARAM)L"UDP");
    SendMessageW(g_hwndProto, CB_ADDSTRING, 0, (LPARAM)L"TCP");
    SendMessageW(g_hwndProto, CB_SETCURSEL, 0, 0);

    g_hwndLocalLabel = MakeControl(L"STATIC", L"本地端口:", SS_LEFT, 0,
                                   IDC_LOCAL_LABEL, hwnd);
    g_hwndLocal = MakeControl(L"EDIT", L"",
        WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, IDC_LOCAL, hwnd);
    SendMessageW(g_hwndLocal, EM_SETLIMITTEXT, 5, 0);
    SendMessageW(g_hwndLocal, EM_SETCUEBANNER, TRUE, (LPARAM)L"留空=随机");
    g_hwndLocalHint = MakeControl(L"STATIC", L"留空=随机", SS_LEFT, 0,
                                  IDC_LOCAL_HINT, hwnd);

    g_hwndBackHostLabel = MakeControl(L"STATIC", L"服务地址:", SS_LEFT, 0,
                                      IDC_BACKHOST_LABEL, hwnd);
    g_hwndBackHost = MakeControl(L"EDIT", DEFAULT_BACKEND_HOST,
        WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, IDC_BACKHOST, hwnd);
    SendMessageW(g_hwndBackHost, EM_SETLIMITTEXT, 100, 0);

    g_hwndBackPortLabel = MakeControl(L"STATIC", L"服务端口:", SS_LEFT, 0,
                                      IDC_BACKPORT_LABEL, hwnd);
    g_hwndBackPort = MakeControl(L"EDIT", L"",
        WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, IDC_BACKPORT, hwnd);
    SendMessageW(g_hwndBackPort, EM_SETLIMITTEXT, 5, 0);

    g_hwndNameLabel = MakeControl(L"STATIC", L"名称:", SS_LEFT, 0,
                                  IDC_NAME_LABEL, hwnd);
    g_hwndName = MakeControl(L"EDIT", L"",
        WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, IDC_NAME, hwnd);
    SendMessageW(g_hwndName, EM_SETLIMITTEXT, 48, 0);
    SendMessageW(g_hwndName, EM_SETCUEBANNER, TRUE, (LPARAM)L"可选");

    g_hwndProxy = MakeControl(L"BUTTON", L"传递源地址（PROXY protocol）",
        WS_TABSTOP | BS_AUTOCHECKBOX, 0, IDC_PROXY, hwnd);
    g_hwndProxyV1 = MakeControl(L"BUTTON", L"用 v1 文本格式",
        WS_TABSTOP | BS_AUTOCHECKBOX, 0, IDC_PROXY_V1, hwnd);
    g_hwndProxyHint = MakeControl(L"STATIC",
        L"服务端需同时开启；服务端只认文本头才勾 v1，否则不要勾",
        SS_LEFT, 0, IDC_PROXY_HINT, hwnd);

    g_hwndAdd = MakeControl(L"BUTTON", L"添加并启动",
        WS_TABSTOP | BS_DEFPUSHBUTTON, 0, IDC_ADD, hwnd);
    g_hwndAddHint = MakeControl(L"STATIC",
        L"添加后自动启动；UDP 随机端口范围 1024-65535。",
        SS_LEFT, 0, IDC_ADD_HINT, hwnd);

    g_hwndList = MakeControl(WC_LISTVIEWW, NULL,
        WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_BORDER,
        0, IDC_LIST, hwnd);
    ListView_SetExtendedListViewStyle(g_hwndList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    g_hwndStart = MakeControl(L"BUTTON", L"启动选中", WS_TABSTOP, 0, IDC_START, hwnd);
    g_hwndStop = MakeControl(L"BUTTON", L"停止选中", WS_TABSTOP, 0, IDC_STOP, hwnd);
    g_hwndDelete = MakeControl(L"BUTTON", L"删除选中", WS_TABSTOP, 0, IDC_DELETE, hwnd);
    g_hwndStopAll = MakeControl(L"BUTTON", L"全部停止", WS_TABSTOP, 0, IDC_STOPALL, hwnd);
    g_hwndConnTable = MakeControl(L"BUTTON", L"连接表", WS_TABSTOP, 0, IDC_CONNTABLE, hwnd);
    g_hwndBlackBtn = MakeControl(L"BUTTON", L"黑名单", WS_TABSTOP, 0, IDC_BLACKLIST, hwnd);
    g_hwndClearLog = MakeControl(L"BUTTON", L"清空日志", WS_TABSTOP, 0, IDC_CLEARLOG, hwnd);

    g_hwndLogLabel = MakeControl(L"STATIC", L"运行日志:", SS_LEFT, 0, IDC_LOGLABEL, hwnd);
    g_hwndLog = MakeControl(L"EDIT", L"",
        ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
        WS_EX_CLIENTEDGE, IDC_LOG, hwnd);
    /* 显式放宽控件上限，保证整段日志都能写进去 */
    SendMessageW(g_hwndLog, EM_SETLIMITTEXT, (WPARAM)(LOG_MAX_CHARS + 8192), 0);
    g_hwndStatus = MakeControl(L"STATIC", L"", SS_LEFT, 0, IDC_STATUS, hwnd);
    ApplyFonts(hwnd);
    UpdateProxyEnable();
}

/* 提示条是多行 STATIC。STATIC 的文字一旦超出控件矩形就会画到控件外，
   窗口变窄时文字换行增多，残留笔画就会糊在别的控件上（"碎成渣"）。
   所以每次布局都按当前宽度重新量一次高度。 */
static int CalcHintBoxHeight(HWND hwnd, int width)
{
    WCHAR text[1024];
    HDC dc;
    HFONT old = NULL;
    RECT rc;
    int h;

    text[0] = L'\0';
    if (g_hwndHint != NULL)
        GetWindowTextW(g_hwndHint, text, (int)(sizeof(text) / sizeof(text[0])));
    if (text[0] == L'\0' || width <= 0)
        return 44;

    dc = GetDC(hwnd);
    if (dc == NULL)
        return 44;
    if (g_hFont != NULL)
        old = (HFONT)SelectObject(dc, g_hFont);
    rc.left = 0;
    rc.top = 0;
    rc.right = width;
    rc.bottom = 0;
    DrawTextW(dc, text, -1, &rc, DT_CALCRECT | DT_WORDBREAK | DT_LEFT | DT_NOPREFIX);
    if (g_hFont != NULL)
        SelectObject(dc, old);
    ReleaseDC(hwnd, dc);

    h = rc.bottom - rc.top;
    if (h < 40)
        h = 40;
    return h + 4;
}

/* 窗口内容高度超过可视高度时整体垂直滚动：g_scrollY 是当前偏移，
   g_scrollShown 记录滚动条是否可见（不读窗口样式，9x 上少走一次 API）。 */
static int g_scrollY = 0;
static BOOL g_scrollShown = FALSE;

/* 单次布局：按 off 偏移摆一遍所有控件，返回内容总高度（不含状态栏）。
   调用方负责决定要不要滚动条、偏移是否合法。 */
static int LayoutPass(HWND hwnd, int W, int H, int off)
{
    int margin = 16;
    int y;
    int hintH;
    int compact;
    int groupH;
    int listTop;
    int listH;
    int logH;
    int availH;
    /* 流量列固定 210px（"入 1023.99 MB / 出 1023.99 MB" 也放得下），
       剩余宽度全部给"状态"列 */
    int baseWidths[8] = { 92, 52, 70, 124, 160, 150, 72, 210 };
    int extra;
    int i;

    /* 宽度不够时把"协议/端口"和"服务地址"拆成两行，否则右侧控件会被
       窗口边缘裁掉（640x480 上原本就是这样，文字糊在边框外面）。 */
    compact = ((W - 2 * margin) < 860) ? 1 : 0;

    hintH = CalcHintBoxHeight(hwnd, W - 2 * margin);
    MoveWindow(g_hwndHint, margin, 8 - off, W - 2 * margin, hintH, TRUE);
    y = 8 + hintH + 8;

    if (!compact) {
        MoveWindow(g_hwndStunLabel, margin, y + 4 - off, 92, 20, TRUE);
        MoveWindow(g_hwndStun, margin + 96, y - off, 210, 24, TRUE);
        MoveWindow(g_hwndStunFormat, margin + 314, y + 4 - off, 110, 20, TRUE);
        MoveWindow(g_hwndUpnp, margin + 432, y + 2 - off, 250, 22, TRUE);
        MoveWindow(g_hwndKeepInfo, W - margin - 300, y + 4 - off, 300, 20, TRUE);
        ShowWindow(g_hwndStunFormat, SW_SHOW);
        ShowWindow(g_hwndKeepInfo, SW_SHOW);
        y += 32;
    } else {
        int editW = W - 2 * margin - 96 - 8;

        if (editW > 210)
            editW = 210;
        if (editW < 90)
            editW = 90;
        MoveWindow(g_hwndStunLabel, margin, y + 4 - off, 92, 20, TRUE);
        MoveWindow(g_hwndStun, margin + 96, y - off, editW, 24, TRUE);
        if (W - 2 * margin - 96 - editW - 8 >= 112) {
            MoveWindow(g_hwndStunFormat, margin + 96 + editW + 8,
                       y + 4 - off, 110, 20, TRUE);
            ShowWindow(g_hwndStunFormat, SW_SHOW);
        } else {
            ShowWindow(g_hwndStunFormat, SW_HIDE);
        }
        MoveWindow(g_hwndUpnp, margin, y + 34 - off, 250, 22, TRUE);
        if (W - 2 * margin >= 560) {
            MoveWindow(g_hwndKeepInfo, W - margin - 300, y + 35 - off,
                       300, 20, TRUE);
            ShowWindow(g_hwndKeepInfo, SW_SHOW);
        } else {
            ShowWindow(g_hwndKeepInfo, SW_HIDE);
        }
        y += 64;
    }

    if (!compact) {
        groupH = 132;
        MoveWindow(g_hwndGroup, margin, y - off, W - 2 * margin, groupH, TRUE);
        MoveWindow(g_hwndProtoLabel, margin + 16, y + 24 - off, 38, 20, TRUE);
        MoveWindow(g_hwndProto, margin + 56, y + 20 - off, 84, 200, TRUE);
        MoveWindow(g_hwndLocalLabel, margin + 156, y + 24 - off, 66, 20, TRUE);
        MoveWindow(g_hwndLocal, margin + 224, y + 20 - off, 66, 24, TRUE);
        MoveWindow(g_hwndLocalHint, margin + 296, y + 24 - off, 110, 20, TRUE);
        MoveWindow(g_hwndBackHostLabel, margin + 416, y + 24 - off, 64, 20, TRUE);
        MoveWindow(g_hwndBackHost, margin + 482, y + 20 - off, 120, 24, TRUE);
        MoveWindow(g_hwndBackPortLabel, margin + 616, y + 24 - off, 64, 20, TRUE);
        MoveWindow(g_hwndBackPort, margin + 682, y + 20 - off, 66, 24, TRUE);
        MoveWindow(g_hwndNameLabel, margin + 16, y + 62 - off, 38, 20, TRUE);
        MoveWindow(g_hwndName, margin + 56, y + 58 - off, 180, 24, TRUE);
        MoveWindow(g_hwndAdd, margin + 250, y + 56 - off, 120, 28, TRUE);
        MoveWindow(g_hwndAddHint, margin + 382, y + 62 - off, 430, 20, TRUE);
        MoveWindow(g_hwndProxy, margin + 16, y + 96 - off, 240, 22, TRUE);
        MoveWindow(g_hwndProxyV1, margin + 266, y + 96 - off, 170, 22, TRUE);
        MoveWindow(g_hwndProxyHint, margin + 446, y + 98 - off,
                   W - 2 * margin - 446, 20, TRUE);
        ShowWindow(g_hwndLocalHint, SW_SHOW);
        ShowWindow(g_hwndAddHint, SW_SHOW);
        ShowWindow(g_hwndProxyHint, SW_SHOW);

        MoveWindow(g_hwndStart, margin, y + 144 - off, 100, 28, TRUE);
        MoveWindow(g_hwndStop, margin + 108, y + 144 - off, 100, 28, TRUE);
        MoveWindow(g_hwndDelete, margin + 216, y + 144 - off, 100, 28, TRUE);
        MoveWindow(g_hwndStopAll, margin + 324, y + 144 - off, 100, 28, TRUE);
        MoveWindow(g_hwndConnTable, margin + 432, y + 144 - off, 100, 28, TRUE);
        MoveWindow(g_hwndBlackBtn, margin + 540, y + 144 - off, 100, 28, TRUE);
        MoveWindow(g_hwndClearLog, margin + 648, y + 144 - off, 100, 28, TRUE);
        y += groupH + 12 + 34;
    } else {
        int x = margin + 16;
        int bw;

        /* 480 宽时"传递源地址 + v1"两个复选框一行放不下，改成分两行 */
        {
            int twoRow = ((W - 2 * margin) < 470) ? 1 : 0;

            groupH = twoRow ? 198 : 168;
            MoveWindow(g_hwndGroup, margin, y - off, W - 2 * margin, groupH, TRUE);
        }
        (void)0;
        MoveWindow(g_hwndProtoLabel, x, y + 24 - off, 38, 20, TRUE);
        MoveWindow(g_hwndProto, x + 40, y + 20 - off, 84, 200, TRUE);
        MoveWindow(g_hwndLocalLabel, x + 136, y + 24 - off, 66, 20, TRUE);
        MoveWindow(g_hwndLocal, x + 204, y + 20 - off, 66, 24, TRUE);
        if (W - 2 * margin >= 420) {
            MoveWindow(g_hwndLocalHint, x + 278, y + 24 - off, 110, 20, TRUE);
            ShowWindow(g_hwndLocalHint, SW_SHOW);
        } else {
            ShowWindow(g_hwndLocalHint, SW_HIDE);
        }
        MoveWindow(g_hwndBackHostLabel, x, y + 62 - off, 64, 20, TRUE);
        MoveWindow(g_hwndBackHost, x + 66, y + 58 - off, 120, 24, TRUE);
        MoveWindow(g_hwndBackPortLabel, x + 196, y + 62 - off, 64, 20, TRUE);
        MoveWindow(g_hwndBackPort, x + 262, y + 58 - off, 66, 24, TRUE);
        MoveWindow(g_hwndNameLabel, x, y + 100 - off, 38, 20, TRUE);
        MoveWindow(g_hwndName, x + 40, y + 96 - off, 180, 24, TRUE);
        MoveWindow(g_hwndAdd, x + 230, y + 96 - off, 120, 28, TRUE);
        ShowWindow(g_hwndAddHint, SW_HIDE);
        MoveWindow(g_hwndProxy, x, y + 138 - off, 240, 22, TRUE);
        MoveWindow(g_hwndProxyV1, x + ((W - 2 * margin) < 470 ? 0 : 246),
                   y + ((W - 2 * margin) < 470 ? 168 : 138) - off, 170, 22, TRUE);
        ShowWindow(g_hwndProxyHint, SW_HIDE);

        y += groupH + 10;
        bw = (W - 2 * margin - 24) / 4;
        if (bw < 60)
            bw = 60;
        MoveWindow(g_hwndStart, margin, y - off, bw, 28, TRUE);
        MoveWindow(g_hwndStop, margin + bw + 8, y - off, bw, 28, TRUE);
        MoveWindow(g_hwndDelete, margin + 2 * (bw + 8), y - off, bw, 28, TRUE);
        MoveWindow(g_hwndStopAll, margin + 3 * (bw + 8), y - off, bw, 28, TRUE);
        MoveWindow(g_hwndConnTable, margin, y + 34 - off, bw, 28, TRUE);
        MoveWindow(g_hwndBlackBtn, margin + bw + 8, y + 34 - off, bw, 28, TRUE);
        MoveWindow(g_hwndClearLog, margin + 2 * (bw + 8), y + 34 - off,
                   bw, 28, TRUE);
        y += 70;
    }

    listTop = y + 4;
    availH = H - 22 - 12 - 16 - listTop;
    if (availH < 0)
        availH = 0;
    {
        int minList = 110;
        int minLog = 90;
        int need = minList + 30 + minLog;
        int gap = 30;               /* 日志标签行 20 + 上下间距 10 */

        if (availH >= need) {
            logH = 150;
            listH = availH - gap - logH;
            if (listH < minList) {
                listH = minList;
                logH = availH - gap - listH;
            }
            if (logH < minLog)
                logH = minLog;
        } else if (availH > gap + 60) {
            /* 800x600 / 640x480 这类小屏：高度不够时按比例压缩列表和日志，
               让整块内容正好落在可视区内。否则日志被挤到窗口下沿以下，
               看着就像"日志不显示"，必须拖滚动条才能露出来。 */
            int sh = availH - gap;

            listH = sh * 3 / 5;
            if (listH > minList)
                listH = minList;
            logH = sh - listH;
            if (logH < 48) {
                logH = 48;
                listH = sh - logH;
            }
            if (listH < 40)
                listH = 40;
        } else {
            listH = minList;
            logH = minLog;
        }
    }

    MoveWindow(g_hwndList, margin, listTop - off, W - 2 * margin, listH, TRUE);
    MoveWindow(g_hwndLogLabel, margin, listTop + listH + 8 - off, 200, 20, TRUE);
    MoveWindow(g_hwndLog, margin, listTop + listH + 8 + 20 - off,
               W - 2 * margin, logH, TRUE);

    extra = (W - 2 * margin) - 930;
    if (extra < 0)
        extra = 0;
    for (i = 0; i < 8; ++i)
        ListView_SetColumnWidth(g_hwndList, i,
                                baseWidths[i] + (i == 5 ? extra : 0));

    return listTop + listH + 8 + 20 + logH;
}

/* 按可视区域重新布局；内容比窗口高时出现垂直滚动条，状态栏始终固定在底部。 */
static void LayoutControls(HWND hwnd)
{
    RECT rc;
    SCROLLINFO si;
    int W;
    int H;
    int contentH;
    int viewH;
    int maxScroll;
    BOOL need;

    GetClientRect(hwnd, &rc);
    W = rc.right;
    H = rc.bottom;
    if (W < 120)
        W = 120;
    viewH = H - 22 - 12;
    if (viewH < 80)
        viewH = 80;

    contentH = LayoutPass(hwnd, W, H, g_scrollY);
    need = (contentH > viewH) ? TRUE : FALSE;
    if (need != g_scrollShown) {
        ShowScrollBar(hwnd, SB_VERT, need);
        g_scrollShown = need;
        GetClientRect(hwnd, &rc);
        W = rc.right;
        H = rc.bottom;
        if (W < 120)
            W = 120;
        viewH = H - 22 - 12;
        if (viewH < 80)
            viewH = 80;
        contentH = LayoutPass(hwnd, W, H, g_scrollY);
        need = (contentH > viewH) ? TRUE : FALSE;
    }

    maxScroll = contentH - viewH;
    if (maxScroll < 0)
        maxScroll = 0;
    if (g_scrollY < 0)
        g_scrollY = 0;
    if (g_scrollY > maxScroll) {
        g_scrollY = maxScroll;
        contentH = LayoutPass(hwnd, W, H, g_scrollY);
    }

    ZeroMemory(&si, sizeof(si));
    si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin = 0;
    si.nMax = contentH > 0 ? contentH - 1 : 0;
    si.nPage = (UINT)viewH;
    si.nPos = g_scrollY;
    SetScrollInfo(hwnd, SB_VERT, &si, TRUE);

    MoveWindow(g_hwndStatus, 16, H - 22 - 4, W - 32, 22, TRUE);
}

static void CreateListColumns(void)
{
    struct {
        const WCHAR *name;
        int width;
    } cols[8] = {
        { L"名称", 92 },
        { L"协议", 52 },
        { L"本地端口", 70 },
        { L"服务地址:端口", 124 },
        { L"公网映射 IP:端口", 160 },
        { L"状态", 150 },
        { L"最近保活", 72 },
        { L"流量 入/出", 210 }
    };
    int i;
    LVCOLUMNW col;

    for (i = 0; i < 8; ++i) {
        ZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.pszText = (LPWSTR)cols[i].name;
        col.cx = cols[i].width;
        col.iSubItem = i;
        ListView_InsertColumn(g_hwndList, i, &col);
    }
}

/* ------------------------------------------------------------------ */
/* GUI 命令                                                            */
/* ------------------------------------------------------------------ */

static void DetachConnTable(NAT_MAPPING *m);

static NAT_MAPPING *GetSelectedMapping(void)
{
    int idx;
    LVITEMW item;

    if (g_hwndList == NULL)
        return NULL;
    idx = ListView_GetNextItem(g_hwndList, -1, LVNI_SELECTED);
    if (idx < 0)
        return NULL;
    ZeroMemory(&item, sizeof(item));
    item.mask = LVIF_PARAM;
    item.iItem = idx;
    if (!ListView_GetItem(g_hwndList, &item))
        return NULL;
    return FindMappingByListParam(item.lParam);
}

/* 参数不合法时只写日志，不弹模态框：模态框会卡住消息循环，
   自动化/批量添加时尤其致命。 */
static void AddMappingReject(const WCHAR *reason)
{
    AddLog(L"添加映射失败: %s", reason);
}

static void AddMappingFromUi(void)
{
    WCHAR err[256];
    WCHAR stunText[192];
    WCHAR localText[32];
    WCHAR backHost[128];
    WCHAR backPortText[32];
    WCHAR nameText[64];
    WCHAR stunHost[128];
    USHORT stunPort = 0;
    USHORT localPort = 0;
    USHORT backPort = 0;
    BOOL autoPort = FALSE;
    int protoSel;
    NAT_MAPPING *m;
    int idx;

    GetWindowTextW(g_hwndStun, stunText, (int)(sizeof(stunText) / sizeof(stunText[0])));
    GetWindowTextW(g_hwndLocal, localText, (int)(sizeof(localText) / sizeof(localText[0])));
    GetWindowTextW(g_hwndBackHost, backHost, (int)(sizeof(backHost) / sizeof(backHost[0])));
    GetWindowTextW(g_hwndBackPort, backPortText, (int)(sizeof(backPortText) / sizeof(backPortText[0])));
    GetWindowTextW(g_hwndName, nameText, (int)(sizeof(nameText) / sizeof(nameText[0])));

    TrimW(stunText);
    TrimW(localText);
    TrimW(backHost);
    TrimW(backPortText);
    TrimW(nameText);


    if (!ParseStunEndpoint(stunText, stunHost,
                           sizeof(stunHost) / sizeof(stunHost[0]),
                           &stunPort, err, sizeof(err) / sizeof(err[0]))) {
        AddMappingReject(err);
        return;
    }
    if (localText[0] == L'\0') {
        autoPort = TRUE;
    } else if (!ParsePortText(localText, &localPort)) {
        AddMappingReject(L"本地端口无效（应为 1-65535，留空则随机）");
        return;
    }
    if (backHost[0] == L'\0')
        wcscpy(backHost, DEFAULT_BACKEND_HOST);
    if (!ParsePortText(backPortText, &backPort)) {
        AddMappingReject(L"服务端口无效（应为 1-65535）");
        return;
    }

    protoSel = (int)SendMessageW(g_hwndProto, CB_GETCURSEL, 0, 0);
    if (protoSel != 0 && protoSel != 1)
        protoSel = 0;

    if (!autoPort && localPort == backPort && IsLoopbackHostText(backHost)) {
        AddMappingReject(L"本地端口不能与服务端口相同（会形成回环）");
        return;
    }

    if (!autoPort) {
        NAT_MAPPING *x;
        BOOL dup = FALSE;

        /* 映射线程会随时改写 local_port，重复检查必须在锁里做，
           否则两个同时启动的映射可能抢到同一个本地端口。 */
        EnterCriticalSection(&g_cs);
        for (x = g_maps; x != NULL; x = x->next) {
            if (x->proto == (protoSel == 1 ? PROTO_TCP : PROTO_UDP) &&
                x->local_port == localPort) {
                dup = TRUE;
                break;
            }
        }
        LeaveCriticalSection(&g_cs);
        if (dup) {
            WPrintf(err, sizeof(err) / sizeof(err[0]),
                    L"本地端口 %u 已被另一个 %s 映射使用",
                    (unsigned)localPort, protoSel == 1 ? L"TCP" : L"UDP");
            AddMappingReject(err);
            return;
        }
    }

    if (g_mapCount >= MAX_MAPPINGS) {
        WPrintf(err, sizeof(err) / sizeof(err[0]), L"最多只能建立 %d 个映射", MAX_MAPPINGS);
        AddMappingReject(err);
        return;
    }

    m = (NAT_MAPPING *)calloc(1, sizeof(NAT_MAPPING));
    if (m == NULL) {
        AddMappingReject(L"内存不足");
        return;
    }
    m->id = ++g_nextId;
    m->proto = (protoSel == 1) ? PROTO_TCP : PROTO_UDP;
    m->auto_port = autoPort;
    m->use_upnp = (g_hwndUpnp != NULL &&
                   SendMessageW(g_hwndUpnp, BM_GETCHECK, 0, 0) == BST_CHECKED) ? 1 : 0;
    /* 到服务这一段是本地回环，服务看不到真实来源；勾选后把来源写进数据流
       最前面（PROXY protocol），服务即可还原源 IP。默认关闭：服务端不改配置
       的话会把这段头当成业务数据。 */
    if (m->proto == PROTO_TCP && g_hwndProxy != NULL &&
        SendMessageW(g_hwndProxy, BM_GETCHECK, 0, 0) == BST_CHECKED) {
        m->proxy_protocol = 1;
        if (g_hwndProxyV1 != NULL &&
            SendMessageW(g_hwndProxyV1, BM_GETCHECK, 0, 0) == BST_CHECKED)
            m->proxy_v1 = 1;
    }
    m->local_port = localPort;
    m->backend_port = backPort;
    m->stun_port = stunPort;
    CopyW(m->backend_host, sizeof(m->backend_host) / sizeof(m->backend_host[0]), backHost);
    CopyW(m->stun_host, sizeof(m->stun_host) / sizeof(m->stun_host[0]), stunHost);
    if (nameText[0] != L'\0') {
        CopyW(m->name, sizeof(m->name) / sizeof(m->name[0]), nameText);
    } else {
        WPrintf(m->name, sizeof(m->name) / sizeof(m->name[0]),
                L"%s 映射 %d", m->proto == PROTO_TCP ? L"TCP" : L"UDP", m->id);
    }
    m->start_time = NowMs64();

    EnterCriticalSection(&g_cs);
    m->next = g_maps;
    g_maps = m;
    g_mapCount++;
    LeaveCriticalSection(&g_cs);

    idx = InsertMappingListItem(m);
    if (idx < 0) {
        EnterCriticalSection(&g_cs);
        {
            NAT_MAPPING **pp = &g_maps;
            while (*pp != NULL && *pp != m)
                pp = &(*pp)->next;
            if (*pp == m)
                *pp = m->next;
            g_mapCount--;
        }
        LeaveCriticalSection(&g_cs);
        free(m);
        AddMappingReject(L"无法创建列表项");
        return;
    }

    if (!StartMapping(m)) {
        /* StartMapping 失败时对象仍在列表，保留以便查看错误 */
        AddLog(L"启动映射失败: %s（线程创建失败）", m->name);
        RefreshList();
        UpdateStatusBar();
        return;
    }

    AddLog(L"添加映射: %s (%s)，服务 %s:%u",
           m->name, m->proto == PROTO_TCP ? L"TCP" : L"UDP",
           m->backend_host, (unsigned)m->backend_port);

    SetWindowTextW(g_hwndName, L"");
    SetWindowTextW(g_hwndLocal, L"");
    SetWindowTextW(g_hwndBackPort, L"");
    SetFocus(g_hwndLocal);
    RefreshList();
    UpdateStatusBar();
}

/* 启动/停止/删除这些操作一律不弹框，结果只写日志 */
static void StartSelectedMapping(void)
{
    NAT_MAPPING *m = GetSelectedMapping();

    if (m == NULL) {
        AddLog(L"启动失败: 请先在列表中选择一个映射");
        return;
    }
    if (InterlockedCompareExchange(&m->running, 0, 0) != 0) {
        AddLog(L"启动跳过: %s 已经在运行", m->name);
        return;
    }
    if (StartMapping(m)) {
        AddLog(L"启动映射: %s", m->name);
        RefreshList();
        UpdateStatusBar();
    } else {
        AddLog(L"启动映射失败: %s（请稍后重试）", m->name);
    }
}

static void StopSelectedMapping(void)
{
    NAT_MAPPING *m = GetSelectedMapping();

    if (m == NULL) {
        AddLog(L"停止失败: 请先在列表中选择一个映射");
        return;
    }
    if (InterlockedCompareExchange(&m->running, 0, 0) == 0 &&
        m->thread == NULL) {
        AddLog(L"停止跳过: %s 当前未运行", m->name);
        return;
    }
    if (StopMapping(m))
        AddLog(L"停止映射: %s", m->name);
    else
        AddLog(L"停止超时: %s 的线程可能仍在退出，请稍后再试", m->name);
    RefreshList();
    UpdateStatusBar();
}

static void DeleteSelectedMapping(void)
{
    NAT_MAPPING *m = GetSelectedMapping();
    int idx;

    if (m == NULL) {
        AddLog(L"删除失败: 请先在列表中选择一个映射");
        return;
    }

    if (!StopMapping(m)) {
        AddLog(L"删除取消: %s 未能停止，请稍后再试", m->name);
        return;
    }

    /* 连接表窗口可能正盯着这个映射，先松开引用再释放 */
    DetachConnTable(m);

    idx = FindListIndexByMapping(m);
    if (idx >= 0)
        ListView_DeleteItem(g_hwndList, idx);

    EnterCriticalSection(&g_cs);
    {
        NAT_MAPPING **pp = &g_maps;
        while (*pp != NULL && *pp != m)
            pp = &(*pp)->next;
        if (*pp == m) {
            *pp = m->next;
            g_mapCount--;
        }
    }
    LeaveCriticalSection(&g_cs);

    AddLog(L"删除映射: %s", m->name);
    FreeMapping(m);
    RefreshList();
    UpdateStatusBar();
}

/* 停止全部映射：先统一置停止标志，再共用一个总超时等待。
   以前是逐个 StopMapping，最坏要等 8 秒 × 映射数，界面长时间没反应。 */
static void StopAllMappings(void)
{
    NAT_MAPPING *m;
    ULONGLONG deadline;

    EnterCriticalSection(&g_cs);
    for (m = g_maps; m != NULL; m = m->next)
        InterlockedExchange(&m->stop, 1);
    LeaveCriticalSection(&g_cs);

    deadline = NowMs64() + STOP_WAIT_MS;
    for (;;) {
        BOOL any = FALSE;

        EnterCriticalSection(&g_cs);
        for (m = g_maps; m != NULL; m = m->next) {
            if (m->thread == NULL)
                continue;
            if (WaitForSingleObject(m->thread, 0) == WAIT_OBJECT_0) {
                CloseHandle(m->thread);
                m->thread = NULL;
                InterlockedExchange(&m->running, 0);
            } else {
                any = TRUE;
            }
        }
        LeaveCriticalSection(&g_cs);

        if (!any)
            break;
        if (NowMs64() >= deadline) {
            AddLog(L"停止超时：仍有映射线程在退出中");
            break;
        }
        Sleep(30);
    }

    RefreshList();
    UpdateStatusBar();
}

static void ClearLog(void)
{
    if (g_hwndLog != NULL)
        SetWindowTextW(g_hwndLog, L"");
    AddLog(L"日志已清空");
}

/* ------------------------------------------------------------------ */
/* 连接表窗口                                                          */
/* ------------------------------------------------------------------ */

#define CONN_MAX_ROWS (MAX_TCP_CONNS + MAX_UDP_SESSIONS)

typedef struct _CONN_ROW {
    WCHAR key[80];          /* 稳定标识：判断是否需要重建列表 */
    WCHAR peer[72];
    WCHAR proto[8];
    WCHAR start[24];
    WCHAR age[24];
    WCHAR last[24];
    WCHAR traffic[64];
} CONN_ROW;

static void SetSubItemText(HWND list, int item, int subItem, const WCHAR *text)
{
    WCHAR old[512];

    if (list == NULL || text == NULL)
        return;
    old[0] = L'\0';
    ListView_GetItemText(list, item, subItem, old,
                         (int)(sizeof(old) / sizeof(old[0])));
    if (wcscmp(old, text) != 0)
        ListView_SetItemText(list, item, subItem, (LPWSTR)text);
}

/* 由"已经过去了多久"反推建立时刻的钟点 */
static void FormatClock(ULONGLONG tick, WCHAR *buf, size_t cch)
{
    SYSTEMTIME st;
    ULONGLONG diff = NowMs64();
    long secs;
    long t;
    int h;
    int m;
    int s;

    diff = (diff > tick) ? (diff - tick) / 1000ULL : 0ULL;
    if (diff > 86400ULL)
        diff = 86400ULL;
    secs = (long)diff;
    GetLocalTime(&st);
    t = (long)st.wHour * 3600L + (long)st.wMinute * 60L + (long)st.wSecond - secs;
    t %= 86400L;
    if (t < 0)
        t += 86400L;
    h = (int)(t / 3600L);
    m = (int)((t % 3600L) / 60L);
    s = (int)(t % 60L);
    WPrintf(buf, cch, L"%02d:%02d:%02d", h, m, s);
}

static void FormatAge(ULONGLONG tick, WCHAR *buf, size_t cch)
{
    ULONGLONG now = NowMs64();
    ULONGLONG secs = (now > tick) ? (now - tick) / 1000ULL : 0ULL;

    if (secs < 60ULL)
        WPrintf(buf, cch, L"%lu 秒", (unsigned long)secs);
    else if (secs < 3600ULL)
        WPrintf(buf, cch, L"%lu 分 %lu 秒", (unsigned long)(secs / 60ULL),
                (unsigned long)(secs % 60ULL));
    else
        WPrintf(buf, cch, L"%lu 小时 %lu 分", (unsigned long)(secs / 3600ULL),
                (unsigned long)((secs % 3600ULL) / 60ULL));
}

static void FormatIdle(ULONGLONG tick, BOOL known, WCHAR *buf, size_t cch)
{
    ULONGLONG now = NowMs64();
    ULONGLONG secs;

    if (!known || tick == 0) {
        WPrintf(buf, cch, L"—");
        return;
    }
    secs = (now > tick) ? (now - tick) / 1000ULL : 0ULL;
    if (secs < 1ULL)
        WPrintf(buf, cch, L"刚刚");
    else
        WPrintf(buf, cch, L"%lu 秒前", (unsigned long)secs);
}

/* 连接表里流量和主列表用同一套自适应单位（B/KB/MB/GB/TB），
   小流量的连接也能看出有没有在动，大流量也不会撑破列宽。 */
static void FormatBytesText(ULONGLONG bytes, WCHAR *buf, size_t cch)
{
    FormatBytesW(buf, cch, bytes);
}

static void FormatConnTraffic(ULONGLONG inBytes, ULONGLONG outBytes,
                              WCHAR *buf, size_t cch)
{
    WCHAR a[32];
    WCHAR b[32];

    FormatBytesText(inBytes, a, sizeof(a) / sizeof(a[0]));
    FormatBytesText(outBytes, b, sizeof(b) / sizeof(b[0]));
    WPrintf(buf, cch, L"入 %s / 出 %s", a, b);
}

/* 采集一条映射的当前连接：TCP 直接读连接链表（关掉就没了），
   UDP 读映射线程每秒发布的会话快照（空闲超时后被关闭，自然消失） */
static int CollectConnRows(NAT_MAPPING *m, CONN_ROW *rows, int max)
{
    int n = 0;
    int i;
    TCP_CONN *c;

    if (m == NULL || rows == NULL || max <= 0)
        return 0;

    EnterCriticalSection(&g_cs);
    for (c = m->conns; c != NULL && n < max; c = c->next) {
        CONN_ROW *r = &rows[n];

        ZeroMemory(r, sizeof(*r));
        WPrintf(r->key, sizeof(r->key) / sizeof(r->key[0]), L"T%p", (void *)c);
        CopyW(r->peer, sizeof(r->peer) / sizeof(r->peer[0]), c->peer);
        CopyW(r->proto, sizeof(r->proto) / sizeof(r->proto[0]), L"TCP");
        FormatClock(c->start, r->start, sizeof(r->start) / sizeof(r->start[0]));
        FormatAge(c->start, r->age, sizeof(r->age) / sizeof(r->age[0]));
        FormatIdle(c->last_active, TRUE, r->last,
                   sizeof(r->last) / sizeof(r->last[0]));
        FormatConnTraffic(c->bytes_in, c->bytes_out, r->traffic,
                          sizeof(r->traffic) / sizeof(r->traffic[0]));
        n++;
    }
    for (i = 0; i < m->udp_view_count && i < MAX_UDP_SESSIONS && n < max; ++i) {
        const CONN_VIEW *v = &m->udp_view[i];
        CONN_ROW *r = &rows[n];
        WCHAR peer[64];

        ZeroMemory(r, sizeof(*r));
        FormatSockAddrW(&v->peer, peer, sizeof(peer) / sizeof(peer[0]));
        WPrintf(r->key, sizeof(r->key) / sizeof(r->key[0]), L"U%08lX:%u",
                (unsigned long)v->peer.sin_addr.s_addr,
                (unsigned)v->peer.sin_port);
        CopyW(r->peer, sizeof(r->peer) / sizeof(r->peer[0]), peer);
        CopyW(r->proto, sizeof(r->proto) / sizeof(r->proto[0]), L"UDP");
        FormatClock(v->start, r->start, sizeof(r->start) / sizeof(r->start[0]));
        FormatAge(v->start, r->age, sizeof(r->age) / sizeof(r->age[0]));
        FormatIdle(v->last_active, TRUE, r->last,
                   sizeof(r->last) / sizeof(r->last[0]));
        FormatConnTraffic(v->bytes_in, v->bytes_out, r->traffic,
                          sizeof(r->traffic) / sizeof(r->traffic[0]));
        n++;
    }
    LeaveCriticalSection(&g_cs);
    return n;
}

static void RefreshConnTable(void)
{
    static CONN_ROW rows[CONN_MAX_ROWS];
    static WCHAR oldKeys[CONN_MAX_ROWS][80];
    static int oldCount = 0;
    NAT_MAPPING *m = g_connMapping;
    int n;
    int i;
    int changed;
    int tcpCount = 0;
    int udpCount = 0;
    WCHAR info[320];

    if (g_hwndConnList == NULL)
        return;

    if (m == NULL) {
        if (oldCount != 0) {
            ListView_DeleteAllItems(g_hwndConnList);
            oldCount = 0;
        }
        SetWindowTextW(g_hwndConnInfo, L"所选映射已不存在");
        return;
    }

    n = CollectConnRows(m, rows, CONN_MAX_ROWS);

    changed = (n != oldCount);
    for (i = 0; !changed && i < n; ++i) {
        if (wcscmp(rows[i].key, oldKeys[i]) != 0)
            changed = 1;
    }

    if (changed) {
        int top = ListView_GetTopIndex(g_hwndConnList);

        ListView_DeleteAllItems(g_hwndConnList);
        for (i = 0; i < n; ++i) {
            LVITEMW item;

            ZeroMemory(&item, sizeof(item));
            item.mask = LVIF_TEXT;
            item.iItem = i;
            item.pszText = rows[i].peer;
            ListView_InsertItem(g_hwndConnList, &item);
            SetSubItemText(g_hwndConnList, i, 1, rows[i].proto);
            SetSubItemText(g_hwndConnList, i, 2, rows[i].start);
            SetSubItemText(g_hwndConnList, i, 3, rows[i].age);
            SetSubItemText(g_hwndConnList, i, 4, rows[i].last);
            SetSubItemText(g_hwndConnList, i, 5, rows[i].traffic);
        }
        if (n > 0) {
            if (top > 0 && top < n)
                ListView_EnsureVisible(g_hwndConnList, top, FALSE);
        }
        oldCount = n;
        for (i = 0; i < n; ++i)
            CopyW(oldKeys[i], sizeof(oldKeys[i]) / sizeof(oldKeys[i][0]),
                  rows[i].key);
    } else {
        for (i = 0; i < n; ++i) {
            SetSubItemText(g_hwndConnList, i, 0, rows[i].peer);
            SetSubItemText(g_hwndConnList, i, 1, rows[i].proto);
            SetSubItemText(g_hwndConnList, i, 2, rows[i].start);
            SetSubItemText(g_hwndConnList, i, 3, rows[i].age);
            SetSubItemText(g_hwndConnList, i, 4, rows[i].last);
            SetSubItemText(g_hwndConnList, i, 5, rows[i].traffic);
        }
    }

    for (i = 0; i < n; ++i) {
        if (wcscmp(rows[i].proto, L"TCP") == 0)
            tcpCount++;
        else
            udpCount++;
    }
    WPrintf(info, sizeof(info) / sizeof(info[0]),
            L"%s · %s · 共 %d 条（TCP %d · UDP %d）· 每秒刷新", m->name,
            m->proto == PROTO_TCP ? L"TCP" : L"UDP", n, tcpCount, udpCount);
    SetWindowTextW(g_hwndConnInfo, info);
}

static void CreateConnControls(HWND hwnd)
{
    struct {
        const WCHAR *name;
        int width;
    } cols[6] = {
        { L"对端地址", 176 },
        { L"协议", 54 },
        { L"建立时间", 88 },
        { L"持续", 84 },
        { L"最近活动", 88 },
        { L"流量 入/出", 210 }
    };
    int i;
    LVCOLUMNW col;

    g_hwndConnInfo = MakeControl(L"STATIC", L"", SS_LEFT, 0, IDC_CONNINFO, hwnd);
    g_hwndConnList = MakeControl(WC_LISTVIEWW, NULL,
        WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_BORDER,
        0, IDC_CONNLIST, hwnd);
    ListView_SetExtendedListViewStyle(g_hwndConnList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    for (i = 0; i < 6; ++i) {
        ZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.pszText = (LPWSTR)cols[i].name;
        col.cx = cols[i].width;
        col.iSubItem = i;
        ListView_InsertColumn(g_hwndConnList, i, &col);
    }

    ApplyFonts(hwnd);
}

static void LayoutConnControls(HWND hwnd)
{
    RECT rc;
    int margin = 10;
    int infoH = 20;
    int listY;

    GetClientRect(hwnd, &rc);
    listY = margin + infoH + 6;
    MoveWindow(g_hwndConnInfo, margin, margin, rc.right - 2 * margin, infoH, TRUE);
    MoveWindow(g_hwndConnList, margin, listY, rc.right - 2 * margin,
               (rc.bottom - listY - margin > 40) ? (rc.bottom - listY - margin) : 40,
               TRUE);
}

static LRESULT CALLBACK ConnWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
        CreateConnControls(hwnd);
        LayoutConnControls(hwnd);
        SetTimer(hwnd, CONN_TIMER_ID, 1000, NULL);
        return 0;

    case WM_SIZE:
        if (g_hwndConnList != NULL)
            LayoutConnControls(hwnd);
        return 0;

    case WM_TIMER:
        if (wParam == CONN_TIMER_ID)
            RefreshConnTable();
        return 0;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, CONN_TIMER_ID);
        g_hwndConn = NULL;
        g_hwndConnList = NULL;
        g_hwndConnInfo = NULL;
        g_connMapping = NULL;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* 子窗口按主窗口偏移打开，在 640x480 上会超出屏幕右/下边，标题栏和
   底部按钮看不见。这里把窗口外框整体挪回工作区内，放不下就先缩到工作区大小。 */
static void ClampWindowRect(RECT *rc)
{
    RECT work;
    int w = rc->right - rc->left;
    int h = rc->bottom - rc->top;

    if (!SystemParametersInfoA(SPI_GETWORKAREA, 0, &work, 0)) {
        work.left = 0;
        work.top = 0;
        work.right = GetSystemMetrics(SM_CXSCREEN);
        work.bottom = GetSystemMetrics(SM_CYSCREEN);
    }
    if (w > work.right - work.left)
        w = work.right - work.left;
    if (h > work.bottom - work.top)
        h = work.bottom - work.top;
    if (rc->left < work.left)
        rc->left = work.left;
    if (rc->top < work.top)
        rc->top = work.top;
    if (rc->left + w > work.right)
        rc->left = work.right - w;
    if (rc->top + h > work.bottom)
        rc->top = work.bottom - h;
    if (rc->left < work.left)
        rc->left = work.left;
    if (rc->top < work.top)
        rc->top = work.top;
    rc->right = rc->left + w;
    rc->bottom = rc->top + h;
}

static void ShowConnTable(void)
{
    NAT_MAPPING *m = GetSelectedMapping();
    RECT main;
    RECT rc;
    WCHAR title[192];

    if (m == NULL) {
        AddLog(L"请先在列表中选择一个映射，再查看连接表");
        return;
    }

    if (g_hwndConn == NULL || !IsWindow(g_hwndConn)) {
        if (!GetWindowRect(g_hwndMain, &main))
            ZeroMemory(&main, sizeof(main));
        rc.left = main.left + 80;
        rc.top = main.top + 80;
        rc.right = rc.left + 780;
        rc.bottom = rc.top + 460;
        AdjustWindowRectEx(&rc, WS_OVERLAPPEDWINDOW, FALSE, 0);
        ClampWindowRect(&rc);
        g_connMapping = m;
        g_hwndConn = CreateWindowExW(WS_EX_CONTROLPARENT, NAT_WNDCLASS_CONN,
                                     L"连接表", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                                     rc.left, rc.top, rc.right - rc.left,
                                     rc.bottom - rc.top, g_hwndMain, NULL,
                                     g_hInst, NULL);
        if (g_hwndConn == NULL) {
            g_connMapping = NULL;
            AddLog(L"连接表窗口创建失败");
            return;
        }
        ShowWindow(g_hwndConn, SW_SHOW);
        UpdateWindow(g_hwndConn);
    }

    g_connMapping = m;
    WPrintf(title, sizeof(title) / sizeof(title[0]), L"连接表 - %s（%s）",
            m->name, m->proto == PROTO_TCP ? L"TCP" : L"UDP");
    SetWindowTextW(g_hwndConn, title);
    RefreshConnTable();
    SetForegroundWindow(g_hwndConn);
}

/* 映射被删除时，连接表窗口不能再指向它 */
static void DetachConnTable(NAT_MAPPING *m)
{
    if (g_connMapping == m) {
        g_connMapping = NULL;
        if (g_hwndConn != NULL) {
            HWND h = g_hwndConn;
            g_hwndConn = NULL;
            DestroyWindow(h);
        }
    }
}

/* ------------------------------------------------------------------ */
/* 黑名单窗口                                                          */
/* ------------------------------------------------------------------ */

typedef struct _BLACK_ROW {
    WCHAR text[BLACK_TEXT_CCH];
    WCHAR range[96];
    WCHAR hits[24];
} BLACK_ROW;

static void FormatIpv4W(const unsigned char *a, WCHAR *buf, size_t cch)
{
    WPrintf(buf, cch, L"%u.%u.%u.%u", (unsigned)a[0], (unsigned)a[1],
            (unsigned)a[2], (unsigned)a[3]);
}

/* 区间是否正好是一个前缀（hi 等于 lo 的前缀位之后全 1）。
   是的话显示成 113.75.0.0/16，比一长串起止地址好读得多。 */
static BOOL RangeIsPrefix(const unsigned char *lo, const unsigned char *hi,
                          int *outBits)
{
    int bits = 0;
    int i;
    int j;

    *outBits = 0;
    for (i = 0; i < 4; ++i) {
        int k;

        if (lo[i] == hi[i]) {
            bits += 8;
            continue;
        }
        k = 0;
        while (k < 8 && ((lo[i] ^ hi[i]) & (0x80u >> k)) == 0)
            ++k;
        /* 共同前缀的 k 位之后：起点必须全 0、终点必须全 1 */
        if ((lo[i] & (0xFFu >> k)) != 0)
            return FALSE;
        if ((hi[i] | (0xFFu >> k)) != 0xFF)
            return FALSE;
        bits += k;
        for (j = i + 1; j < 4; ++j) {
            if (lo[j] != 0 || hi[j] != 0xFF)
                return FALSE;
        }
        *outBits = bits;
        return TRUE;
    }
    *outBits = bits;                /* 起止相同 */
    return TRUE;
}

/* 列表里显示“到底屏蔽了哪一段”，比看原始规则直观 */
static void FormatBlackRangeW(const unsigned char *lo, const unsigned char *hi,
                              WCHAR *buf, size_t cch)
{
    WCHAR a[24];
    WCHAR b[24];
    BOOL allZero = TRUE;
    BOOL allOnes = TRUE;
    int bits = 0;
    int i;

    for (i = 0; i < 4; ++i) {
        if (lo[i] != 0)
            allZero = FALSE;
        if (hi[i] != 0xFF)
            allOnes = FALSE;
    }
    if (allZero && allOnes) {
        WPrintf(buf, cch, L"全部 IPv4 地址");
        return;
    }
    FormatIpv4W(lo, a, sizeof(a) / sizeof(a[0]));
    if (RangeIsPrefix(lo, hi, &bits)) {
        if (bits >= 32)
            WPrintf(buf, cch, L"%s", a);
        else
            WPrintf(buf, cch, L"%s/%d", a, bits);
        return;
    }
    FormatIpv4W(hi, b, sizeof(b) / sizeof(b[0]));
    WPrintf(buf, cch, L"%s - %s", a, b);
}

static void RefreshBlackList(void)
{
    static BLACK_ROW rows[BLACK_MAX_RULES];
    static int builtVersion = -1;
    int version;
    int n = 0;
    int i;
    unsigned long totalHits = 0;

    if (g_hwndBlackRuleList == NULL)
        return;

    version = (int)InterlockedCompareExchange(&g_blackVersion, 0, 0);

    EnterCriticalSection(&g_cs);
    for (i = 0; i < g_blackCount && n < BLACK_MAX_RULES; ++i) {
        BLACK_ROW *row = &rows[n];

        ZeroMemory(row, sizeof(*row));
        CopyW(row->text, sizeof(row->text) / sizeof(row->text[0]), g_black[i].text);
        FormatBlackRangeW(g_black[i].lo, g_black[i].hi,
                          row->range, sizeof(row->range) / sizeof(row->range[0]));
        WPrintf(row->hits, sizeof(row->hits) / sizeof(row->hits[0]), L"%lu",
                g_black[i].hits);
        totalHits += g_black[i].hits;
        ++n;
    }
    LeaveCriticalSection(&g_cs);

    /* 数量对不上也要重建：窗口关掉再打开时列表控件是新的，
       而 builtVersion 是函数静态变量、不会跟着窗口重置 */
    if (version != builtVersion ||
        ListView_GetItemCount(g_hwndBlackRuleList) != n) {
        int top = ListView_GetTopIndex(g_hwndBlackRuleList);

        ListView_DeleteAllItems(g_hwndBlackRuleList);
        for (i = 0; i < n; ++i) {
            LVITEMW item;

            ZeroMemory(&item, sizeof(item));
            item.mask = LVIF_TEXT;
            item.iItem = i;
            item.pszText = rows[i].text;
            ListView_InsertItem(g_hwndBlackRuleList, &item);
            SetSubItemText(g_hwndBlackRuleList, i, 1, rows[i].range);
            SetSubItemText(g_hwndBlackRuleList, i, 2, rows[i].hits);
        }
        if (top > 0 && top < n)
            ListView_EnsureVisible(g_hwndBlackRuleList, top, FALSE);
        builtVersion = version;
    } else {
        for (i = 0; i < n; ++i) {
            SetSubItemText(g_hwndBlackRuleList, i, 0, rows[i].text);
            SetSubItemText(g_hwndBlackRuleList, i, 1, rows[i].range);
            SetSubItemText(g_hwndBlackRuleList, i, 2, rows[i].hits);
        }
    }

    if (g_hwndBlack != NULL) {
        WCHAR title[128];

        WPrintf(title, sizeof(title) / sizeof(title[0]),
                L"黑名单 - %d 条规则（累计命中 %lu 次）", n, totalHits);
        SetWindowTextW(g_hwndBlack, title);
    }
}

static void CreateBlackControls(HWND hwnd)
{
    struct {
        const WCHAR *name;
        int width;
    } cols[3] = {
        { L"规则", 220 },
        { L"匹配范围", 360 },
        { L"命中", 60 }
    };
    int i;
    LVCOLUMNW col;

    g_hwndBlackInfo = MakeControl(L"STATIC",
        L"命中后：TCP 立即回 RST 断开，UDP 直接丢弃；只在连接建立时检查一次，已建立的连接不受影响。\r\n"
        L"规则写法：113.75.1.10  |  113.75.*.*  |  113.75  |  113.75.1.0/24  |  "
        L"113.75.1.10-113.75.1.200",
        SS_LEFT, 0, IDC_BLACKINFO, hwnd);

    g_hwndBlackEdit = MakeControl(L"EDIT", L"",
        WS_TABSTOP | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, IDC_BLACKEDIT, hwnd);
    SendMessageW(g_hwndBlackEdit, EM_SETLIMITTEXT, BLACK_TEXT_CCH - 1, 0);
    SendMessageW(g_hwndBlackEdit, EM_SETCUEBANNER, TRUE,
                 (LPARAM)L"输入要屏蔽的网段，例如 113.75.*.* 或 113.75.1.10-113.75.1.200");

    g_hwndBlackAdd = MakeControl(L"BUTTON", L"添加",
        WS_TABSTOP | BS_DEFPUSHBUTTON, 0, IDC_BLACKADD, hwnd);
    g_hwndBlackDel = MakeControl(L"BUTTON", L"删除选中", WS_TABSTOP, 0,
                                 IDC_BLACKDEL, hwnd);
    g_hwndBlackClear = MakeControl(L"BUTTON", L"全部清空", WS_TABSTOP, 0,
                                   IDC_BLACKCLEAR, hwnd);

    g_hwndBlackRuleList = MakeControl(WC_LISTVIEWW, NULL,
        WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_BORDER,
        0, IDC_BLACKRULELIST, hwnd);
    ListView_SetExtendedListViewStyle(g_hwndBlackRuleList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    for (i = 0; i < 3; ++i) {
        ZeroMemory(&col, sizeof(col));
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        col.pszText = (LPWSTR)cols[i].name;
        col.cx = cols[i].width;
        col.iSubItem = i;
        ListView_InsertColumn(g_hwndBlackRuleList, i, &col);
    }

    g_hwndBlackStatus = MakeControl(L"STATIC",
        L"输入规则后点“添加”，立即生效；已经建立的连接不会被断开。",
        SS_LEFT, 0, IDC_BLACKSTATUS, hwnd);

    ApplyFonts(hwnd);
}

static void LayoutBlackControls(HWND hwnd)
{
    RECT rc;
    int margin = 12;
    int infoH = 48;
    int editY;
    int listY;
    int statusH = 20;
    int btnW = 84;
    int delW = 96;
    int clrW = 96;
    int editW;
    int listH;

    GetClientRect(hwnd, &rc);
    editY = margin + infoH + 10;
    editW = rc.right - 2 * margin - btnW - delW - clrW - 3 * 8;
    if (editW < 120)
        editW = 120;

    MoveWindow(g_hwndBlackInfo, margin, margin, rc.right - 2 * margin, infoH, TRUE);
    MoveWindow(g_hwndBlackEdit, margin, editY, editW, 24, TRUE);
    MoveWindow(g_hwndBlackAdd, margin + editW + 8, editY - 2, btnW, 28, TRUE);
    MoveWindow(g_hwndBlackDel, margin + editW + 8 + btnW + 8, editY - 2,
               delW, 28, TRUE);
    MoveWindow(g_hwndBlackClear,
               margin + editW + 8 + btnW + 8 + delW + 8, editY - 2,
               clrW, 28, TRUE);

    listY = editY + 34;
    listH = rc.bottom - listY - margin - statusH - 8;
    if (listH < 80)
        listH = 80;
    MoveWindow(g_hwndBlackRuleList, margin, listY, rc.right - 2 * margin,
               listH, TRUE);
    MoveWindow(g_hwndBlackStatus, margin, rc.bottom - margin - statusH,
               rc.right - 2 * margin, statusH, TRUE);

    /* 窗口变窄时让“匹配范围”列先缩，避免出现横向滚动条把“命中”列挡掉 */
    {
        int listW = rc.right - 2 * margin;
        int rangeW = listW - (200 + 70) - 6;

        if (rangeW < 140)
            rangeW = 140;
        ListView_SetColumnWidth(g_hwndBlackRuleList, 0, 200);
        ListView_SetColumnWidth(g_hwndBlackRuleList, 1, rangeW);
        ListView_SetColumnWidth(g_hwndBlackRuleList, 2, 70);
    }
}

static void BlackAddFromUi(void)
{
    WCHAR text[BLACK_TEXT_CCH * 2];
    WCHAR err[160];
    WCHAR msg[256];
    unsigned char lo[4];
    unsigned char hi[4];
    int i;
    BOOL dup = FALSE;
    BOOL full = FALSE;

    if (g_hwndBlackEdit == NULL)
        return;

    text[0] = L'\0';
    GetWindowTextW(g_hwndBlackEdit, text, (int)(sizeof(text) / sizeof(text[0])));
    TrimW(text);
    if (text[0] == L'\0') {
        SetWindowTextW(g_hwndBlackStatus, L"请先输入规则");
        SetFocus(g_hwndBlackEdit);
        return;
    }
    if (!ParseBlackRule(text, lo, hi, err, sizeof(err) / sizeof(err[0]))) {
        WPrintf(msg, sizeof(msg) / sizeof(msg[0]), L"添加失败：%s", err);
        SetWindowTextW(g_hwndBlackStatus, msg);
        return;
    }

    EnterCriticalSection(&g_cs);
    for (i = 0; i < g_blackCount; ++i) {
        if (memcmp(g_black[i].lo, lo, 4) == 0 &&
            memcmp(g_black[i].hi, hi, 4) == 0) {
            dup = TRUE;
            break;
        }
    }
    if (!dup) {
        if (g_blackCount >= BLACK_MAX_RULES) {
            full = TRUE;
        } else {
            BLACK_RULE *r = &g_black[g_blackCount];

            ZeroMemory(r, sizeof(*r));
            memcpy(r->lo, lo, 4);
            memcpy(r->hi, hi, 4);
            CopyW(r->text, sizeof(r->text) / sizeof(r->text[0]), text);
            ++g_blackCount;
            InterlockedIncrement(&g_blackVersion);
        }
    }
    LeaveCriticalSection(&g_cs);

    if (dup) {
        SetWindowTextW(g_hwndBlackStatus, L"该规则已存在（地址范围完全相同）");
        return;
    }
    if (full) {
        SetWindowTextW(g_hwndBlackStatus, L"规则数量已达上限，请先删除旧规则");
        return;
    }

    SetWindowTextW(g_hwndBlackEdit, L"");
    SetWindowTextW(g_hwndBlackStatus, L"已添加，立即生效（只影响之后建立的连接）");
    AddLog(L"黑名单新增规则: %s", text);
    RefreshBlackList();
    SetFocus(g_hwndBlackEdit);
}

static void BlackDeleteSelected(void)
{
    WCHAR removed[BLACK_TEXT_CCH];
    WCHAR msg[192];
    BOOL ok = FALSE;
    int idx;

    if (g_hwndBlackRuleList == NULL)
        return;
    idx = ListView_GetNextItem(g_hwndBlackRuleList, -1, LVNI_SELECTED);
    if (idx < 0) {
        SetWindowTextW(g_hwndBlackStatus, L"请先在列表里选中一行");
        return;
    }

    removed[0] = L'\0';
    EnterCriticalSection(&g_cs);
    if (idx < g_blackCount) {
        CopyW(removed, sizeof(removed) / sizeof(removed[0]), g_black[idx].text);
        if (idx + 1 < g_blackCount) {
            memmove(&g_black[idx], &g_black[idx + 1],
                    (size_t)(g_blackCount - idx - 1) * sizeof(BLACK_RULE));
        }
        --g_blackCount;
        InterlockedIncrement(&g_blackVersion);
        ok = TRUE;
    }
    LeaveCriticalSection(&g_cs);

    if (!ok)
        return;
    WPrintf(msg, sizeof(msg) / sizeof(msg[0]), L"已删除: %s", removed);
    SetWindowTextW(g_hwndBlackStatus, msg);
    AddLog(L"黑名单删除规则: %s", removed);
    RefreshBlackList();
}

static void BlackClearAll(void)
{
    int n;

    EnterCriticalSection(&g_cs);
    n = g_blackCount;
    g_blackCount = 0;
    if (n > 0)
        InterlockedIncrement(&g_blackVersion);
    LeaveCriticalSection(&g_cs);

    if (n > 0) {
        SetWindowTextW(g_hwndBlackStatus, L"已清空全部规则");
        AddLog(L"黑名单已清空（原来 %d 条）", n);
    } else {
        SetWindowTextW(g_hwndBlackStatus, L"黑名单本来就是空的");
    }
    RefreshBlackList();
}

static void ShowBlacklistWindow(void)
{
    RECT main;
    RECT rc;

    if (g_hwndBlack == NULL || !IsWindow(g_hwndBlack)) {
        if (!GetWindowRect(g_hwndMain, &main))
            ZeroMemory(&main, sizeof(main));
        rc.left = main.left + 90;
        rc.top = main.top + 90;
        rc.right = rc.left + 860;
        rc.bottom = rc.top + 500;
        AdjustWindowRectEx(&rc, WS_OVERLAPPEDWINDOW, FALSE, 0);
        ClampWindowRect(&rc);
        g_hwndBlack = CreateWindowExW(WS_EX_CONTROLPARENT,
                                      NAT_WNDCLASS_BLACK, L"黑名单",
                                      WS_OVERLAPPEDWINDOW,
                                      rc.left, rc.top, rc.right - rc.left,
                                      rc.bottom - rc.top, g_hwndMain, NULL,
                                      g_hInst, NULL);
        if (g_hwndBlack == NULL) {
            AddLog(L"黑名单窗口创建失败（错误 %lu）",
                   (unsigned long)GetLastError());
            return;
        }
        ShowWindow(g_hwndBlack, SW_SHOW);
        UpdateWindow(g_hwndBlack);
    } else {
        if (IsIconic(g_hwndBlack))
            ShowWindow(g_hwndBlack, SW_RESTORE);
        RefreshBlackList();
    }
    SetForegroundWindow(g_hwndBlack);
}

static LRESULT CALLBACK BlackWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
        CreateBlackControls(hwnd);
        LayoutBlackControls(hwnd);
        SetTimer(hwnd, BLACK_TIMER_ID, 1000, NULL);
        RefreshBlackList();
        return 0;

    case WM_SIZE:
        if (g_hwndBlackRuleList != NULL)
            LayoutBlackControls(hwnd);
        return 0;

    case WM_TIMER:
        if (wParam == BLACK_TIMER_ID)
            RefreshBlackList();
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BLACKADD:
            if (HIWORD(wParam) == BN_CLICKED)
                BlackAddFromUi();
            return 0;
        case IDC_BLACKDEL:
            if (HIWORD(wParam) == BN_CLICKED)
                BlackDeleteSelected();
            return 0;
        case IDC_BLACKCLEAR:
            if (HIWORD(wParam) == BN_CLICKED)
                BlackClearAll();
            return 0;
        }
        return 0;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, BLACK_TIMER_ID);
        g_hwndBlack = NULL;
        g_hwndBlackInfo = NULL;
        g_hwndBlackEdit = NULL;
        g_hwndBlackAdd = NULL;
        g_hwndBlackDel = NULL;
        g_hwndBlackClear = NULL;
        g_hwndBlackRuleList = NULL;
        g_hwndBlackStatus = NULL;
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* 窗口过程                                                            */
/* ------------------------------------------------------------------ */

/* 窗口带 WS_CLIPCHILDREN：父窗口擦背景时子窗口矩形被整块排除，
   而 STATIC/GROUPBOX 自己又不会擦客户区，所以控件一移动，旧文字就永远
   留在屏幕上（缩放窗口时"碎成渣"）。这里直接往窗口 DC 上把整个客户区
   涂成窗口底色，绕开裁剪，再把所有子控件重画一遍。 */
static void ForceRepaintAll(HWND hwnd)
{
    HDC dc;
    RECT rc;

    if (hwnd == NULL)
        return;
    dc = GetDC(hwnd);
    if (dc != NULL) {
        GetClientRect(hwnd, &rc);
        FillRect(dc, &rc, g_bgBrush != NULL ? g_bgBrush
                                            : GetSysColorBrush(COLOR_BTNFACE));
        ReleaseDC(hwnd, dc);
    }
    RedrawWindow(hwnd, NULL, NULL,
                 RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN |
                 RDW_UPDATENOW | RDW_FRAME);
}

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE:
        g_hwndMain = hwnd;
        g_bgBrush = CreateSolidBrush(GetSysColor(COLOR_BTNFACE));
        CreateFonts(hwnd);
        CreateControls(hwnd);
        if (g_hwndList == NULL || g_hwndLog == NULL || g_hwndStatus == NULL ||
            g_hwndStun == NULL || g_hwndLocal == NULL ||
            g_hwndBackPort == NULL || g_hwndAdd == NULL ||
            g_hwndProto == NULL || g_hwndUpnp == NULL ||
            g_hwndBlackBtn == NULL) {
            MessageBoxW(hwnd, L"界面控件创建失败，程序无法继续", APP_NAME,
                        MB_OK | MB_ICONERROR);
            return -1;              /* 让 CreateWindowExW 直接失败 */
        }
        CreateListColumns();
        LayoutControls(hwnd);
        SetTimer(hwnd, APP_TIMER_ID, 1000, NULL);
        AddLog(L"%s %s 已启动", NAT_PRODUCT, APP_VERSION);
        AddLog(L"默认 STUN: %s", DEFAULT_STUN_TEXT);
        AddLog(L"提示: 本工具适合映射行为和过滤行为均为 EndpointIndependent 的用户。");
        AddLog(L"      不提供 NAT 类型检测。UDP 每 30 秒、TCP 每 30 秒发送 STUN 保活。");
        AddLog(L"默认启用 UPnP 自动端口映射；网关不支持 UPnP 时自动改用 STUN 穿透。");
        AddLog(L"请填写本地端口（可留空随机）、服务端口，然后点击“添加并启动”。");
        AddLog(L"外网连不进来时先查 Windows 防火墙：本程序是绿色单文件，"
               L"入站规则必须指向实际运行的 exe 路径，规则缺失或路径不符都会被静默丢弃。");
        return 0;

    case WM_SIZE:
        /* 最小化时客户区是 0×0，按它重排会把控件压成负尺寸，直接跳过 */
        if (g_hwndList != NULL && wParam != SIZE_MINIMIZED) {
            LayoutControls(hwnd);
            /* 每帧立刻整窗重画：拖动边框时如果等系统自己处理，上一帧
               的文字会一直留在屏幕上（"碎成渣"）。 */
            ForceRepaintAll(hwnd);
        }
        return 0;

    case WM_EXITSIZEMOVE:
        /* 拖拽结束再补一次，确保松手后的最终画面干净 */
        ForceRepaintAll(hwnd);
        return 0;

    case WM_VSCROLL:
        {
            SCROLLINFO si;
            int old = g_scrollY;

            ZeroMemory(&si, sizeof(si));
            si.cbSize = sizeof(si);
            si.fMask = SIF_ALL;
            GetScrollInfo(hwnd, SB_VERT, &si);
            switch (LOWORD(wParam)) {
            case SB_LINEUP:
                g_scrollY -= 24;
                break;
            case SB_LINEDOWN:
                g_scrollY += 24;
                break;
            case SB_PAGEUP:
                g_scrollY -= (int)si.nPage;
                break;
            case SB_PAGEDOWN:
                g_scrollY += (int)si.nPage;
                break;
            case SB_THUMBTRACK:
            case SB_THUMBPOSITION:
                g_scrollY = (int)si.nTrackPos;
                break;
            case SB_TOP:
                g_scrollY = 0;
                break;
            case SB_BOTTOM:
                g_scrollY = (int)si.nMax;
                break;
            }
            if (g_scrollY < 0)
                g_scrollY = 0;
            if (old != g_scrollY) {
                LayoutControls(hwnd);
                ForceRepaintAll(hwnd);
            }
        }
        return 0;

    case WM_MOUSEWHEEL:
        {
            int delta = (int)(short)HIWORD(wParam);

            g_scrollY -= (delta / WHEEL_DELTA) * 48;
            if (g_scrollY < 0)
                g_scrollY = 0;
            LayoutControls(hwnd);
            ForceRepaintAll(hwnd);
        }
        return 0;

    case WM_TIMER:
        if (wParam == APP_TIMER_ID) {
            /* 兜底：万一某次 WM_APP_LOG 没投递成功（9x 上 PostMessageW
               就是这种情况），每秒补搬一次日志队列，日志不会永久空白 */
            DrainLogQueue();
            RefreshList();
            UpdateStatusBar();
        }
        return 0;

    case WM_APP_LOG:
        DrainLogQueue();
        return 0;

    case WM_CTLCOLORSTATIC:
        {
            HDC dc = (HDC)wParam;
            HWND child = (HWND)lParam;

            /* 日志是只读多行编辑框：必须用不透明背景重绘，
               否则滚动时旧字符不会被擦除，文字会糊成一片。 */
            if (child == g_hwndLog) {
                SetBkMode(dc, OPAQUE);
                SetBkColor(dc, GetSysColor(COLOR_WINDOW));
                SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
                return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
            }

            /* 透明背景画字时 STATIC 不会擦掉自己客户区的旧像素，控件一移动
               旧文字就会一层层叠上来（缩放窗口时"碎成渣"）。改成不透明背景。 */
            SetBkMode(dc, OPAQUE);
            SetBkColor(dc, GetSysColor(COLOR_BTNFACE));
            if (child == g_hwndHint)
                SetTextColor(dc, RGB(0, 80, 160));
            else
                SetTextColor(dc, GetSysColor(COLOR_WINDOWTEXT));
            return (LRESULT)g_bgBrush;
        }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_ADD:
            if (HIWORD(wParam) == BN_CLICKED)
                AddMappingFromUi();
            return 0;
        case IDC_START:
            if (HIWORD(wParam) == BN_CLICKED)
                StartSelectedMapping();
            return 0;
        case IDC_STOP:
            if (HIWORD(wParam) == BN_CLICKED)
                StopSelectedMapping();
            return 0;
        case IDC_DELETE:
            if (HIWORD(wParam) == BN_CLICKED)
                DeleteSelectedMapping();
            return 0;
        case IDC_STOPALL:
            if (HIWORD(wParam) == BN_CLICKED) {
                if (g_mapCount == 0) {
                    AddLog(L"当前没有映射");
                } else {
                    StopAllMappings();
                    AddLog(L"已请求停止全部映射");
                }
            }
            return 0;
        case IDC_CONNTABLE:
            if (HIWORD(wParam) == BN_CLICKED)
                ShowConnTable();
            return 0;
        case IDC_BLACKLIST:
            if (HIWORD(wParam) == BN_CLICKED)
                ShowBlacklistWindow();
            return 0;
        case IDC_CLEARLOG:
            if (HIWORD(wParam) == BN_CLICKED)
                ClearLog();
            return 0;
        case IDC_PROXY:
            if (HIWORD(wParam) == BN_CLICKED)
                UpdateProxyEnable();
            return 0;
        case IDC_PROTO:
            if (HIWORD(wParam) == CBN_SELCHANGE)
                UpdateProxyEnable();
            return 0;
        }
        return 0;

    case WM_GETMINMAXINFO:
        {
            MINMAXINFO *mmi = (MINMAXINFO *)lParam;
            RECT work;
            int maxW;
            int maxH;

            /* 下限从 1000x620 降到 480x360，并且不允许超过屏幕工作区：
               原来在 640x480 上最小尺寸比屏幕还大，窗口根本缩不小。 */
            mmi->ptMinTrackSize.x = 480;
            mmi->ptMinTrackSize.y = 360;
            if (!SystemParametersInfoA(SPI_GETWORKAREA, 0, &work, 0)) {
                work.left = 0;
                work.top = 0;
                work.right = GetSystemMetrics(SM_CXSCREEN);
                work.bottom = GetSystemMetrics(SM_CYSCREEN);
            }
            maxW = work.right - work.left;
            maxH = work.bottom - work.top;
            if (mmi->ptMinTrackSize.x > maxW)
                mmi->ptMinTrackSize.x = maxW;
            if (mmi->ptMinTrackSize.y > maxH)
                mmi->ptMinTrackSize.y = maxH;
            if (mmi->ptMaxTrackSize.x > maxW)
                mmi->ptMaxTrackSize.x = maxW;
            if (mmi->ptMaxTrackSize.y > maxH)
                mmi->ptMaxTrackSize.y = maxH;
        }
        return 0;

    case WM_CLOSE:
        if (g_mapCount > 0) {
            if (MessageBoxW(hwnd, L"关闭程序会停止所有映射，确定退出吗？",
                            APP_NAME, MB_YESNO | MB_ICONQUESTION) != IDYES)
                return 0;
        }
        if (InterlockedCompareExchange(&g_appStopping, 0, 0) != 0)
            return 0;               /* 已经在退出，别重复走一遍 */
        InterlockedExchange(&g_appStop, 1);
        {
            HCURSOR oldCursor = SetCursor(LoadCursorW(NULL, IDC_WAIT));

            StopAllMappings();
            SetCursor(oldCursor);   /* 等待光标必须还原，否则鼠标一直是漏斗 */
        }
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        InterlockedExchange(&g_appStopping, 1);
        KillTimer(hwnd, APP_TIMER_ID);
        FreeLogQueue();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/* ------------------------------------------------------------------ */
/* 入口                                                                */
/* ------------------------------------------------------------------ */

#ifndef NATHELPER_NO_WINMAIN
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    WSADATA wsa;
    INITCOMMONCONTROLSEX icc;
    WNDCLASSEXW wc;
    HWND hwnd;
    MSG msg;
    RECT rc;
    ZeroMemory(&msg, sizeof(msg));
    int x;
    int y;

    (void)hPrevInstance;
    (void)lpCmdLine;

    g_hInst = hInstance;

    /* Win95 零售版没有 ws2_32.dll，只有 Winsock 1.1；NT4 SP4 之前也一样。
       先按 2.2 要，失败再退 1.1，两个都失败才算没有网络栈。 */
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0 &&
        WSAStartup(MAKEWORD(1, 1), &wsa) != 0) {
        MessageBoxW(NULL, L"Winsock 初始化失败", APP_NAME, MB_OK | MB_ICONERROR);
        return 1;
    }

    ZeroMemory(&icc, sizeof(icc));
    icc.dwSize = sizeof(icc);
#if NAT_LEGACY
    /* NT4 自带的是 comctl32 4.0，没有 InitCommonControlsEx（4.71 起）。
       静态调用会让 exe 在老系统上因缺导出而无法加载，所以运行期取地址：
       新系统照常用 Ex，老系统退回 InitCommonControls。 */
    {
        HMODULE hCtl = LoadLibraryA("comctl32.dll");
        BOOL (WINAPI *pInitEx)(const INITCOMMONCONTROLSEX *) = NULL;

        if (hCtl != NULL)
            pInitEx = (BOOL (WINAPI *)(const INITCOMMONCONTROLSEX *))(void *)
                      GetProcAddress(hCtl, "InitCommonControlsEx");
        if (pInitEx != NULL) {
            icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
            if (!pInitEx(&icc)) {
                icc.dwICC = ICC_LISTVIEW_CLASSES;
                pInitEx(&icc);
            }
        } else {
            InitCommonControls();
        }
    }
#else
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
    if (!InitCommonControlsEx(&icc)) {
        /* 没有 comctl32 v6 激活上下文时 ICC_STANDARD_CLASSES 会失败，
           退一步只请求 ListView；仍失败也不致命，系统自带控件照样能用。 */
        icc.dwICC = ICC_LISTVIEW_CLASSES;
        InitCommonControlsEx(&icc);
    }
#endif

    InitializeCriticalSection(&g_cs);

    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = NAT_WNDCLASS_MAIN;
    if (!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"窗口类注册失败", APP_NAME, MB_OK | MB_ICONERROR);
        WSACleanup();
        DeleteCriticalSection(&g_cs);
        return 1;
    }

    /* 连接表是独立的半模态窗口；注册失败也不影响主窗口运行 */
    wc.lpfnWndProc = ConnWndProc;
    wc.lpszClassName = NAT_WNDCLASS_CONN;
    wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        /* 连接表窗口不可用不影响主窗口，但要在日志里说清楚 */
        AddLog(L"连接表窗口类注册失败（错误 %lu），连接表功能不可用",
               (unsigned long)GetLastError());
    }

    /* 黑名单窗口同样独立；注册失败只影响黑名单界面，拦截逻辑不受影响 */
    wc.lpfnWndProc = BlackWndProc;
    wc.lpszClassName = NAT_WNDCLASS_BLACK;
    wc.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        AddLog(L"黑名单窗口类注册失败（错误 %lu），黑名单界面不可用",
               (unsigned long)GetLastError());
    }

    /* 初始尺寸不超过屏幕工作区：640x480 上原设计的 1120x730 根本放不下，
       窗口会被任务栏和屏幕边缘切掉一块。 */
    {
        RECT work;
        int cw = 1120;
        int ch = 730;

        if (SystemParametersInfoA(SPI_GETWORKAREA, 0, &work, 0)) {
            if (cw > work.right - work.left)
                cw = work.right - work.left;
            if (ch > work.bottom - work.top)
                ch = work.bottom - work.top;
        } else {
            if (cw > GetSystemMetrics(SM_CXSCREEN))
                cw = GetSystemMetrics(SM_CXSCREEN);
            if (ch > GetSystemMetrics(SM_CYSCREEN))
                ch = GetSystemMetrics(SM_CYSCREEN);
        }
        if (cw < 480)
            cw = 480;
        if (ch < 360)
            ch = 360;
        rc.left = 0;
        rc.top = 0;
        rc.right = cw;
        rc.bottom = ch;
    }
    AdjustWindowRectEx(&rc, WS_OVERLAPPEDWINDOW, FALSE, 0);
    x = (GetSystemMetrics(SM_CXSCREEN) - (rc.right - rc.left)) / 2;
    y = (GetSystemMetrics(SM_CYSCREEN) - (rc.bottom - rc.top)) / 2;
    /* 居中之后再把位置夹进工作区：任务栏在左侧的机器上，居中会把窗口
       压到任务栏上面，标题栏和左边框都被盖住 */
    {
        RECT work;

        if (SystemParametersInfoA(SPI_GETWORKAREA, 0, &work, 0)) {
            if (x < work.left)
                x = work.left;
            if (y < work.top)
                y = work.top;
            if (x + (rc.right - rc.left) > work.right)
                x = work.right - (rc.right - rc.left);
            if (y + (rc.bottom - rc.top) > work.bottom)
                y = work.bottom - (rc.bottom - rc.top);
        }
    }
    if (x < 0)
        x = 0;
    if (y < 0)
        y = 0;

    /* 不能用 WS_CLIPCHILDREN：那样父窗口的绘制会被整块裁掉子窗口区域，
       而 STATIC/GROUPBOX 自己并不擦客户区，控件一移动旧文字就永久留在
       屏幕上（缩放窗口"碎成渣"）。去掉后父窗口才能真正擦干净整块客户区。 */
    hwnd = CreateWindowExW(WS_EX_CONTROLPARENT,
                           NAT_WNDCLASS_MAIN, APP_TITLE,
                           WS_OVERLAPPEDWINDOW | WS_VSCROLL,
                           x, y, rc.right - rc.left, rc.bottom - rc.top,
                           NULL, NULL, hInstance, NULL);
    if (hwnd == NULL) {
        MessageBoxW(NULL, L"窗口创建失败", APP_NAME, MB_OK | MB_ICONERROR);
        WSACleanup();
        DeleteCriticalSection(&g_cs);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    for (;;) {
        BOOL got = GetMessageW(&msg, NULL, 0, 0);

        if (got == 0)
            break;                  /* WM_QUIT */
        if (got == (BOOL)-1) {
            /* 消息循环出错：不能再等，按退出处理 */
            msg.wParam = 1;
            AddLog(L"消息循环异常（错误 %lu），程序退出",
                   (unsigned long)GetLastError());
            break;
        }
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    InterlockedExchange(&g_appStop, 1);
    InterlockedExchange(&g_appStopping, 1);
    {
        NAT_MAPPING *m;
        EnterCriticalSection(&g_cs);
        for (m = g_maps; m != NULL; m = m->next)
            InterlockedExchange(&m->stop, 1);
        LeaveCriticalSection(&g_cs);
    }

    /* 所有映射共用一个等待总时长，别一个个等满 8 秒 */
    {
        ULONGLONG deadline = NowMs64() + STOP_WAIT_MS;

        for (;;) {
            BOOL any = FALSE;
            NAT_MAPPING *m;

            EnterCriticalSection(&g_cs);
            for (m = g_maps; m != NULL; m = m->next) {
                if (m->thread == NULL)
                    continue;
                if (WaitForSingleObject(m->thread, 0) == WAIT_OBJECT_0) {
                    CloseHandle(m->thread);
                    m->thread = NULL;
                } else {
                    any = TRUE;
                }
            }
            LeaveCriticalSection(&g_cs);
            if (!any)
                break;
            if (NowMs64() >= deadline)
                break;
            Sleep(30);
        }
    }

    {
        BOOL threadsLeft = FALSE;
        NAT_MAPPING *m = g_maps;
        USHORT upnpPorts[MAX_MAPPINGS];
        int upnpCount = 0;
        int i;

        /* 还有线程没退出时，至少把路由器上的 UPnP 规则删掉再结束进程 */
        EnterCriticalSection(&g_cs);
        for (m = g_maps; m != NULL; m = m->next) {
            if (m->thread != NULL) {
                threadsLeft = TRUE;
                if (m->upnp_mapped && m->upnp_ext_port != 0 &&
                    upnpCount < MAX_MAPPINGS) {
                    upnpPorts[upnpCount++] = m->upnp_ext_port;
                    m->upnp_mapped = 0;
                }
            }
        }
        LeaveCriticalSection(&g_cs);
        for (i = 0; i < upnpCount; ++i)
            UpnpRemoveMappedPort(TRUE, upnpPorts[i]);

        while (m != NULL) {
            NAT_MAPPING *next = m->next;

            if (m->thread == NULL)
                free(m);
            m = next;
        }
        g_maps = NULL;
        g_mapCount = 0;

        if (threadsLeft) {
            /* 线程卡住时不能 WSACleanup/DeleteCriticalSection，
               只能结束进程；此时 UPnP 规则已经清掉了。 */
            if (g_upnp_lock != NULL) {
                CloseHandle(g_upnp_lock);
                g_upnp_lock = NULL;
            }
            ExitProcess((UINT)msg.wParam);
        }
    }

    if (g_hFont != NULL && g_fontOwned)
        DeleteObject(g_hFont);
    if (g_bgBrush != NULL)
        DeleteObject(g_bgBrush);
    if (g_upnp_lock != NULL) {
        CloseHandle(g_upnp_lock);
        g_upnp_lock = NULL;
    }
    WSACleanup();
    DeleteCriticalSection(&g_cs);
    return (int)msg.wParam;
}
#endif
