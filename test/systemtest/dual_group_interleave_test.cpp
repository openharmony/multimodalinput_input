/*
 * dual_group_interleave_test.cpp
 *
 * 双显示组 + 双鼠标/双键盘 综合验收测试
 * 通过 UpdateDisplayInfo 构造双显示组（含 ScreenInfo/screenArea），
 * 用 /dev/uinput 创建双鼠标+双键盘，覆盖：
 *   鼠标移动隔离、光标边界钳制、按钮隔离、跨组同时按钮保持、滚轮隔离、
 *   z-order 命中（含全屏位置无关）、热区穿透、窗口 ADD→CHANGE→DEL 生命周期、
 *   键盘路由、修饰键状态隔离、动态焦点切换（含非主组）、设备重绑定、
 *   显示组移除+状态清理、captureMode 隔离、PointerStyle per-window、并发压力
 *
 * 验证手段：注入 uinput 事件 → hidumper -G → SequenceSnapshots / PointerState
 */

#include <cstdio>
#include <cstring>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>
#include <linux/input.h>
#include <linux/uinput.h>

#include "input_manager.h"

using namespace OHOS::MMI;

/* ====================================================================== */
/* 全局焦点追踪（SetupDualDisplayGroups 和 InjectAllWindows 共享）         */
/* ====================================================================== */
static int32_t g_focusWin0 = 1000;
static int32_t g_focusWin1 = 2000;

/* ====================================================================== */
/* Helper: 创建虚拟 USB 鼠标                                              */
/* ====================================================================== */
static int CreateMouse(const char *name, uint16_t product)
{
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) { return -1; }
    ioctl(fd, UI_SET_EVBIT, EV_KEY);
    ioctl(fd, UI_SET_EVBIT, EV_REL);
    ioctl(fd, UI_SET_EVBIT, EV_MSC);
    ioctl(fd, UI_SET_KEYBIT, BTN_LEFT);
    ioctl(fd, UI_SET_KEYBIT, BTN_RIGHT);
    ioctl(fd, UI_SET_KEYBIT, BTN_MIDDLE);
    ioctl(fd, UI_SET_RELBIT, REL_X);
    ioctl(fd, UI_SET_RELBIT, REL_Y);
    ioctl(fd, UI_SET_RELBIT, REL_WHEEL);
    ioctl(fd, UI_SET_MSCBIT, MSC_SCAN);
    struct uinput_user_dev ud = {};
    strncpy(ud.name, name, UINPUT_MAX_NAME_SIZE - 1);
    ud.id.bustype = BUS_USB;
    ud.id.vendor = 0x93a;
    ud.id.product = product;
    ud.id.version = 1;
    write(fd, &ud, sizeof(ud));
    ioctl(fd, UI_DEV_CREATE);
    return fd;
}

/* ====================================================================== */
/* Helper: 创建虚拟 USB 键盘                                              */
/* ====================================================================== */
static int CreateKeyboard(const char *name, uint16_t product)
{
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) { return -1; }
    ioctl(fd, UI_SET_EVBIT, EV_KEY);
    ioctl(fd, UI_SET_EVBIT, EV_MSC);
    ioctl(fd, UI_SET_EVBIT, EV_LED);
    ioctl(fd, UI_SET_EVBIT, EV_REP);
    for (unsigned int code = 1; code <= 248; ++code) {
        ioctl(fd, UI_SET_KEYBIT, code);
    }
    ioctl(fd, UI_SET_MSCBIT, MSC_SCAN);
    ioctl(fd, UI_SET_LEDBIT, LED_NUML);
    ioctl(fd, UI_SET_LEDBIT, LED_CAPSL);
    ioctl(fd, UI_SET_LEDBIT, LED_SCROLLL);
    struct uinput_user_dev ud = {};
    strncpy(ud.name, name, UINPUT_MAX_NAME_SIZE - 1);
    ud.id.bustype = BUS_USB;
    ud.id.vendor = 0x24ae;
    ud.id.product = product;
    ud.id.version = 1;
    write(fd, &ud, sizeof(ud));
    ioctl(fd, UI_DEV_CREATE);
    return fd;
}

/* ====================================================================== */
/* Helper: 注入鼠标相对移动                                                */
/* ====================================================================== */
static void Inject(int fd, int dx, int dy)
{
    struct input_event ev = {};
    ev.type = EV_REL; ev.code = REL_X; ev.value = dx;
    write(fd, &ev, sizeof(ev));
    ev.code = REL_Y; ev.value = dy;
    write(fd, &ev, sizeof(ev));
    ev.type = EV_SYN; ev.code = SYN_REPORT; ev.value = 0;
    write(fd, &ev, sizeof(ev));
}

/* ====================================================================== */
/* Helper: 注入鼠标按钮 press/release                                      */
/* ====================================================================== */
static void InjectButton(int fd, unsigned int button, int value)
{
    struct input_event ev = {};
    ev.type = EV_KEY; ev.code = button; ev.value = value;
    write(fd, &ev, sizeof(ev));
    ev.type = EV_SYN; ev.code = SYN_REPORT; ev.value = 0;
    write(fd, &ev, sizeof(ev));
}

/* ====================================================================== */
/* Helper: 注入键盘按键 press/release                                      */
/* ====================================================================== */
static void InjectKeyEvent(int fd, unsigned int keyCode, int value)
{
    struct input_event ev = {};
    ev.type = EV_KEY; ev.code = keyCode; ev.value = value;
    write(fd, &ev, sizeof(ev));
    ev.type = EV_SYN; ev.code = SYN_REPORT; ev.value = 0;
    write(fd, &ev, sizeof(ev));
}

/* ====================================================================== */
/* Helper: 注入滚轮事件                                                    */
/* ====================================================================== */
static void InjectScroll(int fd, int delta)
{
    struct input_event ev = {};
    ev.type = EV_REL; ev.code = REL_WHEEL; ev.value = delta;
    write(fd, &ev, sizeof(ev));
    ev.type = EV_SYN; ev.code = SYN_REPORT; ev.value = 0;
    write(fd, &ev, sizeof(ev));
}

/* ====================================================================== */
/* Helper: 精确设置光标位置                                                 */
/* ====================================================================== */
static void SetCursorPos(int32_t x, int32_t y, int32_t displayId = -1)
{
    int32_t ret = InputManager::GetInstance()->SetPointerLocation(x, y, displayId);
    std::cout << "  SetPointerLocation(" << x << "," << y << ",disp=" << displayId
              << ") ret=" << ret << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

/* ====================================================================== */
/* Helper: 查找设备 ID                                                     */
/* ====================================================================== */
static int FindDevice(const std::string &targetName)
{
    std::mutex mtx;
    std::condition_variable cv;
    int foundId = -1;
    for (int attempt = 0; attempt < 30 && foundId < 0; ++attempt) {
        bool done = false;
        InputManager::GetInstance()->GetDeviceIds([&](std::vector<int32_t> &ids) {
            for (auto id : ids) {
                InputManager::GetInstance()->GetDevice(id, [&](std::shared_ptr<InputDevice> dev) {
                    if (dev && dev->GetName() == targetName) {
                        foundId = id;
                    }
                });
            }
            std::lock_guard<std::mutex> lock(mtx);
            done = true;
            cv.notify_one();
        });
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait_for(lock, std::chrono::milliseconds(500), [&] { return done; });
        if (foundId >= 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    return foundId;
}

/* ====================================================================== */
/* Helper: 构造双显示组（含 ScreenInfo + screenArea）                       */
/* 使用全局焦点变量 g_focusWin0/g_focusWin1                                */
/* ====================================================================== */
static void SetupDualDisplayGroups(int32_t focusWin0 = -1, int32_t focusWin1 = -1)
{
    if (focusWin0 >= 0) { g_focusWin0 = focusWin0; }
    if (focusWin1 >= 0) { g_focusWin1 = focusWin1; }

    DisplayGroupInfo group0;
    group0.id = 0;
    group0.name = "default";
    group0.type = GroupType::GROUP_DEFAULT;
    group0.mainDisplayId = 0;
    group0.focusWindowId = g_focusWin0;
    DisplayInfo disp0;
    disp0.id = 0; disp0.x = 0; disp0.y = 0;
    disp0.width = 720; disp0.height = 1280; disp0.dpi = 240;
    disp0.name = "main";
    disp0.direction = DIRECTION0; disp0.displayDirection = DIRECTION0;
    disp0.screenArea.id = 0;
    disp0.screenArea.area = { 0, 0, 720, 1280 };
    group0.displaysInfo.push_back(disp0);

    DisplayGroupInfo group1;
    group1.id = 1;
    group1.name = "secondary";
    group1.type = GroupType::GROUP_SPECIAL;
    group1.mainDisplayId = 1;
    group1.focusWindowId = g_focusWin1;
    DisplayInfo disp1;
    disp1.id = 1; disp1.x = 0; disp1.y = 0;
    disp1.width = 1920; disp1.height = 1080; disp1.dpi = 160;
    disp1.name = "secondary";
    disp1.direction = DIRECTION0; disp1.displayDirection = DIRECTION0;
    disp1.screenArea.id = 1;
    disp1.screenArea.area = { 0, 0, 1920, 1080 };
    group1.displaysInfo.push_back(disp1);

    UserScreenInfo screenInfo;
    screenInfo.userId = 100;
    screenInfo.displayGroups.push_back(group0);
    screenInfo.displayGroups.push_back(group1);

    ScreenInfo screen0;
    screen0.id = 0;
    screen0.uniqueId = "default0";
    screen0.width = 720; screen0.height = 1280;
    screen0.physicalWidth = 62; screen0.physicalHeight = 110;
    screen0.dpi = 240; screen0.ppi = 295;
    screen0.tpDirection = DIRECTION0;
    screenInfo.screens.push_back(screen0);

    ScreenInfo screen1;
    screen1.id = 1;
    screen1.uniqueId = "secondary1";
    screen1.width = 1920; screen1.height = 1080;
    screen1.physicalWidth = 531; screen1.physicalHeight = 299;
    screen1.dpi = 160; screen1.ppi = 92;
    screen1.tpDirection = DIRECTION0;
    screenInfo.screens.push_back(screen1);

    int32_t ret = InputManager::GetInstance()->UpdateDisplayInfo(screenInfo);
    std::cout << "  UpdateDisplayInfo ret=" << ret
              << " (focus0=" << g_focusWin0 << " focus1=" << g_focusWin1 << ")" << std::endl;
}

/* ====================================================================== */
/* Helper: 注入窗口 (批量，指定 groupId)                                    */
/* ====================================================================== */
struct WinDesc {
    int32_t id;
    Rect area;
    float zOrder;
};

static void InjectWindows(int32_t groupId, int32_t displayId, int32_t focusWindowId,
    const std::vector<WinDesc> &windows)
{
    WindowGroupInfo wgi;
    wgi.displayId = displayId;
    wgi.focusWindowId = focusWindowId;
    for (const auto &w : windows) {
        WindowInfo wi = {};
        wi.id = w.id;
        wi.pid = getpid();
        wi.uid = getuid();
        wi.area = w.area;
        wi.defaultHotAreas.push_back(w.area);
        wi.pointerHotAreas.push_back(w.area);
        wi.agentWindowId = -1;
        wi.flags = 0;
        wi.action = WINDOW_UPDATE_ACTION::ADD;
        wi.displayId = displayId;
        wi.groupId = groupId;
        wi.zOrder = w.zOrder;
        wgi.windowsInfo.push_back(wi);
    }
    int32_t ret = InputManager::GetInstance()->UpdateWindowInfo(wgi);
    std::cout << "  UpdateWindowInfo group=" << groupId << " display=" << displayId
              << " windows=" << windows.size() << " ret=" << ret << std::endl;
}

/* ====================================================================== */
/* Helper: 注入单个窗口（增量 ADD/CHANGE/DEL）                              */
/* ====================================================================== */
static void InjectSingleWindow(int32_t winId, int32_t groupId, int32_t displayId,
    Rect area, float zOrder, WINDOW_UPDATE_ACTION action, int32_t focusWinId = -1)
{
    WindowGroupInfo wgi;
    wgi.focusWindowId = focusWinId;
    wgi.displayId = displayId;
    WindowInfo wi = {};
    wi.id = winId;
    wi.pid = getpid();
    wi.uid = getuid();
    wi.area = area;
    wi.defaultHotAreas = { area };
    wi.pointerHotAreas = { area };
    wi.agentWindowId = -1;
    wi.flags = 0;
    wi.action = action;
    wi.displayId = displayId;
    wi.groupId = groupId;
    wi.zOrder = zOrder;
    wgi.windowsInfo.push_back(wi);
    int32_t ret = InputManager::GetInstance()->UpdateWindowInfo(wgi);
    std::cout << "  InjectSingleWindow id=" << winId << " action=" << static_cast<int>(action)
              << " z=" << zOrder << " ret=" << ret << std::endl;
}

/* ====================================================================== */
/* Helper: 注入单个窗口（自定义 hotArea，用于热区穿透测试）                  */
/* ====================================================================== */
static void InjectWindowWithHotArea(int32_t winId, int32_t groupId, int32_t displayId,
    Rect area, Rect hotArea, float zOrder, WINDOW_UPDATE_ACTION action, int32_t focusWinId = -1)
{
    WindowGroupInfo wgi;
    wgi.focusWindowId = focusWinId;
    wgi.displayId = displayId;
    WindowInfo wi = {};
    wi.id = winId;
    wi.pid = getpid();
    wi.uid = getuid();
    wi.area = area;
    wi.defaultHotAreas = { hotArea };
    wi.pointerHotAreas = { hotArea };
    wi.agentWindowId = -1;
    wi.flags = 0;
    wi.action = action;
    wi.displayId = displayId;
    wi.groupId = groupId;
    wi.zOrder = zOrder;
    wgi.windowsInfo.push_back(wi);
    int32_t ret = InputManager::GetInstance()->UpdateWindowInfo(wgi);
    std::cout << "  InjectWindowWithHotArea id=" << winId << " area=("
              << area.x << "," << area.y << "," << area.width << "," << area.height
              << ") hotArea=(" << hotArea.x << "," << hotArea.y << ","
              << hotArea.width << "," << hotArea.height << ") ret=" << ret << std::endl;
}

/* ====================================================================== */
/* Helper: 注入两个 group 的全部标准窗口（使用全局焦点变量）                 */
/* ====================================================================== */
static void InjectAllWindows()
{
    InjectWindows(0, 0, g_focusWin0, {
        {1000, {0, 80, 720, 1200}, 10.0f},
        {1001, {0, 0, 720, 80},    100.0f},
        {1002, {300, 400, 120, 120}, 200.0f},
    });
    InjectWindows(1, 1, g_focusWin1, {
        {2000, {0, 0, 1920, 1080}, 10.0f},
        {2001, {660, 340, 600, 400}, 200.0f},
    });
}

/* ====================================================================== */
/* Helper: hidumper -G 输出                                                */
/* ====================================================================== */
static void DumpG(const char *label)
{
    FILE *out = fopen("/data/local/tmp/dual_group_dump.txt", "a");
    if (out) { fprintf(out, "\n===== %s =====\n", label); }

    std::cout << "\n===== " << label << " =====" << std::endl;
    std::cout.flush();

    FILE *fp = popen("hidumper -s 3101 -a -G 2>&1", "r");
    if (fp) {
        char buf[512];
        while (fgets(buf, sizeof(buf), fp)) {
            std::cout << buf;
            if (out) { fputs(buf, out); }
        }
        pclose(fp);
    }
    if (out) { fclose(out); }
    std::cout.flush();
}

/* ====================================================================== */
/* Helper: 确保绑定有效（WMS 可能随时覆盖 DisplayInfo 导致绑定丢失）       */
/* ====================================================================== */
struct BindSpec { int devId; int displayId; };

static void EnsureBindings(const std::vector<BindSpec> &bindings)
{
    std::string msg;
    for (const auto &b : bindings) {
        InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(b.devId, b.displayId, msg);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

/* ====================================================================== */
/* Helper: 绑定后 warm-up 事件（触发 EnsureGroupState 和 cursorPosMap_）    */
/* ====================================================================== */
static void WarmUp(int fdA, int fdB)
{
    for (int i = 0; i < 3; ++i) {
        Inject(fdA, 1, 1);
        Inject(fdB, 1, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

/* ====================================================================== */
/* main: 步骤化测试                                                        */
/* ====================================================================== */
int main()
{
    system("rm -f /data/local/tmp/dual_group_dump.txt");
    std::cout << "============================================" << std::endl;
    std::cout << " 双显示组 + 双鼠标/双键盘 综合验收测试" << std::endl;
    std::cout << "============================================" << std::endl;

    // ================================================================
    // Step 1: 构造双显示组（含 ScreenInfo + screenArea）
    // ================================================================
    std::cout << "\n[Step 1] 构造双显示组 (group0: 720x1280, group1: 1920x1080)" << std::endl;
    SetupDualDisplayGroups(1000, 2000);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    DumpG("Step1: 构造双显示组后");

    // ================================================================
    // Step 2: 创建双鼠标
    // ================================================================
    std::cout << "\n[Step 2] 创建双虚拟 USB 鼠标" << std::endl;
    int fdA = CreateMouse("GroupTestMouseA", 0xAA01);
    int fdB = CreateMouse("GroupTestMouseB", 0xAA02);
    std::cout << "  Mouse A fd=" << fdA << ", Mouse B fd=" << fdB << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // ================================================================
    // Step 3: 绑定前交互移动
    // ================================================================
    std::cout << "\n[Step 3] 绑定前：A(+10,+5) B(-3,-2) 交替移动 x10" << std::endl;
    for (int i = 0; i < 10; i++) {
        Inject(fdA, 10, 5);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        Inject(fdB, -3, -2);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    DumpG("Step3: 绑定前交互移动后 — 两鼠标应互相影响同一组光标");

    // ================================================================
    // Step 4: 查找设备并绑定鼠标 + warm-up
    // ================================================================
    std::cout << "\n[Step 4] 查找设备并绑定鼠标" << std::endl;
    int devA = FindDevice("GroupTestMouseA");
    int devB = FindDevice("GroupTestMouseB");
    std::cout << "  devA=" << devA << ", devB=" << devB << std::endl;

    if (devA < 0 || devB < 0) {
        std::cout << "  FAIL: 鼠标设备发现失败，跳过后续步骤" << std::endl;
        DumpG("FAIL: 设备发现失败");
        if (fdA >= 0) { ioctl(fdA, UI_DEV_DESTROY); close(fdA); }
        if (fdB >= 0) { ioctl(fdB, UI_DEV_DESTROY); close(fdB); }
        return 1;
    }

    std::string msg;
    int32_t retA = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devA, 0, msg);
    std::cout << "  Bind MouseA→display0: ret=" << retA << " msg=" << msg << std::endl;
    int32_t retB = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devB, 1, msg);
    std::cout << "  Bind MouseB→display1: ret=" << retB << " msg=" << msg << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    WarmUp(fdA, fdB);
    DumpG("Step4: 鼠标绑定 + warm-up 后 — RuntimeBindings 应有 2 条");

    // ================================================================
    // Step 5: 绑定后交互移动（鼠标移动隔离）
    // ================================================================
    std::cout << "\n[Step 5] 绑定后：A(+20,+10) B(-15,-8) 交替移动 x10" << std::endl;
    EnsureBindings({{devA, 0}, {devB, 1}});
    for (int i = 0; i < 10; i++) {
        Inject(fdA, 20, 10);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        Inject(fdB, -15, -8);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step5: 绑定后交互移动 — group0 和 group1 光标位置应独立变化");

    // ================================================================
    // Step 5.5: 光标边界钳制 — 验证各组光标不超出 display 边界
    // group0: 720×1280, group1: 1920×1080
    // ================================================================
    std::cout << "\n[Step 5.5] 光标边界钳制测试" << std::endl;
    EnsureBindings({{devA, 0}, {devB, 1}});

    // MouseA: 大幅右移（远超 720），光标 X 应钳制在 [0, 720) 内
    std::cout << "  MouseA: 极大右移 (+5000,0) — 应钳制在 720 内" << std::endl;
    for (int i = 0; i < 50; ++i) {
        Inject(fdA, 100, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step5.5a: MouseA 极大右移 — group0 X 应≤719");

    // MouseA: 大幅下移（远超 1280）
    std::cout << "  MouseA: 极大下移 (0,+5000) — 应钳制在 1280 内" << std::endl;
    for (int i = 0; i < 50; ++i) {
        Inject(fdA, 0, 100);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step5.5b: MouseA 极大下移 — group0 Y 应≤1279");

    // MouseB: 大幅右移（远超 1920），然后大幅下移（远超 1080）
    std::cout << "  MouseB: 极大右移 (+5000,0) 然后极大下移 (0,+5000)" << std::endl;
    for (int i = 0; i < 50; ++i) {
        Inject(fdB, 100, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    for (int i = 0; i < 50; ++i) {
        Inject(fdB, 0, 100);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step5.5c: MouseB 极大右下移 — group1 X≤1919, Y≤1079");

    // MouseA: 大幅左上移（负向），光标应钳制在 (0,0) 或附近
    std::cout << "  MouseA: 极大左上移 (-5000,-5000) — 应钳制在 (0,0)" << std::endl;
    for (int i = 0; i < 50; ++i) {
        Inject(fdA, -100, -100);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step5.5d: MouseA 极大左上移 — group0 位置应≈(0,0)");

    // ================================================================
    // Step 6: 注入窗口（为后续测试提供目标窗口）
    // ================================================================
    std::cout << "\n[Step 6] 注入多窗口 + 设置焦点" << std::endl;
    EnsureBindings({{devA, 0}, {devB, 1}});
    InjectAllWindows();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    DumpG("Step6: 窗口注入后 — 各 group 应有多窗口");

    // ================================================================
    // Step 6.5: PointerStyle per-window 光标外观
    // ================================================================
    std::cout << "\n[Step 6.5] PointerStyle per-window 光标外观" << std::endl;
    {
        PointerStyle style0;
        style0.id = 13;     // CROSS
        style0.size = 3;
        style0.color = 0xFF0000;
        int32_t ret0 = InputManager::GetInstance()->SetPointerStyle(1000, style0);
        std::cout << "  SetPointerStyle(win1000, CROSS/red) ret=" << ret0 << std::endl;

        PointerStyle style1;
        style1.id = 19;     // HAND_POINTING
        style1.size = 5;
        style1.color = 0x0000FF;
        int32_t ret1 = InputManager::GetInstance()->SetPointerStyle(2000, style1);
        std::cout << "  SetPointerStyle(win2000, HAND/blue) ret=" << ret1 << std::endl;

        PointerStyle readBack;
        InputManager::GetInstance()->GetPointerStyle(1000, readBack);
        std::cout << "  GetPointerStyle(win1000): id=" << readBack.id
                  << " size=" << readBack.size << " color=0x" << std::hex << readBack.color
                  << std::dec << std::endl;
        InputManager::GetInstance()->GetPointerStyle(2000, readBack);
        std::cout << "  GetPointerStyle(win2000): id=" << readBack.id
                  << " size=" << readBack.size << " color=0x" << std::hex << readBack.color
                  << std::dec << std::endl;
    }
    DumpG("Step6.5: PointerStyle — win1000=CROSS/red, win2000=HAND/blue");

    // ================================================================
    // Step 7: 鼠标按钮事件隔离 (G-4)
    // ================================================================
    std::cout << "\n[Step 7] 鼠标按钮事件隔离 (BTN_LEFT)" << std::endl;
    EnsureBindings({{devA, 0}, {devB, 1}});

    SetCursorPos(360, 640, 0);
    std::cout << "  MouseA: BTN_LEFT press..." << std::endl;
    InjectButton(fdA, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step7a: MouseA BTN_LEFT pressed — SequenceSnapshots BUTTON beginGroup=0 beginWindow=1000");
    InjectButton(fdA, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    SetCursorPos(500, 500, 1);
    std::cout << "  MouseB: BTN_LEFT press..." << std::endl;
    InjectButton(fdB, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step7b: MouseB BTN_LEFT pressed — SequenceSnapshots BUTTON beginGroup=1 beginWindow=2000");
    InjectButton(fdB, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // BTN_RIGHT 隔离
    std::cout << "  MouseA: BTN_RIGHT press..." << std::endl;
    InjectButton(fdA, BTN_RIGHT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step7c: MouseA BTN_RIGHT pressed — beginGroup=0");
    InjectButton(fdA, BTN_RIGHT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // ================================================================
    // Step 7.5: 跨组同时按钮保持
    // MouseA 和 MouseB 同时按住 BTN_LEFT，验证两组独立追踪
    // ================================================================
    std::cout << "\n[Step 7.5] 跨组同时按钮保持" << std::endl;
    EnsureBindings({{devA, 0}, {devB, 1}});

    std::cout << "  MouseA: BTN_LEFT press (hold)..." << std::endl;
    InjectButton(fdA, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::cout << "  MouseB: BTN_LEFT press (hold) — 两组同时按住..." << std::endl;
    InjectButton(fdB, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step7.5a: 双鼠标同时 BTN_LEFT held — 两组各有独立 BUTTON snapshot");

    // 释放 MouseA，MouseB 仍保持
    std::cout << "  MouseA: BTN_LEFT release, MouseB: still held..." << std::endl;
    InjectButton(fdA, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step7.5b: MouseA released, MouseB still held — group1 仍有 BUTTON snapshot");

    // 释放 MouseB
    InjectButton(fdB, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // BTN_MIDDLE 交叉测试: A 按中键，B 按右键
    std::cout << "  MouseA: BTN_MIDDLE press, MouseB: BTN_RIGHT press..." << std::endl;
    InjectButton(fdA, BTN_MIDDLE, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    InjectButton(fdB, BTN_RIGHT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step7.5c: A=BTN_MIDDLE held, B=BTN_RIGHT held — 不同按钮跨组独立");
    InjectButton(fdA, BTN_MIDDLE, 0);
    InjectButton(fdB, BTN_RIGHT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // ================================================================
    // Step 8: 滚轮事件隔离 (G-5)
    // ================================================================
    std::cout << "\n[Step 8] 滚轮事件隔离 (REL_WHEEL)" << std::endl;
    EnsureBindings({{devA, 0}, {devB, 1}});
    std::cout << "  MouseA: scroll +3 (up)" << std::endl;
    InjectScroll(fdA, 3);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::cout << "  MouseB: scroll -3 (down)" << std::endl;
    InjectScroll(fdB, -3);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    DumpG("Step8: 滚轮注入后 — PointerStateByGroup 应各组独立");

    // ================================================================
    // Step 8.5: captureMode 隔离
    // ================================================================
    std::cout << "\n[Step 8.5] captureMode 隔离" << std::endl;
    EnsureBindings({{devA, 0}, {devB, 1}});
    {
        int32_t retEnter = InputManager::GetInstance()->EnterCaptureMode(1000);
        std::cout << "  EnterCaptureMode(win1000) ret=" << retEnter << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step8.5a: captureMode — group0=true, group1=false");

        int32_t retLeave = InputManager::GetInstance()->LeaveCaptureMode(1000);
        std::cout << "  LeaveCaptureMode(win1000) ret=" << retLeave << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step8.5b: captureMode — group0=false (恢复)");
    }

    // ================================================================
    // Step 9: z-order 命中测试 (G-2) — 精确光标定位
    // ================================================================
    std::cout << "\n[Step 9] z-order 命中测试（精确定位）" << std::endl;
    EnsureBindings({{devA, 0}, {devB, 1}});

    InjectAllWindows();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 9a: 悬浮窗区域 (360,460) → win1002 (zOrder=200)
    std::cout << "  9a: 移到悬浮窗 (360,460) → 期望 win1002" << std::endl;
    SetCursorPos(360, 460, 0);
    InjectButton(fdA, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step9a: 悬浮窗命中 — Cursor Info.windowId=1002");
    InjectButton(fdA, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // 9b: 状态栏区域 (360,40) → win1001 (zOrder=100)
    std::cout << "  9b: 移到状态栏 (360,40) → 期望 win1001" << std::endl;
    SetCursorPos(360, 40, 0);
    InjectButton(fdA, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step9b: 状态栏命中 — Cursor Info.windowId=1001");
    InjectButton(fdA, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // 9c: 普通内容区域 (360,640) → win1000 (zOrder=10)
    std::cout << "  9c: 移到普通区域 (360,640) → 期望 win1000" << std::endl;
    SetCursorPos(360, 640, 0);
    InjectButton(fdA, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step9c: 普通区域命中 — Cursor Info.windowId=1000");
    InjectButton(fdA, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // 9d: Group1 弹窗区域 (800,500) → win2001
    std::cout << "  9d: Group1 移到弹窗 (800,500) → 期望 win2001" << std::endl;
    SetCursorPos(800, 500, 1);
    InjectButton(fdB, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step9d: Group1弹窗命中 — Cursor Info.windowId=2001");
    InjectButton(fdB, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // ================================================================
    // Step 9.5: 全屏 z-order 位置无关验证
    // ADD 多个全屏窗口（不同 zOrder），不依赖光标位置
    // ================================================================
    std::cout << "\n[Step 9.5] 全屏 z-order 位置无关验证" << std::endl;
    EnsureBindings({{devA, 0}, {devB, 1}});

    // 在 group0 追加两个全屏窗口，zOrder 高于 win1002(200)
    InjectSingleWindow(1005, 0, 0, {0, 0, 720, 1280}, 300.0f,
        WINDOW_UPDATE_ACTION::ADD, g_focusWin0);
    InjectSingleWindow(1006, 0, 0, {0, 0, 720, 1280}, 400.0f,
        WINDOW_UPDATE_ACTION::ADD, g_focusWin0);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 点击 → 应命中 win1006 (z=400, 最高全屏)
    InjectButton(fdA, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step9.5a: 全屏z-order — Cursor Info.windowId=1006 (z=400最高)");
    InjectButton(fdA, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // DEL win1006 → 应回退到 win1005 (z=300)
    InjectSingleWindow(1006, 0, 0, {0, 0, 0, 0}, 0.0f,
        WINDOW_UPDATE_ACTION::DEL, g_focusWin0);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    InjectButton(fdA, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step9.5b: DEL win1006 后 — Cursor Info.windowId=1005 (z=300)");
    InjectButton(fdA, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // 清理：DEL win1005
    InjectSingleWindow(1005, 0, 0, {0, 0, 0, 0}, 0.0f,
        WINDOW_UPDATE_ACTION::DEL, g_focusWin0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // ================================================================
    // Step 9.6: 热区穿透 (pointerHotAreas != area)
    // ================================================================
    std::cout << "\n[Step 9.6] 热区穿透测试" << std::endl;
    EnsureBindings({{devA, 0}, {devB, 1}});

    // ADD win1004: area 大 (100,200,400,400) 但 hotArea 小 (200,300,200,200)
    InjectWindowWithHotArea(1004, 0, 0,
        {100, 200, 400, 400},     // area
        {200, 300, 200, 200},     // hotArea (小于 area)
        250.0f, WINDOW_UPDATE_ACTION::ADD, g_focusWin0);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 点击 hotArea 内 (300,400) → 应命中 win1004 (z=250)
    SetCursorPos(300, 400, 0);
    InjectButton(fdA, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step9.6a: hotArea 内 (300,400) — Cursor Info.windowId=1004");
    InjectButton(fdA, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // 点击 area 内但 hotArea 外 (150,250) → 穿透到 win1000 (z=10)
    SetCursorPos(150, 250, 0);
    InjectButton(fdA, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step9.6b: area 内 hotArea 外 (150,250) — 穿透到 win1000");
    InjectButton(fdA, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // 清理 win1004
    InjectSingleWindow(1004, 0, 0, {0, 0, 0, 0}, 0.0f,
        WINDOW_UPDATE_ACTION::DEL, g_focusWin0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // ================================================================
    // Step 9.7: 窗口生命周期 ADD → CHANGE → DEL
    // ================================================================
    std::cout << "\n[Step 9.7] 窗口生命周期 ADD → CHANGE → DEL" << std::endl;
    EnsureBindings({{devA, 0}, {devB, 1}});

    // ADD 弹窗 win1003 at (200,200,320,320) z=300
    InjectSingleWindow(1003, 0, 0, {200, 200, 320, 320}, 300.0f,
        WINDOW_UPDATE_ACTION::ADD, g_focusWin0);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    SetCursorPos(360, 360, 0);
    InjectButton(fdA, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step9.7a: ADD win1003 — 点击 (360,360) 应命中 win1003");
    InjectButton(fdA, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // CHANGE: 移动 win1003 到 (400,800,320,320)
    InjectSingleWindow(1003, 0, 0, {400, 800, 320, 320}, 300.0f,
        WINDOW_UPDATE_ACTION::CHANGE, g_focusWin0);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // 点击原位置 (360,360) → 穿透到 win1002(z=200) 或 win1000(z=10)
    SetCursorPos(360, 360, 0);
    InjectButton(fdA, BTN_LEFT, 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step9.7b: CHANGE win1003 位置后 — 原位置 (360,360) 穿透");
    InjectButton(fdA, BTN_LEFT, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // DEL win1003
    InjectSingleWindow(1003, 0, 0, {0, 0, 0, 0}, 0.0f,
        WINDOW_UPDATE_ACTION::DEL, g_focusWin0);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    DumpG("Step9.7c: DEL win1003 — 窗口列表恢复");

    // ================================================================
    // Step 10: 创建键盘 + 绑定 (G-1 准备)
    // ================================================================
    std::cout << "\n[Step 10] 创建双虚拟键盘 + 绑定" << std::endl;
    int fdKbdA = CreateKeyboard("GroupTestKbdA", 0xBB01);
    int fdKbdB = CreateKeyboard("GroupTestKbdB", 0xBB02);
    std::cout << "  KbdA fd=" << fdKbdA << ", KbdB fd=" << fdKbdB << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));

    int devKbdA = FindDevice("GroupTestKbdA");
    int devKbdB = FindDevice("GroupTestKbdB");
    std::cout << "  devKbdA=" << devKbdA << ", devKbdB=" << devKbdB << std::endl;

    if (devKbdA < 0 || devKbdB < 0) {
        std::cout << "  WARN: 键盘设备发现失败，跳过键盘相关步骤" << std::endl;
        DumpG("WARN: 键盘设备发现失败");
    } else {
        EnsureBindings({{devA, 0}, {devB, 1}, {devKbdA, 0}, {devKbdB, 1}});
        DumpG("Step10: 键盘绑定后 — RuntimeBindings 应有 4 条 (2鼠标+2键盘)");

        // ================================================================
        // Step 11: 键盘事件端到端 (G-1)
        // ================================================================
        std::cout << "\n[Step 11] 键盘事件端到端路由" << std::endl;
        EnsureBindings({{devA, 0}, {devB, 1}, {devKbdA, 0}, {devKbdB, 1}});

        // 恢复焦点到初始状态
        SetupDualDisplayGroups(1000, 2000);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        EnsureBindings({{devA, 0}, {devB, 1}, {devKbdA, 0}, {devKbdB, 1}});
        InjectAllWindows();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        std::cout << "  KbdA: KEY_A press..." << std::endl;
        InjectKeyEvent(fdKbdA, KEY_A, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step11a: KbdA KEY_A pressed — KEY beginGroup=0 beginWindow=1000");
        InjectKeyEvent(fdKbdA, KEY_A, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        std::cout << "  KbdB: KEY_B press..." << std::endl;
        InjectKeyEvent(fdKbdB, KEY_B, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step11b: KbdB KEY_B pressed — KEY beginGroup=1 beginWindow=2000");
        InjectKeyEvent(fdKbdB, KEY_B, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // ================================================================
        // Step 11.5: 修饰键状态隔离
        // KbdA 按住 Shift → KbdB 按 KEY_A → KbdB 的事件不应带 Shift 修饰
        // ================================================================
        std::cout << "\n[Step 11.5] 修饰键状态隔离" << std::endl;
        EnsureBindings({{devA, 0}, {devB, 1}, {devKbdA, 0}, {devKbdB, 1}});

        // KbdA: 按住 LEFT_SHIFT（group0 的修饰键状态变化）
        std::cout << "  KbdA: KEY_LEFTSHIFT press (hold)..." << std::endl;
        InjectKeyEvent(fdKbdA, KEY_LEFTSHIFT, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // KbdA: Shift held 状态下按 KEY_A（group0 应带 Shift 修饰）
        std::cout << "  KbdA: KEY_A press (with Shift held in group0)..." << std::endl;
        InjectKeyEvent(fdKbdA, KEY_A, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step11.5a: KbdA KEY_A with Shift — beginGroup=0, 应带 Shift 修饰");
        InjectKeyEvent(fdKbdA, KEY_A, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // KbdB: 按 KEY_A（group1 不应受 KbdA 的 Shift 影响）
        std::cout << "  KbdB: KEY_A press (Shift only on KbdA/group0)..." << std::endl;
        InjectKeyEvent(fdKbdB, KEY_A, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step11.5b: KbdB KEY_A (no Shift) — beginGroup=1, 不应带 Shift 修饰");
        InjectKeyEvent(fdKbdB, KEY_A, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // 释放 KbdA 的 Shift
        InjectKeyEvent(fdKbdA, KEY_LEFTSHIFT, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Ctrl 修饰键隔离测试
        std::cout << "  KbdB: KEY_LEFTCTRL press (hold on group1)..." << std::endl;
        InjectKeyEvent(fdKbdB, KEY_LEFTCTRL, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        std::cout << "  KbdA: KEY_C press (Ctrl only on KbdB/group1)..." << std::endl;
        InjectKeyEvent(fdKbdA, KEY_C, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step11.5c: KbdA KEY_C (no Ctrl) — beginGroup=0, 不应带 Ctrl 修饰");
        InjectKeyEvent(fdKbdA, KEY_C, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        std::cout << "  KbdB: KEY_C press (with Ctrl held on group1)..." << std::endl;
        InjectKeyEvent(fdKbdB, KEY_C, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step11.5d: KbdB KEY_C with Ctrl — beginGroup=1, 应带 Ctrl 修饰");
        InjectKeyEvent(fdKbdB, KEY_C, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        InjectKeyEvent(fdKbdB, KEY_LEFTCTRL, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // ================================================================
        // Step 12: 动态焦点切换 (G-3)
        // 12a: group0 焦点 1000 → 1001
        // 12b: group1 焦点 2000 → 2001（非主组，必须通过 UpdateDisplayInfo）
        // ================================================================
        std::cout << "\n[Step 12] 动态焦点切换" << std::endl;

        // 12a: group0 焦点切到 win1001
        std::cout << "  12a: group0 焦点 1000→1001" << std::endl;
        SetupDualDisplayGroups(1001, 2000);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        EnsureBindings({{devA, 0}, {devB, 1}, {devKbdA, 0}, {devKbdB, 1}});
        InjectAllWindows();
        std::this_thread::sleep_for(std::chrono::seconds(1));

        std::cout << "  KbdA: KEY_C press (焦点已切到 win1001)..." << std::endl;
        InjectKeyEvent(fdKbdA, KEY_C, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step12a: KbdA KEY_C — KEY beginGroup=0 beginWindow=1001");
        InjectKeyEvent(fdKbdA, KEY_C, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // 12b: group1 焦点切到 win2001（非主组必须通过 UpdateDisplayInfo）
        std::cout << "  12b: group1 焦点 2000→2001 (非主组)" << std::endl;
        SetupDualDisplayGroups(1001, 2001);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        EnsureBindings({{devA, 0}, {devB, 1}, {devKbdA, 0}, {devKbdB, 1}});
        InjectAllWindows();
        std::this_thread::sleep_for(std::chrono::seconds(1));

        std::cout << "  KbdB: KEY_F press (group1 焦点已切到 win2001)..." << std::endl;
        InjectKeyEvent(fdKbdB, KEY_F, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step12b: KbdB KEY_F — KEY beginGroup=1 beginWindow=2001");
        InjectKeyEvent(fdKbdB, KEY_F, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // 恢复焦点
        SetupDualDisplayGroups(1000, 2000);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        EnsureBindings({{devA, 0}, {devB, 1}, {devKbdA, 0}, {devKbdB, 1}});
        InjectAllWindows();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // ================================================================
        // Step 12.5: 设备重绑定 — 将 MouseA 从 group0 移到 group1
        // ================================================================
        std::cout << "\n[Step 12.5] 设备重绑定（MouseA: group0→group1→group0）" << std::endl;
        EnsureBindings({{devA, 0}, {devB, 1}, {devKbdA, 0}, {devKbdB, 1}});

        // 重绑定 MouseA 到 display1 (group1)
        std::cout << "  Rebind MouseA → display1 (group1)..." << std::endl;
        int32_t rebindRet = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devA, 1, msg);
        std::cout << "  Rebind ret=" << rebindRet << " msg=" << msg << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        DumpG("Step12.5a: MouseA 重绑定到 group1 — RuntimeBindings 应反映变化");

        // MouseA 现在在 group1，移动应影响 group1 的光标
        std::cout << "  MouseA 移动 (+30,+20) — 应影响 group1 光标" << std::endl;
        for (int i = 0; i < 5; ++i) {
            Inject(fdA, 30, 20);
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // MouseA 按钮也应路由到 group1
        std::cout << "  MouseA: BTN_LEFT press (now in group1)..." << std::endl;
        SetCursorPos(960, 540, 1);
        InjectButton(fdA, BTN_LEFT, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step12.5b: MouseA BTN_LEFT in group1 — beginGroup 应=1");
        InjectButton(fdA, BTN_LEFT, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // 恢复 MouseA 到 group0
        std::cout << "  Rebind MouseA back → display0 (group0)..." << std::endl;
        rebindRet = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devA, 0, msg);
        std::cout << "  Rebind back ret=" << rebindRet << " msg=" << msg << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        WarmUp(fdA, fdB);
        DumpG("Step12.5c: MouseA 恢复到 group0 — RuntimeBindings 恢复原状");

        // ================================================================
        // Step 13: 并发压力测试 (G-8)
        // ================================================================
        std::cout << "\n[Step 13] 并发压力测试 (4 设备交替注入 x50)" << std::endl;
        EnsureBindings({{devA, 0}, {devB, 1}, {devKbdA, 0}, {devKbdB, 1}});
        for (int i = 0; i < 50; ++i) {
            Inject(fdA, 5, 3);
            InjectKeyEvent(fdKbdA, KEY_D, 1);
            Inject(fdB, -3, -5);
            InjectKeyEvent(fdKbdB, KEY_E, 1);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            InjectKeyEvent(fdKbdA, KEY_D, 0);
            InjectKeyEvent(fdKbdB, KEY_E, 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        int32_t speed = -1;
        int32_t speedRet = InputManager::GetInstance()->GetPointerSpeed(speed);
        std::cout << "  GetPointerSpeed ret=" << speedRet << " speed=" << speed
                  << (speedRet == 0 ? " — 服务存活" : " — 服务异常") << std::endl;
        DumpG("Step13: 并发压力后 — 服务应存活，RuntimeBindings 应完整");

        // ================================================================
        // Step 13.5: 显示组移除 + 状态清理
        // 移除 group1 → 验证 group1 绑定/光标被清理
        // 重建 group1 → 验证可以重新绑定
        // ================================================================
        std::cout << "\n[Step 13.5] 显示组移除 + 状态清理" << std::endl;

        // 13.5a: 移除 group1 — 只发送 group0 的 DisplayInfo
        std::cout << "  13.5a: 移除 group1（只保留 group0）" << std::endl;
        {
            DisplayGroupInfo g0only;
            g0only.id = 0;
            g0only.name = "default";
            g0only.type = GroupType::GROUP_DEFAULT;
            g0only.mainDisplayId = 0;
            g0only.focusWindowId = g_focusWin0;
            DisplayInfo d0;
            d0.id = 0; d0.x = 0; d0.y = 0;
            d0.width = 720; d0.height = 1280; d0.dpi = 240;
            d0.name = "main";
            d0.direction = DIRECTION0; d0.displayDirection = DIRECTION0;
            d0.screenArea.id = 0;
            d0.screenArea.area = { 0, 0, 720, 1280 };
            g0only.displaysInfo.push_back(d0);

            UserScreenInfo singleGroupInfo;
            singleGroupInfo.userId = 100;
            singleGroupInfo.displayGroups.push_back(g0only);

            ScreenInfo scr0;
            scr0.id = 0; scr0.uniqueId = "default0";
            scr0.width = 720; scr0.height = 1280;
            scr0.physicalWidth = 62; scr0.physicalHeight = 110;
            scr0.dpi = 240; scr0.ppi = 295;
            scr0.tpDirection = DIRECTION0;
            singleGroupInfo.screens.push_back(scr0);

            int32_t removeRet = InputManager::GetInstance()->UpdateDisplayInfo(singleGroupInfo);
            std::cout << "  UpdateDisplayInfo (group0 only) ret=" << removeRet << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
        DumpG("Step13.5a: group1 移除后 — group1 绑定/光标应被清理");

        // 13.5b: MouseB 事件应回落到默认组（或被忽略）
        std::cout << "  MouseB: 移动 (+10,+10) — group1 已移除" << std::endl;
        Inject(fdB, 10, 10);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step13.5b: group1 移除后 MouseB 事件行为");

        // 13.5c: 重建双显示组
        std::cout << "  13.5c: 重建双显示组" << std::endl;
        SetupDualDisplayGroups(1000, 2000);
        std::this_thread::sleep_for(std::chrono::seconds(1));
        InjectAllWindows();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // 重新绑定 MouseB 到 group1
        EnsureBindings({{devA, 0}, {devB, 1}, {devKbdA, 0}, {devKbdB, 1}});
        WarmUp(fdA, fdB);
        DumpG("Step13.5c: 双显示组重建并重绑后 — RuntimeBindings 应恢复完整");

        // 验证重建后 MouseB 仍正常路由到 group1
        std::cout << "  MouseB: BTN_LEFT press (验证重建后路由)..." << std::endl;
        SetCursorPos(500, 500, 1);
        InjectButton(fdB, BTN_LEFT, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        DumpG("Step13.5d: 重建后 MouseB BTN_LEFT — beginGroup 应=1");
        InjectButton(fdB, BTN_LEFT, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // ================================================================
        // Step 14: 全部解绑 + 清理
        // ================================================================
        std::cout << "\n[Step 14] 全部解绑" << std::endl;
        InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devA, msg);
        std::cout << "  Unbind MouseA: " << msg << std::endl;
        InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devB, msg);
        std::cout << "  Unbind MouseB: " << msg << std::endl;
        InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devKbdA, msg);
        std::cout << "  Unbind KbdA: " << msg << std::endl;
        InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devKbdB, msg);
        std::cout << "  Unbind KbdB: " << msg << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        DumpG("Step14: 全部解绑后 — RuntimeBindings 应为 empty");
    }

    // Cleanup: 恢复默认单组 DisplayGroupInfo，避免破坏真机触屏路由
    std::cout << "\n[Cleanup] 恢复默认单显示组" << std::endl;
    {
        DisplayGroupInfo g0;
        g0.id = 0;
        g0.name = "default";
        g0.type = GroupType::GROUP_DEFAULT;
        g0.mainDisplayId = 0;
        g0.focusWindowId = -1;
        DisplayInfo d0;
        d0.id = 0; d0.x = 0; d0.y = 0;
        d0.width = 720; d0.height = 1280; d0.dpi = 240;
        d0.name = "main";
        d0.direction = DIRECTION0; d0.displayDirection = DIRECTION0;
        d0.screenArea.id = 0;
        d0.screenArea.area = { 0, 0, 720, 1280 };
        g0.displaysInfo.push_back(d0);

        UserScreenInfo restoreInfo;
        restoreInfo.userId = 100;
        restoreInfo.displayGroups.push_back(g0);

        ScreenInfo scr0;
        scr0.id = 0; scr0.uniqueId = "default0";
        scr0.width = 720; scr0.height = 1280;
        scr0.physicalWidth = 62; scr0.physicalHeight = 110;
        scr0.dpi = 240; scr0.ppi = 295;
        scr0.tpDirection = DIRECTION0;
        restoreInfo.screens.push_back(scr0);

        int32_t ret = InputManager::GetInstance()->UpdateDisplayInfo(restoreInfo);
        std::cout << "  UpdateDisplayInfo (restore default) ret=" << ret << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Cleanup: 销毁 uinput 设备
    if (fdA >= 0)    { ioctl(fdA, UI_DEV_DESTROY); close(fdA); }
    if (fdB >= 0)    { ioctl(fdB, UI_DEV_DESTROY); close(fdB); }
    if (fdKbdA >= 0) { ioctl(fdKbdA, UI_DEV_DESTROY); close(fdKbdA); }
    if (fdKbdB >= 0) { ioctl(fdKbdB, UI_DEV_DESTROY); close(fdKbdB); }

    std::cout << "\n============================================" << std::endl;
    std::cout << " 全部完成 — 结果见 /data/local/tmp/dual_group_dump.txt" << std::endl;
    std::cout << "============================================" << std::endl;
    std::cout << "DONE" << std::endl;
    return 0;
}
