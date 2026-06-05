/*
 * dual_group_interleave_test.cpp
 *
 * 双显示组 + 双鼠标交互移动 + 绑定前后对比测试
 * 通过 UpdateDisplayInfo 构造双显示组，用 /dev/uinput 创建双鼠标，
 * 绑定前交互移动 → hidumper → 绑定 → 绑定后交互移动 → hidumper
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

static int CreateMouse(const char *name, uint16_t product)
{
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) { return -1; }
    ioctl(fd, UI_SET_EVBIT, EV_KEY);
    ioctl(fd, UI_SET_EVBIT, EV_REL);
    ioctl(fd, UI_SET_KEYBIT, BTN_LEFT);
    ioctl(fd, UI_SET_RELBIT, REL_X);
    ioctl(fd, UI_SET_RELBIT, REL_Y);
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

static void SetupDualDisplayGroups()
{
    // Group 0: default, 720x1280
    DisplayGroupInfo group0;
    group0.id = 0;
    group0.name = "default";
    group0.type = GroupType::GROUP_DEFAULT;
    group0.mainDisplayId = 0;
    group0.focusWindowId = -1;
    DisplayInfo disp0;
    disp0.id = 0; disp0.x = 0; disp0.y = 0;
    disp0.width = 720; disp0.height = 1280; disp0.dpi = 240;
    disp0.name = "main";
    disp0.direction = DIRECTION0; disp0.displayDirection = DIRECTION0;
    group0.displaysInfo.push_back(disp0);

    // Group 1: secondary, 1920x1080
    DisplayGroupInfo group1;
    group1.id = 1;
    group1.name = "secondary";
    group1.type = GroupType::GROUP_SPECIAL;
    group1.mainDisplayId = 1;
    group1.focusWindowId = -1;
    DisplayInfo disp1;
    disp1.id = 1; disp1.x = 0; disp1.y = 0;
    disp1.width = 1920; disp1.height = 1080; disp1.dpi = 160;
    disp1.name = "secondary";
    disp1.direction = DIRECTION0; disp1.displayDirection = DIRECTION0;
    group1.displaysInfo.push_back(disp1);

    UserScreenInfo screenInfo;
    screenInfo.userId = 100;
    screenInfo.displayGroups.push_back(group0);
    screenInfo.displayGroups.push_back(group1);

    int32_t ret = InputManager::GetInstance()->UpdateDisplayInfo(screenInfo);
    std::cout << "  UpdateDisplayInfo ret=" << ret << std::endl;
}

static void DumpG(const char *label)
{
    std::cout << "\n===== " << label << " =====" << std::endl;
    std::cout.flush();
    system("hidumper -s 3101 -a -G 2>/dev/null");
    std::cout.flush();
}

int main()
{
    std::cout << "============================================" << std::endl;
    std::cout << " 双显示组 + 双鼠标 绑定前后交互移动对比" << std::endl;
    std::cout << "============================================" << std::endl;

    // Step 1: 构造双显示组
    std::cout << "\n[Step 1] 构造双显示组 (group0: 720x1280, group1: 1920x1080)" << std::endl;
    SetupDualDisplayGroups();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    DumpG("构造双显示组后");

    // Step 2: 创建双鼠标
    std::cout << "\n[Step 2] 创建双虚拟 USB 鼠标" << std::endl;
    int fdA = CreateMouse("GroupTestMouseA", 0xAA01);
    int fdB = CreateMouse("GroupTestMouseB", 0xAA02);
    std::cout << "  Mouse A fd=" << fdA << ", Mouse B fd=" << fdB << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // Step 3: 绑定前交互移动
    std::cout << "\n[Step 3] 绑定前：A(+10,+5) B(-3,-2) 交替移动 x10" << std::endl;
    for (int i = 0; i < 10; i++) {
        Inject(fdA, 10, 5);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        Inject(fdB, -3, -2);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    DumpG("绑定前交互移动后 — 两鼠标应互相影响同一组光标");

    // Step 4: 查找设备并绑定
    std::cout << "\n[Step 4] 查找设备并绑定" << std::endl;
    int devA = FindDevice("GroupTestMouseA");
    int devB = FindDevice("GroupTestMouseB");
    std::cout << "  devA=" << devA << ", devB=" << devB << std::endl;

    if (devA >= 0 && devB >= 0) {
        std::string msg;
        int32_t retA = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devA, 0, msg);
        std::cout << "  Bind A→display0: ret=" << retA << " msg=" << msg << std::endl;
        int32_t retB = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devB, 1, msg);
        std::cout << "  Bind B→display1: ret=" << retB << " msg=" << msg << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        DumpG("绑定后 — RuntimeBindings 应有 2 条, DisplayGroups 应有 2 组");

        // Step 5: 绑定后交互移动
        std::cout << "\n[Step 5] 绑定后：A(+20,+10) B(-15,-8) 交替移动 x10" << std::endl;
        for (int i = 0; i < 10; i++) {
            Inject(fdA, 20, 10);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            Inject(fdB, -15, -8);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        DumpG("绑定后交互移动 — group0 和 group1 光标位置应独立变化");

        // Step 6: 解绑
        std::cout << "\n[Step 6] 解绑" << std::endl;
        InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devA, msg);
        InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devB, msg);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        DumpG("解绑后 — RuntimeBindings 应为 empty");
    } else {
        std::cout << "  SKIP: 设备发现失败" << std::endl;
        DumpG("设备发现失败时的 hidumper");
    }

    // Cleanup
    ioctl(fdA, UI_DEV_DESTROY); close(fdA);
    ioctl(fdB, UI_DEV_DESTROY); close(fdB);
    std::cout << "\nDONE" << std::endl;
    return 0;
}
