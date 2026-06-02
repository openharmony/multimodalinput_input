/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <iostream>
#include <linux/input.h>
#include <linux/uinput.h>
#include <mutex>
#include <thread>
#include <unistd.h>
#include <vector>

#include "input_manager.h"

using namespace OHOS::MMI;

static int CreateVirtualMouse(const char *name)
{
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) {
        std::cerr << "Cannot open /dev/uinput" << std::endl;
        return -1;
    }
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

    struct uinput_user_dev uidev = {};
    strncpy(uidev.name, name, UINPUT_MAX_NAME_SIZE - 1);
    uidev.id.bustype = BUS_USB;
    uidev.id.vendor = 0x93a;
    uidev.id.product = 0x2510;
    uidev.id.version = 1;
    write(fd, &uidev, sizeof(uidev));
    ioctl(fd, UI_DEV_CREATE);
    return fd;
}

static int FindDeviceByName(const std::string &targetName)
{
    std::mutex mtx;
    std::condition_variable cv;
    int foundId = -1;

    for (int attempt = 0; attempt < 20 && foundId < 0; ++attempt) {
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

int main()
{
    std::cout << "=== Multi-Group Binding Real Service Test ===" << std::endl;

    std::cout << "[1] Creating virtual mouse..." << std::endl;
    int mouseFd = CreateVirtualMouse("RealSvcTest Mouse");
    if (mouseFd < 0) return 1;
    std::this_thread::sleep_for(std::chrono::seconds(3));

    std::cout << "[2] Finding device..." << std::endl;
    int mouseId = FindDeviceByName("RealSvcTest Mouse");
    if (mouseId < 0) {
        std::cerr << "FAIL: device not found" << std::endl;
        ioctl(mouseFd, UI_DEV_DESTROY);
        close(mouseFd);
        return 1;
    }
    std::cout << "  Found mouseId=" << mouseId << std::endl;

    std::cout << "[3] Hidumper before bind..." << std::endl;
    system("hidumper -s 3101 -a -G > /data/local/tmp/real_svc_before.txt 2>&1");

    std::cout << "[4] Binding mouse to displayId=0..." << std::endl;
    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(mouseId, 0, msg);
    std::cout << "  ret=" << ret << " msg=" << msg << std::endl;

    std::cout << "[5] Hidumper after bind..." << std::endl;
    system("hidumper -s 3101 -a -G > /data/local/tmp/real_svc_after_bind.txt 2>&1");

    std::cout << "[6] Unbinding..." << std::endl;
    ret = InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(mouseId, msg);
    std::cout << "  ret=" << ret << std::endl;

    std::cout << "[7] Hidumper after unbind..." << std::endl;
    system("hidumper -s 3101 -a -G > /data/local/tmp/real_svc_after_unbind.txt 2>&1");

    std::cout << "[8] Cleanup..." << std::endl;
    ioctl(mouseFd, UI_DEV_DESTROY);
    close(mouseFd);

    std::cout << "=== DONE ===" << std::endl;
    return 0;
}
