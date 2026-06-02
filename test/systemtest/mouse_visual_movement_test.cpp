/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/input.h>
#include <linux/uinput.h>
#include <thread>
#include <chrono>
#include <unistd.h>

#include "input_manager.h"

using namespace OHOS::MMI;

static int CreateVirtualMouse(const char *name)
{
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) return -1;
    ioctl(fd, UI_SET_EVBIT, EV_KEY);
    ioctl(fd, UI_SET_EVBIT, EV_REL);
    ioctl(fd, UI_SET_KEYBIT, BTN_LEFT);
    ioctl(fd, UI_SET_RELBIT, REL_X);
    ioctl(fd, UI_SET_RELBIT, REL_Y);
    struct uinput_user_dev uidev = {};
    strncpy(uidev.name, name, UINPUT_MAX_NAME_SIZE - 1);
    uidev.id.bustype = BUS_USB;
    uidev.id.vendor = 0x93a;
    uidev.id.product = 0x2510;
    write(fd, &uidev, sizeof(uidev));
    ioctl(fd, UI_DEV_CREATE);
    return fd;
}

static void InjectRelativeMotion(int fd, int dx, int dy)
{
    struct input_event ev = {};
    ev.type = EV_REL;
    ev.code = REL_X;
    ev.value = dx;
    write(fd, &ev, sizeof(ev));

    ev.code = REL_Y;
    ev.value = dy;
    write(fd, &ev, sizeof(ev));

    ev.type = EV_SYN;
    ev.code = SYN_REPORT;
    ev.value = 0;
    write(fd, &ev, sizeof(ev));
}

int main()
{
    std::cout << "=== Mouse Visual Movement Test ===" << std::endl;

    int fd = CreateVirtualMouse("VisualMove Mouse");
    if (fd < 0) {
        std::cerr << "FAIL: cannot create virtual mouse" << std::endl;
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::seconds(3));

    std::cout << "[1] Injecting 10 relative movements..." << std::endl;
    for (int i = 0; i < 10; i++) {
        InjectRelativeMotion(fd, 5, 3);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    std::cout << "  Done" << std::endl;

    std::cout << "[2] Hidumper after movement..." << std::endl;
    system("hidumper -s 3101 -a -G");

    std::cout << "[3] Cleanup..." << std::endl;
    ioctl(fd, UI_DEV_DESTROY);
    close(fd);

    std::cout << "=== DONE ===" << std::endl;
    return 0;
}
