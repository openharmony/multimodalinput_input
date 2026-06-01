/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Board-side integration test for HID display group binding.
 *
 * This standalone executable creates virtual USB HID devices via /dev/uinput,
 * waits for the multimodal input service to register them, then exercises the
 * BindDeviceToDisplayGroupByDisplay / UnbindDeviceFromDisplayGroup APIs while
 * capturing hidumper evidence at each step.
 *
 * Usage:  Push the binary to the board and run as root:
 *         hid_display_bind_board_test
 *
 * Evidence files are written to /data/local/tmp/.
 */

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>
#include <vector>
#include <condition_variable>

#include <linux/input.h>
#include <linux/uinput.h>

#include "input_manager.h"

using namespace OHOS::MMI;

/* ---------- helpers --------------------------------------------------- */

static const char *EVIDENCE_DIR = "/data/local/tmp";

static void PrintStep(int step, const char *msg)
{
    std::cout << "\n===== STEP " << step << ": " << msg << " =====" << std::endl;
}

static void PrintResult(const char *label, int32_t ret)
{
    if (ret == 0) {
        std::cout << "  [OK] " << label << " returned 0 (success)" << std::endl;
    } else {
        std::cout << "  [FAIL] " << label << " returned " << ret << std::endl;
    }
}

static void CaptureHidumper(const char *tag)
{
    std::string cmd = "hidumper -s 3101 -a -G > ";
    cmd += EVIDENCE_DIR;
    cmd += "/hid_bind_evidence_";
    cmd += tag;
    cmd += ".txt 2>&1";
    std::cout << "  Capturing hidumper: " << cmd << std::endl;
    int rc = system(cmd.c_str());
    if (rc != 0) {
        std::cout << "  Warning: hidumper command exited with code " << rc << std::endl;
    }
}

/* ---------- uinput device creation ------------------------------------ */

static int SetEvBit(int fd, unsigned int bit)
{
    return ioctl(fd, UI_SET_EVBIT, bit);
}

static int SetKeyBit(int fd, unsigned int bit)
{
    return ioctl(fd, UI_SET_KEYBIT, bit);
}

static int SetRelBit(int fd, unsigned int bit)
{
    return ioctl(fd, UI_SET_RELBIT, bit);
}

static int SetMscBit(int fd, unsigned int bit)
{
    return ioctl(fd, UI_SET_MSCBIT, bit);
}

static int SetLedBit(int fd, unsigned int bit)
{
    return ioctl(fd, UI_SET_LEDBIT, bit);
}

/*
 * CreateVirtualMouse -- mirrors tools/vuinput/src/virtual_mouse.cpp
 * BUS_USB, vendor 0x93a, product 0x2510
 */
static int CreateVirtualMouse()
{
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) {
        std::cerr << "Failed to open /dev/uinput: " << strerror(errno) << std::endl;
        return -1;
    }

    /* Event types: EV_KEY, EV_REL, EV_MSC */
    SetEvBit(fd, EV_KEY);
    SetEvBit(fd, EV_REL);
    SetEvBit(fd, EV_MSC);

    /* Mouse buttons */
    SetKeyBit(fd, BTN_LEFT);
    SetKeyBit(fd, BTN_RIGHT);
    SetKeyBit(fd, BTN_MIDDLE);
    SetKeyBit(fd, BTN_SIDE);
    SetKeyBit(fd, BTN_EXTRA);
    SetKeyBit(fd, BTN_FORWARD);
    SetKeyBit(fd, BTN_BACK);
    SetKeyBit(fd, BTN_TASK);

    /* Relative axes */
    SetRelBit(fd, REL_X);
    SetRelBit(fd, REL_Y);
    SetRelBit(fd, REL_WHEEL);
#ifdef REL_WHEEL_HI_RES
    SetRelBit(fd, REL_WHEEL_HI_RES);
#endif

    /* Misc */
    SetMscBit(fd, MSC_SCAN);

    struct uinput_user_dev udev = {};
    strncpy(udev.name, "VTest Mouse A", sizeof(udev.name) - 1);
    udev.id.bustype = BUS_USB;
    udev.id.vendor  = 0x93a;
    udev.id.product = 0x2510;
    udev.id.version = 1;

    if (write(fd, &udev, sizeof(udev)) < 0) {
        std::cerr << "Failed to write uinput_user_dev for mouse: " << strerror(errno) << std::endl;
        close(fd);
        return -1;
    }
    if (ioctl(fd, UI_DEV_CREATE) < 0) {
        std::cerr << "UI_DEV_CREATE failed for mouse: " << strerror(errno) << std::endl;
        close(fd);
        return -1;
    }
    std::cout << "  Created virtual mouse fd=" << fd << std::endl;
    return fd;
}

/*
 * CreateVirtualKeyboard -- mirrors tools/vuinput/src/virtual_keyboard.cpp
 * BUS_USB, vendor 0x24ae, product 0x4035
 */
static int CreateVirtualKeyboard()
{
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) {
        std::cerr << "Failed to open /dev/uinput: " << strerror(errno) << std::endl;
        return -1;
    }

    /* Event types: EV_KEY, EV_MSC, EV_LED, EV_REP */
    SetEvBit(fd, EV_KEY);
    SetEvBit(fd, EV_MSC);
    SetEvBit(fd, EV_LED);
    SetEvBit(fd, EV_REP);

    /* All key codes used by virtual_keyboard.cpp */
    static const uint32_t keyCodes[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
        57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
        75, 76, 77, 78, 79, 80, 81, 82, 83, 85, 86, 87, 88, 89, 90, 91, 92, 93,
        94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
        110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124,
        125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 140,
        141, 142, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 157, 158, 159,
        160, 161, 162, 163, 164, 165, 166, 170, 173, 175, 176, 177, 178, 179, 180,
        182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 200, 201,
        202, 203, 204, 205, 211, 213, 214, 215, 218, 220, 221, 222, 223, 226, 227,
        231, 232, 233, 236, 237, 238, 239, 240, 242, 243, 245, 246, 247, 248, 464,
        522, 523
    };
    for (uint32_t code : keyCodes) {
        SetKeyBit(fd, code);
    }

    /* Misc */
    SetMscBit(fd, MSC_SCAN);

    /* LEDs */
    SetLedBit(fd, LED_NUML);
    SetLedBit(fd, LED_CAPSL);
    SetLedBit(fd, LED_SCROLLL);
    SetLedBit(fd, LED_COMPOSE);
    SetLedBit(fd, LED_KANA);

    struct uinput_user_dev udev = {};
    strncpy(udev.name, "VTest Keyboard B", sizeof(udev.name) - 1);
    udev.id.bustype = BUS_USB;
    udev.id.vendor  = 0x24ae;
    udev.id.product = 0x4035;
    udev.id.version = 1;

    if (write(fd, &udev, sizeof(udev)) < 0) {
        std::cerr << "Failed to write uinput_user_dev for keyboard: " << strerror(errno) << std::endl;
        close(fd);
        return -1;
    }
    if (ioctl(fd, UI_DEV_CREATE) < 0) {
        std::cerr << "UI_DEV_CREATE failed for keyboard: " << strerror(errno) << std::endl;
        close(fd);
        return -1;
    }
    std::cout << "  Created virtual keyboard fd=" << fd << std::endl;
    return fd;
}

static void DestroyDevice(int &fd)
{
    if (fd >= 0) {
        ioctl(fd, UI_DEV_DESTROY);
        close(fd);
        fd = -1;
    }
}

/* ---------- device discovery via InputManager ------------------------- */

static constexpr int POLL_MAX_ATTEMPTS = 30;
static constexpr int POLL_INTERVAL_US  = 500000;  /* 0.5 s */

/*
 * PollForDeviceByName - poll GetDeviceIds() and GetDevice() until a device
 * whose name matches |targetName| appears.  Returns the device ID or -1.
 */
static int32_t PollForDeviceByName(const std::string &targetName)
{
    for (int attempt = 0; attempt < POLL_MAX_ATTEMPTS; ++attempt) {
        std::mutex mtx;
        std::condition_variable cv;
        bool done = false;
        std::vector<int32_t> ids;

        InputManager::GetInstance()->GetDeviceIds([&](std::vector<int32_t> &devIds) {
            std::lock_guard<std::mutex> lock(mtx);
            ids = devIds;
            done = true;
            cv.notify_one();
        });

        /* Wait up to 2 s for the callback */
        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait_for(lock, std::chrono::seconds(2), [&] { return done; });
        }

        for (int32_t id : ids) {
            std::mutex mtx2;
            std::condition_variable cv2;
            bool done2 = false;
            std::string foundName;

            InputManager::GetInstance()->GetDevice(id, [&](std::shared_ptr<InputDevice> dev) {
                std::lock_guard<std::mutex> lock(mtx2);
                if (dev) {
                    foundName = dev->GetName();
                }
                done2 = true;
                cv2.notify_one();
            });

            {
                std::unique_lock<std::mutex> lock(mtx2);
                cv2.wait_for(lock, std::chrono::seconds(2), [&] { return done2; });
            }

            if (foundName == targetName) {
                std::cout << "  Found device \"" << targetName
                          << "\" with id=" << id << std::endl;
                return id;
            }
        }

        if (attempt < POLL_MAX_ATTEMPTS - 1) {
            std::cout << "  Polling attempt " << (attempt + 1)
                      << "/" << POLL_MAX_ATTEMPTS
                      << " - device \"" << targetName << "\" not yet visible" << std::endl;
            usleep(POLL_INTERVAL_US);
        }
    }
    return -1;
}

/* ---------- main ------------------------------------------------------ */

int main()
{
    int mouseFd  = -1;
    int kbFd     = -1;
    int failures = 0;

    std::cout << "========================================" << std::endl;
    std::cout << " HID Display Group Binding Board Test   " << std::endl;
    std::cout << "========================================" << std::endl;

    /* ---- Step 1: Create virtual HID devices ---- */
    PrintStep(1, "Create virtual USB HID devices via /dev/uinput");

    mouseFd = CreateVirtualMouse();
    if (mouseFd < 0) {
        std::cerr << "FATAL: Could not create virtual mouse. Aborting." << std::endl;
        return 1;
    }

    kbFd = CreateVirtualKeyboard();
    if (kbFd < 0) {
        std::cerr << "FATAL: Could not create virtual keyboard. Aborting." << std::endl;
        DestroyDevice(mouseFd);
        return 1;
    }

    std::cout << "  Sleeping 3 s for kernel/service to pick up new devices..." << std::endl;
    sleep(3);

    /* ---- Step 2: Wait for device registration ---- */
    PrintStep(2, "Poll InputManager for virtual devices");

    int32_t mouseDevId = PollForDeviceByName("VTest Mouse A");
    if (mouseDevId < 0) {
        std::cerr << "  FAIL: Virtual mouse never appeared in InputManager" << std::endl;
        ++failures;
    }

    int32_t kbDevId = PollForDeviceByName("VTest Keyboard B");
    if (kbDevId < 0) {
        std::cerr << "  FAIL: Virtual keyboard never appeared in InputManager" << std::endl;
        ++failures;
    }

    /* ---- Step 3: Confirm device info ---- */
    PrintStep(3, "Verify device info via GetDevice()");
    if (mouseDevId >= 0) {
        std::mutex mtx;
        std::condition_variable cv;
        bool done = false;

        InputManager::GetInstance()->GetDevice(mouseDevId, [&](std::shared_ptr<InputDevice> dev) {
            std::lock_guard<std::mutex> lock(mtx);
            if (dev) {
                std::cout << "  Mouse device id=" << dev->GetId()
                          << " name=\"" << dev->GetName() << "\""
                          << " bus=" << dev->GetBus()
                          << " vendor=0x" << std::hex << dev->GetVendor() << std::dec
                          << " product=0x" << std::hex << dev->GetProduct() << std::dec
                          << std::endl;
            } else {
                std::cerr << "  FAIL: GetDevice returned null for mouse id="
                          << mouseDevId << std::endl;
                ++failures;
            }
            done = true;
            cv.notify_one();
        });

        std::unique_lock<std::mutex> lock(mtx);
        cv.wait_for(lock, std::chrono::seconds(2), [&] { return done; });
    }
    if (kbDevId >= 0) {
        std::mutex mtx;
        std::condition_variable cv;
        bool done = false;

        InputManager::GetInstance()->GetDevice(kbDevId, [&](std::shared_ptr<InputDevice> dev) {
            std::lock_guard<std::mutex> lock(mtx);
            if (dev) {
                std::cout << "  Keyboard device id=" << dev->GetId()
                          << " name=\"" << dev->GetName() << "\""
                          << " bus=" << dev->GetBus()
                          << " vendor=0x" << std::hex << dev->GetVendor() << std::dec
                          << " product=0x" << std::hex << dev->GetProduct() << std::dec
                          << std::endl;
            } else {
                std::cerr << "  FAIL: GetDevice returned null for keyboard id="
                          << kbDevId << std::endl;
                ++failures;
            }
            done = true;
            cv.notify_one();
        });

        std::unique_lock<std::mutex> lock(mtx);
        cv.wait_for(lock, std::chrono::seconds(2), [&] { return done; });
    }

    /* ---- Step 4: Capture hidumper BEFORE bind ---- */
    PrintStep(4, "Capture hidumper state BEFORE bind");
    CaptureHidumper("before_bind");

    /* ---- Step 5: BindDeviceToDisplayGroupByDisplay ---- */
    PrintStep(5, "BindDeviceToDisplayGroupByDisplay (mouse -> displayId=0)");
    if (mouseDevId >= 0) {
        std::string msg;
        int32_t displayId = 0;
        int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
            mouseDevId, displayId, msg);
        PrintResult("BindDeviceToDisplayGroupByDisplay", ret);
        std::cout << "  Message: " << msg << std::endl;
        if (ret != 0) {
            ++failures;
        }
    } else {
        std::cout << "  Skipped: mouse device not found" << std::endl;
        ++failures;
    }

    sleep(1);

    /* ---- Step 6: Capture hidumper AFTER bind ---- */
    PrintStep(6, "Capture hidumper state AFTER bind");
    CaptureHidumper("after_bind");

    /* ---- Step 7: UnbindDeviceFromDisplayGroup ---- */
    PrintStep(7, "UnbindDeviceFromDisplayGroup (mouse)");
    if (mouseDevId >= 0) {
        std::string msg;
        int32_t ret = InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(
            mouseDevId, msg);
        PrintResult("UnbindDeviceFromDisplayGroup", ret);
        std::cout << "  Message: " << msg << std::endl;
        if (ret != 0) {
            ++failures;
        }
    } else {
        std::cout << "  Skipped: mouse device not found" << std::endl;
    }

    sleep(1);

    /* ---- Step 8: Capture hidumper AFTER unbind ---- */
    PrintStep(8, "Capture hidumper state AFTER unbind");
    CaptureHidumper("after_unbind");

    /* ---- Step 9: Cleanup ---- */
    PrintStep(9, "Cleanup: destroy virtual devices");
    DestroyDevice(mouseFd);
    DestroyDevice(kbFd);
    std::cout << "  Virtual devices destroyed." << std::endl;

    /* ---- Summary ---- */
    std::cout << "\n========================================" << std::endl;
    if (failures == 0) {
        std::cout << " RESULT: ALL STEPS PASSED" << std::endl;
    } else {
        std::cout << " RESULT: " << failures << " FAILURE(S)" << std::endl;
    }
    std::cout << " Evidence files in " << EVIDENCE_DIR << ":" << std::endl;
    std::cout << "   hid_bind_evidence_before_bind.txt" << std::endl;
    std::cout << "   hid_bind_evidence_after_bind.txt" << std::endl;
    std::cout << "   hid_bind_evidence_after_unbind.txt" << std::endl;
    std::cout << "========================================" << std::endl;

    return (failures == 0) ? 0 : 1;
}
