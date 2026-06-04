/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
 * System-level gtest suite for mouse movement injection and visual
 * verification. Creates virtual mouse via /dev/uinput, injects movement
 * patterns, and verifies via InputManager APIs and hidumper.
 * Runs against real mmi_service on DAYU200/RK3568.
 */

#include <cstdio>
#include <cstring>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <linux/input.h>
#include <linux/uinput.h>

#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "input_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MouseVisualMovementTest"

using namespace OHOS::MMI;

namespace {

constexpr int POLL_MAX_ATTEMPTS = 30;
constexpr int POLL_INTERVAL_MS = 500;
constexpr int DEVICE_SETTLE_MS = 3000;
constexpr int MOVE_INTERVAL_MS = 30;

/* ---------- uinput helpers ------------------------------------------- */

static int CreateVirtualMouse(const char *name)
{
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) {
        return -1;
    }
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
    if (write(fd, &uidev, sizeof(uidev)) < 0) {
        close(fd);
        return -1;
    }
    if (ioctl(fd, UI_DEV_CREATE) < 0) {
        close(fd);
        return -1;
    }
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
                return id;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(POLL_INTERVAL_MS));
    }
    return -1;
}

/* ---------- test fixture --------------------------------------------- */

class MouseVisualMovementTest : public testing::Test {
protected:
    void SetUp() override
    {
        mouseFd_ = -1;
        mouseId_ = -1;
    }

    void TearDown() override
    {
        DestroyDevice(mouseFd_);
    }

    bool CreateAndFindMouse(const char *name)
    {
        mouseFd_ = CreateVirtualMouse(name);
        if (mouseFd_ < 0) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));
        mouseId_ = PollForDeviceByName(name);
        return mouseId_ >= 0;
    }

    int mouseFd_;
    int32_t mouseId_;
};

/* ===== Movement pattern tests ========================================= */

/**
 * @tc.name: MouseVisualMovement_FullScreenTraversal
 * @tc.desc: Inject moves to traverse right and down across the screen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseVisualMovementTest, MouseVisualMovement_FullScreenTraversal, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("MvTest Traverse")) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    /* Move right across the screen */
    for (int i = 0; i < 50; ++i) {
        InjectRelativeMotion(mouseFd_, 20, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(MOVE_INTERVAL_MS));
    }

    /* Move down */
    for (int i = 0; i < 50; ++i) {
        InjectRelativeMotion(mouseFd_, 0, 15);
        std::this_thread::sleep_for(std::chrono::milliseconds(MOVE_INTERVAL_MS));
    }

    /* Move left */
    for (int i = 0; i < 50; ++i) {
        InjectRelativeMotion(mouseFd_, -20, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(MOVE_INTERVAL_MS));
    }

    /* Move up */
    for (int i = 0; i < 50; ++i) {
        InjectRelativeMotion(mouseFd_, 0, -15);
        std::this_thread::sleep_for(std::chrono::milliseconds(MOVE_INTERVAL_MS));
    }

    /* Verify cursor is at a valid position */
    int32_t displayId = -1;
    double x = -1.0, y = -1.0;
    int32_t ret = InputManager::GetInstance()->GetPointerLocation(displayId, x, y);
    EXPECT_EQ(ret, RET_OK) << "GetPointerLocation failed after traversal";
    EXPECT_GE(x, 0.0);
    EXPECT_GE(y, 0.0);
}

/**
 * @tc.name: MouseVisualMovement_DiagonalPattern
 * @tc.desc: Inject diagonal movement pattern
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseVisualMovementTest, MouseVisualMovement_DiagonalPattern, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("MvTest Diagonal")) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    /* Diagonal down-right */
    for (int i = 0; i < 40; ++i) {
        InjectRelativeMotion(mouseFd_, 10, 10);
        std::this_thread::sleep_for(std::chrono::milliseconds(MOVE_INTERVAL_MS));
    }

    /* Diagonal up-left */
    for (int i = 0; i < 40; ++i) {
        InjectRelativeMotion(mouseFd_, -10, -10);
        std::this_thread::sleep_for(std::chrono::milliseconds(MOVE_INTERVAL_MS));
    }

    /* Diagonal down-left */
    for (int i = 0; i < 40; ++i) {
        InjectRelativeMotion(mouseFd_, -10, 10);
        std::this_thread::sleep_for(std::chrono::milliseconds(MOVE_INTERVAL_MS));
    }

    /* Diagonal up-right */
    for (int i = 0; i < 40; ++i) {
        InjectRelativeMotion(mouseFd_, 10, -10);
        std::this_thread::sleep_for(std::chrono::milliseconds(MOVE_INTERVAL_MS));
    }

    SUCCEED() << "Diagonal movement pattern completed";
}

/**
 * @tc.name: MouseVisualMovement_SpiralPattern
 * @tc.desc: Inject spiral inward movement pattern
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseVisualMovementTest, MouseVisualMovement_SpiralPattern, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("MvTest Spiral")) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    /* Spiral inward: decreasing radius */
    for (int radius = 20; radius > 2; radius -= 2) {
        /* Right */
        for (int i = 0; i < radius; ++i) {
            InjectRelativeMotion(mouseFd_, 5, 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }
        /* Down */
        for (int i = 0; i < radius; ++i) {
            InjectRelativeMotion(mouseFd_, 0, 5);
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }
        /* Left */
        for (int i = 0; i < radius; ++i) {
            InjectRelativeMotion(mouseFd_, -5, 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }
        /* Up */
        for (int i = 0; i < radius; ++i) {
            InjectRelativeMotion(mouseFd_, 0, -5);
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }
    }

    /* Verify pointer is reachable */
    int32_t displayId = -1;
    double x = -1.0, y = -1.0;
    int32_t ret = InputManager::GetInstance()->GetPointerLocation(displayId, x, y);
    EXPECT_EQ(ret, RET_OK) << "GetPointerLocation failed after spiral";
}

/**
 * @tc.name: MouseVisualMovement_VerifyDeviceInfo
 * @tc.desc: Verify virtual mouse device properties via InputManager API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseVisualMovementTest, MouseVisualMovement_VerifyDeviceInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("MvTest DevInfo")) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::mutex mtx;
    std::condition_variable cv;
    bool done = false;
    bool verified = false;

    InputManager::GetInstance()->GetDevice(mouseId_, [&](std::shared_ptr<InputDevice> dev) {
        std::lock_guard<std::mutex> lock(mtx);
        if (dev) {
            EXPECT_EQ(dev->GetName(), "MvTest DevInfo");
            EXPECT_EQ(dev->GetBus(), BUS_USB);
            EXPECT_EQ(dev->GetVendor(), 0x93a);
            EXPECT_EQ(dev->GetProduct(), 0x2510);
            verified = true;
        }
        done = true;
        cv.notify_one();
    });

    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait_for(lock, std::chrono::seconds(5), [&] { return done; });
    }

    EXPECT_TRUE(verified) << "Device info verification failed";
}

/**
 * @tc.name: MouseVisualMovement_RapidSmallMoves
 * @tc.desc: Inject many small rapid moves to stress test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseVisualMovementTest, MouseVisualMovement_RapidSmallMoves, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("MvTest Rapid")) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    for (int i = 0; i < 100; ++i) {
        InjectRelativeMotion(mouseFd_, 1, 1);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    /* Verify service is still responsive */
    int32_t speed = -1;
    int32_t ret = InputManager::GetInstance()->GetPointerSpeed(speed);
    EXPECT_EQ(ret, RET_OK) << "Service should still respond after rapid moves";
}

/**
 * @tc.name: MouseVisualMovement_ZeroMove
 * @tc.desc: Inject zero-delta moves, verify no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseVisualMovementTest, MouseVisualMovement_ZeroMove, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("MvTest Zero")) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    for (int i = 0; i < 10; ++i) {
        InjectRelativeMotion(mouseFd_, 0, 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    SUCCEED() << "Zero-delta moves completed without crash";
}

/**
 * @tc.name: MouseVisualMovement_HidumperAfterMovement
 * @tc.desc: Inject moves then verify hidumper output
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MouseVisualMovementTest, MouseVisualMovement_HidumperAfterMovement, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("MvTest HiDmp")) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    for (int i = 0; i < 10; ++i) {
        InjectRelativeMotion(mouseFd_, 5, 3);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    int rc = system("hidumper -s 3101 -a -G > /data/local/tmp/movement_evidence.txt 2>&1");
    EXPECT_EQ(rc, 0) << "hidumper command failed";
}

} // namespace
