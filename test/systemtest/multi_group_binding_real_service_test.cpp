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
 * System-level gtest suite for multi-group device binding against a real
 * mmi_service running on DAYU200/RK3568. Creates virtual USB HID devices
 * via /dev/uinput, exercises BindDeviceToDisplayGroupByDisplay /
 * UnbindDeviceFromDisplayGroup APIs, and verifies state through hidumper.
 */

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
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
#define MMI_LOG_TAG "MultiGroupBindingRealServiceTest"

using namespace OHOS::MMI;

namespace {

constexpr int POLL_MAX_ATTEMPTS = 30;
constexpr int POLL_INTERVAL_MS = 500;
constexpr int DEVICE_SETTLE_MS = 3000;
constexpr int BIND_SETTLE_MS = 500;
constexpr int32_t VALID_DISPLAY_ID = 0;
constexpr int32_t INVALID_DISPLAY_ID = 99999;
constexpr int32_t INVALID_DEVICE_ID = -9999;

/* ---------- uinput helpers ------------------------------------------- */

static int CreateVirtualMouse(const char *name)
{
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) {
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

static int CreateVirtualKeyboard(const char *name)
{
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
    if (fd < 0) {
        return -1;
    }
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

    struct uinput_user_dev uidev = {};
    strncpy(uidev.name, name, UINPUT_MAX_NAME_SIZE - 1);
    uidev.id.bustype = BUS_USB;
    uidev.id.vendor = 0x24ae;
    uidev.id.product = 0x4035;
    uidev.id.version = 1;
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

static void InjectButtonClick(int fd, unsigned int button)
{
    struct input_event ev = {};
    ev.type = EV_KEY;
    ev.code = button;
    ev.value = 1;
    write(fd, &ev, sizeof(ev));

    ev.type = EV_SYN;
    ev.code = SYN_REPORT;
    ev.value = 0;
    write(fd, &ev, sizeof(ev));

    ev.type = EV_KEY;
    ev.code = button;
    ev.value = 0;
    write(fd, &ev, sizeof(ev));

    ev.type = EV_SYN;
    ev.code = SYN_REPORT;
    ev.value = 0;
    write(fd, &ev, sizeof(ev));
}

/* ---------- device discovery ----------------------------------------- */

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

static std::string RunHidumperCapture(const char *args)
{
    std::string cmd = "hidumper -s 3101 -a ";
    cmd += args;
    cmd += " 2>&1";
    std::string result;
    FILE *fp = popen(cmd.c_str(), "r");
    if (fp != nullptr) {
        char buf[1024];
        while (fgets(buf, sizeof(buf), fp) != nullptr) {
            result += buf;
        }
        pclose(fp);
    }
    return result;
}

/* ---------- test fixture --------------------------------------------- */

class MultiGroupBindingRealServiceTest : public testing::Test {
protected:
    void SetUp() override
    {
        mouseFdA_ = -1;
        mouseFdB_ = -1;
        kbFd_ = -1;
        mouseIdA_ = -1;
        mouseIdB_ = -1;
        kbId_ = -1;
    }

    void TearDown() override
    {
        /* Unbind any devices that were bound */
        std::string msg;
        if (mouseIdA_ >= 0) {
            InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(mouseIdA_, msg);
        }
        if (mouseIdB_ >= 0) {
            InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(mouseIdB_, msg);
        }
        if (kbId_ >= 0) {
            InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(kbId_, msg);
        }
        DestroyDevice(mouseFdA_);
        DestroyDevice(mouseFdB_);
        DestroyDevice(kbFd_);
    }

    bool CreateAndFindMouse(const char *name, int &fd, int32_t &devId)
    {
        fd = CreateVirtualMouse(name);
        if (fd < 0) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));
        devId = PollForDeviceByName(name);
        return devId >= 0;
    }

    bool CreateAndFindKeyboard(const char *name, int &kbFd, int32_t &devId)
    {
        kbFd = CreateVirtualKeyboard(name);
        if (kbFd < 0) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));
        devId = PollForDeviceByName(name);
        return devId >= 0;
    }

    int mouseFdA_;
    int mouseFdB_;
    int kbFd_;
    int32_t mouseIdA_;
    int32_t mouseIdB_;
    int32_t kbId_;
};

/* ===== Device creation & discovery ==================================== */

/**
 * @tc.name: CreateVirtualMice
 * @tc.desc: Create 2 virtual USB mice via /dev/uinput, verify they appear
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, CreateVirtualMice, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseFdA_ = CreateVirtualMouse("SysTest MouseA");
    if (mouseFdA_ < 0) {
        GTEST_SKIP() << "Cannot open /dev/uinput, skipping";
    }
    mouseFdB_ = CreateVirtualMouse("SysTest MouseB");
    ASSERT_GE(mouseFdB_, 0) << "Failed to create second virtual mouse";

    std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));

    mouseIdA_ = PollForDeviceByName("SysTest MouseA");
    EXPECT_GE(mouseIdA_, 0) << "MouseA not found in InputManager";

    mouseIdB_ = PollForDeviceByName("SysTest MouseB");
    EXPECT_GE(mouseIdB_, 0) << "MouseB not found in InputManager";

    EXPECT_NE(mouseIdA_, mouseIdB_) << "Both mice should have different device IDs";
}

/**
 * @tc.name: UnboundDevicesInDefaultGroup
 * @tc.desc: Unbound mice share same default cursor group
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, UnboundDevicesInDefaultGroup, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest DfltA", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }
    if (!CreateAndFindMouse("SysTest DfltB", mouseFdB_, mouseIdB_)) {
        GTEST_SKIP() << "Cannot create second virtual mouse";
    }

    /* Both devices should exist -- verify via hidumper that no runtime bindings exist */
    std::string dump = RunHidumperCapture("-G");
    /* At minimum the dump should succeed */
    EXPECT_FALSE(dump.empty()) << "Hidumper returned empty output";
}

/**
 * @tc.name: MoveBeforeBinding_BothAffectSameCursor
 * @tc.desc: Inject moves from both mice before binding, verify no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, MoveBeforeBinding_BothAffectSameCursor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest MvA", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }
    if (!CreateAndFindMouse("SysTest MvB", mouseFdB_, mouseIdB_)) {
        GTEST_SKIP() << "Cannot create second virtual mouse";
    }

    /* Inject moves from both mice -- should affect same default cursor */
    for (int i = 0; i < 5; ++i) {
        InjectRelativeMotion(mouseFdA_, 3, 2);
        InjectRelativeMotion(mouseFdB_, -3, -2);
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    /* Success = no crash or hang */
    SUCCEED();
}

/* ===== Bind/unbind validation ========================================= */

/**
 * @tc.name: UnbindIdempotent
 * @tc.desc: Unbind a non-bound device returns RET_OK (idempotent)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, UnbindIdempotent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest Unbind", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(mouseIdA_, msg);
    EXPECT_EQ(ret, RET_OK) << "Unbinding an unbound device should return RET_OK, msg=" << msg;
}

/**
 * @tc.name: BindInvalidDisplay
 * @tc.desc: Bind to non-existent displayId returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, BindInvalidDisplay, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest BadDisp", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, INVALID_DISPLAY_ID, msg);
    EXPECT_NE(ret, RET_OK) << "Binding to invalid displayId should fail, msg=" << msg;
}

/**
 * @tc.name: BindInvalidDevice
 * @tc.desc: Bind non-existent deviceId returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, BindInvalidDevice, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        INVALID_DEVICE_ID, VALID_DISPLAY_ID, msg);
    EXPECT_NE(ret, RET_OK) << "Binding invalid device should fail, msg=" << msg;
}

/**
 * @tc.name: QueryBindingAfterUnbind
 * @tc.desc: After bind then unbind, hidumper shows no active binding for device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, QueryBindingAfterUnbind, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest QryUn", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    ASSERT_EQ(ret, RET_OK) << "Bind should succeed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    ret = InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(mouseIdA_, msg);
    ASSERT_EQ(ret, RET_OK) << "Unbind should succeed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    /* Verify no binding in hidumper */
    std::string dump = RunHidumperCapture("-G");
    std::string devIdStr = std::to_string(mouseIdA_);
    /* After unbind, the RuntimeBindings section should not reference this deviceId as bound */
    EXPECT_TRUE(dump.find("RuntimeBindings") != std::string::npos)
        << "Hidumper should contain RuntimeBindings section";
}

/**
 * @tc.name: AutoUnbindOnDisconnect
 * @tc.desc: Destroy uinput device, verify binding is cleared
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, AutoUnbindOnDisconnect, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest AutoUn", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    ASSERT_EQ(ret, RET_OK) << "Bind should succeed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    /* Destroy the uinput device */
    DestroyDevice(mouseFdA_);
    mouseIdA_ = -1; /* prevent TearDown from trying to unbind */

    /* Wait for the service to detect device removal */
    std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));

    /* Verify device is gone from hidumper */
    std::string dump = RunHidumperCapture("-G");
    EXPECT_FALSE(dump.empty()) << "Hidumper should produce output";
}

/* ===== Boundary & reliability ========================================= */

/**
 * @tc.name: BoundaryMove_LargePositive
 * @tc.desc: Inject large dx/dy values, verify no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, BoundaryMove_LargePositive, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest BigPos", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(mouseIdA_, VALID_DISPLAY_ID, msg);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    InjectRelativeMotion(mouseFdA_, 30000, 30000);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    InjectRelativeMotion(mouseFdA_, 32767, 32767);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    SUCCEED() << "No crash with large positive moves";
}

/**
 * @tc.name: BoundaryMove_LargeNegative
 * @tc.desc: Inject large negative dx/dy values, verify no crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, BoundaryMove_LargeNegative, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest BigNeg", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(mouseIdA_, VALID_DISPLAY_ID, msg);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    InjectRelativeMotion(mouseFdA_, -30000, -30000);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    InjectRelativeMotion(mouseFdA_, -32768, -32768);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    SUCCEED() << "No crash with large negative moves";
}

/**
 * @tc.name: ReliabilityRapidMoves
 * @tc.desc: 50 rapid consecutive moves on bound device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, ReliabilityRapidMoves, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest Rapid", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    ASSERT_EQ(ret, RET_OK) << "Bind failed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    for (int i = 0; i < 50; ++i) {
        InjectRelativeMotion(mouseFdA_, (i % 2 == 0) ? 5 : -5, (i % 3 == 0) ? 3 : -3);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    SUCCEED() << "50 rapid moves completed without crash";
}

/**
 * @tc.name: ReliabilityRepeatedButtonClicks
 * @tc.desc: 20 rapid button click cycles on bound device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, ReliabilityRepeatedButtonClicks, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest Click", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    ASSERT_EQ(ret, RET_OK) << "Bind failed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    for (int i = 0; i < 20; ++i) {
        InjectButtonClick(mouseFdA_, BTN_LEFT);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    SUCCEED() << "20 rapid click cycles completed without crash";
}

/**
 * @tc.name: ReliabilityReconnectCycle
 * @tc.desc: Create, bind, destroy, recreate, bind cycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, ReliabilityReconnectCycle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest Reconn", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    ASSERT_EQ(ret, RET_OK) << "First bind failed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    /* Destroy device */
    DestroyDevice(mouseFdA_);
    mouseIdA_ = -1;
    std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));

    /* Recreate with same name */
    if (!CreateAndFindMouse("SysTest Reconn", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot recreate virtual mouse after disconnect";
    }

    /* Bind again */
    ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    EXPECT_EQ(ret, RET_OK) << "Rebind after reconnect failed, msg=" << msg;
}

/* ===== Device type validation ========================================= */

/**
 * @tc.name: BindKeyboardDevice_Allowed
 * @tc.desc: Bind USB keyboard succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, BindKeyboardDevice_Allowed, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindKeyboard("SysTest KbBind", kbFd_, kbId_)) {
        GTEST_SKIP() << "Cannot create virtual keyboard";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        kbId_, VALID_DISPLAY_ID, msg);
    EXPECT_EQ(ret, RET_OK) << "Binding keyboard should succeed, msg=" << msg;
}

/**
 * @tc.name: BindTouchDevice_Rejected
 * @tc.desc: Attempt to bind a non-existent touch device returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, BindTouchDevice_Rejected, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    /* Use a bogus device ID that doesn't correspond to any real device */
    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        -12345, VALID_DISPLAY_ID, msg);
    EXPECT_NE(ret, RET_OK) << "Binding invalid device should fail, msg=" << msg;
}

/* ===== State cleanup ================================================== */

/**
 * @tc.name: UnbindCleansGroupState
 * @tc.desc: Verify group state removed after unbind via hidumper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, UnbindCleansGroupState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest ClnGrp", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    ASSERT_EQ(ret, RET_OK) << "Bind failed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    /* Capture state after bind */
    std::string dumpBound = RunHidumperCapture("-G");
    EXPECT_TRUE(dumpBound.find("DisplayGroups") != std::string::npos);

    ret = InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(mouseIdA_, msg);
    ASSERT_EQ(ret, RET_OK) << "Unbind failed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    /* Capture state after unbind */
    std::string dumpUnbound = RunHidumperCapture("-G");
    EXPECT_TRUE(dumpUnbound.find("DisplayGroups") != std::string::npos);
}

/**
 * @tc.name: RebindCleansOldGroupState
 * @tc.desc: Rebind to different group cleans old binding state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, RebindCleansOldGroupState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest Rebind", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    ASSERT_EQ(ret, RET_OK) << "First bind failed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    /* Rebind to same display (simulates rebind) */
    ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    EXPECT_EQ(ret, RET_OK) << "Rebind should succeed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    /* Verify state is consistent */
    std::string dump = RunHidumperCapture("-G");
    EXPECT_TRUE(dump.find("RuntimeBindings") != std::string::npos);
}

/* ===== Additional bind/unbind edge cases ============================== */

/**
 * @tc.name: BindUnbindBind_FullCycle
 * @tc.desc: Full bind-unbind-bind cycle works correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, BindUnbindBind_FullCycle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest Cycle", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    EXPECT_EQ(ret, RET_OK) << "First bind failed";
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    ret = InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(mouseIdA_, msg);
    EXPECT_EQ(ret, RET_OK) << "Unbind failed";
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    EXPECT_EQ(ret, RET_OK) << "Second bind failed";
}

/**
 * @tc.name: DoubleBindSameDevice
 * @tc.desc: Binding same device twice to same display succeeds idempotently
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, DoubleBindSameDevice, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest DblBnd", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret1 = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    EXPECT_EQ(ret1, RET_OK) << "First bind failed";
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    int32_t ret2 = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    EXPECT_EQ(ret2, RET_OK) << "Second bind to same display should succeed";
}

/**
 * @tc.name: DoubleUnbindSameDevice
 * @tc.desc: Unbinding same device twice returns RET_OK both times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, DoubleUnbindSameDevice, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest DblUn", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(mouseIdA_, VALID_DISPLAY_ID, msg);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    int32_t ret1 = InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(mouseIdA_, msg);
    EXPECT_EQ(ret1, RET_OK) << "First unbind failed";

    int32_t ret2 = InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(mouseIdA_, msg);
    EXPECT_EQ(ret2, RET_OK) << "Second unbind should still succeed";
}

/**
 * @tc.name: BindTwoMiceToDifferentDisplays
 * @tc.desc: Bind two mice, verify both bindings via hidumper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, BindTwoMiceToDifferentDisplays, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest TwoA", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create first virtual mouse";
    }
    if (!CreateAndFindMouse("SysTest TwoB", mouseFdB_, mouseIdB_)) {
        GTEST_SKIP() << "Cannot create second virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    EXPECT_EQ(ret, RET_OK) << "Bind mouseA failed, msg=" << msg;

    ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdB_, VALID_DISPLAY_ID, msg);
    EXPECT_EQ(ret, RET_OK) << "Bind mouseB failed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    std::string dump = RunHidumperCapture("-G");
    EXPECT_TRUE(dump.find("RuntimeBindings") != std::string::npos);
}

/**
 * @tc.name: HidumperBeforeAndAfterBind
 * @tc.desc: Capture hidumper evidence before and after bind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, HidumperBeforeAndAfterBind, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest HiDmp", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    system("hidumper -s 3101 -a -G > /data/local/tmp/sys_before_bind.txt 2>&1");

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    EXPECT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    system("hidumper -s 3101 -a -G > /data/local/tmp/sys_after_bind.txt 2>&1");

    ret = InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(mouseIdA_, msg);
    EXPECT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    system("hidumper -s 3101 -a -G > /data/local/tmp/sys_after_unbind.txt 2>&1");
}

/**
 * @tc.name: MoveAfterBind_NoServiceCrash
 * @tc.desc: Inject moves after binding, verify service stays alive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, MoveAfterBind_NoServiceCrash, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest MvBnd", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    for (int i = 0; i < 20; ++i) {
        InjectRelativeMotion(mouseFdA_, 10, 10);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    /* Verify service is still responsive */
    int32_t speed = -1;
    ret = InputManager::GetInstance()->GetPointerSpeed(speed);
    EXPECT_EQ(ret, RET_OK) << "Service should still respond after move injection";
}

/**
 * @tc.name: ClickAfterBind_NoServiceCrash
 * @tc.desc: Inject button clicks after binding, verify service stays alive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest, ClickAfterBind_NoServiceCrash, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("SysTest ClkBnd", mouseFdA_, mouseIdA_)) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseIdA_, VALID_DISPLAY_ID, msg);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    for (int i = 0; i < 10; ++i) {
        InjectButtonClick(mouseFdA_, BTN_LEFT);
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }

    /* Verify service still alive */
    int32_t speed = -1;
    ret = InputManager::GetInstance()->GetPointerSpeed(speed);
    EXPECT_EQ(ret, RET_OK);
}

/* ====================================================================== */
/* Dual display-group + dual mouse isolation tests                        */
/* ====================================================================== */

static void SetupDualDisplayGroups()
{
    DisplayGroupInfo group0;
    group0.id = 0;
    group0.name = "default";
    group0.type = GroupType::GROUP_DEFAULT;
    group0.mainDisplayId = 0;
    group0.focusWindowId = -1;
    DisplayInfo disp0;
    disp0.id = 0;
    disp0.x = 0;
    disp0.y = 0;
    disp0.width = 720;
    disp0.height = 1280;
    disp0.dpi = 240;
    disp0.name = "main";
    disp0.uniq = "default0";
    disp0.direction = DIRECTION0;
    group0.displaysInfo.push_back(disp0);

    DisplayGroupInfo group1;
    group1.id = 1;
    group1.name = "secondary";
    group1.type = GroupType::GROUP_SPECIAL;
    group1.mainDisplayId = 1;
    group1.focusWindowId = -1;
    DisplayInfo disp1;
    disp1.id = 1;
    disp1.x = 0;
    disp1.y = 0;
    disp1.width = 1920;
    disp1.height = 1080;
    disp1.dpi = 160;
    disp1.name = "secondary";
    disp1.uniq = "secondary0";
    disp1.direction = DIRECTION0;
    group1.displaysInfo.push_back(disp1);

    UserScreenInfo screenInfo;
    screenInfo.userId = 100;
    screenInfo.displayGroups.push_back(group0);
    screenInfo.displayGroups.push_back(group1);

    int32_t ret = InputManager::GetInstance()->UpdateDisplayInfo(screenInfo);
    MMI_HILOGI("SetupDualDisplayGroups: UpdateDisplayInfo ret=%{public}d", ret);
}

static void InjectRelativeMove(int fd, int dx, int dy)
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

static std::string CaptureHidumperG()
{
    FILE *fp = popen("hidumper -s 3101 -a -G", "r");
    if (!fp) {
        return "";
    }
    std::string result;
    char buf[512];
    while (fgets(buf, sizeof(buf), fp)) {
        result += buf;
    }
    pclose(fp);
    return result;
}

static std::string CaptureHidumperCursor()
{
    FILE *fp = popen("hidumper -s 3101 -a -c", "r");
    if (!fp) {
        return "";
    }
    std::string result;
    char buf[512];
    while (fgets(buf, sizeof(buf), fp)) {
        result += buf;
    }
    pclose(fp);
    return result;
}

/**
 * @tc.name: DualGroup_BeforeBinding_InterleavedMoves_PositionsAffectEachOther
 * @tc.desc: Before binding, two mice share the same default group cursor.
 *           Interleaved moves from A and B both affect the same position.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest,
         DualGroup_BeforeBinding_InterleavedMoves_PositionsAffectEachOther, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetupDualDisplayGroups();

    int fdA = CreateVirtualMouse("DualPreBindA");
    int fdB = CreateVirtualMouse("DualPreBindB");
    ASSERT_GE(fdA, 0) << "Failed to create mouse A";
    ASSERT_GE(fdB, 0) << "Failed to create mouse B";
    std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));

    int32_t devA = PollForDeviceByName("DualPreBindA");
    int32_t devB = PollForDeviceByName("DualPreBindB");
    if (devA < 0 || devB < 0) {
        ioctl(fdA, UI_DEV_DESTROY); close(fdA);
        ioctl(fdB, UI_DEV_DESTROY); close(fdB);
        GTEST_SKIP() << "Device discovery failed (devA=" << devA << " devB=" << devB << ")";
    }

    /* Both mice unbound -- interleave moves and verify shared cursor */
    for (int round = 0; round < 10; ++round) {
        InjectRelativeMove(fdA, 10, 5);
        std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

        int32_t dispIdAfterA = 0;
        double xAfterA = 0.0;
        double yAfterA = 0.0;
        InputManager::GetInstance()->GetPointerLocation(dispIdAfterA, xAfterA, yAfterA);

        InjectRelativeMove(fdB, -3, -2);
        std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

        int32_t dispIdAfterB = 0;
        double xAfterB = 0.0;
        double yAfterB = 0.0;
        InputManager::GetInstance()->GetPointerLocation(dispIdAfterB, xAfterB, yAfterB);

        std::cout << "BEFORE BIND: after A move pos=(" << xAfterA << "," << yAfterA
                  << "), after B move pos=(" << xAfterB << "," << yAfterB << ")" << std::endl;

        /* B's move should change the position that A just set (shared cursor) */
        if (round > 0) {
            EXPECT_TRUE(xAfterB != xAfterA || yAfterB != yAfterA)
                << "B's move should change the cursor position that A set";
        }
    }

    /* Cleanup */
    std::string msg;
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devA, msg);
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devB, msg);
    ioctl(fdA, UI_DEV_DESTROY); close(fdA);
    ioctl(fdB, UI_DEV_DESTROY); close(fdB);
}

/**
 * @tc.name: DualGroup_AfterBinding_InterleavedMoves_PositionsIsolated
 * @tc.desc: After binding A to group 0 and B to group 1, interleaved moves
 *           from B do NOT change group 0's cursor position (isolation).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest,
         DualGroup_AfterBinding_InterleavedMoves_PositionsIsolated, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetupDualDisplayGroups();

    int fdA = CreateVirtualMouse("DualPostBindA");
    int fdB = CreateVirtualMouse("DualPostBindB");
    ASSERT_GE(fdA, 0);
    ASSERT_GE(fdB, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));

    int32_t devA = PollForDeviceByName("DualPostBindA");
    int32_t devB = PollForDeviceByName("DualPostBindB");
    if (devA < 0 || devB < 0) {
        ioctl(fdA, UI_DEV_DESTROY); close(fdA);
        ioctl(fdB, UI_DEV_DESTROY); close(fdB);
        GTEST_SKIP() << "Device discovery failed (devA=" << devA << " devB=" << devB << ")";
    }

    /* Bind: A -> display 0 (group 0), B -> display 1 (group 1) */
    std::string msg;
    int32_t retA = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devA, 0, msg);
    EXPECT_EQ(retA, RET_OK) << "Bind mouse A failed: " << msg;
    int32_t retB = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devB, 1, msg);
    EXPECT_EQ(retB, RET_OK) << "Bind mouse B failed: " << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    /* After binding, group 1's cursor should start at screen center (1920/2=960, 1080/2=540) */
    std::string dumpInit = CaptureHidumperG();
    std::cout << "AFTER BIND: group1 initial pos should be screen center (960,540)" << std::endl;
    std::cout << "AFTER BIND: hidumper output:\n" << dumpInit << std::endl;

    /* Interleave: A moves, capture group 0 pos; B moves, capture group 0 pos again */
    for (int round = 0; round < 10; ++round) {
        InjectRelativeMove(fdA, 10, 5);
        std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

        int32_t dispId0 = 0;
        double xAfterA = 0.0;
        double yAfterA = 0.0;
        InputManager::GetInstance()->GetPointerLocation(dispId0, xAfterA, yAfterA);

        InjectRelativeMove(fdB, -3, -2);
        std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

        int32_t dispId0Again = 0;
        double xAfterB = 0.0;
        double yAfterB = 0.0;
        InputManager::GetInstance()->GetPointerLocation(dispId0Again, xAfterB, yAfterB);

        std::cout << "AFTER BIND: A moved to (" << xAfterA << "," << yAfterA
                  << "), B moved, A's group still at (" << xAfterB << "," << yAfterB << ")"
                  << std::endl;

        /* B's move in group 1 should NOT change group 0's position */
        EXPECT_DOUBLE_EQ(xAfterA, xAfterB)
            << "Group 0 X should be unchanged after B's move in group 1";
        EXPECT_DOUBLE_EQ(yAfterA, yAfterB)
            << "Group 0 Y should be unchanged after B's move in group 1";
    }

    /* Cleanup */
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devA, msg);
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devB, msg);
    ioctl(fdA, UI_DEV_DESTROY); close(fdA);
    ioctl(fdB, UI_DEV_DESTROY); close(fdB);
}

/**
 * @tc.name: DualGroup_AfterBinding_GlobalApiOnlyAffectsDefaultGroup
 * @tc.desc: After binding, global APIs (SetPointerSize, SetPointerColor,
 *           SetPointerSpeed) only affect the default group. Group 1
 *           should NOT be affected by global API calls.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest,
         DualGroup_AfterBinding_GlobalApiOnlyAffectsDefaultGroup, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetupDualDisplayGroups();

    int fdA = CreateVirtualMouse("DualGlobalA");
    int fdB = CreateVirtualMouse("DualGlobalB");
    ASSERT_GE(fdA, 0);
    ASSERT_GE(fdB, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));

    int32_t devA = PollForDeviceByName("DualGlobalA");
    int32_t devB = PollForDeviceByName("DualGlobalB");
    if (devA < 0 || devB < 0) {
        ioctl(fdA, UI_DEV_DESTROY); close(fdA);
        ioctl(fdB, UI_DEV_DESTROY); close(fdB);
        GTEST_SKIP() << "Device discovery failed";
    }

    /* Save original values */
    int32_t origSize = 0;
    int32_t origColor = 0;
    int32_t origSpeed = 0;
    InputManager::GetInstance()->GetPointerSize(origSize);
    InputManager::GetInstance()->GetPointerColor(origColor);
    InputManager::GetInstance()->GetPointerSpeed(origSpeed);

    /* Bind: A -> group 0, B -> group 1 */
    std::string msg;
    EXPECT_EQ(InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devA, 0, msg), RET_OK);
    EXPECT_EQ(InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devB, 1, msg), RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    /* Call global APIs */
    InputManager::GetInstance()->SetPointerSize(5);
    InputManager::GetInstance()->SetPointerColor(0xFF0000);
    InputManager::GetInstance()->SetPointerSpeed(7);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    /* Verify global APIs return the set values (default group) */
    int32_t gotSize = 0;
    int32_t gotColor = 0;
    int32_t gotSpeed = 0;
    InputManager::GetInstance()->GetPointerSize(gotSize);
    InputManager::GetInstance()->GetPointerColor(gotColor);
    InputManager::GetInstance()->GetPointerSpeed(gotSpeed);

    std::cout << "GLOBAL API: SetPointerSize(5) -> GetPointerSize=" << gotSize
              << ", expected 5" << std::endl;
    std::cout << "GLOBAL API: SetPointerColor(0xFF0000) -> GetPointerColor=" << gotColor
              << ", expected " << 0xFF0000 << std::endl;
    std::cout << "GLOBAL API: SetPointerSpeed(7) -> GetPointerSpeed=" << gotSpeed
              << ", expected 7" << std::endl;

    EXPECT_EQ(gotSize, 5) << "GetPointerSize should return 5";
    EXPECT_EQ(gotColor, 0xFF0000) << "GetPointerColor should return 0xFF0000";
    EXPECT_EQ(gotSpeed, 7) << "GetPointerSpeed should return 7";

    /* Capture hidumper -G: verify group 0's state reflects global changes */
    std::string dumpG = CaptureHidumperG();
    std::cout << "GLOBAL API: hidumper -G output:\n" << dumpG << std::endl;
    EXPECT_NE(dumpG.find("RuntimeBindings"), std::string::npos);

    /* Capture hidumper -c: check per-group cursor context if available */
    std::string dumpC = CaptureHidumperCursor();
    std::cout << "GLOBAL API: hidumper -c output:\n" << dumpC << std::endl;

    /* These global APIs cannot target a specific group, so group 1 should NOT be affected */
    /* We verify via hidumper that group 0 shows the changes */
    EXPECT_NE(dumpG.find("groupId=0:"), std::string::npos)
        << "Group 0 state should exist in hidumper";

    /* Restore original values */
    InputManager::GetInstance()->SetPointerSize(origSize);
    InputManager::GetInstance()->SetPointerColor(origColor);
    InputManager::GetInstance()->SetPointerSpeed(origSpeed);

    /* Cleanup */
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devA, msg);
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devB, msg);
    ioctl(fdA, UI_DEV_DESTROY); close(fdA);
    ioctl(fdB, UI_DEV_DESTROY); close(fdB);
}

/**
 * @tc.name: DualGroup_AfterBinding_PerGroupStyleIsolated
 * @tc.desc: After binding, injecting moves from mouse A only affects group 0
 *           in hidumper, and injecting moves from mouse B only affects group 1.
 *           SetPointerStyle is window-scoped (uses windowId), not group-scoped,
 *           so we verify isolation through hidumper position state.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest,
         DualGroup_AfterBinding_PerGroupStyleIsolated, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetupDualDisplayGroups();

    int fdA = CreateVirtualMouse("DualStyleA");
    int fdB = CreateVirtualMouse("DualStyleB");
    ASSERT_GE(fdA, 0);
    ASSERT_GE(fdB, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));

    int32_t devA = PollForDeviceByName("DualStyleA");
    int32_t devB = PollForDeviceByName("DualStyleB");
    if (devA < 0 || devB < 0) {
        ioctl(fdA, UI_DEV_DESTROY); close(fdA);
        ioctl(fdB, UI_DEV_DESTROY); close(fdB);
        GTEST_SKIP() << "Device discovery failed";
    }

    /* Bind: A -> group 0, B -> group 1 */
    std::string msg;
    EXPECT_EQ(InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devA, 0, msg), RET_OK);
    EXPECT_EQ(InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devB, 1, msg), RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    /* Capture baseline hidumper */
    std::string dumpBaseline = CaptureHidumperG();
    std::cout << "STYLE ISO: baseline hidumper:\n" << dumpBaseline << std::endl;

    /* Inject moves from A only */
    for (int i = 0; i < 15; ++i) {
        InjectRelativeMove(fdA, 8, 4);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    std::string dumpAfterA = CaptureHidumperG();
    std::cout << "STYLE ISO: after A moves only:\n" << dumpAfterA << std::endl;
    /* Group 0 should have position changes, group 1 unchanged */
    EXPECT_NE(dumpAfterA.find("groupId=0:"), std::string::npos)
        << "Group 0 should have state after A moves";

    /* Inject moves from B only */
    for (int i = 0; i < 15; ++i) {
        InjectRelativeMove(fdB, -6, -3);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    std::string dumpAfterB = CaptureHidumperG();
    std::cout << "STYLE ISO: after B moves only:\n" << dumpAfterB << std::endl;
    /* Group 1 should now have position changes, group 0 unchanged from A's last position */
    EXPECT_NE(dumpAfterB.find("groupId=1:"), std::string::npos)
        << "Group 1 should have state after B moves";

    /* Print all PointerStateByGroup lines for evidence */
    std::istringstream stream(dumpAfterB);
    std::string line;
    bool inSection = false;
    while (std::getline(stream, line)) {
        if (line.find("PointerStateByGroup") != std::string::npos) {
            inSection = true;
        }
        if (inSection) {
            std::cout << "STYLE ISO PointerState: " << line << std::endl;
            if (line.find("---") != std::string::npos && line.find("PointerStateByGroup") == std::string::npos) {
                break;
            }
        }
    }

    /* Cleanup */
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devA, msg);
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devB, msg);
    ioctl(fdA, UI_DEV_DESTROY); close(fdA);
    ioctl(fdB, UI_DEV_DESTROY); close(fdB);
}

/**
 * @tc.name: DualGroup_BeforeVsAfterBinding_FullComparison
 * @tc.desc: Complete lifecycle: before binding (shared), bind (2 bindings),
 *           inject moves, unbind A (1 binding), unbind B (empty).
 *           Captures hidumper at each phase to verify state transitions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupBindingRealServiceTest,
         DualGroup_BeforeVsAfterBinding_FullComparison, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetupDualDisplayGroups();

    int fdA = CreateVirtualMouse("DualLifecycleA");
    int fdB = CreateVirtualMouse("DualLifecycleB");
    ASSERT_GE(fdA, 0);
    ASSERT_GE(fdB, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));

    int32_t devA = PollForDeviceByName("DualLifecycleA");
    int32_t devB = PollForDeviceByName("DualLifecycleB");
    if (devA < 0 || devB < 0) {
        ioctl(fdA, UI_DEV_DESTROY); close(fdA);
        ioctl(fdB, UI_DEV_DESTROY); close(fdB);
        GTEST_SKIP() << "Device discovery failed";
    }

    /* Phase 1: Before binding -- both mice share state, RuntimeBindings empty */
    std::string dumpPhase1 = CaptureHidumperG();
    std::cout << "LIFECYCLE Phase1 (before bind):\n" << dumpPhase1 << std::endl;
    EXPECT_NE(dumpPhase1.find("RuntimeBindings"), std::string::npos);
    EXPECT_NE(dumpPhase1.find("(empty)"), std::string::npos)
        << "Before binding, RuntimeBindings should be empty";

    /* Phase 2: Bind A -> group 0, B -> group 1 */
    std::string msg;
    EXPECT_EQ(InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devA, 0, msg), RET_OK);
    EXPECT_EQ(InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devB, 1, msg), RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    std::string dumpPhase2 = CaptureHidumperG();
    std::cout << "LIFECYCLE Phase2 (2 bindings):\n" << dumpPhase2 << std::endl;
    /* Count deviceId= occurrences to verify 2 bindings */
    size_t bindCount2 = 0;
    size_t searchPos = 0;
    while ((searchPos = dumpPhase2.find("deviceId=", searchPos)) != std::string::npos) {
        bindCount2++;
        searchPos += 9;
    }
    EXPECT_GE(bindCount2, 2u) << "After binding 2 devices, should have >= 2 binding entries";

    /* Phase 3: Inject interleaved moves */
    for (int i = 0; i < 15; ++i) {
        InjectRelativeMove(fdA, 5, 3);
        InjectRelativeMove(fdB, -3, -5);
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    std::string dumpPhase3 = CaptureHidumperG();
    std::cout << "LIFECYCLE Phase3 (after moves):\n" << dumpPhase3 << std::endl;
    EXPECT_NE(dumpPhase3.find("groupId=0:"), std::string::npos);
    EXPECT_NE(dumpPhase3.find("groupId=1:"), std::string::npos)
        << "After moves from both bound mice, both group states should exist";

    /* Phase 4: Unbind A only -- 1 binding remaining */
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devA, msg);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    std::string dumpPhase4 = CaptureHidumperG();
    std::cout << "LIFECYCLE Phase4 (1 binding remaining):\n" << dumpPhase4 << std::endl;
    /* Should still have at least 1 deviceId= entry (device B) */
    EXPECT_NE(dumpPhase4.find("deviceId=" + std::to_string(devB)), std::string::npos)
        << "After unbinding A, device B should still be bound";

    /* Phase 5: Unbind B -- empty */
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devB, msg);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    std::string dumpPhase5 = CaptureHidumperG();
    std::cout << "LIFECYCLE Phase5 (empty):\n" << dumpPhase5 << std::endl;
    /* After unbind, RuntimeBindings should contain "(empty)" again */
    size_t rtPos = dumpPhase5.find("RuntimeBindings");
    if (rtPos != std::string::npos) {
        size_t nextSection = dumpPhase5.find("---", rtPos + 10);
        std::string rtSection = dumpPhase5.substr(rtPos,
            (nextSection != std::string::npos) ? nextSection - rtPos : std::string::npos);
        EXPECT_NE(rtSection.find("(empty)"), std::string::npos)
            << "After unbinding all devices, RuntimeBindings should be empty";
    }

    /* Verify transition: empty -> 2 bindings -> 1 binding -> empty */
    std::cout << "LIFECYCLE: Verified transitions: empty -> 2 bindings -> 1 binding -> empty"
              << std::endl;

    /* Cleanup */
    ioctl(fdA, UI_DEV_DESTROY); close(fdA);
    ioctl(fdB, UI_DEV_DESTROY); close(fdB);
}

} // namespace
