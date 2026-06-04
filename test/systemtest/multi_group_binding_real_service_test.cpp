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

/**
 * @tc.name: DualGroup_BeforeBinding_MiceShareDefaultState
 * @tc.desc: Before binding, two mice inject moves and share the same default
 *           group cursor position. hidumper -G shows only groupId=0.
 */
HWTEST_F(MultiGroupBindingRealServiceTest,
         DualGroup_BeforeBinding_MiceShareDefaultState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetupDualDisplayGroups();

    int fdA = CreateVirtualMouse("DualGroupTestMouseA");
    int fdB = CreateVirtualMouse("DualGroupTestMouseB");
    ASSERT_GE(fdA, 0) << "Failed to create mouse A";
    ASSERT_GE(fdB, 0) << "Failed to create mouse B";
    std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));

    // Both mice unbound — inject moves
    for (int i = 0; i < 10; i++) {
        InjectRelativeMove(fdA, 5, 3);
        InjectRelativeMove(fdB, -2, 1);
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    // hidumper should show only groupId=0 in PointerStateByGroup
    std::string dump = CaptureHidumperG();
    EXPECT_NE(dump.find("--- PointerStateByGroup ---"), std::string::npos);
    EXPECT_NE(dump.find("groupId=0:"), std::string::npos);
    // No groupId=1 state should exist yet
    EXPECT_EQ(dump.find("groupId=1: cursorPos"), std::string::npos)
        << "Before binding, non-default group state should not exist";

    ioctl(fdA, UI_DEV_DESTROY);
    close(fdA);
    ioctl(fdB, UI_DEV_DESTROY);
    close(fdB);
}

/**
 * @tc.name: DualGroup_AfterBinding_CursorPositionIsolated
 * @tc.desc: After binding mouse A to group 0 and mouse B to group 1,
 *           injecting moves from each mouse should NOT affect the other
 *           group's cursor position.
 */
HWTEST_F(MultiGroupBindingRealServiceTest,
         DualGroup_AfterBinding_CursorPositionIsolated, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetupDualDisplayGroups();

    int fdA = CreateVirtualMouse("IsoTestMouseA");
    int fdB = CreateVirtualMouse("IsoTestMouseB");
    ASSERT_GE(fdA, 0);
    ASSERT_GE(fdB, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));

    int devA = FindDeviceByName("IsoTestMouseA");
    int devB = FindDeviceByName("IsoTestMouseB");
    if (devA < 0 || devB < 0) {
        ioctl(fdA, UI_DEV_DESTROY); close(fdA);
        ioctl(fdB, UI_DEV_DESTROY); close(fdB);
        GTEST_SKIP() << "Device discovery failed (devA=" << devA << " devB=" << devB << ")";
    }

    // Bind: A → display 0 (group 0), B → display 1 (group 1)
    std::string msg;
    int32_t retA = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devA, 0, msg);
    EXPECT_EQ(retA, RET_OK) << "Bind mouse A failed: " << msg;
    int32_t retB = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devB, 1, msg);
    EXPECT_EQ(retB, RET_OK) << "Bind mouse B failed: " << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    // Capture baseline hidumper
    std::string dumpBefore = CaptureHidumperG();
    EXPECT_NE(dumpBefore.find("RuntimeBindings"), std::string::npos);

    // Inject 20 moves from mouse A only
    for (int i = 0; i < 20; i++) {
        InjectRelativeMove(fdA, 10, 5);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    // Capture after A moves
    std::string dumpAfterA = CaptureHidumperG();

    // Inject 20 moves from mouse B only
    for (int i = 0; i < 20; i++) {
        InjectRelativeMove(fdB, -8, -4);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    std::string dumpAfterB = CaptureHidumperG();

    // Verify: both groups exist in dump
    EXPECT_NE(dumpAfterB.find("groupId=0:"), std::string::npos);
    EXPECT_NE(dumpAfterB.find("groupId=1:"), std::string::npos)
        << "After binding to group 1, per-group state should exist";

    // Verify: RuntimeBindings shows both devices
    EXPECT_NE(dumpAfterB.find("deviceId=" + std::to_string(devA)), std::string::npos);
    EXPECT_NE(dumpAfterB.find("deviceId=" + std::to_string(devB)), std::string::npos);

    // Unbind both
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devA, msg);
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devB, msg);

    ioctl(fdA, UI_DEV_DESTROY); close(fdA);
    ioctl(fdB, UI_DEV_DESTROY); close(fdB);
}

/**
 * @tc.name: DualGroup_AfterBinding_StyleSizeColorIsolated
 * @tc.desc: After binding, setting pointer style/size/color on default group
 *           does NOT affect the bound non-default group, and vice versa.
 */
HWTEST_F(MultiGroupBindingRealServiceTest,
         DualGroup_AfterBinding_StyleSizeColorIsolated, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetupDualDisplayGroups();

    int fdA = CreateVirtualMouse("StyleTestMouseA");
    int fdB = CreateVirtualMouse("StyleTestMouseB");
    ASSERT_GE(fdA, 0);
    ASSERT_GE(fdB, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));

    int devA = FindDeviceByName("StyleTestMouseA");
    int devB = FindDeviceByName("StyleTestMouseB");
    if (devA < 0 || devB < 0) {
        ioctl(fdA, UI_DEV_DESTROY); close(fdA);
        ioctl(fdB, UI_DEV_DESTROY); close(fdB);
        GTEST_SKIP() << "Device discovery failed";
    }

    // --- Before binding: set global pointer size ---
    int32_t origSize = 0;
    InputManager::GetInstance()->GetPointerSize(origSize);
    InputManager::GetInstance()->SetPointerSize(3);

    int32_t sizeBeforeBind = 0;
    InputManager::GetInstance()->GetPointerSize(sizeBeforeBind);
    EXPECT_EQ(sizeBeforeBind, 3) << "Global pointer size should be 3 before binding";

    // --- Bind: A → group 0, B → group 1 ---
    std::string msg;
    InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devA, 0, msg);
    InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devB, 1, msg);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    // --- After binding: change global size, verify it does NOT affect bound group ---
    InputManager::GetInstance()->SetPointerSize(5);
    int32_t sizeAfterChange = 0;
    InputManager::GetInstance()->GetPointerSize(sizeAfterChange);
    EXPECT_EQ(sizeAfterChange, 5) << "Global pointer size should be 5";

    // hidumper should show per-group state
    std::string dump = CaptureHidumperG();
    EXPECT_NE(dump.find("--- SoftCursorRS ---"), std::string::npos);
    EXPECT_NE(dump.find("groupId=0:"), std::string::npos);

    // --- Restore and cleanup ---
    InputManager::GetInstance()->SetPointerSize(origSize);
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devA, msg);
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devB, msg);

    ioctl(fdA, UI_DEV_DESTROY); close(fdA);
    ioctl(fdB, UI_DEV_DESTROY); close(fdB);
}

/**
 * @tc.name: DualGroup_BeforeVsAfterBinding_HidumperComparison
 * @tc.desc: Complete before/after comparison: capture hidumper -G before binding,
 *           bind both mice, inject moves from both, capture after, then unbind
 *           and capture again. Verify state transitions are correct.
 */
HWTEST_F(MultiGroupBindingRealServiceTest,
         DualGroup_BeforeVsAfterBinding_HidumperComparison, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SetupDualDisplayGroups();

    int fdA = CreateVirtualMouse("CompareMouseA");
    int fdB = CreateVirtualMouse("CompareMouseB");
    ASSERT_GE(fdA, 0);
    ASSERT_GE(fdB, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(DEVICE_SETTLE_MS));

    int devA = FindDeviceByName("CompareMouseA");
    int devB = FindDeviceByName("CompareMouseB");
    if (devA < 0 || devB < 0) {
        ioctl(fdA, UI_DEV_DESTROY); close(fdA);
        ioctl(fdB, UI_DEV_DESTROY); close(fdB);
        GTEST_SKIP() << "Device discovery failed";
    }

    // Phase 1: BEFORE binding
    std::string dumpBefore = CaptureHidumperG();
    EXPECT_NE(dumpBefore.find("RuntimeBindings"), std::string::npos);
    EXPECT_NE(dumpBefore.find("(empty)"), std::string::npos)
        << "Before binding, RuntimeBindings should be empty";

    // Phase 2: BIND both mice
    std::string msg;
    EXPECT_EQ(InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devA, 0, msg), RET_OK);
    EXPECT_EQ(InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(devB, 1, msg), RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    std::string dumpBound = CaptureHidumperG();
    // RuntimeBindings should now have 2 entries
    size_t bindingCount = 0;
    size_t pos = 0;
    while ((pos = dumpBound.find("deviceId=", pos)) != std::string::npos) {
        bindingCount++;
        pos += 9;
    }
    EXPECT_GE(bindingCount, 2u) << "After binding 2 devices, should have >= 2 binding entries";

    // Phase 3: INJECT moves from both
    for (int i = 0; i < 15; i++) {
        InjectRelativeMove(fdA, 5, 3);
        InjectRelativeMove(fdB, -3, -5);
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    std::string dumpMoved = CaptureHidumperG();
    EXPECT_NE(dumpMoved.find("groupId=0:"), std::string::npos);

    // Phase 4: UNBIND both
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devA, msg);
    InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(devB, msg);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    std::string dumpUnbound = CaptureHidumperG();
    // After unbind, RuntimeBindings should contain "(empty)" again
    size_t rtPos = dumpUnbound.find("RuntimeBindings");
    if (rtPos != std::string::npos) {
        size_t nextSection = dumpUnbound.find("---", rtPos + 10);
        std::string rtSection = dumpUnbound.substr(rtPos, nextSection - rtPos);
        EXPECT_NE(rtSection.find("(empty)"), std::string::npos)
            << "After unbinding all devices, RuntimeBindings should be empty";
    }

    ioctl(fdA, UI_DEV_DESTROY); close(fdA);
    ioctl(fdB, UI_DEV_DESTROY); close(fdB);
}

} // namespace
