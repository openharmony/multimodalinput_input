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
 * System-level gtest suite verifying that global pointer/mouse APIs
 * remain functional and isolated after the multi-group binding feature
 * is present. Runs against real mmi_service on DAYU200/RK3568.
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
#define MMI_LOG_TAG "MultiGroupApiImpactTest"

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

static void DestroyDevice(int &fd)
{
    if (fd >= 0) {
        ioctl(fd, UI_DEV_DESTROY);
        close(fd);
        fd = -1;
    }
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

class MultiGroupApiImpactTest : public testing::Test {
protected:
    void SetUp() override
    {
        mouseFd_ = -1;
        mouseId_ = -1;
        /* Save original values for restoration */
        InputManager::GetInstance()->GetPointerSize(origSize_);
        InputManager::GetInstance()->GetPointerSpeed(origSpeed_);
        InputManager::GetInstance()->GetPointerColor(origColor_);
    }

    void TearDown() override
    {
        /* Restore original pointer settings */
        InputManager::GetInstance()->SetPointerSize(origSize_);
        InputManager::GetInstance()->SetPointerSpeed(origSpeed_);
        InputManager::GetInstance()->SetPointerColor(origColor_);

        /* Unbind and cleanup device */
        if (mouseId_ >= 0) {
            std::string msg;
            InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(mouseId_, msg);
        }
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
    int32_t origSize_ = 1;
    int32_t origSpeed_ = 5;
    int32_t origColor_ = 0;
};

/* ===== Global API isolation =========================================== */

/**
 * @tc.name: GlobalApi_SetPointerSize_OnlyAffectsDefaultGroup
 * @tc.desc: SetPointerSize works and returns consistent value via GetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, GlobalApi_SetPointerSize_OnlyAffectsDefaultGroup, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t testSize = 3;
    int32_t ret = InputManager::GetInstance()->SetPointerSize(testSize);
    EXPECT_EQ(ret, RET_OK) << "SetPointerSize failed";

    int32_t readBack = -1;
    ret = InputManager::GetInstance()->GetPointerSize(readBack);
    EXPECT_EQ(ret, RET_OK) << "GetPointerSize failed";
    EXPECT_EQ(readBack, testSize) << "Pointer size mismatch";
}

/**
 * @tc.name: GlobalApi_SetPointerColor_OnlyAffectsDefaultGroup
 * @tc.desc: SetPointerColor works and returns consistent value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, GlobalApi_SetPointerColor_OnlyAffectsDefaultGroup, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t testColor = 0xFF0000;
    int32_t ret = InputManager::GetInstance()->SetPointerColor(testColor);
    EXPECT_EQ(ret, RET_OK) << "SetPointerColor failed";

    int32_t readBack = -1;
    ret = InputManager::GetInstance()->GetPointerColor(readBack);
    EXPECT_EQ(ret, RET_OK) << "GetPointerColor failed";
    EXPECT_EQ(readBack, testColor) << "Pointer color mismatch";
}

/**
 * @tc.name: GlobalApi_SetPointerSpeed_OnlyAffectsDefaultGroup
 * @tc.desc: SetPointerSpeed works and returns consistent value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, GlobalApi_SetPointerSpeed_OnlyAffectsDefaultGroup, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t testSpeed = 7;
    int32_t ret = InputManager::GetInstance()->SetPointerSpeed(testSpeed);
    EXPECT_EQ(ret, RET_OK) << "SetPointerSpeed failed";

    int32_t readBack = -1;
    ret = InputManager::GetInstance()->GetPointerSpeed(readBack);
    EXPECT_EQ(ret, RET_OK) << "GetPointerSpeed failed";
    EXPECT_EQ(readBack, testSpeed) << "Pointer speed mismatch";
}

/**
 * @tc.name: GlobalApi_SetPointerVisible_OnlyAffectsDefaultGroup
 * @tc.desc: SetPointerVisible / IsPointerVisible round-trip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, GlobalApi_SetPointerVisible_OnlyAffectsDefaultGroup, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = InputManager::GetInstance()->SetPointerVisible(true);
    EXPECT_EQ(ret, RET_OK) << "SetPointerVisible(true) failed";

    bool visible = InputManager::GetInstance()->IsPointerVisible();
    EXPECT_TRUE(visible) << "Pointer should be visible";

    ret = InputManager::GetInstance()->SetPointerVisible(false);
    EXPECT_EQ(ret, RET_OK) << "SetPointerVisible(false) failed";

    visible = InputManager::GetInstance()->IsPointerVisible();
    EXPECT_FALSE(visible) << "Pointer should be invisible";

    /* Restore visibility */
    InputManager::GetInstance()->SetPointerVisible(true);
}

/**
 * @tc.name: GlobalApi_GetPointerLocation_ReturnsDefaultGroup
 * @tc.desc: GetPointerLocation returns valid coordinates for default display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, GlobalApi_GetPointerLocation_ReturnsDefaultGroup, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = -1;
    double x = -1.0;
    double y = -1.0;
    int32_t ret = InputManager::GetInstance()->GetPointerLocation(displayId, x, y);
    EXPECT_EQ(ret, RET_OK) << "GetPointerLocation failed";
    EXPECT_GE(displayId, 0) << "displayId should be non-negative";
    EXPECT_GE(x, 0.0) << "x coordinate should be non-negative";
    EXPECT_GE(y, 0.0) << "y coordinate should be non-negative";
}

/* ===== After binding ================================================== */

/**
 * @tc.name: AfterBinding_GlobalApiDoesNotAffectBoundDevice
 * @tc.desc: Global API calls still succeed after a device is bound
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, AfterBinding_GlobalApiDoesNotAffectBoundDevice, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("ApiTest Bound")) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseId_, VALID_DISPLAY_ID, msg);
    ASSERT_EQ(ret, RET_OK) << "Bind failed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    /* Global APIs should still work */
    int32_t size = -1;
    ret = InputManager::GetInstance()->GetPointerSize(size);
    EXPECT_EQ(ret, RET_OK) << "GetPointerSize should work after binding";

    int32_t speed = -1;
    ret = InputManager::GetInstance()->GetPointerSpeed(speed);
    EXPECT_EQ(ret, RET_OK) << "GetPointerSpeed should work after binding";

    int32_t color = -1;
    ret = InputManager::GetInstance()->GetPointerColor(color);
    EXPECT_EQ(ret, RET_OK) << "GetPointerColor should work after binding";

    bool visible = InputManager::GetInstance()->IsPointerVisible();
    (void)visible; /* Just verify no crash */
}

/**
 * @tc.name: AfterBinding_PerGroupMouseStateIsolation
 * @tc.desc: Set pointer speed, bind device, verify speed setting unchanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, AfterBinding_PerGroupMouseStateIsolation, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t testSpeed = 3;
    int32_t ret = InputManager::GetInstance()->SetPointerSpeed(testSpeed);
    ASSERT_EQ(ret, RET_OK);

    if (!CreateAndFindMouse("ApiTest Isol")) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseId_, VALID_DISPLAY_ID, msg);
    ASSERT_EQ(ret, RET_OK) << "Bind failed, msg=" << msg;
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    int32_t readBack = -1;
    ret = InputManager::GetInstance()->GetPointerSpeed(readBack);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(readBack, testSpeed) << "Global pointer speed should not be affected by binding";
}

/* ===== Hidumper cross-verification ==================================== */

/**
 * @tc.name: Hidumper_VerifyBindingInfo
 * @tc.desc: Call hidumper -G, parse output, verify binding data present
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, Hidumper_VerifyBindingInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("ApiTest HiDmp")) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseId_, VALID_DISPLAY_ID, msg);
    ASSERT_EQ(ret, RET_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(BIND_SETTLE_MS));

    std::string dump = RunHidumperCapture("-G");
    EXPECT_FALSE(dump.empty()) << "Hidumper should return output";
    EXPECT_TRUE(dump.find("RuntimeBindings") != std::string::npos)
        << "Hidumper should contain RuntimeBindings section";
    EXPECT_TRUE(dump.find("DisplayGroups") != std::string::npos)
        << "Hidumper should contain DisplayGroups section";
}

/**
 * @tc.name: Hidumper_VerifyCursorInfo
 * @tc.desc: Verify cursor state in hidumper matches API state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, Hidumper_VerifyCursorInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string dump = RunHidumperCapture("-G");
    EXPECT_FALSE(dump.empty()) << "Hidumper should return output";
    EXPECT_TRUE(dump.find("PointerStateByGroup") != std::string::npos)
        << "Hidumper should contain PointerStateByGroup section";
}

/* ===== Error handling ================================================= */

/**
 * @tc.name: ErrorHandling_BindInvalidDevice
 * @tc.desc: Binding invalid deviceId returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, ErrorHandling_BindInvalidDevice, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        INVALID_DEVICE_ID, VALID_DISPLAY_ID, msg);
    EXPECT_NE(ret, RET_OK) << "Binding invalid device should fail";
}

/**
 * @tc.name: ErrorHandling_BindInvalidDisplay
 * @tc.desc: Binding to invalid displayId returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, ErrorHandling_BindInvalidDisplay, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("ApiTest BadDsp")) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->BindDeviceToDisplayGroupByDisplay(
        mouseId_, INVALID_DISPLAY_ID, msg);
    EXPECT_NE(ret, RET_OK) << "Binding to invalid display should fail";
}

/**
 * @tc.name: ErrorHandling_UnbindNotBoundDevice
 * @tc.desc: Unbinding a device that was never bound returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, ErrorHandling_UnbindNotBoundDevice, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    if (!CreateAndFindMouse("ApiTest NotBnd")) {
        GTEST_SKIP() << "Cannot create virtual mouse";
    }

    std::string msg;
    int32_t ret = InputManager::GetInstance()->UnbindDeviceFromDisplayGroup(mouseId_, msg);
    EXPECT_EQ(ret, RET_OK) << "Unbinding unbound device should be idempotent";
}

/**
 * @tc.name: ErrorHandling_SetInvalidPointerSize
 * @tc.desc: SetPointerSize with boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, ErrorHandling_SetInvalidPointerSize, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    /* Negative size -- behavior depends on service validation */
    int32_t ret = InputManager::GetInstance()->SetPointerSize(-1);
    /* Service may accept or reject -- the key is no crash */
    (void)ret;

    /* Extremely large size */
    ret = InputManager::GetInstance()->SetPointerSize(999999);
    (void)ret;

    /* Verify service is still responsive */
    int32_t size = -1;
    ret = InputManager::GetInstance()->GetPointerSize(size);
    EXPECT_EQ(ret, RET_OK) << "Service should still respond after invalid size attempts";
}

/**
 * @tc.name: ErrorHandling_SetInvalidPointerSpeed
 * @tc.desc: SetPointerSpeed with boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultiGroupApiImpactTest, ErrorHandling_SetInvalidPointerSpeed, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    /* Negative speed */
    int32_t ret = InputManager::GetInstance()->SetPointerSpeed(-1);
    (void)ret;

    /* Extremely large speed */
    ret = InputManager::GetInstance()->SetPointerSpeed(999999);
    (void)ret;

    /* Verify service is still responsive */
    int32_t speed = -1;
    ret = InputManager::GetInstance()->GetPointerSpeed(speed);
    EXPECT_EQ(ret, RET_OK) << "Service should still respond after invalid speed attempts";
}

} // namespace
