/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>
#include "window_switch.h"
#include "error_multimodal.h"

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "WindowSwitchTest" };

class WindowSwitchTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(WindowSwitchTest, SetSize, TestSize.Level1)
{
    size_t size = 1;
    WindowSwitch winSwitch;

    winSwitch.SetSize(size);
    EXPECT_TRUE((winSwitch.GetSize()) == size);
}

HWTEST_F(WindowSwitchTest, SetSize_001, TestSize.Level1)
{
    size_t size = 0;
    WindowSwitch winSwitch;

    winSwitch.SetSize(size);
    EXPECT_TRUE((winSwitch.GetSize()) == size);
}

HWTEST_F(WindowSwitchTest, SetSize_002, TestSize.Level1)
{
    size_t size = 1000000;
    WindowSwitch winSwitch;

    winSwitch.SetSize(size);
    EXPECT_TRUE((winSwitch.GetSize()) == size);
}

HWTEST_F(WindowSwitchTest, SetSurfaceId, TestSize.Level1)
{
    size_t windowId = 1;
    WindowSwitch winSwitch;

    winSwitch.SetSurfaceId(windowId);
}

HWTEST_F(WindowSwitchTest, SetSurfaceId_001, TestSize.Level1)
{
    size_t windowId = 0;
    WindowSwitch winSwitch;

    winSwitch.SetSurfaceId(windowId);
}

HWTEST_F(WindowSwitchTest, SetSurfaceId_002, TestSize.Level1)
{
    size_t windowId = 100000;
    WindowSwitch winSwitch;

    winSwitch.SetSurfaceId(windowId);
}

HWTEST_F(WindowSwitchTest, GetEventPointer, TestSize.Level1)
{
    WindowSwitch winSwitch;

    winSwitch.GetEventPointer();
}

HWTEST_F(WindowSwitchTest, SetPointerByButton, TestSize.Level1)
{
    WindowSwitch winSwitch;

    EventPointer point = {};
    CHK(EOK == memcpy_s(point.deviceName, MAX_DEVICENAME, "deviceName", MAX_DEVICENAME), OHOS::MEMCPY_SEC_FUN_FAIL);
    CHK(EOK == memcpy_s(point.devicePhys, MAX_DEVICENAME, "HOS_mouse", MAX_DEVICENAME), OHOS::MEMCPY_SEC_FUN_FAIL);

    winSwitch.SetPointerByButton(point);
}

HWTEST_F(WindowSwitchTest, SetPointerByMotion_001, TestSize.Level1)
{
    WindowSwitch winSwitch;

    EventPointer point = {};
    CHK(EOK == memcpy_s(point.deviceName, MAX_DEVICENAME, "deviceName", MAX_DEVICENAME), OHOS::MEMCPY_SEC_FUN_FAIL);
    CHK(EOK == memcpy_s(point.devicePhys, MAX_DEVICENAME, "HOS_mouse", MAX_DEVICENAME), OHOS::MEMCPY_SEC_FUN_FAIL);

    point.delta_raw.x = DEF_SCREEN_MAX_WIDTH;
    point.delta_raw.y = DEF_SCREEN_MAX_WIDTH;
    winSwitch.SetPointerByMotion(point);
}

HWTEST_F(WindowSwitchTest, SetPointerByMotion_002, TestSize.Level1)
{
    WindowSwitch winSwitch;

    EventPointer point = {};
    CHK(EOK == memcpy_s(point.deviceName, MAX_DEVICENAME, "deviceName", MAX_DEVICENAME), OHOS::MEMCPY_SEC_FUN_FAIL);
    CHK(EOK == memcpy_s(point.devicePhys, MAX_DEVICENAME, "HOS_mouse", MAX_DEVICENAME), OHOS::MEMCPY_SEC_FUN_FAIL);

    point.delta_raw.x = -1;
    point.delta_raw.y = -1;
    winSwitch.SetPointerByMotion(point);
}

HWTEST_F(WindowSwitchTest, SetPointerByAbsMotion, TestSize.Level1)
{
    WindowSwitch winSwitch;

    EventPointer point = {};
    CHK(EOK == memcpy_s(point.deviceName, MAX_DEVICENAME, "deviceName", MAX_DEVICENAME), OHOS::MEMCPY_SEC_FUN_FAIL);
    CHK(EOK == memcpy_s(point.devicePhys, MAX_DEVICENAME, "HOS_mouse", MAX_DEVICENAME), OHOS::MEMCPY_SEC_FUN_FAIL);

    winSwitch.SetPointerByAbsMotion(point);
}

HWTEST_F(WindowSwitchTest, SetPointerByTouch, TestSize.Level1)
{
    WindowSwitch winSwitch;

    EventTouch touch = {};
    CHK(EOK == memcpy_s(touch.deviceName, MAX_DEVICENAME, "deviceName", MAX_DEVICENAME), OHOS::MEMCPY_SEC_FUN_FAIL);
    CHK(EOK == memcpy_s(touch.devicePhys, MAX_DEVICENAME, "HOS_mouse", MAX_DEVICENAME), OHOS::MEMCPY_SEC_FUN_FAIL);

    winSwitch.SetPointerByTouch(touch);
}
} // namespace
