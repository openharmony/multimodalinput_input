/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "mouse_event_interface.h"
#include "pointer_event.h"
#include "libinput.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;

constexpr int32_t TEST_DEVICE_ID = 1;
constexpr int32_t TEST_DEVICE_ID_2 = 2;
constexpr int32_t TEST_DEVICE_ID_INVALID = -1;
constexpr int32_t TEST_X = 100;
constexpr int32_t TEST_Y = 200;
constexpr int32_t TEST_X_2 = 300;
constexpr int32_t TEST_Y_2 = 400;
constexpr int32_t TEST_DISPLAY_ID = 0;
constexpr int32_t TEST_DISPLAY_ID_2 = 1;
constexpr int32_t TEST_ROWS = 3;
constexpr int32_t TEST_ROWS_2 = 5;
constexpr int32_t TEST_SPEED = 5;
constexpr int32_t TEST_SPEED_2 = 8;
constexpr int32_t TEST_SPEED_MIN = 0;
constexpr int32_t TEST_SPEED_MAX = 20;
constexpr int32_t TEST_PID = 1234;
constexpr int32_t TEST_PID_2 = 5678;
constexpr int32_t TEST_PRIMARY_BUTTON_LEFT = 1;
constexpr int32_t TEST_PRIMARY_BUTTON_RIGHT = 2;
constexpr int32_t TEST_PRIMARY_BUTTON_MIDDLE = 3;
constexpr int32_t TEST_TYPE_SINGLE = 1;
constexpr int32_t TEST_TYPE_DOUBLE = 2;
constexpr double TEST_ANGLE = 90.0;
constexpr double TEST_ANGLE_45 = 45.0;
constexpr double TEST_ANGLE_180 = 180.0;
constexpr int32_t TEST_OFFSET_X = 10;
constexpr int32_t TEST_OFFSET_Y = 20;
constexpr int32_t TEST_OFFSET_X_NEG = -15;
constexpr int32_t TEST_OFFSET_Y_NEG = -25;
constexpr uint32_t TEST_BTN_CODE_LEFT = 0x110;
constexpr uint32_t TEST_BTN_CODE_RIGHT = 0x111;
constexpr uint32_t TEST_BTN_CODE_MIDDLE = 0x112;
constexpr uint32_t TEST_BTN_CODE_SIDE = 0x113;
constexpr uint32_t TEST_BTN_CODE_EXTRA = 0x114;
constexpr int32_t TEST_FD = 1;
constexpr int32_t TEST_FD_2 = 2;
constexpr int32_t TEST_REPEAT_COUNT = 3;
} // namespace

class MouseEventInterfaceTest : public testing::Test {
protected:
    void SetUp() override
    {
        mouseInterface_ = MouseEventInterface::GetInstance();
        ASSERT_NE(mouseInterface_, nullptr);
    }

    void TearDown() override
    {
        mouseInterface_.reset();
    }

    std::shared_ptr<MouseEventInterface> mouseInterface_;
};

/**
 * @tc.name: TestGetInstance_001
 * @tc.desc: Test GetInstance returns same instance
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetInstance_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto instance1 = MouseEventInterface::GetInstance();
    auto instance2 = MouseEventInterface::GetInstance();
    
    ASSERT_NE(instance1, nullptr);
    ASSERT_NE(instance2, nullptr);
    EXPECT_EQ(instance1.get(), instance2.get());
}

/**
 * @tc.name: TestHasMouse_001
 * @tc.desc: Test HasMouse returns false when module not loaded
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestHasMouse_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = mouseInterface_->HasMouse();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestOnEvent_001
 * @tc.desc: Test OnEvent with null event returns error
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestOnEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->OnEvent(nullptr);
    EXPECT_EQ(ret, RET_ERR);
}


/**
 * @tc.name: TestGetPointerEvent_001
 * @tc.desc: Test GetPointerEvent returns null when module not loaded
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto ret = mouseInterface_->GetPointerEvent();
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: TestGetPointerEventWithId_001
 * @tc.desc: Test GetPointerEvent with valid device id
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetPointerEventWithId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto ret = mouseInterface_->GetPointerEvent(TEST_DEVICE_ID);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: TestGetPointerEventWithId_002
 * @tc.desc: Test GetPointerEvent with different device ids
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetPointerEventWithId_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> deviceIds = {TEST_DEVICE_ID, TEST_DEVICE_ID_2, TEST_DEVICE_ID_INVALID};
    for (auto id : deviceIds) {
        auto ret = mouseInterface_->GetPointerEvent(id);
        EXPECT_EQ(ret, nullptr);
    }
}

/**
 * @tc.name: TestDump_001
 * @tc.desc: Test Dump with empty args
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestDump_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args;
    mouseInterface_->Dump(TEST_FD, args);
    SUCCEED();
}

/**
 * @tc.name: TestDump_002
 * @tc.desc: Test Dump with verbose args
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestDump_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"--verbose"};
    mouseInterface_->Dump(TEST_FD, args);
    SUCCEED();
}

/**
 * @tc.name: TestDump_003
 * @tc.desc: Test Dump with help args
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestDump_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"--help"};
    mouseInterface_->Dump(TEST_FD, args);
    SUCCEED();
}

/**
 * @tc.name: TestDump_004
 * @tc.desc: Test Dump with different file descriptors
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestDump_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> args = {"--verbose"};
    std::vector<int32_t> fds = {TEST_FD, TEST_FD_2, 0};
    for (auto fd : fds) {
        mouseInterface_->Dump(fd, args);
    }
    SUCCEED();
}

/**
 * @tc.name: TestNormalizeRotateEvent_001
 * @tc.desc: Test NormalizeRotateEvent with null event
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestNormalizeRotateEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->NormalizeRotateEvent(nullptr, 0, TEST_ANGLE);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestNormalizeRotateEvent_002
 * @tc.desc: Test NormalizeRotateEvent with different angles
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestNormalizeRotateEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<double> angles = {TEST_ANGLE, TEST_ANGLE_45, TEST_ANGLE_180};
    for (auto angle : angles) {
        int32_t ret = mouseInterface_->NormalizeRotateEvent(nullptr, 0, angle);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: TestNormalizeRotateEvent_003
 * @tc.desc: Test NormalizeRotateEvent with different types
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestNormalizeRotateEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> types = {0, 1, 2, 3};
    for (auto type : types) {
        int32_t ret = mouseInterface_->NormalizeRotateEvent(nullptr, type, TEST_ANGLE);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: TestCheckAndPackageAxisEvent_001
 * @tc.desc: Test CheckAndPackageAxisEvent with null event
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestCheckAndPackageAxisEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = mouseInterface_->CheckAndPackageAxisEvent(nullptr);
    EXPECT_FALSE(ret);
}

#ifdef OHOS_BUILD_MOUSE_REPORTING_RATE
/**
 * @tc.name: TestCheckFilterMouseEvent_001
 * @tc.desc: Test CheckFilterMouseEvent with null event
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestCheckFilterMouseEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = mouseInterface_->CheckFilterMouseEvent(nullptr);
    EXPECT_FALSE(ret);
}

#endif

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
/**
 * @tc.name: TestNormalizeMoveMouse_001
 * @tc.desc: Test NormalizeMoveMouse with positive offsets
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestNormalizeMoveMouse_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = mouseInterface_->NormalizeMoveMouse(TEST_OFFSET_X, TEST_OFFSET_Y);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestNormalizeMoveMouse_002
 * @tc.desc: Test NormalizeMoveMouse with negative offsets
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestNormalizeMoveMouse_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = mouseInterface_->NormalizeMoveMouse(TEST_OFFSET_X_NEG, TEST_OFFSET_Y_NEG);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestOnDisplayLost_001
 * @tc.desc: Test OnDisplayLost with valid display id
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestOnDisplayLost_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseInterface_->OnDisplayLost(TEST_DISPLAY_ID);
    SUCCEED();
}

/**
 * @tc.name: TestOnDisplayLost_002
 * @tc.desc: Test OnDisplayLost with different display ids
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestOnDisplayLost_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> displayIds = {TEST_DISPLAY_ID, TEST_DISPLAY_ID_2};
    for (auto id : displayIds) {
        mouseInterface_->OnDisplayLost(id);
    }
    SUCCEED();
}

/**
 * @tc.name: TestGetDisplayId_001
 * @tc.desc: Test GetDisplayId returns error when module not loaded
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetDisplayId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->GetDisplayId();
    EXPECT_EQ(ret, RET_ERR);
}
#endif

/**
 * @tc.name: TestSetPointerLocation_001
 * @tc.desc: Test SetPointerLocation with valid coordinates
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetPointerLocation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetPointerLocation(TEST_X, TEST_Y, TEST_DISPLAY_ID);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetMouseAccelerateMotionSwitch_001
 * @tc.desc: Test SetMouseAccelerateMotionSwitch with enable true
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetMouseAccelerateMotionSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetMouseAccelerateMotionSwitch(TEST_DEVICE_ID, true);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetMouseAccelerateMotionSwitch_002
 * @tc.desc: Test SetMouseAccelerateMotionSwitch with enable false
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetMouseAccelerateMotionSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetMouseAccelerateMotionSwitch(TEST_DEVICE_ID, false);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetMouseScrollRows_001
 * @tc.desc: Test SetMouseScrollRows with valid rows
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetMouseScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetMouseScrollRows(TEST_ROWS);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetMouseScrollRows_002
 * @tc.desc: Test SetMouseScrollRows with different values
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetMouseScrollRows_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> rowsList = {TEST_ROWS, TEST_ROWS_2, 0, 10};
    for (auto rows : rowsList) {
        int32_t ret = mouseInterface_->SetMouseScrollRows(rows);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: TestGetMouseScrollRows_001
 * @tc.desc: Test GetMouseScrollRows returns error without context
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetMouseScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->GetMouseScrollRows();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetMousePrimaryButton_001
 * @tc.desc: Test SetMousePrimaryButton with left button
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetMousePrimaryButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetMousePrimaryButton(TEST_PRIMARY_BUTTON_LEFT);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetMousePrimaryButton_002
 * @tc.desc: Test SetMousePrimaryButton with right button
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetMousePrimaryButton_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetMousePrimaryButton(TEST_PRIMARY_BUTTON_RIGHT);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetMousePrimaryButton_003
 * @tc.desc: Test SetMousePrimaryButton with middle button
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetMousePrimaryButton_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetMousePrimaryButton(TEST_PRIMARY_BUTTON_MIDDLE);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestGetMousePrimaryButton_001
 * @tc.desc: Test GetMousePrimaryButton returns error without context
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetMousePrimaryButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->GetMousePrimaryButton();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetPointerSpeed_001
 * @tc.desc: Test SetPointerSpeed with valid speed
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetPointerSpeed(TEST_SPEED);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetPointerSpeed_002
 * @tc.desc: Test SetPointerSpeed with different speeds
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetPointerSpeed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> speeds = {TEST_SPEED, TEST_SPEED_2, TEST_SPEED_MIN, TEST_SPEED_MAX};
    for (auto speed : speeds) {
        int32_t ret = mouseInterface_->SetPointerSpeed(speed);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: TestGetPointerSpeed_001
 * @tc.desc: Test GetPointerSpeed returns error without context
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->GetPointerSpeed();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestGetTouchpadSpeed_001
 * @tc.desc: Test GetTouchpadSpeed returns error without context
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetTouchpadSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->GetTouchpadSpeed();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetTouchpadScrollSwitch_001
 * @tc.desc: Test SetTouchpadScrollSwitch with enable true
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetTouchpadScrollSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetTouchpadScrollSwitch(TEST_PID, true);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetTouchpadScrollSwitch_002
 * @tc.desc: Test SetTouchpadScrollSwitch with enable false
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetTouchpadScrollSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetTouchpadScrollSwitch(TEST_PID, false);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetTouchpadScrollSwitch_003
 * @tc.desc: Test SetTouchpadScrollSwitch with different pids
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetTouchpadScrollSwitch_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> pids = {TEST_PID, TEST_PID_2, 0};
    for (auto pid : pids) {
        int32_t ret = mouseInterface_->SetTouchpadScrollSwitch(pid, true);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: TestGetTouchpadScrollSwitch_001
 * @tc.desc: Test GetTouchpadScrollSwitch without context
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetTouchpadScrollSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    mouseInterface_->GetTouchpadScrollSwitch(flag);
    SUCCEED();
}

/**
 * @tc.name: TestSetTouchpadScrollDirection_001
 * @tc.desc: Test SetTouchpadScrollDirection with true
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetTouchpadScrollDirection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetTouchpadScrollDirection(true);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetTouchpadScrollDirection_002
 * @tc.desc: Test SetTouchpadScrollDirection with false
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetTouchpadScrollDirection_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetTouchpadScrollDirection(false);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestGetTouchpadScrollDirection_001
 * @tc.desc: Test GetTouchpadScrollDirection without context
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetTouchpadScrollDirection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool state = false;
    mouseInterface_->GetTouchpadScrollDirection(state);
    SUCCEED();
}

/**
 * @tc.name: TestSetTouchpadTapSwitch_001
 * @tc.desc: Test SetTouchpadTapSwitch with enable true
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetTouchpadTapSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetTouchpadTapSwitch(true);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetTouchpadTapSwitch_002
 * @tc.desc: Test SetTouchpadTapSwitch with enable false
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetTouchpadTapSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetTouchpadTapSwitch(false);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestGetTouchpadTapSwitch_001
 * @tc.desc: Test GetTouchpadTapSwitch without context
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetTouchpadTapSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    mouseInterface_->GetTouchpadTapSwitch(flag);
    SUCCEED();
}

/**
 * @tc.name: TestSetTouchpadRightClickType_001
 * @tc.desc: Test SetTouchpadRightClickType with single click
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetTouchpadRightClickType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetTouchpadRightClickType(TEST_TYPE_SINGLE);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetTouchpadRightClickType_002
 * @tc.desc: Test SetTouchpadRightClickType with double click
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetTouchpadRightClickType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetTouchpadRightClickType(TEST_TYPE_DOUBLE);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestGetTouchpadRightClickType_001
 * @tc.desc: Test GetTouchpadRightClickType without context
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetTouchpadRightClickType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t type = 0;
    mouseInterface_->GetTouchpadRightClickType(type);
    SUCCEED();
}

/**
 * @tc.name: TestSetTouchpadPointerSpeed_001
 * @tc.desc: Test SetTouchpadPointerSpeed with valid speed
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetTouchpadPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->SetTouchpadPointerSpeed(TEST_SPEED);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetTouchpadPointerSpeed_002
 * @tc.desc: Test SetTouchpadPointerSpeed with different speeds
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetTouchpadPointerSpeed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> speeds = {TEST_SPEED, TEST_SPEED_2, TEST_SPEED_MIN, TEST_SPEED_MAX};
    for (auto speed : speeds) {
        int32_t ret = mouseInterface_->SetTouchpadPointerSpeed(speed);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: TestGetTouchpadPointerSpeed_001
 * @tc.desc: Test GetTouchpadPointerSpeed without context
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetTouchpadPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t speed = 0;
    mouseInterface_->GetTouchpadPointerSpeed(speed);
    SUCCEED();
}

/**
 * @tc.name: TestReadTouchpadCDG_001
 * @tc.desc: Test ReadTouchpadCDG without module
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestReadTouchpadCDG_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchpadCDG cdg;
    mouseInterface_->ReadTouchpadCDG(cdg);
    SUCCEED();
}

/**
 * @tc.name: TestGetMouseCoordsX_001
 * @tc.desc: Test GetMouseCoordsX returns error without module
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetMouseCoordsX_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->GetMouseCoordsX();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestGetMouseCoordsY_001
 * @tc.desc: Test GetMouseCoordsY returns error without module
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetMouseCoordsY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->GetMouseCoordsY();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestSetMouseCoords_001
 * @tc.desc: Test SetMouseCoords with valid coordinates
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetMouseCoords_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseInterface_->SetMouseCoords(TEST_X, TEST_Y);
    SUCCEED();
}

/**
 * @tc.name: TestSetMouseCoords_002
 * @tc.desc: Test SetMouseCoords with different coordinates
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestSetMouseCoords_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::pair<int32_t, int32_t>> coords = {
        {TEST_X, TEST_Y},
        {TEST_X_2, TEST_Y_2},
        {0, 0}
    };
    for (auto [x, y] : coords) {
        mouseInterface_->SetMouseCoords(x, y);
    }
    SUCCEED();
}

/**
 * @tc.name: TestIsLeftBtnPressed_001
 * @tc.desc: Test IsLeftBtnPressed returns false without module
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestIsLeftBtnPressed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool ret = mouseInterface_->IsLeftBtnPressed();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TestGetPressedButtons_001
 * @tc.desc: Test GetPressedButtons returns empty vector without module
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestGetPressedButtons_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> buttons;
    mouseInterface_->GetPressedButtons(buttons);
    EXPECT_TRUE(buttons.empty());
}

/**
 * @tc.name: TestMouseBtnStateCounts_001
 * @tc.desc: Test MouseBtnStateCounts with left button pressed
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestMouseBtnStateCounts_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseInterface_->MouseBtnStateCounts(TEST_BTN_CODE_LEFT, BUTTON_STATE_PRESSED);
    SUCCEED();
}

/**
 * @tc.name: TestMouseBtnStateCounts_002
 * @tc.desc: Test MouseBtnStateCounts with right button pressed
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestMouseBtnStateCounts_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseInterface_->MouseBtnStateCounts(TEST_BTN_CODE_RIGHT, BUTTON_STATE_PRESSED);
    SUCCEED();
}

/**
 * @tc.name: TestMouseBtnStateCounts_003
 * @tc.desc: Test MouseBtnStateCounts with middle button pressed
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestMouseBtnStateCounts_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseInterface_->MouseBtnStateCounts(TEST_BTN_CODE_MIDDLE, BUTTON_STATE_PRESSED);
    SUCCEED();
}

/**
 * @tc.name: TestMouseBtnStateCounts_004
 * @tc.desc: Test MouseBtnStateCounts with side button pressed
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestMouseBtnStateCounts_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseInterface_->MouseBtnStateCounts(TEST_BTN_CODE_SIDE, BUTTON_STATE_PRESSED);
    SUCCEED();
}

/**
 * @tc.name: TestMouseBtnStateCounts_005
 * @tc.desc: Test MouseBtnStateCounts with extra button pressed
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestMouseBtnStateCounts_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseInterface_->MouseBtnStateCounts(TEST_BTN_CODE_EXTRA, BUTTON_STATE_PRESSED);
    SUCCEED();
}

/**
 * @tc.name: TestMouseBtnStateCounts_006
 * @tc.desc: Test MouseBtnStateCounts with left button released
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestMouseBtnStateCounts_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseInterface_->MouseBtnStateCounts(TEST_BTN_CODE_LEFT, BUTTON_STATE_RELEASED);
    SUCCEED();
}

/**
 * @tc.name: TestLibinputChangeToPointer_001
 * @tc.desc: Test LibinputChangeToPointer with left button
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestLibinputChangeToPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->LibinputChangeToPointer(TEST_BTN_CODE_LEFT);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestLibinputChangeToPointer_002
 * @tc.desc: Test LibinputChangeToPointer with right button
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestLibinputChangeToPointer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t ret = mouseInterface_->LibinputChangeToPointer(TEST_BTN_CODE_RIGHT);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: TestLibinputChangeToPointer_003
 * @tc.desc: Test LibinputChangeToPointer with different button codes
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestLibinputChangeToPointer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<uint32_t> btnCodes = {
        TEST_BTN_CODE_LEFT,
        TEST_BTN_CODE_RIGHT,
        TEST_BTN_CODE_MIDDLE,
        TEST_BTN_CODE_SIDE,
        TEST_BTN_CODE_EXTRA
    };
    for (auto code : btnCodes) {
        int32_t ret = mouseInterface_->LibinputChangeToPointer(code);
        EXPECT_EQ(ret, RET_ERR);
    }
}

/**
 * @tc.name: TestLoadMouseExplicitly_001
 * @tc.desc: Test LoadMouseExplicitly once
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestLoadMouseExplicitly_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseInterface_->LoadMouseExplicitly();
    SUCCEED();
}

/**
 * @tc.name: TestLoadMouseExplicitly_002
 * @tc.desc: Test LoadMouseExplicitly multiple times
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestLoadMouseExplicitly_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    for (int32_t i = 0; i < TEST_REPEAT_COUNT; i++) {
        mouseInterface_->LoadMouseExplicitly();
    }
    SUCCEED();
}

/**
 * @tc.name: TestAttachInputServiceContext_001
 * @tc.desc: Test AttachInputServiceContext with null context
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestAttachInputServiceContext_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseInterface_->AttachInputServiceContext(nullptr);
    SUCCEED();
}

/**
 * @tc.name: TestDestructor_001
 * @tc.desc: Test MouseEventInterface destructor
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestDestructor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto instance = std::make_shared<MouseEventInterface>();
    EXPECT_NE(instance, nullptr);
    instance.reset();
    SUCCEED();
}

/**
 * @tc.name: TestMouseEventHdr_001
 * @tc.desc: Test MouseEventHdr macro returns valid instance
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestMouseEventHdr_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto instance = MouseEventHdr;
    ASSERT_NE(instance, nullptr);
}

/**
 * @tc.name: TestMultipleCalls_001
 * @tc.desc: Test multiple different calls in sequence
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestMultipleCalls_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(mouseInterface_->HasMouse());
    EXPECT_EQ(mouseInterface_->OnEvent(nullptr), RET_ERR);
    EXPECT_EQ(mouseInterface_->GetPointerEvent(), nullptr);
    EXPECT_EQ(mouseInterface_->SetMouseScrollRows(TEST_ROWS), RET_ERR);
    EXPECT_EQ(mouseInterface_->SetPointerSpeed(TEST_SPEED), RET_ERR);
    EXPECT_EQ(mouseInterface_->GetMouseCoordsX(), RET_ERR);
    EXPECT_FALSE(mouseInterface_->IsLeftBtnPressed());
    SUCCEED();
}

/**
 * @tc.name: TestMultipleCalls_002
 * @tc.desc: Test multiple touchpad settings in sequence
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestMultipleCalls_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(mouseInterface_->GetTouchpadSpeed(), RET_ERR);
    EXPECT_EQ(mouseInterface_->SetTouchpadScrollSwitch(TEST_PID, true), RET_ERR);
    EXPECT_EQ(mouseInterface_->SetTouchpadScrollDirection(true), RET_ERR);
    EXPECT_EQ(mouseInterface_->SetTouchpadTapSwitch(true), RET_ERR);
    EXPECT_EQ(mouseInterface_->SetTouchpadRightClickType(TEST_TYPE_SINGLE), RET_ERR);
    EXPECT_EQ(mouseInterface_->SetTouchpadPointerSpeed(TEST_SPEED), RET_ERR);
    SUCCEED();
}

/**
 * @tc.name: TestMultipleCalls_003
 * @tc.desc: Test multiple button state calls in sequence
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestMultipleCalls_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseInterface_->MouseBtnStateCounts(TEST_BTN_CODE_LEFT, BUTTON_STATE_PRESSED);
    mouseInterface_->MouseBtnStateCounts(TEST_BTN_CODE_RIGHT, BUTTON_STATE_PRESSED);
    mouseInterface_->MouseBtnStateCounts(TEST_BTN_CODE_LEFT, BUTTON_STATE_RELEASED);
    mouseInterface_->MouseBtnStateCounts(TEST_BTN_CODE_RIGHT, BUTTON_STATE_RELEASED);
    
    SUCCEED();
}

/**
 * @tc.name: TestMultipleCalls_004
 * @tc.desc: Test multiple coordinate calls in sequence
 * @tc.type: FUNC
 */
HWTEST_F(MouseEventInterfaceTest, TestMultipleCalls_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    mouseInterface_->SetMouseCoords(TEST_X, TEST_Y);
    mouseInterface_->SetMouseCoords(TEST_X_2, TEST_Y_2);
    EXPECT_EQ(mouseInterface_->GetMouseCoordsX(), RET_ERR);
    EXPECT_EQ(mouseInterface_->GetMouseCoordsY(), RET_ERR);
    SUCCEED();
}
} // namespace MMI
} // namespace OHOS