/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <fstream>
#include <gmock/gmock.h>

#include "event_filter_handler.h"
#include "fingersense_wrapper.h"
#include "i_pointer_drawing_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "input_windows_manager.h"
#include "libinput_interface.h"
#include "mmi_log.h"
#include "mock_input_windows_manager.h"
#include "pixel_map.h"
#include "pointer_drawing_manager.h"
#include "proto.h"
#include "scene_board_judgement.h"
#include "struct_multimodal.h"
#include "uds_server.h"
#include "window_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputWindowsManagerOneTest"

using namespace OHOS::MMI;
using namespace OHOS::Media;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
MockInputWindowsManager *g_inputWindowManagerInterface;

MockInputWindowsManager::MockInputWindowsManager()
{
    g_inputWindowManagerInterface = this;
}

MockInputWindowsManager::~MockInputWindowsManager()
{
    g_inputWindowManagerInterface = nullptr;
}

static InputWindowsManagerInterface *GetInputWindowsManagerInterface()
{
    return g_inputWindowManagerInterface;
}

std::optional<WindowInfo> InputWindowsManager::GetWindowAndDisplayInfo(int32_t windowId, int32_t displayId)
{
    return GetInputWindowsManagerInterface()->GetWindowAndDisplayInfo(windowId, displayId);
}

bool Rosen::SceneBoardJudgement::IsSceneBoardEnabled()
{
    return GetInputWindowsManagerInterface()->IsSceneBoardEnabled();
}

namespace MMI {
namespace {
constexpr int32_t CAST_INPUT_DEVICEID{ 0xAAAAAAFF };
}

class InputWindowsManagerOneTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(void){};
    void SetDown(void){};
};

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
/* *
 * @tc.name: InputWindowsManagerOneTest_ScreenRotateAdjustDisplayXY_001
 * @tc.desc: Test the funcation ScreenRotateAdjustDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ScreenRotateAdjustDisplayXY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo info;
    info.direction = DIRECTION90;
    info.validWidth = 0;
    info.validHeight = 0;
    PhysicalCoordinate coord;
    coord.x = 1;
    coord.y = 0;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->cursorPos_.direction = Direction::DIRECTION0;
    NiceMock<MockInputWindowsManager> mockInputWindowsManager;
    EXPECT_CALL(mockInputWindowsManager, IsSceneBoardEnabled)
        .WillOnce(Return(false))
        .WillOnce(Return(false))
        .WillOnce(Return(true));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ScreenRotateAdjustDisplayXY(info, coord));

    coord.x = 1;
    coord.y = 0;
    info.direction = DIRECTION0;
    inputWindowsManager->cursorPos_.direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ScreenRotateAdjustDisplayXY(info, coord));

    coord.x = 1;
    coord.y = 0;
    info.direction = DIRECTION0;
    inputWindowsManager->cursorPos_.direction = Direction::DIRECTION90;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ScreenRotateAdjustDisplayXY(info, coord));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_RotateScreen_001
 * @tc.desc: Test the funcation RotateScreen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_RotateScreen_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo info;
    info.direction = DIRECTION0;
    info.displayDirection = Direction::DIRECTION0;
    info.validWidth = 0;
    info.validHeight = 0;
    PhysicalCoordinate coord;
    coord.x = 1;
    coord.y = 0;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->cursorPos_.direction = Direction::DIRECTION90;
    inputWindowsManager->cursorPos_.displayDirection = Direction::DIRECTION90;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(1);
    inputWindowsManager->UpdateTargetPointer(pointerEvent);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->RotateScreen(info, coord));

    coord.x = 0;
    coord.y = 1;
    inputWindowsManager->cursorPos_.direction = Direction::DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->RotateScreen(info, coord));

    coord.x = 0;
    coord.y = 1;
    inputWindowsManager->cursorPos_.direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->RotateScreen(info, coord));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_RotateScreen_002
 * @tc.desc: Test the funcation RotateScreen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_RotateScreen_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo info;
    info.direction = DIRECTION0;
    info.displayDirection = Direction::DIRECTION0;
    info.validWidth = 0;
    info.validHeight = 0;
    PhysicalCoordinate coord;
    coord.x = 1;
    coord.y = 0;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->cursorPos_.direction = Direction::DIRECTION90;
    inputWindowsManager->cursorPos_.displayDirection = Direction::DIRECTION90;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    pointerEvent->SetPointerAction(1);
    inputWindowsManager->UpdateTargetPointer(pointerEvent);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->RotateScreen(info, coord));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_TriggerTouchUpOnInvalidAreaEntry_001
 * @tc.desc: Test the funcation TriggerTouchUpOnInvalidAreaEntry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_TriggerTouchUpOnInvalidAreaEntry_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pointerId = 0;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    EXPECT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.canceled_ = false;
    item.pressed_ = true;
    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    pointerEvent->pointers_.push_back(item);
    pointerEvent->SetPointerId(pointerId);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    inputWindowsManager->lastPointerEventforGesture_ = pointerEvent;
    inputWindowsManager->extraData_.appended = true;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    inputWindowsManager->extraData_.pointerId = pointerId;
    WindowInfo windowInfo;
    windowInfo.agentWindowId = 1;
    NiceMock<MockInputWindowsManager> mockInputWindowsManager;
    EXPECT_CALL(mockInputWindowsManager, GetWindowAndDisplayInfo)
        .WillRepeatedly(Return(std::make_optional(windowInfo)));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TriggerTouchUpOnInvalidAreaEntry(pointerId));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_TriggerTouchUpOnInvalidAreaEntry_002
 * @tc.desc: Test the funcation TriggerTouchUpOnInvalidAreaEntry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_TriggerTouchUpOnInvalidAreaEntry_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pointerId = 0;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    EXPECT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.canceled_ = false;
    item.pressed_ = true;
    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    pointerEvent->pointers_.push_back(item);
    pointerEvent->SetPointerId(pointerId);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    inputWindowsManager->lastPointerEventforGesture_ = pointerEvent;
    inputWindowsManager->extraData_.appended = true;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    inputWindowsManager->extraData_.pointerId = pointerId + 1;
    WindowInfo windowInfo;
    windowInfo.agentWindowId = 1;
    NiceMock<MockInputWindowsManager> mockInputWindowsManager;
    EXPECT_CALL(mockInputWindowsManager, GetWindowAndDisplayInfo).WillRepeatedly(Return(std::nullopt));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TriggerTouchUpOnInvalidAreaEntry(pointerId));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_TriggerTouchUpOnInvalidAreaEntry_003
 * @tc.desc: Test the funcation TriggerTouchUpOnInvalidAreaEntry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_TriggerTouchUpOnInvalidAreaEntry_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pointerId = 0;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    EXPECT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.canceled_ = false;
    item.pressed_ = false;
    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    pointerEvent->pointers_.push_back(item);
    pointerEvent->SetPointerId(pointerId);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    inputWindowsManager->lastPointerEventforGesture_ = pointerEvent;
    inputWindowsManager->extraData_.appended = true;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    inputWindowsManager->extraData_.pointerId = pointerId + 1;
    WindowInfo windowInfo;
    windowInfo.agentWindowId = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TriggerTouchUpOnInvalidAreaEntry(pointerId));

    item.canceled_ = true;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TriggerTouchUpOnInvalidAreaEntry(pointerId));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_TouchPointToDisplayPoint_001
 * @tc.desc: Test the funcation TouchPointToDisplayPoint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_TouchPointToDisplayPoint_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 0;
    libinput_event_touch touch;
    EventTouch touchInfo;
    int32_t physicalDisplayId = 0;
    bool isNeedClear = false;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    EXPECT_FALSE(
        inputWindowsManager->TouchPointToDisplayPoint(deviceId, &touch, touchInfo, physicalDisplayId, isNeedClear));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_SelectWindowInfo_001
 * @tc.desc: Test the funcation SelectWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SelectWindowInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t logicalX = 0;
    int32_t logicalY = 0;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(-1);
    pointerEvent->SetTargetWindowId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.windowInputType = WindowInputType::TRANSMIT_ANTI_AXIS_MOVE;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    std::unique_ptr<Media::PixelMap> pixelMap = nullptr;
    inputWindowsManager->transparentWins_.insert_or_assign(windowInfo.id, std::move(pixelMap));

    std::optional<WindowInfo> result = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_FALSE(result.has_value());
}

/* *
 * @tc.name: InputWindowsManagerOneTest_SelectWindowInfo_002
 * @tc.desc: Test the funcation SelectWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SelectWindowInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t logicalX = 0;
    int32_t logicalY = 0;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(-1);
    pointerEvent->SetTargetWindowId(1);
    pointerEvent->SetPointerAction(PointerEvent::NORMAL);
    pointerEvent->SetDeviceId(CAST_INPUT_DEVICEID);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.windowInputType = WindowInputType::NORMAL;
    windowInfo.isSkipSelfWhenShowOnVirtualScreen = true;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionserver_ = true;
    inputWindowsManager->privacyProtection_.isOpen = true;
    std::unique_ptr<Media::PixelMap> pixelMap = nullptr;
    inputWindowsManager->transparentWins_.insert_or_assign(windowInfo.id, std::move(pixelMap));

    std::optional<WindowInfo> result = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_FALSE(result.has_value());
}

/* *
 * @tc.name: InputWindowsManagerOneTest_SelectWindowInfo_003
 * @tc.desc: Test the funcation SelectWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SelectWindowInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t logicalX = 10;
    int32_t logicalY = 20;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(-1);
    pointerEvent->SetTargetWindowId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    pointerEvent->SetDeviceId(CAST_INPUT_DEVICEID);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.pointerHotAreas = { { 0, 0, 30, 40 } };
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    windowInfo.isSkipSelfWhenShowOnVirtualScreen = true;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionserver_ = true;
    inputWindowsManager->privacyProtection_.isOpen = false;
    inputWindowsManager->extraData_.appended = true;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    std::unique_ptr<Media::PixelMap> pixelMap = nullptr;
    inputWindowsManager->transparentWins_.insert_or_assign(windowInfo.id, std::move(pixelMap));

    std::optional<WindowInfo> result = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_FALSE(result.has_value());
}

/* *
 * @tc.name: InputWindowsManagerOneTest_SelectWindowInfo_004
 * @tc.desc: Test the funcation SelectWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SelectWindowInfo_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t logicalX = 10;
    int32_t logicalY = 20;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(-1);
    pointerEvent->SetTargetWindowId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    pointerEvent->SetDeviceId(CAST_INPUT_DEVICEID);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.pointerHotAreas = { { 0, 0, 30, 40 } };
    windowInfo.windowInputType = WindowInputType::NORMAL;
    windowInfo.isSkipSelfWhenShowOnVirtualScreen = true;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionserver_ = true;
    inputWindowsManager->privacyProtection_.isOpen = false;
    inputWindowsManager->extraData_.appended = true;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    std::unique_ptr<Media::PixelMap> pixelMap = nullptr;
    inputWindowsManager->transparentWins_.insert_or_assign(windowInfo.id, std::move(pixelMap));

    std::optional<WindowInfo> result = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_TRUE(result.has_value());
}

/* *
 * @tc.name: InputWindowsManagerOneTest_SelectWindowInfo_005
 * @tc.desc: Test the funcation SelectWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SelectWindowInfo_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t logicalX = 10;
    int32_t logicalY = 20;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(-1);
    pointerEvent->SetTargetWindowId(-1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_END);
    pointerEvent->SetDeviceId(CAST_INPUT_DEVICEID);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.pointerHotAreas = { { 0, 0, 30, 40 } };
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    windowInfo.isSkipSelfWhenShowOnVirtualScreen = true;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionserver_ = true;
    inputWindowsManager->privacyProtection_.isOpen = false;
    inputWindowsManager->extraData_.appended = false;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    std::unique_ptr<Media::PixelMap> pixelMap = nullptr;
    inputWindowsManager->transparentWins_.insert_or_assign(windowInfo.id, std::move(pixelMap));

    std::optional<WindowInfo> result = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_FALSE(result.has_value());

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    pointerEvent->pressedButtons_.insert(1);
    Rect rect{
        .x = 100,
        .y = 100,
        .width = 300,
        .height = 300,
    };
    WindowInfo winInfo;
    winInfo.id = 50;
    winInfo.defaultHotAreas.push_back(rect);
    windowInfo.uiExtentionWindowInfo.push_back(winInfo);
    inputWindowsManager->displayGroupInfo_.windowsInfo.clear();
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    std::optional<WindowInfo> result1 = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_TRUE(result1.has_value());
}

/* *
 * @tc.name: InputWindowsManagerOneTest_SelectWindowInfo_006
 * @tc.desc: Test the funcation SelectWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SelectWindowInfo_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t logicalX = 10;
    int32_t logicalY = 20;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(-1);
    pointerEvent->SetTargetWindowId(-1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    pointerEvent->SetDeviceId(CAST_INPUT_DEVICEID);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.pointerHotAreas = { { 0, 0, 30, 40 } };
    windowInfo.windowInputType = WindowInputType::NORMAL;
    windowInfo.isSkipSelfWhenShowOnVirtualScreen = true;
    windowInfo.uiExtentionWindowInfo.clear();
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionserver_ = true;
    inputWindowsManager->privacyProtection_.isOpen = false;
    inputWindowsManager->extraData_.appended = false;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    std::unique_ptr<Media::PixelMap> pixelMap = nullptr;
    inputWindowsManager->transparentWins_.insert_or_assign(windowInfo.id, std::move(pixelMap));

    std::optional<WindowInfo> result = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_TRUE(result.has_value());
}

/* *
 * @tc.name: InputWindowsManagerOneTest_SelectWindowInfo_007
 * @tc.desc: Test the funcation SelectWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SelectWindowInfo_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t logicalX = 10;
    int32_t logicalY = 20;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(-1);
    pointerEvent->SetTargetWindowId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    pointerEvent->SetDeviceId(CAST_INPUT_DEVICEID);
    pointerEvent->SetButtonId(PointerEvent::MOUSE_BUTTON_LEFT);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.pointerHotAreas = { { 0, 0, 30, 40 } };
    windowInfo.windowInputType = WindowInputType::NORMAL;
    windowInfo.isSkipSelfWhenShowOnVirtualScreen = true;
    windowInfo.uiExtentionWindowInfo.clear();
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionserver_ = true;
    inputWindowsManager->privacyProtection_.isOpen = false;
    inputWindowsManager->extraData_.appended = false;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    std::unique_ptr<Media::PixelMap> pixelMap = nullptr;
    inputWindowsManager->transparentWins_.insert_or_assign(windowInfo.id, std::move(pixelMap));

    std::optional<WindowInfo> result = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_TRUE(result.has_value());
}

/* *
 * @tc.name: InputWindowsManagerOneTest_SelectWindowInfo_008
 * @tc.desc: Test the funcation SelectWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SelectWindowInfo_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t logicalX = 10;
    int32_t logicalY = 20;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pressedButtons_.insert(1);
    pointerEvent->SetTargetDisplayId(-1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    WindowInfo info;
    info.id = 1;
    info.windowInputType = WindowInputType::TRANSMIT_ANTI_AXIS_MOVE;

    WindowInfo windowInfo;
    windowInfo.id = 1;
    info.uiExtentionWindowInfo.push_back(windowInfo);
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(info);
    inputWindowsManager->extraData_.appended = false;
    inputWindowsManager->firstBtnDownWindowInfo_.first = 1;
    WindowInfo beginWindowInfo;
    beginWindowInfo.id = 1;
    inputWindowsManager->axisBeginWindowInfo_ = beginWindowInfo;
    std::optional<WindowInfo> result = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_TRUE(result.has_value());
}

/* *
 * @tc.name: InputWindowsManagerOneTest_SelectWindowInfo_009
 * @tc.desc: Test the funcation SelectWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SelectWindowInfo_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t logicalX = 10;
    int32_t logicalY = 20;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pressedButtons_.insert(1);
    pointerEvent->SetTargetDisplayId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    WindowInfo info;
    info.id = 0;
    info.windowInputType = WindowInputType::TRANSMIT_ANTI_AXIS_MOVE;

    WindowInfo windowInfo;
    windowInfo.id = 0;
    info.uiExtentionWindowInfo.push_back(windowInfo);
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(info);
    inputWindowsManager->extraData_.appended = false;
    inputWindowsManager->firstBtnDownWindowInfo_.first = 1;
    inputWindowsManager->firstBtnDownWindowInfo_.second = -1;
    WindowInfo beginWindowInfo;
    beginWindowInfo.id = 1;
    inputWindowsManager->axisBeginWindowInfo_ = beginWindowInfo;
    std::optional<WindowInfo> result = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_FALSE(result.has_value());
}

/* *
 * @tc.name: InputWindowsManagerOneTest_SelectWindowInfo_010
 * @tc.desc: Test the funcation SelectWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SelectWindowInfo_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t logicalX = 10;
    int32_t logicalY = 20;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pressedButtons_.insert(1);
    pointerEvent->SetTargetDisplayId(-1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    WindowInfo info;
    info.id = 0;
    info.windowInputType = WindowInputType::TRANSMIT_ANTI_AXIS_MOVE;

    WindowInfo windowInfo;
    windowInfo.id = -1;
    info.uiExtentionWindowInfo.push_back(windowInfo);
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();

    WindowGroupInfo windowGroupInfo;
    windowGroupInfo.windowsInfo.push_back(info);
    inputWindowsManager->windowsPerDisplay_.insert(std::make_pair(2, windowGroupInfo));

    inputWindowsManager->extraData_.appended = false;
    inputWindowsManager->firstBtnDownWindowInfo_.first = 0;
    inputWindowsManager->firstBtnDownWindowInfo_.second = 2;
    WindowInfo beginWindowInfo;
    beginWindowInfo.id = 1;
    inputWindowsManager->axisBeginWindowInfo_ = beginWindowInfo;
    std::optional<WindowInfo> result = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_TRUE(result.has_value());

    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    std::optional<WindowInfo> result1 = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_TRUE(result1.has_value());
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_POINTER
/* *
 * @tc.name: InputWindowsManagerOneTest_GetPositionDisplayDirection_001
 * @tc.desc: Test the funcation GetPositionDisplayDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_GetPositionDisplayDirection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t id = -1;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    EXPECT_EQ(inputWindowsManager->GetPositionDisplayDirection(id), Direction::DIRECTION0);
}
#endif // OHOS_BUILD_ENABLE_POINTER

/* *
 * @tc.name: InputWindowsManagerOneTest_UpdateCustomStyle_001
 * @tc.desc: Test the funcation UpdateCustomStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_UpdateCustomStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 0;
    PointerStyle pointerStyle;
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    PointerStyle pointerStyle1;
    pointerStyle1.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerStyle1.size = 11;
    std::map<int32_t, PointerStyle> tmpPointerStyle = { { windowId + 1, pointerStyle1 } };
    inputWindowsManager->pointerStyle_.insert(std::make_pair(1, tmpPointerStyle));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateCustomStyle(windowId, pointerStyle));

    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateCustomStyle(windowId, pointerStyle));
}
} // namespace MMI
} // namespace OHOS
