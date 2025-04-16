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
#include "util.h"
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
    if (GetInputWindowsManagerInterface() != nullptr) {
        return GetInputWindowsManagerInterface()->GetWindowAndDisplayInfo(windowId, displayId);
    }
    return std::nullopt;
}

void InputWindowsManager::PrintDisplayInfo(const DisplayInfo displayInfo) {}

bool Rosen::SceneBoardJudgement::IsSceneBoardEnabled()
{
    if (GetInputWindowsManagerInterface() != nullptr) {
        return GetInputWindowsManagerInterface()->IsSceneBoardEnabled();
    }
    return false;
}

namespace MMI {
namespace {
constexpr int32_t CAST_INPUT_DEVICEID{ 0xAAAAAAFF };
constexpr int32_t CAST_SCREEN_DEVICEID{ 0xAAAAAAFE };
}  // namespace

std::string ReadJsonFile(const std::string &filePath)
{
    if (g_inputWindowManagerInterface != nullptr) {
        return GetInputWindowsManagerInterface()->ReadJsonFile(filePath);
    }
    return "";
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
    ASSERT_NE(pointerEvent, nullptr);
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
    ASSERT_NE(pointerEvent, nullptr);
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
    ASSERT_NE(pointerEvent, nullptr);
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
#endif  // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

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
#endif  // OHOS_BUILD_ENABLE_POINTER

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

/* *
 * @tc.name: InputWindowsManagerOneTest_SkipPrivacyProtectionWindow_001
 * @tc.desc: Test the funcation SkipPrivacyProtectionWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SkipPrivacyProtectionWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetDeviceId(CAST_INPUT_DEVICEID);
    bool isSkip = true;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->isOpenPrivacyProtectionserver_ = false;
    inputWindowsManager->privacyProtection_.isOpen = true;
    EXPECT_TRUE(inputWindowsManager->SkipPrivacyProtectionWindow(pointerEvent, isSkip));

    pointerEvent->SetDeviceId(CAST_SCREEN_DEVICEID);
    isSkip = false;
    EXPECT_FALSE(inputWindowsManager->SkipPrivacyProtectionWindow(pointerEvent, isSkip));

    inputWindowsManager->privacyProtection_.isOpen = false;
    EXPECT_FALSE(inputWindowsManager->SkipPrivacyProtectionWindow(pointerEvent, isSkip));
}

#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
/* *
 * @tc.name: InputWindowsManagerOneTest_HandleOneHandMode_001
 * @tc.desc: Test the funcation HandleOneHandMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_HandleOneHandMode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo displayInfo;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem pointerItem;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    pointerItem.SetDisplayXPos(0.0);
    pointerItem.SetDisplayYPos(0.0);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    pointerEvent->SetAutoToVirtualScreen(true);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleOneHandMode(displayInfo, pointerEvent, pointerItem));

    pointerEvent->SetAutoToVirtualScreen(false);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleOneHandMode(displayInfo, pointerEvent, pointerItem));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_UpdatePointerItemInOneHandMode_001
 * @tc.desc: Test the funcation UpdatePointerItemInOneHandMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_UpdatePointerItemInOneHandMode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo displayInfo;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    PointerEvent::PointerItem item;
    int32_t pointerId = 0;
    item.SetPointerId(pointerId);
    pointerEvent->pointers_.push_back(item);
    pointerEvent->SetPointerId(pointerId + 1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdatePointerItemInOneHandMode(displayInfo, pointerEvent));

    pointerEvent->SetPointerId(pointerId);
    displayInfo.height = 0;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdatePointerItemInOneHandMode(displayInfo, pointerEvent));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_UpdatePointerItemInOneHandMode_002
 * @tc.desc: Test the funcation UpdatePointerItemInOneHandMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_UpdatePointerItemInOneHandMode_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo displayInfo;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    PointerEvent::PointerItem item;
    int32_t pointerId = 0;
    item.SetPointerId(pointerId);
    pointerEvent->pointers_.push_back(item);
    pointerEvent->SetPointerId(pointerId);
    displayInfo.height = 1;
    displayInfo.oneHandY = displayInfo.height;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdatePointerItemInOneHandMode(displayInfo, pointerEvent));

    displayInfo.oneHandY = displayInfo.height + 1;
    displayInfo.scalePercent = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdatePointerItemInOneHandMode(displayInfo, pointerEvent));
}
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
/* *
 * @tc.name: InputWindowsManagerOneTest_UpdateTransformDisplayXY_001
 * @tc.desc: Test the funcation UpdateTransformDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_UpdateTransformDisplayXY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    std::vector<WindowInfo> windowsInfo;
    DisplayInfo displayInfo;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();

    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetDisplayXPos(0.0);
    item.SetDisplayYPos(0.0);
    pointerEvent->pointers_.push_back(item);
    pointerEvent->SetPointerId(pointerId);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE_NAVIGATION;
    displayInfo.transform.push_back(1.0f);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateTransformDisplayXY(pointerEvent, windowsInfo, displayInfo));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_UpdateTransformDisplayXY_002
 * @tc.desc: Test the funcation UpdateTransformDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_UpdateTransformDisplayXY_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    std::vector<WindowInfo> windowsInfo;
    DisplayInfo displayInfo;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();

    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetDisplayXPos(0.0);
    item.SetDisplayYPos(0.0);
    pointerEvent->pointers_.push_back(item);
    pointerEvent->SetPointerId(pointerId);
    displayInfo.transform.push_back(1.0f);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_ACCESSIBILITY;
    pointerEvent->SetZOrder(1.0f);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetTargetWindowId(-1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateTransformDisplayXY(pointerEvent, windowsInfo, displayInfo));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_UpdateTransformDisplayXY_003
 * @tc.desc: Test the funcation UpdateTransformDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_UpdateTransformDisplayXY_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    std::vector<WindowInfo> windowsInfo;
    DisplayInfo displayInfo;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();

    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetDisplayXPos(0.0);
    item.SetDisplayYPos(0.0);
    pointerEvent->pointers_.push_back(item);
    pointerEvent->SetPointerId(pointerId);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_ACCESSIBILITY | InputEvent::EVENT_FLAG_SIMULATE_NAVIGATION;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    displayInfo.transform.clear();
    pointerEvent->SetTargetWindowId(-1);
    pointerEvent->SetZOrder(0.0f);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateTransformDisplayXY(pointerEvent, windowsInfo, displayInfo));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_UpdateTransformDisplayXY_004
 * @tc.desc: Test the funcation UpdateTransformDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_UpdateTransformDisplayXY_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    std::vector<WindowInfo> windowsInfo;
    DisplayInfo displayInfo;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();

    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetDisplayXPos(0.0);
    item.SetDisplayYPos(0.0);
    pointerEvent->pointers_.push_back(item);
    pointerEvent->SetPointerId(pointerId);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_ACCESSIBILITY;
    displayInfo.transform.clear();
    pointerEvent->SetTargetWindowId(-1);
    pointerEvent->SetZOrder(1.0f);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateTransformDisplayXY(pointerEvent, windowsInfo, displayInfo));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_UpdateTransformDisplayXY_005
 * @tc.desc: Test the funcation UpdateTransformDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_UpdateTransformDisplayXY_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    std::vector<WindowInfo> windowsInfo;
    DisplayInfo displayInfo;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();

    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetDisplayXPos(10.0);
    item.SetDisplayYPos(20.0);
    pointerEvent->pointers_.push_back(item);
    pointerEvent->SetPointerId(pointerId);
    displayInfo.transform.push_back(1.0f);
    pointerEvent->bitwise_ = 0;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    WindowInfo info;
    info.id = 50;
    info.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    Rect rect{
        .x = 0,
        .y = 0,
        .width = 300,
        .height = 300,
    };
    info.defaultHotAreas.push_back(rect);
    windowsInfo.push_back(info);
    pointerEvent->SetZOrder(0.0f);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateTransformDisplayXY(pointerEvent, windowsInfo, displayInfo));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_UpdateTransformDisplayXY_006
 * @tc.desc: Test the funcation UpdateTransformDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_UpdateTransformDisplayXY_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    std::vector<WindowInfo> windowsInfo;
    DisplayInfo displayInfo;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();

    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetDisplayXPos(10.0);
    item.SetDisplayYPos(20.0);
    pointerEvent->pointers_.push_back(item);
    pointerEvent->SetPointerId(pointerId);
    pointerEvent->SetZOrder(1.0f);
    displayInfo.transform.push_back(1.0f);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_ACCESSIBILITY;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetTargetWindowId(1);
    WindowInfo info;
    info.id = 0;
    info.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    Rect rect{
        .x = 0,
        .y = 0,
        .width = 300,
        .height = 300,
    };
    info.defaultHotAreas.push_back(rect);
    windowsInfo.push_back(info);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateTransformDisplayXY(pointerEvent, windowsInfo, displayInfo));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_DispatchTouch_001
 * @tc.desc: Test the funcation DispatchTouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_DispatchTouch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_PULL_IN_WINDOW;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_CalculateAcrossDirection_001
 * @tc.desc: Test the funcation CalculateAcrossDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_CalculateAcrossDirection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    DisplayInfo displayInfo;
    Vector2D<double> layout;
    displayInfo.x = 1;
    displayInfo.y = 1;
    displayInfo.validWidth = 2;
    displayInfo.validHeight = 1;
    layout.x = 2;
    layout.y = 2;
    EXPECT_EQ(inputWindowsManager->CalculateAcrossDirection(displayInfo, layout), AcrossDirection::DOWNWARDS);
}

/* *
 * @tc.name: InputWindowsManagerOneTest_AcrossDisplay_001
 * @tc.desc: Test the funcation AcrossDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_AcrossDisplay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    DisplayInfo displayInfoDes;
    DisplayInfo displayInfoOri;
    Vector2D<double> logical;
    Vector2D<double> layout;
    AcrossDirection acrossDirection = AcrossDirection::RIGHTWARDS;

    displayInfoDes.x = INT32_MAX;
    displayInfoDes.validWidth = 1;
    EXPECT_FALSE(inputWindowsManager->AcrossDisplay(displayInfoDes, displayInfoOri, logical, layout, acrossDirection));

    displayInfoDes.x = 1;
    displayInfoDes.y = 1;
    displayInfoDes.validHeight = INT32_MAX;
    EXPECT_FALSE(inputWindowsManager->AcrossDisplay(displayInfoDes, displayInfoOri, logical, layout, acrossDirection));

    displayInfoDes.validHeight = 1;
    displayInfoOri.x = 0;
    displayInfoOri.y = 0;
    displayInfoOri.validWidth = 1;
    displayInfoOri.validHeight = 0;

    layout.x = 0;
    layout.y = 0;
    EXPECT_TRUE(inputWindowsManager->AcrossDisplay(displayInfoDes, displayInfoOri, logical, layout, acrossDirection));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_FindPhysicalDisplay_001
 * @tc.desc: Test the funcation FindPhysicalDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_FindPhysicalDisplay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();

    DisplayInfo displayInfo;
    double physicalX = 0.0f;
    double physicalY = 0.0f;
    int32_t displayId = 0;

    DisplayInfo displayInfo1;
    displayInfo1.id = 0;
    displayInfo1.dpi = -10;
    displayInfo1.uniq = "default0";
    inputWindowsManager->displayGroupInfo_.displaysInfo.push_back(displayInfo1);

    displayInfo.id = 1;
    displayInfo.x = INT32_MAX;
    displayInfo.y = 1;
    displayInfo.validWidth = INT32_MAX;
    displayInfo.validHeight = 1;
    displayInfo.direction = DIRECTION0;
    displayInfo.displayDirection = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_ReverseRotateDisplayScreen_001
 * @tc.desc: Test the funcation ReverseRotateDisplayScreen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ReverseRotateDisplayScreen_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    DisplayInfo info;
    double x = 0.0f;
    double y = 0.0f;
    Coordinate2D cursorPos = { 0.0, 0.0 };
    info.direction = Direction::DIRECTION90;
    info.displayDirection = Direction::DIRECTION0;
    info.width = 0;
    info.height = 0;
    info.validWidth = 0;
    info.validHeight = 0;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ReverseRotateDisplayScreen(info, x, y, cursorPos));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_ReverseRotateDisplayScreen_002
 * @tc.desc: Test the funcation ReverseRotateDisplayScreen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ReverseRotateDisplayScreen_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    DisplayInfo info;
    double x = 0.0f;
    double y = 0.0f;
    Coordinate2D cursorPos = { 0.0, 0.0 };
    info.direction = Direction::DIRECTION180;
    info.displayDirection = Direction::DIRECTION0;
    info.width = 0;
    info.height = 0;
    info.validWidth = 0;
    info.validHeight = 0;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ReverseRotateDisplayScreen(info, x, y, cursorPos));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_ShiftAppMousePointerEvent_001
 * @tc.desc: Test the funcation ShiftAppMousePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ShiftAppMousePointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ShiftWindowInfo shiftWindowInfo;
    bool autoGenDown = false;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    inputWindowsManager->lastPointerEvent_ = pointerEvent;
    EXPECT_EQ(inputWindowsManager->ShiftAppMousePointerEvent(shiftWindowInfo, autoGenDown), RET_ERR);
}
#endif  // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

/* *
 * @tc.name: InputWindowsManagerOneTest_AppendExtraData_001
 * @tc.desc: Test the funcation AppendExtraData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_AppendExtraData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ExtraData extraData;
    extraData.drawCursor = true;
    extraData.eventId = 1;
    extraData.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    inputWindowsManager->mouseDownEventId_ = -1;
    EXPECT_EQ(inputWindowsManager->AppendExtraData(extraData), RET_ERR);
}

/* *
 * @tc.name: InputWindowsManagerOneTest_AppendExtraData_002
 * @tc.desc: Test the funcation AppendExtraData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_AppendExtraData_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ExtraData extraData;
    extraData.drawCursor = true;
    extraData.eventId = 1;
    extraData.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    inputWindowsManager->mouseDownEventId_ = extraData.eventId + 1;
    EXPECT_EQ(inputWindowsManager->AppendExtraData(extraData), RET_ERR);
}

/* *
 * @tc.name: InputWindowsManagerOneTest_AppendExtraData_003
 * @tc.desc: Test the funcation AppendExtraData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_AppendExtraData_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ExtraData extraData;
    extraData.drawCursor = true;
    extraData.eventId = 1;
    extraData.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    inputWindowsManager->mouseDownEventId_ = extraData.eventId;
    EXPECT_EQ(inputWindowsManager->AppendExtraData(extraData), RET_OK);

    extraData.sourceType = PointerEvent::SOURCE_TYPE_UNKNOWN;
    EXPECT_EQ(inputWindowsManager->AppendExtraData(extraData), RET_OK);

    extraData.eventId = 0;
    EXPECT_EQ(inputWindowsManager->AppendExtraData(extraData), RET_OK);
}

/* *
 * @tc.name: InputWindowsManagerOneTest_ParseJson_001
 * @tc.desc: Test the funcation ParseJson
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ParseJson_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::string configFile = "config_file_path";
    NiceMock<MockInputWindowsManager> mockInputWindowsManager;
    EXPECT_CALL(mockInputWindowsManager, ReadJsonFile)
        .WillOnce(Return(""))
        .WillOnce(Return("not an object"))
        .WillOnce(Return(R"({"whiteList": "not an array"})"))
        .WillOnce(Return(R"({"whiteList": [123]})"))
        .WillOnce(Return(R"({"whiteList": [{"keyCode": 1}]})"))
        .WillOnce(Return(R"({"whiteList": [{"keyCode": "not a number", "pressedKey": 1}]})"));
    EXPECT_FALSE(inputWindowsManager->ParseJson(configFile));
    EXPECT_FALSE(inputWindowsManager->ParseJson(configFile));
    EXPECT_FALSE(inputWindowsManager->ParseJson(configFile));
    EXPECT_TRUE(inputWindowsManager->ParseJson(configFile));
    EXPECT_TRUE(inputWindowsManager->ParseJson(configFile));
    EXPECT_TRUE(inputWindowsManager->ParseJson(configFile));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_GetPidByWindowId_001
 * @tc.desc: Test the funcation GetPidByWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_GetPidByWindowId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    int32_t id = 0;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.windowInputType = WindowInputType::TRANSMIT_ANTI_AXIS_MOVE;
    WindowInfo winInfo;
    winInfo.id = id;
    windowInfo.uiExtentionWindowInfo.push_back(winInfo);
    inputWindowsManager->displayGroupInfo_.windowsInfo.push_back(windowInfo);
    EXPECT_EQ(inputWindowsManager->GetPidByWindowId(id), windowInfo.pid);

    id = -1;
    EXPECT_EQ(inputWindowsManager->GetPidByWindowId(id), RET_ERR);
}

#ifdef OHOS_BUILD_ENABLE_TOUCH
/* *
 * @tc.name: InputWindowsManagerOneTest_CancelTouch_001
 * @tc.desc: Test the funcation CancelTouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_CancelTouch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    int32_t touch = 1;
    WindowInfoEX winInfoEx;
    winInfoEx.flag = true;
    inputWindowsManager->touchItemDownInfos_.insert(std::make_pair(touch, winInfoEx));
    EXPECT_TRUE(inputWindowsManager->CancelTouch(touch));

    EXPECT_FALSE(inputWindowsManager->CancelTouch(touch));

    inputWindowsManager->touchItemDownInfos_.clear();
    EXPECT_FALSE(inputWindowsManager->CancelTouch(touch));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_CancelAllTouches_001
 * @tc.desc: Test the funcation CancelAllTouches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_CancelAllTouches_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    bool isDisplayChanged = true;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    PointerEvent::PointerItem item;
    item.pressed_ = false;
    pointerEvent->pointers_.push_back(item);

    item.pressed_ = true;
    inputWindowsManager->extraData_.appended = true;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    item.pointerId_ = 1;
    inputWindowsManager->extraData_.pointerId = item.GetPointerId();
    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    pointerEvent->pointers_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->CancelAllTouches(pointerEvent, isDisplayChanged));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_CancelAllTouches_002
 * @tc.desc: Test the funcation CancelAllTouches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_CancelAllTouches_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    bool isDisplayChanged = true;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    PointerEvent::PointerItem item;
    item.pressed_ = true;
    item.pointerId_ = 1;
    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    inputWindowsManager->extraData_.appended = true;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    inputWindowsManager->extraData_.pointerId = item.GetPointerId() + 1;
    pointerEvent->pointers_.push_back(item);

    item.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    inputWindowsManager->extraData_.pointerId = item.GetPointerId() + 1;
    pointerEvent->pointers_.push_back(item);

    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_UNKNOWN;
    pointerEvent->pointers_.push_back(item);

    inputWindowsManager->extraData_.appended = false;
    pointerEvent->pointers_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->CancelAllTouches(pointerEvent, isDisplayChanged));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_CalcDrawCoordinate_001
 * @tc.desc: Test the funcation CalcDrawCoordinate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_CalcDrawCoordinate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    DisplayInfo displayInfo;
    PointerEvent::PointerItem pointerItem;
    pointerItem.rawDisplayX_ = 0;
    pointerItem.rawDisplayY_ = 0;
    displayInfo.transform.push_back(1.0f);
    auto result = inputWindowsManager->CalcDrawCoordinate(displayInfo, pointerItem);
    EXPECT_EQ(result.first, 0);
    EXPECT_EQ(result.second, 0);
}
#endif  // OHOS_BUILD_ENABLE_TOUCH
}  // namespace MMI
}  // namespace OHOS
