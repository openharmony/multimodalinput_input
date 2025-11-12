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
#include "input_manager_util.h"
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

void InputWindowsManager::PrintDisplayInfo(const OLD::DisplayInfo displayInfo) {}

bool Rosen::SceneBoardJudgement::IsSceneBoardEnabled()
{
    if (GetInputWindowsManagerInterface() != nullptr) {
        return GetInputWindowsManagerInterface()->IsSceneBoardEnabled();
    }
    return false;
}

namespace MMI {
namespace {
constexpr int32_t CAST_INPUT_DEVICEID {0xAAAAAAFF};
constexpr int32_t CAST_SCREEN_DEVICEID {0xAAAAAAFE};
constexpr int32_t DEFAULT_POSITION { 0 };
} // namespace

std::string ReadJsonFile(const std::string &filePath)
{
    if (g_inputWindowManagerInterface != nullptr) {
        return GetInputWindowsManagerInterface()->ReadJsonFile(filePath);
    }
    return "";
}

class InputWindowsManagerOneTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {};
    void SetDown(void) {};
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
    OLD::DisplayInfo info;
    info.direction = DIRECTION90;
    info.validWidth = 0;
    info.validHeight = 0;
    PhysicalCoordinate coord;
    coord.x = 1;
    coord.y = 0;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    CursorPosition cursorPosRef;
    auto it = inputWindowsManager->cursorPosMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->cursorPosMap_.end()) {
        cursorPosRef = it->second;
    }
    cursorPosRef.direction = Direction::DIRECTION0;
    NiceMock<MockInputWindowsManager> mockInputWindowsManager;
    EXPECT_CALL(mockInputWindowsManager, IsSceneBoardEnabled)
        .WillOnce(Return(false))
        .WillOnce(Return(false))
        .WillOnce(Return(true));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ScreenRotateAdjustDisplayXY(info, coord));

    coord.x = 1;
    coord.y = 0;
    info.direction = DIRECTION0;
    cursorPosRef.direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ScreenRotateAdjustDisplayXY(info, coord));

    coord.x = 1;
    coord.y = 0;
    info.direction = DIRECTION0;
    cursorPosRef.direction = Direction::DIRECTION90;
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
    OLD::DisplayInfo info;
    info.direction = DIRECTION0;
    info.displayDirection = Direction::DIRECTION0;
    info.validWidth = 0;
    info.validHeight = 0;
    PhysicalCoordinate coord;
    coord.x = 1;
    coord.y = 0;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    CursorPosition cursorPosRef;
    auto it = inputWindowsManager->cursorPosMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->cursorPosMap_.end()) {
        cursorPosRef = it->second;
    }
    cursorPosRef.direction = Direction::DIRECTION90;
    cursorPosRef.displayDirection = Direction::DIRECTION90;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(1);
    inputWindowsManager->UpdateTargetPointer(pointerEvent);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->RotateScreen(info, coord));

    coord.x = 0;
    coord.y = 1;
    cursorPosRef.direction = Direction::DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->RotateScreen(info, coord));

    coord.x = 0;
    coord.y = 1;
    cursorPosRef.direction = Direction::DIRECTION180;
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
    OLD::DisplayInfo info;
    info.direction = DIRECTION0;
    info.displayDirection = Direction::DIRECTION0;
    info.validWidth = 0;
    info.validHeight = 0;
    PhysicalCoordinate coord;
    coord.x = 1;
    coord.y = 0;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    CursorPosition cursorPosRef;
    auto it = inputWindowsManager->cursorPosMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->cursorPosMap_.end()) {
        cursorPosRef = it->second;
    }
    cursorPosRef.direction = Direction::DIRECTION90;
    cursorPosRef.displayDirection = Direction::DIRECTION90;
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
    inputWindowsManager->lastPointerEventForGesture_ = pointerEvent;
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
    inputWindowsManager->lastPointerEventForGesture_ = pointerEvent;
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
    inputWindowsManager->lastPointerEventForGesture_ = pointerEvent;
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
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
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
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionServer_ = true;
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
    windowInfo.pointerHotAreas = {
        {0, 0, 30, 40}
    };
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    windowInfo.isSkipSelfWhenShowOnVirtualScreen = true;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionServer_ = true;
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
    windowInfo.pointerHotAreas = {
        {0, 0, 30, 40}
    };
    windowInfo.windowInputType = WindowInputType::NORMAL;
    windowInfo.isSkipSelfWhenShowOnVirtualScreen = true;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionServer_ = true;
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
    windowInfo.pointerHotAreas = {
        {0, 0, 30, 40}
    };
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    windowInfo.isSkipSelfWhenShowOnVirtualScreen = true;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionServer_ = true;
    inputWindowsManager->privacyProtection_.isOpen = false;
    inputWindowsManager->extraData_.appended = false;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    std::unique_ptr<Media::PixelMap> pixelMap = nullptr;
    inputWindowsManager->transparentWins_.insert_or_assign(windowInfo.id, std::move(pixelMap));

    std::optional<WindowInfo> result = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_FALSE(result.has_value());

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    pointerEvent->pressedButtons_.insert(1);
    Rect rect {
        .x = 100,
        .y = 100,
        .width = 300,
        .height = 300,
    };
    WindowInfo winInfo;
    winInfo.id = 50;
    winInfo.defaultHotAreas.push_back(rect);
    windowInfo.uiExtentionWindowInfo.push_back(winInfo);
    it->second.windowsInfo.clear();
    it->second.windowsInfo.push_back(windowInfo);
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
    windowInfo.pointerHotAreas = {
        {0, 0, 30, 40}
    };
    windowInfo.windowInputType = WindowInputType::NORMAL;
    windowInfo.isSkipSelfWhenShowOnVirtualScreen = true;
    windowInfo.uiExtentionWindowInfo.clear();
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionServer_ = true;
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
    windowInfo.pointerHotAreas = {
        {0, 0, 30, 40}
    };
    windowInfo.windowInputType = WindowInputType::NORMAL;
    windowInfo.isSkipSelfWhenShowOnVirtualScreen = true;
    windowInfo.uiExtentionWindowInfo.clear();
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionServer_ = true;
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
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
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
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
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
    EXPECT_FALSE(result.has_value());

    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    std::optional<WindowInfo> result1 = inputWindowsManager->SelectWindowInfo(logicalX, logicalY, pointerEvent);
    EXPECT_FALSE(result1.has_value());
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
    std::map<int32_t, PointerStyle> tmpPointerStyle = {
        {windowId + 1, pointerStyle1}
    };
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
    inputWindowsManager->isOpenPrivacyProtectionServer_ = false;
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
    OLD::DisplayInfo displayInfo;
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
    OLD::DisplayInfo displayInfo;
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
    OLD::DisplayInfo displayInfo;
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
    OLD::DisplayInfo displayInfo;
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
    OLD::DisplayInfo displayInfo;
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
    OLD::DisplayInfo displayInfo;
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
    OLD::DisplayInfo displayInfo;
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
    OLD::DisplayInfo displayInfo;
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
    Rect rect {
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
    OLD::DisplayInfo displayInfo;
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
    Rect rect {
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
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
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
    OLD::DisplayInfo displayInfo;
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
    OLD::DisplayInfo displayInfoDes;
    OLD::DisplayInfo displayInfoOri;
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

    OLD::DisplayInfo displayInfo;
    double physicalX = 0.0f;
    double physicalY = 0.0f;
    int32_t displayId = 0;

    OLD::DisplayInfo displayInfo1;
    displayInfo1.id = 0;
    displayInfo1.dpi = -10;
    displayInfo1.uniq = "default0";
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo1);
    }

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
    OLD::DisplayInfo info;
    double x = 0.0f;
    double y = 0.0f;
    Coordinate2D cursorPos = {0.0, 0.0};
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
    OLD::DisplayInfo info;
    double x = 0.0f;
    double y = 0.0f;
    Coordinate2D cursorPos = {0.0, 0.0};
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
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

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
 * @tc.name: InputWindowsManagerOneTest_GetPidByDisplayIdAndWindowId_001
 * @tc.desc: Test the funcation GetPidByDisplayIdAndWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_GetPidByDisplayIdAndWindowId_001, TestSize.Level1)
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
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
        it->second.mainDisplayId = 0;
    }
    EXPECT_EQ(inputWindowsManager->GetPidByDisplayIdAndWindowId(0, id), windowInfo.pid);

    id = -1;
    EXPECT_EQ(inputWindowsManager->GetPidByDisplayIdAndWindowId(0, id), RET_ERR);
}

/* *
 * @tc.name: InputWindowsManagerOneTest_GetAgentPidByDisplayIdAndWindowId_001
 * @tc.desc: Test the funcation GetAgentPidByDisplayIdAndWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_GetAgentPidByDisplayIdAndWindowId_001, TestSize.Level1)
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
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
        it->second.mainDisplayId = 0;
    }
    EXPECT_EQ(inputWindowsManager->GetAgentPidByDisplayIdAndWindowId(0, id), windowInfo.agentPid);

    id = -1;
    EXPECT_EQ(inputWindowsManager->GetAgentPidByDisplayIdAndWindowId(0, id), RET_ERR);
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
    OLD::DisplayInfo displayInfo;
    PointerEvent::PointerItem pointerItem;
    pointerItem.rawDisplayX_ = 0;
    pointerItem.rawDisplayY_ = 0;
    displayInfo.transform.push_back(1.0f);
    auto result = inputWindowsManager->CalcDrawCoordinate(displayInfo, pointerItem);
    EXPECT_EQ(result.first, 0);
    EXPECT_EQ(result.second, 0);
}

/* *
 * @tc.name: InputWindowsManagerOneTest_GetWindowGroupInfoByDisplayIdCopy
 * @tc.desc: Test the funcation GetWindowGroupInfoByDisplayIdCopy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_GetWindowGroupInfoByDisplayIdCopy, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    WindowGroupInfo windowGroupInfo;
    int32_t displayId = 1;
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(displayId, windowGroupInfo));
    inputWindowsManager.GetWindowGroupInfoByDisplayIdCopy(displayId);
    inputWindowsManager.windowsPerDisplay_.clear();
    inputWindowsManager.GetWindowGroupInfoByDisplayIdCopy(displayId);
    inputWindowsManager.windowsPerDisplayMap_.clear();
    EXPECT_TRUE(inputWindowsManager.GetWindowGroupInfoByDisplayIdCopy(displayId).empty());
}

/* *
 * @tc.name: InputWindowsManagerOneTest_FindTargetDisplayGroupInfo
 * @tc.desc: Test the funcation FindTargetDisplayGroupInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_FindTargetDisplayGroupInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    WindowGroupInfo windowGroupInfo;
    int32_t displayId = 1;
    OLD::DisplayInfo displayInfo1;
    displayInfo1.id = 0;
    displayInfo1.dpi = -10;
    displayInfo1.uniq = "default0";
    auto it = inputWindowsManager.displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager.displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo1);
    }
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(displayId, windowGroupInfo));
    inputWindowsManager.FindTargetDisplayGroupInfo(0);
    displayId = 8;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.FindTargetDisplayGroupInfo(8));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_SetDragFlagByPointer001
 * @tc.desc: Test the funcation SetDragFlagByPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SetDragFlagByPointer001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    inputWindowsManager->SetDragFlagByPointer(pointerEvent);
    ASSERT_EQ(inputWindowsManager->dragFlag_, true);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    inputWindowsManager->SetDragFlagByPointer(pointerEvent);
    ASSERT_EQ(inputWindowsManager->dragFlag_, false);
}

/* *
 * @tc.name: InputWindowsManagerOneTest_ShiftAppTouchPointerEvent001
 * @tc.desc: Test the funcation ShiftAppTouchPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ShiftAppTouchPointerEvent001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    ShiftWindowInfo info;
    auto ret = inputWindowsManager->ShiftAppTouchPointerEvent(info);
    ASSERT_EQ(ret, RET_ERR);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

/* *
 * @tc.name: InputWindowsManagerOneTest_PrintHighZorder_001
 * @tc.desc: Test the funcation PrintHighZorder
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_PrintHighZorder_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = 2;
    windowInfo.flags = 0;
    windowInfo.pointerHotAreas = {
        {0, 0, 30, 40}
    };
    windowInfo.windowInputType = WindowInputType::NORMAL;
    std::vector<WindowInfo> windowsInfo = {windowInfo};
    pointerEvent->SetZOrder(1.0f);
    int32_t pointerAction = PointerEvent::POINTER_ACTION_AXIS_BEGIN;
    int32_t targetWindowId = 1;
    int32_t logicalX = 1;
    int32_t logicalY = 1;
    EXPECT_NO_FATAL_FAILURE(
        inputWindowsManager->PrintHighZorder(windowsInfo, pointerAction, targetWindowId, logicalX, logicalY));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_PrintHighZorder_002
 * @tc.desc: Test the funcation PrintHighZorder
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_PrintHighZorder_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 1;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    std::vector<WindowInfo> windowsInfo = {windowInfo};
    pointerEvent->SetZOrder(1.0f);
    int32_t pointerAction = PointerEvent::POINTER_ACTION_AXIS_UPDATE;
    int32_t targetWindowId = 1;
    int32_t logicalX = 1;
    int32_t logicalY = 1;
    EXPECT_NO_FATAL_FAILURE(
        inputWindowsManager->PrintHighZorder(windowsInfo, pointerAction, targetWindowId, logicalX, logicalY));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_FindTargetDisplayGroupInfo_001
 * @tc.desc: Test the funcation FindTargetDisplayGroupInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_FindTargetDisplayGroupInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    int32_t displayId = 0;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->FindTargetDisplayGroupInfo(displayId));
    displayId = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->FindTargetDisplayGroupInfo(displayId));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_IsPointerOnCenter_001
 * @tc.desc: Test the funcation IsPointerOnCenter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_IsPointerOnCenter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.validWidth = 1;
    displayInfo.validHeight = 1;
    CursorPosition currentPos;
    currentPos.cursorPos.x = 0.5;
    currentPos.cursorPos.y = 0.5;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsPointerOnCenter(currentPos, displayInfo));
    currentPos.cursorPos.x = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsPointerOnCenter(currentPos, displayInfo));
    currentPos.cursorPos.x = 0.5;
    currentPos.cursorPos.y = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsPointerOnCenter(currentPos, displayInfo));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_ShiftAppMousePointerEvent_002
 * @tc.desc: Test the funcation ShiftAppMousePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ShiftAppMousePointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ShiftWindowInfo shiftWindowInfo;
    bool autoGenDown = false;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pressedButtons_.insert(1);
    inputWindowsManager->lastPointerEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppMousePointerEvent(shiftWindowInfo, autoGenDown));
    autoGenDown = true;
    shiftWindowInfo.x = -1;
    shiftWindowInfo.y = -1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppMousePointerEvent(shiftWindowInfo, autoGenDown));
    shiftWindowInfo.x = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppMousePointerEvent(shiftWindowInfo, autoGenDown));
    shiftWindowInfo.x = -1;
    shiftWindowInfo.y = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppMousePointerEvent(shiftWindowInfo, autoGenDown));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_ShiftAppTouchPointerEvent002
 * @tc.desc: Test the funcation ShiftAppTouchPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ShiftAppTouchPointerEvent002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    ShiftWindowInfo shiftWindowInfo;
    shiftWindowInfo.fingerId = -1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppTouchPointerEvent(shiftWindowInfo));
    shiftWindowInfo.fingerId = 1;
    pointerEvent->pointers_.clear();
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppTouchPointerEvent(shiftWindowInfo));
    PointerEvent::PointerItem item;
    int32_t pointerId = 0;
    item.SetPointerId(pointerId);
    pointerEvent->pointers_.push_back(item);
    item.pressed_ = true;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppTouchPointerEvent(shiftWindowInfo));
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
/**
 * @tc.name: InputWindowsManagerOneTest_ReissueEvent_005
 * @tc.desc: Verify ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ReissueEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    int32_t focusWindowId = -1;
    inputWindowsManager->focusWindowId_ = 0;
    keyEvent->SetRepeatKey(true);

    std::shared_ptr<EventDispatchHandler> handler = std::make_shared<EventDispatchHandler>();
    NiceMock<MockInputWindowsManager> mockInputWindowsManager;
    UDSServer udServer;
    EXPECT_CALL(mockInputWindowsManager, GetEventDispatchHandler).WillRepeatedly(Return(handler));
    EXPECT_CALL(mockInputWindowsManager, GetUDSServer).WillRepeatedly(Return(&udServer));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ReissueEvent(keyEvent, focusWindowId));
}

/**
 * @tc.name: InputWindowsManagerOneTest_ReissueEvent_006
 * @tc.desc: Verify ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ReissueEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    int32_t focusWindowId = -1;
    inputWindowsManager->focusWindowId_ = 0;
    keyEvent->SetRepeatKey(true);

    std::shared_ptr<EventDispatchHandler> handler = std::make_shared<EventDispatchHandler>();
    NiceMock<MockInputWindowsManager> mockInputWindowsManager;
    EXPECT_CALL(mockInputWindowsManager, GetEventDispatchHandler).WillRepeatedly(Return(handler));
    EXPECT_CALL(mockInputWindowsManager, GetUDSServer).WillRepeatedly(Return(nullptr));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ReissueEvent(keyEvent, focusWindowId));
}

/**
 * @tc.name: InputWindowsManagerOneTest_ReissueEvent_007
 * @tc.desc: Verify ReissueEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ReissueEvent_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    int32_t focusWindowId = -1;
    inputWindowsManager->focusWindowId_ = 0;
    keyEvent->SetRepeatKey(true);

    NiceMock<MockInputWindowsManager> mockInputWindowsManager;
    EXPECT_CALL(mockInputWindowsManager, GetEventDispatchHandler).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(mockInputWindowsManager, GetUDSServer).WillRepeatedly(Return(nullptr));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ReissueEvent(keyEvent, focusWindowId));
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

/**
 * @tc.name: InputWindowsManagerOneTest_UpdateDisplayInfoExtIfNeed01
 * @tc.desc: Test UpdateDisplayInfoExtIfNeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_UpdateDisplayInfoExtIfNeed01, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    OLD::DisplayGroupInfo displayGroupInfo;
    OLD::DisplayInfo displayInfo;
    displayGroupInfo.displaysInfo.push_back(displayInfo);
    displayGroupInfo.groupId = -1;
    bool needUpdateDisplayExt = true;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.UpdateDisplayInfoExtIfNeed(displayGroupInfo, needUpdateDisplayExt));
}

/**
 * @tc.name: InputWindowsManagerOneTest_GetMainScreenDisplayInfo
 * @tc.desc: Test GetMainScreenDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_GetMainScreenDisplayInfo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    std::vector<OLD::DisplayInfo> displaysInfo;
    OLD::DisplayInfo mainScreenDisplayInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.GetMainScreenDisplayInfo(displaysInfo, mainScreenDisplayInfo));
    displaysInfo.push_back(mainScreenDisplayInfo);
    displaysInfo.push_back(mainScreenDisplayInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.GetMainScreenDisplayInfo(displaysInfo, mainScreenDisplayInfo));
}

/**
 * @tc.name: InputWindowsManagerOneTest_ResetPointerPosition
 * @tc.desc: Test ResetPointerPosition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ResetPointerPosition, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    OLD::DisplayGroupInfo displayGroupInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.ResetPointerPosition(displayGroupInfo));
    OLD::DisplayInfo currentDisplay;
    displayGroupInfo.displaysInfo.push_back(currentDisplay);
    displayGroupInfo.displaysInfo.push_back(currentDisplay);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.ResetPointerPosition(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerOneTest_IsPointerOnCenter
 * @tc.desc: Test IsPointerOnCenter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_IsPointerOnCenter, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    OLD::DisplayInfo currentDisplay;
    currentDisplay.validHeight = 2;
    currentDisplay.validWidth = 2;
    CursorPosition currentPos;
    currentPos.cursorPos.x = 1;
    currentPos.cursorPos.y = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.IsPointerOnCenter(currentPos, currentDisplay));
    currentPos.cursorPos.y = 0;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.IsPointerOnCenter(currentPos, currentDisplay));
    currentPos.cursorPos.x = 0;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.IsPointerOnCenter(currentPos, currentDisplay));
}

/**
 * @tc.name: InputWindowsManagerOneTest_ResetCursorPos
 * @tc.desc: Test ResetCursorPos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ResetCursorPos, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    OLD::DisplayGroupInfo displayGroupInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.ResetCursorPos(displayGroupInfo));
    OLD::DisplayInfo displayInfo;
    displayGroupInfo.displaysInfo.push_back(displayInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.ResetCursorPos(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerOneTest_IsPositionOutValidDisplay
 * @tc.desc: Test IsPositionOutValidDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_IsPositionOutValidDisplay, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    OLD::DisplayInfo currentDisplay;
    currentDisplay.validHeight = 2;
    currentDisplay.validWidth = 2;
    currentDisplay.height = 2;
    currentDisplay.width = 2;
    currentDisplay.offsetX = 0;
    currentDisplay.offsetY = 0;
    Coordinate2D position;
    position.x = 1;
    position.y = 1;
    currentDisplay.fixedDirection = DIRECTION90;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.IsPositionOutValidDisplay(position, currentDisplay, true));
    currentDisplay.fixedDirection = DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.IsPositionOutValidDisplay(position, currentDisplay, true));
    currentDisplay.fixedDirection = DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.IsPositionOutValidDisplay(position, currentDisplay, true));
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.IsPositionOutValidDisplay(position, currentDisplay, false));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_ProcessTouchTracking
 * @tc.desc: Test the funcation ProcessTouchTracking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ProcessTouchTracking, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetDisplayXPos(0.0);
    pointerItem.SetDisplayYPos(0.0);
    WindowInfo targetWindow;
    targetWindow.id = 1;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_MOVE);
    pointerEvent->targetWindowId_ = 1;
    pointerEvent->pointers_.clear();
    pointerItem.SetPointerId(1);
    pointerEvent->pointers_.push_back(pointerItem);
    EXPECT_EQ(pointerEvent->GetPointerCount(), 1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ProcessTouchTracking(pointerEvent, targetWindow));

    pointerEvent->SetTargetWindowId(targetWindow.id);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ProcessTouchTracking(pointerEvent, targetWindow));

    targetWindow.id = -1;
    pointerEvent->pointers_.clear();
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ProcessTouchTracking(pointerEvent, targetWindow));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_ClearMouseHideFlag
 * @tc.desc: Test the funcation ClearMouseHideFlag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ClearMouseHideFlag, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    auto eventId = -1;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetPointerId(eventId);
    inputWindowsManager->lastPointerEvent_ = pointerEvent;
    EXPECT_EQ(pointerEvent->GetId(), eventId);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ClearMouseHideFlag(eventId));
    eventId = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ClearMouseHideFlag(eventId));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_IsAccessibilityEventWithZorderInjected
 * @tc.desc: Test the funcation IsAccessibilityEventWithZorderInjected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_IsAccessibilityEventWithZorderInjected, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_ENTER);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    pointerEvent->SetZOrder(1.0f);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsAccessibilityEventWithZorderInjected(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsAccessibilityEventWithZorderInjected(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_ENTER);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_ACCESSIBILITY;
    pointerEvent->SetZOrder(0.0f);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsAccessibilityEventWithZorderInjected(pointerEvent));
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->IsAccessibilityEventWithZorderInjected(pointerEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_SendCancelEventWhenLock
 * @tc.desc: Test the funcation SendCancelEventWhenLock
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerTest_SendCancelEventWhenLock, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    inputWindowsMgr.lastTouchEventOnBackGesture_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsMgr.lastTouchEventOnBackGesture_, nullptr);
    InputHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    EXPECT_NE(InputHandler->eventNormalizeHandler_, nullptr);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.SendCancelEventWhenLock());
    inputWindowsMgr.lastTouchEventOnBackGesture_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.SendCancelEventWhenLock());
    inputWindowsMgr.lastTouchEventOnBackGesture_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.SendCancelEventWhenLock());
    inputWindowsMgr.lastTouchEventOnBackGesture_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.SendCancelEventWhenLock());
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfoEX windowInfoEX;
    windowInfoEX.flag = true;
    pointerEvent->SetPointerId(1);

    inputWindowsMgr.touchItemDownInfos_.insert(std::make_pair(pointerEvent->GetPointerId(), windowInfoEX));
    inputWindowsMgr.lastTouchEventOnBackGesture_->SetPointerId(2);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.SendCancelEventWhenLock());
    inputWindowsMgr.lastTouchEventOnBackGesture_->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.SendCancelEventWhenLock());
}

/* *
 * @tc.name: InputWindowsManagerOneTest_ProcessInjectEventGlobalXY
 * @tc.desc: Test the funcation ProcessInjectEventGlobalXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ProcessInjectEventGlobalXY, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetGlobalX(DBL_MAX);
    pointerItem.SetGlobalY(DBL_MAX);
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->ClearFlag();
    int32_t useCoordinate = 0;
    auto pointerId = 1;
    OLD::DisplayInfo displayInfo;
    displayInfo.offsetX = 0;
    displayInfo.offsetY = 0;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(displayInfo);
    }
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ProcessInjectEventGlobalXY(pointerEvent, useCoordinate));

    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ProcessInjectEventGlobalXY(pointerEvent, useCoordinate));
    useCoordinate = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ProcessInjectEventGlobalXY(pointerEvent, useCoordinate));

    pointerItem.SetPointerId(pointerId);
    pointerEvent->pointers_.push_back(pointerItem);
    EXPECT_EQ(pointerEvent->GetPointerCount(), pointerId);
    pointerEvent->SetPointerId(pointerId);
    EXPECT_TRUE(pointerEvent->GetPointerItem(pointerId, pointerItem));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ProcessInjectEventGlobalXY(pointerEvent, useCoordinate));

    auto globalValue = 15.00;
    pointerEvent->pointers_.clear();
    pointerItem.SetGlobalX(globalValue);
    pointerEvent->pointers_.push_back(pointerItem);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ProcessInjectEventGlobalXY(pointerEvent, useCoordinate));

    pointerEvent->pointers_.clear();
    pointerItem.SetGlobalX(globalValue);
    pointerItem.SetGlobalY(globalValue);
    pointerEvent->pointers_.push_back(pointerItem);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ProcessInjectEventGlobalXY(pointerEvent, useCoordinate));

    globalValue = -15.00;
    pointerEvent->pointers_.clear();
    pointerItem.SetGlobalX(globalValue);
    pointerEvent->pointers_.push_back(pointerItem);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ProcessInjectEventGlobalXY(pointerEvent, useCoordinate));
}

/**
 * @tc.name: InputWindowsManagerOneTest_GetMainScreenDisplayInfo_001
 * @tc.desc: Test GetMainScreenDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_GetMainScreenDisplayInfo_001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    std::vector<OLD::DisplayInfo> displaysInfo;
    OLD::DisplayInfo mainScreenDisplayInfo;
    mainScreenDisplayInfo.id = 100;
    mainScreenDisplayInfo.uniq = "uniq";
    mainScreenDisplayInfo.validHeight = 2;
    mainScreenDisplayInfo.validWidth = 2;
    mainScreenDisplayInfo.height = 2;
    mainScreenDisplayInfo.width = 2;
    mainScreenDisplayInfo.offsetX = 0;
    mainScreenDisplayInfo.offsetY = 0;
    mainScreenDisplayInfo.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_MIRROR;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.GetMainScreenDisplayInfo(displaysInfo, mainScreenDisplayInfo));
    displaysInfo.push_back(mainScreenDisplayInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.GetMainScreenDisplayInfo(displaysInfo, mainScreenDisplayInfo));
    displaysInfo.clear();
    mainScreenDisplayInfo.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_MAIN;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.GetMainScreenDisplayInfo(displaysInfo, mainScreenDisplayInfo));
}

/**
 * @tc.name: InputWindowsManagerOneTest_ResetPointerPosition_001
 * @tc.desc: Test ResetPointerPosition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ResetPointerPosition_001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    OLD::DisplayGroupInfo displayGroupInfo;
    OLD::DisplayInfo currentDisplay;
    auto it = inputWindowsMgr.displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsMgr.displayGroupInfoMap_.end()) {
        it->second.displaysInfo.push_back(currentDisplay);
    }
    displayGroupInfo.displaysInfo.push_back(currentDisplay);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.ResetPointerPosition(displayGroupInfo));
    currentDisplay.id = 1;
    currentDisplay.width = 500;
    currentDisplay.height = 500;
    currentDisplay.displayDirection = DIRECTION0;
    currentDisplay.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_MIRROR;
    displayGroupInfo.displaysInfo.clear();
    it->second.displaysInfo.clear();
    displayGroupInfo.displaysInfo.push_back(currentDisplay);
    it->second.displaysInfo.push_back(currentDisplay);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.ResetPointerPosition(displayGroupInfo));
    displayGroupInfo.displaysInfo.clear();
    it->second.displaysInfo.clear();
    CursorPosition cursorPosCur;
    cursorPosCur.cursorPos.x = 1;
    cursorPosCur.cursorPos.y = 1;
    inputWindowsMgr.cursorPosMap_[0] = cursorPosCur;
    currentDisplay.displayDirection = DIRECTION90;
    currentDisplay.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_MAIN;
    currentDisplay.rsId = 1;
    it->second.displaysInfo.push_back(currentDisplay);
    currentDisplay.rsId = 0;
    displayGroupInfo.displaysInfo.push_back(currentDisplay);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.ResetPointerPosition(displayGroupInfo));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_GetWindowGroupInfoByDisplayIdCopy1
 * @tc.desc: Test the funcation GetWindowGroupInfoByDisplayIdCopy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_GetWindowGroupInfoByDisplayIdCopy1, TestSize.Level0)
{
    CALL_TEST_DEBUG;

    int32_t displayId = 1;
    int32_t groupId = 1003;

    OLD::DisplayInfo displayInfo = {};
    displayInfo.id = displayId;

    OLD::DisplayGroupInfo displayGroupInfo = {};
    displayGroupInfo.groupId = groupId;
    displayGroupInfo.displaysInfo.push_back(displayInfo);

    InputWindowsManager inputWindowsManager;
    inputWindowsManager.displayGroupInfoMap_.insert(std::make_pair(groupId, displayGroupInfo));

    WindowGroupInfo windowGroupInfo;
    windowGroupInfo.windowsInfo.clear();
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(displayId, windowGroupInfo));
    inputWindowsManager.GetWindowGroupInfoByDisplayIdCopy(displayId);
    inputWindowsManager.windowsPerDisplay_.clear();
    inputWindowsManager.GetWindowGroupInfoByDisplayIdCopy(displayId);
    inputWindowsManager.windowsPerDisplayMap_.clear();
    EXPECT_TRUE(inputWindowsManager.GetWindowGroupInfoByDisplayIdCopy(displayId).empty());
}

/**
 * @tc.name: InputWindowsManagerOneTest_GetWindowGroupInfoByDisplayId1
 * @tc.desc: Test GetWindowGroupInfoByDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_GetWindowGroupInfoByDisplayId1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    int32_t displayId = 1;
    int32_t groupId = 1003;

    OLD::DisplayInfo displayInfo = {};
    displayInfo.id = displayId;

    OLD::DisplayGroupInfo displayGroupInfo = {};
    displayGroupInfo.groupId = groupId;
    displayGroupInfo.displaysInfo.push_back(displayInfo);

    InputWindowsManager inputWindowsManager;
    inputWindowsManager.displayGroupInfoMap_.insert(std::make_pair(groupId, displayGroupInfo));

    WindowGroupInfo windowGroupInfo;

    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(displayId, windowGroupInfo));
    EXPECT_TRUE(inputWindowsManager.GetWindowGroupInfoByDisplayId(displayId).empty());

    WindowInfo windowInfo;
    displayId = 2;
    windowInfo.id = 1;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(displayId, windowGroupInfo));
    EXPECT_FALSE(!inputWindowsManager.GetWindowGroupInfoByDisplayId(displayId).empty());
}

/**
 * @tc.name: InputWindowsManagerOneTest_GetCancelEventFlag1
 * @tc.desc: Test the funcation GetCancelEventFlag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_GetCancelEventFlag1, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->bitwise_ = 0x00000080;
    EXPECT_TRUE(inputWindowsManager.GetCancelEventFlag(pointerEvent));
    pointerEvent->bitwise_ = 0x00000100;
    EXPECT_TRUE(inputWindowsManager.GetCancelEventFlag(pointerEvent));
}

/**
 * @tc.name: InputWindowsManagerOneTest_ClearMouseHideFlag001
 * @tc.desc: Test ClearMouseHideFlag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ClearMouseHideFlag001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    inputWindowsMgr.lastPointerEvent_ = pointerEvent;
    auto eventId = 100;
    inputWindowsMgr.lastPointerEvent_->SetId(eventId);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.ClearMouseHideFlag(eventId));
    eventId = 200;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.ClearMouseHideFlag(eventId));
}

/**
 * @tc.name: InputWindowsManagerOneTest_SendBackCenterPointerEvent
 * @tc.desc: Test BypassChainAndDispatchDirectly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SendBackCenterPointerEvent, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    inputWindowsMgr.lastPointerEvent_ = pointerEvent;
    CursorPosition currentPos;
    currentPos.cursorPos.x = 1;
    currentPos.cursorPos.y = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.SendBackCenterPointerEvent(currentPos));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_DispatchTouch_002
 * @tc.desc: Test the funcation DispatchTouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_DispatchTouch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    auto pointerId = 1;
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetGlobalX(DBL_MAX);
    pointerItem.SetGlobalY(DBL_MAX);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->lastTouchEvent_->SetPointerId(pointerId);
    pointerItem.SetPointerId(pointerId);
    inputWindowsManager->lastTouchEvent_->pointers_.push_back(pointerItem);
    auto fixedMode = PointerEvent::FixedMode::NORMAL;
    inputWindowsManager->lastTouchEvent_->SetFixedMode(fixedMode);
    inputWindowsManager->lastTouchWindowInfo_.windowInputType = WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));
    inputWindowsManager->lastTouchWindowInfo_.windowInputType = WindowInputType::DUALTRIGGER_TOUCH;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));
    inputWindowsManager->lastTouchWindowInfo_.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));

    inputWindowsManager->lastTouchWindowInfo_.windowInputType = WindowInputType::NORMAL;
    inputWindowsManager->lastTouchWindowInfo_.transform.clear();
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));
    float pointerChangeAreasCount = 8;
    inputWindowsManager->lastTouchWindowInfo_.transform.push_back(pointerChangeAreasCount);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->DispatchTouch(pointerAction));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_ChangeWindowArea
 * @tc.desc: Test the funcation ChangeWindowArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ChangeWindowArea, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ASSERT_NE(inputWindowsManager, nullptr);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    auto pointerId = 1;
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetGlobalX(DBL_MAX);
    pointerItem.SetGlobalY(DBL_MAX);
    int32_t x = 100;
    int32_t y = 200;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->lastTouchEvent_->SetPointerId(pointerId);
    pointerItem.SetPointerId(pointerId);
    inputWindowsManager->lastTouchEvent_->pointers_.push_back(pointerItem);
    auto fixedMode = PointerEvent::FixedMode::NORMAL;
    inputWindowsManager->lastTouchEvent_->SetFixedMode(fixedMode);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ChangeWindowArea(x, y, windowInfo));
}

/**
 * @tc.name: InputWindowsManagerOneTest_SendBackCenterPointerEvent_001
 * @tc.desc: Test SendBackCenterPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_SendBackCenterPointerEvent_001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
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
    windowInfo.pointerHotAreas = {
        {0, 0, 30, 40}
    };
    windowInfo.windowInputType = WindowInputType::NORMAL;
    windowInfo.isSkipSelfWhenShowOnVirtualScreen = true;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->firstBtnDownWindowInfo_.first = -1;
    inputWindowsManager->isOpenPrivacyProtectionServer_ = true;
    inputWindowsManager->privacyProtection_.isOpen = false;
    inputWindowsManager->extraData_.appended = true;
    inputWindowsManager->extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    std::unique_ptr<Media::PixelMap> pixelMap = nullptr;
    inputWindowsManager->transparentWins_.insert_or_assign(windowInfo.id, std::move(pixelMap));
    CursorPosition currentPos;
    currentPos.cursorPos.x = 1;
    currentPos.cursorPos.y = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->SendBackCenterPointerEvent(currentPos));

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->SendBackCenterPointerEvent(currentPos));

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_MOVE);
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->SendBackCenterPointerEvent(currentPos));
}

/**
 * @tc.name: InputWindowsManagerOneTest_HandleWindowPositionChange
 * @tc.desc: Test HandleWindowPositionChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_HandleWindowPositionChange, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    OLD::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 1;

    OLD::DisplayInfo displayInfo1;
    displayInfo1.id = 1;
    displayInfo1.x = 1;
    displayInfo1.y = 1;
    displayInfo1.width = 2;
    displayInfo1.height = 2;
    displayInfo1.dpi = 240;
    displayInfo1.name = "pp";
    displayInfo1.direction = DIRECTION0;
    displayInfo1.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_MAIN;

    OLD::DisplayInfo displayInfo2;
    displayInfo2.id = 2;
    displayInfo2.x = 1;
    displayInfo2.y = 1;
    displayInfo2.width = 2;
    displayInfo2.height = 2;
    displayInfo2.dpi = 240;
    displayInfo2.name = "pp";
    displayInfo2.uniq = "pp";
    displayInfo2.direction = DIRECTION0;
    displayInfo2.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_EXPAND;
    displayGroupInfo.displaysInfo.push_back(displayInfo2);
    displayGroupInfo.displaysInfo.push_back(displayInfo1);
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    pointerEvent->SetTargetDisplayId(-1);
    pointerEvent->SetTargetWindowId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    pointerEvent->SetDeviceId(CAST_INPUT_DEVICEID);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->HandleWindowPositionChange(displayGroupInfo));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_PrintZorderInfo
 * @tc.desc: Test the funcation PrintZorderInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_PrintZorderInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ASSERT_NE(inputWindowsManager, nullptr);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    auto pointerId = 1;
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetGlobalX(DBL_MAX);
    pointerItem.SetGlobalY(DBL_MAX);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;

    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->lastTouchEvent_->SetPointerId(pointerId);
    pointerItem.SetPointerId(pointerId);
    inputWindowsManager->lastTouchEvent_->pointers_.push_back(pointerItem);
    auto fixedMode = PointerEvent::FixedMode::NORMAL;
    inputWindowsManager->lastTouchEvent_->SetFixedMode(fixedMode);
    std::string windowPrint;
    windowPrint += StringPrintf("highZorder");
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->PrintZorderInfo(windowInfo, windowPrint));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_PrintWindowGroupInfo
 * @tc.desc: Test the funcation PrintWindowGroupInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_PrintWindowGroupInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    auto pointerId = 1;
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetGlobalX(DBL_MAX);
    pointerItem.SetGlobalY(DBL_MAX);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;

    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->lastTouchEvent_->SetPointerId(pointerId);
    pointerItem.SetPointerId(pointerId);
    inputWindowsManager->lastTouchEvent_->pointers_.push_back(pointerItem);
    auto fixedMode = PointerEvent::FixedMode::NORMAL;
    inputWindowsManager->lastTouchEvent_->SetFixedMode(fixedMode);
    WindowGroupInfo windowGroupInfo;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->PrintWindowGroupInfo(windowGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerOneTest_PrintDisplayGroupInfo
 * @tc.desc: Test PrintDisplayGroupInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_PrintDisplayGroupInfo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    OLD::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 1;

    OLD::DisplayInfo displayInfo1;
    displayInfo1.id = 1;
    displayInfo1.x = 1;
    displayInfo1.y = 1;
    displayInfo1.width = 2;
    displayInfo1.height = 2;
    displayInfo1.dpi = 240;
    displayInfo1.name = "pp";
    displayInfo1.direction = DIRECTION0;
    displayInfo1.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_MAIN;

    OLD::DisplayInfo displayInfo2;
    displayInfo2.id = 2;
    displayInfo2.x = 1;
    displayInfo2.y = 1;
    displayInfo2.width = 2;
    displayInfo2.height = 2;
    displayInfo2.dpi = 240;
    displayInfo2.name = "pp";
    displayInfo2.uniq = "pp";
    displayInfo2.direction = DIRECTION0;
    displayInfo2.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_EXPAND;
    displayGroupInfo.displaysInfo.push_back(displayInfo2);
    displayGroupInfo.displaysInfo.push_back(displayInfo1);
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    pointerEvent->SetTargetDisplayId(-1);
    pointerEvent->SetTargetWindowId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    pointerEvent->SetDeviceId(CAST_INPUT_DEVICEID);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->PrintDisplayGroupInfo(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerOneTest_Dump
 * @tc.desc: Test the dump function of the input window manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_Dump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
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

    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetGlobalX(DBL_MAX);
    pointerItem.SetGlobalY(DBL_MAX);
    int32_t fd = 1;
    std::vector<std::string> args;
    ASSERT_NO_FATAL_FAILURE(inputWindowsManager->Dump(fd, args));
}

/**
 * @tc.name: InputWindowsManagerOneTest_UpdateKeyEventDisplayId
 * @tc.desc: Test the funcation UpdateKeyEventDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_UpdateKeyEventDisplayId, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    int32_t focusWindowId = 1;
    int32_t groupId = 0;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->UpdateKeyEventDisplayId(keyEvent, focusWindowId));

    WindowInfo windowInfo = {.displayId = 1};
    WindowGroupInfo windowGroupInfo = {.focusWindowId = 1, .displayId = 1, .windowsInfo = {windowInfo}};
    inputWindowsManager->windowsPerDisplay_.emplace(std::make_pair(1, windowGroupInfo));
    keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    inputWindowsManager->UpdateKeyEventDisplayId(keyEvent, focusWindowId);
    EXPECT_EQ(keyEvent->GetTargetDisplayId(), -1);

    OLD::DisplayInfo displayInfo1;
    displayInfo1.id = 1;
    displayInfo1.x = 1;
    displayInfo1.y = 1;
    displayInfo1.width = 2;
    displayInfo1.height = 2;
    displayInfo1.dpi = 240;
    displayInfo1.name = "pp";
    displayInfo1.direction = DIRECTION0;
    displayInfo1.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_MAIN;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.displaysInfo.emplace_back(displayInfo1);
    }
    inputWindowsManager->windowsPerDisplayMap_.clear();
    std::map<int32_t, WindowGroupInfo> windowsPerDisplay = {
        {focusWindowId + 1, windowGroupInfo}
    };
    inputWindowsManager->windowsPerDisplayMap_.emplace(0, windowsPerDisplay);
    ASSERT_NO_FATAL_FAILURE(inputWindowsManager->UpdateKeyEventDisplayId(keyEvent, focusWindowId, groupId));
    EXPECT_EQ(keyEvent->GetTargetDisplayId(), 1);
}

/**
 * @tc.name: InputWindowsManagerOneTest_GetWindowInfoById
 * @tc.desc: Test GetWindowInfoById
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_GetWindowInfoById, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    int32_t focusWindowId = 1;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    WindowGroupInfo windowGroupInfo = {.focusWindowId = 1, .displayId = 1, .windowsInfo = {windowInfo}};
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->windowsPerDisplayMap_.clear();
    std::map<int32_t, WindowGroupInfo> windowsPerDisplay = {
        {focusWindowId + 1, windowGroupInfo}
    };
    inputWindowsManager->windowsPerDisplayMap_.emplace(0, windowsPerDisplay);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetGlobalX(DBL_MAX);
    pointerItem.SetGlobalY(DBL_MAX);
    int32_t windowId = 1;
    std::optional<WindowInfo> info = inputWindowsManager->GetWindowInfoById(windowId);
    EXPECT_TRUE(info.has_value());
}

/**
 * @tc.name: InputWindowsManagerOneTest_NeedTouchTracking
 * @tc.desc: Test NeedTouchTracking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_NeedTouchTracking, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ASSERT_NE(inputWindowsManager, nullptr);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    auto pointerId = 1;
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetGlobalX(DBL_MAX);
    pointerItem.SetGlobalY(DBL_MAX);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;

    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->lastTouchEvent_->SetPointerId(pointerId);
    pointerItem.SetPointerId(pointerId);
    inputWindowsManager->lastTouchEvent_->pointers_.push_back(pointerItem);
    auto fixedMode = PointerEvent::FixedMode::NORMAL;
    inputWindowsManager->lastTouchEvent_->SetFixedMode(fixedMode);
    PointerEvent event(InputEvent::EVENT_TYPE_POINTER);
    ASSERT_NO_FATAL_FAILURE(inputWindowsManager->NeedTouchTracking(event));

    event.AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_ACCESSIBILITY);
    ASSERT_NO_FATAL_FAILURE(inputWindowsManager->NeedTouchTracking(event));

    event.SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_MOVE);
    ASSERT_NO_FATAL_FAILURE(inputWindowsManager->NeedTouchTracking(event));
}

/**
 * @tc.name: InputWindowsManagerOneTest_ProcessTouchTracking_001
 * @tc.desc: Test ProcessTouchTracking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ProcessTouchTracking_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ASSERT_NE(inputWindowsManager, nullptr);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    ASSERT_NO_FATAL_FAILURE(inputWindowsManager->ProcessTouchTracking(pointerEvent, windowInfo));
    pointerEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_ACCESSIBILITY);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_MOVE);
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    ASSERT_NO_FATAL_FAILURE(inputWindowsManager->ProcessTouchTracking(pointerEvent, windowInfo));
    int32_t windowId = 1;
    pointerEvent->SetTargetWindowId(windowId);
    ASSERT_NO_FATAL_FAILURE(inputWindowsManager->ProcessTouchTracking(pointerEvent, windowInfo));
}

/**
 * @tc.name: InputWindowsManagerOneTest_ProcessTouchTracking_002
 * @tc.desc: Test ProcessTouchTracking
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ProcessTouchTracking_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ASSERT_NE(inputWindowsManager, nullptr);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    UDSServer udsServer;
    inputWindowsManager->udsServer_ = &udsServer;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.flags = 0;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    pointerEvent->AddFlag(OHOS::MMI::InputEvent::EVENT_FLAG_ACCESSIBILITY);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_MOVE);
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    int32_t windowId = 2;
    pointerEvent->SetTargetWindowId(windowId);
    ASSERT_NO_FATAL_FAILURE(inputWindowsManager->ProcessTouchTracking(pointerEvent, windowInfo));
}

/**
 * @tc.name: InputWindowsManagerOneTest_AddActiveWindow
 * @tc.desc: Test the function AddActiveWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_AddActiveWindow, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ASSERT_NE(inputWindowsManager, nullptr);
    int32_t windowId = 1;
    int32_t pointerId = 0;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->AddActiveWindow(windowId, pointerId));

    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    auto it = inputWindowsManager->displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->displayGroupInfoMap_.end()) {
        it->second.windowsInfo.push_back(windowInfo);
    }
    inputWindowsManager->AddActiveWindow(windowId, pointerId);
    pointerId = 100;
    inputWindowsManager->activeTouchWinTypes_.clear();
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->AddActiveWindow(windowId, pointerId));
}

/* *
 * @tc.name: InputWindowsManagerOneTest_UpdateTargetTouchWinIds_001
 * @tc.desc: Test the funcation UpdateTargetTouchWinIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_UpdateTargetTouchWinIds_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo winInfo;
    int32_t pointerId = 1;
    PointerEvent::PointerItem pointerItem;

    inputWindowsManager->targetTouchWinIds_[1][1] = {10, 20, 30};
    inputWindowsManager->targetTouchWinIds_[1][2] = {10, 20, 30};
    pointerItem.SetDisplayXPos(0.0);
    pointerItem.SetDisplayYPos(0.0);
    winInfo.windowInputType = WindowInputType::TRANSMIT_ALL;
    inputWindowsManager->UpdateTargetTouchWinIds(winInfo, pointerItem, pointerEvent, pointerId, 1, 1);
    EXPECT_FALSE(inputWindowsManager->targetTouchWinIds_[1][pointerId].empty());
}

/* *
 * @tc.name: InputWindowsManagerOneTest_ShiftAppSimulateTouchPointerEvent
 * @tc.desc: Test the funcation ShiftAppSimulateTouchPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_ShiftAppSimulateTouchPointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ShiftWindowInfo shiftWindowInfo;
    shiftWindowInfo.fingerId = 1;
    PointerEvent::PointerItem item;
    int32_t pointerId = 0;
    item.SetPointerId(pointerId);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    inputWindowsManager->lastTouchEvent_ = pointerEvent;
    pointerEvent->pointers_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppSimulateTouchPointerEvent(shiftWindowInfo));
    shiftWindowInfo.fingerId = 0;
    item.pressed_ = false;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppSimulateTouchPointerEvent(shiftWindowInfo));
    item.pressed_ = true;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppSimulateTouchPointerEvent(shiftWindowInfo));
    shiftWindowInfo.x = -1;
    shiftWindowInfo.y = -1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppSimulateTouchPointerEvent(shiftWindowInfo));
    shiftWindowInfo.x = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppSimulateTouchPointerEvent(shiftWindowInfo));
    shiftWindowInfo.x = -1;
    shiftWindowInfo.y = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->ShiftAppSimulateTouchPointerEvent(shiftWindowInfo));
}

#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
/* *
 * @tc.name: InputWindowsManagerOneTest_TouchEnterLeaveEvent
 * @tc.desc: Test the funcation TouchEnterLeaveEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_TouchEnterLeaveEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetDisplayXPos(0.0);
    pointerItem.SetDisplayYPos(0.0);
    auto logicalX = 100;
    auto logicalY = 200;
    WindowInfo touchWindow;
    auto pointerId = 1;
    touchWindow.id = 1;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    pointerEvent->targetWindowId_ = 1;
    pointerEvent->pointers_.clear();
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TouchEnterLeaveEvent(logicalX, logicalY, pointerEvent, &touchWindow));
    pointerItem.SetPointerId(pointerId);
    pointerEvent->pointers_.push_back(pointerItem);
    EXPECT_EQ(pointerEvent->GetPointerCount(), pointerId);
    pointerEvent->SetPointerId(pointerId);
    EXPECT_TRUE(pointerEvent->GetPointerItem(pointerId, pointerItem));
    touchWindow.windowInputType = WindowInputType::ANTI_MISTAKE_TOUCH;
    inputWindowsManager->lastTouchWindowInfo_.id = touchWindow.id;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TouchEnterLeaveEvent(logicalX, logicalY, pointerEvent, &touchWindow));

    touchWindow.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    inputWindowsManager->lastTouchWindowInfo_.id = 5;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TouchEnterLeaveEvent(logicalX, logicalY, pointerEvent, &touchWindow));

    inputWindowsManager->lastTouchWindowInfo_.id = -1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TouchEnterLeaveEvent(logicalX, logicalY, pointerEvent, &touchWindow));

    inputWindowsManager->lastTouchWindowInfo_.id = 5;
    touchWindow.windowInputType = WindowInputType::SLID_TOUCH_WINDOW;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->TouchEnterLeaveEvent(logicalX, logicalY, pointerEvent, &touchWindow));
}
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING

/**
 * @tc.name: InputWindowsManagerOneTest_AdjustDisplayRotation_001
 * @tc.desc: Test the funcation AdjustDisplayRotation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_AdjustDisplayRotation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    ASSERT_NE(inputWindowsManager, nullptr);
    auto it = inputWindowsManager->cursorPosMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager->cursorPosMap_.end()) {
        it->second.direction = Direction::DIRECTION0;
    }
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->AdjustDisplayRotation());
    it->second.direction = Direction::DIRECTION90;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->AdjustDisplayRotation());
    it->second.direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->AdjustDisplayRotation());
    it->second.direction = Direction::DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager->AdjustDisplayRotation());
}

#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

/**
 * @tc.name: InputWindowsManagerOneTest_FoldScreenRotation_010
 * @tc.desc: Test the function FoldScreenRotation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_FoldScreenRotation_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfoEX winInfoEx;
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 10;
    pointerEvent->bitwise_ = 0x00000080;
    pointerEvent->SetPointerId(1);
    pointerEvent->SetTargetDisplayId(10);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.FoldScreenRotation(pointerEvent));
}

/**
 * @tc.name: InputWindowsManagerOneTest_FoldScreenRotation_011
 * @tc.desc: Test the function FoldScreenRotation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_FoldScreenRotation_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfoEX winInfoEx;
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 10;
    pointerEvent->bitwise_ = 0x00000080;
    pointerEvent->SetPointerId(1);
    pointerEvent->SetTargetDisplayId(10);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    OLD::DisplayGroupInfo displayGroupInfoRef;
    auto it = inputWindowsManager.displayGroupInfoMap_.find(DEFAULT_GROUP_ID);
    if (it != inputWindowsManager.displayGroupInfoMap_.end()) {
        displayGroupInfoRef = it->second;
    }
    displayGroupInfoRef.displaysInfo.push_back(displayInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.FoldScreenRotation(pointerEvent));
}

/**
 * @tc.name: InputWindowsManagerOneTest_HandleHardWareCursorTest002
 * @tc.desc: Test the funcation HandleHardWareCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, InputWindowsManagerOneTest_HandleHardWareCursorTest002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputWindowsManager> inputWindowsManager =
        std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(inputWindowsManager, nullptr);
    std::vector<int32_t> result = inputWindowsManager->HandleHardwareCursor(nullptr, 512, 384);
    EXPECT_EQ(result[0], DEFAULT_POSITION);
    EXPECT_EQ(result[1], DEFAULT_POSITION);
}

/**
 * @tc.name: IsMouseDragging_001
 * @tc.desc: Test the IsMouseDragging
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, IsMouseDragging_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ExtraData extraData1 {};
    extraData1.appended = true;
    extraData1.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    WIN_MGR->AppendExtraData(extraData1);
    EXPECT_TRUE(WIN_MGR->IsMouseDragging());

    ExtraData extraData2 {};
    extraData2.appended = false;
    extraData2.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    WIN_MGR->AppendExtraData(extraData2);
    EXPECT_FALSE(WIN_MGR->IsMouseDragging());

    ExtraData extraData3 {};
    extraData3.appended = false;
    extraData3.sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    WIN_MGR->AppendExtraData(extraData3);
    EXPECT_FALSE(WIN_MGR->IsMouseDragging());
}

/**
 * @tc.name: EnsureMouseEventCycle_001
 * @tc.desc: Test EnsureMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, EnsureMouseEventCycle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->EnsureMouseEventCycle(nullptr));
}

/**
 * @tc.name: EnsureMouseEventCycle_002
 * @tc.desc: Test EnsureMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, EnsureMouseEventCycle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto event = PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->EnsureMouseEventCycle(event));
}

/**
 * @tc.name: EnsureMouseEventCycle_003
 * @tc.desc: Test EnsureMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, EnsureMouseEventCycle_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ExtraData extraData {};
    extraData.appended = true;
    extraData.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    WIN_MGR->AppendExtraData(extraData);

    auto event = PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->EnsureMouseEventCycle(event));
}

/**
 * @tc.name: EnsureMouseEventCycle_004
 * @tc.desc: Test EnsureMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, EnsureMouseEventCycle_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ExtraData extraData {};
    extraData.appended = false;
    extraData.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    WIN_MGR->AppendExtraData(extraData);

    auto event = PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    event->ClearFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->EnsureMouseEventCycle(event));
}

/**
 * @tc.name: EnsureMouseEventCycle_005
 * @tc.desc: Test EnsureMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, EnsureMouseEventCycle_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto winMgr = std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(winMgr, nullptr);

    ExtraData extraData {};
    extraData.appended = false;
    extraData.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    winMgr->AppendExtraData(extraData);

    auto event = PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    event->AddFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    EXPECT_NO_FATAL_FAILURE(winMgr->EnsureMouseEventCycle(event));
}

/**
 * @tc.name: EnsureMouseEventCycle_006
 * @tc.desc: Test EnsureMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, EnsureMouseEventCycle_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto winMgr = std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(winMgr, nullptr);

    ExtraData extraData {};
    extraData.appended = false;
    extraData.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    winMgr->AppendExtraData(extraData);

    int32_t displayId { -1 };
    int32_t windowId { -1 };
    winMgr->mouseDownInfo_.displayId = displayId;
    winMgr->mouseDownInfo_.id = windowId;
    winMgr->mouseDownInfo_.agentWindowId = windowId;

    auto event = PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    event->AddFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    EXPECT_NO_FATAL_FAILURE(winMgr->EnsureMouseEventCycle(event));
}

/**
 * @tc.name: EnsureMouseEventCycle_007
 * @tc.desc: Test EnsureMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, EnsureMouseEventCycle_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto winMgr = std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(winMgr, nullptr);

    ExtraData extraData {};
    extraData.appended = false;
    extraData.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    winMgr->AppendExtraData(extraData);

    int32_t displayId { 1 };
    int32_t windowId { 37 };
    winMgr->mouseDownInfo_.displayId = displayId;
    winMgr->mouseDownInfo_.id = windowId;
    winMgr->mouseDownInfo_.agentWindowId = windowId;

    auto event = PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    event->AddFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    event->SetTargetWindowId(windowId);
    EXPECT_NO_FATAL_FAILURE(winMgr->EnsureMouseEventCycle(event));
}

/**
 * @tc.name: EnsureMouseEventCycle_008
 * @tc.desc: Test EnsureMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, EnsureMouseEventCycle_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto winMgr = std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(winMgr, nullptr);
    ExtraData extraData {};
    extraData.appended = false;
    extraData.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    winMgr->AppendExtraData(extraData);

    int32_t displayId { 1 };
    int32_t windowId { 37 };
    winMgr->mouseDownInfo_.displayId = displayId;
    winMgr->mouseDownInfo_.id = windowId;
    winMgr->mouseDownInfo_.agentWindowId = windowId;

    auto event = PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    event->AddFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    int32_t targetWindowId { 43 };
    event->SetTargetWindowId(targetWindowId);

    EXPECT_NO_FATAL_FAILURE(winMgr->EnsureMouseEventCycle(event));
    EXPECT_EQ(event->GetTargetDisplayId(), displayId);
    EXPECT_EQ(event->GetTargetWindowId(), windowId);
    EXPECT_EQ(event->GetAgentWindowId(), windowId);
}

/**
 * @tc.name: CleanMouseEventCycle_001
 * @tc.desc: Test CleanMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CleanMouseEventCycle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->CleanMouseEventCycle(nullptr));
}

/**
 * @tc.name: CleanMouseEventCycle_002
 * @tc.desc: Test CleanMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CleanMouseEventCycle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto event = PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    auto winMgr = std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(winMgr, nullptr);
    int32_t windowId { 37 };
    int32_t pid { 16 };
    winMgr->mouseDownInfo_.id = windowId;
    winMgr->mouseDownInfo_.pid = pid;

    EXPECT_NO_FATAL_FAILURE(winMgr->CleanMouseEventCycle(event));
}

/**
 * @tc.name: CleanMouseEventCycle_003
 * @tc.desc: Test CleanMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CleanMouseEventCycle_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto event = PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);

    auto winMgr = std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(winMgr, nullptr);
    EXPECT_NO_FATAL_FAILURE(winMgr->CleanMouseEventCycle(event));
    EXPECT_EQ(winMgr->mouseDownInfo_.id, -1);
    EXPECT_EQ(winMgr->mouseDownInfo_.pid, -1);
    EXPECT_TRUE(winMgr->mouseDownInfo_.defaultHotAreas.empty());
    EXPECT_TRUE(winMgr->mouseDownInfo_.pointerHotAreas.empty());
}

/**
 * @tc.name: CleanMouseEventCycle_004
 * @tc.desc: Test CleanMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CleanMouseEventCycle_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto event = PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);

    auto winMgr = std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(winMgr, nullptr);
    EXPECT_NO_FATAL_FAILURE(winMgr->CleanMouseEventCycle(event));
    EXPECT_EQ(winMgr->mouseDownInfo_.id, -1);
    EXPECT_EQ(winMgr->mouseDownInfo_.pid, -1);
    EXPECT_TRUE(winMgr->mouseDownInfo_.defaultHotAreas.empty());
    EXPECT_TRUE(winMgr->mouseDownInfo_.pointerHotAreas.empty());
}

/**
 * @tc.name: CleanMouseEventCycle_005
 * @tc.desc: Test CleanMouseEventCycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CleanMouseEventCycle_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto event = PointerEvent::Create();
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);

    auto winMgr = std::static_pointer_cast<InputWindowsManager>(WIN_MGR);
    ASSERT_NE(winMgr, nullptr);
    int32_t windowId { 37 };
    int32_t pid { 16 };
    winMgr->mouseDownInfo_.id = windowId;
    winMgr->mouseDownInfo_.pid = pid;

    EXPECT_NO_FATAL_FAILURE(winMgr->CleanMouseEventCycle(event));
}
} // namespace MMI
} // namespace OHOS
