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

#include <cstdio>
#include <gmock/gmock.h>
#include <memory>
#include <vector>

#include "input_windows_manager.h"
#include "key_event.h"
#include "pointer_event.h"
#include "window_info.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputWindowsManagerMethodsTest"

using namespace OHOS::MMI;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace MMI {

// ============================================================================
// Test Constants - Descriptive names for magic numbers
// ============================================================================
namespace TestConstants {
    // Coordinate values for testing
    constexpr int32_t DEFAULT_DISPLAY_X = 500;
    constexpr int32_t DEFAULT_DISPLAY_Y = 400;
    constexpr int32_t OUT_OF_BOUNDS_X = 9999;
    constexpr int32_t OUT_OF_BOUNDS_Y = 9999;
    constexpr int32_t CLAMP_MIN_X = 100;
    constexpr int32_t CLAMP_MIN_Y = 150;

    // Window size values
    constexpr int32_t DEFAULT_WINDOW_WIDTH = 1000;
    constexpr int32_t DEFAULT_WINDOW_HEIGHT = 800;

    // Display size values
    constexpr int32_t DEFAULT_DISPLAY_WIDTH = 1920;
    constexpr int32_t DEFAULT_DISPLAY_HEIGHT = 1080;

    // ID values
    constexpr int32_t TEST_PROCESS_ID = 100;
    constexpr int32_t TEST_POINTER_ID = 1;
    constexpr int32_t TEST_DEVICE_ID = 5;
    constexpr int32_t TEST_KEY_DEVICE_ID = 1;
    constexpr int32_t TEST_WINDOW_ID = 1;
    constexpr int32_t INVALID_DEVICE_ID = 99999;
    constexpr int32_t INVALID_POINTER_ID = 99999;
    constexpr int32_t INVALID_GROUP_ID = 99999;

    // ZOrder values
    constexpr int32_t DEFAULT_ZORDER = 1;
    constexpr int32_t MEDIUM_ZORDER = 3;
    constexpr int32_t HIGH_ZORDER = 5;
} // namespace TestConstants

/**
 * @class InputWindowsManagerMethodsTest
 * @brief Test fixture for InputWindowsManager specific methods
 */
class InputWindowsManagerOneTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        // Setup code that runs once before all tests
    }

    static void TearDownTestCase(void)
    {
        // Cleanup code that runs once after all tests
    }

    void SetUp(void) override
    {
        // Setup code that runs before each test
        inputWindowsManager_ = std::make_shared<InputWindowsManager>();
        ASSERT_NE(inputWindowsManager_, nullptr);
    }

    void TearDown(void) override
    {
        // Cleanup code that runs after each test
        inputWindowsManager_.reset();
    }

protected:
    /**
     * @brief Create a test pointer event
     * @param pointerId The pointer ID
     * @param action The pointer action
     * @param sourceType The source type
     * @return Shared pointer to the created pointer event
     */
    std::shared_ptr<PointerEvent> CreateTestPointerEvent(int32_t pointerId = TestConstants::TEST_POINTER_ID,
        int32_t action = PointerEvent::POINTER_ACTION_MOVE,
        int32_t sourceType = PointerEvent::SOURCE_TYPE_MOUSE)
    {
        auto pointerEvent = PointerEvent::Create();
        if (pointerEvent == nullptr) {
            return nullptr;
        }

        PointerEvent::PointerItem pointerItem;
        pointerItem.SetPointerId(pointerId);
        pointerItem.SetDisplayX(TestConstants::DEFAULT_DISPLAY_X);
        pointerItem.SetDisplayY(TestConstants::DEFAULT_DISPLAY_Y);
        pointerItem.SetWindowX(TestConstants::DEFAULT_DISPLAY_X);
        pointerItem.SetWindowY(TestConstants::DEFAULT_DISPLAY_Y);
        pointerEvent->AddPointerItem(pointerItem);
        pointerEvent->SetPointerId(pointerId);
        pointerEvent->SetPointerAction(action);
        pointerEvent->SetSourceType(sourceType);
        pointerEvent->SetDeviceId(TestConstants::TEST_DEVICE_ID);

        return pointerEvent;
    }

    /**
     * @brief Create a test key event
     * @param action The key action
     * @param flags The event flags
     * @return Shared pointer to the created key event
     */
    std::shared_ptr<KeyEvent> CreateTestKeyEvent(int32_t action = KeyEvent::KEY_ACTION_DOWN,
        uint32_t flags = 0)
    {
        auto keyEvent = KeyEvent::Create();
        if (keyEvent == nullptr) {
            return nullptr;
        }

        keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
        keyEvent->SetKeyAction(action);
        keyEvent->SetDeviceId(TestConstants::TEST_KEY_DEVICE_ID);
        keyEvent->AddFlag(flags);

        return keyEvent;
    }

    /**
     * @brief Create a test window info
     * @param windowId The window ID
     * @param flags The window flags
     * @return WindowInfo structure
     */
    WindowInfo CreateTestWindowInfo(int32_t windowId = TestConstants::TEST_WINDOW_ID, uint32_t flags = 0)
    {
        WindowInfo windowInfo;
        windowInfo.id = windowId;
        windowInfo.flags = flags;
        windowInfo.pid = TestConstants::TEST_PROCESS_ID;
        windowInfo.area.width = TestConstants::DEFAULT_WINDOW_WIDTH;
        windowInfo.area.height = TestConstants::DEFAULT_WINDOW_HEIGHT;
        windowInfo.zOrder = TestConstants::DEFAULT_ZORDER;

        return windowInfo;
    }

    std::shared_ptr<InputWindowsManager> inputWindowsManager_;
};

// ============================================================================
// Test Cases for SendBackCenterPointerEvent
// ============================================================================

/**
 * @tc.name: SendBackCenterPointerEvent_NullLastPointerEvent_001
 * @tc.desc: Test SendBackCenterPointerEvent with null last pointer event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, SendBackCenterPointerEvent_NullLastPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Cursor position but null last pointer event
    inputWindowsManager_->lastPointerEvent_ = nullptr;
    CursorPosition cursorPos;
    cursorPos.displayId = 0;
    cursorPos.cursorPos.x = TestConstants::DEFAULT_DISPLAY_X;
    cursorPos.cursorPos.y = TestConstants::DEFAULT_DISPLAY_Y;

    // When: Call SendBackCenterPointerEvent with null last pointer event
    // Then: Should handle gracefully (CHKPV will return) without modifying state
    inputWindowsManager_->SendBackCenterPointerEvent(cursorPos);
    EXPECT_EQ(inputWindowsManager_->lastPointerEvent_, nullptr);
}

/**
 * @tc.name: SendBackCenterPointerEvent_NoWindowFound_002
 * @tc.desc: Test SendBackCenterPointerEvent when no window is found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, SendBackCenterPointerEvent_NoWindowFound_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Valid cursor position but no window at that position
    auto pointerEvent = CreateTestPointerEvent(1, PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NE(pointerEvent, nullptr);
    inputWindowsManager_->lastPointerEvent_ = pointerEvent;
    int32_t originalAction = pointerEvent->GetPointerAction();

    CursorPosition cursorPos;
    cursorPos.displayId = 0;
    cursorPos.cursorPos.x = TestConstants::OUT_OF_BOUNDS_X;
    cursorPos.cursorPos.y = TestConstants::OUT_OF_BOUNDS_Y;

    // When: Call SendBackCenterPointerEvent
    // Then: Should return early when no window found without modifying last event
    inputWindowsManager_->SendBackCenterPointerEvent(cursorPos);
    EXPECT_EQ(inputWindowsManager_->lastPointerEvent_->GetPointerAction(), originalAction);
}

/**
 * @tc.name: SendBackCenterPointerEvent_PointerActionMove_003
 * @tc.desc: Test SendBackCenterPointerEvent with POINTER_ACTION_MOVE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, SendBackCenterPointerEvent_PointerActionMove_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Valid cursor position and MOVE action
    auto pointerEvent = CreateTestPointerEvent(1, PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NE(pointerEvent, nullptr);

    CursorPosition cursorPos;
    cursorPos.displayId = 0;
    cursorPos.cursorPos.x = TestConstants::DEFAULT_DISPLAY_X;
    cursorPos.cursorPos.y = TestConstants::DEFAULT_DISPLAY_Y;

    // When: Call SendBackCenterPointerEvent with MOVE action
    // Then: Should set action to CANCEL
    inputWindowsManager_->lastPointerEvent_ = pointerEvent;
    inputWindowsManager_->SendBackCenterPointerEvent(cursorPos);
    EXPECT_EQ(inputWindowsManager_->lastPointerEvent_->GetPointerAction(), PointerEvent::POINTER_ACTION_CANCEL);
}

/**
 * @tc.name: SendBackCenterPointerEvent_PointerActionPullMove_004
 * @tc.desc: Test SendBackCenterPointerEvent with POINTER_ACTION_PULL_MOVE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, SendBackCenterPointerEvent_PointerActionPullMove_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Valid cursor position and PULL_MOVE action
    auto pointerEvent = CreateTestPointerEvent(1, PointerEvent::POINTER_ACTION_PULL_MOVE);
    ASSERT_NE(pointerEvent, nullptr);

    CursorPosition cursorPos;
    cursorPos.displayId = 0;
    cursorPos.cursorPos.x = TestConstants::DEFAULT_DISPLAY_X;
    cursorPos.cursorPos.y = TestConstants::DEFAULT_DISPLAY_Y;

    // When: Call SendBackCenterPointerEvent with PULL_MOVE action
    // Then: Should set action to PULL_CANCEL
    inputWindowsManager_->lastPointerEvent_ = pointerEvent;
    inputWindowsManager_->SendBackCenterPointerEvent(cursorPos);
    EXPECT_EQ(inputWindowsManager_->lastPointerEvent_->GetPointerAction(), PointerEvent::POINTER_ACTION_PULL_CANCEL);
}

// ============================================================================
// Test Cases for PrintHighZorder
// ============================================================================

/**
 * @tc.name: PrintHighZorder_NullTargetWindow_001
 * @tc.desc: Test PrintHighZorder with null target window
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, PrintHighZorder_NullTargetWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Invalid target window ID
    int32_t targetWindowId = -1;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_AXIS_BEGIN;
    int32_t logicalX = TestConstants::DEFAULT_DISPLAY_X;
    int32_t logicalY = TestConstants::DEFAULT_DISPLAY_Y;

    std::vector<WindowInfo> windowsInfo;
    size_t originalSize = windowsInfo.size();

    // When: Call PrintHighZorder with invalid target window
    // Then: Should return early without printing or modifying state
    inputWindowsManager_->PrintHighZorder(windowsInfo, pointerAction,
        targetWindowId, logicalX, logicalY);
    EXPECT_EQ(windowsInfo.size(), originalSize);
}

/**
 * @tc.name: PrintHighZorder_ValidTargetNoHigherZorder_002
 * @tc.desc: Test PrintHighZorder with valid target but no higher zorder windows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, PrintHighZorder_ValidTargetNoHigherZorder_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Valid target window with no higher zorder windows
    WindowInfo targetWindow = CreateTestWindowInfo(TestConstants::TEST_WINDOW_ID, 0);
    targetWindow.zOrder = TestConstants::HIGH_ZORDER;

    std::vector<WindowInfo> windowsInfo;
    windowsInfo.push_back(targetWindow);

    int32_t targetWindowId = TestConstants::TEST_WINDOW_ID;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_AXIS_BEGIN;
    int32_t logicalX = TestConstants::DEFAULT_DISPLAY_X;
    int32_t logicalY = TestConstants::DEFAULT_DISPLAY_Y;
    size_t originalSize = windowsInfo.size();

    // When: Call PrintHighZorder with no higher zorder windows
    // Then: Should not modify input data
    inputWindowsManager_->PrintHighZorder(windowsInfo, pointerAction,
        targetWindowId, logicalX, logicalY);
    EXPECT_EQ(windowsInfo.size(), originalSize);
    EXPECT_EQ(windowsInfo[0].id, 1);
}

/**
 * @tc.name: PrintHighZorder_HigherZorderWindowsExist_003
 * @tc.desc: Test PrintHighZorder with higher zorder windows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, PrintHighZorder_HigherZorderWindowsExist_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Target window with higher zorder windows
    WindowInfo targetWindow = CreateTestWindowInfo(TestConstants::TEST_WINDOW_ID, 0);
    targetWindow.zOrder = TestConstants::MEDIUM_ZORDER;

    WindowInfo higherWindow = CreateTestWindowInfo(2, 0);
    higherWindow.zOrder = TestConstants::HIGH_ZORDER;
    higherWindow.windowInputType = WindowInputType::NORMAL;

    std::vector<WindowInfo> windowsInfo;
    windowsInfo.push_back(higherWindow);
    windowsInfo.push_back(targetWindow);

    int32_t targetWindowId = TestConstants::TEST_WINDOW_ID;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_AXIS_BEGIN;
    int32_t logicalX = TestConstants::DEFAULT_DISPLAY_X;
    int32_t logicalY = TestConstants::DEFAULT_DISPLAY_Y;
    size_t originalSize = windowsInfo.size();

    // When: Call PrintHighZorder with higher zorder windows
    // Then: Should print zorder info without modifying input
    inputWindowsManager_->PrintHighZorder(windowsInfo, pointerAction,
        targetWindowId, logicalX, logicalY);
    EXPECT_EQ(windowsInfo.size(), originalSize);
}

// ============================================================================
// Test Cases for GetFocusPid
// ============================================================================

/**
 * @tc.name: GetFocusPid_NoDisplayGroup_001
 * @tc.desc: Test GetFocusPid when display group not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, GetFocusPid_NoDisplayGroup_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Non-existent display group ID
    int32_t groupId = TestConstants::INVALID_GROUP_ID;

    // When: Call GetFocusPid with non-existent group
    int32_t result = inputWindowsManager_->GetFocusPid(groupId);

    // Then: Should return -1
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: GetFocusPid_FocusWindowNotFound_002
 * @tc.desc: Test GetFocusPid when focus window not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, GetFocusPid_FocusWindowNotFound_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Display group exists but focus window doesn't
    int32_t groupId = 1;

    // When: Call GetFocusPid with non-existent focus window
    int32_t result = inputWindowsManager_->GetFocusPid(groupId);

    // Then: Should return -1
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: GetFocusPid_NoFocusWindow_003
 * @tc.desc: Test GetFocusPid when no focus window exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, GetFocusPid_NoFocusWindow_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Display group without any focus window set up
    int32_t groupId = 1;

    // When: Call GetFocusPid when no focus window exists
    int32_t result = inputWindowsManager_->GetFocusPid(groupId);

    // Then: Should return -1 when focus window is not found
    EXPECT_EQ(result, -1);
}

// ============================================================================
// Test Cases for ClearMismatchTypeWinIds
// ============================================================================

/**
 * @tc.name: ClearMismatchTypeWinIds_NoDeviceEntry_001
 * @tc.desc: Test ClearMismatchTypeWinIds when device entry doesn't exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, ClearMismatchTypeWinIds_NoDeviceEntry_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Non-existent device ID
    int32_t pointerId = 1;
    int32_t displayId = 0;
    int32_t deviceId = TestConstants::INVALID_DEVICE_ID;

    // When: Call ClearMismatchTypeWinIds with non-existent device
    // Then: Should return early without error or crash
    // This test verifies the function handles non-existent device gracefully
    EXPECT_NO_THROW(inputWindowsManager_->ClearMismatchTypeWinIds(pointerId, displayId, deviceId));
}

/**
 * @tc.name: ClearMismatchTypeWinIds_NoPointerEntry_002
 * @tc.desc: Test ClearMismatchTypeWinIds when pointer entry doesn't exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, ClearMismatchTypeWinIds_NoPointerEntry_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Existing device but non-existent pointer ID
    int32_t pointerId = TestConstants::INVALID_POINTER_ID;
    int32_t displayId = 0;
    int32_t deviceId = TestConstants::TEST_DEVICE_ID;

    // When: Call ClearMismatchTypeWinIds with non-existent pointer
    // Then: Should return early without error or crash
    EXPECT_NO_THROW(inputWindowsManager_->ClearMismatchTypeWinIds(pointerId, displayId, deviceId));
}

/**
 * @tc.name: ClearMismatchTypeWinIds_WindowsWithTransmitFlag_003
 * @tc.desc: Test ClearMismatchTypeWinIds with windows having TRANSMIT_ALL flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, ClearMismatchTypeWinIds_WindowsWithTransmitFlag_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Windows with TRANSMIT_ALL flag should be kept
    int32_t pointerId = 1;
    int32_t displayId = 0;
    int32_t deviceId = 5;

    // When: Call ClearMismatchTypeWinIds
    // Then: Should remove non-TRANSMIT_ALL windows only
    EXPECT_NO_THROW(inputWindowsManager_->ClearMismatchTypeWinIds(pointerId, displayId, deviceId));
}


// ============================================================================
// Test Cases for SetDragFlagByPointer
// ============================================================================

/**
 * @tc.name: SetDragFlagByPointer_ButtonDown_001
 * @tc.desc: Test SetDragFlagByPointer with BUTTON_DOWN action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, SetDragFlagByPointer_ButtonDown_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Pointer event with BUTTON_DOWN action
    auto pointerEvent = CreateTestPointerEvent(1, PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    ASSERT_NE(pointerEvent, nullptr);
    inputWindowsManager_->dragFlag_ = false;

    // When: Call SetDragFlagByPointer with BUTTON_DOWN
    // Then: Should set dragFlag_ to true
    inputWindowsManager_->SetDragFlagByPointer(pointerEvent);
    EXPECT_TRUE(inputWindowsManager_->dragFlag_);
}

/**
 * @tc.name: SetDragFlagByPointer_ButtonUp_002
 * @tc.desc: Test SetDragFlagByPointer with BUTTON_UP action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, SetDragFlagByPointer_ButtonUp_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Pointer event with BUTTON_UP action
    auto pointerEvent = CreateTestPointerEvent(1, PointerEvent::POINTER_ACTION_BUTTON_UP);
    ASSERT_NE(pointerEvent, nullptr);
    inputWindowsManager_->dragFlag_ = true;
    inputWindowsManager_->isDragBorder_ = true;

    // When: Call SetDragFlagByPointer with BUTTON_UP
    // Then: Should set dragFlag_ to false and isDragBorder_ to false
    inputWindowsManager_->SetDragFlagByPointer(pointerEvent);
    EXPECT_FALSE(inputWindowsManager_->dragFlag_);
    EXPECT_FALSE(inputWindowsManager_->isDragBorder_);
}

/**
 * @tc.name: SetDragFlagByPointer_OtherAction_003
 * @tc.desc: Test SetDragFlagByPointer with other actions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, SetDragFlagByPointer_OtherAction_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Pointer event with MOVE action
    auto pointerEvent = CreateTestPointerEvent(1, PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NE(pointerEvent, nullptr);
    inputWindowsManager_->dragFlag_ = true;

    // When: Call SetDragFlagByPointer with MOVE action
    // Then: Should not modify drag flags
    bool originalDragFlag = inputWindowsManager_->dragFlag_;
    inputWindowsManager_->SetDragFlagByPointer(pointerEvent);
    EXPECT_EQ(inputWindowsManager_->dragFlag_, originalDragFlag);
}

/**
 * @tc.name: SetDragFlagByPointer_NullEvent_004
 * @tc.desc: Test SetDragFlagByPointer with null event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, SetDragFlagByPointer_NullEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Null pointer event
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    inputWindowsManager_->dragFlag_ = true;

    // When: Call SetDragFlagByPointer with null event
    // Then: Should handle gracefully without modifying state
    inputWindowsManager_->SetDragFlagByPointer(pointerEvent);
    EXPECT_TRUE(inputWindowsManager_->dragFlag_);
}

// ============================================================================
// Test Cases for CancelAllTouches
// ============================================================================

/**
 * @tc.name: CancelAllTouches_NullEvent_001
 * @tc.desc: Test CancelAllTouches with null event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CancelAllTouches_NullEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Null pointer event
    std::shared_ptr<PointerEvent> event = nullptr;

    // When: Call CancelAllTouches with null event
    // Then: Should handle gracefully (CHKPV will return) without throwing
    EXPECT_NO_THROW(inputWindowsManager_->CancelAllTouches(event, false));
}

/**
 * @tc.name: CancelAllTouches_NoPressedItems_002
 * @tc.desc: Test CancelAllTouches with no pressed items
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CancelAllTouches_NoPressedItems_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Pointer event with no pressed items
    auto event = CreateTestPointerEvent(1, PointerEvent::POINTER_ACTION_UP);
    ASSERT_NE(event, nullptr);

    // When: Call CancelAllTouches with no pressed items
    // Then: Should complete without throwing
    EXPECT_NO_THROW(inputWindowsManager_->CancelAllTouches(event, false));
}

/**
 * @tc.name: CancelAllTouches_WithPressedItems_003
 * @tc.desc: Test CancelAllTouches with pressed items
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CancelAllTouches_WithPressedItems_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Pointer event with pressed items
    auto event = CreateTestPointerEvent(1, PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    // When: Call CancelAllTouches with pressed items
    // Then: Should cancel all touches without throwing
    EXPECT_NO_THROW(inputWindowsManager_->CancelAllTouches(event, false));
}

/**
 * @tc.name: CancelAllTouches_IsDragging_004
 * @tc.desc: Test CancelAllTouches when dragging
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CancelAllTouches_IsDragging_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Pointer event during dragging
    auto event = CreateTestPointerEvent(1, PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NE(event, nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);

    // When: Call CancelAllTouches during drag
    // Then: Should use PULL_CANCEL action without throwing
    EXPECT_NO_THROW(inputWindowsManager_->CancelAllTouches(event, false));
}

/**
 * @tc.name: CancelAllTouches_DisplayChanged_005
 * @tc.desc: Test CancelAllTouches when display changed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CancelAllTouches_DisplayChanged_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Pointer event with display changed
    auto event = CreateTestPointerEvent(1, PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NE(event, nullptr);

    // When: Call CancelAllTouches with isDisplayChanged=true
    // Then: Should add NO_INTERCEPT flag without throwing
    EXPECT_NO_THROW(inputWindowsManager_->CancelAllTouches(event, true));
}

// ============================================================================
// Test Cases for PullEnterLeaveEvent
// ============================================================================

/**
 * @tc.name: PullEnterLeaveEvent_NullPointerEvent_001
 * @tc.desc: Test PullEnterLeaveEvent with null pointer event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, PullEnterLeaveEvent_NullPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Window info but null pointer event
    WindowInfo touchWindow;
    touchWindow.id = TestConstants::TEST_WINDOW_ID;
    touchWindow.area.width = TestConstants::DEFAULT_WINDOW_WIDTH;
    touchWindow.area.height = TestConstants::DEFAULT_WINDOW_HEIGHT;

    int32_t logicalX = TestConstants::DEFAULT_DISPLAY_X;
    int32_t logicalY = TestConstants::DEFAULT_DISPLAY_Y;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;

    // When: Call PullEnterLeaveEvent with null pointer event
    // Then: Should return early (CHKPV) without throwing
    EXPECT_NO_THROW(inputWindowsManager_->PullEnterLeaveEvent(logicalX, logicalY,
        pointerEvent, &touchWindow));
}

/**
 * @tc.name: PullEnterLeaveEvent_NullTouchWindow_002
 * @tc.desc: Test PullEnterLeaveEvent with null touch window
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, PullEnterLeaveEvent_NullTouchWindow_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Valid pointer event but null touch window
    auto pointerEvent = CreateTestPointerEvent();
    ASSERT_NE(pointerEvent, nullptr);

    int32_t logicalX = TestConstants::DEFAULT_DISPLAY_X;
    int32_t logicalY = TestConstants::DEFAULT_DISPLAY_Y;
    WindowInfo* touchWindow = nullptr;

    // When: Call PullEnterLeaveEvent with null touch window
    // Then: Should return early (CHKPV) without throwing
    EXPECT_NO_THROW(inputWindowsManager_->PullEnterLeaveEvent(logicalX, logicalY,
        pointerEvent, touchWindow));
}

/**
 * @tc.name: PullEnterLeaveEvent_GetPointerItemFailed_003
 * @tc.desc: Test PullEnterLeaveEvent when GetPointerItem fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, PullEnterLeaveEvent_GetPointerItemFailed_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Valid pointers but GetPointerItem will fail
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(TestConstants::TEST_POINTER_ID);
    pointerEvent->SetDeviceId(TestConstants::TEST_DEVICE_ID);
    // Don't add any pointer items - GetPointerItem will fail

    WindowInfo touchWindow;
    touchWindow.id = TestConstants::TEST_WINDOW_ID;
    touchWindow.area.width = TestConstants::DEFAULT_WINDOW_WIDTH;
    touchWindow.area.height = TestConstants::DEFAULT_WINDOW_HEIGHT;

    int32_t logicalX = TestConstants::DEFAULT_DISPLAY_X;
    int32_t logicalY = TestConstants::DEFAULT_DISPLAY_Y;

    // When: Call PullEnterLeaveEvent with no pointer items
    // Then: Should return early when GetPointerItem fails without throwing
    EXPECT_NO_THROW(inputWindowsManager_->PullEnterLeaveEvent(logicalX, logicalY,
        pointerEvent, &touchWindow));
}

/**
 * @tc.name: PullEnterLeaveEvent_MixLeftRightAntiAxisMove_004
 * @tc.desc: Test PullEnterLeaveEvent with MIX_LEFT_RIGHT_ANTI_AXIS_MOVE window type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, PullEnterLeaveEvent_MixLeftRightAntiAxisMove_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: MIX_LEFT_RIGHT_ANTI_AXIS_MOVE window type
    auto pointerEvent = CreateTestPointerEvent();
    ASSERT_NE(pointerEvent, nullptr);

    WindowInfo touchWindow;
    touchWindow.id = TestConstants::TEST_WINDOW_ID;
    touchWindow.area.width = TestConstants::DEFAULT_WINDOW_WIDTH;
    touchWindow.area.height = TestConstants::DEFAULT_WINDOW_HEIGHT;
    touchWindow.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;

    int32_t logicalX = TestConstants::DEFAULT_DISPLAY_X;
    int32_t logicalY = TestConstants::DEFAULT_DISPLAY_Y;

    // When: Call PullEnterLeaveEvent with MIX_LEFT_RIGHT_ANTI_AXIS_MOVE type
    // Then: Should update pointer item coordinates without throwing
    EXPECT_NO_THROW(inputWindowsManager_->PullEnterLeaveEvent(logicalX, logicalY,
        pointerEvent, &touchWindow));
}

/**
 * @tc.name: PullEnterLeaveEvent_WindowSwitch_005
 * @tc.desc: Test PullEnterLeaveEvent when window switches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, PullEnterLeaveEvent_WindowSwitch_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Window switch scenario
    auto pointerEvent = CreateTestPointerEvent();
    ASSERT_NE(pointerEvent, nullptr);

    WindowInfo touchWindow;
    touchWindow.id = 2;  // Different window
    touchWindow.area.width = 1000;
    touchWindow.area.height = 800;
    touchWindow.windowInputType = WindowInputType::NORMAL;

    int32_t logicalX = TestConstants::DEFAULT_DISPLAY_X;
    int32_t logicalY = TestConstants::DEFAULT_DISPLAY_Y;

    // When: Call PullEnterLeaveEvent with different window
    // Then: Should handle window switch logic without throwing
    EXPECT_NO_THROW(inputWindowsManager_->PullEnterLeaveEvent(logicalX, logicalY,
        pointerEvent, &touchWindow));
}

/**
 * @tc.name: PullEnterLeaveEvent_CoordinateClamping_006
 * @tc.desc: Test PullEnterLeaveEvent with coordinate clamping
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, PullEnterLeaveEvent_CoordinateClamping_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Coordinates that need clamping
    auto pointerEvent = CreateTestPointerEvent();
    ASSERT_NE(pointerEvent, nullptr);

    WindowInfo touchWindow;
    touchWindow.id = TestConstants::TEST_WINDOW_ID;
    touchWindow.area.width = TestConstants::DEFAULT_WINDOW_WIDTH;
    touchWindow.area.height = TestConstants::DEFAULT_WINDOW_HEIGHT;
    touchWindow.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;

    // Set currentDisplayXY_ for lower boundary
    inputWindowsManager_->currentDisplayXY_.first = TestConstants::CLAMP_MIN_X;
    inputWindowsManager_->currentDisplayXY_.second = TestConstants::CLAMP_MIN_Y;

    int32_t logicalX = TestConstants::DEFAULT_DISPLAY_X;
    int32_t logicalY = TestConstants::DEFAULT_DISPLAY_Y;

    // When: Call PullEnterLeaveEvent with coordinates needing clamping
    // Then: Coordinates should be clamped to window bounds without throwing
    EXPECT_NO_THROW(inputWindowsManager_->PullEnterLeaveEvent(logicalX, logicalY,
        pointerEvent, &touchWindow));
}

// ============================================================================
// Test Cases for CalcDrawCoordinate
// ============================================================================

/**
 * @tc.name: CalcDrawCoordinate_EmptyTransform_001
 * @tc.desc: Test CalcDrawCoordinate with empty transform
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CalcDrawCoordinate_EmptyTransform_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Display info with empty transform
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.width = TestConstants::DEFAULT_DISPLAY_WIDTH;
    displayInfo.height = TestConstants::DEFAULT_DISPLAY_HEIGHT;
    displayInfo.validWidth = TestConstants::DEFAULT_DISPLAY_WIDTH;
    displayInfo.validHeight = TestConstants::DEFAULT_DISPLAY_HEIGHT;
    displayInfo.x = 0;
    displayInfo.y = 0;

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetRawDisplayX(TestConstants::DEFAULT_DISPLAY_X);
    pointerItem.SetRawDisplayY(TestConstants::DEFAULT_DISPLAY_Y);

    // When: Call CalcDrawCoordinate with empty transform
    auto result = inputWindowsManager_->CalcDrawCoordinate(displayInfo, pointerItem);

    // Then: Should return raw coordinates
    EXPECT_EQ(result.first, TestConstants::DEFAULT_DISPLAY_X);
    EXPECT_EQ(result.second, TestConstants::DEFAULT_DISPLAY_Y);
}

/**
 * @tc.name: CalcDrawCoordinate_WithTransform_002
 * @tc.desc: Test CalcDrawCoordinate with transform
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CalcDrawCoordinate_WithTransform_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Display info with transform
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.width = 1920;
    displayInfo.height = 1080;

    PointerEvent::PointerItem pointerItem;
    pointerItem.SetRawDisplayX(TestConstants::DEFAULT_DISPLAY_X);
    pointerItem.SetRawDisplayY(TestConstants::DEFAULT_DISPLAY_Y);

    // When: Call CalcDrawCoordinate
    auto result = inputWindowsManager_->CalcDrawCoordinate(displayInfo, pointerItem);

    // Then: Should return calculated coordinates
    EXPECT_GE(result.first, 0);
    EXPECT_GE(result.second, 0);
}

// ============================================================================
// Test Cases for CancelTouch
// ============================================================================

/**
 * @tc.name: CancelTouch_NoDeviceEntry_001
 * @tc.desc: Test CancelTouch when device entry doesn't exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CancelTouch_NoDeviceEntry_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Non-existent device ID
    int32_t touch = 1;
    int32_t deviceId = TestConstants::INVALID_DEVICE_ID;

    // When: Call CancelTouch with non-existent device
    bool result = inputWindowsManager_->CancelTouch(touch, deviceId);

    // Then: Should return false
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: CancelTouch_NoTouchEntry_002
 * @tc.desc: Test CancelTouch when touch entry doesn't exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CancelTouch_NoTouchEntry_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Existing device but non-existent touch ID
    int32_t touch = 99999;
    int32_t deviceId = 5;

    // When: Call CancelTouch with non-existent touch
    bool result = inputWindowsManager_->CancelTouch(touch, deviceId);

    // Then: Should return false
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: CancelTouch_ValidEntry_003
 * @tc.desc: Test CancelTouch with valid entry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerOneTest, CancelTouch_ValidEntry_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    // Given: Valid touch and device IDs with internal state set up
    int32_t touch = TestConstants::TEST_POINTER_ID;
    int32_t deviceId = TestConstants::TEST_DEVICE_ID;

    // Set up internal state: create a touch entry with flag=true
    WindowInfoEX windowInfoEx;
    windowInfoEx.window.id = TestConstants::TEST_WINDOW_ID;
    windowInfoEx.flag = true;
    inputWindowsManager_->touchItemDownInfos_[deviceId][touch] = windowInfoEx;

    // When: Call CancelTouch with valid entry
    bool result = inputWindowsManager_->CancelTouch(touch, deviceId);

    // Then: Should return true and clear the flag
    EXPECT_TRUE(result);
    EXPECT_FALSE(inputWindowsManager_->touchItemDownInfos_[deviceId][touch].flag);
}

} // namespace MMI
} // namespace OHOS
