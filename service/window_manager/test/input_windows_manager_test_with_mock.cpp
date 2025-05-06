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

#include <gmock/gmock.h>

#include "define_multimodal.h"
#include "input_event_handler.h"
#include "input_windows_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputWindowsManagerTestWithMock"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t FIRST_DISPLAY_ID { 1 };
constexpr int32_t DISPLAY_WIDTH { 720 };
constexpr int32_t DISPLAY_HEIGHT { 1280 };
constexpr int32_t FIRST_DISPLAY_DPI { 240 };
constexpr int32_t UPPER_WINDOW_ID { 1 };
constexpr int32_t LOWER_WINDOW_ID { 2 };
constexpr int32_t FIRST_POINTER_ID { 0 };
constexpr int32_t SECOND_POINTER_ID { 1 };
}

using namespace testing;
using namespace testing::ext;

void EventNormalizeHandler::HandleEvent(libinput_event* event, int64_t frameTime) {}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void EventNormalizeHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) {}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void EventNormalizeHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) {}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void EventNormalizeHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    if (nextHandler_ != nullptr) {
        nextHandler_->HandleTouchEvent(pointerEvent);
    }
}
#endif // OHOS_BUILD_ENABLE_TOUCH

class InputEventCheater final : public IInputEventHandler {
public:
    InputEventCheater() = default;
    ~InputEventCheater() override = default;

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_TOUCH
    std::shared_ptr<PointerEvent> GetTouchEvent();

private:
    std::shared_ptr<PointerEvent> touchEvent_;
};

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void InputEventCheater::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) {}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void InputEventCheater::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) {}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void InputEventCheater::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    touchEvent_ = std::make_shared<PointerEvent>(*pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

std::shared_ptr<PointerEvent> InputEventCheater::GetTouchEvent()
{
    return touchEvent_;
}

class InputWindowsManagerTestWithMock : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

private:
    void SetupDisplayInfo();
    std::shared_ptr<PointerEvent> BuildTouchEvent001();
    std::shared_ptr<PointerEvent> BuildTouchEvent002();
};

void InputWindowsManagerTestWithMock::SetUpTestCase()
{}

void InputWindowsManagerTestWithMock::TearDownTestCase()
{}

void InputWindowsManagerTestWithMock::SetUp()
{
    SetupDisplayInfo();
}

void InputWindowsManagerTestWithMock::TearDown()
{}

void InputWindowsManagerTestWithMock::SetupDisplayInfo()
{
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.width = DISPLAY_WIDTH;
    displayGroupInfo.height = DISPLAY_HEIGHT;
    displayGroupInfo.focusWindowId = UPPER_WINDOW_ID;

    WindowInfo upperWin {};
    upperWin.id = UPPER_WINDOW_ID;
    upperWin.area = Rect {
        .x = 0,
        .y = 0,
        .width = DISPLAY_WIDTH,
        .height = DISPLAY_HEIGHT / 2,
    };
    upperWin.defaultHotAreas = { upperWin.area };
    upperWin.pointerHotAreas = { upperWin.area };
    upperWin.agentWindowId = UPPER_WINDOW_ID;
    displayGroupInfo.windowsInfo.push_back(upperWin);

    WindowInfo lowerWin {};
    lowerWin.id = LOWER_WINDOW_ID;
    lowerWin.area = Rect {
        .x = 0,
        .y = DISPLAY_HEIGHT / 2,
        .width = DISPLAY_WIDTH,
        .height = DISPLAY_HEIGHT / 2,
    };
    lowerWin.defaultHotAreas = { lowerWin.area };
    lowerWin.pointerHotAreas = { lowerWin.area };
    lowerWin.agentWindowId = LOWER_WINDOW_ID;
    lowerWin.action = WINDOW_UPDATE_ACTION::ADD_END;
    displayGroupInfo.windowsInfo.push_back(lowerWin);

    DisplayInfo displayInfo {};
    displayInfo.id = FIRST_DISPLAY_ID;
    displayInfo.x = 0;
    displayInfo.y = 0;
    displayInfo.width = DISPLAY_WIDTH;
    displayInfo.height = DISPLAY_HEIGHT;
    displayInfo.dpi = FIRST_DISPLAY_DPI;
    displayInfo.name = "display 0";
    displayInfo.uniq = "default0";
    displayInfo.direction = DIRECTION0;
    displayGroupInfo.displaysInfo.push_back(displayInfo);

    WIN_MGR->UpdateDisplayInfo(displayGroupInfo);
}

std::shared_ptr<PointerEvent> InputWindowsManagerTestWithMock::BuildTouchEvent001()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    int32_t touchX { 360 };
    int32_t touchY { 960 };

    PointerEvent::PointerItem pointerItem {};
    pointerItem.SetPointerId(FIRST_POINTER_ID);
    pointerItem.SetDisplayX(touchX);
    pointerItem.SetDisplayY(touchY);
    pointerItem.SetDisplayXPos(touchX);
    pointerItem.SetDisplayYPos(touchY);
    pointerItem.SetPressed(true);
    pointerItem.SetTargetWindowId(UPPER_WINDOW_ID);
    pointerEvent->AddPointerItem(pointerItem);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(FIRST_POINTER_ID);
    pointerEvent->SetTargetWindowId(UPPER_WINDOW_ID);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> InputWindowsManagerTestWithMock::BuildTouchEvent002()
{
    auto pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    int32_t touchX1 { 360 };
    int32_t touchY1 { 320 };

    PointerEvent::PointerItem pointerItem {};
    pointerItem.SetPointerId(FIRST_POINTER_ID);
    pointerItem.SetDisplayX(touchX1);
    pointerItem.SetDisplayY(touchY1);
    pointerItem.SetDisplayXPos(touchX1);
    pointerItem.SetDisplayYPos(touchY1);
    pointerItem.SetPressed(true);
    pointerItem.SetTargetWindowId(UPPER_WINDOW_ID);
    pointerEvent->AddPointerItem(pointerItem);

    int32_t touchX2 { 360 };
    int32_t touchY2 { 960 };

    pointerItem.SetPointerId(SECOND_POINTER_ID);
    pointerItem.SetDisplayX(touchX2);
    pointerItem.SetDisplayY(touchY2);
    pointerItem.SetDisplayXPos(touchX2);
    pointerItem.SetDisplayYPos(touchY2);
    pointerItem.SetPressed(true);
    pointerItem.SetTargetWindowId(UPPER_WINDOW_ID);
    pointerEvent->AddPointerItem(pointerItem);

    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerId(SECOND_POINTER_ID);
    pointerEvent->SetTargetWindowId(UPPER_WINDOW_ID);
    return pointerEvent;
}

/**
 * @tc.name: InputWindowsManagerTestWithMock_TouchTracking_001
 * @tc.desc: This feature will be disabled by default, so events will be dispatched to the window first touch on.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTestWithMock, InputWindowsManagerTestWithMock_TouchTracking_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WIN_MGR->SwitchTouchTracking(false);
    auto pointerEvent = BuildTouchEvent001();
    ASSERT_NE(pointerEvent, nullptr);
    auto ret = WIN_MGR->UpdateTargetPointer(pointerEvent);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_EQ(pointerEvent->GetTargetWindowId(), UPPER_WINDOW_ID);
}

/**
 * @tc.name: InputWindowsManagerTestWithMock_TouchTracking_002
 * @tc.desc: With this feature enabled, touch events will be dispatched to touched window accordingly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTestWithMock, InputWindowsManagerTestWithMock_TouchTracking_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WIN_MGR->SwitchTouchTracking(true);
    auto pointerEvent = BuildTouchEvent001();
    ASSERT_NE(pointerEvent, nullptr);
    auto ret = WIN_MGR->UpdateTargetPointer(pointerEvent);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_EQ(pointerEvent->GetTargetWindowId(), LOWER_WINDOW_ID);
}

/**
 * @tc.name: InputWindowsManagerTestWithMock_TouchTracking_003
 * @tc.desc: Will skip touch events from accessibility.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTestWithMock, InputWindowsManagerTestWithMock_TouchTracking_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WIN_MGR->SwitchTouchTracking(true);
    auto pointerEvent = BuildTouchEvent001();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);

    auto ret = WIN_MGR->UpdateTargetPointer(pointerEvent);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_EQ(pointerEvent->GetTargetWindowId(), UPPER_WINDOW_ID);
}

/**
 * @tc.name: InputWindowsManagerTestWithMock_TouchTracking_004
 * @tc.desc: This feature only works for single touch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTestWithMock, InputWindowsManagerTestWithMock_TouchTracking_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WIN_MGR->SwitchTouchTracking(true);
    auto pointerEvent = BuildTouchEvent002();
    ASSERT_NE(pointerEvent, nullptr);
    auto ret = WIN_MGR->UpdateTargetPointer(pointerEvent);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_EQ(pointerEvent->GetTargetWindowId(), UPPER_WINDOW_ID);
}

/**
 * @tc.name: InputWindowsManagerTestWithMock_TouchTracking_005
 * @tc.desc: With this feature enabled, when touch moves onto another window, MMI will dispatch 'CANCEL' to
 *           previous window, then dispatch 'DOWN' to current window.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTestWithMock, InputWindowsManagerTestWithMock_TouchTracking_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    auto cheater = std::make_shared<InputEventCheater>();
    InputHandler->eventNormalizeHandler_->SetNext(cheater);

    WIN_MGR->SwitchTouchTracking(true);
    auto pointerEvent = BuildTouchEvent001();
    ASSERT_NE(pointerEvent, nullptr);
    auto ret = WIN_MGR->UpdateTargetPointer(pointerEvent);
    ASSERT_EQ(ret, RET_OK);

    auto touchEvent = cheater->GetTouchEvent();
    ASSERT_NE(touchEvent, nullptr);
    EXPECT_EQ(touchEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_CANCEL);
    EXPECT_EQ(touchEvent->GetTargetWindowId(), UPPER_WINDOW_ID);

    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_EQ(pointerEvent->GetTargetWindowId(), LOWER_WINDOW_ID);
}

/**
 * @tc.name: InputWindowsManagerTestWithMock_TouchTracking_006
 * @tc.desc: With this feature enabled, until touch moves out of the window on which it presses down,
 *           MMI will dispatch touch events to the window.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTestWithMock, InputWindowsManagerTestWithMock_TouchTracking_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    auto cheater = std::make_shared<InputEventCheater>();
    InputHandler->eventNormalizeHandler_->SetNext(cheater);

    WIN_MGR->SwitchTouchTracking(true);
    auto pointerEvent = BuildTouchEvent001();
    ASSERT_NE(pointerEvent, nullptr);

    int32_t touchY { 480 };
    PointerEvent::PointerItem pointerItem {};
    ASSERT_TRUE(pointerEvent->GetPointerItem(pointerEvent->GetPointerId(), pointerItem));
    pointerItem.SetDisplayY(touchY);
    pointerItem.SetDisplayYPos(touchY);
    pointerEvent->UpdatePointerItem(pointerEvent->GetPointerId(), pointerItem);

    auto ret = WIN_MGR->UpdateTargetPointer(pointerEvent);
    ASSERT_EQ(ret, RET_OK);
    auto touchEvent = cheater->GetTouchEvent();
    EXPECT_EQ(touchEvent, nullptr);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_MOVE);
    EXPECT_EQ(pointerEvent->GetTargetWindowId(), UPPER_WINDOW_ID);
}
} // namespace MMI
} // namespace OHOS
