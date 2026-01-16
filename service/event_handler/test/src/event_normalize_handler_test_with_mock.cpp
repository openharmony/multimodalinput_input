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

#include <linux/input.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "event_normalize_handler.h"
#include "input_device_manager.h"
#include "joystick_event_interface.h"
#include "libinput_mock.h"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

class EventNormalizeHandlerTestWithMock : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EventNormalizeHandlerTestWithMock::SetUpTestCase()
{}

void EventNormalizeHandlerTestWithMock::TearDownTestCase()
{}

void EventNormalizeHandlerTestWithMock::SetUp()
{}

void EventNormalizeHandlerTestWithMock::TearDown()
{
    InputDeviceManagerMock::ReleaseInstance();
    JoystickEventInterface::ReleaseInstance();
}

struct InputEventHandlerMock : public IInputEventHandler {
    InputEventHandlerMock() = default;
    virtual ~InputEventHandlerMock() = default;

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> event) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent>) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent>) override {}
#endif // OHOS_BUILD_ENABLE_TOUCH

    std::vector<std::shared_ptr<KeyEvent>> events_;
    std::vector<std::shared_ptr<PointerEvent>> pointerEvents_;
};

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void InputEventHandlerMock::HandleKeyEvent(const std::shared_ptr<KeyEvent> event)
{
    CHKPV(event);
    auto keyEvent = KeyEvent::Clone(event);
    CHKPV(keyEvent);
    events_.push_back(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void InputEventHandlerMock::HandlePointerEvent(const std::shared_ptr<PointerEvent> event)
{
    CHKPV(event);
    auto pointerEvent = std::make_shared<PointerEvent>(*event);
    pointerEvents_.push_back(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_JOYSTICK

HWTEST_F(EventNormalizeHandlerTestWithMock, HandleJoystickButtonEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_BUTTON_A);

    EXPECT_CALL(*JOYSTICK_NORMALIZER, OnButtonEvent).WillRepeatedly(Return(keyEvent));

    EventNormalizeHandler eventHandler;
    auto nextHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(nextHandler);

    libinput_event event {};
    auto ret = eventHandler.HandleJoystickButtonEvent(&event);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_TRUE(!nextHandler->events_.empty());
    if (!nextHandler->events_.empty()) {
        auto keyEvent = nextHandler->events_.back();
        EXPECT_EQ(keyEvent->GetKeyCode(), KeyEvent::KEYCODE_BUTTON_A);
        EXPECT_EQ(keyEvent->GetKeyAction(), KeyEvent::KEY_ACTION_DOWN);
    }
}

HWTEST_F(EventNormalizeHandlerTestWithMock, HandleJoystickAxisEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    double axisValue { 0.1 };
    pointerEvent->SetAxisValue(PointerEvent::AXIS_TYPE_ABS_X, axisValue);

    EXPECT_CALL(*JOYSTICK_NORMALIZER, OnAxisEvent).WillRepeatedly(Return(pointerEvent));

    EventNormalizeHandler eventHandler;
    auto nextHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(nextHandler);

    libinput_event event {};
    auto ret = eventHandler.HandleJoystickAxisEvent(&event);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_TRUE(!nextHandler->pointerEvents_.empty());
    if (!nextHandler->pointerEvents_.empty()) {
        auto pointerEvent = nextHandler->pointerEvents_.back();
        EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_AXIS_UPDATE);
        EXPECT_TRUE(pointerEvent->HasAxis(PointerEvent::AXIS_TYPE_ABS_X));
    }
}

#endif // OHOS_BUILD_ENABLE_JOYSTICK
} // namespace MMI
} // namespace OHOS
