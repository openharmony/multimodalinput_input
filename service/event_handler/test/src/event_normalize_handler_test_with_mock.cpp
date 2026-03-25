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

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
/**
 * @tc.name: UpdateKeyEventHandlerChain_ExtendedFunctionKey_001
 * @tc.desc: Test UpdateKeyEventHandlerChain with KEYCODE_EXT_FN_MIN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTestWithMock,
    UpdateKeyEventHandlerChain_ExtendedFunctionKey_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_EXT_FN_MIN); // 16777216

    EventNormalizeHandler eventHandler;
    auto nextHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(nextHandler);

    // Extended function key should bypass the chain and go directly to dispatch
    // So nextHandler should NOT receive the event
    eventHandler.UpdateKeyEventHandlerChain(keyEvent);

    // Verify that the nextHandler did NOT receive the event
    // (extended function keys bypass the interceptor/filter/monitor chain)
    EXPECT_TRUE(nextHandler->events_.empty());
}

/**
 * @tc.name: UpdateKeyEventHandlerChain_ExtendedFunctionKey_002
 * @tc.desc: Test UpdateKeyEventHandlerChain with KEYCODE_EXT_FN_MAX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTestWithMock,
    UpdateKeyEventHandlerChain_ExtendedFunctionKey_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_EXT_FN_MAX); // 33554431

    EventNormalizeHandler eventHandler;
    auto nextHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(nextHandler);

    eventHandler.UpdateKeyEventHandlerChain(keyEvent);

    // Verify that the nextHandler did NOT receive the event
    EXPECT_TRUE(nextHandler->events_.empty());
}

/**
 * @tc.name: UpdateKeyEventHandlerChain_ExtendedFunctionKey_003
 * @tc.desc: Test UpdateKeyEventHandlerChain with a value in the middle of extended function range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTestWithMock,
    UpdateKeyEventHandlerChain_ExtendedFunctionKey_003,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    // Use a value in the middle: (16777216 + 33554431) / 2 = 25165823
    keyEvent->SetKeyCode(25165823);

    EventNormalizeHandler eventHandler;
    auto nextHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(nextHandler);

    eventHandler.UpdateKeyEventHandlerChain(keyEvent);

    // Verify that the nextHandler did NOT receive the event
    EXPECT_TRUE(nextHandler->events_.empty());
}

/**
 * @tc.name: UpdateKeyEventHandlerChain_NormalKey_001
 * @tc.desc: Test UpdateKeyEventHandlerChain with normal key (KEYCODE_A)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTestWithMock,
    UpdateKeyEventHandlerChain_NormalKey_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A); // Normal key, outside extended function range

    EventNormalizeHandler eventHandler;
    auto nextHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(nextHandler);

    eventHandler.UpdateKeyEventHandlerChain(keyEvent);

    // Normal keys should go through the normal chain
    EXPECT_FALSE(nextHandler->events_.empty());
    if (!nextHandler->events_.empty()) {
        auto receivedEvent = nextHandler->events_.back();
        EXPECT_EQ(receivedEvent->GetKeyCode(), KeyEvent::KEYCODE_A);
        EXPECT_EQ(receivedEvent->GetKeyAction(), KeyEvent::KEY_ACTION_DOWN);
    }
}

/**
 * @tc.name: UpdateKeyEventHandlerChain_Boundary_001
 * @tc.desc: Test UpdateKeyEventHandlerChain with key just below KEYCODE_EXT_FN_MIN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTestWithMock,
    UpdateKeyEventHandlerChain_Boundary_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_EXT_FN_MIN - 1); // 16777215, just below the range

    EventNormalizeHandler eventHandler;
    auto nextHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(nextHandler);

    eventHandler.UpdateKeyEventHandlerChain(keyEvent);

    // Keys below the extended function range should go through the normal chain
    EXPECT_FALSE(nextHandler->events_.empty());
    if (!nextHandler->events_.empty()) {
        auto receivedEvent = nextHandler->events_.back();
        EXPECT_EQ(receivedEvent->GetKeyCode(), KeyEvent::KEYCODE_EXT_FN_MIN - 1);
    }
}

/**
 * @tc.name: UpdateKeyEventHandlerChain_Boundary_002
 * @tc.desc: Test UpdateKeyEventHandlerChain with key just above KEYCODE_EXT_FN_MAX
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTestWithMock,
    UpdateKeyEventHandlerChain_Boundary_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_EXT_FN_MAX + 1); // 33554432, just above the range

    EventNormalizeHandler eventHandler;
    auto nextHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(nextHandler);

    eventHandler.UpdateKeyEventHandlerChain(keyEvent);

    // Keys above the extended function range should go through the normal chain
    EXPECT_FALSE(nextHandler->events_.empty());
    if (!nextHandler->events_.empty()) {
        auto receivedEvent = nextHandler->events_.back();
        EXPECT_EQ(receivedEvent->GetKeyCode(), KeyEvent::KEYCODE_EXT_FN_MAX + 1);
    }
}

/**
 * @tc.name: UpdateKeyEventHandlerChain_NormalKey_Variety
 * @tc.desc: Test UpdateKeyEventHandlerChain with various normal keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTestWithMock,
    UpdateKeyEventHandlerChain_NormalKey_Variety,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> normalKeyCodes = {
        KeyEvent::KEYCODE_0,
        KeyEvent::KEYCODE_9,
        KeyEvent::KEYCODE_F1,
        KeyEvent::KEYCODE_F12,
        KeyEvent::KEYCODE_ESCAPE,
        KeyEvent::KEYCODE_SPACE,
        KeyEvent::KEYCODE_ENTER
    };

    for (auto keyCode : normalKeyCodes) {
        auto keyEvent = KeyEvent::Create();
        ASSERT_NE(keyEvent, nullptr);
        keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
        keyEvent->SetKeyCode(keyCode);

        EventNormalizeHandler eventHandler;
        auto nextHandler = std::make_shared<InputEventHandlerMock>();
        eventHandler.SetNext(nextHandler);

        eventHandler.UpdateKeyEventHandlerChain(keyEvent);

        // All normal keys should go through the normal chain
        EXPECT_FALSE(nextHandler->events_.empty());
        if (!nextHandler->events_.empty()) {
            auto receivedEvent = nextHandler->events_.back();
            EXPECT_EQ(receivedEvent->GetKeyCode(), keyCode);
        }
    }
}

/**
 * @tc.name: UpdateKeyEventHandlerChain_ExtendedFunctionKey_Multiple
 * @tc.desc: Test UpdateKeyEventHandlerChain with multiple extended function keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTestWithMock,
    UpdateKeyEventHandlerChain_ExtendedFunctionKey_Multiple,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> extendedKeyCodes = {
        KeyEvent::KEYCODE_EXT_FN_MIN,            // 16777216
        KeyEvent::KEYCODE_EXT_FN_MIN + 100,      // 16778316
        KeyEvent::KEYCODE_EXT_FN_MIN + 1000,     // 16778216
        KeyEvent::KEYCODE_EXT_FN_MAX - 1000,     // 33553431
        KeyEvent::KEYCODE_EXT_FN_MAX             // 33554431
    };

    for (auto keyCode : extendedKeyCodes) {
        auto keyEvent = KeyEvent::Create();
        ASSERT_NE(keyEvent, nullptr);
        keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
        keyEvent->SetKeyCode(keyCode);

        EventNormalizeHandler eventHandler;
        auto nextHandler = std::make_shared<InputEventHandlerMock>();
        eventHandler.SetNext(nextHandler);

        eventHandler.UpdateKeyEventHandlerChain(keyEvent);

        // All extended function keys should bypass the chain
        EXPECT_TRUE(nextHandler->events_.empty());
    }
}

/**
 * @tc.name: UpdateKeyEventHandlerChain_NullKeyEvent
 * @tc.desc: Test UpdateKeyEventHandlerChain with null KeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTestWithMock,
    UpdateKeyEventHandlerChain_NullKeyEvent,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;

    EventNormalizeHandler eventHandler;
    auto nextHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(nextHandler);

    // Should handle null event gracefully
    ASSERT_NO_FATAL_FAILURE(eventHandler.UpdateKeyEventHandlerChain(keyEvent));

    // No event should be passed to nextHandler
    EXPECT_TRUE(nextHandler->events_.empty());
}

/**
 * @tc.name: UpdateKeyEventHandlerChain_ExtendedFunctionKey_UpAction
 * @tc.desc: Test UpdateKeyEventHandlerChain with extended function key KEY_ACTION_UP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTestWithMock,
    UpdateKeyEventHandlerChain_ExtendedFunctionKey_UpAction,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_EXT_FN_MIN);

    EventNormalizeHandler eventHandler;
    auto nextHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(nextHandler);

    eventHandler.UpdateKeyEventHandlerChain(keyEvent);

    // Extended function keys should bypass the chain regardless of action
    EXPECT_TRUE(nextHandler->events_.empty());
}

/**
 * @tc.name: UpdateKeyEventHandlerChain_ExtendedFunctionKey_CancelAction
 * @tc.desc: Test UpdateKeyEventHandlerChain with extended function key KEY_ACTION_CANCEL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventNormalizeHandlerTestWithMock,
    UpdateKeyEventHandlerChain_ExtendedFunctionKey_CancelAction,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_EXT_FN_MIN + 5000);

    EventNormalizeHandler eventHandler;
    auto nextHandler = std::make_shared<InputEventHandlerMock>();
    eventHandler.SetNext(nextHandler);

    eventHandler.UpdateKeyEventHandlerChain(keyEvent);

    // Extended function keys should bypass the chain regardless of action
    EXPECT_TRUE(nextHandler->events_.empty());
}

#endif // OHOS_BUILD_ENABLE_KEYBOARD
#endif // OHOS_BUILD_ENABLE_JOYSTICK
} // namespace MMI
} // namespace OHOS
