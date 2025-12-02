/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#include "joystick_event_processor.h"
#include "mmi_log.h"
#include <iomanip>
#include "key_map_manager.h"
#include "key_event_normalize.h"
#include "key_unicode_transformation.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickEventProcessorTest"

#define KEY_MAX			0x2ff
#define KEY_CNT			(KEY_MAX + 1)

typedef void (*libinput_seat_destroy_func) (struct libinput_seat *seat);

struct libinput_device_config {};

struct list {
    struct list *next, *prev;
};

struct libinput_device_group {
    int refcount;
    void *user_data;
    char *identifier; /* unique identifier or NULL for singletons */
    struct list link;
};

struct libinput_seat {
    struct libinput *libinput;
    struct list link;
    struct list devices_list;
    void *user_data;
    int refcount;
    libinput_seat_destroy_func destroy;

    char *physical_name;
    char *logical_name;

    uint32_t slot_map;

    uint32_t button_count[KEY_CNT];
};

struct libinput_device {
    struct libinput_seat *seat;
    struct libinput_device_group *group;
    struct list link;
    struct list event_listeners;
    void *user_data;
    int refcount;
    struct libinput_device_config config;
};

struct libinput_event {
    enum libinput_event_type type;
    struct libinput_device *device;
};

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class JoystickEventProcessorTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: JoystickEventProcessorTest_OnButtonEvent
 * @tc.desc: Test OnButtonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_OnButtonEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(deviceId);
    libinput_event libInputEvent;
    ASSERT_EQ(joystick.OnButtonEvent(&libInputEvent), nullptr);
}

/**
 * @tc.name: JoystickEventProcessorTest_OnAxisEvent_001
 * @tc.desc: Test OnAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_OnAxisEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 2;
    auto joystickEventProcessor = std::make_shared<JoystickEventProcessor>(deviceId);
        libinput_event libInputEvent = {
        .type = LIBINPUT_EVENT_NONE,
        .device = nullptr
    };
    ASSERT_EQ(joystickEventProcessor->OnButtonEvent(&libInputEvent), nullptr);
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckIntention
 * @tc.desc: Test CheckIntention
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckIntention, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(deviceId);
    std::shared_ptr<PointerEvent> pointerEvent;
    ASSERT_NO_FATAL_FAILURE(
        joystick.CheckIntention(pointerEvent, [=] (std::shared_ptr<OHOS::MMI::KeyEvent>) { return; }));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckIntention_002
 * @tc.desc: Test CheckIntention
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckIntention_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_LEFT};
    ASSERT_NO_FATAL_FAILURE(
        JoystickEvent->CheckIntention(pointerEvent, [=] (std::shared_ptr<OHOS::MMI::KeyEvent>) { return; }));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckIntention_003
 * @tc.desc: Test CheckIntention
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckIntention_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_DOWN};
    ASSERT_NO_FATAL_FAILURE(
        JoystickEvent->CheckIntention(pointerEvent, [=] (std::shared_ptr<OHOS::MMI::KeyEvent>) { return; }));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckIntention_004
 * @tc.desc: Test CheckIntention with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckIntention_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 1.0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;

    ASSERT_NO_FATAL_FAILURE(
        joystickEvent->CheckIntention(pointerEvent, nullptr));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckIntention_005
 * @tc.desc: Test CheckIntention with non-joystick source
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckIntention_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 1.0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;

    ASSERT_NO_FATAL_FAILURE(
        joystickEvent->CheckIntention(pointerEvent, [=] (std::shared_ptr<OHOS::MMI::KeyEvent>) { return; }));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X
 * @tc.desc: Test CheckHAT0X
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(deviceId);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    ASSERT_NO_FATAL_FAILURE(joystick.CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X_002
 * @tc.desc: Test CheckHAT0X
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_SCROLL_VERTICAL;
    std::vector<KeyEvent::KeyItem> buttonEvents;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X_003
 * @tc.desc: Test CheckHAT0X
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 0.02;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
    axisValue = -0.02;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X_004
 * @tc.desc: Test CheckHAT0X
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_LEFT};
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_RIGHT};
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X_005
 * @tc.desc: Test CheckHAT0X
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X_006
 * @tc.desc: Test CheckHAT0X with positive axis value and no pressed buttons
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 1.0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;

    ASSERT_NO_FATAL_FAILURE(joystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0X_007
 * @tc.desc: Test CheckHAT0X with negative axis value and no pressed buttons
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0X_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = -1.0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;

    ASSERT_NO_FATAL_FAILURE(joystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y
 * @tc.desc: Test CheckHAT0Y
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(deviceId);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    ASSERT_NO_FATAL_FAILURE(joystick.CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y_002
 * @tc.desc: Test CheckHAT0Y
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_SCROLL_VERTICAL;
    std::vector<KeyEvent::KeyItem> buttonEvents;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y_003
 * @tc.desc: Test CheckHAT0Y
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = 0.02;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
    axisValue = -0.02;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y_004
 * @tc.desc: Test CheckHAT0Y
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_DOWN};
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_UP};
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y_005
 * @tc.desc: Test CheckHAT0Y
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y_006
 * @tc.desc: Test CheckHAT0Y with positive axis value and no pressed buttons
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = 1.0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;

    ASSERT_NO_FATAL_FAILURE(joystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_CheckHAT0Y_007
 * @tc.desc: Test CheckHAT0Y with negative axis value and no pressed buttons
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CheckHAT0Y_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = -1.0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;

    ASSERT_NO_FATAL_FAILURE(joystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
}

/**
 * @tc.name: JoystickEventProcessorTest_UpdateButtonState
 * @tc.desc: Test UpdateButtonState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_UpdateButtonState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(deviceId);
    KeyEvent::KeyItem keyItem {};
    ASSERT_NO_FATAL_FAILURE(joystick.UpdateButtonState(keyItem));
}

/**
 * @tc.name: JoystickEventProcessorTest_UpdateButtonState_002
 * @tc.desc: Test UpdateButtonState with pressed button
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_UpdateButtonState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    KeyEvent::KeyItem keyItem {};
    keyItem.SetPressed(true);
    keyItem.SetKeyCode(KeyEvent::KEYCODE_BUTTON_A);

    ASSERT_NO_FATAL_FAILURE(joystickEvent->UpdateButtonState(keyItem));
}

/**
 * @tc.name: JoystickEventProcessorTest_UpdateButtonState_003
 * @tc.desc: Test UpdateButtonState with released button
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_UpdateButtonState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    KeyEvent::KeyItem keyItem {};
    keyItem.SetPressed(false);
    keyItem.SetKeyCode(KeyEvent::KEYCODE_BUTTON_A);

    KeyEvent::KeyItem pressedKey {};
    pressedKey.SetPressed(true);
    pressedKey.SetKeyCode(KeyEvent::KEYCODE_BUTTON_A);
    joystickEvent->UpdateButtonState(pressedKey);

    ASSERT_NO_FATAL_FAILURE(joystickEvent->UpdateButtonState(keyItem));
}

/**
 * @tc.name: JoystickEventProcessorTest_FormatButtonEvent
 * @tc.desc: Test FormatButtonEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_FormatButtonEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(deviceId);
    KeyEvent::KeyItem keyItem {};
    EXPECT_NE(joystick.FormatButtonEvent(keyItem), nullptr);
}

/**
 * @tc.name: JoystickEventProcessorTest_FormatButtonEvent_002
 * @tc.desc: Test FormatButtonEvent with pressed button
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_FormatButtonEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    KeyEvent::KeyItem keyItem {};
    keyItem.SetPressed(true);
    keyItem.SetKeyCode(KeyEvent::KEYCODE_BUTTON_A);

    auto keyEvent = joystickEvent->FormatButtonEvent(keyItem);
    EXPECT_NE(keyEvent, nullptr);
    if (keyEvent != nullptr) {
        EXPECT_EQ(keyEvent->GetKeyAction(), KeyEvent::KEY_ACTION_DOWN);
    }
}

/**
 * @tc.name: JoystickEventProcessorTest_FormatButtonEvent_003
 * @tc.desc: Test FormatButtonEvent with released button
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_FormatButtonEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    KeyEvent::KeyItem keyItem {};
    keyItem.SetPressed(false);
    keyItem.SetKeyCode(KeyEvent::KEYCODE_BUTTON_A);

    auto keyEvent = joystickEvent->FormatButtonEvent(keyItem);
    EXPECT_NE(keyEvent, nullptr);
    if (keyEvent != nullptr) {
        EXPECT_EQ(keyEvent->GetKeyAction(), KeyEvent::KEY_ACTION_UP);
    }
}

/**
 * @tc.name: JoystickEventProcessorTest_CleanUpKeyEvent
 * @tc.desc: Test CleanUpKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CleanUpKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(deviceId);
    EXPECT_NE(joystick.CleanUpKeyEvent(), nullptr);
}

/**
 * @tc.name: JoystickEventProcessorTest_CleanUpKeyEvent_002
 * @tc.desc: Test CleanUpKeyEvent with pressed buttons
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_CleanUpKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);

    KeyEvent::KeyItem keyItem1 {};
    keyItem1.SetPressed(true);
    keyItem1.SetKeyCode(KeyEvent::KEYCODE_BUTTON_A);
    joystickEvent->UpdateButtonState(keyItem1);

    KeyEvent::KeyItem keyItem2 {};
    keyItem2.SetPressed(true);
    keyItem2.SetKeyCode(KeyEvent::KEYCODE_BUTTON_B);
    joystickEvent->UpdateButtonState(keyItem2);

    auto cleanUpEvent = joystickEvent->CleanUpKeyEvent();
    EXPECT_NE(cleanUpEvent, nullptr);
}

/**
 * @tc.name: JoystickEventProcessorTest_DumpJoystickAxisEvent
 * @tc.desc: Test DumpJoystickAxisEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_DumpJoystickAxisEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(deviceId);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(joystick.DumpJoystickAxisEvent(pointerEvent), "");
}

/**
 * @tc.name: JoystickEventProcessorTest_DumpJoystickAxisEvent_003
 * @tc.desc: Test DumpJoystickAxisEvent with multiple axes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_DumpJoystickAxisEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X | PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = 0.5;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = -0.3;

    std::string dumpResult = joystickEvent->DumpJoystickAxisEvent(pointerEvent);
    ASSERT_NE(dumpResult, "");
}

/**
 * @tc.name: JoystickEventProcessorTest_Normalize
 * @tc.desc: Test Normalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_Normalize, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId { 2 };
    JoystickEventProcessor joystick(deviceId);
    struct libinput_event_joystick_axis_abs_info axis {};
    double low  { 2.1 };
    double high { 1.3 };
    ASSERT_NE(joystick.Normalize(axis, low, high), 3.5f);
}

/**
 * @tc.name: JoystickEventProcessorTest_Normalize_002
 * @tc.desc: Test Normalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_Normalize_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    const struct libinput_event_joystick_axis_abs_info axis = {
        .code = 1,
        .value = 5,
        .maximum = 0,
        .minimum  = 10,
        .fuzz = 0,
        .flat = 0,
        .resolution = 0,
        .standardValue = 1.0
    };
    double low = 0.0f;
    double high = 1.0f;
    ASSERT_EQ(JoystickEvent->Normalize(axis, low, high), 0.0f);
}

/**
 * @tc.name: JoystickEventProcessorTest_Normalize_003
 * @tc.desc: Test Normalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_Normalize_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    const struct libinput_event_joystick_axis_abs_info axis = {
        .code = 1,
        .value = 20,
        .maximum = 10,
        .minimum  = 0,
        .fuzz = 0,
        .flat = 0,
        .resolution = 0,
        .standardValue = 1.0
    };
    double low = 0.0f;
    double high = 1.0f;
    ASSERT_EQ(JoystickEvent->Normalize(axis, low, high), 1.0f);
}

/**
 * @tc.name: JoystickEventProcessorTest_Normalize_004
 * @tc.desc: Test Normalize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_Normalize_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto JoystickEvent = std::make_shared<JoystickEventProcessor>(2);
    const struct libinput_event_joystick_axis_abs_info axis = {
        .code = 1,
        .value = 5,
        .maximum = 10,
        .minimum  = 0,
        .fuzz = 0,
        .flat = 0,
        .resolution = 0,
        .standardValue = 1.0
    };
    double low = 0.0f;
    double high = 1.0f;
    ASSERT_EQ(JoystickEvent->Normalize(axis, low, high), 0.5f);
}

/**
 * @tc.name: JoystickEventProcessorTest_Normalize_005
 * @tc.desc: Test Normalize with maximum equals minimum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_Normalize_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    const struct libinput_event_joystick_axis_abs_info axis = {
        .code = 1,
        .value = 5,
        .maximum = 10,
        .minimum  = 10,
        .fuzz = 0,
        .flat = 0,
        .resolution = 0,
        .standardValue = 1.0
    };
    double low = 0.0f;
    double high = 1.0f;

    ASSERT_EQ(joystickEvent->Normalize(axis, low, high), low);
}

/**
 * @tc.name: JoystickEventProcessorTest_Normalize_006
 * @tc.desc: Test Normalize with value less than minimum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_Normalize_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    const struct libinput_event_joystick_axis_abs_info axis = {
        .code = 1,
        .value = -5,
        .maximum = 10,
        .minimum  = 0,
        .fuzz = 0,
        .flat = 0,
        .resolution = 0,
        .standardValue = 1.0
    };
    double low = 0.0f;
    double high = 1.0f;

    ASSERT_EQ(joystickEvent->Normalize(axis, low, high), low);
}

/**
 * @tc.name: JoystickEventProcessorTest_Normalize_007
 * @tc.desc: Test Normalize with value greater than maximum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_Normalize_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);
    const struct libinput_event_joystick_axis_abs_info axis = {
        .code = 1,
        .value = 15,
        .maximum = 10,
        .minimum  = 0,
        .fuzz = 0,
        .flat = 0,
        .resolution = 0,
        .standardValue = 1.0
    };
    double low = 0.0f;
    double high = 1.0f;

    ASSERT_EQ(joystickEvent->Normalize(axis, low, high), high);
}

/**
 * @tc.name: JoystickEventProcessorTest_OnAxisEvent_002
 * @tc.desc: Test OnAxisEvent with null event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(JoystickEventProcessorTest, JoystickEventProcessorTest_OnAxisEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto joystickEvent = std::make_shared<JoystickEventProcessor>(2);

    ASSERT_EQ(joystickEvent->OnAxisEvent(nullptr), nullptr);
}
} // namespace MMI
} // namespace OHOS
