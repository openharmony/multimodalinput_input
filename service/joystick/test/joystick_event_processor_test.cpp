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
    std::shared_ptr<JoystickEventProcessor> JoystickEvent;
    libinput_event libInputEvent;
    ASSERT_EQ(JoystickEvent->OnButtonEvent(&libInputEvent), nullptr);
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
    auto JoystickEvent = new JoystickEventProcessor(2);
    std::shared_ptr<PointerEvent> pointerEvent;
    ASSERT_NO_FATAL_FAILURE(
        JoystickEvent->CheckIntention(pointerEvent, [=] (std::shared_ptr<OHOS::MMI::KeyEvent>) { return; }));
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
    auto JoystickEvent = new JoystickEventProcessor(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
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
    auto JoystickEvent = new JoystickEventProcessor(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;
    JoystickEvent->pressedButtons_ = {KeyEvent::KEYCODE_DPAD_DOWN};
    ASSERT_NO_FATAL_FAILURE(
        JoystickEvent->CheckIntention(pointerEvent, [=] (std::shared_ptr<OHOS::MMI::KeyEvent>) { return; }));
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
    auto JoystickEvent = new JoystickEventProcessor(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
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
    auto JoystickEvent = new JoystickEventProcessor(2);
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
    auto JoystickEvent = new JoystickEventProcessor(2);
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
    auto JoystickEvent = new JoystickEventProcessor(2);
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
    auto JoystickEvent = new JoystickEventProcessor(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0X;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0X] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0X(pointerEvent, buttonEvents));
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
    auto JoystickEvent = new JoystickEventProcessor(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
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
    auto JoystickEvent = new JoystickEventProcessor(2);
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
    auto JoystickEvent = new JoystickEventProcessor(2);
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
    auto JoystickEvent = new JoystickEventProcessor(2);
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
    auto JoystickEvent = new JoystickEventProcessor(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::vector<KeyEvent::KeyItem> buttonEvents;
    pointerEvent->axes_ = PointerEvent::AXIS_TYPE_ABS_HAT0Y;
    double axisValue = 0;
    pointerEvent->axisValues_[PointerEvent::AXIS_TYPE_ABS_HAT0Y] = axisValue;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->CheckHAT0Y(pointerEvent, buttonEvents));
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
    auto JoystickEvent = new JoystickEventProcessor(2);
    const KeyEvent::KeyItem keyItem;
    ASSERT_NO_FATAL_FAILURE(JoystickEvent->UpdateButtonState(keyItem));
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
    auto JoystickEvent = new JoystickEventProcessor(2);
    const KeyEvent::KeyItem keyItem;
    ASSERT_NE(JoystickEvent->FormatButtonEvent(keyItem), nullptr);
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
    auto JoystickEvent = new JoystickEventProcessor(2);
    ASSERT_NE(JoystickEvent->CleanUpKeyEvent(), nullptr);
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
    auto JoystickEvent = new JoystickEventProcessor(2);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(JoystickEvent->DumpJoystickAxisEvent(pointerEvent), "");
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
    auto JoystickEvent = new JoystickEventProcessor(2);
    const struct libinput_event_joystick_axis_abs_info axis{ 0 };
    double low = 2.1f;
    double high = 1.3f;
    ASSERT_NE(JoystickEvent->Normalize(axis, low, high), 3.5f);
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
    auto JoystickEvent = new JoystickEventProcessor(2);
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
    auto JoystickEvent = new JoystickEventProcessor(2);
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
    auto JoystickEvent = new JoystickEventProcessor(2);
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
} // namespace MMI
} // namespace OHOS
