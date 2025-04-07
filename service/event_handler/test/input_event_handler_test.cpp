/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <climits>
#include <cstdio>
#include <cstring>
#include <functional>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "general_touchpad.h"
#include "i_input_windows_manager.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "key_command_handler.h"
#include "libinput_mock.h"
#include "mmi_log.h"
#include "timer_manager.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEventHandlerTest"

static double g_mockLibinputDeviceGetSizeWidth = 0.0;
static int g_mockLibinputDeviceGetSizeRetrunIntValue = 0;

using namespace testing;
using namespace testing::ext;

extern "C" {
int libinput_device_get_size(struct libinput_device *device, double *width, double *height)
{
    if (width != nullptr) {
        *width = g_mockLibinputDeviceGetSizeWidth;
    }
    return g_mockLibinputDeviceGetSizeRetrunIntValue;
}
}  // extern "C"

namespace OHOS {
namespace MMI {

void EventNormalizeHandler::HandleEvent(libinput_event *event, int64_t frameTime) {}

class InputEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void InputEventHandlerTest::SetUpTestCase(void) {}

void InputEventHandlerTest::TearDownTestCase(void) {}

void InputEventHandlerTest::SetUp(void)
{
    g_mockLibinputDeviceGetSizeWidth = 0.0;
    g_mockLibinputDeviceGetSizeRetrunIntValue = 0;
}

void InputEventHandlerTest::TearDown(void) {}

/**
 * @tc.name: InputEventHandler_OnEvent_001
 * @tc.desc: Test the funcation OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_OnEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    void *event = nullptr;
    int64_t frameTime = 0;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    inputEventHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->OnEvent(event, frameTime));
}

/**
 * @tc.name: InputEventHandler_OnEvent_002
 * @tc.desc: Test the funcation OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_OnEvent_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    libinput_event event;
    libinput_event_pointer pointer;
    pointer.buttonState = LIBINPUT_BUTTON_STATE_RELEASED;
    int64_t frameTime = 0;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType)
        .WillOnce(Return(LIBINPUT_EVENT_POINTER_AXIS))
        .WillOnce(Return(LIBINPUT_EVENT_TOUCHPAD_DOWN))
        .WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD));
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillOnce(Return(nullptr));
    EXPECT_CALL(libinputMock, GetDevice).WillOnce(Return(nullptr));
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    inputEventHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    inputEventHandler->idSeed_ = std::numeric_limits<uint64_t>::max() - 1;
    inputEventHandler->isButtonMistouch_ = true;
    inputEventHandler->isDwtEdgeAreaForTouchpadMotionActing_ = false;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->OnEvent(&event, frameTime));
}

/**
 * @tc.name: InputEventHandler_UpdateDwtRecord_001
 * @tc.desc: Test the funcation UpdateDwtRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_UpdateDwtRecord_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_TOUCHPAD_DOWN));
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillOnce(Return(nullptr));
    libinput_event event;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtRecord(&event));
}

/**
 * @tc.name: InputEventHandler_UpdateDwtRecord_002
 * @tc.desc: Test the funcation UpdateDwtRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_UpdateDwtRecord_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_TOUCHPAD_MOTION));
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillOnce(Return(nullptr));
    libinput_event event;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtRecord(&event));
}

/**
 * @tc.name: InputEventHandler_UpdateDwtRecord_003
 * @tc.desc: Test the funcation UpdateDwtRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_UpdateDwtRecord_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_KEYBOARD_KEY));
    EXPECT_CALL(libinputMock, LibinputEventGetKeyboardEvent).WillOnce(Return(nullptr));
    libinput_event event;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtRecord(&event));
}

/**
 * @tc.name: InputEventHandler_UpdateDwtRecord_004
 * @tc.desc: Test the funcation UpdateDwtRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_UpdateDwtRecord_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_NONE));
    libinput_event event;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtRecord(&event));
}

/**
 * @tc.name: InputEventHandler_UpdateDwtTouchpadRecord_001
 * @tc.desc: Test the funcation UpdateDwtTouchpadRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_UpdateDwtTouchpadRecord_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_touch touchpadEvent;
    libinput_event event;
    libinput_device touchpadDevice;
    g_mockLibinputDeviceGetSizeRetrunIntValue = 1;
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillOnce(Return(&touchpadEvent));
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_NONE));
    EXPECT_CALL(libinputMock, GetDevice).WillOnce(Return(&touchpadDevice));
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtTouchpadRecord(&event));
}

/**
 * @tc.name: InputEventHandler_UpdateDwtTouchpadRecord_002
 * @tc.desc: Test the funcation UpdateDwtTouchpadRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_UpdateDwtTouchpadRecord_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_touch touchpadEvent;
    libinput_event event;
    libinput_device touchpadDevice;
    touchpadEvent.x = InputEventHandler::TOUCHPAD_EDGE_WIDTH_FOR_TAP + 1;
    touchpadEvent.y = 0;
    g_mockLibinputDeviceGetSizeWidth = 1000.0;
    g_mockLibinputDeviceGetSizeRetrunIntValue = 1;
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillRepeatedly(Return(&touchpadEvent));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TOUCHPAD_DOWN));
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&touchpadDevice));
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtTouchpadRecord(&event));

    touchpadEvent.x = 2000.0;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtTouchpadRecord(&event));

    touchpadEvent.x = 1.0;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtTouchpadRecord(&event));
}

/**
 * @tc.name: InputEventHandler_UpdateDwtTouchpadRecord_003
 * @tc.desc: Test the funcation UpdateDwtTouchpadRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_UpdateDwtTouchpadRecord_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_touch touchpadEvent;
    libinput_event event;
    libinput_device touchpadDevice;
    touchpadEvent.x = InputEventHandler::TOUCHPAD_EDGE_WIDTH_RELEASE + 1;
    touchpadEvent.y = 0;
    g_mockLibinputDeviceGetSizeWidth = 1000.0;
    g_mockLibinputDeviceGetSizeRetrunIntValue = 1;
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillRepeatedly(Return(&touchpadEvent));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TOUCHPAD_MOTION));
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&touchpadDevice));
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtTouchpadRecord(&event));

    touchpadEvent.x = 2000.0;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtTouchpadRecord(&event));

    touchpadEvent.x = 1.0;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtTouchpadRecord(&event));
}

/**
 * @tc.name: InputEventHandler_UpdateDwtTouchpadRecord_004
 * @tc.desc: Test the funcation UpdateDwtTouchpadRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_UpdateDwtTouchpadRecord_004, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_touch touchpadEvent;
    libinput_event event;
    libinput_device touchpadDevice;
    g_mockLibinputDeviceGetSizeRetrunIntValue = 1;
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillRepeatedly(Return(&touchpadEvent));
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TOUCHPAD_MOTION));
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&touchpadDevice));
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtTouchpadRecord(&event));
}

/**
 * @tc.name: InputEventHandler_UpdateDwtKeyboardRecord_001
 * @tc.desc: Test the funcation UpdateDwtKeyboardRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_UpdateDwtKeyboardRecord_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_keyboard keyboardEvent;
    libinput_event event;
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKey).WillOnce(Return(KEY_LEFTCTRL));
    EXPECT_CALL(libinputMock, LibinputEventGetKeyboardEvent).WillOnce(Return(&keyboardEvent));
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtKeyboardRecord(&event));
}

/**
 * @tc.name: InputEventHandler_UpdateDwtKeyboardRecord_002
 * @tc.desc: Test the funcation UpdateDwtKeyboardRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_UpdateDwtKeyboardRecord_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_keyboard keyboardEvent;
    libinput_event event;
    uint32_t key = KEY_LEFTCTRL;
    EXPECT_CALL(libinputMock, LibinputEventGetKeyboardEvent).WillOnce(Return(&keyboardEvent));
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKey).WillOnce(Return(key));
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKeyState).WillOnce(Return(LIBINPUT_KEY_STATE_PRESSED));
    inputEventHandler->modifierPressedCount_ = 10;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtKeyboardRecord(&event));
    EXPECT_TRUE(inputEventHandler->isKeyPressedWithAnyModifiers_[key]);
}

/**
 * @tc.name: InputEventHandler_UpdateDwtKeyboardRecord_003
 * @tc.desc: Test the funcation UpdateDwtKeyboardRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_UpdateDwtKeyboardRecord_003, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    NiceMock<LibinputInterfaceMock> libinputMock;
    libinput_event_keyboard keyboardEvent;
    libinput_event event;
    uint32_t key = KEY_LEFTCTRL;
    EXPECT_CALL(libinputMock, LibinputEventGetKeyboardEvent).WillRepeatedly(Return(&keyboardEvent));
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKey).WillRepeatedly(Return(key));
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKeyState)
        .WillOnce(Return(LIBINPUT_KEY_STATE_PRESSED))
        .WillOnce(Return(LIBINPUT_KEY_STATE_PRESSED))
        .WillOnce(Return(LIBINPUT_KEY_STATE_RELEASED))
        .WillOnce(Return(LIBINPUT_KEY_STATE_RELEASED));
    inputEventHandler->modifierPressedCount_ = 10;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtKeyboardRecord(&event));
    EXPECT_TRUE(inputEventHandler->isKeyPressedWithAnyModifiers_[key]);

    inputEventHandler->modifierPressedCount_ = 0;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtKeyboardRecord(&event));
    EXPECT_TRUE(inputEventHandler->isKeyPressedWithAnyModifiers_[key]);

    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtKeyboardRecord(&event));
    EXPECT_FALSE(inputEventHandler->isKeyPressedWithAnyModifiers_[key]);

    ASSERT_NO_FATAL_FAILURE(inputEventHandler->UpdateDwtKeyboardRecord(&event));
    EXPECT_FALSE(inputEventHandler->isKeyPressedWithAnyModifiers_[key]);
}

/**
 * @tc.name: InputEventHandler_IsStandaloneFunctionKey_001
 * @tc.desc: Test the funcation IsStandaloneFunctionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_IsStandaloneFunctionKey_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    uint32_t keycode = KEY_ESC;
    EXPECT_TRUE(inputEventHandler->IsStandaloneFunctionKey(keycode));
}

/**
 * @tc.name: InputEventHandler_IsStandaloneFunctionKey_002
 * @tc.desc: Test the funcation IsStandaloneFunctionKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_IsStandaloneFunctionKey_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    uint32_t keycode = 0;
    EXPECT_FALSE(inputEventHandler->IsStandaloneFunctionKey(keycode));
}

/**
 * @tc.name: InputEventHandler_IsTouchpadMistouch_001
 * @tc.desc: Test the funcation IsTouchpadMistouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_IsTouchpadMistouch_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    libinput_event event;
    libinput_event_touch touchpadEvent;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType)
        .WillOnce(Return(LIBINPUT_EVENT_TOUCHPAD_MOTION))
        .WillOnce(Return(LIBINPUT_EVENT_TABLET_TOOL_TIP))
        .WillOnce(Return(LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD))
        .WillOnce(Return(LIBINPUT_EVENT_POINTER_TAP))
        .WillOnce(Return(LIBINPUT_EVENT_POINTER_MOTION_TOUCHPAD));
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillRepeatedly(Return(&touchpadEvent));
    EXPECT_CALL(libinputMock, TouchpadGetTool).WillOnce(Return(MT_TOOL_PALM)).WillRepeatedly(Return(MT_TOOL_PEN));
    inputEventHandler->isDwtEdgeAreaForTouchpadMotionActing_ = false;
    EXPECT_FALSE(inputEventHandler->IsTouchpadMistouch(&event));

    EXPECT_FALSE(inputEventHandler->IsTouchpadMistouch(&event));

    EXPECT_CALL(libinputMock, LibinputGetPointerEvent).WillRepeatedly(Return(nullptr));
    EXPECT_FALSE(inputEventHandler->IsTouchpadMistouch(&event));

    EXPECT_FALSE(inputEventHandler->IsTouchpadMistouch(&event));

    inputEventHandler->isDwtEdgeAreaForTouchpadMotionActing_ = false;
    EXPECT_FALSE(inputEventHandler->IsTouchpadMistouch(&event));
}

/**
 * @tc.name: InputEventHandler_IsTouchpadButtonMistouch_001
 * @tc.desc: Test the funcation IsTouchpadButtonMistouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_IsTouchpadButtonMistouch_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    libinput_event event;
    libinput_device touchpadDevice;
    libinput_event_pointer touchpadButtonEvent;
    touchpadButtonEvent.buttonState = LIBINPUT_BUTTON_STATE_PRESSED;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, LibinputGetPointerEvent).WillRepeatedly(Return(&touchpadButtonEvent));
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&touchpadDevice));
    g_mockLibinputDeviceGetSizeRetrunIntValue = 1;
    inputEventHandler->isDwtEdgeAreaForTouchpadButtonActing_ = true;
    inputEventHandler->touchpadEventAbsX_ = InputEventHandler::TOUCHPAD_EDGE_WIDTH_FOR_BUTTON;
    EXPECT_FALSE(inputEventHandler->IsTouchpadButtonMistouch(&event));

    g_mockLibinputDeviceGetSizeRetrunIntValue = 0;
    inputEventHandler->touchpadEventAbsX_ = InputEventHandler::TOUCHPAD_EDGE_WIDTH_FOR_BUTTON + 1;
    EXPECT_TRUE(inputEventHandler->IsTouchpadButtonMistouch(&event));

    inputEventHandler->isDwtEdgeAreaForTouchpadButtonActing_ = false;
    EXPECT_FALSE(inputEventHandler->IsTouchpadButtonMistouch(&event));

    touchpadButtonEvent.buttonState = LIBINPUT_BUTTON_STATE_RELEASED;
    inputEventHandler->isButtonMistouch_ = true;
    EXPECT_TRUE(inputEventHandler->IsTouchpadButtonMistouch(&event));

    EXPECT_FALSE(inputEventHandler->IsTouchpadButtonMistouch(&event));
}

/**
 * @tc.name: InputEventHandler_IsTouchpadTapMistouch_001
 * @tc.desc: Test the funcation IsTouchpadTapMistouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_IsTouchpadTapMistouch_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    libinput_event event;
    libinput_event_pointer touchpadButtonEvent;
    libinput_device touchpadDevice;
    touchpadButtonEvent.buttonState = LIBINPUT_BUTTON_STATE_PRESSED;
    g_mockLibinputDeviceGetSizeRetrunIntValue = 1;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, LibinputGetPointerEvent).WillRepeatedly(Return(&touchpadButtonEvent));
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&touchpadDevice));
    EXPECT_FALSE(inputEventHandler->IsTouchpadTapMistouch(&event));

    g_mockLibinputDeviceGetSizeRetrunIntValue = 0;
    g_mockLibinputDeviceGetSizeWidth = 1000.0;
    inputEventHandler->touchpadEventDownAbsX_ = InputEventHandler::TOUCHPAD_EDGE_WIDTH_FOR_TAP;
    inputEventHandler->isDwtEdgeAreaForTouchpadTapActing_ = true;
    EXPECT_TRUE(inputEventHandler->IsTouchpadTapMistouch(&event));

    inputEventHandler->isDwtEdgeAreaForTouchpadTapActing_ = false;
    EXPECT_FALSE(inputEventHandler->IsTouchpadTapMistouch(&event));

    touchpadButtonEvent.buttonState = LIBINPUT_BUTTON_STATE_RELEASED;
    inputEventHandler->isTapMistouch_ = true;
    EXPECT_TRUE(inputEventHandler->IsTouchpadTapMistouch(&event));

    inputEventHandler->isTapMistouch_ = false;
    EXPECT_FALSE(inputEventHandler->IsTouchpadTapMistouch(&event));
}

/**
 * @tc.name: InputEventHandler_IsTouchpadMotionMistouch_001
 * @tc.desc: Test the funcation IsTouchpadMotionMistouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_IsTouchpadMotionMistouch_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    libinput_event event;
    inputEventHandler->isDwtEdgeAreaForTouchpadMotionActing_ = false;
    EXPECT_FALSE(inputEventHandler->IsTouchpadMotionMistouch(&event));

    inputEventHandler->isDwtEdgeAreaForTouchpadMotionActing_ = true;
    libinput_event_touch touchpadEvent;
    libinput_device touchpadDevice;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTouchpadEvent).WillRepeatedly(Return(&touchpadEvent));
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&touchpadDevice));
    g_mockLibinputDeviceGetSizeRetrunIntValue = 1;
    inputEventHandler->touchpadEventDownAbsX_ = InputEventHandler::TOUCHPAD_EDGE_WIDTH;
    EXPECT_FALSE(inputEventHandler->IsTouchpadMotionMistouch(&event));

    g_mockLibinputDeviceGetSizeRetrunIntValue = 0;
    g_mockLibinputDeviceGetSizeWidth = InputEventHandler::TOUCHPAD_EDGE_WIDTH;
    inputEventHandler->touchpadEventDownAbsX_ = InputEventHandler::TOUCHPAD_EDGE_WIDTH + 1;
    EXPECT_TRUE(inputEventHandler->IsTouchpadMotionMistouch(&event));

    g_mockLibinputDeviceGetSizeWidth = 1000.0;
    EXPECT_FALSE(inputEventHandler->IsTouchpadMotionMistouch(&event));
}

/**
 * @tc.name: InputEventHandler_IsTouchpadPointerMotionMistouch_001
 * @tc.desc: Test the funcation IsTouchpadPointerMotionMistouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandler_IsTouchpadPointerMotionMistouch_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<InputEventHandler> inputEventHandler = std::make_shared<InputEventHandler>();
    libinput_event event;
    inputEventHandler->isDwtEdgeAreaForTouchpadMotionActing_ = false;
    EXPECT_FALSE(inputEventHandler->IsTouchpadPointerMotionMistouch(&event));

    libinput_event_pointer pointerEvent;
    libinput_device touchpadDevice;
    NiceMock<LibinputInterfaceMock> libinputMock;
    inputEventHandler->isDwtEdgeAreaForTouchpadMotionActing_ = true;
    g_mockLibinputDeviceGetSizeRetrunIntValue = 1;
    EXPECT_CALL(libinputMock, LibinputGetPointerEvent).WillRepeatedly(Return(&pointerEvent));
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&touchpadDevice));
    EXPECT_FALSE(inputEventHandler->IsTouchpadPointerMotionMistouch(&event));

    g_mockLibinputDeviceGetSizeRetrunIntValue = 0;
    inputEventHandler->touchpadEventDownAbsX_ = InputEventHandler::TOUCHPAD_EDGE_WIDTH;
    EXPECT_TRUE(inputEventHandler->IsTouchpadPointerMotionMistouch(&event));

    g_mockLibinputDeviceGetSizeWidth = InputEventHandler::TOUCHPAD_EDGE_WIDTH;
    inputEventHandler->touchpadEventDownAbsX_ = InputEventHandler::TOUCHPAD_EDGE_WIDTH + 1;
    EXPECT_TRUE(inputEventHandler->IsTouchpadPointerMotionMistouch(&event));

    g_mockLibinputDeviceGetSizeWidth = 1000.0;
    inputEventHandler->touchpadEventDownAbsX_ = InputEventHandler::TOUCHPAD_EDGE_WIDTH + 1;
    EXPECT_FALSE(inputEventHandler->IsTouchpadPointerMotionMistouch(&event));
}
}  // namespace MMI
}  // namespace OHOS
