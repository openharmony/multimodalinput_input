/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <libinput.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>

#include "general_touchpad.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "i_input_windows_manager.h"
#include "key_command_handler.h"
#include "libinput_wrapper.h"
#include "mmi_log.h"
#include "timer_manager.h"
#include "util.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEventHandlerTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputEventHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    
private:
    static void SetupTouchpad();
    static void CloseTouchpad();
    static GeneralTouchpad vTouchpad_;
    static LibinputWrapper libinput_;
};

GeneralTouchpad InputEventHandlerTest::vTouchpad_;
LibinputWrapper InputEventHandlerTest::libinput_;

void InputEventHandlerTest::SetUpTestCase(void)
{
    ASSERT_TRUE(libinput_.Init());
    SetupTouchpad();
}

void InputEventHandlerTest::TearDownTestCase(void)
{
    CloseTouchpad();
}

void InputEventHandlerTest::SetupTouchpad()
{
    ASSERT_TRUE(vTouchpad_.SetUp());
    std::cout << "device node name: " << vTouchpad_.GetDevPath() << std::endl;
    ASSERT_TRUE(libinput_.AddPath(vTouchpad_.GetDevPath()));
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    ASSERT_EQ(libinput_event_get_type(event), LIBINPUT_EVENT_DEVICE_ADDED);
    struct libinput_device *device = libinput_event_get_device(event);
    ASSERT_TRUE(device != nullptr);
    INPUT_DEV_MGR->OnInputDeviceAdded(device);
}

void InputEventHandlerTest::CloseTouchpad()
{
    libinput_.RemovePath(vTouchpad_.GetDevPath());
    vTouchpad_.Close();
}

void InputEventHandlerTest::SetUp()
{
}

void InputEventHandlerTest::TearDown()
{
}

/**
 * @tc.name: InputEventHandler_GetEventDispatchHandler_001
 * @tc.desc: Get event dispatch handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetEventDispatchHandler_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetEventDispatchHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetFilterHandler_001
 * @tc.desc: Get filter handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetFilterHandler_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetFilterHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetMonitorHandler_001
 * @tc.desc: Get monitor handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetMonitorHandler_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetMonitorHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetKeyCommandHandler_001
 * @tc.desc: Get monitor handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetKeyCommandHandler_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetKeyCommandHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetSwitchSubscriberHandler_001
 * @tc.desc: Get switch subscriber handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetSwitchSubscriberHandler_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetSwitchSubscriberHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetSubscriberHandler_001
 * @tc.desc: Get subscriber handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetSubscriberHandler_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetSubscriberHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetInterceptorHandler_001
 * @tc.desc: Get interceptor handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetInterceptorHandler_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetInterceptorHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetEventNormalizeHandler_001
 * @tc.desc: Get eventNormalize handler verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetEventNormalizeHandler_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetEventNormalizeHandler();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_GetUDSServer_001
 * @tc.desc: Get UDS server verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_GetUDSServer_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    auto result = inputHandler->GetUDSServer();
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHandler_BuildInputHandlerChain_001
 * @tc.desc: Build input handler chain verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_BuildInputHandlerChain_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    UDSServer udsServer;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    ASSERT_NO_FATAL_FAILURE(inputHandler->Init(udsServer));
}

/**
 * @tc.name: InputEventHandler_OnEvent_001
 * @tc.desc: On event verify
 * @tc.type: FUNC
 * @tc.require:SR000HQ0RR
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_OnEvent_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    void* mockEvent = nullptr;
    int64_t mockFrameTime = 123456789;
    std::shared_ptr<OHOS::MMI::InputEventHandler> inputHandler = InputHandler;
    ASSERT_NO_FATAL_FAILURE(inputHandler->OnEvent(mockEvent, mockFrameTime));
}

/**
 * @tc.name: InputEventHandler_OnEvent_002
 * @tc.desc: Test the funcation OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_OnEvent_002, TestSize.Level1)
{
    InputEventHandler inputEventHandler ;
    void *event = nullptr;
    int64_t frameTime = 1234;
    inputEventHandler.eventNormalizeHandler_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler.OnEvent(event, frameTime));
}

/**
 * @tc.name: InputEventHandler_OnEvent_003
 * @tc.desc: Test the funcation OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_OnEvent_003, TestSize.Level1)
{
    InputEventHandler inputEventHandler ;
    void *event = nullptr;
    int64_t frameTime = 1234;
    inputEventHandler.eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    ASSERT_TRUE(inputEventHandler.eventNormalizeHandler_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(inputEventHandler.OnEvent(event, frameTime));
}

/**
 * @tc.name: InputEventHandler_OnEvent_004
 * @tc.desc: Test the funcation OnEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_OnEvent_004, TestSize.Level1)
{
    InputEventHandler inputEventHandler ;
    int64_t frameTime = 1234;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 185);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 1511);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 384);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOOL_FINGER, 1);
    vTouchpad_.SendEvent(EV_ABS, ABS_X, 1511);
    vTouchpad_.SendEvent(EV_ABS, ABS_Y, 384);
    vTouchpad_.SendEvent(EV_MSC, MSC_TIMESTAMP, 0);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 1510);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 386);
    vTouchpad_.SendEvent(EV_ABS, ABS_X, 1510);
    vTouchpad_.SendEvent(EV_ABS, ABS_Y, 386);
    vTouchpad_.SendEvent(EV_MSC, MSC_TIMESTAMP, 42000);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 0);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOOL_FINGER, 0);
    vTouchpad_.SendEvent(EV_MSC, MSC_TIMESTAMP, 123000);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    inputEventHandler.eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    ASSERT_TRUE(inputEventHandler.eventNormalizeHandler_ != nullptr);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    struct libinput_device *dev = libinput_event_get_device(event);
    ASSERT_TRUE(dev != nullptr);
    std::cout << "pointer device: " << libinput_device_get_name(dev) << std::endl;
    const uint64_t maxUInt64 = (std::numeric_limits<uint64_t>::max)() - 1;
    inputEventHandler.idSeed_ = maxUInt64 + 1;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler.OnEvent(event, frameTime));
    inputEventHandler.idSeed_ = 123;
    ASSERT_NO_FATAL_FAILURE(inputEventHandler.OnEvent(event, frameTime));
}

/**
 * @tc.name: InputEventHandler_IsTouchpadMistouch_001
 * @tc.desc: Test the funcation IsTouchpadMistouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_IsTouchpadMistouch_001, TestSize.Level1)
{
    InputEventHandler inputEventHandler ;
    libinput_event* event = nullptr;
    bool ret = inputEventHandler.IsTouchpadMistouch(event);
    ASSERT_FALSE(ret);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 185);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 1511);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 384);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOOL_FINGER, 1);
    vTouchpad_.SendEvent(EV_ABS, ABS_X, 1511);
    vTouchpad_.SendEvent(EV_ABS, ABS_Y, 384);
    vTouchpad_.SendEvent(EV_MSC, MSC_TIMESTAMP, 0);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    auto type = libinput_event_get_type(event);
    ASSERT_FALSE(ret);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 1510);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 386);
    vTouchpad_.SendEvent(EV_ABS, ABS_X, 1510);
    vTouchpad_.SendEvent(EV_ABS, ABS_Y, 386);
    vTouchpad_.SendEvent(EV_MSC, MSC_TIMESTAMP, 42000);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    type = libinput_event_get_type(event);
    ASSERT_FALSE(ret);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 0);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOOL_FINGER, 0);
    vTouchpad_.SendEvent(EV_MSC, MSC_TIMESTAMP, 123000);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    touchpad = libinput_event_get_touchpad_event(event);
    type = libinput_event_get_type(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputEventHandler_IsTouchpadMistouch_002
 * @tc.desc: Test the funcation IsTouchpadMistouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_IsTouchpadMistouch_002, TestSize.Level1)
{
    InputEventHandler inputEventHandler ;
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 189);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 10);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 1050);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOOL_FINGER, 1);
    vTouchpad_.SendEvent(EV_ABS, ABS_X, 10);
    vTouchpad_.SendEvent(EV_ABS, ABS_Y, 1050);
    vTouchpad_.SendEvent(EV_MSC, MSC_TIMESTAMP, 0);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    libinput_event *event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    auto touchpad = libinput_event_get_touchpad_event(event);
    auto type = libinput_event_get_type(event);
    bool ret = inputEventHandler.IsTouchpadMistouch(event);
    ASSERT_FALSE(ret);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 1510);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 386);
    vTouchpad_.SendEvent(EV_ABS, ABS_X, 1510);
    vTouchpad_.SendEvent(EV_ABS, ABS_Y, 386);
    vTouchpad_.SendEvent(EV_MSC, MSC_TIMESTAMP, 42000);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    type = libinput_event_get_type(event);
    ASSERT_FALSE(ret);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 0);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOOL_FINGER, 0);
    vTouchpad_.SendEvent(EV_MSC, MSC_TIMESTAMP, 362000);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    touchpad = libinput_event_get_touchpad_event(event);
    ASSERT_TRUE(touchpad != nullptr);
    type = libinput_event_get_type(event);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputEventHandler_IsTouchpadTapMistouch_001
 * @tc.desc: Test the funcation IsTouchpadTapMistouch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHandlerTest, InputEventHandlerTest_IsTouchpadTapMistouch_001, TestSize.Level1)
{
    InputEventHandler inputEventHandler ;
    libinput_event* event = nullptr;
    bool ret = inputEventHandler.IsTouchpadTapMistouch(event);
    ASSERT_FALSE(ret);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, 189);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 10);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 1050);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOOL_FINGER, 1);
    vTouchpad_.SendEvent(EV_ABS, ABS_X, 10);
    vTouchpad_.SendEvent(EV_ABS, ABS_Y, 1050);
    vTouchpad_.SendEvent(EV_MSC, MSC_TIMESTAMP, 0);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    ASSERT_FALSE(ret);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_X, 1510);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_POSITION_Y, 386);
    vTouchpad_.SendEvent(EV_ABS, ABS_X, 1510);
    vTouchpad_.SendEvent(EV_ABS, ABS_Y, 386);
    vTouchpad_.SendEvent(EV_MSC, MSC_TIMESTAMP, 42000);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    ASSERT_FALSE(ret);
    vTouchpad_.SendEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOUCH, 0);
    vTouchpad_.SendEvent(EV_KEY, BTN_TOOL_FINGER, 0);
    vTouchpad_.SendEvent(EV_MSC, MSC_TIMESTAMP, 362000);
    vTouchpad_.SendEvent(EV_SYN, SYN_REPORT, 0);
    event = libinput_.Dispatch();
    ASSERT_TRUE(event != nullptr);
    ASSERT_FALSE(ret);
}
} // namespace MMI
} // namespace OHOS