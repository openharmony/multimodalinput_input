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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "event_interceptor_handler.h"
#include "mmi_log.h"
#include "mock.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventInterceptorHandlerExTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
const std::string PROGRAM_NAME = "uds_session_test";
constexpr int32_t MODULE_TYPE = 1;
constexpr int32_t UDS_FD = 1;
constexpr int32_t UDS_UID = 100;
constexpr int32_t UDS_PID = 100;
} // namespace

class EventInterceptorHandlerExTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void EventInterceptorHandlerExTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}

void EventInterceptorHandlerExTest::TearDownTestCase()
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

/**
 * @tc.name: EventInterceptorHandlerExTest_HandleEvent_Key
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerExTest, EventInterceptorHandlerExTest_HandleEvent_Key, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EventInterceptorHandler::InterceptorCollection interceptors;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EventInterceptorHandler::SessionHandler sessionHandler(handlerType, eventType, priority,
        deviceTags, sess);
    interceptors.interceptors_.push_back(sessionHandler);
    KeyEvent::KeyItem item;
    item.SetDeviceId(100);
    keyEvent->AddKeyItem(item);
    EXPECT_FALSE(interceptors.HandleEvent(keyEvent));
}

/**
 * @tc.name: EventInterceptorHandlerExTest_HandleEvent_Key_001
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerExTest, EventInterceptorHandlerExTest_HandleEvent_Key_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EventInterceptorHandler::InterceptorCollection interceptors;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 17;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EventInterceptorHandler::SessionHandler sessionHandler(handlerType, eventType, priority,
        deviceTags, sess);
    interceptors.interceptors_.push_back(sessionHandler);
    KeyEvent::KeyItem item;
    item.SetDeviceId(100);
    keyEvent->AddKeyItem(item);
    EXPECT_FALSE(interceptors.HandleEvent(keyEvent));
}

/**
 * @tc.name: EventInterceptorHandlerExTest_HandleEvent_Key_002
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerExTest, EventInterceptorHandlerExTest_HandleEvent_Key_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    inputDevice->AddCapability(INPUT_DEV_CAP_KEYBOARD);
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EventInterceptorHandler::InterceptorCollection interceptors;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = CapabilityToTags(INPUT_DEV_CAP_KEYBOARD);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EventInterceptorHandler::SessionHandler sessionHandler(handlerType, eventType, priority,
        deviceTags, sess);
    interceptors.interceptors_.push_back(sessionHandler);
    KeyEvent::KeyItem item;
    item.SetDeviceId(100);
    keyEvent->AddKeyItem(item);
    EXPECT_FALSE(interceptors.HandleEvent(keyEvent));
}

/**
 * @tc.name: EventInterceptorHandlerExTest_HandleEvent_Key_003
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerExTest, EventInterceptorHandlerExTest_HandleEvent_Key_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    inputDevice->AddCapability(INPUT_DEV_CAP_KEYBOARD);
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EventInterceptorHandler::InterceptorCollection interceptors;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    int32_t priority = 0;
    uint32_t deviceTags = CapabilityToTags(INPUT_DEV_CAP_KEYBOARD);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EventInterceptorHandler::SessionHandler sessionHandler(handlerType, eventType, priority,
        deviceTags, sess);
    interceptors.interceptors_.push_back(sessionHandler);
    KeyEvent::KeyItem item;
    item.SetDeviceId(100);
    keyEvent->AddKeyItem(item);
    EXPECT_TRUE(interceptors.HandleEvent(keyEvent));
}

/**
 * @tc.name: EventInterceptorHandlerExTest_HandleEvent_Pointer
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerExTest, EventInterceptorHandlerExTest_HandleEvent_Pointer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EventInterceptorHandler::InterceptorCollection interceptors;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 0;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EventInterceptorHandler::SessionHandler sessionHandler(handlerType, eventType, priority, deviceTags, sess);
    interceptors.interceptors_.push_back(sessionHandler);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(100);
    pointerEvent->SetPointerId(100);
    pointerEvent->AddPointerItem(pointerItem);
    EXPECT_FALSE(interceptors.HandleEvent(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandlerExTest_HandleEvent_Pointer_001
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerExTest, EventInterceptorHandlerExTest_HandleEvent_Pointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EventInterceptorHandler::InterceptorCollection interceptors;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 6;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EventInterceptorHandler::SessionHandler sessionHandler(handlerType, eventType, priority, deviceTags, sess);
    interceptors.interceptors_.push_back(sessionHandler);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(100);
    pointerEvent->SetPointerId(100);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->AddPointerItem(pointerItem);
    EXPECT_FALSE(interceptors.HandleEvent(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandlerExTest_HandleEvent_Pointer_002
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerExTest, EventInterceptorHandlerExTest_HandleEvent_Pointer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EventInterceptorHandler::InterceptorCollection interceptors;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = 6;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EventInterceptorHandler::SessionHandler sessionHandler(handlerType, eventType, priority, deviceTags, sess);
    interceptors.interceptors_.push_back(sessionHandler);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(100);
    pointerEvent->SetPointerId(100);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_FINGERPRINT);
    pointerEvent->AddPointerItem(pointerItem);
    EXPECT_FALSE(interceptors.HandleEvent(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandlerExTest_HandleEvent_Pointer_003
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerExTest, EventInterceptorHandlerExTest_HandleEvent_Pointer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    inputDevice->AddCapability(INPUT_DEV_CAP_POINTER);
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EventInterceptorHandler::InterceptorCollection interceptors;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 0;
    int32_t priority = 0;
    uint32_t deviceTags = CapabilityToTags(INPUT_DEV_CAP_POINTER);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EventInterceptorHandler::SessionHandler sessionHandler(handlerType, eventType, priority, deviceTags, sess);
    interceptors.interceptors_.push_back(sessionHandler);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(100);
    pointerEvent->SetPointerId(100);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->AddPointerItem(pointerItem);
    EXPECT_FALSE(interceptors.HandleEvent(pointerEvent));
}

/**
 * @tc.name: EventInterceptorHandlerExTest_HandleEvent_Pointer_004
 * @tc.desc: Test the function HandleEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventInterceptorHandlerExTest, EventInterceptorHandlerExTest_HandleEvent_Pointer_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    inputDevice->AddCapability(INPUT_DEV_CAP_POINTER);
    EXPECT_CALL(*messageParcelMock_, GetInputDevice(_, _)).WillRepeatedly(Return(inputDevice));
    EventInterceptorHandler::InterceptorCollection interceptors;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = HANDLE_EVENT_TYPE_POINTER;
    int32_t priority = 0;
    uint32_t deviceTags = CapabilityToTags(INPUT_DEV_CAP_POINTER);
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    EventInterceptorHandler::SessionHandler sessionHandler(handlerType, eventType, priority, deviceTags, sess);
    interceptors.interceptors_.push_back(sessionHandler);
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetPointerId(100);
    pointerEvent->SetPointerId(100);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->AddPointerItem(pointerItem);
    EXPECT_TRUE(interceptors.HandleEvent(pointerEvent));
}
} // namespace MMI
} // namespace OHOS