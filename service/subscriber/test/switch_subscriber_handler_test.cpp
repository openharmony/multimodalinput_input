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


#include <fstream>
#include <gtest/gtest.h>

#include "input_event_handler.h"
#include "mmi_log.h"
#include "switch_subscriber_handler.h"
#include "uds_server.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "SwitchSubscriberHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t INVAID_VALUE = -1;
constexpr int32_t SUBSCRIBER_ID = 0;
constexpr int32_t POINTER_EVENT_TYPE = 3;
constexpr int32_t SESSION_MODULE_TYPE = 3;
constexpr int32_t SESSION_FD = -1;
constexpr int32_t SESSION_UID = 0;
constexpr int32_t SESSION_PID = 0;
} // namespace

class SwitchSubscriberHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: SwitchSubscriberHandlerTest_HandleKeyEvent_001
 * @tc.desc: Test HandleKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_HandleKeyEvent_001, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);
    auto nextSwitchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(nextSwitchSubscriberHandler, nullptr);

    switchSubscriberHandler->HandleKeyEvent(nullptr);
    switchSubscriberHandler->HandleKeyEvent(keyEvent);
    switchSubscriberHandler->nextHandler_ = nextSwitchSubscriberHandler;
    switchSubscriberHandler->HandleKeyEvent(keyEvent);
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_HandlePointerEvent_001
 * @tc.desc: Test HandlePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_HandlePointerEvent_001, TestSize.Level1)
{
    auto pointerEvent = std::make_shared<PointerEvent>(POINTER_EVENT_TYPE);
    ASSERT_NE(pointerEvent, nullptr);
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);
    auto nextSwitchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(nextSwitchSubscriberHandler, nullptr);

    switchSubscriberHandler->HandlePointerEvent(nullptr);
    switchSubscriberHandler->HandlePointerEvent(pointerEvent);
    switchSubscriberHandler->nextHandler_ = nextSwitchSubscriberHandler;
    switchSubscriberHandler->HandlePointerEvent(pointerEvent);
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_HandleTouchEvent_001
 * @tc.desc: Test HandleTouchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_HandleTouchEvent_001, TestSize.Level1)
{
    auto pointerEvent = std::make_shared<PointerEvent>(POINTER_EVENT_TYPE);
    ASSERT_NE(pointerEvent, nullptr);
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);
    auto nextSwitchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(nextSwitchSubscriberHandler, nullptr);

    switchSubscriberHandler->HandleTouchEvent(nullptr);
    switchSubscriberHandler->HandleTouchEvent(pointerEvent);
    switchSubscriberHandler->nextHandler_ = nextSwitchSubscriberHandler;
    switchSubscriberHandler->HandleTouchEvent(pointerEvent);
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_HandleSwitchEvent_001
 * @tc.desc: Test HandleSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_HandleSwitchEvent_001, TestSize.Level1)
{
    auto switchEvent = std::make_shared<SwitchEvent>(INVAID_VALUE);
    ASSERT_NE(switchEvent, nullptr);
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);
    auto nextSwitchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(nextSwitchSubscriberHandler, nullptr);

    switchSubscriberHandler->HandleSwitchEvent(nullptr);
    switchEvent->SetSwitchType(SwitchEvent::SwitchType::SWITCH_PRIVACY);
    switchEvent->SetSwitchValue(SwitchEvent::SWITCH_ON);
    switchSubscriberHandler->HandleSwitchEvent(switchEvent);
    switchSubscriberHandler->nextHandler_ = nextSwitchSubscriberHandler;
    switchSubscriberHandler->HandleSwitchEvent(switchEvent);

    auto sess = std::make_shared<UDSSession>(
        "switch_subscriber_handler_test", SESSION_MODULE_TYPE, SESSION_FD, SESSION_UID, SESSION_PID);
    ASSERT_NE(sess, nullptr);
    auto subscriber = std::make_shared<SwitchSubscriberHandler::Subscriber>(
        SUBSCRIBER_ID, sess, SwitchEvent::SwitchType::SWITCH_PRIVACY);
    ASSERT_NE(subscriber, nullptr);

    switchSubscriberHandler->InsertSubScriber(subscriber);
    switchSubscriberHandler->HandleSwitchEvent(switchEvent);
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_SubscribeSwitchEvent_001
 * @tc.desc: Test SubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_SubscribeSwitchEvent_001, TestSize.Level1)
{
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);

    ASSERT_EQ(switchSubscriberHandler->SubscribeSwitchEvent(
        nullptr, INVAID_VALUE, SwitchEvent::SwitchType::SWITCH_DEFAULT), RET_ERR);
    ASSERT_EQ(switchSubscriberHandler->SubscribeSwitchEvent(nullptr, SUBSCRIBER_ID, INVAID_VALUE), RET_ERR);
    ASSERT_EQ(switchSubscriberHandler->SubscribeSwitchEvent(
        nullptr, SUBSCRIBER_ID, SwitchEvent::SwitchType::SWITCH_DEFAULT), ERROR_NULL_POINTER);
    auto sess = std::make_shared<UDSSession>(
        "switch_subscriber_handler_test", SESSION_MODULE_TYPE, SESSION_FD, SESSION_UID, SESSION_PID);
    ASSERT_NE(sess, nullptr);

    ASSERT_EQ(switchSubscriberHandler->SubscribeSwitchEvent(
        sess, SUBSCRIBER_ID, SwitchEvent::SwitchType::SWITCH_PRIVACY), RET_OK);
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_UnsubscribeSwitchEvent_001
 * @tc.desc: Test UnsubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_UnsubscribeSwitchEvent_001, TestSize.Level1)
{
    auto firstSess = std::make_shared<UDSSession>(
        "switch_subscriber_handler_test", SESSION_MODULE_TYPE, SESSION_FD, SESSION_UID, SESSION_PID);
    ASSERT_NE(firstSess, nullptr);
    auto secondSess = std::make_shared<UDSSession>(
        "switch_subscriber_handler_test", SESSION_MODULE_TYPE, SESSION_FD, SESSION_UID, SESSION_PID);
    ASSERT_NE(secondSess, nullptr);
    auto switchEvent = std::make_shared<SwitchEvent>(SwitchEvent::SwitchType::SWITCH_DEFAULT);
    ASSERT_NE(switchEvent, nullptr);
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);

    switchEvent->SetSwitchType(SwitchEvent::SwitchType::SWITCH_LID);
    switchEvent->SetSwitchValue(SwitchEvent::SWITCH_ON);

    ASSERT_EQ(switchSubscriberHandler->UnsubscribeSwitchEvent(firstSess, SUBSCRIBER_ID), RET_ERR);
    ASSERT_EQ(switchSubscriberHandler->SubscribeSwitchEvent(firstSess, SUBSCRIBER_ID,
        SwitchEvent::SwitchType::SWITCH_DEFAULT), RET_OK);
    ASSERT_EQ(switchSubscriberHandler->SubscribeSwitchEvent(secondSess, SUBSCRIBER_ID,
        SwitchEvent::SwitchType::SWITCH_DEFAULT), RET_OK);
    ASSERT_EQ(switchSubscriberHandler->UnsubscribeSwitchEvent(firstSess, SUBSCRIBER_ID), RET_OK);
    ASSERT_EQ(switchSubscriberHandler->UnsubscribeSwitchEvent(firstSess, SUBSCRIBER_ID), RET_ERR);
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_OnSubscribeSwitchEvent_001
 * @tc.desc: Test OnSubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_OnSubscribeSwitchEvent_001, TestSize.Level1)
{
    auto sess = std::make_shared<UDSSession>(
        "switch_subscriber_handler_test", SESSION_MODULE_TYPE, SESSION_FD, SESSION_UID, SESSION_PID);
    ASSERT_NE(sess, nullptr);
    auto switchEvent = std::make_shared<SwitchEvent>(SwitchEvent::SwitchType::SWITCH_DEFAULT);
    ASSERT_NE(switchEvent, nullptr);
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);

    switchEvent->SetSwitchType(SwitchEvent::SwitchType::SWITCH_PRIVACY);
    switchEvent->SetSwitchValue(SwitchEvent::SWITCH_ON);
    switchEvent->SetSwitchMask(INVAID_VALUE);
    switchEvent->GetSwitchMask();

    ASSERT_EQ(switchSubscriberHandler->OnSubscribeSwitchEvent(nullptr), false);
    ASSERT_EQ(switchSubscriberHandler->SubscribeSwitchEvent(sess, SUBSCRIBER_ID,
        SwitchEvent::SwitchType::SWITCH_PRIVACY), RET_OK);
    ASSERT_EQ(switchSubscriberHandler->OnSubscribeSwitchEvent(switchEvent), true);
    ASSERT_EQ(switchSubscriberHandler->UnsubscribeSwitchEvent(sess, SUBSCRIBER_ID), RET_OK);
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_OnSubscribeSwitchEvent_002
 * @tc.desc: Test OnSubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_OnSubscribeSwitchEvent_002, TestSize.Level1)
{
    auto sess = std::make_shared<UDSSession>(
        "switch_subscriber_handler_test", SESSION_MODULE_TYPE, SESSION_FD, SESSION_UID, SESSION_PID);
    ASSERT_NE(sess, nullptr);
    auto switchEvent = std::make_shared<SwitchEvent>(SwitchEvent::SwitchType::SWITCH_DEFAULT);
    ASSERT_NE(switchEvent, nullptr);
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);

    switchEvent->SetSwitchType(SwitchEvent::SwitchType::SWITCH_LID);
    switchEvent->SetSwitchValue(SwitchEvent::SWITCH_ON);

    ASSERT_EQ(switchSubscriberHandler->SubscribeSwitchEvent(sess, SUBSCRIBER_ID,
        SwitchEvent::SwitchType::SWITCH_DEFAULT), RET_OK);
    ASSERT_EQ(switchSubscriberHandler->OnSubscribeSwitchEvent(switchEvent), true);
    ASSERT_EQ(switchSubscriberHandler->UnsubscribeSwitchEvent(sess, SUBSCRIBER_ID), RET_OK);
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_OnSubscribeSwitchEvent_003
 * @tc.desc: Test OnSubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_OnSubscribeSwitchEvent_003, TestSize.Level1)
{
    auto sess = std::make_shared<UDSSession>(
        "switch_subscriber_handler_test", SESSION_MODULE_TYPE, SESSION_FD, SESSION_UID, SESSION_PID);
    ASSERT_NE(sess, nullptr);
    auto switchEvent = std::make_shared<SwitchEvent>(SwitchEvent::SwitchType::SWITCH_DEFAULT);
    ASSERT_NE(switchEvent, nullptr);
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);

    switchEvent->SetSwitchType(SwitchEvent::SwitchType::SWITCH_PRIVACY);
    switchEvent->SetSwitchValue(SwitchEvent::SWITCH_ON);

    ASSERT_EQ(switchSubscriberHandler->SubscribeSwitchEvent(sess, SUBSCRIBER_ID,
        SwitchEvent::SwitchType::SWITCH_DEFAULT), RET_OK);
    ASSERT_EQ(switchSubscriberHandler->OnSubscribeSwitchEvent(switchEvent), false);
    ASSERT_EQ(switchSubscriberHandler->UnsubscribeSwitchEvent(sess, SUBSCRIBER_ID), RET_OK);
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_InsertSubScriber_001
 * @tc.desc: Test InsertSubScriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_InsertSubScriber_001, TestSize.Level1)
{
    auto sess = std::make_shared<UDSSession>(
        "switch_subscriber_handler_test", SESSION_MODULE_TYPE, SESSION_FD, SESSION_UID, SESSION_PID);
    ASSERT_NE(sess, nullptr);
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);
    auto subscriber = std::make_shared<SwitchSubscriberHandler::Subscriber>(
        SUBSCRIBER_ID, sess, SwitchEvent::SwitchType::SWITCH_PRIVACY);
    ASSERT_NE(subscriber, nullptr);
    auto repeatSubscriber = std::make_shared<SwitchSubscriberHandler::Subscriber>(
        SUBSCRIBER_ID, sess, SwitchEvent::SwitchType::SWITCH_PRIVACY);
    ASSERT_NE(repeatSubscriber, nullptr);

    switchSubscriberHandler->InsertSubScriber(nullptr);
    switchSubscriberHandler->InsertSubScriber(subscriber);
    switchSubscriberHandler->InsertSubScriber(repeatSubscriber);
    repeatSubscriber->sess_ = nullptr;
    switchSubscriberHandler->InsertSubScriber(repeatSubscriber);
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_OnSessionDelete_001
 * @tc.desc: Test OnSessionDelete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_OnSessionDelete_001, TestSize.Level1)
{
    auto firstSess = std::make_shared<UDSSession>(
        "switch_subscriber_handler_test", SESSION_MODULE_TYPE, SESSION_FD, SESSION_UID, SESSION_PID);
    ASSERT_NE(firstSess, nullptr);
    auto secondSess = std::make_shared<UDSSession>(
        "switch_subscriber_handler_test", SESSION_MODULE_TYPE, SESSION_FD, SESSION_UID, SESSION_PID);
    ASSERT_NE(secondSess, nullptr);
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);
    auto firstSubscriber = std::make_shared<SwitchSubscriberHandler::Subscriber>(
        SUBSCRIBER_ID, firstSess, SwitchEvent::SwitchType::SWITCH_PRIVACY);
    ASSERT_NE(firstSubscriber, nullptr);
    auto secondSubscriber = std::make_shared<SwitchSubscriberHandler::Subscriber>(
        SUBSCRIBER_ID, secondSess, SwitchEvent::SwitchType::SWITCH_PRIVACY);
    ASSERT_NE(secondSubscriber, nullptr);

    switchSubscriberHandler->OnSessionDelete(firstSess);
    switchSubscriberHandler->InsertSubScriber(firstSubscriber);
    switchSubscriberHandler->InsertSubScriber(secondSubscriber);
    switchSubscriberHandler->OnSessionDelete(nullptr);
    switchSubscriberHandler->OnSessionDelete(secondSess);
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_NotifySubscriber_001
 * @tc.desc: Test NotifySubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_NotifySubscriber_001, TestSize.Level1)
{
    auto switchEvent = std::make_shared<SwitchEvent>(SwitchEvent::SwitchType::SWITCH_DEFAULT);
    ASSERT_NE(switchEvent, nullptr);
    auto sess = std::make_shared<UDSSession>(
        "switch_subscriber_handler_test", SESSION_MODULE_TYPE, SESSION_FD, SESSION_UID, SESSION_PID);
    ASSERT_NE(sess, nullptr);
    auto subscriber = std::make_shared<SwitchSubscriberHandler::Subscriber>(
        SUBSCRIBER_ID, sess, SwitchEvent::SwitchType::SWITCH_PRIVACY);
    ASSERT_NE(subscriber, nullptr);
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);

    switchSubscriberHandler->NotifySubscriber(nullptr, subscriber);
    switchSubscriberHandler->NotifySubscriber(switchEvent, nullptr);
    switchSubscriberHandler->NotifySubscriber(switchEvent, subscriber);

    UDSServer udsServer;
    InputHandler->udsServer_ = &udsServer;
    switchSubscriberHandler->NotifySubscriber(switchEvent, subscriber);
    subscriber->sess_ = nullptr;
    switchSubscriberHandler->NotifySubscriber(switchEvent, subscriber);
    InputHandler->udsServer_ = nullptr;
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_InitSessionDeleteCallback_001
 * @tc.desc: Test InitSessionDeleteCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_InitSessionDeleteCallback_001, TestSize.Level1)
{
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);

    ASSERT_EQ(switchSubscriberHandler->InitSessionDeleteCallback(), false);

    UDSServer udsServer;
    InputHandler->udsServer_ = &udsServer;
    ASSERT_EQ(switchSubscriberHandler->InitSessionDeleteCallback(), true);
    ASSERT_EQ(switchSubscriberHandler->InitSessionDeleteCallback(), true);
    InputHandler->udsServer_ = nullptr;
}

/**
 * @tc.name: SwitchSubscriberHandlerTest_Dump_001
 * @tc.desc: Test Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SwitchSubscriberHandlerTest, SwitchSubscriberHandlerTest_Dump_001, TestSize.Level1)
{
    auto sess = std::make_shared<UDSSession>(
        "switch_subscriber_handler_test", SESSION_MODULE_TYPE, SESSION_FD, SESSION_UID, SESSION_PID);
    ASSERT_NE(sess, nullptr);
    auto subscriber = std::make_shared<SwitchSubscriberHandler::Subscriber>(
        SUBSCRIBER_ID, sess, SwitchEvent::SwitchType::SWITCH_PRIVACY);
    ASSERT_NE(subscriber, nullptr);
    auto switchSubscriberHandler = std::make_shared<SwitchSubscriberHandler>();
    ASSERT_NE(switchSubscriberHandler, nullptr);

    switchSubscriberHandler->InsertSubScriber(subscriber);

    std::vector<std::string> args;
    args.push_back("args0");
    args.push_back("args1");

    switchSubscriberHandler->Dump(INVAID_VALUE, args);
}

} // namespace MMI
} // namespace OHOS
