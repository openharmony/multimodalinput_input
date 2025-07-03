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

#include <cstdio>
#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "input_device_consumer_handler.h"
#include "input_event_handler.h"

#include "mock.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDeviceConsumerHandlerTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

const std::string PROGRAM_NAME { "uds_session_test" };
constexpr int32_t MODULE_TYPE { 1 };
constexpr int32_t UDS_FD { 1 };
constexpr int32_t UDS_UID { 100 };
constexpr int32_t UDS_PID { 100 };

class InputDeviceConsumerHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void InputDeviceConsumerHandlerTest::SetUpTestCase(void)
{
}

void InputDeviceConsumerHandlerTest::TearDownTestCase(void)
{
}

void InputDeviceConsumerHandlerTest::SetUp()
{
}

void InputDeviceConsumerHandlerTest::TearDown()
{
    MOCKHANDLER->DestroyInstance();
    DEVICEHANDLER->deviceConsumerHandler_.deviceHandler_.clear();
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_SetDeviceConsumerHandler
 * @tc.desc: Test SetDeviceConsumerHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_SetDeviceConsumerHandler, TestSize.Level1)
{
    std::vector<std::string> deviceNames;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    std::string name = "test";
    deviceNames.push_back("ttttt");
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto ret = DEVICEHANDLER->SetDeviceConsumerHandler(deviceNames, sess);
    DEVICEHANDLER->HandleDeviceConsumerEvent(name, pointerEvent);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_ClearDeviceConsumerHandler
 * @tc.desc: Test SetDeviceConsumerHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_ClearDeviceConsumerHandler, TestSize.Level1)
{
    std::vector<std::string> deviceNames;
    deviceNames.push_back("test");
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto ret = DEVICEHANDLER->ClearDeviceConsumerHandler(deviceNames, sess);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_RemoveDeviceHandler
 * @tc.desc: Test SetDeviceConsumerHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_RemoveDeviceHandler, TestSize.Level1)
{
    std::vector<std::string> deviceNames;
    deviceNames.push_back("test");
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto ret = DEVICEHANDLER->deviceConsumerHandler_.RemoveDeviceHandler(deviceNames, sess);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_SetDeviceConsumerHandler_001
 * @tc.desc: Test SetDeviceConsumerHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_SetDeviceConsumerHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> deviceNames = {"device1", "device2"};
    SessionPtr session = nullptr;
    auto ret = DEVICEHANDLER->SetDeviceConsumerHandler(deviceNames, session);
    ASSERT_EQ(ret, ERROR_NULL_POINTER);
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_SetDeviceConsumerHandler_002
 * @tc.desc: Test SetDeviceConsumerHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_SetDeviceConsumerHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> deviceNames = {"device1", "device2"};
    int32_t fd_1 = 1;
    int32_t fd_2 = 2;
    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, fd_1, UDS_UID, UDS_PID);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, fd_2, UDS_UID, UDS_PID);
    auto& deviceHandler = DEVICEHANDLER->deviceConsumerHandler_.deviceHandler_;
    auto sessionHandler = std::set<InputDeviceConsumerHandler::SessionHandler>{session1};
    deviceHandler["device1"] = sessionHandler;
    EXPECT_EQ(deviceHandler["device1"].size(), 1);
    InputHandler->udsServer_ = nullptr;
    auto ret = DEVICEHANDLER->SetDeviceConsumerHandler(deviceNames, session2);
    EXPECT_EQ(deviceHandler.size(), 2);
    EXPECT_EQ(deviceHandler["device1"].size(), 2);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_SetDeviceConsumerHandler_003
 * @tc.desc: Test SetDeviceConsumerHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_SetDeviceConsumerHandler_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> deviceNames = {"device1", "device2"};
    int32_t fd_1 = 1;
    int32_t fd_2 = 2;
    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, fd_1, UDS_UID, UDS_PID);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, fd_2, UDS_UID, UDS_PID);
    auto& deviceHandler = DEVICEHANDLER->deviceConsumerHandler_.deviceHandler_;
    auto sessionHandler = std::set<InputDeviceConsumerHandler::SessionHandler>{session1};
    deviceHandler["device1"] = sessionHandler;
    EXPECT_EQ(deviceHandler["device1"].size(), 1);
    auto udsServer = std::make_shared<UDSServer>();
    InputHandler->udsServer_ = udsServer.get();
    MOCKHANDLER->mockSessionPara = session1;
    auto ret = DEVICEHANDLER->SetDeviceConsumerHandler(deviceNames, session2);
    EXPECT_EQ(deviceHandler.size(), 2);
    EXPECT_EQ(deviceHandler["device1"].size(), 1);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_HandleDeviceConsumerEvent_001
 * @tc.desc: Test HandleDeviceConsumerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_HandleDeviceConsumerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "device1";
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(DEVICEHANDLER->HandleDeviceConsumerEvent(name, pointerEvent));
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_HandleDeviceConsumerEvent_002
 * @tc.desc: Test HandleDeviceConsumerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_HandleDeviceConsumerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "device1";
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NO_FATAL_FAILURE(DEVICEHANDLER->HandleDeviceConsumerEvent(name, pointerEvent));
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_HandleDeviceConsumerEvent_003
 * @tc.desc: Test HandleDeviceConsumerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_HandleDeviceConsumerEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "device1";
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    auto& deviceHandler = DEVICEHANDLER->deviceConsumerHandler_.deviceHandler_;
    auto sessionHandler = std::set<InputDeviceConsumerHandler::SessionHandler>();
    deviceHandler["device1"] = sessionHandler;
    MOCKHANDLER->mockChkRWErrorRet = true;
    ASSERT_NO_FATAL_FAILURE(DEVICEHANDLER->HandleDeviceConsumerEvent(name, pointerEvent));
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_HandleDeviceConsumerEvent_004
 * @tc.desc: Test HandleDeviceConsumerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_HandleDeviceConsumerEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "device1";
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    auto& deviceHandler = DEVICEHANDLER->deviceConsumerHandler_.deviceHandler_;
    auto sessionHandler = std::set<InputDeviceConsumerHandler::SessionHandler>();
    deviceHandler["device1"] = sessionHandler;
    MOCKHANDLER->mockChkRWErrorRet = false;
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetOrientation(0);
    item.SetBlobId(0);
    item.SetToolType(0);
    pointerEvent->UpdatePointerItem(0, item);
    MOCKHANDLER->mockGetPointerItemRet = false;
    ASSERT_NO_FATAL_FAILURE(DEVICEHANDLER->HandleDeviceConsumerEvent(name, pointerEvent));
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_HandleDeviceConsumerEvent_005
 * @tc.desc: Test HandleDeviceConsumerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_HandleDeviceConsumerEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "device1";
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    auto& deviceHandler = DEVICEHANDLER->deviceConsumerHandler_.deviceHandler_;
    auto sessionHandler = std::set<InputDeviceConsumerHandler::SessionHandler>();
    deviceHandler["device1"] = sessionHandler;
    MOCKHANDLER->mockChkRWErrorRet = false;
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetOrientation(0);
    item.SetBlobId(0);
    item.SetToolType(0);
    pointerEvent->UpdatePointerItem(0, item);
    MOCKHANDLER->mockGetPointerItemRet = true;
    MOCKHANDLER->mockMarshallingRet = RET_ERR;
    ASSERT_NO_FATAL_FAILURE(DEVICEHANDLER->HandleDeviceConsumerEvent(name, pointerEvent));
}

/**
 * @tc.name: InputDeviceConsumerHandlerTest_HandleDeviceConsumerEvent_006
 * @tc.desc: Test HandleDeviceConsumerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputDeviceConsumerHandlerTest, InputDeviceConsumerHandlerTest_HandleDeviceConsumerEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "device1";
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    MOCKHANDLER->mockChkRWErrorRet = false;
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetOrientation(0);
    item.SetBlobId(0);
    item.SetToolType(0);
    pointerEvent->UpdatePointerItem(0, item);
    MOCKHANDLER->mockGetPointerItemRet = true;
    MOCKHANDLER->mockMarshallingRet = RET_OK;
    int32_t fd_1 = 1;
    int32_t fd_2 = 2;
    SessionPtr session1 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, fd_1, UDS_UID, UDS_PID);
    SessionPtr session2 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, fd_2, UDS_UID, UDS_PID);
    auto& deviceHandler = DEVICEHANDLER->deviceConsumerHandler_.deviceHandler_;
    auto sessionHandler1 = std::set<InputDeviceConsumerHandler::SessionHandler>{session1};
    auto sessionHandler2 = std::set<InputDeviceConsumerHandler::SessionHandler>{session2};
    deviceHandler["device1"] = sessionHandler1;
    deviceHandler["device2"] = sessionHandler2;
    MOCKHANDLER->mockSendMsgRet = false;
    ASSERT_NO_FATAL_FAILURE(DEVICEHANDLER->HandleDeviceConsumerEvent(name, pointerEvent));
}
} // namespace MMI
} // namespace OHOS