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

#include <gtest/gtest.h>
#include "client_msg_handler.h"
#include "input_active_subscribe_manager.h"
#include "input_handler_type.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ClientMsgHandlerTest"


namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class MockUDSClient : public UDSClient {
public:
    int32_t Socket() override { return 0; }
};

class ClientMsgHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {}
    static void TearDownTestCase(void)
    {}
};

/**
 * @tc.name: ClientMsgHandler_Test_001
 * @tc.desc: Test ClientMsgHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientMsgHandlerTest, ClientMsgHandler_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientMsgHandler handler;
    const MockUDSClient client;
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    int32_t result = handler.OnPreKeyEvent(client, pkt);
    EXPECT_EQ(result, SHIELD_MODE::UNSET_MODE);
}


/**
 * @tc.name: ClientMsgHandler_Test_002
 * @tc.desc: Test ClientMsgHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientMsgHandlerTest, ClientMsgHandler_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientMsgHandler handler;
    MockUDSClient client;
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    int32_t result = handler.NotifyBundleName(client, pkt);
    EXPECT_EQ(result, SHIELD_MODE::FACTORY_MODE);
}

/**
 * @tc.name: ClientMsgHandler_Test_003
 * @tc.desc: Test ClientMsgHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientMsgHandlerTest, ClientMsgHandler_Test_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientMsgHandler handler;
    MockUDSClient client;
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    int32_t result = handler.ReportDeviceConsumer(client, pkt);
    EXPECT_EQ(result, SHIELD_MODE::UNSET_MODE);
}

/**
 * @tc.name: ClientMsgHandler_Test_004
 * @tc.desc: Test ClientMsgHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientMsgHandlerTest, ClientMsgHandler_Test_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientMsgHandler handler;
    MockUDSClient client;
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    int32_t result = handler.OnSubscribeKeyMonitor(client, pkt);
    EXPECT_EQ(result, SHIELD_MODE::UNSET_MODE);
}

/**
 * @tc.name: ClientMsgHandler_Test_005
 * @tc.desc: Test ClientMsgHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientMsgHandlerTest, ClientMsgHandler_Test_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientMsgHandler handler;
    MockUDSClient client;
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    int32_t result = handler.NotifyWindowStateError(client, pkt);
    EXPECT_EQ(result, SHIELD_MODE::UNSET_MODE);
}

/**
 * @tc.name: ClientMsgHandler_Test_006
 * @tc.desc: Test ClientMsgHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientMsgHandlerTest, ClientMsgHandler_Test_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientMsgHandler handler;
    int32_t eventId = 1;
    int64_t actionTime = 2;
    ASSERT_NO_FATAL_FAILURE(handler.OnDispatchEventProcessed(eventId, actionTime));
    eventId = -1;
    actionTime = -2;
    ASSERT_NO_FATAL_FAILURE(handler.OnDispatchEventProcessed(eventId, actionTime));
}

/**
 * @tc.name: ClientMsgHandler_Test_007
 * @tc.desc: Test ClientMsgHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientMsgHandlerTest, ClientMsgHandler_Test_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientMsgHandler handler;
    MockUDSClient client;
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    int32_t result = handler.OnSubscribeInputActiveCallback(client, pkt);
    EXPECT_EQ(result, SHIELD_MODE::UNSET_MODE);
}

/**
 * @tc.name: ClientMsgHandler_Test_008
 * @tc.desc: Test ClientMsgHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientMsgHandlerTest, ClientMsgHandler_Test_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientMsgHandler handler;
    MockUDSClient client;
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    int32_t result = handler.OnSubscribeLongPressEventCallback(client, pkt);
    EXPECT_EQ(result, SHIELD_MODE::UNSET_MODE);
}

/**
 * @tc.name: ClientMsgHandler_Test_009
 * @tc.desc: Test ClientMsgHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientMsgHandlerTest, ClientMsgHandler_Test_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientMsgHandler handler;
    MockUDSClient client;
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    int32_t result = handler.OnSubscribeTabletProximityCallback(client, pkt);
    EXPECT_NE(result, PACKET_READ_FAIL);
}

/**
 * @tc.name: ClientMsgHandler_Test_010
 * @tc.desc: Test ClientMsgHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientMsgHandlerTest, ClientMsgHandler_Test_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientMsgHandler handler;
    MockUDSClient client;
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    int32_t result = handler.OnAnr(client, pkt);
    EXPECT_EQ(result, SHIELD_MODE::UNSET_MODE);
}

/**
 * @tc.name: ClientMsgHandler_Test_011
 * @tc.desc: Test ClientMsgHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientMsgHandlerTest, ClientMsgHandler_Test_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ClientMsgHandler handler;
    MockUDSClient client;
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    int32_t result = handler.OnAnr(client, pkt);
    EXPECT_EQ(result, SHIELD_MODE::UNSET_MODE);
}
} // namespace MMI
} // namespace OHOS