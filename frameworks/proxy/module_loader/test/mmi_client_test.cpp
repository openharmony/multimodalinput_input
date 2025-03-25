/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "mmi_client.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MMIClientTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class MMIClientTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

ConnectCallback connectFun;

/**
 * @tc.name: RegisterConnectedFunction
 * @tc.desc: Verify register connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, RegisterConnectedFunction, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIClient mmiClient;
    ASSERT_NO_FATAL_FAILURE(mmiClient.RegisterConnectedFunction(connectFun));
}

/**
 * @tc.name: RegisterDisconnectedFunction
 * @tc.desc: Verify register disconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, RegisterDisconnectedFunction, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIClient mmiClient;
    ASSERT_NO_FATAL_FAILURE(mmiClient.RegisterDisconnectedFunction(connectFun));
}

/**
 * @tc.name: KeyCommandHandlerTest_Start_001
 * @tc.desc: Create a connection to server
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, MMIClientTest_Start__001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MMIClient> client = std::make_shared<MMIClient>();
    EXPECT_TRUE(client->Start());
    client->Stop();
}

/**
 * @tc.name: KeyCommandHandlerTest_GetCurrentConnectedStatus_001
 * @tc.desc: Get current connection status
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, MMIClientTest_GetCurrentConnectedStatus__001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MMIClient> client = std::make_shared<MMIClient>();
    client->Start();
    EXPECT_TRUE(client->GetCurrentConnectedStatus());
    client->Stop();
}

/**
 * @tc.name: KeyCommandHandlerTest_Reconnect_001
 * @tc.desc: Socket reconnection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, MMIClientTest_Reconnect_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MMIClient> client = std::make_shared<MMIClient>();
    client->Start();
    EXPECT_FALSE(client->Reconnect());
    client->Stop();
}

/**
 * @tc.name: KeyCommandHandlerTest_OnDisconnect_001
 * @tc.desc: Disconnected from server
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, MMIClientTest_OnDisconnect_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MMIClient> client = std::make_shared<MMIClient>();
    client->Start();
    client->OnDisconnect();
    ASSERT_NO_FATAL_FAILURE(client->OnDisconnect());
    client->Stop();
}

/**
 * @tc.name: MMIClientTest_StartEventRunner_001
 * @tc.desc: Start event runner
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, MMIClientTest_StartEventRunner_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MMIClient> client = std::make_shared<MMIClient>();
    client->isConnected_ = true;
    client->fd_ = 1;
    client->eventHandler_ = nullptr;
    bool result = client->StartEventRunner();
    EXPECT_TRUE(result);
}
}
} // namespace MMI
