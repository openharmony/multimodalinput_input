/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "mmi_client.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
} // namespace

class MMIClientTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class MMIClientUnitTest : public MMIClient {
public:
    void OnDisconnectedUnitTest()
    {
        OnDisconnected();
    }
    void OnConnectedUnitTest()
    {
        OnConnected();
    }
};

MMIClient mmiClient;
ConnectCallback connectFun;

/**
 * @tc.name:RegisterConnectedFunction
 * @tc.desc:Verify register connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, RegisterConnectedFunction, TestSize.Level1)
{
    mmiClient.RegisterConnectedFunction(connectFun);
}

/**
 * @tc.name:RegisterConnectedFunction
 * @tc.desc:Verify register disconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, RegisterDisconnectedFunction, TestSize.Level1)
{
    mmiClient.RegisterDisconnectedFunction(connectFun);
}

/**
 * @tc.name:VirtualKeyIn
 * @tc.desc:Verify virtual key in
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, VirtualKeyIn, TestSize.Level1)
{
    RawInputEvent virtualKeyEvent = {};
    mmiClient.VirtualKeyIn(virtualKeyEvent);
}

/**
 * @tc.name:ReplyMessageToServer_001
 * @tc.desc:Verify reply message to server
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, ReplyMessageToServer_001, TestSize.Level1)
{
    int64_t serverStartTime = 1;
    int64_t clientEndTime = 1;

    mmiClient.ReplyMessageToServer(static_cast<MmiMessageId>(4), serverStartTime, clientEndTime);
}

/**
 * @tc.name:ReplyMessageToServer_002
 * @tc.desc:Verify reply message to server
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, ReplyMessageToServer_002, TestSize.Level1)
{
    int64_t serverStartTime = 0;
    int64_t clientEndTime = 0;

    mmiClient.ReplyMessageToServer(static_cast<MmiMessageId>(3), serverStartTime, clientEndTime);
}

/**
 * @tc.name:SdkGetMultimodeInputInfo
 * @tc.desc:Verify get multimodal input info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, SdkGetMultimodeInputInfo, TestSize.Level1)
{
    mmiClient.SdkGetMultimodeInputInfo();
}

MMIClientUnitTest mmiClientTest;
/**
 * @tc.name:Re_RegisterConnectedFunction
 * @tc.desc:Verify register connetct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_RegisterConnectedFunction, TestSize.Level1)
{
    mmiClientTest.RegisterConnectedFunction(connectFun);
}

/**
 * @tc.name:Re_RegisterDisconnectedFunction
 * @tc.desc:Verify register disconnetct
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_RegisterDisconnectedFunction, TestSize.Level1)
{
    mmiClientTest.RegisterDisconnectedFunction(connectFun);
}

/**
 * @tc.name:Re_VirtualKeyIn
 * @tc.desc:Verify virtual key in
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_VirtualKeyIn, TestSize.Level1)
{
    RawInputEvent virtualKeyEvent = {};
    mmiClientTest.VirtualKeyIn(virtualKeyEvent);
}

/**
 * @tc.name:Re_ReplyMessageToServer_001
 * @tc.desc:Verify reply message to server
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_ReplyMessageToServer_001, TestSize.Level1)
{
    int64_t serverStartTime = 1;
    int64_t clientEndTime = 1;

    mmiClientTest.ReplyMessageToServer(static_cast<MmiMessageId>(1), serverStartTime, clientEndTime);
}

/**
 * @tc.name:Re_ReplyMessageToServer_002
 * @tc.desc:Verify reply message to server
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_ReplyMessageToServer_002, TestSize.Level1)
{
    int64_t serverStartTime = 0;
    int64_t clientEndTime = 0;

    mmiClientTest.ReplyMessageToServer(static_cast<MmiMessageId>(2), serverStartTime, clientEndTime);
}

/**
 * @tc.name:Re_SdkGetMultimodeInputInfo
 * @tc.desc:Verify get multimodal input info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_SdkGetMultimodeInputInfo, TestSize.Level1)
{
    mmiClientTest.SdkGetMultimodeInputInfo();
}

/**
 * @tc.name:Re_OnConnected
 * @tc.desc:Verify connnected unit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_OnConnected, TestSize.Level1)
{
    mmiClientTest.OnConnectedUnitTest();
}

/**
 * @tc.name:Re_OnConnected_002
 * @tc.desc:Verify connnected unit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_OnConnected_002, TestSize.Level1)
{
    ConnectCallback funTmp;
    mmiClientTest.RegisterConnectedFunction(funTmp);
    mmiClientTest.OnConnectedUnitTest();
}

/**
 * @tc.name:Re_OnDisconnected
 * @tc.desc:Verify disconnnected unit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_OnDisconnected, TestSize.Level1)
{
    mmiClientTest.OnDisconnectedUnitTest();
}

/**
 * @tc.name:Re_OnDisconnected_002
 * @tc.desc:Verify disconnnected unit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIClientTest, Re_OnDisconnected_002, TestSize.Level1)
{
    ConnectCallback funTmp;
    mmiClientTest.RegisterDisconnectedFunction(funTmp);
    mmiClientTest.OnDisconnectedUnitTest();
}
} // namespace MMI
} // namespace OHOS
