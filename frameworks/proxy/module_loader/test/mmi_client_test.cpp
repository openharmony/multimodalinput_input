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

#include "mmi_client.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

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

HWTEST_F(MMIClientTest, RegisterConnectedFunction, TestSize.Level1)
{
    mmiClient.RegisterConnectedFunction(connectFun);
}

HWTEST_F(MMIClientTest, RegisterDisconnectedFunction, TestSize.Level1)
{
    mmiClient.RegisterDisconnectedFunction(connectFun);
}

HWTEST_F(MMIClientTest, VirtualKeyIn, TestSize.Level1)
{
    RawInputEvent virtualKeyEvent = {};
    mmiClient.VirtualKeyIn(virtualKeyEvent);
}

HWTEST_F(MMIClientTest, ReplyMessageToServer_001, TestSize.Level1)
{
    int64_t serverStartTime = 1;
    int64_t clientEndTime = 1;

    mmiClient.ReplyMessageToServer(static_cast<MmiMessageId>(4), serverStartTime, clientEndTime);
}

HWTEST_F(MMIClientTest, ReplyMessageToServer_002, TestSize.Level1)
{
    int64_t serverStartTime = 0;
    int64_t clientEndTime = 0;

    mmiClient.ReplyMessageToServer(static_cast<MmiMessageId>(3), serverStartTime, clientEndTime);
}

HWTEST_F(MMIClientTest, SdkGetMultimodeInputInfo, TestSize.Level1)
{
    mmiClient.SdkGetMultimodeInputInfo();
}

MMIClientUnitTest mmiClientTest;
HWTEST_F(MMIClientTest, Re_RegisterConnectedFunction, TestSize.Level1)
{
    mmiClientTest.RegisterConnectedFunction(connectFun);
}

HWTEST_F(MMIClientTest, Re_RegisterDisconnectedFunction, TestSize.Level1)
{
    mmiClientTest.RegisterDisconnectedFunction(connectFun);
}

HWTEST_F(MMIClientTest, Re_VirtualKeyIn, TestSize.Level1)
{
    RawInputEvent virtualKeyEvent = {};
    mmiClientTest.VirtualKeyIn(virtualKeyEvent);
}

HWTEST_F(MMIClientTest, Re_ReplyMessageToServer_001, TestSize.Level1)
{
    int64_t serverStartTime = 1;
    int64_t clientEndTime = 1;

    mmiClientTest.ReplyMessageToServer(static_cast<MmiMessageId>(1), serverStartTime, clientEndTime);
}

HWTEST_F(MMIClientTest, Re_ReplyMessageToServer_002, TestSize.Level1)
{
    int64_t serverStartTime = 0;
    int64_t clientEndTime = 0;

    mmiClientTest.ReplyMessageToServer(static_cast<MmiMessageId>(2), serverStartTime, clientEndTime);
}

HWTEST_F(MMIClientTest, Re_SdkGetMultimodeInputInfo, TestSize.Level1)
{
    mmiClientTest.SdkGetMultimodeInputInfo();
}

HWTEST_F(MMIClientTest, Re_OnConnected, TestSize.Level1)
{
    mmiClientTest.OnConnectedUnitTest();
}
HWTEST_F(MMIClientTest, Re_OnConnected_002, TestSize.Level1)
{
    ConnectCallback funTmp;
    mmiClientTest.RegisterConnectedFunction(funTmp);
    mmiClientTest.OnConnectedUnitTest();
}

HWTEST_F(MMIClientTest, Re_OnDisconnected, TestSize.Level1)
{
    mmiClientTest.OnDisconnectedUnitTest();
}

HWTEST_F(MMIClientTest, Re_OnDisconnected_002, TestSize.Level1)
{
    ConnectCallback funTmp;
    mmiClientTest.RegisterDisconnectedFunction(funTmp);
    mmiClientTest.OnDisconnectedUnitTest();
}
} // namespace
