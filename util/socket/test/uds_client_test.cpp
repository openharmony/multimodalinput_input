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

#include <future>

#include <gtest/gtest.h>

#include "uds_client.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class UDSClientTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class UDSClientUnitTest : public UDSClient {
public:
    void SetFd(int32_t fd)
    {
        fd_ = fd;
    }
    int32_t Socket()
    {
        return fd_;
    }
};

HWTEST_F(UDSClientTest, ConnectTo_01, TestSize.Level1)
{
    UDSClientUnitTest udsClient;
    int32_t retResult = udsClient.ConnectTo();
    ASSERT_EQ(RET_ERR, retResult);
}

HWTEST_F(UDSClientTest, ConnectTo_02, TestSize.Level1)
{
    UDSClientUnitTest udsClient;
    udsClient.SetFd(0);
    int32_t retResult = udsClient.ConnectTo();
    ASSERT_EQ(RET_OK, retResult);
}

HWTEST_F(UDSClientTest, SendMsg_001, TestSize.Level1)
{
    const char *buf = nullptr;
    size_t size = 0;

    UDSClientUnitTest udsClientUt;
    auto retResult = udsClientUt.SendMsg(buf, size);
    ASSERT_FALSE(retResult);
}

HWTEST_F(UDSClientTest, SendMsg_002, TestSize.Level1)
{
    const char *buf = "1234#";
    size_t size = 5;

    UDSClientUnitTest udsClientUt;
    auto retResult = udsClientUt.SendMsg(buf, size);
    ASSERT_FALSE(retResult);
}

HWTEST_F(UDSClientTest, SendMsg_type2_001, TestSize.Level1)
{
    NetPacket pkt(MmiMessageId::INVALID);

    UDSClientUnitTest udsClientUt;
    auto retResult = udsClientUt.SendMsg(pkt);
    ASSERT_FALSE(retResult);
}

HWTEST_F(UDSClientTest, SendMsg_type2_002, TestSize.Level1)
{
    NetPacket pkt(static_cast<MmiMessageId>(222));

    UDSClientUnitTest udsClientUt;
    auto retResult = udsClientUt.SendMsg(pkt);
    ASSERT_FALSE(retResult);
}

HWTEST_F(UDSClientTest, Stop_001, TestSize.Level1)
{
    UDSClientUnitTest udsClientUt;
    ASSERT_NO_FATAL_FAILURE(udsClientUt.Stop());
}

HWTEST_F(UDSClientTest, SendMsg_003, TestSize.Level1)
{
    const char *buf = "1234#";
    size_t size = 1025 * 8;

    UDSClientUnitTest udsClientUt;
    udsClientUt.SetFd(0);
    auto retResult = udsClientUt.SendMsg(buf, size);
    ASSERT_FALSE(retResult);
}

HWTEST_F(UDSClientTest, SendMsg_004, TestSize.Level1)
{
    const char *buf = "1234#";
    size_t size = 0;

    UDSClientUnitTest udsClientUt;
    udsClientUt.SetFd(0);
    auto retResult = udsClientUt.SendMsg(buf, size);
    ASSERT_FALSE(retResult);
}

HWTEST_F(UDSClientTest, SendMsg_005, TestSize.Level1)
{
    const char *buf = "1234#";
    size_t size = 8;

    UDSClientUnitTest udsClientUt;
    udsClientUt.SetFd(0);
    auto retResult = udsClientUt.SendMsg(buf, size);
    ASSERT_FALSE(retResult);
}

void StartClientTest(const UDSClient &udsClient, NetPacket &netPacket) {}

HWTEST_F(UDSClientTest, StartClient_001, TestSize.Level1)
{
    UDSClientUnitTest udsClientUt;
    udsClientUt.isRunning_ = true;
    udsClientUt.isConnected_ = false;
    MsgClientFunCallback fun = StartClientTest;
    ASSERT_NO_FATAL_FAILURE(udsClientUt.StartClient(fun));
}

HWTEST_F(UDSClientTest, StartClient_002, TestSize.Level1)
{
    UDSClientUnitTest udsClientUt;
    udsClientUt.isRunning_ = false;
    udsClientUt.isConnected_ = true;
    MsgClientFunCallback fun = StartClientTest;
    ASSERT_NO_FATAL_FAILURE(udsClientUt.StartClient(fun));
}
} // namespace MMI
} // namespace OHOS
