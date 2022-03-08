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

#include "uds_client.h"
#include <future>
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

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

    bool StartClientTestUnitTest(MsgClientFunCallback fun)
    {
        auto retResult = StartClient(fun, true);
        return retResult;
    }

    void OnRecvTestUnitTest(const char *buf, size_t size)
    {
        OnRecv(buf, size);
    }

    void OnEventUnitTest(const struct epoll_event& ev, StreamBuffer& buf)
    {
        OnEvent(ev, buf);
    }

    void OnThreadUnitTest()
    {
        OnThread();
    }
};

#if BINDER_TODO
HWTEST_F(UDSClientTest, ConnectTo_02, TestSize.Level1)
{
    int32_t retResult;
    const char *path = "1234";
    bool isBind = false;

    UDSClient udsClient;
    retResult = udsClient.ConnectTo(path, isBind);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSClientTest, ConnectTo_03, TestSize.Level1)
{
    int32_t retResult;
    const char *path = "568*";
    bool isBind = true;

    UDSClient udsClient;
    retResult = udsClient.ConnectTo(path, isBind);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSClientTest, ConnectTo_04, TestSize.Level1)
{
    int32_t retResult;
    const char *path = "./";
    bool isBind = true;

    UDSClient udsClient;
    retResult = udsClient.ConnectTo(path, isBind);
    ASSERT_EQ(-1, retResult);
}

HWTEST_F(UDSClientTest, SendMsg_001, TestSize.Level1)
{
    const char *buf = nullptr;
    size_t size = 0;

    UDSClientUnitTest udsClientUt;
    udsClientUt.SetFd(0);

    UDSClient udsClient;
    auto retResult = udsClient.SendMsg(buf, size);
    ASSERT_EQ(0, retResult);
}

HWTEST_F(UDSClientTest, SendMsg_002, TestSize.Level1)
{
    const char *buf = "1234#";
    size_t size = 5;

    UDSClientUnitTest udsClientUt;
    udsClientUt.SetFd(0);

    UDSClient udsClient;
    auto retResult = udsClient.SendMsg(buf, size);
    ASSERT_EQ(0, retResult);
}

HWTEST_F(UDSClientTest, SendMsg_003, TestSize.Level1)
{
    const char *buf = "1234";
    size_t size = 4;

    UDSClientUnitTest udsClientUt;
    udsClientUt.SetFd(0);

    UDSClient udsClient;
    auto retResult = udsClient.SendMsg(buf, size);
    ASSERT_EQ(0, retResult);
}

HWTEST_F(UDSClientTest, SendMsg_004, TestSize.Level1)
{
    const char *buf = "1234&";
    size_t size = 5;

    UDSClientUnitTest udsClientUt;
    udsClientUt.SetFd(0);

    UDSClient udsClient;
    auto retResult = udsClient.SendMsg(buf, size);
    ASSERT_EQ(0, retResult);
}

HWTEST_F(UDSClientTest, SendMsg_005, TestSize.Level1)
{
    const char *buf = "Arg_012,@#$";
    size_t size = 11;

    UDSClientUnitTest udsClientUt;
    udsClientUt.SetFd(0);

    UDSClient udsClient;
    auto retResult = udsClient.SendMsg(buf, size);
    ASSERT_EQ(0, retResult);
}

HWTEST_F(UDSClientTest, SendMsg_006, TestSize.Level1)
{
    const char *buf = "Arg_012,@#$435";
    size_t size = 14;

    UDSClientUnitTest udsClientUt;
    udsClientUt.SetFd(0);

    UDSClient udsClient;
    auto retResult = udsClient.SendMsg(buf, size);
    ASSERT_EQ(0, retResult);
}

HWTEST_F(UDSClientTest, SendMsg_type2_001, TestSize.Level1)
{
    OHOS::MMI::NetPacket pkt(MmiMessageId::INVALID);

    UDSClient udsClient;
    auto retResult = udsClient.SendMsg(pkt);
    EXPECT_EQ(0, retResult);
}

HWTEST_F(UDSClientTest, SendMsg_type2_002, TestSize.Level1)
{
    OHOS::MMI::NetPacket pkt(static_cast<MmiMessageId>(222));

    UDSClient udsClient;
    auto retResult = udsClient.SendMsg(pkt);
    EXPECT_EQ(0, retResult);
}

HWTEST_F(UDSClientTest, OnRecv_001, TestSize.Level1)
{
    const char *buf = nullptr;
    size_t size = 0;
    UDSClientUnitTest udsClientUt;
    udsClientUt.OnRecvTestUnitTest(buf, size);
}

HWTEST_F(UDSClientTest, OnRecv_002, TestSize.Level1)
{
    const char *buf = "3333&";
    size_t size = 0;
    UDSClientUnitTest udsClientUt;
    udsClientUt.OnRecvTestUnitTest(buf, size);
}

HWTEST_F(UDSClientTest, OnRecv_003, TestSize.Level1)
{
    const char *buf = "1234";
    size_t size = 3;
    UDSClientUnitTest udsClientUt;
    udsClientUt.OnRecvTestUnitTest(buf, size);
}

HWTEST_F(UDSClientTest, Stop_001, TestSize.Level1)
{
    UDSClient udsClient;
    udsClient.Stop();
}

HWTEST_F(UDSClientTest, OnEvent, TestSize.Level1)
{
    struct epoll_event ev = {};
    StreamBuffer buf;

    UDSClientUnitTest udsClientUt;
    udsClientUt.OnEventUnitTest(ev, buf);
}

HWTEST_F(UDSClientTest, OnThread, TestSize.Level1)
{
    UDSClientUnitTest udsClientUt;
    udsClientUt.OnThreadUnitTest();
}
#endif
} // namespace
