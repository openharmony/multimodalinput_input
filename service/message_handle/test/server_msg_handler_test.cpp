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

#include "server_msg_handler.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

class ServerMsgHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class ServerMsgHandlerUnitTest : public ServerMsgHandler {
public:
    int32_t OnVirtualKeyEventTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return OnVirtualKeyEvent(sess, pkt);
    }

#ifdef OHOS_BUILD_HDF
    int32_t OnHdiInjectTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return OnHdiInject(sess, pkt);
    }
#endif

    int32_t OnDumpTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return OnDump(sess, pkt);
    }

    int32_t GetMultimodeInputInfoTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return GetMultimodeInputInfo(sess, pkt);
    }

    int32_t OnInjectKeyEventTest(SessionPtr sess, OHOS::MMI::NetPacket pkt)
    {
        int32_t retResult = OnInjectKeyEvent(sess, pkt);
        return retResult;
    }
};

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}
} // namespace
