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

#include "server_msg_handler.h"


namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class ServerMsgHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class ServerMsgHandlerUnitTest : public ServerMsgHandler {
public:
    int32_t OnVirtualKeyEventTest(SessionPtr sess, NetPacket& pkt)
    {
        return OnVirtualKeyEvent(sess, pkt);
    }

#ifdef OHOS_BUILD_HDF
    int32_t OnHdiInjectTest(SessionPtr sess, NetPacket& pkt)
    {
        return OnHdiInject(sess, pkt);
    }
#endif

    int32_t OnDumpTest(SessionPtr sess, NetPacket& pkt)
    {
        return OnDump(sess, pkt);
    }

    int32_t GetMultimodeInputInfoTest(SessionPtr sess, NetPacket& pkt)
    {
        return GetMultimodeInputInfo(sess, pkt);
    }

    int32_t OnInjectKeyEventTest(SessionPtr sess, NetPacket pkt)
    {
        int32_t retResult = OnInjectKeyEvent(sess, pkt);
        return retResult;
    }
};

/**
 * @tc.name:OnVirtualKeyEventTest_01
 * @tc.desc:Verify virtual key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

/**
 * @tc.name:OnVirtualKeyEventTest_02
 * @tc.desc:Verify virtual key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

/**
 * @tc.name:OnVirtualKeyEventTest_03
 * @tc.desc:Verify virtual key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

/**
 * @tc.name:OnVirtualKeyEventTest_04
 * @tc.desc:Verify virtual key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

/**
 * @tc.name:OnVirtualKeyEventTest_05
 * @tc.desc:Verify virtual key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

/**
 * @tc.name:OnVirtualKeyEventTest_06
 * @tc.desc:Verify virtual key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

/**
 * @tc.name:OnVirtualKeyEventTest_07
 * @tc.desc:Verify virtual key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

/**
 * @tc.name:OnVirtualKeyEventTest_08
 * @tc.desc:Verify virtual key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

/**
 * @tc.name:OnVirtualKeyEventTest_09
 * @tc.desc:Verify virtual key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

/**
 * @tc.name:OnVirtualKeyEventTest_010
 * @tc.desc:Verify virtual key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

/**
 * @tc.name:OnDumpTest_01
 * @tc.desc:Verify dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnDumpTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

/**
 * @tc.name:OnDumpTest_02
 * @tc.desc:Verify dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnDumpTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

/**
 * @tc.name:OnDumpTest_03
 * @tc.desc:Verify dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnDumpTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

/**
 * @tc.name:OnDumpTest_04
 * @tc.desc:Verify dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnDumpTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

/**
 * @tc.name:OnDumpTest_05
 * @tc.desc:Verify dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnDumpTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

/**
 * @tc.name:OnDumpTest_06
 * @tc.desc:Verify dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnDumpTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

/**
 * @tc.name:OnDumpTest_07
 * @tc.desc:Verify dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnDumpTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

/**
 * @tc.name:OnDumpTest_08
 * @tc.desc:Verify dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnDumpTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

/**
 * @tc.name:OnDumpTest_09
 * @tc.desc:Verify dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnDumpTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

/**
 * @tc.name:OnDumpTest_010
 * @tc.desc:Verify dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, OnDumpTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

/**
 * @tc.name:GetMultimodeInputInfoTest_01
 * @tc.desc:Verify getmultimodal input info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

/**
 * @tc.name:GetMultimodeInputInfoTest_02
 * @tc.desc:Verify getmultimodal input info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

/**
 * @tc.name:GetMultimodeInputInfoTest_03
 * @tc.desc:Verify getmultimodal input info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

/**
 * @tc.name:GetMultimodeInputInfoTest_04
 * @tc.desc:Verify getmultimodal input info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

/**
 * @tc.name:GetMultimodeInputInfoTest_05
 * @tc.desc:Verify getmultimodal input info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

/**
 * @tc.name:GetMultimodeInputInfoTest_06
 * @tc.desc:Verify getmultimodal input info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

/**
 * @tc.name:GetMultimodeInputInfoTest_07
 * @tc.desc:Verify getmultimodal input info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

/**
 * @tc.name:GetMultimodeInputInfoTest_08
 * @tc.desc:Verify getmultimodal input info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

/**
 * @tc.name:GetMultimodeInputInfoTest_09
 * @tc.desc:Verify getmultimodal input info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}
} // namespace MMI
} // namespace OHOS
