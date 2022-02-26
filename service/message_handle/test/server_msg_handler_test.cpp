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

    int32_t OnRegisterAppInfoTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return OnRegisterAppInfo(sess, pkt);
    }

    int32_t OnRegisterMsgHandlerTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return OnRegisterMsgHandler(sess, pkt);
    }

    int32_t OnUnregisterMsgHandlerTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return OnUnregisterMsgHandler(sess, pkt);
    }
#ifdef  OHOS_BUILD_AI
    int32_t OnAiSensorInfoTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return OnSeniorInputFuncProc(sess, pkt);
    }
#endif
    int32_t OnListInjectTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return OnListInject(sess, pkt);
    }

#ifdef OHOS_BUILD_HDF
    int32_t OnHdiInjectTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return OnHdiInject(sess, pkt);
    }
#endif

    int32_t OnWindowsTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return OnWindow(sess, pkt);
    }

    int32_t OnDumpTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return OnDump(sess, pkt);
    }

    int32_t CheckReplyMessageFormClientTest(SessionPtr sess, OHOS::MMI::NetPacket& pkt)
    {
        return CheckReplyMessageFormClient(sess, pkt);
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
    SessionPtr sess;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnVirtualKeyEventTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnVirtualKeyEventTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterAppInfoTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnRegisterAppInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterAppInfoTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnRegisterAppInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterAppInfoTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnRegisterAppInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterAppInfoTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnRegisterAppInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterAppInfoTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnRegisterAppInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterAppInfoTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnRegisterAppInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterAppInfoTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnRegisterAppInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterAppInfoTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnRegisterAppInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterAppInfoTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnRegisterAppInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterAppInfoTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnRegisterAppInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterMsgHandlerTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnRegisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterMsgHandlerTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnRegisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterMsgHandlerTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnRegisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterMsgHandlerTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnRegisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterMsgHandlerTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnRegisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterMsgHandlerTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnRegisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterMsgHandlerTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnRegisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterMsgHandlerTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnRegisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterMsgHandlerTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnRegisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnRegisterMsgHandlerTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnRegisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnUnregisterMsgHandlerTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnUnregisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnUnregisterMsgHandlerTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnUnregisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnUnregisterMsgHandlerTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnUnregisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnUnregisterMsgHandlerTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnUnregisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnUnregisterMsgHandlerTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnUnregisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnUnregisterMsgHandlerTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnUnregisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnUnregisterMsgHandlerTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnUnregisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnUnregisterMsgHandlerTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnUnregisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnUnregisterMsgHandlerTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnUnregisterMsgHandlerTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnUnregisterMsgHandlerTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnUnregisterMsgHandlerTest(sess, pkt);
}
#ifdef  OHOS_BUILD_AI
HWTEST_F(ServerMsgHandlerTest, OnAiSensorInfoTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnAiSensorInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnAiSensorInfoTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnAiSensorInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnAiSensorInfoTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnAiSensorInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnAiSensorInfoTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnAiSensorInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnAiSensorInfoTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnAiSensorInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnAiSensorInfoTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnAiSensorInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnAiSensorInfoTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnAiSensorInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnAiSensorInfoTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnAiSensorInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnAiSensorInfoTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnAiSensorInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnAiSensorInfoTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnAiSensorInfoTest(sess, pkt);
}
#endif
HWTEST_F(ServerMsgHandlerTest, OnListInjectTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnListInjectTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnListInjectTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnListInjectTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnListInjectTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnListInjectTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnListInjectTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnListInjectTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnListInjectTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnListInjectTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnListInjectTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnListInjectTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnListInjectTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnListInjectTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnListInjectTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnListInjectTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnListInjectTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnListInjectTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnListInjectTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnListInjectTest(sess, pkt);
}


HWTEST_F(ServerMsgHandlerTest, OnWindowsTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnWindowsTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnWindowsTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnWindowsTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnWindowsTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnWindowsTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnWindowsTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnWindowsTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnWindowsTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnWindowsTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnWindowsTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnWindowsTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnWindowsTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnWindowsTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnWindowsTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnWindowsTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnWindowsTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnWindowsTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnWindowsTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnWindowsTest(sess, pkt);
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
    SessionPtr sess;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, OnDumpTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.OnDumpTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, CheckReplyMessageFormClientTest_01, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.CheckReplyMessageFormClientTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, CheckReplyMessageFormClientTest_02, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.CheckReplyMessageFormClientTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, CheckReplyMessageFormClientTest_03, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.CheckReplyMessageFormClientTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, CheckReplyMessageFormClientTest_04, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.CheckReplyMessageFormClientTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, CheckReplyMessageFormClientTest_05, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess = nullptr;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.CheckReplyMessageFormClientTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, CheckReplyMessageFormClientTest_06, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.CheckReplyMessageFormClientTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, CheckReplyMessageFormClientTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.CheckReplyMessageFormClientTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, CheckReplyMessageFormClientTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.CheckReplyMessageFormClientTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, CheckReplyMessageFormClientTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.CheckReplyMessageFormClientTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, CheckReplyMessageFormClientTest_010, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-10000));
    serverMsgHandlerTest.CheckReplyMessageFormClientTest(sess, pkt);
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
    SessionPtr sess;
    NetPacket pkt(MmiMessageId::INVALID);
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_07, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(-1));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_08, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(1));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}

HWTEST_F(ServerMsgHandlerTest, GetMultimodeInputInfoTest_09, TestSize.Level1)
{
    ServerMsgHandlerUnitTest serverMsgHandlerTest;
    SessionPtr sess;
    NetPacket pkt(static_cast<MmiMessageId>(10000));
    serverMsgHandlerTest.GetMultimodeInputInfoTest(sess, pkt);
}
} // namespace
