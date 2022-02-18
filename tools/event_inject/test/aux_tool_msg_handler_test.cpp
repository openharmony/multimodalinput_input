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

#include "test_aux_tool_msg_handler.h"
#include <gtest/gtest.h>
#include "proto.h"

#if BINDER_TODO
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;

class AuxToolMsgHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(AuxToolMsgHandlerTest, Init_001, TestSize.Level1)
{
    TestAuxToolMsgHandler auxObj;
    bool retResult = auxObj.Init();
    EXPECT_TRUE(retResult);
}

HWTEST_F(AuxToolMsgHandlerTest, OnMsgHandler_001, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::INVALID;
    UDSClient client;
    NetPacket newPacket(idMsg);

    TestAuxToolMsgHandler auxObj;
    auxObj.OnMsgHandler(client, newPacket);
}

HWTEST_F(AuxToolMsgHandlerTest, OnMsgHandler_002, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::REGISTER_APP_INFO;
    UDSClient client;
    NetPacket newPacket(idMsg);

    TestAuxToolMsgHandler auxObj;
    auxObj.OnMsgHandler(client, newPacket);
}

HWTEST_F(AuxToolMsgHandlerTest, OnMsgHandler_003, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::REGISTER_MSG_HANDLER;
    UDSClient client;
    NetPacket newPacket(idMsg);

    TestAuxToolMsgHandler auxObj;
    auxObj.OnMsgHandler(client, newPacket);
}

HWTEST_F(AuxToolMsgHandlerTest, OnAiServerReply_001, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::INVALID;
    UDSClient client;
    NetPacket newPacket(idMsg);

    TestAuxToolMsgHandler auxObj;
    int32_t retResult = auxObj.OnAiServerReply(client, newPacket);
    EXPECT_EQ(RET_OK, retResult);
}

HWTEST_F(AuxToolMsgHandlerTest, OnAiServerReply_002, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::INVALID;
    int32_t replyCode = RET_ERR;

    UDSClient client;
    NetPacket newPacket(idMsg);
    newPacket << replyCode;

    TestAuxToolMsgHandler auxObj;
    int32_t retResult = auxObj.OnAiServerReply(client, newPacket);
    EXPECT_EQ(RET_ERR, retResult);
}
} // namespace
#endif
