/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "net_packet.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
class NetPacketTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(NetPacketTest, construct_001, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pack(idMsg);
}

HWTEST_F(NetPacketTest, construct_002, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pack(idMsg);
    NetPacket packTmp(pack);
}

HWTEST_F(NetPacketTest, construct_003, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(-2002);
    NetPacket pack(idMsg);
    NetPacket packTmp(pack);
}

HWTEST_F(NetPacketTest, GetSize_001, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pack(idMsg);
    size_t retResult = pack.GetSize();
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(NetPacketTest, GetSize_002, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(-1001);
    NetPacket pack(idMsg);
    size_t retResult = pack.GetSize();
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(NetPacketTest, GetSize_003, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(65535);
    NetPacket pack(idMsg);
    size_t retResult = pack.GetSize();
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(NetPacketTest, GetData_001, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pack(idMsg);
    const char *retResult = pack.GetData();
    EXPECT_TRUE(retResult != nullptr);
}

HWTEST_F(NetPacketTest, GetData_002, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(-3003);

    NetPacket pack(idMsg);
    const char *retResult = pack.GetData();
    EXPECT_TRUE(retResult != nullptr);
}

HWTEST_F(NetPacketTest, GetData_003, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(65535);

    NetPacket pack(idMsg);
    const char *retResult = pack.GetData();
    EXPECT_TRUE(retResult != nullptr);
}

HWTEST_F(NetPacketTest, GetMsgId_001, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(22);

    NetPacket pack(idMsg);
    const MmiMessageId retResult = pack.GetMsgId();
    EXPECT_TRUE(retResult == idMsg);
}

HWTEST_F(NetPacketTest, GetMsgId_002, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(-33);

    NetPacket pack(idMsg);
    const MmiMessageId retResult = pack.GetMsgId();
    EXPECT_TRUE(retResult == idMsg);
}

HWTEST_F(NetPacketTest, GetMsgId_003, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(65535);

    NetPacket pack(idMsg);
    const MmiMessageId retResult = pack.GetMsgId();
    EXPECT_TRUE(retResult == idMsg);
}
} // namespace
