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
    NetPacket pkt(idMsg);
}

HWTEST_F(NetPacketTest, construct_002, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    NetPacket packTmp(pkt);
}

HWTEST_F(NetPacketTest, construct_003, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(-2002);
    NetPacket pkt(idMsg);
    NetPacket packTmp(pkt);
}

HWTEST_F(NetPacketTest, GetSize_001, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    size_t retResult = pkt.GetSize();
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(NetPacketTest, GetSize_002, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(-1001);
    NetPacket pkt(idMsg);
    size_t retResult = pkt.GetSize();
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(NetPacketTest, GetSize_003, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(65535);
    NetPacket pkt(idMsg);
    size_t retResult = pkt.GetSize();
    EXPECT_TRUE(retResult == 0);
}

HWTEST_F(NetPacketTest, GetData_001, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    const char *retResult = pkt.GetData();
    EXPECT_TRUE(retResult != nullptr);
}

HWTEST_F(NetPacketTest, GetData_002, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(-3003);

    NetPacket pkt(idMsg);
    const char *retResult = pkt.GetData();
    EXPECT_TRUE(retResult != nullptr);
}

HWTEST_F(NetPacketTest, GetData_003, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(65535);

    NetPacket pkt(idMsg);
    const char *retResult = pkt.GetData();
    EXPECT_TRUE(retResult != nullptr);
}

HWTEST_F(NetPacketTest, GetMsgId_001, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(22);

    NetPacket pkt(idMsg);
    const MmiMessageId retResult = pkt.GetMsgId();
    EXPECT_TRUE(retResult == idMsg);
}

HWTEST_F(NetPacketTest, GetMsgId_002, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(-33);

    NetPacket pkt(idMsg);
    const MmiMessageId retResult = pkt.GetMsgId();
    EXPECT_TRUE(retResult == idMsg);
}

HWTEST_F(NetPacketTest, GetMsgId_003, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(65535);

    NetPacket pkt(idMsg);
    const MmiMessageId retResult = pkt.GetMsgId();
    EXPECT_TRUE(retResult == idMsg);
}

HWTEST_F(NetPacketTest, ReadAndWrite, TestSize.Level1)
{
    int32_t p1 = 112;
    std::string p2 = "test111";
    NetPacket pkt(MmiMessageId::REGISTER_APP_INFO);
    pkt << p1 << p2;

    int32_t r1 = 0;
    std::string r2;
    pkt >> r1 >> r2;
    EXPECT_EQ(p1, r1);
    EXPECT_EQ(p2, r2);
}

HWTEST_F(NetPacketTest, WriteError, TestSize.Level1)
{
    int32_t p1 = 112;
    std::string p2 = "test111";
    struct TestData {
        int32_t xx;
        char szTest[MAX_STREAM_BUF_SIZE];
    };
    TestData data = {333, "test111"};
    NetPacket pkt(MmiMessageId::REGISTER_APP_INFO);
    pkt << p1 << p2;
    EXPECT_FALSE(pkt.ChkError());
    pkt << data;
    EXPECT_TRUE(pkt.ChkError());
}

HWTEST_F(NetPacketTest, ReadError, TestSize.Level1)
{
    int32_t p1 = 112;
    std::string p2 = "test111";
    NetPacket pkt(MmiMessageId::REGISTER_APP_INFO);
    pkt << p1 << p2;
    EXPECT_FALSE(pkt.ChkError());
    
    int32_t r1 = 0;
    std::string r2;
    pkt >> r1 >> r2;
    EXPECT_FALSE(pkt.ChkError());
    EXPECT_EQ(p1, r1);
    EXPECT_EQ(p2, r2);
    int32_t r3;
    pkt >> r3;
    EXPECT_TRUE(pkt.ChkError());
}
} // namespace
