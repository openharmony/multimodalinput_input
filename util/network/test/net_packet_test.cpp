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

#include <gtest/gtest.h>

#include "net_packet.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class NetPacketTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:construct_002
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, GetSize_001, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    NetPacket packTmp(pkt);
    size_t retResult = pkt.GetSize();
    EXPECT_TRUE(retResult == 0);
}

/**
 * @tc.name:construct_002
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, GetSize_002, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(-1001);
    NetPacket pkt(idMsg);
    NetPacket packTmp(pkt);
    size_t retResult = pkt.GetSize();
    EXPECT_TRUE(retResult == 0);
}

/**
 * @tc.name:construct_002
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, GetSize_003, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(65535);
    NetPacket pkt(idMsg);
    NetPacket packTmp(pkt);
    size_t retResult = pkt.GetSize();
    EXPECT_TRUE(retResult == 0);
}

/**
 * @tc.name:construct_002
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, GetData_001, TestSize.Level1)
{
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    NetPacket packTmp(pkt);
    const char *retResult = pkt.GetData();
    EXPECT_TRUE(retResult != nullptr);
}

/**
 * @tc.name:construct_002
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, GetData_002, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(-3003);
    NetPacket pkt(idMsg);
    NetPacket packTmp(pkt);
    const char *retResult = pkt.GetData();
    EXPECT_TRUE(retResult != nullptr);
}

/**
 * @tc.name:construct_002
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, GetData_003, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(65535);

    NetPacket pkt(idMsg);
    NetPacket packTmp(pkt);
    const char *retResult = pkt.GetData();
    EXPECT_TRUE(retResult != nullptr);
}

/**
 * @tc.name:construct_002
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, GetMsgId_001, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(22);

    NetPacket pkt(idMsg);
    NetPacket packTmp(pkt);
    const MmiMessageId retResult = pkt.GetMsgId();
    EXPECT_TRUE(retResult == idMsg);
}

/**
 * @tc.name:construct_002
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, GetMsgId_002, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(-33);

    NetPacket pkt(idMsg);
    NetPacket packTmp(pkt);
    const MmiMessageId retResult = pkt.GetMsgId();
    EXPECT_TRUE(retResult == idMsg);
}

/**
 * @tc.name:construct_002
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, GetMsgId_003, TestSize.Level1)
{
    MmiMessageId idMsg = static_cast<MmiMessageId>(65535);

    NetPacket pkt(idMsg);
    NetPacket packTmp(pkt);
    const MmiMessageId retResult = pkt.GetMsgId();
    EXPECT_TRUE(retResult == idMsg);
}

/**
 * @tc.name:construct_002
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, ReadAndWrite, TestSize.Level1)
{
    int32_t p1 = 112;
    std::string p2 = "test111";
    NetPacket pkt(MmiMessageId::INVALID);
    pkt << p1 << p2;

    int32_t r1 = 0;
    std::string r2;
    pkt >> r1 >> r2;
    EXPECT_EQ(p1, r1);
    EXPECT_EQ(p2, r2);
}

/**
 * @tc.name:construct_002
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, WriteError, TestSize.Level1)
{
    int32_t p1 = 112;
    std::string p2 = "test111";
    NetPacket pkt(MmiMessageId::INVALID);
    pkt << p1 << p2;
    EXPECT_FALSE(pkt.ChkRWError());
    struct TestData {
        int32_t xx;
        char szTest[MAX_STREAM_BUF_SIZE];
    };
    TestData data = { 333, "test111" };
    pkt << data;
    EXPECT_TRUE(pkt.ChkRWError());
}

/**
 * @tc.name:construct_002
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, ReadError, TestSize.Level1)
{
    int32_t p1 = 112;
    std::string p2 = "test111";
    NetPacket pkt(MmiMessageId::INVALID);
    pkt << p1 << p2;
    EXPECT_FALSE(pkt.ChkRWError());

    int32_t r1 = 0;
    std::string r2;
    pkt >> r1 >> r2;
    EXPECT_FALSE(pkt.ChkRWError());
    EXPECT_EQ(p1, r1);
    EXPECT_EQ(p2, r2);
    int32_t r3;
    pkt >> r3;
    EXPECT_TRUE(pkt.ChkRWError());
}


/**
 * @tc.name:construct_005
 * @tc.desc:Verify net packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NetPacketTest, GetMsgId_005, TestSize.Level1)
{

MmiMessageId idMsg = static_cast(12345);

NetPacket pkt(idMsg);
NetPacket packTmp = pkt;
const MmiMessageId retResult = packTmp.GetMsgId();
EXPECT_TRUE(retResult == idMsg);
}
} // namespace MMI
} // namespace OHOS
