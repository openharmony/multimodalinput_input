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

#include "stream_buffer.h"


namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS::MMI;
} // namespace

class StreamBufferTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class StreamBufferUnitTest : public StreamBuffer {
public:
    const char *ReadBufUnitTest() const
    {
        return ReadBuf();
    }
    const char *WriteBufUnitTest() const
    {
        return WriteBuf();
    }
    bool CloneUnitTest(const StreamBuffer& buf)
    {
        return Clone(buf);
    }
};

/**
 * @tc.name:construct_001
 * @tc.desc:Verify stream buffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, construct_001, TestSize.Level1)
{
    StreamBuffer bufObj;
}

/**
 * @tc.name:construct_002
 * @tc.desc:Verify stream buffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, construct_002, TestSize.Level1)
{
    StreamBuffer bufObj;
    StreamBuffer bufObjTmp(bufObj);
}

/**
 * @tc.name:read_Type1_001
 * @tc.desc:Verify stream buffer read
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, read_Type1_001, TestSize.Level1)
{
    char buf[] = "";
    size_t size = 4;

    StreamBuffer bufObj;
    bool retResult = bufObj.Read(buf, size);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name:read_Type1_002
 * @tc.desc:Verify stream buffer read
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, read_Type1_002, TestSize.Level1)
{
    char buf[] = "1234";
    size_t size = 4;

    StreamBuffer bufObj;
    bool retResult = bufObj.Read(buf, size);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name:read_Type2_001
 * @tc.desc:Verify stream buffer read
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest,  read_Type2_001, TestSize.Level1)
{
    std::string buf = "";

    StreamBuffer bufObj;
    bool retResult = bufObj.Read(buf);
    ASSERT_FALSE(retResult);
}

/**
 * @tc.name:read_Type2_002
 * @tc.desc:Verify stream buffer read
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, read_Type2_002, TestSize.Level1)
{
    std::string buf = "Stream Data";

    StreamBuffer bufObj;
    bool retResult = bufObj.Read(buf);
    ASSERT_FALSE(retResult);
}

/**
 * @tc.name:read_Type3_001
 * @tc.desc:Verify stream buffer read
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest,  read_Type3_001, TestSize.Level1)
{
    StreamBuffer buf;

    StreamBuffer bufObj;
    bool retResult = bufObj.Read(buf);
    ASSERT_FALSE(retResult);
}

/**
 * @tc.name:write_Type1_001
 * @tc.desc:Verify stream buffer write
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, write_Type1_001, TestSize.Level1)
{
    std::string buf;

    StreamBuffer streamBuffer;
    bool retResult = streamBuffer.Write(buf);
    ASSERT_TRUE(retResult);
}

/**
 * @tc.name:write_Type1_002
 * @tc.desc:Verify stream buffer write
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, write_Type1_002, TestSize.Level1)
{
    std::string buf = "stream data";

    StreamBuffer streamBuffer;
    bool retResult = streamBuffer.Write(buf);
    ASSERT_TRUE(retResult);
}

/**
 * @tc.name:write_Type2_001
 * @tc.desc:Verify stream buffer write
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, write_Type2_001, TestSize.Level1)
{
    StreamBuffer buf;

    StreamBuffer streamBuffer;
    bool retResult = streamBuffer.Write(buf);
    ASSERT_FALSE(retResult);
}

/**
 * @tc.name:write_Type3_001
 * @tc.desc:Verify stream buffer write
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, write_Type3_001, TestSize.Level1)
{
    char buf[100];
    size_t size = 0;

    StreamBuffer streamBuffer;
    bool retResult = streamBuffer.Write(buf, size);
    EXPECT_FALSE(retResult);
}

/**
 * @tc.name:write_Type3_002
 * @tc.desc:Verify stream buffer write
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, write_Type3_002, TestSize.Level1)
{
    char buf[100] = "stream data type3 001";
    size_t size = 10;

    StreamBuffer streamBuffer;
    bool retResult = streamBuffer.Write(buf, size);
    EXPECT_TRUE(retResult);
}

/**
 * @tc.name:Data
 * @tc.desc:Verify stream buffer data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, Data, TestSize.Level1)
{
    StreamBuffer bufObj;
    const char *retResult = bufObj.Data();
    EXPECT_TRUE(retResult);
}

/**
 * @tc.name:Size_001
 * @tc.desc:Verify stream buffer size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, Size_001, TestSize.Level1)
{
    StreamBuffer streamBuffer;
    streamBuffer.Size();
}

/**
 * @tc.name:operatorLeft
 * @tc.desc:Verify stream buffer operator left
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, operatorLeft, TestSize.Level1)
{
    int32_t val = 111;
    StreamBuffer streamBufferSrc;
    streamBufferSrc << val;
}

/**
 * @tc.name:operatorRight
 * @tc.desc:Verify stream buffer operator right
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, operatorRight, TestSize.Level1)
{
    int32_t val = 111;
    StreamBuffer streamBufferSrc;
    streamBufferSrc << val;
    streamBufferSrc >> val;
}

/**
 * @tc.name:ReadBuf
 * @tc.desc:Verify stream buffer read buffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, ReadBuf, TestSize.Level1)
{
    StreamBufferUnitTest bufObj;
    const char *retResult = bufObj.ReadBufUnitTest();
    EXPECT_NE(retResult, nullptr);
}

/**
 * @tc.name:WriteBuf
 * @tc.desc:Verify stream buffer write buffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, WriteBuf, TestSize.Level1)
{
    StreamBufferUnitTest bufObj;
    const char *retResult = bufObj.WriteBufUnitTest();
    EXPECT_NE(retResult, nullptr);
}

/**
 * @tc.name:Clone
 * @tc.desc:Verify stream buffer clone
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(StreamBufferTest, Clone, TestSize.Level1)
{
    const StreamBuffer buf;

    StreamBufferUnitTest bufObj;
    bool retResult = bufObj.CloneUnitTest(buf);
    EXPECT_FALSE(retResult);
}
} // namespace MMI
} // namespace OHOS
