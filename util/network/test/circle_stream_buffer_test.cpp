/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "circle_stream_buffer.h"
#include "key_event_napi.h"
#include "stream_buffer.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class CircleStreamBufferTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name:CircleStreamBufferTest_CopyDataToBegin_001
 * @tc.desc:Test the funcation CopyDataToBegin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CircleStreamBufferTest, CircleStreamBufferTest_CopyDataToBegin_001, TestSize.Level1)
{
    CircleStreamBuffer circleStreamBuffer;
    StreamBuffer streamBuffer;
    streamBuffer.wPos_ = 10;
    streamBuffer.rPos_ = 5;
    ASSERT_NO_FATAL_FAILURE(circleStreamBuffer.CopyDataToBegin());
    streamBuffer.rPos_ = -5;
    ASSERT_NO_FATAL_FAILURE(circleStreamBuffer.CopyDataToBegin());
    streamBuffer.wPos_ = 5;
    streamBuffer.rPos_ = 10;
    ASSERT_NO_FATAL_FAILURE(circleStreamBuffer.CopyDataToBegin());
}

/**
 * @tc.name:CircleStreamBufferTest_CheckWrite_001
 * @tc.desc:Test the funcation CheckWrite
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CircleStreamBufferTest, CircleStreamBufferTest_CheckWrite_001, TestSize.Level1)
{
    CircleStreamBuffer circleStreamBuffer;
    StreamBuffer streamBuffer;
    size_t size = 4;
    streamBuffer.wPos_ = 20000;
    streamBuffer.rPos_ = 1;
    bool ret = circleStreamBuffer.CheckWrite(size);
    ASSERT_TRUE(ret);
    streamBuffer.rPos_ = -10;
    ret = circleStreamBuffer.CheckWrite(size);
    ASSERT_TRUE(ret);
    streamBuffer.wPos_ = 100;
    ret = circleStreamBuffer.CheckWrite(size);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name:CircleStreamBufferTest_Write_001
 * @tc.desc:Test the funcation Write
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CircleStreamBufferTest, CircleStreamBufferTest_Write_001, TestSize.Level1)
{
    CircleStreamBuffer circleStreamBuffer;
    StreamBuffer streamBuffer;
    const char *buf = "1234#";
    size_t size = 6;
    streamBuffer.wPos_ = 30000;
    streamBuffer.rPos_ = 8;
    bool ret = circleStreamBuffer.Write(buf, size);
    ASSERT_TRUE(ret);
    streamBuffer.rPos_ = -11;
    ret = circleStreamBuffer.Write(buf, size);
    ASSERT_TRUE(ret);
    streamBuffer.wPos_ = 200;
    ret = circleStreamBuffer.Write(buf, size);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name:CircleStreamBufferTest_CreateKeyEvent_001
 * @tc.desc:Test the funcation CreateKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CircleStreamBufferTest, CircleStreamBufferTest_CreateKeyEvent_001, TestSize.Level1)
{
    KeyEventNapi napi;
    napi_env env = nullptr;
    std::shared_ptr<KeyEvent> in = KeyEvent::Create();
    ASSERT_NE(in, nullptr);
    napi_value out = nullptr;
    napi_status status = napi.CreateKeyEvent(env, in, out);
    ASSERT_NE(status, napi_ok);
}

/**
 * @tc.name:CircleStreamBufferTest_GetKeyEvent_001
 * @tc.desc:Test the funcation GetKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CircleStreamBufferTest, CircleStreamBufferTest_GetKeyEvent_001, TestSize.Level1)
{
    KeyEventNapi napi;
    napi_env env = nullptr;
    napi_value in = nullptr;
    std::shared_ptr<KeyEvent> out = KeyEvent::Create();
    ASSERT_NE(out, nullptr);
    napi_status status = napi.GetKeyEvent(env, in, out);
    ASSERT_NE(status, napi_ok);
}

/**
 * @tc.name:CircleStreamBufferTest_CreateKeyItem_001
 * @tc.desc:Test the funcation CreateKeyItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CircleStreamBufferTest, CircleStreamBufferTest_CreateKeyItem_001, TestSize.Level1)
{
    KeyEventNapi napi;
    napi_env env = nullptr;
    KeyEvent::KeyItem item;
    std::optional<KeyEvent::KeyItem> in;
    item.SetKeyCode(2018);
    item.SetPressed(false);
    in.emplace(item);
    napi_value out = nullptr;
    napi_status status = napi.CreateKeyItem(env, in, out);
    ASSERT_NE(status, napi_ok);
}

/**
 * @tc.name:CircleStreamBufferTest_GetKeyItem_001
 * @tc.desc:Test the funcation GetKeyItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CircleStreamBufferTest, CircleStreamBufferTest_GetKeyItem_001, TestSize.Level1)
{
    KeyEventNapi napi;
    napi_env env = nullptr;
    napi_value in = nullptr;
    KeyEvent::KeyItem out;
    out.SetKeyCode(2024);
    out.SetPressed(false);
    napi_status status = napi.GetKeyItem(env, in, out);
    ASSERT_EQ(status, napi_ok);
}
} // namespace MMI
} // namespace OHOS
