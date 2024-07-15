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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "anco_channel_stub.h"
#include "mock.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AncoChannelStubExTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;

class AncoChannelTest : public AncoChannelStub {
public:
    AncoChannelTest() = default;
    virtual ~AncoChannelTest() = default;

    int32_t SyncInputEvent(std::shared_ptr<PointerEvent> pointerEvent)
    {
        return 0;
    }
    int32_t SyncInputEvent(std::shared_ptr<KeyEvent> keyEvent)
    {
        return 0;
    }
    int32_t UpdateWindowInfo(std::shared_ptr<AncoWindows> windows)
    {
        return 0;
    }
};
} // namespace

class AncoChannelStubExTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    void SetUp() {}
    void TearDown() {}

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void AncoChannelStubExTest::SetUpTestCase(void)
{
    messageParcelMock_ = std::make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}
void AncoChannelStubExTest::TearDownTestCase()
{
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

/**
 * @tc.name: AncoChannelStubExTest_StubSyncPointerEvent
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AncoChannelStubExTest, AncoChannelStubExTest_StubSyncPointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadFromParcel(_)).WillRepeatedly(Return(false));
    std::shared_ptr<AncoChannelStub> ancoChannel = std::make_shared<AncoChannelTest>();
    ASSERT_NE(ancoChannel, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(ancoChannel->StubSyncPointerEvent(data, reply), RET_ERR);
}

/**
 * @tc.name: AncoChannelStubExTest_StubSyncPointerEvent_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AncoChannelStubExTest, AncoChannelStubExTest_StubSyncPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadFromParcel(_)).WillRepeatedly(Return(true));
    std::shared_ptr<AncoChannelStub> ancoChannel = std::make_shared<AncoChannelTest>();
    ASSERT_NE(ancoChannel, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(ancoChannel->StubSyncPointerEvent(data, reply), RET_ERR);
}

/**
 * @tc.name: AncoChannelStubExTest_StubSyncKeyEvent
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AncoChannelStubExTest, AncoChannelStubExTest_StubSyncKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadFromParcel(_)).WillRepeatedly(Return(false));
    std::shared_ptr<AncoChannelStub> ancoChannel = std::make_shared<AncoChannelTest>();
    ASSERT_NE(ancoChannel, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(ancoChannel->StubSyncKeyEvent(data, reply), RET_ERR);
}

/**
 * @tc.name: AncoChannelStubExTest_StubSyncKeyEvent_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AncoChannelStubExTest, AncoChannelStubExTest_StubSyncKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*messageParcelMock_, ReadFromParcel(_)).WillRepeatedly(Return(true));
    std::shared_ptr<AncoChannelStub> ancoChannel = std::make_shared<AncoChannelTest>();
    ASSERT_NE(ancoChannel, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(ancoChannel->StubSyncKeyEvent(data, reply), RET_ERR);
}

/**
 * @tc.name: AncoChannelStubExTest_StubUpdateWindowInfo
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AncoChannelStubExTest, AncoChannelStubExTest_StubUpdateWindowInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<AncoChannelStub> ancoChannel = std::make_shared<AncoChannelTest>();
    ASSERT_NE(ancoChannel, nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(ancoChannel->StubUpdateWindowInfo(data, reply), RET_ERR);
}
} // namespace MMI
} // namespace OHOS