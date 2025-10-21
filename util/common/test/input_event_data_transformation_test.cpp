/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "input_event_data_transformation.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace OHOS;
} // namespace

class InputEventDataTransformationTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: UnmarshallingEnhanceData_001
 * @tc.desc: Test UnmarshallingEnhanceData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, UnmarshallingEnhanceData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    pkt << InputEventDataTransformation::MAX_HMAC_SIZE + 1;
    int32_t ret = InputEventDataTransformation::UnmarshallingEnhanceData(pkt, keyEvent);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: UnmarshallingEnhanceData_002
 * @tc.desc: Test UnmarshallingEnhanceData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, UnmarshallingEnhanceData_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    pkt << InputEventDataTransformation::MAX_HMAC_SIZE;
    int32_t ret = InputEventDataTransformation::UnmarshallingEnhanceData(pkt, keyEvent);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: UnmarshallingEnhanceData_003
 * @tc.desc: Test UnmarshallingEnhanceData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, UnmarshallingEnhanceData_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    pkt << 0;
    int32_t ret = InputEventDataTransformation::UnmarshallingEnhanceData(pkt, keyEvent);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MarshallingEnhanceData_001
 * @tc.desc: Test MarshallingEnhanceData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, MarshallingEnhanceData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    pkt << InputEventDataTransformation::MAX_HMAC_SIZE + 1;
    int32_t ret = InputEventDataTransformation::MarshallingEnhanceData(pointerEvent, pkt);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MarshallingEnhanceData_002
 * @tc.desc: Test MarshallingEnhanceData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, MarshallingEnhanceData_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    pkt << 0;
    int32_t ret = InputEventDataTransformation::MarshallingEnhanceData(keyEvent, pkt);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SwitchEventToNetPacket
 * @tc.desc: Test SwitchEventToNetPacket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, SwitchEventToNetPacket, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr switchEvent = std::make_shared(0);
    ASSERT_NE(switchEvent, nullptr);

    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    pkt << 0;
    auto ret = InputEventDataTransformation::SwitchEventToNetPacket(switchEvent, pkt);
    ASSERT_EQ(ret, RET_OK);
    ret = InputEventDataTransformation::NetPacketToSwitchEvent(pkt, switchEvent);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: LongPressEventToNetPacket
 * @tc.desc: Test LongPressEventToNetPacket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, LongPressEventToNetPacket, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LongPressEvent longPressEvent = {
    .fingerCount = 1,
    .duration = 1000,
    .pid = 1,
    .displayId = 0,
    .displayX = 100,
    .displayY = 200,
    .result = 0,
    .windowId = 123,
    .pointerId = 456,
    .downTime = 789,
    .bundleName = "com.example.bundle"
    };
    NetPacket pkt(MmiMessageId::ON_SUBSCRIBE_SWITCH);
    auto ret = InputEventDataTransformation::LongPressEventToNetPacket(longPressEvent, pkt);
    ASSERT_EQ(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS