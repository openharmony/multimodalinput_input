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
} // namespace MMI
} // namespace OHOS