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
constexpr int64_t TEST_KEY_DOWN_TIME { 100 };

std::shared_ptr<KeyEvent> CreateKeyEventForExtTest()
{
    auto keyEvent = KeyEvent::Create();
    if (keyEvent == nullptr) {
        return nullptr;
    }
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    item.SetDownTime(TEST_KEY_DOWN_TIME);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    return keyEvent;
}

void CheckDefaultKeyEventExt(const std::shared_ptr<KeyEvent> keyEvent)
{
    ASSERT_NE(keyEvent, nullptr);
    EXPECT_EQ(keyEvent->GetRawCode(), -1);
    EXPECT_EQ(keyEvent->GetRepeatCount(), 0);
    auto item = keyEvent->GetKeyItem(KeyEvent::KEYCODE_A);
    ASSERT_TRUE(item.has_value());
    EXPECT_EQ(item->GetRawCode(), -1);
}
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
    ASSERT_EQ(ret, RET_OK);
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
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
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
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
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
    std::shared_ptr<SwitchEvent> switchEvent = std::make_shared<SwitchEvent>(0);
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

/**
 * @tc.name: KeyEventExtToNetPacket
 * @tc.desc: Test key event extension serialization
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, KeyEventExtToNetPacket, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetRawCode(30);
    keyEvent->SetRepeatCount(2);

    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    item.SetDownTime(TEST_KEY_DOWN_TIME);
    item.SetPressed(true);
    item.SetRawCode(30);
    keyEvent->AddKeyItem(item);

    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    ASSERT_EQ(InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt), RET_OK);
    ASSERT_EQ(InputEventDataTransformation::WriteKeyEventExt(keyEvent, pkt), RET_OK);

    auto outEvent = KeyEvent::Create();
    ASSERT_NE(outEvent, nullptr);
    ASSERT_EQ(InputEventDataTransformation::NetPacketToKeyEvent(pkt, outEvent), RET_OK);
    ASSERT_EQ(InputEventDataTransformation::ReadKeyEventExt(pkt, outEvent), RET_OK);
    EXPECT_EQ(outEvent->GetRawCode(), 30);
    EXPECT_EQ(outEvent->GetRepeatCount(), 2);
    auto outItem = outEvent->GetKeyItem(KeyEvent::KEYCODE_A);
    ASSERT_TRUE(outItem.has_value());
    EXPECT_EQ(outItem->GetRawCode(), 30);
}

/**
 * @tc.name: KeyEventExtToNetPacketWithoutTail
 * @tc.desc: Test key event extension defaults for old packets
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, KeyEventExtToNetPacketWithoutTail, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);

    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_A);
    item.SetDownTime(TEST_KEY_DOWN_TIME);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);

    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    ASSERT_EQ(InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt), RET_OK);

    auto outEvent = KeyEvent::Create();
    ASSERT_NE(outEvent, nullptr);
    ASSERT_EQ(InputEventDataTransformation::NetPacketToKeyEvent(pkt, outEvent), RET_OK);
    ASSERT_EQ(InputEventDataTransformation::ReadKeyEventExt(pkt, outEvent), RET_OK);
    EXPECT_EQ(outEvent->GetRawCode(), -1);
    EXPECT_EQ(outEvent->GetRepeatCount(), 0);
}

/**
 * @tc.name: KeyEventExtToNetPacketWithShortTail
 * @tc.desc: Test key event extension rejects a truncated extension tail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, KeyEventExtToNetPacketWithShortTail, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = CreateKeyEventForExtTest();
    ASSERT_NE(keyEvent, nullptr);

    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    ASSERT_EQ(InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt), RET_OK);
    pkt << 30;

    auto outEvent = KeyEvent::Create();
    ASSERT_NE(outEvent, nullptr);
    ASSERT_EQ(InputEventDataTransformation::NetPacketToKeyEvent(pkt, outEvent), RET_OK);
    EXPECT_EQ(InputEventDataTransformation::ReadKeyEventExt(pkt, outEvent), RET_ERR);
    CheckDefaultKeyEventExt(outEvent);
}

/**
 * @tc.name: KeyEventExtToNetPacketWithNegativeRawCodeCount
 * @tc.desc: Test key event extension rejects negative key item rawCode count
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, KeyEventExtToNetPacketWithNegativeRawCodeCount, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = CreateKeyEventForExtTest();
    ASSERT_NE(keyEvent, nullptr);

    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    ASSERT_EQ(InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt), RET_OK);
    pkt << 30 << -1 << 0;

    auto outEvent = KeyEvent::Create();
    ASSERT_NE(outEvent, nullptr);
    ASSERT_EQ(InputEventDataTransformation::NetPacketToKeyEvent(pkt, outEvent), RET_OK);
    EXPECT_EQ(InputEventDataTransformation::ReadKeyEventExt(pkt, outEvent), RET_ERR);
    CheckDefaultKeyEventExt(outEvent);
}

/**
 * @tc.name: KeyEventExtToNetPacketWithTooManyRawCodes
 * @tc.desc: Test key event extension rejects rawCode count greater than key item count
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, KeyEventExtToNetPacketWithTooManyRawCodes, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = CreateKeyEventForExtTest();
    ASSERT_NE(keyEvent, nullptr);

    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    ASSERT_EQ(InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt), RET_OK);
    pkt << 30 << 2 << 0;

    auto outEvent = KeyEvent::Create();
    ASSERT_NE(outEvent, nullptr);
    ASSERT_EQ(InputEventDataTransformation::NetPacketToKeyEvent(pkt, outEvent), RET_OK);
    EXPECT_EQ(InputEventDataTransformation::ReadKeyEventExt(pkt, outEvent), RET_ERR);
    CheckDefaultKeyEventExt(outEvent);
}

/**
 * @tc.name: KeyEventExtToNetPacketWithInsufficientRawCodeData
 * @tc.desc: Test key event extension rejects missing key item rawCode or repeatCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventDataTransformationTest, KeyEventExtToNetPacketWithInsufficientRawCodeData, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = CreateKeyEventForExtTest();
    ASSERT_NE(keyEvent, nullptr);

    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    ASSERT_EQ(InputEventDataTransformation::KeyEventToNetPacket(keyEvent, pkt), RET_OK);
    pkt << 30 << 1 << 30;

    auto outEvent = KeyEvent::Create();
    ASSERT_NE(outEvent, nullptr);
    ASSERT_EQ(InputEventDataTransformation::NetPacketToKeyEvent(pkt, outEvent), RET_OK);
    EXPECT_EQ(InputEventDataTransformation::ReadKeyEventExt(pkt, outEvent), RET_ERR);
    CheckDefaultKeyEventExt(outEvent);
}
} // namespace MMI
} // namespace OHOS
