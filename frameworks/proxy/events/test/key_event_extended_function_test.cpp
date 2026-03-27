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
#include "key_event.h"

using namespace OHOS::MMI;

class KeyEventExtendedFunctionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void KeyEventExtendedFunctionTest::SetUpTestCase() {}
void KeyEventExtendedFunctionTest::TearDownTestCase() {}
void KeyEventExtendedFunctionTest::SetUp() {}
void KeyEventExtendedFunctionTest::TearDown() {}

/**
 * @tc.name: TestExtendedFunctionKeyCode001
 * @tc.desc: Test IsExtendedFunctionKey with KEYCODE_EXT_FN_MIN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyCode001, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_EXT_FN_MIN);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());
}

/**
 * @tc.name: TestExtendedFunctionKeyCode002
 * @tc.desc: Test IsExtendedFunctionKey with regular key codes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyCode002, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    // Test common keys
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_0);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_F1);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_ENTER);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_UNKNOWN);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());

    // Test special keys
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_HOME);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_BACK);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_POWER);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
}

/**
 * @tc.name: TestExtendedFunctionKeyCode003
 * @tc.desc: Test IsExtendedFunctionKeyCode with boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyCode003, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_EXT_FN_MIN);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());  // 0x01000000
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_EXT_FN_MAX);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());  // 0x01FFFFFF

    // Test near boundaries
    // 16777215 = 0x00FFFFFF, Just before KEYCODE_EXT_FN_MIN
    int32_t keyJustBelowExtFnMin = 16777215;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyJustBelowExtFnMin);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    // 33554432 = 0x02000000, Just after KEYCODE_EXT_FN_MAX
    int32_t keyJustAboveExtFnMax = 33554432;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyJustAboveExtFnMax);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
}

/**
 * @tc.name: TestExtendedFunctionKeyCode004
 * @tc.desc: Test IsExtendedFunctionKeyCode with extreme values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyCode004, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(INT32_MIN);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(INT32_MAX);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(0);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(-1);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
}

/**
 * @tc.name: TestExtendedFunctionKeyEvent001
 * @tc.desc: Test KeyEvent::IsExtendedFunctionKey method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyEvent001, TestSize.Level1)
{
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_EXT_FN_MIN);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());

    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
}

/**
 * @tc.name: TestExtendedFunctionKeyMask001
 * @tc.desc: Test extended function key mask value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyMask001, TestSize.Level1)
{
    EXPECT_EQ(KeyEvent::EXTENDED_FUNCTION_KEY_MASK, 0x00FF0000);
    EXPECT_EQ(KeyEvent::EXTENDED_FUNCTION_KEY_FLAG, 0x00010000);
}

/**
 * @tc.name: TestExtendedFunctionKeyValues001
 * @tc.desc: Test extended function key constant values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyValues001, TestSize.Level1)
{
    // KEYCODE_EXT_FN_MIN = 16777216 (0x01000000), minimum extended function key value
    EXPECT_EQ(KeyEvent::KEYCODE_EXT_FN_MIN, 16777216);
    // KEYCODE_EXT_FN_MAX = 33554431 (0x01FFFFFF), maximum extended function key value
    EXPECT_EQ(KeyEvent::KEYCODE_EXT_FN_MAX, 33554431);
}

/**
 * @tc.name: TestExtendedFunctionKeyBitOperation001
 * @tc.desc: Test bit operation for extended function key detection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyBitOperation001, TestSize.Level1)
{
    int32_t extKey = KeyEvent::KEYCODE_EXT_FN_MIN;

    // Test mask operation
    EXPECT_EQ(extKey & KeyEvent::EXTENDED_FUNCTION_KEY_MASK, KeyEvent::EXTENDED_FUNCTION_KEY_FLAG);

    // Test non-extended key
    int32_t regularKey = KeyEvent::KEYCODE_A;
    EXPECT_NE(regularKey & KeyEvent::EXTENDED_FUNCTION_KEY_MASK, KeyEvent::EXTENDED_FUNCTION_KEY_FLAG);

    // Test with key in buffer zone
    // 10012 = KEYCODE_FLOATING_BACK, Maximum existing key code before extended function range
    int32_t maxExistingKey = 10012;  // KEYCODE_FLOATING_BACK
    EXPECT_NE(maxExistingKey & KeyEvent::EXTENDED_FUNCTION_KEY_MASK, KeyEvent::EXTENDED_FUNCTION_KEY_FLAG);
}

/**
 * @tc.name: TestExtendedFunctionKeySafetyBuffer001
 * @tc.desc: Test safety buffer between existing keys and extended keys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeySafetyBuffer001, TestSize.Level1)
{
    // Test keys in the safety buffer (10013 - 16777215)
    // These keys are between existing max key (10012) and extended function range start (16777216)
    // All have fourth byte = 0x00, so they are not extended function keys
    // 10013 = 0x0000271D, First key in safety buffer, below extended range
    int32_t keyInBuffer1 = 10013;  // 0x0000271D, Below extended range
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyInBuffer1);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    // 20000 = 0x00004E20, In safety buffer, below extended range
    int32_t keyInBuffer2 = 20000;  // 0x00004E20, Below extended range
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyInBuffer2);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    // 32768 = 0x00008000, In safety buffer, below extended range
    int32_t keyInBuffer3 = 32768;  // 0x00008000, Below extended range
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyInBuffer3);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    // 50000 = 0x0000C350, In safety buffer, below extended range
    int32_t keyInBuffer4 = 50000;  // 0x0000C350, Below extended range
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyInBuffer4);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    // 16777215 = 0x00FFFFFF, Last key in safety buffer, just before extended range
    int32_t keyJustBeforeExtFnMin = 16777215;  // 0x00FFFFFF, Just before extended range
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyJustBeforeExtFnMin);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
}

/**
 * @tc.name: TestExtendedFunctionKeyFullRange001
 * @tc.desc: Test extended function key detection across full reserved range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyFullRange001, TestSize.Level1)
{
    // Test start, middle, and end of reserved range
    // All have fourth byte = 0x01, so they are extended function keys
    // 16777216 = 0x01000000, Start of extended function range (KEYCODE_EXT_FN_MIN)
    int32_t extFnMinKey = 16777216;  // 0x01000000, Start (KEYCODE_EXT_FN_MIN)
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(extFnMinKey);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());
    // 25165823 = 0x01802007, Middle of range
    int32_t extFnMidKey = 25165823;  // 0x01802007, Middle of range
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(extFnMidKey);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());
    // 33554431 = 0x01FFFFFF, End of extended function range (KEYCODE_EXT_FN_MAX)
    int32_t extFnMaxKey = 33554431;  // 0x01FFFFFF, End (KEYCODE_EXT_FN_MAX)
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(extFnMaxKey);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());

    // Verify sample keys in reserved range are identified
    // 20000000 = 0x01312D00, In range
    int32_t extFnSampleKey1 = 20000000;  // 0x01312D00, In range
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(extFnSampleKey1);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());
    // 25000000 = 0x017D7840, In range
    int32_t extFnSampleKey2 = 25000000;  // 0x017D7840, In range
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(extFnSampleKey2);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());
    // 30000000 = 0x01C9C340, In range
    int32_t extFnSampleKey3 = 30000000;  // 0x01C9C340, In range
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(extFnSampleKey3);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());
}

/**
 * @tc.name: TestExtendedFunctionKeyFourthByte001
 * @tc.desc: Test that fourth byte (bits 24-31) is correctly identified
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyFourthByte001, TestSize.Level1)
{
    // Test keys with different fourth byte values
    // Extended function keys are identified by fourth byte = 0x01 (mask: 0xFF000000, flag: 0x01000000)
    // 0x01000000 = 16777216, Fourth byte = 0x01, matches flag
    int32_t fourthByte01_min = 0x01000000;  // Fourth byte = 0x01, matches flag
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(fourthByte01_min);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());
    // 0x01FFFFFF = 33554431, Fourth byte = 0x01, matches flag
    int32_t fourthByte01_max = 0x01FFFFFF;  // Fourth byte = 0x01, matches flag
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(fourthByte01_max);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());
    // 0x02000000 = 33554432, Fourth byte = 0x02, doesn't match flag
    int32_t fourthByte02 = 0x02000000;  // Fourth byte = 0x02, doesn't match flag
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(fourthByte02);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    // 0x03000000 = 50331648, Fourth byte = 0x03, doesn't match flag
    int32_t fourthByte03 = 0x03000000;  // Fourth byte = 0x03, doesn't match flag
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(fourthByte03);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    // 0xFF000000 = -16777216, Fourth byte = 0xFF, doesn't match flag
    int32_t fourthByteFF = 0xFF000000;  // Fourth byte = 0xFF, doesn't match flag
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(fourthByteFF);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
}

/**
 * @tc.name: TestExtendedFunctionKeyReservedRange001
 * @tc.desc: Test reserved range boundaries and extensibility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyReservedRange001, TestSize.Level1)
{
    // Verify the reserved range is properly defined
    EXPECT_LT(KeyEvent::KEYCODE_EXT_FN_MIN, KeyEvent::KEYCODE_EXT_FN_MAX);
    // Calculate available keys in extended function range: 33554431 - 16777216 = 16777215
    // Total of 16777216 keys available (0x01000000 to 0x01FFFFFF)
    // 16777215 = 0x00FFFFFF, Number of keys between MIN and MAX
    int32_t extFnRangeSize = 16777215;  // 0x00FFFFFF, Total keys available minus 1
    EXPECT_EQ(KeyEvent::KEYCODE_EXT_FN_MAX - KeyEvent::KEYCODE_EXT_FN_MIN, extFnRangeSize);

    // Test that keys outside reserved range are not identified
    // 16777215 = 0x00FFFFFF, Just before KEYCODE_EXT_FN_MIN
    int32_t keyBelowExtFnMin = KeyEvent::KEYCODE_EXT_FN_MIN - 1;  // 0x00FFFFFF, Just before MIN
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyBelowExtFnMin);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
    // 33554432 = 0x02000000, Just after KEYCODE_EXT_FN_MAX
    int32_t keyAboveExtFnMax = KeyEvent::KEYCODE_EXT_FN_MAX + 1;  // 0x02000000, Just after MAX
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(keyAboveExtFnMax);
    EXPECT_FALSE(keyEvent->IsExtendedFunctionKey());
}

/**
 * @tc.name: TestExtendedFunctionKeyExpandedCapacity001
 * @tc.desc: Test expanded capacity of extended function keys (16777216 keys: 0x01000000-0x01FFFFFF)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyExpandedCapacity001, TestSize.Level1)
{
    // Verify the expanded capacity: 16777216 keys total (0x01000000 to 0x01FFFFFF)
    // This provides much more space compared to the previous third-byte design (65,536 keys)
    // Calculate available keys in extended function range: 33554431 - 16777216 = 16777215
    // Total of 16777216 keys available (0x01000000 to 0x01FFFFFF)
    // 16777215 = 0x00FFFFFF, Number of keys between MIN and MAX
    int32_t extFnRangeSize = 16777215;  // 0x00FFFFFF, Total keys available minus 1
    EXPECT_EQ(KeyEvent::KEYCODE_EXT_FN_MAX - KeyEvent::KEYCODE_EXT_FN_MIN, extFnRangeSize);

    // Test keys at various positions in the expanded range
    // 20000000 = 0x01312D00, Low-mid range
    int32_t expandedRangeLowMid = 20000000;  // 0x01312D00, Low-mid range
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(expandedRangeLowMid);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());
    // 25000000 = 0x017D7840, Mid range
    int32_t expandedRangeMid = 25000000;  // 0x017D7840, Mid range
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(expandedRangeMid);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());
    // 30000000 = 0x01C9C340, High-mid range
    int32_t expandedRangeHighMid = 30000000;  // 0x01C9C340, High-mid range
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(expandedRangeHighMid);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());
    // 33554431 = 0x01FFFFFF, Maximum value (KEYCODE_EXT_FN_MAX)
    int32_t expandedRangeMax = 33554431;  // 0x01FFFFFF, Maximum value (KEYCODE_EXT_FN_MAX)
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(expandedRangeMax);
    EXPECT_TRUE(keyEvent->IsExtendedFunctionKey());
}
