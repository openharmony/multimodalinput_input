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
 * @tc.desc: Test IsExtendedFunctionKeyCode with KEYCODE_EXT_FN_MIN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyCode001, TestSize.Level1)
{
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_EXT_FN_MIN));
}

/**
 * @tc.name: TestExtendedFunctionKeyCode002
 * @tc.desc: Test IsExtendedFunctionKeyCode with regular key codes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyCode002, TestSize.Level1)
{
    // Test common keys
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_A));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_0));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_F1));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_ENTER));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_UNKNOWN));

    // Test special keys
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_HOME));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_BACK));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_POWER));
}

/**
 * @tc.name: TestExtendedFunctionKeyCode003
 * @tc.desc: Test IsExtendedFunctionKeyCode with boundary values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyCode003, TestSize.Level1)
{
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_EXT_FN_MIN));  // 16777216
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_EXT_FN_MAX));    // 33554431

    // Test near boundaries
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(16777215));   // Just before range
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(33554432));   // Just after range
}

/**
 * @tc.name: TestExtendedFunctionKeyCode004
 * @tc.desc: Test IsExtendedFunctionKeyCode with extreme values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyCode004, TestSize.Level1)
{
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(INT32_MIN));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(INT32_MAX));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(0));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(-1));
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
    EXPECT_EQ(KeyEvent::KEYCODE_EXT_FN_MIN, 16777216);
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
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(10013));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(20000));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(32768));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(50000));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(16777215));
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
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(16777216));  // Start (KEYCODE_EXT_FN_MIN)
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(25165823));  // Middle
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(33554431));  // End (KEYCODE_EXT_FN_MAX)

    // Verify sample keys in reserved range are identified
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(20000000));
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(25000000));
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(30000000));
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
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(0x01000000));  // Fourth byte = 0x01
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(0x01FFFFFF));  // Fourth byte = 0x01
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(0x02000000)); // Fourth byte = 0x02
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(0x03000000)); // Fourth byte = 0x03
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(0xFF000000)); // Fourth byte = 0xFF
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
    EXPECT_EQ(KeyEvent::KEYCODE_EXT_FN_MAX - KeyEvent::KEYCODE_EXT_FN_MIN, 16777215);

    // Test that keys outside reserved range are not identified
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_EXT_FN_MIN - 1));
    EXPECT_FALSE(KeyEvent::IsExtendedFunctionKeyCode(KeyEvent::KEYCODE_EXT_FN_MAX + 1));
}

/**
 * @tc.name: TestExtendedFunctionKeyExpandedCapacity001
 * @tc.desc: Test expanded capacity of extended function keys (16777216 keys)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventExtendedFunctionTest, TestExtendedFunctionKeyExpandedCapacity001, TestSize.Level1)
{
    // Verify the expanded capacity: 16777216 keys (16777216 to 33554431)
    EXPECT_EQ(KeyEvent::KEYCODE_EXT_FN_MAX - KeyEvent::KEYCODE_EXT_FN_MIN, 16777215);

    // Test keys at various positions in the expanded range
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(20000000));  // Low-mid range
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(25000000));  // Mid range
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(30000000));  // High-mid range
    EXPECT_TRUE(KeyEvent::IsExtendedFunctionKeyCode(33554431));  // Maximum value
}
