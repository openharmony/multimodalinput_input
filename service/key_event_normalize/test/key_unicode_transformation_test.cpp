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

#include <cstdio>

#include <gtest/gtest.h>

#include "key_unicode_transformation.h"
#include "key_event.h"
#include "hos_key_event.h"


#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyUnicodeTransformationTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class KeyUnicodeTransformationTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(){};
    void TearDown(){};
};

struct KeyUnicode {
    uint32_t original { 0 };
    uint32_t transitioned { 0 };
};
constexpr uint32_t DEFAULT_UNICODE = 0x0000;
const std::map<int32_t, KeyUnicode> KEY_UNICODE_TRANSFORMATION = {
    { HOS_KEY_A,                { 0x0061, 0x0041 } },
    { HOS_KEY_B,                { 0x0062, 0x0042 } },
    { HOS_KEY_C,                { 0x0063, 0x0043 } },
    { HOS_KEY_D,                { 0x0064, 0x0044 } },
    { HOS_KEY_E,                { 0x0065, 0x0045 } },
    { HOS_KEY_F,                { 0x0066, 0x0046 } },
    { HOS_KEY_G,                { 0x0067, 0x0047 } },
    { HOS_KEY_H,                { 0x0068, 0x0048 } },
    { HOS_KEY_I,                { 0x0069, 0x0049 } },
    { HOS_KEY_J,                { 0x006A, 0x004A } },
    { HOS_KEY_K,                { 0x006B, 0x004B } },
    { HOS_KEY_L,                { 0x006C, 0x004C } },
    { HOS_KEY_M,                { 0x006D, 0x004D } },
    { HOS_KEY_N,                { 0x006E, 0x004E } },
    { HOS_KEY_O,                { 0x006F, 0x004F } },
    { HOS_KEY_P,                { 0x0070, 0x0050 } },
    { HOS_KEY_Q,                { 0x0071, 0x0051 } },
    { HOS_KEY_R,                { 0x0072, 0x0052 } },
    { HOS_KEY_S,                { 0x0073, 0x0053 } },
    { HOS_KEY_T,                { 0x0074, 0x0054 } },
    { HOS_KEY_U,                { 0x0075, 0x0055 } },
    { HOS_KEY_V,                { 0x0076, 0x0056 } },
    { HOS_KEY_W,                { 0x0077, 0x0057 } },
    { HOS_KEY_X,                { 0x0078, 0x0058 } },
    { HOS_KEY_Y,                { 0x0079, 0x0059 } },
    { HOS_KEY_Z,                { 0x007A, 0x005A } },
    { HOS_KEY_0,                { 0x0030, 0x0029 } },
    { HOS_KEY_1,                { 0x0031, 0x0021 } },
    { HOS_KEY_2,                { 0x0032, 0x0040 } },
    { HOS_KEY_3,                { 0x0033, 0x0023 } },
    { HOS_KEY_4,                { 0x0034, 0x0024 } },
    { HOS_KEY_5,                { 0x0035, 0x0025 } },
    { HOS_KEY_6,                { 0x0036, 0x005E } },
    { HOS_KEY_7,                { 0x0037, 0x0026 } },
    { HOS_KEY_8,                { 0x0038, 0x002A } },
    { HOS_KEY_9,                { 0x0039, 0x0028 } },
    { HOS_KEY_GRAVE,            { 0x0060, 0x007E } },
    { HOS_KEY_MINUS,            { 0x002D, 0x005F } },
    { HOS_KEY_EQUALS,           { 0x002B, 0x003D } },
    { HOS_KEY_LEFT_BRACKET,     { 0x005B, 0x007B } },
    { HOS_KEY_RIGHT_BRACKET,    { 0x005D, 0x007D } },
    { HOS_KEY_BACKSLASH,        { 0x005C, 0x007C } },
    { HOS_KEY_SEMICOLON,        { 0x003B, 0x003A } },
    { HOS_KEY_APOSTROPHE,       { 0x0027, 0x0022 } },
    { HOS_KEY_SLASH,            { 0x002F, 0x003F } },
    { HOS_KEY_COMMA,            { 0x002C, 0x003C } },
    { HOS_KEY_PERIOD,           { 0x002E, 0x003E } },
    { HOS_KEY_NUMPAD_0,         { 0x0030, 0x0000 } },
    { HOS_KEY_NUMPAD_1,         { 0x0031, 0x0000 } },
    { HOS_KEY_NUMPAD_2,         { 0x0032, 0x0000 } },
    { HOS_KEY_NUMPAD_3,         { 0x0033, 0x0000 } },
    { HOS_KEY_NUMPAD_4,         { 0x0034, 0x0000 } },
    { HOS_KEY_NUMPAD_5,         { 0x0035, 0x0000 } },
    { HOS_KEY_NUMPAD_6,         { 0x0036, 0x0000 } },
    { HOS_KEY_NUMPAD_7,         { 0x0037, 0x0000 } },
    { HOS_KEY_NUMPAD_8,         { 0x0038, 0x0000 } },
    { HOS_KEY_NUMPAD_9,         { 0x0039, 0x0000 } },
    { HOS_KEY_NUMPAD_DIVIDE,    { 0x002F, 0x0000 } },
    { HOS_KEY_NUMPAD_MULTIPLY,  { 0x0038, 0x0000 } },
    { HOS_KEY_NUMPAD_SUBTRACT,  { 0x002D, 0x0000 } },
    { HOS_KEY_NUMPAD_ADD,       { 0x002B, 0x0000 } },
    { HOS_KEY_NUMPAD_DOT,       { 0x002E, 0x0000 } }
};

/**
 * @tc.name: ShouldReturnOriginal
 * @tc.desc: Test IsShiftPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyUnicodeTransformationTest, ShouldReturnOriginal, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    EXPECT_EQ(IsShiftPressed(keyEvent), false);
}

/**
 * @tc.name: ShouldReturnOriginalUnicodeWhenKeyCode
 * @tc.desc: Test KeyCodeToUnicode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyUnicodeTransformationTest, ShouldReturnOriginalUnicodeWhenKeyCode, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 0;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    EXPECT_EQ(KeyCodeToUnicode(keyCode, keyEvent), DEFAULT_UNICODE);
}

/**
 * @tc.name: ShouldReturnOriginalUnicode_001
 * @tc.desc: Test KeyCodeToUnicode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyUnicodeTransformationTest, ShouldReturnOriginalUnicode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = 0;
    auto keyEvent = KeyEvent::Create();
    EXPECT_EQ(KeyCodeToUnicode(keyCode, keyEvent), DEFAULT_UNICODE);
}

/**
 * @tc.name: ShouldReturnOriginalUnicode_002
 * @tc.desc: Test KeyCodeToUnicode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyUnicodeTransformationTest, ShouldReturnOriginalUnicode_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = HOS_KEY_A;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_DPAD_DOWN);
    keyEvent->AddKeyItem(item);
    EXPECT_NO_FATAL_FAILURE(KeyCodeToUnicode(keyCode, keyEvent));
}

/**
 * @tc.name: ShouldReturnTransitionedUnicode_003
 * @tc.desc: Test KeyCodeToUnicode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyUnicodeTransformationTest, ShouldReturnTransitionedUnicode_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = HOS_KEY_NUMPAD_DOT;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_DPAD_DOWN);
    keyEvent->AddKeyItem(item);
    EXPECT_NO_FATAL_FAILURE(KeyCodeToUnicode(keyCode, keyEvent));
}
/**
 * @tc.name: ShouldReturnTransitionedUnicode_004
 * @tc.desc: Test KeyCodeToUnicode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyUnicodeTransformationTest, ShouldReturnTransitionedUnicode_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = HOS_KEY_A;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(HOS_KEY_SHIFT_LEFT);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    EXPECT_NO_FATAL_FAILURE(KeyCodeToUnicode(keyCode, keyEvent));
}

/**
 * @tc.name: ShouldReturnTransitionedUnicode_005
 * @tc.desc: Test KeyCodeToUnicode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyUnicodeTransformationTest, ShouldReturnTransitionedUnicode_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyCode = HOS_KEY_NUMPAD_DOT;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    item.SetKeyCode(HOS_KEY_SHIFT_LEFT);
    item.SetPressed(true);
    keyEvent->AddKeyItem(item);
    EXPECT_NO_FATAL_FAILURE(KeyCodeToUnicode(keyCode, keyEvent));
}

/**
 * @tc.name: Test_IsShiftPressed_002
 * @tc.desc: Test IsShiftPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyUnicodeTransformationTest, Test_IsShiftPressed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(HOS_KEY_SHIFT_LEFT);
    item1.SetPressed(true);
    item1.SetDownTime(500);
    keyEvent->keys_.push_back(item1);
    EXPECT_EQ(IsShiftPressed(keyEvent), true);
}

/**
 * @tc.name: Test_IsShiftPressed_003
 * @tc.desc: Test IsShiftPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyUnicodeTransformationTest, Test_IsShiftPressed_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(HOS_KEY_SHIFT_RIGHT);
    item1.SetPressed(true);
    item1.SetDownTime(500);
    keyEvent->keys_.push_back(item1);
    EXPECT_EQ(IsShiftPressed(keyEvent), true);
}
/**
 * @tc.name: Test_IsShiftPressed_004
 * @tc.desc: Test IsShiftPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyUnicodeTransformationTest, Test_IsShiftPressed_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    KeyEvent::KeyItem item1;
    item1.SetKeyCode(HOS_KEY_ALT_RIGHT);
    item1.SetPressed(true);
    item1.SetDownTime(500);
    keyEvent->keys_.push_back(item1);
    EXPECT_EQ(IsShiftPressed(keyEvent), false);
}

}
}