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

#include "keyboard_event.h"
#include <gtest/gtest.h>

static int32_t g_keyCodeOne = 1;
static int32_t g_keyCodeTwo = 1;
static int32_t g_keyCodeThree = 1;
namespace {
using namespace testing::ext;
using namespace OHOS;

class KeyboardEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

KeyBoardEvent g_keyBoardEvent;
HWTEST_F(KeyboardEventTest, Initialize_true, TestSize.Level1)
{
    int32_t windowId = 1;
    bool handledByIme = true;
    int32_t unicode = 1;
    bool isSingleNonCharacter = true;
    bool isTwoNonCharacters = true;
    bool isThreeNonCharacters = true;
    bool isPressed = true;
    int32_t keyCode = 1;
    int32_t keyDownDuration = 1;
    int32_t highLevelEvent = 1;
    std::string strUuid = "111";
    int32_t sourceType = 1;
    int64_t occurredTime = 1;
    std::string deviceId = "111";
    int32_t inputDeviceId = 1;
    bool isHighLevelEvent = true;
    g_keyBoardEvent.Initialize(windowId, handledByIme, unicode, isSingleNonCharacter, isTwoNonCharacters,
                               isThreeNonCharacters, isPressed, keyCode, keyDownDuration,
                               highLevelEvent, strUuid, sourceType, occurredTime,
                               deviceId, inputDeviceId, isHighLevelEvent, 0, 0);
}

HWTEST_F(KeyboardEventTest, Initialize_002, TestSize.Level1)
{
    KeyBoardEvent keyBoardEvent2;
    keyBoardEvent2.Initialize(g_keyBoardEvent);
}

HWTEST_F(KeyboardEventTest, Initialize_003, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTmp;
    KeyBoardEvent keyBoardEvent2;
    keyBoardEvent2.Initialize(keyBoardEventTmp);
}

HWTEST_F(KeyboardEventTest, EnableIme, TestSize.Level1)
{
    g_keyBoardEvent.EnableIme();
}

HWTEST_F(KeyboardEventTest, IsHandledByIme_TRUE, TestSize.Level1)
{
    bool retResult = g_keyBoardEvent.IsHandledByIme();
    EXPECT_TRUE(retResult);
}

HWTEST_F(KeyboardEventTest, DisableIme, TestSize.Level1)
{
    g_keyBoardEvent.DisableIme();
}

HWTEST_F(KeyboardEventTest, IsHandledByIme_FALSE, TestSize.Level1)
{
    g_keyBoardEvent.DisableIme();
    bool retResult = g_keyBoardEvent.IsHandledByIme();
    EXPECT_FALSE(retResult);
}

HWTEST_F(KeyboardEventTest, IsNoncharacterKeyPressed_I_TRUE, TestSize.Level1)
{
    bool retResult = g_keyBoardEvent.IsNoncharacterKeyPressed(g_keyCodeOne);
    EXPECT_FALSE(retResult);
}

HWTEST_F(KeyboardEventTest, IsNoncharacterKeyPressed_II_TRUE, TestSize.Level1)
{
    bool retResult = g_keyBoardEvent.IsNoncharacterKeyPressed(g_keyCodeOne, g_keyCodeTwo);
    EXPECT_FALSE(retResult);
}

HWTEST_F(KeyboardEventTest, IsNoncharacterKeyPressed_III_TRUE, TestSize.Level1)
{
    bool retResult = g_keyBoardEvent.IsNoncharacterKeyPressed(g_keyCodeOne, g_keyCodeTwo, g_keyCodeThree);
    EXPECT_FALSE(retResult);
}

HWTEST_F(KeyboardEventTest, GetUnicode_001, TestSize.Level1)
{
    int32_t retResult = g_keyBoardEvent.GetUnicode();
    EXPECT_EQ(retResult, 1);
}

HWTEST_F(KeyboardEventTest, GetUnicode_002, TestSize.Level1)
{
    int32_t retResult = g_keyBoardEvent.GetUnicode();
    EXPECT_NE(retResult, 2);
}

HWTEST_F(KeyboardEventTest, Initialize_false, TestSize.Level1)
{
    int32_t windowId = 1;
    bool handledByIme = false;
    int32_t uniCode = 22;
    bool isSingleNonCharacter = false;
    bool isTwoNonCharacters = false;
    bool isThreeNonCharacters = false;
    bool isPressed = false;
    int32_t keyCode = 1;
    int32_t keyDownDuration = 1;
    int32_t highLevelEvent = 1;
    std::string strUuid = "222";
    int32_t sourceType = 1;
    int64_t occurredTime = 1;
    std::string deviceId = "111";
    int32_t inputDeviceId = 1;
    bool isHighLevelEvent = false;
    g_keyBoardEvent.Initialize(windowId, handledByIme, uniCode, isSingleNonCharacter, isTwoNonCharacters,
                               isThreeNonCharacters, isPressed, keyCode, keyDownDuration,
                               highLevelEvent, strUuid, sourceType, occurredTime,
                               deviceId, inputDeviceId, isHighLevelEvent, 0, 0);
}

HWTEST_F(KeyboardEventTest, IsNoncharacterKeyPressed_I_FALSE, TestSize.Level1)
{
    bool retResult = g_keyBoardEvent.IsNoncharacterKeyPressed(g_keyCodeOne);
    EXPECT_FALSE(retResult);
}

HWTEST_F(KeyboardEventTest, IsNoncharacterKeyPressed_II_FALSE, TestSize.Level1)
{
    bool retResult = g_keyBoardEvent.IsNoncharacterKeyPressed(g_keyCodeOne, g_keyCodeTwo);
    EXPECT_FALSE(retResult);
}

HWTEST_F(KeyboardEventTest, IsNoncharacterKeyPressed_III_FALSE, TestSize.Level1)
{
    bool retResult = g_keyBoardEvent.IsNoncharacterKeyPressed(g_keyCodeOne, g_keyCodeTwo, g_keyCodeThree);
    EXPECT_FALSE(retResult);
}

HWTEST_F(KeyboardEventTest, GetUnicode_II_001, TestSize.Level1)
{
    int32_t retResult = g_keyBoardEvent.GetUnicode();
    EXPECT_EQ(retResult, 22);
}

HWTEST_F(KeyboardEventTest, GetUnicode_II_002, TestSize.Level1)
{
    int32_t retResult = g_keyBoardEvent.GetUnicode();
    EXPECT_NE(retResult, 2);
}

HWTEST_F(KeyboardEventTest, IsHandledByIme_TMP_001, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTmp;
    keyBoardEventTmp.Initialize(33, false, 33, false, false,
                                false, false, 33, 33, 33, "33", 33, 33, "33", 33, false, 0, 0);
    keyBoardEventTmp.EnableIme();
    bool retResult = keyBoardEventTmp.IsHandledByIme();
    EXPECT_EQ(retResult, true);
}

HWTEST_F(KeyboardEventTest, IsHandledByIme_TMP_002, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTmp;
    keyBoardEventTmp.Initialize(44, true, 44, true, true,
                                true, true, 44, 44, 44, "44", 44, 44, "44", 44, true, 0, 0);
    keyBoardEventTmp.DisableIme();
    bool retResult = keyBoardEventTmp.IsHandledByIme();
    EXPECT_EQ(retResult, false);
}

HWTEST_F(KeyboardEventTest, IsNoncharacterKeyPressed_TMP_001, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTmp;
    keyBoardEventTmp.Initialize(55, false, 55, false, false,
                                false, false, 55, 55, 55, "55", 55, 55, "55", 55, false, 0, 0);
    bool retResult = keyBoardEventTmp.IsNoncharacterKeyPressed(0);
    EXPECT_EQ(retResult, false);
}

HWTEST_F(KeyboardEventTest, IsNoncharacterKeyPressed_TMP_002, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTmp;
    keyBoardEventTmp.Initialize(33, false, 33, true, false,
                                false, false, 54, 54, 54, "54", 54, 54, "54", 54, false, 0, 0);
    bool retResult = keyBoardEventTmp.IsNoncharacterKeyPressed(8);
    EXPECT_FALSE(retResult);
}

HWTEST_F(KeyboardEventTest, IsNoncharacterKeyPressed_TTMP_001, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTmp;
    keyBoardEventTmp.Initialize(65, false, 65, false, false,
                                false, false, 65, 65, 65, "65", 65, 65, "65", 65, false, 0, 0);
    bool retResult = keyBoardEventTmp.IsNoncharacterKeyPressed(101, 102);
    EXPECT_EQ(retResult, false);
}

HWTEST_F(KeyboardEventTest, IsNoncharacterKeyPressed_TTMP_002, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTmp;
    keyBoardEventTmp.Initialize(67, true, 67, true, true,
                                true, true, 67, 67, 67, "67", 67, 67, "67", 67, true, 0, 0);
    bool retResult = keyBoardEventTmp.IsNoncharacterKeyPressed(201, 202);
    EXPECT_FALSE(retResult);
}

HWTEST_F(KeyboardEventTest, IsNoncharacterKeyPressed_RTMP_001, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTmp;
    keyBoardEventTmp.Initialize(77, false, 77, false, false,
                                false, false, 77, 77, 77, "77", 77, 77, "77", 77, false, 0, 0);
    bool retResult = keyBoardEventTmp.IsNoncharacterKeyPressed(301, 302, 303);
    EXPECT_EQ(retResult, false);
}

HWTEST_F(KeyboardEventTest, IsNoncharacterKeyPressed_RTMP_002, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTmp;
    keyBoardEventTmp.Initialize(99, true, 99, true, true,
                                true, true, 99, 99, 99, "99", 99, 99, "99", 99, true, 0, 0);
    bool retResult = keyBoardEventTmp.IsNoncharacterKeyPressed(401, 402, 403);
    EXPECT_FALSE(retResult);
}

HWTEST_F(KeyboardEventTest, GetUnicode_RTMP_001, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTmp;
    keyBoardEventTmp.Initialize(100, true, 100, true, true,
                                true, true, 100, 100, 100, "100", 100, 100, "100", 100, true, 0, 0);
    int32_t retResult = keyBoardEventTmp.GetUnicode();
    EXPECT_EQ(retResult, 100);
}

HWTEST_F(KeyboardEventTest, GetUnicode_RTMP_002, TestSize.Level1)
{
    int32_t uniCode = static_cast<int32_t>('a');
    KeyBoardEvent keyBoardEventTmp;
    keyBoardEventTmp.Initialize(100, true, uniCode, true, true,
                                true, true, 100, 100, 100, "100", 100, 100, "100", 100, true, 0, 0);
    int32_t retResult = keyBoardEventTmp.GetUnicode();
    EXPECT_EQ(retResult, uniCode);
}

HWTEST_F(KeyboardEventTest, GetUnicode_RTMP_003, TestSize.Level1)
{
    int32_t uniCode = -101;
    KeyBoardEvent keyBoardEventTmp;
    keyBoardEventTmp.Initialize(100, true, uniCode, true, true,
                                true, true, 100, 100, 100, "100", 100, 100, "100", 100, true, 0, 0);
    int32_t retResult = keyBoardEventTmp.GetUnicode();
    EXPECT_EQ(retResult, uniCode);
}

HWTEST_F(KeyboardEventTest, GetUnicode_RTMP_004, TestSize.Level1)
{
    int32_t uniCode = static_cast<int32_t>('a') + static_cast<int32_t>('c');
    KeyBoardEvent keyBoardEventTmp;
    keyBoardEventTmp.Initialize(100, true, uniCode, true, true,
                                true, true, 100, 100, 100, "100", 100, 100, "100", 100, true, 0, 0);
    int32_t retResult = keyBoardEventTmp.GetUnicode();
    EXPECT_EQ(retResult, uniCode);
}
} // namespace
