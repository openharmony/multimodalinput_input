/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "keyboard_event.h"

namespace {
using namespace testing::ext;
using namespace OHOS;

class KeyboardEventApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(KeyboardEventApiTest, Api_Test_IsHandledByIme_InitTrue, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t windowId = 0;
    bool handledByIme = true;
    int32_t uniCode = 0x21;
    bool isSingleNonCharacter = true;
    bool isTwoNonCharacters = true;
    bool isThreeNonCharacters = true;
    bool isPressed = true;
    int32_t keyCode = 0;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 0;
    keyBoardEventTest.Initialize(windowId, handledByIme, uniCode, isSingleNonCharacter, isTwoNonCharacters,
        isThreeNonCharacters, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType, occurredTime,
        deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto rethandledByIme = keyBoardEventTest.IsHandledByIme();
    EXPECT_TRUE(rethandledByIme == true);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsHandledByIme_InitFalse, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t windowId = 0;
    bool handledByIme = false;
    int32_t uniCode = 0x21;
    bool isSingleNonCharacter = true;
    bool isTwoNonCharacters = true;
    bool isThreeNonCharacters = true;
    bool isPressed = true;
    int32_t keyCode = 0;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 0;
    keyBoardEventTest.Initialize(windowId, handledByIme, uniCode, isSingleNonCharacter, isTwoNonCharacters,
        isThreeNonCharacters, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType, occurredTime,
        deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto rethandledByIme = keyBoardEventTest.IsHandledByIme();
    EXPECT_TRUE(rethandledByIme == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_EnableIme_IsHandledByIme, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    keyBoardEventTest.EnableIme();
    auto handledByIme = keyBoardEventTest.IsHandledByIme();
    EXPECT_TRUE(handledByIme == true);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_DisableIme_IsHandledByIme, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    keyBoardEventTest.DisableIme();
    auto handledByIme = keyBoardEventTest.IsHandledByIme();
    EXPECT_TRUE(handledByIme == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsNoncharacterKeyPressed_One_Normal, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t keycodeOne = 0;
    auto noncharacterKeyPressed = keyBoardEventTest.IsNoncharacterKeyPressed(keycodeOne);
    EXPECT_TRUE(noncharacterKeyPressed == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsNoncharacterKeyPressed_One_Abnormal, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t keycodeOne = 0xFFFFFFF;
    auto noncharacterKeyPressed = keyBoardEventTest.IsNoncharacterKeyPressed(keycodeOne);
    EXPECT_TRUE(noncharacterKeyPressed == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsNoncharacterKeyPressed_One_Min, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t keycodeOne = static_cast<int32_t>(0xFFFFFFFF);
    auto noncharacterKeyPressed = keyBoardEventTest.IsNoncharacterKeyPressed(keycodeOne);
    EXPECT_TRUE(noncharacterKeyPressed == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsNoncharacterKeyPressed_One_Max, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t keycodeOne = 0x7FFFFFFF;
    auto noncharacterKeyPressed = keyBoardEventTest.IsNoncharacterKeyPressed(keycodeOne);
    EXPECT_TRUE(noncharacterKeyPressed == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsNoncharacterKeyPressed_Two_Normal, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t keycodeOne = 0;
    int32_t keycodeTwo = 0;
    auto noncharacterKeyPressed = keyBoardEventTest.IsNoncharacterKeyPressed(keycodeOne, keycodeTwo);
    EXPECT_TRUE(noncharacterKeyPressed == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsNoncharacterKeyPressed_Two_Abnormal, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t keycodeOne = 0xFFFFFFFF;
    int32_t keycodeTwo = 0xFFFFFFFF;
    auto noncharacterKeyPressed = keyBoardEventTest.IsNoncharacterKeyPressed(keycodeOne, keycodeTwo);
    EXPECT_TRUE(noncharacterKeyPressed == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsNoncharacterKeyPressed_Two_Min, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t keycodeOne = static_cast<int32_t>(0xFFFFFFFF);
    int32_t keycodeTwo = static_cast<int32_t>(0xFFFFFFFF);
    auto noncharacterKeyPressed = keyBoardEventTest.IsNoncharacterKeyPressed(keycodeOne, keycodeTwo);
    EXPECT_TRUE(noncharacterKeyPressed == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsNoncharacterKeyPressed_Two_Max, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t keycodeOne = 0x7FFFFFFF;
    int32_t keycodeTwo = 0x7FFFFFFF;
    auto noncharacterKeyPressed = keyBoardEventTest.IsNoncharacterKeyPressed(keycodeOne, keycodeTwo);
    EXPECT_TRUE(noncharacterKeyPressed == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsNoncharacterKeyPressed_Three_Normal, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t keycodeOne = 0;
    int32_t keycodeTwo = 0;
    int32_t keycodeThree = 0;
    auto noncharacterKeyPressed = keyBoardEventTest.IsNoncharacterKeyPressed(keycodeOne, keycodeTwo, keycodeThree);
    EXPECT_TRUE(noncharacterKeyPressed == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsNoncharacterKeyPressed_Three_Abnormal, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t keycodeOne = 0xFFFFFFFF;
    int32_t keycodeTwo = 0xFFFFFFFF;
    int32_t keycodeThree = 0xFFFFFFFF;
    auto noncharacterKeyPressed = keyBoardEventTest.IsNoncharacterKeyPressed(keycodeOne, keycodeTwo, keycodeThree);
    EXPECT_TRUE(noncharacterKeyPressed == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsNoncharacterKeyPressed_Three_Min, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t keycodeOne = static_cast<int32_t>(0xFFFFFFFF);
    int32_t keycodeTwo = static_cast<int32_t>(0xFFFFFFFF);
    int32_t keycodeThree = static_cast<int32_t>(0xFFFFFFFF);
    auto noncharacterKeyPressed = keyBoardEventTest.IsNoncharacterKeyPressed(keycodeOne, keycodeTwo, keycodeThree);
    EXPECT_TRUE(noncharacterKeyPressed == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_IsNoncharacterKeyPressed_Three_Max, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t keycodeOne = 0x7FFFFFFF;
    int32_t keycodeTwo = 0x7FFFFFFF;
    int32_t keycodeThree = 0x7FFFFFFF;
    auto noncharacterKeyPressed = keyBoardEventTest.IsNoncharacterKeyPressed(keycodeOne, keycodeTwo, keycodeThree);
    EXPECT_TRUE(noncharacterKeyPressed == false);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_GetUnicode_Normal, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t windowId = 0;
    bool handledByIme = true;
    int32_t uniCode = 0x21;
    bool isSingleNonCharacter = true;
    bool isTwoNonCharacters = true;
    bool isThreeNonCharacters = true;
    bool isPressed = true;
    int32_t keyCode = 0;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 0;
    keyBoardEventTest.Initialize(windowId, handledByIme, uniCode, isSingleNonCharacter, isTwoNonCharacters,
        isThreeNonCharacters, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType, occurredTime,
        deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retUnicode = keyBoardEventTest.GetUnicode();
    EXPECT_EQ(retUnicode, uniCode);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_GetUnicode_Abnormal, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t windowId = 0;
    bool handledByIme = true;
    int32_t uniCode = 0xFFFFFFFF;
    bool isSingleNonCharacter = true;
    bool isTwoNonCharacters = true;
    bool isThreeNonCharacters = true;
    bool isPressed = true;
    int32_t keyCode = 0;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 0;
    keyBoardEventTest.Initialize(windowId, handledByIme, uniCode, isSingleNonCharacter, isTwoNonCharacters,
        isThreeNonCharacters, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType, occurredTime,
        deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retUnicode = keyBoardEventTest.GetUnicode();
    EXPECT_EQ(retUnicode, uniCode);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_GetUnicode_Min, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t windowId = 0;
    bool handledByIme = true;
    int32_t uniCode = static_cast<int32_t>(0xFFFFFFFF);
    bool isSingleNonCharacter = true;
    bool isTwoNonCharacters = true;
    bool isThreeNonCharacters = true;
    bool isPressed = true;
    int32_t keyCode = 0;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 0;
    keyBoardEventTest.Initialize(windowId, handledByIme, uniCode, isSingleNonCharacter, isTwoNonCharacters,
        isThreeNonCharacters, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType, occurredTime,
        deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retUnicode = keyBoardEventTest.GetUnicode();
    EXPECT_EQ(retUnicode, uniCode);
}

HWTEST_F(KeyboardEventApiTest, Api_Test_GetUnicode_Max, TestSize.Level1)
{
    KeyBoardEvent keyBoardEventTest;
    int32_t windowId = 0;
    bool handledByIme = true;
    int32_t uniCode = 0x7FFFFFFF;
    bool isSingleNonCharacter = true;
    bool isTwoNonCharacters = true;
    bool isThreeNonCharacters = true;
    bool isPressed = true;
    int32_t keyCode = 0;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 0;
    keyBoardEventTest.Initialize(windowId, handledByIme, uniCode, isSingleNonCharacter, isTwoNonCharacters,
        isThreeNonCharacters, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType, occurredTime,
        deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retUnicode = keyBoardEventTest.GetUnicode();
    EXPECT_EQ(retUnicode, uniCode);
}
} // namespace
