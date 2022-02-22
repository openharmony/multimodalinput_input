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

#include "key_event_pre.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS;

class KeyEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

KeyEvent g_keyEvent;
HWTEST_F(KeyEventTest, Initialize_001, TestSize.Level1)
{
    int32_t windowId = 1;
    bool isPressed = true;
    int32_t keyCode = 1;
    int32_t keyDownDuration = 1;
    int32_t highLevelEvent = 1;
    std::string strUuid = "111";
    int32_t sourceType = 1;
    uint64_t occurredTime = 1;
    std::string deviceId = "111";
    int32_t inputDeviceId = 1;
    bool isHighLevelEvent = true;

    g_keyEvent.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, strUuid,
                        sourceType, occurredTime, deviceId, inputDeviceId,
                        isHighLevelEvent);
}

HWTEST_F(KeyEventTest, Initialize_002, TestSize.Level1)
{
    KeyEvent keyEventII;
    keyEventII.Initialize(g_keyEvent);
}

HWTEST_F(KeyEventTest, Initialize_003, TestSize.Level1)
{
    int32_t windowId = 1;
    KeyEvent keyEventTmp;
    bool isPressed = false;
    int32_t keyCode = 2;
    int32_t keyDownDuration = 2;
    int32_t highLevelEvent = 2;
    std::string strUuid = "222";
    int32_t sourceType = 2;
    uint64_t occurredTime = 2;
    std::string deviceId = "222";
    int32_t inputDeviceId = 2;
    bool isHighLevelEvent = false;
    keyEventTmp.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, strUuid,
                           sourceType, occurredTime, deviceId, inputDeviceId,
                           isHighLevelEvent);

    KeyEvent keyEventII;
    keyEventII.Initialize(keyEventTmp);
}

HWTEST_F(KeyEventTest, Initialize_004, TestSize.Level1)
{
    int32_t windowId = 1;
    KeyEvent keyEventTmp;
    bool isPressed = true;
    int32_t keyCode = 3;
    int32_t keyDownDuration = 3;
    int32_t highLevelEvent = 3;
    std::string strUuid = "333";
    int32_t sourceType = 3;
    uint64_t occurredTime = 3;
    std::string deviceId = "333";
    int32_t inputDeviceId = 3;
    bool isHighLevelEvent = false;
    keyEventTmp.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, strUuid,
                           sourceType, occurredTime, deviceId, inputDeviceId,
                           isHighLevelEvent);

    KeyEvent keyEventII;
    keyEventII.Initialize(keyEventTmp);
}

HWTEST_F(KeyEventTest, Initialize_005, TestSize.Level1)
{
    int32_t windowId = 1;
    KeyEvent keyEventTmp;
    bool isPressed = false;
    int32_t keyCode = 4;
    int32_t keyDownDuration = 4;
    int32_t highLevelEvent = 4;
    std::string strUuid = "444";
    int32_t sourceType = 4;
    uint64_t occurredTime = 4;
    std::string deviceId = "444";
    int32_t inputDeviceId = 4;
    bool isHighLevelEvent = true;
    keyEventTmp.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, strUuid,
                           sourceType, occurredTime, deviceId, inputDeviceId,
                           isHighLevelEvent);

    KeyEvent keyEventII;
    keyEventII.Initialize(keyEventTmp);
}

HWTEST_F(KeyEventTest, GetMaxKeyCode_001, TestSize.Level1)
{
    int32_t retResult = g_keyEvent.GetMaxKeyCode();
    EXPECT_EQ(retResult, NOW_MAX_KEY);
}

HWTEST_F(KeyEventTest, IsKeyDown_001, TestSize.Level1)
{
    bool retResult = g_keyEvent.IsKeyDown();
    EXPECT_TRUE(retResult);
}

HWTEST_F(KeyEventTest, GetKeyCode_001, TestSize.Level1)
{
    int32_t retResult = g_keyEvent.GetKeyCode();
    EXPECT_EQ(1, retResult);
}

HWTEST_F(KeyEventTest, GetKeyCode_002, TestSize.Level1)
{
    int32_t retResult = g_keyEvent.GetKeyCode();
    EXPECT_NE(retResult, 2);
}

HWTEST_F(KeyEventTest, GetKeyDownDuration_001, TestSize.Level1)
{
    int32_t retResult = g_keyEvent.GetKeyDownDuration();
    EXPECT_EQ(retResult, 1);
}

HWTEST_F(KeyEventTest, GetKeyDownDuration_002, TestSize.Level1)
{
    int32_t retResult = g_keyEvent.GetKeyDownDuration();
    EXPECT_NE(retResult, 2);
}

HWTEST_F(KeyEventTest, Initialize_L, TestSize.Level1)
{
    int32_t windowId = 1;
    bool isPressed = false;
    int32_t keyCode = 5;
    int32_t keyDownDuration = 5;
    int32_t highLevelEvent = 5;
    std::string strUuid = "555";
    int32_t sourceType = 5;
    uint64_t occurredTime = 5;
    std::string deviceId = "555";
    int32_t inputDeviceId = 5;
    bool isHighLevelEvent = false;

    g_keyEvent.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, strUuid,
                        sourceType, occurredTime, deviceId, inputDeviceId,
                        isHighLevelEvent);
}

HWTEST_F(KeyEventTest, GetMaxKeyCode_L_001, TestSize.Level1)
{
    int32_t retResult = g_keyEvent.GetMaxKeyCode();
    EXPECT_EQ(retResult, NOW_MAX_KEY);
}

HWTEST_F(KeyEventTest, IsKeyDown_L_001, TestSize.Level1)
{
    bool retResult = g_keyEvent.IsKeyDown();
    EXPECT_FALSE(retResult);
}

HWTEST_F(KeyEventTest, GetKeyCode_L_001, TestSize.Level1)
{
    int32_t retResult = g_keyEvent.GetKeyCode();
    EXPECT_EQ(5, retResult);
}

HWTEST_F(KeyEventTest, GetKeyCode_L_002, TestSize.Level1)
{
    int32_t retResult = g_keyEvent.GetKeyCode();
    EXPECT_NE(retResult, 1);
}

HWTEST_F(KeyEventTest, GetKeyDownDuration_L_001, TestSize.Level1)
{
    int32_t retResult = g_keyEvent.GetKeyDownDuration();
    EXPECT_EQ(retResult, 5);
}

HWTEST_F(KeyEventTest, GetKeyDownDuration_L_002, TestSize.Level1)
{
    int32_t retResult = g_keyEvent.GetKeyDownDuration();
    EXPECT_NE(retResult, 2);
}

HWTEST_F(KeyEventTest, GetKeyDownDuration_TMP_001, TestSize.Level1)
{
    KeyEvent keyEventTmp;
    keyEventTmp.Initialize(7, false, 7, 7, 7, "777", 7, 7, "777", 7, false);
    bool retResult = keyEventTmp.IsKeyDown();
    EXPECT_EQ(false, retResult);
}

HWTEST_F(KeyEventTest, GetKeyDownDuration_TMP_002, TestSize.Level1)
{
    KeyEvent keyEventTmp;
    keyEventTmp.Initialize(9, true, 9, 9, 9, "999", 9, 9, "999", 9, false);
    bool retResult = keyEventTmp.IsKeyDown();
    EXPECT_EQ(true, retResult);
}

HWTEST_F(KeyEventTest, GetKeyCode_TMP_001, TestSize.Level1)
{
    int32_t keyCode = 65;
    KeyEvent keyEventTmp;
    keyEventTmp.Initialize(12, false, keyCode, 12, 12, "12", 12, 12, "12", 12, false);
    int32_t retResult = keyEventTmp.GetKeyCode();
    EXPECT_EQ(keyCode, retResult);
}

HWTEST_F(KeyEventTest, GetKeyCode_TMP_002, TestSize.Level1)
{
    int32_t keyCode = int32_t('s');
    KeyEvent keyEventTmp;
    keyEventTmp.Initialize(34, true, keyCode, 34, 34, "34", 34, 34, "34", 34, false);
    int32_t retResult = keyEventTmp.GetKeyCode();
    EXPECT_EQ(keyCode, retResult);
}
} // namespace
