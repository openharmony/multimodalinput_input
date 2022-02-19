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

class KeyEventApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(KeyEventApiTest, Api_Test_GetOriginEventType_Normal, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 0;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto originEventType = keyEventTest.GetOriginEventType();
    EXPECT_EQ(originEventType, deviceEventType);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetOriginEventType_Abnormal, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 0;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 0xFFFFFFFF;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto originEventType = keyEventTest.GetOriginEventType();
    EXPECT_EQ(originEventType, deviceEventType);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetOriginEventType_Min, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 0;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = static_cast<int32_t>(0xFFFFFFFF);
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto originEventType = keyEventTest.GetOriginEventType();
    EXPECT_EQ(originEventType, deviceEventType);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetOriginEventType_Max, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 0;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 0x7FFFFFFF;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto originEventType = keyEventTest.GetOriginEventType();
    EXPECT_EQ(originEventType, deviceEventType);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetMaxKeyCode, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    auto originEventType = keyEventTest.GetMaxKeyCode();
    EXPECT_TRUE(originEventType == NOW_MAX_KEY);
}

HWTEST_F(KeyEventApiTest, Api_Test_IsKeyDown_Normal, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 0;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto keyDown = keyEventTest.IsKeyDown();
    EXPECT_EQ(keyDown, isPressed);
}

HWTEST_F(KeyEventApiTest, Api_Test_IsKeyDown_Abnormal, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = false;
    int32_t keyCode = 0;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto keyDown = keyEventTest.IsKeyDown();
    EXPECT_EQ(keyDown, isPressed);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetKeyCode_Normal, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 10;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retKeyCode = keyEventTest.GetKeyCode();
    EXPECT_EQ(retKeyCode, keyCode);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetKeyCode_Min, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = static_cast<int32_t>(0xFFFFFFFF);
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retKeyCode = keyEventTest.GetKeyCode();
    EXPECT_EQ(retKeyCode, keyCode);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetKeyCode_Max, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 0x7FFFFFFF;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retKeyCode = keyEventTest.GetKeyCode();
    EXPECT_EQ(retKeyCode, keyCode);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetKeyCode_Abnormal, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 0xFFFFFFFF;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retKeyCode = keyEventTest.GetKeyCode();
    EXPECT_EQ(retKeyCode, keyCode);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetKeyCode_MinValue, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = static_cast<int32_t>(0xFFFFFFFF);
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retKeyCode = keyEventTest.GetKeyCode();
    EXPECT_EQ(retKeyCode, keyCode);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetKeyCode_MaxValue, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 0x7FFFFFFF;
    int32_t keyDownDuration = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retKeyCode = keyEventTest.GetKeyCode();
    EXPECT_EQ(retKeyCode, keyCode);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetKeyDownDuration_Normal, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 10;
    int32_t keyDownDuration = 5;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retKeyDownDuration = keyEventTest.GetKeyDownDuration();
    EXPECT_EQ(retKeyDownDuration, keyDownDuration);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetKeyDownDuration_Abnormal, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 10;
    int32_t keyDownDuration = 0xFFFFFFFF;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retKeyDownDuration = keyEventTest.GetKeyDownDuration();
    EXPECT_EQ(retKeyDownDuration, keyDownDuration);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetKeyDownDuration_Min, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 10;
    int32_t keyDownDuration = static_cast<int32_t>(0xFFFFFFFF);
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retKeyDownDuration = keyEventTest.GetKeyDownDuration();
    EXPECT_EQ(retKeyDownDuration, keyDownDuration);
}

HWTEST_F(KeyEventApiTest, Api_Test_GetKeyDownDuration_Max, TestSize.Level1)
{
    OHOS::KeyEvent keyEventTest;
    int32_t windowId = 0;
    bool isPressed = true;
    int32_t keyCode = 10;
    int32_t keyDownDuration = 0x7FFFFFFF;
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    keyEventTest.Initialize(windowId, isPressed, keyCode, keyDownDuration, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags, deviceEventType);
    auto retKeyDownDuration = keyEventTest.GetKeyDownDuration();
    EXPECT_EQ(retKeyDownDuration, keyDownDuration);
}
} // namespace
