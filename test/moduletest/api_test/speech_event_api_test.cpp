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
#include "speech_event.h"

namespace {
using namespace testing::ext;
using namespace OHOS;

class SpeechEventApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(SpeechEventApiTest, Api_Test_GetAction_Normal, TestSize.Level1)
{
    SpeechEvent speechEventTest;
    int32_t windowId = 0;
    int32_t action = 54;
    int32_t scene = 0;
    int32_t mode = 0;
    const std::string actionProperty = "a";
    int32_t highLevelEvent = 0;
    const std::string uuid = "b";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "c";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    speechEventTest.Initialize(windowId, action, scene, mode, actionProperty, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retAction = speechEventTest.GetAction();
    EXPECT_EQ(retAction, action);
}

HWTEST_F(SpeechEventApiTest, Api_Test_GetAction_Abnormal, TestSize.Level1)
{
    SpeechEvent speechEventTest;
    int32_t windowId = 0;
    int32_t action = 0xFFFFFFFF;
    int32_t scene = 0;
    int32_t mode = 0;
    const std::string actionProperty = "a";
    int32_t highLevelEvent = 0;
    const std::string uuid = "b";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "c";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    speechEventTest.Initialize(windowId, action, scene, mode, actionProperty, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retAction = speechEventTest.GetAction();
    EXPECT_EQ(retAction, action);
}

HWTEST_F(SpeechEventApiTest, Api_Test_GetScene_Normal, TestSize.Level1)
{
    SpeechEvent speechEventTest;
    int32_t windowId = 0;
    int32_t action = 54;
    int32_t scene = 32;
    int32_t mode = 0;
    const std::string actionProperty = "a";
    int32_t highLevelEvent = 0;
    const std::string uuid = "b";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "c";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    speechEventTest.Initialize(windowId, action, scene, mode, actionProperty, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retScene = speechEventTest.GetScene();
    EXPECT_EQ(retScene, scene);
}

HWTEST_F(SpeechEventApiTest, Api_Test_GetScene_Abnormal, TestSize.Level1)
{
    SpeechEvent speechEventTest;
    int32_t windowId = 0;
    int32_t action = 54;
    int32_t scene = 0xFFFFFFFF;
    int32_t mode = 0;
    const std::string actionProperty = "a";
    int32_t highLevelEvent = 0;
    const std::string uuid = "b";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "c";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    speechEventTest.Initialize(windowId, action, scene, mode, actionProperty, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retScene = speechEventTest.GetScene();
    EXPECT_EQ(retScene, scene);
}

HWTEST_F(SpeechEventApiTest, Api_Test_GetActionProperty_Normal, TestSize.Level1)
{
    SpeechEvent speechEventTest;
    int32_t windowId = 0;
    int32_t action = 54;
    int32_t scene = 32;
    int32_t mode = 0;
    const std::string actionProperty = "actionProperty";
    int32_t highLevelEvent = 0;
    const std::string uuid = "b";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "c";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    speechEventTest.Initialize(windowId, action, scene, mode, actionProperty, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retActionProperty = speechEventTest.GetActionProperty();
    EXPECT_EQ(retActionProperty, actionProperty);
}

HWTEST_F(SpeechEventApiTest, Api_Test_GetActionProperty_Abnormal, TestSize.Level1)
{
    SpeechEvent speechEventTest;
    int32_t windowId = 0;
    int32_t action = 54;
    int32_t scene = 32;
    int32_t mode = 0;
    const std::string actionProperty = "ERROR";
    int32_t highLevelEvent = 0;
    const std::string uuid = "b";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "c";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    speechEventTest.Initialize(windowId, action, scene, mode, actionProperty, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retActionProperty = speechEventTest.GetActionProperty();
    EXPECT_EQ(retActionProperty, actionProperty);
}

HWTEST_F(SpeechEventApiTest, Api_Test_GetMatchMode_Normal, TestSize.Level1)
{
    SpeechEvent speechEventTest;
    int32_t windowId = 0;
    int32_t action = 54;
    int32_t scene = 32;
    int32_t mode = 594;
    const std::string actionProperty = "actionProperty";
    int32_t highLevelEvent = 0;
    const std::string uuid = "b";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "c";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    speechEventTest.Initialize(windowId, action, scene, mode, actionProperty, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retMatchMode = speechEventTest.GetMatchMode();
    EXPECT_EQ(retMatchMode, mode);
}

HWTEST_F(SpeechEventApiTest, Api_Test_GetMatchMode_Abnormal, TestSize.Level1)
{
    SpeechEvent speechEventTest;
    int32_t windowId = 0;
    int32_t action = 54;
    int32_t scene = 32;
    int32_t mode = 0xFFFFFFFF;
    const std::string actionProperty = "actionProperty";
    int32_t highLevelEvent = 0;
    const std::string uuid = "b";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "c";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    speechEventTest.Initialize(windowId, action, scene, mode, actionProperty, highLevelEvent, uuid, sourceType,
        occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retMatchMode = speechEventTest.GetMatchMode();
    EXPECT_EQ(retMatchMode, mode);
}
} // namespace
