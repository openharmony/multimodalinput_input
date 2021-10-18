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
#include "stylus_event.h"

namespace {
using namespace testing::ext;
using namespace OHOS;

class StylusEventApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(StylusEventApiTest, Api_Test_GetAction_Normal, TestSize.Level1)
{
    StylusEvent stylusEventTest;
    int32_t windowId = 0;
    int32_t action = 15;
    int32_t buttons = 0;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "2";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "5";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    stylusEventTest.Initialize(windowId, action, buttons, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retAction = stylusEventTest.GetAction();
    EXPECT_EQ(retAction, action);
}

HWTEST_F(StylusEventApiTest, Api_Test_GetAction_Abnormal, TestSize.Level1)
{
    StylusEvent stylusEventTest;
    int32_t windowId = 0;
    int32_t action = 0xFFFFFFFF;
    int32_t buttons = 0;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "2";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "5";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    stylusEventTest.Initialize(windowId, action, buttons, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retAction = stylusEventTest.GetAction();
    EXPECT_EQ(retAction, action);
}

HWTEST_F(StylusEventApiTest, Api_Test_GetButtons_Normal, TestSize.Level1)
{
    StylusEvent stylusEventTest;
    int32_t windowId = 0;
    int32_t action = 15;
    int32_t buttons = 23;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "2";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "5";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    stylusEventTest.Initialize(windowId, action, buttons, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retButtons = stylusEventTest.GetButtons();
    EXPECT_EQ(retButtons, buttons);
}

HWTEST_F(StylusEventApiTest, Api_Test_GetButtons_Abnormal, TestSize.Level1)
{
    StylusEvent stylusEventTest;
    int32_t windowId = 0;
    int32_t action = 15;
    int32_t buttons = 0xFFFFFFFF;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "2";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "5";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    stylusEventTest.Initialize(windowId, action, buttons, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retButtons = stylusEventTest.GetButtons();
    EXPECT_EQ(retButtons, buttons);
}

HWTEST_F(StylusEventApiTest, Api_Test_GetActionButton_Normal, TestSize.Level1)
{
    StylusEvent stylusEventTest;
    int32_t windowId = 0;
    int32_t action = 15;
    int32_t buttons = 0x14c;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "2";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "5";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    stylusEventTest.Initialize(windowId, action, buttons, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retActionButton = stylusEventTest.GetActionButton();
    EXPECT_EQ(retActionButton, BUTTON_STYLUS2);
}

HWTEST_F(StylusEventApiTest, Api_Test_GetActionButton_Anomalous, TestSize.Level1)
{
    StylusEvent stylusEventTest;
    int32_t windowId = 0;
    int32_t action = 15;
    int32_t buttons = -1;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "2";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "5";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    stylusEventTest.Initialize(windowId, action, buttons, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retActionButton = stylusEventTest.GetActionButton();
    EXPECT_EQ(retActionButton, buttons);
}
} // namespace
