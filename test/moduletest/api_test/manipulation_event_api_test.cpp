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
#include "manipulation_event.h"

namespace {
using namespace testing::ext;
using namespace OHOS;

class ManipulationEventApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(ManipulationEventApiTest, Api_Test_GetStartTime_Normal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos* fingersInfos = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retStartTime =  manipulationEventTest.GetStartTime();
    EXPECT_EQ(retStartTime, startTime);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetStartTime_Abnormal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 0xFFFFFFFF;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos* fingersInfos = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retStartTime = manipulationEventTest.GetStartTime();
    EXPECT_EQ(retStartTime, startTime);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetStartTime_Min, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = static_cast<int32_t>(0xFFFFFFFF);
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos* fingersInfos = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retStartTime = manipulationEventTest.GetStartTime();
    EXPECT_EQ(retStartTime, startTime);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetStartTime_Max, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 0x7FFFFFFF;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos* fingersInfos = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retStartTime = manipulationEventTest.GetStartTime();
    EXPECT_EQ(retStartTime, startTime);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPhase_Normal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 0;
    fingerInfos* fingersInfos = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retPhase = manipulationEventTest.GetPhase();
    EXPECT_EQ(retPhase, operationState);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPhase_Abnormal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 0xFFFFFFFF;
    int32_t pointerCount = 0;
    fingerInfos* fingersInfos = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retPhase = manipulationEventTest.GetPhase();
    EXPECT_EQ(retPhase, operationState);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPhase_Min, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = static_cast<int32_t>(0xFFFFFFFF);
    int32_t pointerCount = 0;
    fingerInfos* fingersInfos = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retPhase = manipulationEventTest.GetPhase();
    EXPECT_EQ(retPhase, operationState);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPhase_Max, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 0x7FFFFFFF;
    int32_t pointerCount = 0;
    fingerInfos* fingersInfos = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retPhase = manipulationEventTest.GetPhase();
    EXPECT_EQ(retPhase, operationState);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerPosition_Normal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 2;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    float x = 0.12f;
    float y = 0.21f;
    fingersInfos[1].mMp.Setxy(x, y);
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
                                     highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
                                     isHighLevelEvent, deviceUdevTags);
    int32_t index = 1;
    auto retPointerPosition = manipulationEventTest.GetPointerPosition(index);
    auto retX = retPointerPosition.GetX();
    EXPECT_FLOAT_EQ(retX, x);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerPosition_Fail, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 2;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    float x = 0.12f;
    float y = 0.21f;
    fingersInfos[1].mMp.Setxy(x, y);
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags);
    int32_t index = 2;
    auto retPointerPosition = manipulationEventTest.GetPointerPosition(index);
    auto retX = retPointerPosition.GetX();
    EXPECT_FLOAT_EQ(retX, 0.0f);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerPosition_Abnormal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 2;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    float x = 0.12f;
    float y = 0.21f;
    fingersInfos[1].mMp.Setxy(x, y);
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags);
    int32_t index = 0;
    auto retPointerPosition = manipulationEventTest.GetPointerPosition(index);
    auto retX = retPointerPosition.GetX();
    EXPECT_FLOAT_EQ(retX, 0.0f);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerPosition_Abnormal_Parameter, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 2;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    float x = 0.12f;
    float y = 0.21f;
    fingersInfos[1].mMp.Setxy(x, y);
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags);
    int32_t index = 0xFFFFFFFF;
    auto retPointerPosition = manipulationEventTest.GetPointerPosition(index);
    auto retX = retPointerPosition.GetX();
    EXPECT_FLOAT_EQ(retX, 0.0f);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_SetScreenOffset_GetFingersInfos_Normal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 2;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
                                     highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
                                     isHighLevelEvent, deviceUdevTags);
    float offsetX = 1.1f;
    float offsetY = 1.1f;
    manipulationEventTest.SetScreenOffset(offsetX, offsetY);
    auto FingersInfos = manipulationEventTest.GetFingersInfos();
    auto retY = FingersInfos->mMp.GetY();
    EXPECT_FLOAT_EQ(retY, offsetY);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_SetScreenOffset_GetFingersInfos_Abnormal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 2;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags);
    float offsetX = 1.1f;
    auto offsetY = static_cast<float>(0xFFFFFFFFFFFFFFFF);
    manipulationEventTest.SetScreenOffset(offsetX, offsetY);
    auto FingersInfos = manipulationEventTest.GetFingersInfos();
    auto retY = FingersInfos->mMp.GetY();
    EXPECT_FLOAT_EQ(retY, offsetY);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerCount_Normal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 2;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags);
    auto retPointerCount = manipulationEventTest.GetPointerCount();
    EXPECT_EQ(retPointerCount, pointerCount);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerCount_Abnormal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 0xFFFFFFFF;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags);
    auto retPointerCount = manipulationEventTest.GetPointerCount();
    EXPECT_EQ(retPointerCount, 0);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerCount_Min, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = static_cast<int32_t>(0xFFFFFFFF);
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags);
    auto retPointerCount = manipulationEventTest.GetPointerCount();
    EXPECT_EQ(retPointerCount, 0);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerCount_Max, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 0x7FFFFFFF;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags);
    auto retPointerCount = manipulationEventTest.GetPointerCount();
    EXPECT_EQ(retPointerCount, 0);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerScreenPosition_Normal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    float x = 0.12f;
    float y = 0.21f;
    fingersInfos[2].mMp.Setxy(x, y);
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags);
    int32_t index = 2;
    auto retPointerPosition = manipulationEventTest.GetPointerScreenPosition(index);
    auto retY = retPointerPosition.GetY();
    EXPECT_FLOAT_EQ(retY, y);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerScreenPosition_Abnormal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    float x = 0.12f;
    float y = 0.21f;
    fingersInfos[2].mMp.Setxy(x, y);
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags);
    int32_t index = 1;
    auto retPointerPosition = manipulationEventTest.GetPointerScreenPosition(index);
    auto retY = retPointerPosition.GetY();
    EXPECT_FLOAT_EQ(retY, 0.0f);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerScreenPosition_Abnormal_Parameter, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    float x = 0.12f;
    float y = 0.21f;
    fingersInfos[2].mMp.Setxy(x, y);
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos,
        highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, deviceUdevTags);
    int32_t index = 0xFFFFFFFF;
    auto retPointerPosition = manipulationEventTest.GetPointerScreenPosition(index);
    auto retY = retPointerPosition.GetY();
    EXPECT_FLOAT_EQ(retY, 0.0f);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerId_Normal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    fingersInfos[2].mPointerId = 3;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    int32_t index = 2;
    auto retPointerId = manipulationEventTest.GetPointerId(index);
    EXPECT_EQ(retPointerId, fingersInfos[2].mPointerId);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerId_Anomalous, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    fingersInfos[2].mPointerId = 3;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    int32_t index = 11;
    auto retPointerId = manipulationEventTest.GetPointerId(index);
    EXPECT_EQ(retPointerId, -1);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerId_Min, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    fingersInfos[2].mPointerId = 3;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    int32_t index = static_cast<int32_t>(0xFFFFFFFF);
    auto retPointerId = manipulationEventTest.GetPointerId(index);
    EXPECT_EQ(retPointerId, -1);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetPointerId_Max, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    fingersInfos[2].mPointerId = 3;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    int32_t index = 0x7FFFFFFF;
    auto retPointerId = manipulationEventTest.GetPointerId(index);
    EXPECT_EQ(retPointerId, -1);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetForce_Normal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    fingersInfos[2].mTouchPressure = 1.5f;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    int32_t index = 2;
    auto retForce = manipulationEventTest.GetForce(index);
    EXPECT_FLOAT_EQ(retForce, fingersInfos[2].mTouchPressure);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetForce_Anomalous, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    fingersInfos[2].mTouchPressure = 1.5f;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    int32_t index = 11;
    auto retForce = manipulationEventTest.GetForce(index);
    EXPECT_FLOAT_EQ(retForce, 0.0f);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetForce_Min, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    fingersInfos[2].mTouchPressure = 1.5f;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    int32_t index = static_cast<int32_t>(0xFFFFFFFF);
    auto retForce = manipulationEventTest.GetForce(index);
    EXPECT_FLOAT_EQ(retForce, 0.0f);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetForce_Max, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    fingersInfos[2].mTouchPressure = 1.5f;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    int32_t index = 0x7FFFFFFF;
    auto retForce = manipulationEventTest.GetForce(index);
    EXPECT_FLOAT_EQ(retForce, 0.0f);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetRadius_Normal, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    fingersInfos[2].mTouchArea = 1.3f;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    int32_t index = 2;
    auto retRadius = manipulationEventTest.GetRadius(index);
    EXPECT_FLOAT_EQ(retRadius, fingersInfos[2].mTouchArea);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetRadius_Anomalous, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    fingersInfos[2].mTouchArea = 1.3f;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    int32_t index = 11;
    auto retRadius = manipulationEventTest.GetRadius(index);
    EXPECT_FLOAT_EQ(retRadius, 0.0f);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetRadius_Min, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    fingersInfos[2].mTouchArea = 1.3f;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    int32_t index = static_cast<int32_t>(0xFFFFFFFF);
    auto retRadius = manipulationEventTest.GetRadius(index);
    EXPECT_FLOAT_EQ(retRadius, 0.0f);
}

HWTEST_F(ManipulationEventApiTest, Api_Test_GetRadius_Max, TestSize.Level1)
{
    ManipulationEvent manipulationEventTest;
    int32_t windowId = 0;
    int32_t startTime = 100;
    int32_t operationState = 10;
    int32_t pointerCount = 3;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "1";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    fingersInfos[2].mTouchArea = 1.3f;
    manipulationEventTest.Initialize(windowId, startTime, operationState, pointerCount, fingersInfos, highLevelEvent,
        uuid, sourceType, occurredTime, deviceId, inputDeviceId, isHighLevelEvent, deviceUdevTags);
    int32_t index = 0x7FFFFFFF;
    auto retRadius = manipulationEventTest.GetRadius(index);
    EXPECT_FLOAT_EQ(retRadius, 0.0f);
}
} // namespace
