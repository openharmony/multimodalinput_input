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
#include "touch_event.h"

namespace {
using namespace testing::ext;
using namespace OHOS;

class TouchEventApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(TouchEventApiTest, Api_Test_GetOriginEventType_Normal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 0;
    int32_t index = 0;
    float forcePrecision = 0.0f;
    float maxForce = 0.0f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retOriginEventType = touchEventTest.GetOriginEventType();
    EXPECT_EQ(retOriginEventType, deviceEventType);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetOriginEventType_Abnormal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 0;
    int32_t index = 0;
    float forcePrecision = 0.0f;
    float maxForce = 0.0f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 0xFFFFFFFF;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retOriginEventType = touchEventTest.GetOriginEventType();
    EXPECT_EQ(retOriginEventType, deviceEventType);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetMultimodalEvent_Normal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 10;
    MultimodalEventPtr deviceEvent = &multimodalEventTest;
    int32_t deviceEventType = 0;
    int32_t action = 0;
    int32_t index = 0;
    float forcePrecision = 0.0f;
    float maxForce = 0.0f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    bool isStandard = true;
    touchEventTest.Initialize(windowId, deviceEvent, deviceEventType, action, index, forcePrecision, maxForce, tapCount,
        startTime, operationState, pointerCount, fingersInfos, isStandard);
    auto retMultimodalEvent = touchEventTest.GetMultimodalEvent();
    EXPECT_TRUE(retMultimodalEvent == (&multimodalEventTest));
}

HWTEST_F(TouchEventApiTest, Api_Test_GetMultimodalEvent_Abnormal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 10;
    MultimodalEventPtr deviceEvent = nullptr;
    int32_t deviceEventType = 0;
    int32_t action = 0;
    int32_t index = 0;
    float forcePrecision = 0.0f;
    float maxForce = 0.0f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    bool isStandard = true;
    touchEventTest.Initialize(windowId, deviceEvent, deviceEventType, action, index, forcePrecision, maxForce, tapCount,
        startTime, operationState, pointerCount, fingersInfos, isStandard);
    auto retMultimodalEvent = touchEventTest.GetMultimodalEvent();
    EXPECT_TRUE(retMultimodalEvent == nullptr);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetAction_Normal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 5;
    int32_t index = 0;
    float forcePrecision = 0.0f;
    float maxForce = 0.0f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retAction = touchEventTest.GetAction();
    EXPECT_EQ(retAction, action);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetAction_Abnormal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 0xFFFFFFFF;
    int32_t index = 0;
    float forcePrecision = 0.0f;
    float maxForce = 0.0f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retAction = touchEventTest.GetAction();
    EXPECT_EQ(retAction, action);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetIndex_Normal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 5;
    int32_t index = 10;
    float forcePrecision = 0.0f;
    float maxForce = 0.0f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retIndex = touchEventTest.GetIndex();
    EXPECT_EQ(retIndex, index);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetIndex_Abnormal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 5;
    int32_t index = 0xFFFFFFFF;
    float forcePrecision = 0.0f;
    float maxForce = 0.0f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retIndex = touchEventTest.GetIndex();
    EXPECT_EQ(retIndex, index);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetForcePrecision_Normal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 5;
    int32_t index = 10;
    float forcePrecision = 0.3f;
    float maxForce = 0.0f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retForcePrecision = touchEventTest.GetForcePrecision();
    EXPECT_FLOAT_EQ(retForcePrecision, forcePrecision);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetForcePrecision_Abnormal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 5;
    int32_t index = 10;
    float forcePrecision = 0.0f;
    float maxForce = 0.0f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retForcePrecision = touchEventTest.GetForcePrecision();
    EXPECT_FLOAT_EQ(retForcePrecision, forcePrecision);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetMaxForce_Normal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 5;
    int32_t index = 10;
    float forcePrecision = 0.3f;
    float maxForce = 0.7f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retMaxForce = touchEventTest.GetMaxForce();
    EXPECT_FLOAT_EQ(retMaxForce, maxForce);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetMaxForce_Abnormal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 5;
    int32_t index = 10;
    float forcePrecision = 0.3f;
    float maxForce = 0.0f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retMaxForce = touchEventTest.GetMaxForce();
    EXPECT_FLOAT_EQ(retMaxForce, maxForce);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetTapCount_Normal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 5;
    int32_t index = 10;
    float forcePrecision = 0.3f;
    float maxForce = 0.7f;
    float tapCount = 1.5f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retTapCount = touchEventTest.GetTapCount();
    EXPECT_FLOAT_EQ(retTapCount, tapCount);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetTapCount_Abnormal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 5;
    int32_t index = 10;
    float forcePrecision = 0.3f;
    float maxForce = 0.7f;
    float tapCount = 0.0f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retTapCount = touchEventTest.GetTapCount();
    EXPECT_FLOAT_EQ(retTapCount, tapCount);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetPointToolType_Normal, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 5;
    int32_t index = TABLET_TOOL_TYPE_ERASER;
    float forcePrecision = 0.3f;
    float maxForce = 0.7f;
    float tapCount = 1.5f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retPointToolType = touchEventTest.GetPointToolType(index);
    EXPECT_EQ(retPointToolType, BUTTON_TOOL_RUBBER);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetPointToolType_Anomalous_IndexOutside, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 5;
    int32_t index = -1;
    float forcePrecision = 0.3f;
    float maxForce = 0.7f;
    float tapCount = 1.5f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retPointToolType = touchEventTest.GetPointToolType(index);
    EXPECT_EQ(retPointToolType, 0);
}

HWTEST_F(TouchEventApiTest, Api_Test_GetPointToolType_Anomalous_IndexAnomalous, TestSize.Level1)
{
    TouchEvent touchEventTest;
    int32_t windowId = 0;
    int32_t action = 5;
    int32_t index = 100;
    float forcePrecision = 0.3f;
    float maxForce = 0.7f;
    float tapCount = 1.5f;
    int32_t startTime = 0;
    int32_t operationState = 0;
    int32_t pointerCount = 0;
    fingerInfos fingersInfos[FINGER_NUM] = {};
    int32_t highLevelEvent = 0;
    const std::string uuid = "a";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    bool isStandard = true;
    uint16_t deviceUdevTags = 0;
    int32_t deviceEventType = 10;
    touchEventTest.Initialize(windowId, action, index, forcePrecision, maxForce, tapCount, startTime, operationState,
        pointerCount, fingersInfos, highLevelEvent, uuid, sourceType, occurredTime, deviceId, inputDeviceId,
        isHighLevelEvent, isStandard, deviceUdevTags, deviceEventType);
    auto retPointToolType = touchEventTest.GetPointToolType(index);
    EXPECT_EQ(retPointToolType, 0);
}
} // namespace
