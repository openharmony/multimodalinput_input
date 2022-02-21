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

#include "multimodal_event.h"
#include <gtest/gtest.h>
#include "struct_multimodal.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MMI;

class MultimodalEventApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(MultimodalEventApiTest, Api_Test_IsSameEvent_Normal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    const std::string id = "aEvent";
    auto isTrue = multimodalEventTest.IsSameEvent(id);
    EXPECT_TRUE(isTrue == true);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_IsSameEvent_Abnormal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    const std::string id = "bEvent";
    auto isTrue = multimodalEventTest.IsSameEvent(id);
    EXPECT_TRUE(isTrue == false);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_IsHighLevelInput_Normal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retHighLevelInput = multimodalEventTest.IsHighLevelInput();
    EXPECT_EQ(retHighLevelInput, isHighLevelEvent);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_IsHighLevelInput_Abnormal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = false;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retHighLevelInput = multimodalEventTest.IsHighLevelInput();
    EXPECT_EQ(retHighLevelInput, isHighLevelEvent);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetHighLevelEvent_Normal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retHighLevelEvent = multimodalEventTest.GetHighLevelEvent();
    EXPECT_EQ(retHighLevelEvent, highLevelEvent);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetHighLevelEvent_Abnormal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 0xFFFFFFFF;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retHighLevelEvent = multimodalEventTest.GetHighLevelEvent();
    EXPECT_EQ(retHighLevelEvent, highLevelEvent);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetHighLevelEvent_Min, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = static_cast<int32_t>(0xFFFFFFFF);
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retHighLevelEvent = multimodalEventTest.GetHighLevelEvent();
    EXPECT_EQ(retHighLevelEvent, highLevelEvent);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetHighLevelEvent_Max, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 0x7FFFFFFF;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retHighLevelEvent = multimodalEventTest.GetHighLevelEvent();
    EXPECT_EQ(retHighLevelEvent, highLevelEvent);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetSourceDevice_Normal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = DEVICE_TYPE_KEYBOARD;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retSourceDevice = multimodalEventTest.GetSourceDevice();
    EXPECT_EQ(retSourceDevice, KEYBOARD);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetSourceDevice_Abnormal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0xFFFFFFFF;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retSourceDevice = multimodalEventTest.GetSourceDevice();
    EXPECT_EQ(retSourceDevice, UNSUPPORTED_DEVICE);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetSourceDevice_Min, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = static_cast<int32_t>(0xFFFFFFFF);
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retSourceDevice = multimodalEventTest.GetSourceDevice();
    EXPECT_EQ(retSourceDevice, UNSUPPORTED_DEVICE);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetSourceDevice_Max, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0x7FFFFFFF;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retSourceDevice = multimodalEventTest.GetSourceDevice();
    EXPECT_EQ(retSourceDevice, UNSUPPORTED_DEVICE);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetDeviceId_Normal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "bDevice";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = DEVICE_TYPE_UNKNOWN;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retDeviceId = multimodalEventTest.GetDeviceId();
    EXPECT_EQ(retDeviceId, deviceId);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetDeviceId_Abnormal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "error";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = DEVICE_TYPE_UNKNOWN;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retDeviceId = multimodalEventTest.GetDeviceId();
    EXPECT_EQ(retDeviceId, deviceId);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetDeviceId_NULL, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = DEVICE_TYPE_UNKNOWN;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retDeviceId = multimodalEventTest.GetDeviceId();
    EXPECT_EQ(retDeviceId, deviceId);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetDeviceId_ERROR, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "ERROR";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = DEVICE_TYPE_UNKNOWN;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retDeviceId = multimodalEventTest.GetDeviceId();
    EXPECT_EQ(retDeviceId, deviceId);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetInputDeviceId_Normal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "bDevice";
    int32_t inputDeviceId = 10;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = DEVICE_TYPE_UNKNOWN;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retDeviceId = multimodalEventTest.GetInputDeviceId();
    EXPECT_EQ(retDeviceId, inputDeviceId);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetInputDeviceId_Abnormal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "bDevice";
    int32_t inputDeviceId = 0xFFFFFFFF;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = DEVICE_TYPE_UNKNOWN;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retDeviceId = multimodalEventTest.GetInputDeviceId();
    EXPECT_EQ(retDeviceId, inputDeviceId);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetInputDeviceId_Min, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "bDevice";
    int32_t inputDeviceId = static_cast<int32_t>(0xFFFFFFFF);
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = DEVICE_TYPE_UNKNOWN;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retDeviceId = multimodalEventTest.GetInputDeviceId();
    EXPECT_EQ(retDeviceId, inputDeviceId);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetInputDeviceId_Max, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "bDevice";
    int32_t inputDeviceId = 0x7FFFFFFF;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = DEVICE_TYPE_UNKNOWN;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retDeviceId = multimodalEventTest.GetInputDeviceId();
    EXPECT_EQ(retDeviceId, inputDeviceId);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetOccurredTime_Normal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 100;
    const std::string deviceId = "bDevice";
    int32_t inputDeviceId = 10;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = DEVICE_TYPE_UNKNOWN;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retOccurredTime = multimodalEventTest.GetOccurredTime();
    EXPECT_EQ(retOccurredTime, occurredTime);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetOccurredTime_Abnormal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0xFFFFFFFFFFFFFFFF;
    const std::string deviceId = "bDevice";
    int32_t inputDeviceId = 10;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = DEVICE_TYPE_UNKNOWN;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retOccurredTime = multimodalEventTest.GetOccurredTime();
    EXPECT_EQ(retOccurredTime, occurredTime);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetOccurredTime_Min, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "bDevice";
    int32_t inputDeviceId = 10;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = DEVICE_TYPE_UNKNOWN;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retOccurredTime = multimodalEventTest.GetOccurredTime();
    EXPECT_EQ(retOccurredTime, occurredTime);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetWindowID_Normal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 105;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 10;
    uint64_t occurredTime = 100;
    const std::string deviceId = "bDevice";
    int32_t inputDeviceId = 10;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 10;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retWindowID = multimodalEventTest.GetWindowID();
    EXPECT_EQ(retWindowID, windowId);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetWindowID_Abnormal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0xFFFFFFFF;
    int32_t highLevelEvent = 10;
    const std::string uuid = "aEvent";
    int32_t sourceType = 10;
    uint64_t occurredTime = 100;
    const std::string deviceId = "bDevice";
    int32_t inputDeviceId = 10;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 10;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retWindowID = multimodalEventTest.GetWindowID();
    EXPECT_EQ(retWindowID, windowId);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetUuid_Normal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "aEvent";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retUuid = multimodalEventTest.GetUuid();
    EXPECT_EQ(retUuid, uuid);
}

HWTEST_F(MultimodalEventApiTest, Api_Test_GetUuid_Abnormal, TestSize.Level1)
{
    MultimodalEvent multimodalEventTest;
    int32_t windowId = 0;
    int32_t highLevelEvent = 0;
    const std::string uuid = "Error";
    int32_t sourceType = 0;
    uint64_t occurredTime = 0;
    const std::string deviceId = "b";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    multimodalEventTest.Initialize(windowId, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retUuid = multimodalEventTest.GetUuid();
    EXPECT_EQ(retUuid, uuid);
}
} // namespace
