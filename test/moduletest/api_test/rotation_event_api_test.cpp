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

#include "rotation_event.h"
#include <gtest/gtest.h>

namespace {
using namespace testing::ext;
using namespace OHOS;

class RotationEventApiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

HWTEST_F(RotationEventApiTest, Api_Test_GetRotationValue_Normal, TestSize.Level1)
{
    RotationEvent rotationEventTest;
    int32_t windowId = 0;
    float rotationValue = 0.154f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "q";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "a";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    rotationEventTest.Initialize(windowId, rotationValue, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retRotationValue = rotationEventTest.GetRotationValue();
    EXPECT_EQ(retRotationValue, rotationValue);
}

HWTEST_F(RotationEventApiTest, Api_Test_GetRotationValue_Abnormal, TestSize.Level1)
{
    RotationEvent rotationEventTest;
    int32_t windowId = 0;
    float rotationValue = 0.0f;
    int32_t highLevelEvent = 0;
    const std::string uuid = "q";
    int32_t sourceType = 0;
    int32_t occurredTime = 0;
    const std::string deviceId = "a";
    int32_t inputDeviceId = 0;
    bool isHighLevelEvent = true;
    uint16_t deviceUdevTags = 0;
    rotationEventTest.Initialize(windowId, rotationValue, highLevelEvent, uuid, sourceType, occurredTime, deviceId,
        inputDeviceId, isHighLevelEvent, deviceUdevTags);
    auto retRotationValue = rotationEventTest.GetRotationValue();
    EXPECT_EQ(retRotationValue, rotationValue);
}
} // namespace
