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

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MMI;

class MultimodalEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

MultimodalEvent multiModalEvent;
HWTEST_F(MultimodalEventTest, Initialize_001, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevelEvent = 1;
    std::string strUuid = "1";
    int32_t sourceType = 1;
    int32_t occurredTime = 1;
    std::string deviceId = "1";
    int32_t inputDeviceId = 1;
    bool isHighLevelEvent = false;
    multiModalEvent.Initialize(windowId, highLevelEvent, strUuid, sourceType, occurredTime,
                               deviceId, inputDeviceId, isHighLevelEvent);
}

HWTEST_F(MultimodalEventTest, Initialize_002, TestSize.Level1)
{
    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(2, 2, "2", 2, 2, "2", 2, true);
}

HWTEST_F(MultimodalEventTest, Initialize_003, TestSize.Level1)
{
    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(multiModalEvent);
}

HWTEST_F(MultimodalEventTest, GetUuid_001, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetUuid();
    ASSERT_STREQ(retResult.c_str(), "1");
}

HWTEST_F(MultimodalEventTest, GetUuid_002, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetUuid();
    ASSERT_STRNE(retResult.c_str(), "2");
}

HWTEST_F(MultimodalEventTest, GetUuid_003, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetUuid();
    ASSERT_STRNE(retResult.c_str(), "2word");
}

HWTEST_F(MultimodalEventTest, GetUuid_004, TestSize.Level1)

{
    std::string retResult = multiModalEvent.GetUuid();
    ASSERT_STRNE(retResult.c_str(), "three word");
}

HWTEST_F(MultimodalEventTest, GetOccurredTime_001, TestSize.Level1)
{
    uint64_t retResult = multiModalEvent.GetOccurredTime();
    EXPECT_TRUE(retResult == 1);
}

HWTEST_F(MultimodalEventTest, GetOccurredTime_002, TestSize.Level1)
{
    uint64_t retResult = multiModalEvent.GetOccurredTime();
    EXPECT_FALSE(retResult == 2);
}

HWTEST_F(MultimodalEventTest, GetInputDeviceId_001, TestSize.Level1)
{
    int32_t retResult = multiModalEvent.GetInputDeviceId();
    EXPECT_TRUE(retResult == 1);
}

HWTEST_F(MultimodalEventTest, GetInputDeviceId_002, TestSize.Level1)
{
    int32_t retResult = multiModalEvent.GetInputDeviceId();
    EXPECT_FALSE(retResult == 2);
}

HWTEST_F(MultimodalEventTest, GetDeviceId_001, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetDeviceId();
    ASSERT_STREQ(retResult.c_str(), "1");
}

HWTEST_F(MultimodalEventTest, GetDeviceId_002, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetDeviceId();
    ASSERT_STRNE(retResult.c_str(), "2");
}

HWTEST_F(MultimodalEventTest, GetDeviceId_003, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetDeviceId();
    ASSERT_STRNE(retResult.c_str(), "2line");
}

HWTEST_F(MultimodalEventTest, GetDeviceId_004, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetDeviceId();
    ASSERT_STRNE(retResult.c_str(), "line2");
}

HWTEST_F(MultimodalEventTest, GetSourceDevice_001, TestSize.Level1)
{
    int32_t retResult = multiModalEvent.GetSourceDevice();
    EXPECT_TRUE(retResult == 1);
}

HWTEST_F(MultimodalEventTest, GetSourceDevice_002, TestSize.Level1)
{
    int32_t retResult = multiModalEvent.GetSourceDevice();
    EXPECT_FALSE(retResult == 2);
}

HWTEST_F(MultimodalEventTest, GetHighLevelEvent_001, TestSize.Level1)
{
    int32_t retResult = multiModalEvent.GetHighLevelEvent();
    EXPECT_TRUE(retResult == 1);
}

HWTEST_F(MultimodalEventTest, GetHighLevelEvent_002, TestSize.Level1)
{
    int32_t retResult = multiModalEvent.GetHighLevelEvent();
    EXPECT_FALSE(retResult == 2);
}

HWTEST_F(MultimodalEventTest, IsHighLevelInput, TestSize.Level1)
{
    bool retResult = multiModalEvent.IsHighLevelInput();
    EXPECT_FALSE(retResult);
}

HWTEST_F(MultimodalEventTest, IsSameEvent_001, TestSize.Level1)
{
    bool retResult = multiModalEvent.IsSameEvent("1");
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalEventTest, IsSameEvent_002, TestSize.Level1)
{
    bool retResult = multiModalEvent.IsSameEvent("2");
    EXPECT_FALSE(retResult);
}

HWTEST_F(MultimodalEventTest, marshalling, TestSize.Level1)
{
    bool retResult = multiModalEvent.marshalling();
    EXPECT_FALSE(retResult);
}

HWTEST_F(MultimodalEventTest, unmarshalling, TestSize.Level1)
{
    bool retResult = multiModalEvent.unmarshalling();
    EXPECT_FALSE(retResult);
}

HWTEST_F(MultimodalEventTest, Initialize_L, TestSize.Level1)
{
    multiModalEvent.Initialize(9, 9, "999", 9, 9, "999", 9, true);
}

HWTEST_F(MultimodalEventTest, GetUuid_L_001, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetUuid();
    ASSERT_STREQ(retResult.c_str(), "999");
}

HWTEST_F(MultimodalEventTest, GetUuid_L_002, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetUuid();
    ASSERT_STRNE(retResult.c_str(), "77");
}

HWTEST_F(MultimodalEventTest, GetUuid_L_003, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetUuid();
    ASSERT_STRNE(retResult.c_str(), "three");
}

HWTEST_F(MultimodalEventTest, GetUuid_L_004, TestSize.Level1)

{
    std::string retResult = multiModalEvent.GetUuid();
    ASSERT_STRNE(retResult.c_str(), "wo33rd");
}

HWTEST_F(MultimodalEventTest, GetOccurredTime_L_001, TestSize.Level1)
{
    uint64_t retResult = multiModalEvent.GetOccurredTime();
    EXPECT_TRUE(retResult == 9);
}

HWTEST_F(MultimodalEventTest, GetOccurredTime_L_002, TestSize.Level1)
{
    uint64_t retResult = multiModalEvent.GetOccurredTime();
    EXPECT_FALSE(retResult == 7);
}

HWTEST_F(MultimodalEventTest, GetInputDeviceId_L_001, TestSize.Level1)
{
    int32_t retResult = multiModalEvent.GetInputDeviceId();
    EXPECT_TRUE(retResult == 9);
}

HWTEST_F(MultimodalEventTest, GetInputDeviceId_L_002, TestSize.Level1)
{
    int32_t retResult = multiModalEvent.GetInputDeviceId();
    EXPECT_FALSE(retResult == 8);
}

HWTEST_F(MultimodalEventTest, GetDeviceId_L_001, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetDeviceId();
    ASSERT_STREQ(retResult.c_str(), "999");
}

HWTEST_F(MultimodalEventTest, GetDeviceId_L_002, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetDeviceId();
    ASSERT_STRNE(retResult.c_str(), "77");
}

HWTEST_F(MultimodalEventTest, GetDeviceId_L_003, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetDeviceId();
    ASSERT_STRNE(retResult.c_str(), "77data");
}

HWTEST_F(MultimodalEventTest, GetDeviceId_L_004, TestSize.Level1)
{
    std::string retResult = multiModalEvent.GetDeviceId();
    ASSERT_STRNE(retResult.c_str(), "da554");
}

HWTEST_F(MultimodalEventTest, _L_001, TestSize.Level1)
{
    int32_t retResult = multiModalEvent.GetSourceDevice();
    EXPECT_TRUE(retResult == 9);
}

HWTEST_F(MultimodalEventTest, _L_002, TestSize.Level1)
{
    int32_t retResult = multiModalEvent.GetSourceDevice();
    EXPECT_FALSE(retResult == 55);
}

HWTEST_F(MultimodalEventTest, GetHighLevelEvent_L_001, TestSize.Level1)
{
    int32_t retResult = multiModalEvent.GetHighLevelEvent();
    EXPECT_TRUE(retResult == 9);
}

HWTEST_F(MultimodalEventTest, GetHighLevelEvent_L_002, TestSize.Level1)
{
    int32_t retResult = multiModalEvent.GetHighLevelEvent();
    EXPECT_FALSE(retResult == 99);
}

HWTEST_F(MultimodalEventTest, IsHighLevelInput_L, TestSize.Level1)
{
    bool retResult = multiModalEvent.IsHighLevelInput();
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalEventTest, IsSameEvent_L_001, TestSize.Level1)
{
    bool retResult = multiModalEvent.IsSameEvent("999");
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalEventTest, IsSameEvent_L_002, TestSize.Level1)
{
    bool retResult = multiModalEvent.IsSameEvent("888");
    EXPECT_FALSE(retResult);
}

HWTEST_F(MultimodalEventTest, marshalling_L, TestSize.Level1)
{
    bool retResult = multiModalEvent.marshalling();
    EXPECT_FALSE(retResult);
}

HWTEST_F(MultimodalEventTest, unmarshalling_L, TestSize.Level1)
{
    bool retResult = multiModalEvent.unmarshalling();
    EXPECT_FALSE(retResult);
}

HWTEST_F(MultimodalEventTest, IsSameEvent_TMP_001, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 1;
    std::string strUuid = "2342";
    int32_t sourceType = 1;
    int32_t occurredTime = 1;
    std::string deviceId = "1";
    int32_t inputDeviceId = 1;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    bool retResult = multiModalEventTmp.IsSameEvent(strUuid);
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalEventTest, IsSameEvent_TMP_002, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "uuid_3356";
    int32_t sourceType = 25;
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    bool retResult = multiModalEventTmp.IsSameEvent(strUuid);
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalEventTest, IsSameEvent_TMP_003, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "-number -a&d";
    int32_t sourceType = 25;
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    bool retResult = multiModalEventTmp.IsSameEvent(strUuid);
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalEventTest, IsSameEvent_TMP_004, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "uuid_1001";
    int32_t sourceType = 25;
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    bool retResult = multiModalEventTmp.IsSameEvent("uuid_1001 ");
    EXPECT_FALSE(retResult);
}

HWTEST_F(MultimodalEventTest, IsHighLevelInput_TMP_001, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 1;
    std::string strUuid = "2342";
    int32_t sourceType = 1;
    int32_t occurredTime = 1;
    std::string deviceId = "1";
    int32_t inputDeviceId = 1;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    bool retResult = multiModalEventTmp.IsHighLevelInput();
    EXPECT_FALSE(retResult);
}

HWTEST_F(MultimodalEventTest, IsHighLevelInput_TMP_002, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "uuid_3356";
    int32_t sourceType = 25;
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = true;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    bool retResult = multiModalEventTmp.IsHighLevelInput();
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalEventTest, GetHighLevelEvent_TMP_001, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = -65535;
    std::string strUuid = "2342";
    int32_t sourceType = 1;
    int32_t occurredTime = 1;
    std::string deviceId = "1";
    int32_t inputDeviceId = 1;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    int32_t retResult = multiModalEventTmp.GetHighLevelEvent();
    EXPECT_EQ(retResult, highLevel);
}

HWTEST_F(MultimodalEventTest, GetHighLevelEvent_TMP_002, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 65535;
    std::string strUuid = "uuid_3356";
    int32_t sourceType = 25;
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    int32_t retResult = multiModalEventTmp.GetHighLevelEvent();
    EXPECT_EQ(retResult, highLevel);
}

HWTEST_F(MultimodalEventTest, GetHighLevelEvent_TMP_003, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = static_cast<int32_t>('a');
    std::string strUuid = "-number -a&d";
    int32_t sourceType = 25;
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    int32_t retResult = multiModalEventTmp.GetHighLevelEvent();
    EXPECT_EQ(retResult, highLevel);
}

HWTEST_F(MultimodalEventTest, GetHighLevelEvent_TMP_004, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = static_cast<int32_t>('a') + static_cast<int32_t>('s');
    std::string strUuid = "uuid_1001";
    int32_t sourceType = 25;
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    int32_t retResult = multiModalEventTmp.GetHighLevelEvent();
    EXPECT_EQ(retResult, highLevel);
}

HWTEST_F(MultimodalEventTest, GetSourceDevice_TMP_001, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 1;
    std::string strUuid = "555";
    int32_t sourceType = -65535;
    int32_t occurredTime = 1;
    std::string deviceId = "1";
    int32_t inputDeviceId = 1;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    bool retResult = multiModalEventTmp.GetSourceDevice();
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalEventTest, GetSourceDevice_TMP_002, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "555";
    int32_t sourceType = 65535;
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    bool retResult = multiModalEventTmp.GetSourceDevice();
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalEventTest, GetSourceDevice_TMP_003, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "555";
    int32_t sourceType = static_cast<int32_t>('b');
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    bool retResult = multiModalEventTmp.GetSourceDevice();
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalEventTest, GetSourceDevice_TMP_004, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "555";
    int32_t sourceType = static_cast<int32_t>('d') + static_cast<int32_t>('s');
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    bool retResult = multiModalEventTmp.GetSourceDevice();
    EXPECT_TRUE(retResult);
}

HWTEST_F(MultimodalEventTest, GetDeviceId_TMP_001, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 1;
    std::string strUuid = "555";
    int32_t sourceType = -65535;
    int32_t occurredTime = 1;
    std::string deviceId = "-65535";
    int32_t inputDeviceId = 1;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    std::string retResult = multiModalEventTmp.GetDeviceId();
    EXPECT_STREQ(retResult.c_str(), deviceId.c_str());
}

HWTEST_F(MultimodalEventTest, GetDeviceId_TMP_002, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "555";
    int32_t sourceType = 65535;
    int32_t occurredTime = 25;
    std::string deviceId = "uuid_3356";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    std::string retResult = multiModalEventTmp.GetDeviceId();
    EXPECT_STREQ(retResult.c_str(), deviceId.c_str());
}

HWTEST_F(MultimodalEventTest, GetDeviceId_TMP_003, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "555";
    int32_t sourceType = static_cast<int32_t>('b');
    int32_t occurredTime = 25;
    std::string deviceId = "-number -a&d";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    std::string retResult = multiModalEventTmp.GetDeviceId();
    EXPECT_STREQ(retResult.c_str(), deviceId.c_str());
}

HWTEST_F(MultimodalEventTest, GetDeviceId_TMP_004, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "555";
    int32_t sourceType = static_cast<int32_t>('d') + static_cast<int32_t>('s');
    int32_t occurredTime = 25;
    std::string deviceId = "uuid_1001";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    std::string retResult = multiModalEventTmp.GetDeviceId();
    EXPECT_STREQ(retResult.c_str(), deviceId.c_str());
}

HWTEST_F(MultimodalEventTest, GetInputDeviceId_TMP_001, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 1;
    std::string strUuid = "555";
    int32_t sourceType = -65535;
    int32_t occurredTime = 1;
    std::string deviceId = "1";
    int32_t inputDeviceId = -65535;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    int32_t retResult = multiModalEventTmp.GetInputDeviceId();
    EXPECT_EQ(retResult, inputDeviceId);
}

HWTEST_F(MultimodalEventTest, GetInputDeviceId_TMP_002, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "555";
    int32_t sourceType = 65535;
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = 65535;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    int32_t retResult = multiModalEventTmp.GetInputDeviceId();
    EXPECT_EQ(retResult, inputDeviceId);
}

HWTEST_F(MultimodalEventTest, GetInputDeviceId_TMP_003, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "555";
    int32_t sourceType = static_cast<int32_t>('b');
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = static_cast<int32_t>('h');
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    int32_t retResult = multiModalEventTmp.GetInputDeviceId();
    EXPECT_EQ(retResult, inputDeviceId);
}

HWTEST_F(MultimodalEventTest, GetInputDeviceId_TMP_004, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "555";
    int32_t sourceType = static_cast<int32_t>('d') + static_cast<int32_t>('s');
    int32_t occurredTime = 25;
    std::string deviceId = "25";
    int32_t inputDeviceId = static_cast<int32_t>('d') + static_cast<int32_t>('s');
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    int32_t retResult = multiModalEventTmp.GetInputDeviceId();
    EXPECT_EQ(retResult, inputDeviceId);
}

HWTEST_F(MultimodalEventTest, GetOccurredTime_TMP_001, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 1;
    std::string strUuid = "555";
    int32_t sourceType = -65535;
    uint64_t occurredTime = -65535;
    std::string deviceId = "1";
    int32_t inputDeviceId = -65535;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    uint64_t retResult = multiModalEventTmp.GetOccurredTime();
    EXPECT_EQ(retResult, occurredTime);
}

HWTEST_F(MultimodalEventTest, GetOccurredTime_TMP_002, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "555";
    int32_t sourceType = 65535;
    uint64_t occurredTime = 65535;
    std::string deviceId = "25";
    int32_t inputDeviceId = 65535;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    uint64_t retResult = multiModalEventTmp.GetOccurredTime();
    EXPECT_EQ(retResult, occurredTime);
}

HWTEST_F(MultimodalEventTest, GetOccurredTime_TMP_003, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "555";
    int32_t sourceType = static_cast<int32_t>('b');
    uint64_t occurredTime = static_cast<int32_t>('s');
    std::string deviceId = "25";
    int32_t inputDeviceId = static_cast<int32_t>('h');
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    uint64_t retResult = multiModalEventTmp.GetOccurredTime();
    EXPECT_EQ(retResult, occurredTime);
}

HWTEST_F(MultimodalEventTest, GetOccurredTime_TMP_004, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "555";
    int32_t sourceType = static_cast<int32_t>('d') + static_cast<int32_t>('s');
    uint64_t occurredTime = static_cast<int32_t>('d') + static_cast<int32_t>('s');
    std::string deviceId = "25";
    int32_t inputDeviceId = static_cast<int32_t>('d') + static_cast<int32_t>('s');
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    uint64_t retResult = multiModalEventTmp.GetOccurredTime();
    EXPECT_EQ(retResult, occurredTime);
}

HWTEST_F(MultimodalEventTest, GetUuid_TMP_001, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 1;
    std::string strUuid = "555";
    int32_t sourceType = -65535;
    int32_t occurredTime = 1;
    std::string deviceId = "-65535";
    int32_t inputDeviceId = 1;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    std::string retResult = multiModalEventTmp.GetUuid();
    EXPECT_STREQ(retResult.c_str(), strUuid.c_str());
}

HWTEST_F(MultimodalEventTest, GetUuid_TMP_002, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "uuid_3356";
    int32_t sourceType = 65535;
    int32_t occurredTime = 25;
    std::string deviceId = "uuid_3356";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    std::string retResult = multiModalEventTmp.GetUuid();
    EXPECT_STREQ(retResult.c_str(), strUuid.c_str());
}

HWTEST_F(MultimodalEventTest, GetUuid_TMP_003, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "-number -a&d";
    int32_t sourceType = static_cast<int32_t>('b');
    int32_t occurredTime = 25;
    std::string deviceId = "-number -a&d";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    std::string retResult = multiModalEventTmp.GetUuid();
    EXPECT_STREQ(retResult.c_str(), strUuid.c_str());
}

HWTEST_F(MultimodalEventTest, GetUuid_TMP_004, TestSize.Level1)
{
    int32_t windowId = 1;
    int32_t highLevel = 25;
    std::string strUuid = "uuid_1001";
    int32_t sourceType = static_cast<int32_t>('d') + static_cast<int32_t>('s');
    int32_t occurredTime = 25;
    std::string deviceId = "uuid_1001";
    int32_t inputDeviceId = 25;
    bool isHighLevelEvent = false;

    MultimodalEvent multiModalEventTmp;
    multiModalEventTmp.Initialize(windowId, highLevel, strUuid, sourceType, occurredTime,
                                  deviceId, inputDeviceId, isHighLevelEvent);
    std::string retResult = multiModalEventTmp.GetUuid();
    EXPECT_STREQ(retResult.c_str(), strUuid.c_str());
}
} // namespace
