/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "input_event.h"
#include "mmi_log.h"
 
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEventTest"
 
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
 
class InputEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};
 
/**
 * @tc.name: InputEventTest_EventTypeToString_001
 * @tc.desc: Test EventTypeToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventTest, InputEventTest_EventTypeToString_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto InputEvent = InputEvent::Create();
    ASSERT_NE(InputEvent, nullptr);
    int32_t eventType = InputEvent::EVENT_TYPE_BASE;
    auto ret = InputEvent->EventTypeToString(eventType);
    ASSERT_STREQ(ret, "base");
    eventType = InputEvent::EVENT_TYPE_KEY;
    ret = InputEvent->EventTypeToString(eventType);
    ASSERT_STREQ(ret, "key");
    eventType = InputEvent::EVENT_TYPE_POINTER;
    ret = InputEvent->EventTypeToString(eventType);
    ASSERT_STREQ(ret, "pointer");
    eventType = InputEvent::EVENT_TYPE_AXIS;
    ret = InputEvent->EventTypeToString(eventType);
    ASSERT_STREQ(ret, "axis");
    eventType = InputEvent::EVENT_TYPE_FINGERPRINT;
    ret = InputEvent->EventTypeToString(eventType);
    ASSERT_STREQ(ret, "fingerprint");
    eventType = InputEvent::ACTION_CANCEL;
    ret = InputEvent->EventTypeToString(eventType);
    ASSERT_STREQ(ret, "unknown");
}

/**
 * @tc.name: InputEventTest_MarkProcessed_001
 * @tc.desc: Test MarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventTest, InputEventTest_MarkProcessed_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto InputEvent = InputEvent::Create();
    ASSERT_NE(InputEvent, nullptr);
    auto callback = [](int a, int b) {};
    InputEvent->processedCallback_ = callback;
    InputEvent->processedCallback_(10, 20);
    ASSERT_NE(InputEvent->processedCallback_, nullptr);
    InputEvent->markEnabled_ = false;
    ASSERT_NO_FATAL_FAILURE(InputEvent->MarkProcessed());
    InputEvent->markEnabled_ = true;
    ASSERT_NO_FATAL_FAILURE(InputEvent->MarkProcessed());
}

/**
 * @tc.name: InputEventTest_SetExtraData_001
 * @tc.desc: Test SetExtraData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventTest, InputEventTest_SetExtraData_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    auto InputEvent = InputEvent::Create();
    ASSERT_NE(InputEvent, nullptr);
    ASSERT_NO_FATAL_FAILURE(InputEvent->SetExtraData(nullptr, 0));
    ASSERT_NO_FATAL_FAILURE(InputEvent->SetExtraData(nullptr, 100));
    ASSERT_NO_FATAL_FAILURE(InputEvent->SetExtraData(nullptr, 1500));
    uint8_t datas[5] = {1, 2, 3, 4, 5};
    std::shared_ptr<const uint8_t[]> sharedData(datas, [](const uint8_t*) {});
    ASSERT_NE(sharedData, nullptr);
    ASSERT_NO_FATAL_FAILURE(InputEvent->SetExtraData(sharedData, 0));
    ASSERT_NO_FATAL_FAILURE(InputEvent->SetExtraData(sharedData, 100));
    ASSERT_NO_FATAL_FAILURE(InputEvent->SetExtraData(sharedData, 1500));
}

/**
 * @tc.name: InputEventTest_WriteToParcel_001
 * @tc.desc: Test WriteToParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventTest, InputEventTest_WriteToParcel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto InputEvent = InputEvent::Create();
    ASSERT_NE(InputEvent, nullptr);
    Parcel out;
    InputEvent->extraData_ = nullptr;
    InputEvent->extraDataLength_ = 0;
    bool ret = InputEvent->WriteToParcel(out);
    ASSERT_TRUE(ret);
    InputEvent->extraDataLength_ = 5;
    ret = InputEvent->WriteToParcel(out);
    ASSERT_TRUE(ret);
    uint8_t datas[5] = {1, 2, 3, 4, 5};
    std::shared_ptr<const uint8_t[]> sharedData(datas, [](const uint8_t*) {});
    InputEvent->extraData_ = sharedData;
    InputEvent->extraDataLength_ = 0;
    ret = InputEvent->WriteToParcel(out);
    ASSERT_TRUE(ret);
    InputEvent->extraDataLength_ = 5;
    ret = InputEvent->WriteToParcel(out);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InputEventTest_ReadFromParcel_001
 * @tc.desc: Test ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventTest, InputEventTest_ReadFromParcel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto InputEvent = InputEvent::Create();
    ASSERT_NE(InputEvent, nullptr);
    Parcel in;
    InputEvent->extraDataLength_ = 0;
    bool ret = InputEvent->ReadFromParcel(in);
    ASSERT_FALSE(ret);
    InputEvent->extraDataLength_ = 1050;
    ret = InputEvent->ReadFromParcel(in);
    ASSERT_FALSE(ret);
    InputEvent->extraDataLength_ = 10;
    ret = InputEvent->ReadFromParcel(in);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputEventTest_ActionToShortStr_001
 * @tc.desc: Test ActionToShortStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventTest, InputEventTest_ActionToShortStr_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto InputEvent = InputEvent::Create();
    ASSERT_NE(InputEvent, nullptr);
    int32_t action = InputEvent::ACTION_CANCEL;
    std::string_view ret = InputEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "B:C:");
    action = InputEvent::ACTION_UNKNOWN;
    ret = InputEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "B:UK:");
    action = InputEvent::EVENT_TYPE_AXIS;
    ret = InputEvent->ActionToShortStr(action);
    ASSERT_EQ(ret, "B:?:");
}

/**
 * @tc.name: InputEventTest_operator_001
 * @tc.desc: Test operator
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventTest, InputEventTest_operator_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LogTracer source1(300, 5, 6);
    LogTracer destination;
    destination = std::move(source1);
    LogTracer source2(400, 7, 8);
    destination = std::move(source2);
    auto InputEvent = InputEvent::Create();
    ASSERT_NE(InputEvent, nullptr);
    Parcel in;
    InputEvent->extraDataLength_ = 0;
    bool ret = InputEvent->ReadFromParcel(in);
    ASSERT_FALSE(ret);
}
} // namespace MMI
} // namespace OHOS