/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "event_statistic.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventStatisticTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t EVENT_OUT_SIZE { 30 };
} // namespace

class EventStatisticTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: EventDumpTest_ConvertInputEventToStr
 * @tc.desc: Event dump ConvertInputEventToStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertInputEventToStr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    auto inputEvent = std::make_shared<InputEvent>(3);
    inputEvent->eventType_ = 3;
    inputEvent->actionTime_ = 280000000;
    inputEvent->deviceId_ = 2;
    inputEvent->sourceType_ = 6;
    std::string str = "";
    str = eventStatistic.ConvertInputEventToStr(inputEvent);
    ASSERT_FALSE(str.empty());
}

/**
 * @tc.name: EventDumpTest_ConvertTimeToStr
 * @tc.desc: Event dump ConvertTimeToStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertTimeToStr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int64_t time = -1;
    std::string str = "";
    str = eventStatistic.ConvertTimeToStr(time);
    ASSERT_EQ(str, "1970-01-01 07:59:59");

    time = 280000000;
    str = eventStatistic.ConvertTimeToStr(time);
    ASSERT_EQ(str, "1978-11-16 01:46:40");
}

/**
 * @tc.name: EventDumpTest_PushPointerEvent
 * @tc.desc: Event dump PushPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushPointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->bitwise_ = 0x000040;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerEvent(pointerEvent));

    pointerEvent->SetAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerEvent(pointerEvent));
}

/**
 * @tc.name: EventDumpTest_PushEventStr
 * @tc.desc: Event dump PushEventStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushEventStr, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    eventStatistic.writeFileEnabled_ = true;
    std::string str = "test_push_event_str";
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushEventStr(str));
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushEvent(inputEvent));

    for (auto i = 0; i < EVENT_OUT_SIZE - 1; i++) {
        auto inputEvent1 = std::make_shared<InputEvent>(2);
        eventStatistic.dumperEventList_.push_back(EventStatistic::ConvertInputEventToStr(inputEvent1));
    }
    eventStatistic.writeFileEnabled_ = false;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushEventStr(str));
}

/**
 * @tc.name: EventDumpTest_Dump
 * @tc.desc: Event dump Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_Dump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int32_t fd = 0;
    std::vector<std::string> dumpStr;
    for (auto i = 0; i < 5; i++) {
        std::string str = "EventStatistic Test Dump ";
        eventStatistic.dumperEventList_.push_back(str);
        dumpStr.push_back(str);
    }
    ASSERT_NO_FATAL_FAILURE(eventStatistic.Dump(fd, dumpStr));
}

/**
 * @tc.name: EventDumpTest_PopEvent
 * @tc.desc: Event dump PopEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PopEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    auto inputEvent = std::make_shared<InputEvent>(3);
    eventStatistic.writeFileEnabled_ = true;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushEvent(inputEvent));
    std::string str = "";
    str = eventStatistic.PopEvent();
    ASSERT_TRUE(!str.empty());
}
} // OHOS
} // MMI