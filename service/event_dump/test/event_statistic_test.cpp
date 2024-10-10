/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <gtest/gtest.h>

#include "event_statistic.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventStatisticTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

class EventStatisticTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void EventStatisticTest::SetUpTestCase(void)
{}

void EventStatisticTest::TearDownTestCase(void)
{}

void EventStatisticTest::SetUp()
{}

void EventStatisticTest::TearDown()
{}

/**
 * @tc.name: EventStatisticTest_PushPointerEvent_01
 * @tc.desc: Test PushPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushPointerEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_MOVE;
    pointerEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerEvent(pointerEvent));
}

/**
 * @tc.name: EventStatisticTest_PushPointerEvent_02
 * @tc.desc: Test PushPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushPointerEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_UP;
    pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE);
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushPointerEvent(pointerEvent));
}

/**
 * @tc.name: EventStatisticTest_PopEvent_02
 * @tc.desc: Test PopEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PopEvent_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    eventStatistic.eventQueue_.push("event1");
    eventStatistic.eventQueue_.push("event2");
    eventStatistic.eventQueue_.push("event3");
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PopEvent());
}

/**
 * @tc.name: EventStatisticTest_ConvertTimeToStr_01
 * @tc.desc: Test ConvertTimeToStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_ConvertTimeToStr_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    int64_t timestamp = 50000;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.ConvertTimeToStr(timestamp));
}

/**
 * @tc.name: EventStatisticTest_PushEvent_01
 * @tc.desc: Test PushEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventStatisticTest, EventStatisticTest_PushEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventStatistic eventStatistic;
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    EventStatistic::writeFileEnabled_ = true;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushEvent(inputEvent));
    EventStatistic::writeFileEnabled_ = false;
    ASSERT_NO_FATAL_FAILURE(eventStatistic.PushEvent(inputEvent));
}
} // namespace MMI
} // namespace OHOS