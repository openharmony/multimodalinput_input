/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>

#include "event_integrity.h"
#include "pointer_event.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventIntegrityTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
} // namespace

class EventIntegrityTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}

    static std::shared_ptr<PointerEvent> CreatePointerEvent(int32_t action)
    {
        auto pointerEvent = PointerEvent::Create();
        if (pointerEvent != nullptr) {
            pointerEvent->SetPointerAction(action);
            pointerEvent->SetPointerId(0);
        }
        return pointerEvent;
    }
};

/**
 * @tc.name: EventIntegrity_IsCompleteEvent_Nullptr_001
 * @tc.desc: Test IsCompleteEvent with nullptr pointer event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_IsCompleteEvent_Nullptr_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    auto result = integrity.IsCompleteEvent(nullptr);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventIntegrity_IsCompleteEvent_SwipeBegin_001
 * @tc.desc: Test IsCompleteEvent with POINTER_ACTION_SWIPE_BEGIN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_IsCompleteEvent_SwipeBegin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    auto pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(pointerEvent, nullptr);
    auto result = integrity.IsCompleteEvent(pointerEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventIntegrity_IsCompleteEvent_SwipeUpdate_FromBegin_001
 * @tc.desc: Test IsCompleteEvent with POINTER_ACTION_SWIPE_UPDATE after SWIPE_BEGIN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_IsCompleteEvent_SwipeUpdate_FromBegin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    // First handle SWIPE_BEGIN
    auto pointerEventBegin = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(pointerEventBegin, nullptr);
    auto resultBegin = integrity.IsCompleteEvent(pointerEventBegin);
    EXPECT_TRUE(resultBegin);

    // Then handle SWIPE_UPDATE
    auto pointerEventUpdate = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(pointerEventUpdate, nullptr);
    auto resultUpdate = integrity.IsCompleteEvent(pointerEventUpdate);
    EXPECT_TRUE(resultUpdate);
}

/**
 * @tc.name: EventIntegrity_IsCompleteEvent_SwipeUpdate_InvalidState_001
 * @tc.desc: Test IsCompleteEvent with POINTER_ACTION_SWIPE_UPDATE in invalid state (initial UNKNOWN)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_IsCompleteEvent_SwipeUpdate_InvalidState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    // Try SWIPE_UPDATE without first handling SWIPE_BEGIN
    // eventAction_ starts as POINTER_ACTION_UNKNOWN
    auto pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(pointerEvent, nullptr);
    auto result = integrity.IsCompleteEvent(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventIntegrity_IsCompleteEvent_SwipeUpdate_FromUpdate_001
 * @tc.desc: Test IsCompleteEvent with POINTER_ACTION_SWIPE_UPDATE after another SWIPE_UPDATE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_IsCompleteEvent_SwipeUpdate_FromUpdate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    // First handle SWIPE_BEGIN
    auto pointerEventBegin = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(pointerEventBegin, nullptr);
    integrity.IsCompleteEvent(pointerEventBegin);

    // First SWIPE_UPDATE
    auto pointerEventUpdate1 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(pointerEventUpdate1, nullptr);
    auto result1 = integrity.IsCompleteEvent(pointerEventUpdate1);
    EXPECT_TRUE(result1);

    // Second consecutive SWIPE_UPDATE
    auto pointerEventUpdate2 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(pointerEventUpdate2, nullptr);
    auto result2 = integrity.IsCompleteEvent(pointerEventUpdate2);
    EXPECT_TRUE(result2);
}

/**
 * @tc.name: EventIntegrity_IsCompleteEvent_SwipeEnd_FromBegin_001
 * @tc.desc: Test IsCompleteEvent with POINTER_ACTION_SWIPE_END after SWIPE_BEGIN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_IsCompleteEvent_SwipeEnd_FromBegin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    // First handle SWIPE_BEGIN
    auto pointerEventBegin = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(pointerEventBegin, nullptr);
    integrity.IsCompleteEvent(pointerEventBegin);

    // Then handle SWIPE_END
    auto pointerEventEnd = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NE(pointerEventEnd, nullptr);
    auto result = integrity.IsCompleteEvent(pointerEventEnd);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventIntegrity_IsCompleteEvent_SwipeEnd_FromUpdate_001
 * @tc.desc: Test IsCompleteEvent with POINTER_ACTION_SWIPE_END after SWIPE_UPDATE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_IsCompleteEvent_SwipeEnd_FromUpdate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    // First handle SWIPE_BEGIN
    auto pointerEventBegin = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(pointerEventBegin, nullptr);
    integrity.IsCompleteEvent(pointerEventBegin);

    // Then handle SWIPE_UPDATE
    auto pointerEventUpdate = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(pointerEventUpdate, nullptr);
    integrity.IsCompleteEvent(pointerEventUpdate);

    // Finally handle SWIPE_END
    auto pointerEventEnd = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NE(pointerEventEnd, nullptr);
    auto result = integrity.IsCompleteEvent(pointerEventEnd);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventIntegrity_IsCompleteEvent_SwipeEnd_InvalidState_001
 * @tc.desc: Test IsCompleteEvent with POINTER_ACTION_SWIPE_END in invalid state (initial UNKNOWN)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_IsCompleteEvent_SwipeEnd_InvalidState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    // Try SWIPE_END without first handling SWIPE_BEGIN
    // eventAction_ starts as POINTER_ACTION_UNKNOWN
    auto pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NE(pointerEvent, nullptr);
    auto result = integrity.IsCompleteEvent(pointerEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: EventIntegrity_IsCompleteEvent_SwipeEnd_AfterEnd_001
 * @tc.desc: Test IsCompleteEvent with POINTER_ACTION_SWIPE_END after another SWIPE_END
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_IsCompleteEvent_SwipeEnd_AfterEnd_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    // First handle SWIPE_BEGIN
    auto pointerEventBegin = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(pointerEventBegin, nullptr);
    integrity.IsCompleteEvent(pointerEventBegin);

    // Then handle SWIPE_END
    auto pointerEventEnd1 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NE(pointerEventEnd1, nullptr);
    auto result1 = integrity.IsCompleteEvent(pointerEventEnd1);
    EXPECT_TRUE(result1);

    // Try another SWIPE_END after the first one (eventAction_ reset to UNKNOWN)
    auto pointerEventEnd2 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NE(pointerEventEnd2, nullptr);
    auto result2 = integrity.IsCompleteEvent(pointerEventEnd2);
    EXPECT_FALSE(result2);
}

/**
 * @tc.name: EventIntegrity_IsCompleteEvent_DefaultAction_001
 * @tc.desc: Test IsCompleteEvent with default action (non-swipe actions)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_IsCompleteEvent_DefaultAction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    // Test with POINTER_ACTION_DOWN (action 2)
    auto pointerEventDown = CreatePointerEvent(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_NE(pointerEventDown, nullptr);
    auto resultDown = integrity.IsCompleteEvent(pointerEventDown);
    EXPECT_TRUE(resultDown);

    // Test with POINTER_ACTION_UP (action 4)
    auto pointerEventUp = CreatePointerEvent(PointerEvent::POINTER_ACTION_UP);
    ASSERT_NE(pointerEventUp, nullptr);
    auto resultUp = integrity.IsCompleteEvent(pointerEventUp);
    EXPECT_TRUE(resultUp);

    // Test with POINTER_ACTION_MOVE (action 3)
    auto pointerEventMove = CreatePointerEvent(PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_NE(pointerEventMove, nullptr);
    auto resultMove = integrity.IsCompleteEvent(pointerEventMove);
    EXPECT_TRUE(resultMove);

    // Test with POINTER_ACTION_UNKNOWN (action 0)
    auto pointerEventUnknown = CreatePointerEvent(PointerEvent::POINTER_ACTION_UNKNOWN);
    ASSERT_NE(pointerEventUnknown, nullptr);
    auto resultUnknown = integrity.IsCompleteEvent(pointerEventUnknown);
    EXPECT_TRUE(resultUnknown);

    // Test with POINTER_ACTION_CANCEL (action 1)
    auto pointerEventCancel = CreatePointerEvent(PointerEvent::POINTER_ACTION_CANCEL);
    ASSERT_NE(pointerEventCancel, nullptr);
    auto resultCancel = integrity.IsCompleteEvent(pointerEventCancel);
    EXPECT_TRUE(resultCancel);
}

/**
 * @tc.name: EventIntegrity_SwipeSequence_Full_001
 * @tc.desc: Test complete swipe sequence: BEGIN -> UPDATE -> UPDATE -> END
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_SwipeSequence_Full_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;

    // SWIPE_BEGIN
    auto begin = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(begin, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(begin));

    // SWIPE_UPDATE 1
    auto update1 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(update1, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(update1));

    // SWIPE_UPDATE 2
    auto update2 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(update2, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(update2));

    // SWIPE_END
    auto end = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NE(end, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(end));
}

/**
 * @tc.name: EventIntegrity_SwipeSequence_Invalid_001
 * @tc.desc: Test invalid swipe sequence: UPDATE without BEGIN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_SwipeSequence_Invalid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;

    // Try SWIPE_UPDATE without SWIPE_BEGIN
    auto update = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(update, nullptr);
    EXPECT_FALSE(integrity.IsCompleteEvent(update));
}

/**
 * @tc.name: EventIntegrity_SwipeSequence_Invalid_002
 * @tc.desc: Test invalid swipe sequence: UPDATE after END (state reset)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_SwipeSequence_Invalid_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;

    // SWIPE_BEGIN -> SWIPE_END
    auto begin = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(begin, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(begin));

    auto end = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NE(end, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(end));

    // Try SWIPE_UPDATE after END (state is UNKNOWN again)
    auto update = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(update, nullptr);
    EXPECT_FALSE(integrity.IsCompleteEvent(update));
}

/**
 * @tc.name: EventIntegrity_SwipeSequence_Invalid_003
 * @tc.desc: Test invalid swipe sequence: BEGIN -> UPDATE -> UPDATE (no END)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_SwipeSequence_Invalid_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;

    // SWIPE_BEGIN
    auto begin = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(begin, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(begin));

    // Multiple SWIPE_UPDATE without END - all valid as long as state is BEGIN or UPDATE
    auto update1 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(update1, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(update1));

    auto update2 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(update2, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(update2));

    auto update3 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(update3, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(update3));
}

/**
 * @tc.name: EventIntegrity_MultipleSwipeSequences_001
 * @tc.desc: Test multiple complete swipe sequences
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_MultipleSwipeSequences_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;

    // First swipe sequence
    auto begin1 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(begin1, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(begin1));

    auto end1 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NE(end1, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(end1));

    // Second swipe sequence
    auto begin2 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(begin2, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(begin2));

    auto end2 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NE(end2, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(end2));

    // Third swipe sequence
    auto begin3 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(begin3, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(begin3));

    auto end3 = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NE(end3, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(end3));
}

/**
 * @tc.name: EventIntegrity_HandleSwipeBegin_001
 * @tc.desc: Test HandleSwipeBegin method indirectly through IsCompleteEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_HandleSwipeBegin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    auto pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(pointerEvent, nullptr);
    // HandleSwipeBegin is private, but we can test it indirectly through IsCompleteEvent
    auto result = integrity.IsCompleteEvent(pointerEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventIntegrity_HandleSwipeUpdate_ValidState_001
 * @tc.desc: Test HandleSwipeUpdate with valid previous state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_HandleSwipeUpdate_ValidState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;

    // Set valid state first (SWIPE_BEGIN)
    auto begin = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(begin, nullptr);
    integrity.IsCompleteEvent(begin);

    // Now SWIPE_UPDATE should work
    auto update = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_UPDATE);
    ASSERT_NE(update, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(update));
}

/**
 * @tc.name: EventIntegrity_HandleSwipeEnd_ValidState_001
 * @tc.desc: Test HandleSwipeEnd with valid previous state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_HandleSwipeEnd_ValidState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;

    // Set valid state first (SWIPE_BEGIN)
    auto begin = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NE(begin, nullptr);
    integrity.IsCompleteEvent(begin);

    // Now SWIPE_END should work
    auto end = CreatePointerEvent(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NE(end, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(end));
}

/**
 * @tc.name: EventIntegrity_HandleAxisBegin_001
 * @tc.desc: Test HandleAxisBegin method indirectly through IsCompleteEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_HandleAxisBegin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    auto pointerEvent = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    ASSERT_NE(pointerEvent, nullptr);
    // HandleAxisBegin is private, but we can test it indirectly through IsCompleteEvent
    auto result = integrity.IsCompleteEvent(pointerEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: EventIntegrity_HandleAxisUpdate_ValidState_001
 * @tc.desc: Test HandleAxisUpdate with valid previous state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_HandleAxisUpdate_ValidState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;

    // Set valid state first (AXIS_BEGIN)
    auto begin = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    ASSERT_NE(begin, nullptr);
    integrity.IsCompleteEvent(begin);

    // Now AXIS_UPDATE should work
    auto update = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ASSERT_NE(update, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(update));

    auto updateEx = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ASSERT_NE(updateEx, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(updateEx));
}

/**
 * @tc.name: EventIntegrity_HandleAxisUpdate_ValidState_002
 * @tc.desc: Test HandleAxisUpdate with valid previous state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_HandleAxisUpdate_ValidState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    auto update = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ASSERT_NE(update, nullptr);
    EXPECT_FALSE(integrity.IsCompleteEvent(update));
}

/**
 * @tc.name: EventIntegrity_HandleAxisEnd_ValidState_001
 * @tc.desc: Test HandleAxisEnd with valid previous state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_HandleAxisEnd_ValidState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;

    // Set valid state first (AXIS_BEGIN)
    auto begin = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    ASSERT_NE(begin, nullptr);
    integrity.IsCompleteEvent(begin);

    // Now AXIS_END should work
    auto end = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_END);
    ASSERT_NE(end, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(end));
}

/**
 * @tc.name: EventIntegrity_HandleAxisEnd_ValidState_002
 * @tc.desc: Test HandleAxisEnd with valid previous state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_HandleAxisEnd_ValidState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;

    // Set valid state first (AXIS_BEGIN)
    auto begin = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    ASSERT_NE(begin, nullptr);
    integrity.IsCompleteEvent(begin);

    auto update = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    ASSERT_NE(update, nullptr);
    integrity.IsCompleteEvent(update);

    // Now AXIS_END should work
    auto end = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_END);
    ASSERT_NE(end, nullptr);
    EXPECT_TRUE(integrity.IsCompleteEvent(end));
}

/**
 * @tc.name: EventIntegrity_HandleAxisEnd_ValidState_003
 * @tc.desc: Test HandleAxisEnd with valid previous state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventIntegrityTest, EventIntegrity_HandleAxisEnd_ValidState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventIntegrity integrity;
    auto end = CreatePointerEvent(PointerEvent::POINTER_ACTION_AXIS_END);
    ASSERT_NE(end, nullptr);
    EXPECT_FALSE(integrity.IsCompleteEvent(end));
}
} // namespace MMI
} // namespace OHOS
