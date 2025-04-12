/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ipc_skeleton.h"

#include "pull_throw_subscriber_handler.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PullThrowSubscriberHandlerTest"

namespace OHOS { 
namespace MMI { 
namespace { 
const int64_t WINDOW_TIME_INTERVAL = 0.5e6 + 1;
} // namespace

class PullThrowSubscriberHandlerTest : public testing::Test {
public:
    std::shared_ptr<PointerEvent> SetupSingleFingerDownEvent();
    std::shared_ptr<PointerEvent> SetupDoubleFingerDownEvent();
    std::shared_ptr<PointerEvent> SetupFingerPoisitionEvent();
};

std::shared_ptr<PointerEvent> PullThrowSubscriberHandlerTest::SetupSingleFingerDownEvent()
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    int32_t downX = 100;
    int32_t downY = 200;
    item.SetDisplayX(downX);
    item.SetDisplayY(downY);
    item.SetPressed(true);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> PullThrowSubscriberHandlerTest::SetupFingerPoisitionEvent()
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    int32_t downX = 10;
    int32_t downY = 20;
    item.SetDisplayX(downX);
    item.SetDisplayY(downY);
    return pointerEvent;
}

std::shared_ptr<PointerEvent> PullThrowSubscriberHandlerTest::SetupDoubleFingerDownEvent()
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    CHKPP(pointerEvent);
    PointerEvent::PointerItem item;
    PointerEvent::PointerItem item2;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    int32_t downX = 100;
    int32_t downY = 200;
    item.SetDisplayX(downX);
    item.SetDisplayY(downY);
    item.SetPressed(true);
    item.SetDownTime(0);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);

    item2.SetPointerId(1);
    item2.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    int32_t secondDownX = 120;
    int32_t secondDownY = 220;
    item2.SetDisplayX(secondDownX);
    item2.SetDisplayY(secondDownY);
    item2.SetPressed(true);
    int64_t downTime = 100000;
    item2.SetDownTime(downTime);
    pointerEvent->SetPointerId(1);
    pointerEvent->AddPointerItem(item2);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    return pointerEvent;
}

/**
 * @tc.name: PullThrowSubscriberHandlerTest_HandleFingerGestureDownEvent_001
 * @tc.desc: Test HandleFingerGestureDownEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_HandleFingerGestureDownEvent_001, testing::ext::TestSize
.Level1)
{
    CALL_TEST_DEBUG;
    auto touchEvent = SetupDoubleFingerDownEvent();
    ASSERT_TRUE(touchEvent != nullptr);
    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->HandleFingerGestureDownEvent(touchEvent));
}

/**
 * @tc.name: PullThrowSubscriberHandlerTest_HandleFingerGestureDownEvent_002
 * @tc.desc: Test HandleFingerGestureDownEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_HandleFingerGestureDownEvent_002, testing::ext::TestSize
.Level1)
{
    CALL_TEST_DEBUG;
    auto touchEvent = SetupFingerPoisitionEvent();
    ASSERT_TRUE(touchEvent != nullptr);
    // PULL_THROW_EVENT_HANDLER->UpdateFingerPoisition(touchEvent);
    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->HandleFingerGestureDownEvent(touchEvent));
}

/**
 * @tc.name: PullThrowSubscriberHandlerTest_HandleFingerGestureMoveEvent_001
 * @tc.desc: Test HandleFingerGestureMoveEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_HandleFingerGestureMoveEvent_001, testing::ext::TestSize
.Level1)
{
    CALL_TEST_DEBUG;
    auto touchEvent = SetupSingleFingerDownEvent();
    ASSERT_TRUE(touchEvent != nullptr);

    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->HandleFingerGestureMoveEvent(touchEvent));
}

/**
 * @tc.name: PullThrowSubscriberHandlerTest_HandleFingerGestureMoveEvent_002
 * @tc.desc: Test HandleFingerGestureMoveEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_HandleFingerGestureMoveEvent_002, testing::ext::TestSize
.Level1)
{
    CALL_TEST_DEBUG;
    auto touchEvent = SetupDoubleFingerDownEvent();
    ASSERT_TRUE(touchEvent != nullptr);
    PULL_THROW_EVENT_HANDLER->StartFingerGesture();

    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->HandleFingerGestureMoveEvent(touchEvent));
}

/**
 * @tc.name: PullThrowSubscriberHandlerTest_HandleFingerGesturePullMoveEvent_001
 * @tc.desc: Test HandleFingerGesturePullMoveEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_HandleFingerGesturePullMoveEvent_001, testing::ext::TestSize
.Level1)
{
    CALL_TEST_DEBUG;
    auto touchEvent = SetupSingleFingerDownEvent();
    ASSERT_TRUE(touchEvent != nullptr);
    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->HandleFingerGesturePullMoveEvent(touchEvent));
}

/**
 * @tc.name: PullThrowSubscriberHandlerTest_HandleFingerGesturePullMoveEvent_002
 * @tc.desc: Test HandleFingerGesturePullMoveEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_HandleFingerGesturePullMoveEvent_002, testing::ext::TestSize
.Level1)
{
    CALL_TEST_DEBUG;
    auto touchEvent = SetupDoubleFingerDownEvent();
    ASSERT_TRUE(touchEvent != nullptr);
    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->HandleFingerGestureDownEvent(touchEvent));
    MMI_HILOGI("LYY HandleFingerGesturePullMoveEvent On PullUp Event");
    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->HandleFingerGesturePullMoveEvent(touchEvent));
}

/**
 * @tc.name: PullThrowSubscriberHandlerTest_HandleFingerGesturePullMoveEvent_003
 * @tc.desc: Test HandleFingerGesturePullMoveEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_HandleFingerGesturePullMoveEvent_003, testing::ext::TestSize
.Level1)
{
    MMI_HILOGI("LYY On");
    CALL_TEST_DEBUG;
    auto touchEvent = SetupDoubleFingerDownEvent();
    ASSERT_TRUE(touchEvent != nullptr);
    PULL_THROW_EVENT_HANDLER->StartFingerGesture();
    MMI_HILOGI("LYY StartFingerGesture success");

    PULL_THROW_EVENT_HANDLER->StopFingerGesture(touchEvent);
    MMI_HILOGI("LYY StopFingerGesture success");
    double actionTime = touchEvent->GetActionTime();
    touchEvent->SetActionTime(actionTime + WINDOW_TIME_INTERVAL);
    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->HandleFingerGesturePullMoveEvent(touchEvent));
    MMI_HILOGI("LYY HandleFingerGesturePullMoveEvent success");
}

/**
 * @tc.name: PullThrowSubscriberHandlerTest_HandleFingerGesturePullUpEvent_001
 * @tc.desc: Test HandleFingerGesturePullUpEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_HandleFingerGesturePullUpEvent_001, testing::ext::TestSize
.Level1)
{
    CALL_TEST_DEBUG;
    auto touchEvent = SetupSingleFingerDownEvent();
    ASSERT_TRUE(touchEvent != nullptr);
    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->HandleFingerGesturePullUpEvent(touchEvent));
    MMI_HILOGI("LYY HandleFingerGesturePullUpEvent success");
}

/**
 * @tc.name: PullThrowSubscriberHandlerTest_HandleFingerGesturePullUpEvent_002
 * @tc.desc: Test HandleFingerGesturePullUpEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_HandleFingerGesturePullUpEvent_002, testing::ext::TestSize
.Level1)
{
    CALL_TEST_DEBUG;
    auto touchEvent = SetupDoubleFingerDownEvent();
    ASSERT_TRUE(touchEvent != nullptr);
    PULL_THROW_EVENT_HANDLER->StartFingerGesture();
    MMI_HILOGI("LYY StartFingerGesture success");
    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->HandleFingerGesturePullUpEvent(touchEvent));
    MMI_HILOGI("LYY HandleFingerGesturePullUpEvent success");
}
/**
 * @tc.name: PullThrowSubscriberHandlerTest_HandleFingerGesturePullUpEvent_003
 * @tc.desc: Test HandleFingerGesturePullUpEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_HandleFingerGesturePullUpEvent_003, testing::ext::TestSize
.Level1)
{
    CALL_TEST_DEBUG;
    auto touchEvent = SetupDoubleFingerDownEvent();
    ASSERT_TRUE(touchEvent != nullptr);
    PULL_THROW_EVENT_HANDLER->StartFingerGesture();
    MMI_HILOGI("LYY StartFingerGesture success");
    auto touchEvent1 = SetupFingerPoisitionEvent();
    PULL_THROW_EVENT_HANDLER->UpdateFingerPoisition(touchEvent1);
    MMI_HILOGI("LYY UpdateFingerPoisition success");
    touchEvent->SetActionTime(0);
    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->HandleFingerGesturePullUpEvent(touchEvent));
    MMI_HILOGI("LYY HandleFingerGesturePullUpEvent success");
}

/**
 * @tc.name: PullThrowSubscriberHandlerTest_HandleFingerGesturePullUpEvent_004
 * @tc.desc: Test HandleFingerGesturePullUpEvent
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_HandleFingerGesturePullMoveEvent_004, testing::ext::TestSize
.Level1)
{
    CALL_TEST_DEBUG;
    auto touchEvent = SetupDoubleFingerDownEvent();
    ASSERT_TRUE(touchEvent != nullptr);
    PULL_THROW_EVENT_HANDLER->StartFingerGesture();
    MMI_HILOGI("LYY StartFingerGesture success");
    PULL_THROW_EVENT_HANDLER->UpdateFingerPoisition(touchEvent);
    MMI_HILOGI("LYY UpdateFingerPoisition success");
    touchEvent->SetActionTime(0);
    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->HandleFingerGesturePullUpEvent(touchEvent));
    MMI_HILOGI("LYY HandleFingerGesturePullUpEvent success");
}

/**
 * @tc.name: PullThrowSubscriberHandlerTest_UpdateFingerPoisition_001
 * @tc.desc: Test UpdateFingerPoisition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_UpdateFingerPoisition_001, testing::ext::TestSize
.Level1)
{
    CALL_TEST_DEBUG;
    auto touchEvent = SetupDoubleFingerDownEvent();
    ASSERT_TRUE(touchEvent != nullptr);
    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->UpdateFingerPoisition(touchEvent));
    MMI_HILOGI("LYY UpdateFingerPoisition success");
}

/**
 * @tc.name: PullThrowSubscriberHandlerTest_StartFingerGesture_001
 * @tc.desc: Test StartFingerGesture
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PullThrowSubscriberHandlerTest, PullThrowSubscriberHandlerTest_StartFingerGesture_001, testing::ext::TestSize
.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(PULL_THROW_EVENT_HANDLER->StartFingerGesture());
    MMI_HILOGI("LYY StartFingerGesture success");
}
} // namespace MMI
} // namespace OHOS