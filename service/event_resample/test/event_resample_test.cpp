/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <queue>
#include <vector>

#include "event_resample.h"
#include "input_event.h"
#include "mmi_log.h"
#include "window_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventResampleTest"

namespace OHOS {
namespace MMI {

namespace {
using namespace testing::ext;
constexpr int64_t START_TIME { 10000 };
constexpr int64_t TIME_DELTA { 2500 };
constexpr uint32_t INITIAL_COORDS { 10 };
constexpr uint32_t COORDS_DELTA { 10 };
constexpr int64_t FRAME_TIME { 8000 };
} // namespace

class EventResampleTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    struct TestData {
        uint32_t framesNum { 10 };
        uint32_t pointerId { 0 };
        uint32_t fingerNum { 1 };
        uint32_t evtNum { 0 };
        int64_t timeDelta { TIME_DELTA };
        uint32_t coordsDelta { COORDS_DELTA };
    };

    struct Context {
        int32_t lastDispX { INITIAL_COORDS };
        int32_t lastDispY { INITIAL_COORDS };
        int64_t lastTime { START_TIME };
        int64_t frameTime { START_TIME };
        int64_t lastFrameTime { START_TIME };

        void Reset(void)
        {
            lastDispX = INITIAL_COORDS;
            lastDispY = INITIAL_COORDS;
            lastTime = START_TIME;
            frameTime = START_TIME;
            lastFrameTime = START_TIME;
        }
    };

    struct InputEvt {
        int32_t action { PointerEvent::POINTER_ACTION_UNKNOWN };
        int64_t actionTime { START_TIME };
        int32_t dispX { INITIAL_COORDS };
        int32_t dispY { INITIAL_COORDS };
        int32_t id { 0 };

        void Initialize(int32_t action, TestData &testData, Context &context)
        {
            this->action = action;
            dispX = context.lastDispX + testData.coordsDelta;
            context.lastDispX = dispX;
            dispY = context.lastDispY + testData.coordsDelta;
            context.lastDispY = dispY;
            id = testData.pointerId;

            if (action == PointerEvent::POINTER_ACTION_DOWN) {
                actionTime = context.lastFrameTime;
                context.lastTime = 0;
            } else {
                actionTime = context.lastFrameTime + context.lastTime + testData.timeDelta;
                context.lastTime = actionTime - context.lastFrameTime;
            }
        }

        void InitializeFrom(InputEvt &event)
        {
            action = event.action;
            actionTime = event.actionTime;
            dispX = event.dispX;
            dispY = event.dispY;
            id = event.id;
        };
    };

    struct ExpectedData {
        int64_t actionTime { 0 };
        int32_t dispX { 0 };
        int32_t dispY { 0 };
        int64_t touchUpTime { 0 };
        int32_t touchUpX { 0 };
        int32_t touchUpY { 0 };
        int32_t id { 0 };

        ExpectedData() {}

        void Reset(int32_t id)
        {
            this->id = id;
            actionTime = 0;
            dispX = 0;
            dispY = 0;
            touchUpTime = 0;
            touchUpX = 0;
            touchUpY = 0;
        }

        void UpdateTouchState(InputEvt &event)
        {
            if (id != event.id) {
                return;
            }

            switch (event.action) {
                case PointerEvent::POINTER_ACTION_DOWN : {
                    touchState.clear();
                    eventBatch.clear();
                    InputEvt evt;
                    evt.InitializeFrom(event);
                    touchState.insert(touchState.begin(), std::move(evt));
                    actionTime = event.actionTime;
                    dispX = event.dispX;
                    dispY = event.dispY;
                    break;
                }
                case PointerEvent::POINTER_ACTION_UP : {
                    touchState.clear();
                    eventBatch.clear();
                    touchUpTime = event.actionTime;
                    touchUpX = event.dispX;
                    touchUpY = event.dispY;
                    break;
                }
                case PointerEvent::POINTER_ACTION_MOVE : {
                    while (touchState.size() > 1) {
                        touchState.pop_back();
                    }
                    InputEvt evt;
                    evt.InitializeFrom(event);
                    touchState.insert(touchState.begin(), std::move(evt));
                    actionTime = event.actionTime;
                    dispX = event.dispX;
                    dispY = event.dispY;
                    break;
                }
            }
        }

        void AddEvent(InputEvt &event)
        {
            if (id != event.id) {
                return;
            }

            if (event.action == PointerEvent::POINTER_ACTION_MOVE) {
                InputEvt evt;
                evt.InitializeFrom(event);
                eventBatch.push_back(std::move(evt));
            } else {
                if ((event.action == PointerEvent::POINTER_ACTION_UP) && (!eventBatch.empty())) {
                    for (size_t i = 0; i < eventBatch.size(); i++) {
                        InputEvt& event = eventBatch.at(i);
                        UpdateTouchState(event);
                    }
                    eventBatch.erase(eventBatch.begin(), eventBatch.begin() + eventBatch.size() - 1);
                }
                UpdateTouchState(event);
            }
        }

        int32_t CalculateExpected(int64_t frameTime)
        {
            int64_t sampleTime = frameTime - EventResample::RESAMPLE_LATENCY;
            InputEvt current;

            if (eventBatch.empty()) {
                MMI_HILOGD("Event Batch empty");
                return ERR_WOULD_BLOCK;
            }

            size_t numSamples = eventBatch.size();
            size_t idx = 0;
            while ((idx < numSamples) && (eventBatch.at(idx).actionTime <= sampleTime)) {
                idx += 1;
            }
            ssize_t split = ssize_t(idx) - 1;
            if (split < 0) {
                MMI_HILOGD("Negative split value");
                return ERR_WOULD_BLOCK;
            }
            size_t count = split + 1;

            // Consume samples in batch
            for (size_t i = 0; i < count; i++) {
                InputEvt& event = eventBatch.at(i);
                UpdateTouchState(event);
            }
            eventBatch.erase(eventBatch.begin(), eventBatch.begin() + count);

            current.InitializeFrom(touchState[0]);

            return ResampleCoord(sampleTime, current);
        }

        int32_t ResampleCoord(int64_t sampleTime, InputEvt &current)
        {
            float alpha = 0.0;
            InputEvt other;

            if (eventBatch.empty()) {
                // Coordinates extrapolation
                MMI_HILOGD("Extrapolation");
                if (touchState.size() < EventResample::HISTORY_SIZE_MAX) {
                    return ERR_OK;
                }
                other.InitializeFrom(touchState[1]);
                int64_t delta = touchState[0].actionTime - touchState[1].actionTime;
                if (delta < EventResample::RESAMPLE_MIN_DELTA) {
                    return ERR_OK;
                } else if (delta > EventResample::RESAMPLE_MAX_DELTA) {
                    return ERR_OK;
                }
                int64_t maxPredict = touchState[0].actionTime +
                                     std::min(delta / 2, EventResample::RESAMPLE_MAX_PREDICTION);
                if (sampleTime > maxPredict) {
                    sampleTime = maxPredict;
                }
                alpha = static_cast<float>(touchState[0].actionTime - sampleTime) / delta;
            } else {
                // Coordinates interpolation
                MMI_HILOGD("Interpolation");
                InputEvt &next = eventBatch.front();
                other.InitializeFrom(next);
                int64_t delta = next.actionTime - touchState[0].actionTime;
                if (delta < EventResample::RESAMPLE_MIN_DELTA) {
                    MMI_HILOGD("RESAMPLE_MIN_DELTA = %{public}" PRId64 ", next_x = %{public}d, ts0_x = %{public}d",
                               delta, next.dispX, touchState[0].dispX);
                    return ERR_OK;
                }
                alpha = static_cast<float>(sampleTime - touchState[0].actionTime) / delta;
            }

            dispX = CalcCoord(current.dispX, other.dispX, alpha);
            dispY = CalcCoord(current.dispY, other.dispY, alpha);
            actionTime = sampleTime;

            return ERR_OK;
        }

    protected:
        std::vector<InputEvt> touchState;
        std::vector<InputEvt> eventBatch;
    };

    EventResampleTest();
    ~EventResampleTest();

    bool SetupPointerEvent(InputEvt &event, TestData &testData);
    int32_t CheckResults(std::shared_ptr<PointerEvent> outEvent,
                         std::vector<ExpectedData> &expected, Context &context);
    bool DoTest(TestData &testData, int32_t testId);
    void ReadQueue(TestData &testData, Context &ctx, std::vector<ExpectedData> &expected);
    void SendTouchUp(TestData &testData, Context &ctx, std::vector<ExpectedData> &expected);

    std::shared_ptr<PointerEvent> pointerEvent_ = nullptr;
    std::queue<InputEvt> eventQueue_;
    uint32_t failCount_ = 0;
};

EventResampleTest::EventResampleTest()
{
    pointerEvent_ = PointerEvent::Create();
}

EventResampleTest::~EventResampleTest()
{
}

bool EventResampleTest::SetupPointerEvent(InputEvt &event, TestData &testData)
{
    pointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent_->SetPointerAction(event.action);
    pointerEvent_->SetPointerId(event.id);
    pointerEvent_->SetDeviceId(0);

    auto pointIds = pointerEvent_->GetPointerIds();
    int64_t time = event.actionTime;
    if (pointIds.empty()) {
        pointerEvent_->SetActionStartTime(time);
    }
    pointerEvent_->SetActionTime(time);

    for (uint32_t idx = 0; idx < testData.fingerNum; idx++) {
        PointerEvent::PointerItem item;
        if (pointerEvent_->GetPointerItem(idx, item)) {
            item.SetPointerId(idx);
            item.SetDisplayX(event.dispX);
            item.SetDisplayY(event.dispY);
            item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
            item.SetDeviceId(0);
            pointerEvent_->UpdatePointerItem(idx, item);
        } else {
            item.SetPointerId(idx);
            item.SetDisplayX(event.dispX);
            item.SetDisplayY(event.dispY);
            item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
            item.SetDeviceId(0);
            pointerEvent_->AddPointerItem(item);
        }
    }

    return true;
}

int32_t EventResampleTest::CheckResults(std::shared_ptr<PointerEvent> outEvent,
                                        std::vector<ExpectedData> &expected, Context &context)
{
    bool ret = ERR_OK;
    int32_t failCount = 0;
    int64_t actionTime = 0;
    int32_t dispX = 0;
    int32_t dispY = 0;

    for (auto &it : expected) {
        PointerEvent::PointerItem pointerItem;
        if (!outEvent->GetPointerItem(it.id, pointerItem)) {
            EXPECT_TRUE(false);
            ret = ERR_INVALID_VALUE;
            break;
        }

        if (outEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_DOWN) {
            actionTime = expected[it.id].actionTime;
            dispX = expected[it.id].dispX;
            dispY = expected[it.id].dispY;
        } else if (outEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_MOVE) {
            expected[it.id].CalculateExpected(context.frameTime);
            actionTime = expected[it.id].actionTime;
            dispX = expected[it.id].dispX;
            dispY = expected[it.id].dispY;
        } else if (outEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_UP) {
            actionTime = expected[it.id].touchUpTime;
            dispX = expected[it.id].touchUpX;
            dispY = expected[it.id].touchUpY;
        }

        MMI_HILOGD("OutEvent: x=%{public}d y=%{public}d t=%{public}" PRId64 " f=%{public}" PRId64 " (%{public}d)",
                   pointerItem.GetDisplayX(), pointerItem.GetDisplayY(), outEvent->GetActionTime(),
                   context.frameTime, outEvent->GetPointerAction());
        MMI_HILOGD("Expected: x=%{public}d y=%{public}d t=%{public}" PRId64, dispX, dispY, actionTime);

        if (pointerItem.GetDisplayX() != dispX) {
            failCount++;
            EXPECT_EQ(pointerItem.GetDisplayX(), dispX);
        }
        if (pointerItem.GetDisplayY() != dispY) {
            failCount++;
            EXPECT_EQ(pointerItem.GetDisplayY(), dispY);
        }
        if (outEvent->GetActionTime() != actionTime) {
            failCount++;
            EXPECT_EQ(outEvent->GetActionTime(), actionTime);
        }

        if (failCount != 0) {
            MMI_HILOGD("Test Failed");
        }
        failCount_ += failCount;
    }

    return ret;
}

bool EventResampleTest::DoTest(TestData &testData, int32_t testId)
{
    CHKPF(pointerEvent_);
    pointerEvent_->Reset();
    Context ctx;
    std::shared_ptr<PointerEvent> outEvent = nullptr;
    std::vector<ExpectedData> expected(testData.fingerNum);

    MMI_HILOGD("Start test %{public}d", testId);

    for (uint32_t idx = 0; idx < testData.fingerNum; idx++) {
        expected[idx].Reset(idx);
    }

    failCount_ = 0;
    ctx.Reset();

    // Send touch down event
    InputEvt touchDown;
    touchDown.Initialize(PointerEvent::POINTER_ACTION_DOWN, testData, ctx);
    eventQueue_.push(std::move(touchDown));

    // Send touch moving events
    for (uint32_t idx = 0; idx < testData.framesNum; idx++) {
        ctx.lastFrameTime = ctx.frameTime;
        ctx.frameTime += FRAME_TIME;
        ctx.lastTime = 0;
        MMI_HILOGD("Frame %{public}d: lf = %{public}" PRId64 " f = %{public}" PRId64,
                   idx, ctx.lastFrameTime, ctx.frameTime);

        for (uint32_t eidx = 0; eidx < testData.evtNum; eidx++) {
            InputEvt touchMove;
            touchMove.Initialize(PointerEvent::POINTER_ACTION_MOVE, testData, ctx);
            eventQueue_.push(std::move(touchMove));
        }

        // Read data from queue and check results
        ReadQueue(testData, ctx, expected);
    }

    // Send touch up event
    SendTouchUp(testData, ctx, expected);

    return (failCount_ != 0) ? false : true;
}

void EventResampleTest::ReadQueue(TestData &testData, Context &ctx, std::vector<ExpectedData> &expected)
{
    std::shared_ptr<PointerEvent> outEvent = nullptr;
    ErrCode status = RET_OK;

    while (!eventQueue_.empty()) {
        InputEvt &event = eventQueue_.front();
        expected[event.id].AddEvent(event);
        SetupPointerEvent(event, testData);

        PointerEvent::PointerItem pointerItem;
        pointerEvent_->GetPointerItem(0, pointerItem);
        MMI_HILOGD("pointerEvent_: x = %{public}d y = %{public}d t = %{public}" PRId64,
                   pointerItem.GetDisplayX(), pointerItem.GetDisplayY(), pointerEvent_->GetActionTime());

        outEvent = EventResampleHdr->OnEventConsume(pointerEvent_, ctx.frameTime, status);
        if ((outEvent != nullptr) && (PointerEvent::POINTER_ACTION_DOWN != outEvent->GetPointerAction())) {
            MMI_HILOGE("Unexpected pointer action:%{public}d while %{public}d expected",
                       outEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_DOWN);
            failCount_++;
        } else if (outEvent != nullptr) {
            EXPECT_EQ(ERR_OK, CheckResults(outEvent, expected, ctx));
            EXPECT_EQ(ERR_OK, status);
        }
        eventQueue_.pop();
    }

    outEvent = EventResampleHdr->OnEventConsume(nullptr, ctx.frameTime, status);
    if (outEvent != nullptr) {
        EXPECT_EQ(ERR_OK, CheckResults(outEvent, expected, ctx));
        EXPECT_EQ(ERR_OK, status);
    } else {
        MMI_HILOGD("NULL Event_: status = %{public}d", status);
    }
}

void EventResampleTest::SendTouchUp(TestData &testData, Context &ctx, std::vector<ExpectedData> &expected)
{
    std::shared_ptr<PointerEvent> outEvent = nullptr;
    ErrCode status = RET_OK;
    InputEvt touchUp;

    touchUp.Initialize(PointerEvent::POINTER_ACTION_UP, testData, ctx);
    expected[touchUp.id].AddEvent(touchUp);
    SetupPointerEvent(touchUp, testData);
    outEvent = EventResampleHdr->OnEventConsume(pointerEvent_, ctx.frameTime, status);
    if (outEvent != nullptr) {
        MMI_HILOGD("Pointer Action:%{public}d", outEvent->GetPointerAction());
        EXPECT_EQ(ERR_OK, CheckResults(outEvent, expected, ctx));
        EXPECT_EQ(ERR_OK, status);
    } else {
        MMI_HILOGD("NULL Event_: status = %{public}d", status);
    }
}

/**
 * @tc.name: EventResampleTest_001
 * @tc.desc: Test to check single touch without moving events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestData testData = {.framesNum = 5, .fingerNum = 1, .evtNum = 0};
    EXPECT_EQ(EventResampleHdr->GetPointerEvent(), nullptr);
    EXPECT_TRUE(DoTest(testData, 1));
    EXPECT_NE(EventResampleHdr->GetPointerEvent(), nullptr);
}

/**
 * @tc.name: EventResampleTest_002
 * @tc.desc: Basic test to check events interpolation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestData testData = {.framesNum = 5, .fingerNum = 1, .evtNum = 2};
    EXPECT_TRUE(DoTest(testData, 2));
}

/**
 * @tc.name: EventResampleTest_003
 * @tc.desc: Basic test to check events extrapolation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestData testData = {.framesNum = 5, .fingerNum = 1, .evtNum = 1};
    EXPECT_TRUE(DoTest(testData, 3));
}

/**
 * @tc.name: EventResampleTest_004
 * @tc.desc: Test to check interpolation behavior when event received later then latency time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestData testData = {.framesNum = 5, .fingerNum = 1, .evtNum = 1, .timeDelta = 6000};
    EXPECT_TRUE(DoTest(testData, 4));
}

/**
 * @tc.name: EventResampleTest_005
 * @tc.desc: Test to check case when events intervals less than minimal delta value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestData testData = {.framesNum = 5, .fingerNum = 1, .evtNum = 5, .timeDelta = 1000};
    EXPECT_TRUE(DoTest(testData, 5));
}

/**
 * @tc.name: EventResampleTest_006
 * @tc.desc: Test to check case when many events are received during time frame
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TestData testData = {.framesNum = 5, .fingerNum = 1, .evtNum = 3};
    EXPECT_TRUE(DoTest(testData, 6));
}

/**
 * @tc.name: EventResampleTest_OnEventConsume
 * @tc.desc: Test OnEventConsume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_OnEventConsume, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int64_t frameTime = 0;
    ErrCode status = ERR_OK;
    EventResampleHdr->frameTime_ = 0;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    ASSERT_NE(EventResampleHdr->OnEventConsume(pointerEvent, frameTime, status), nullptr);
}

/**
 * @tc.name: EventResampleTest_InitializeInputEvent
 * @tc.desc: Test InitializeInputEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_InitializeInputEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    int64_t frameTime = 0;
    EventResampleHdr->frameTime_ = 0;
    ASSERT_EQ(EventResampleHdr->InitializeInputEvent(pointerEvent, frameTime), ERR_OK);
}

/**
 * @tc.name: EventResampleTest_TransformSampleWindowXY
 * @tc.desc: Test TransformSampleWindowXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_TransformSampleWindowXY, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    PointerEvent::PointerItem item;
    int32_t logicX = 100;
    int32_t logicY = 100;
    std::pair<int32_t, int32_t> pair { logicX, logicY };
    ASSERT_EQ(EventResampleHdr->TransformSampleWindowXY(pointerEvent, item, logicX, logicY), pair);
}

/**
 * @tc.name: EventResampleTest_UpdatePointerEvent_001
 * @tc.desc: Test the funcation UpdatePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_UpdatePointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventResample::MotionEvent outEvent;
    outEvent.actionTime = 100;
    outEvent.pointerAction = PointerEvent::POINTER_ACTION_MOVE;
    outEvent.actionTime = 5;
    outEvent.eventId = 6;
    EventResample::Pointer p;
    p.coordX = 100;
    p.coordY = 10;
    p.toolType = 1;
    p.id = 6;
    outEvent.pointers.insert(std::make_pair(1, p));
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->UpdatePointerEvent(&outEvent));
    outEvent.pointerAction = PointerEvent::POINTER_ACTION_UP;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->UpdatePointerEvent(&outEvent));
    outEvent.pointerAction = PointerEvent::POINTER_ACTION_DOWN;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->UpdatePointerEvent(&outEvent));
}

/**
 * @tc.name: EventResampleTest_UpdatePointerEvent_002
 * @tc.desc: Test the funcation UpdatePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_UpdatePointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventResample::MotionEvent outEvent;
    outEvent.actionTime = 20;
    outEvent.pointerAction = 10;
    outEvent.actionTime = 2;
    outEvent.eventId = 6;
    EventResample::Pointer p;
    p.coordX = 20;
    p.coordY = 30;
    p.toolType = 2;
    p.id = 3;
    outEvent.pointers.insert(std::make_pair(1, p));
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->UpdatePointerEvent(&outEvent));
}

/**
 * @tc.name: EventResampleTest_TransformSampleWindowXY_001
 * @tc.desc: Test the funcation TransformSampleWindowXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_TransformSampleWindowXY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDownTime(100);
    item.SetToolDisplayX(90);
    item.SetToolDisplayY(90);
    item.SetToolWindowX(50);
    item.SetToolWindowY(50);
    item.SetToolWidth(30);
    item.SetToolHeight(30);
    item.SetLongAxis(100);
    item.SetShortAxis(20);
    item.SetToolType(2);
    item.SetTargetWindowId(0);
    pointerEvent->AddPointerItem(item);
    int32_t logicX = 100;
    int32_t logicY = 100;
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->targetDisplayId_ = 10;
    inputEvent->targetWindowId_ = 10;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->TransformSampleWindowXY(pointerEvent, item, logicX, logicY));
    WindowInfo window;
    window.transform.push_back(1.0f);
    window.transform.push_back(2.0f);
    window.transform.push_back(3.0f);
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->TransformSampleWindowXY(pointerEvent, item, logicX, logicY));
}

/**
 * @tc.name: EventResampleTest_TransformSampleWindowXY_002
 * @tc.desc: Test the funcation TransformSampleWindowXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_TransformSampleWindowXY_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDownTime(10);
    item.SetToolDisplayX(9);
    item.SetToolDisplayY(8);
    item.SetToolWindowX(7);
    item.SetToolWindowY(6);
    item.SetToolWidth(5);
    item.SetToolHeight(4);
    item.SetLongAxis(3);
    item.SetShortAxis(2);
    item.SetToolType(1);
    item.SetTargetWindowId(0);
    pointerEvent->AddPointerItem(item);
    int32_t logicX = 10;
    int32_t logicY = 20;
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->targetDisplayId_ = 20;
    inputEvent->targetWindowId_ = 10;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->TransformSampleWindowXY(pointerEvent, item, logicX, logicY));
}

/**
 * @tc.name: EventResampleTest_ConsumeBatch_001
 * @tc.desc: Test the funcation ConsumeBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_ConsumeBatch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t frameTime = 5;
    EventResample::MotionEvent** outEvent = new EventResample::MotionEvent*[3];
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->ConsumeBatch(frameTime, outEvent));
    frameTime = -4;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->ConsumeBatch(frameTime, outEvent));
}

/**
 * @tc.name: EventResampleTest_ResampleTouchState_001
 * @tc.desc: Test the funcation ResampleTouchState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_ResampleTouchState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t sampleTime = 5;
    EventResample::MotionEvent event;
    EventResample::MotionEvent next;
    event.actionTime = 10;
    event.pointerAction = 20;
    event.actionTime = 5;
    event.eventId = 6;
    next.actionTime = 20;
    next.pointerAction = 30;
    next.actionTime = 8;
    next.eventId = 9;
    EventResampleHdr->resampleTouch_ = false;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->ResampleTouchState(sampleTime, &event, &next));
    EventResampleHdr->resampleTouch_ = true;
    event.sourceType = PointerEvent::SOURCE_TYPE_TOUCHPAD;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->ResampleTouchState(sampleTime, &event, &next));
    event.sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    event.pointerAction = PointerEvent::POINTER_ACTION_UP;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->ResampleTouchState(sampleTime, &event, &next));
    event.pointerAction = PointerEvent::POINTER_ACTION_MOVE;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->ResampleTouchState(sampleTime, &event, &next));
}

/**
 * @tc.name: EventResampleTest_ResampleTouchState_002
 * @tc.desc: Test the funcation ResampleTouchState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_ResampleTouchState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t sampleTime = 7;
    EventResample::MotionEvent event;
    EventResample::MotionEvent next;
    event.actionTime = 1;
    event.pointerAction = 2;
    event.actionTime = 2;
    event.eventId = 4;
    next.actionTime = 5;
    next.pointerAction = 6;
    next.actionTime = 7;
    next.eventId = 8;
    EventResampleHdr->resampleTouch_ = true;
    event.sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    event.pointerAction = PointerEvent::POINTER_ACTION_MOVE;
    int32_t deviceId = 9;
    int32_t source = 8;
    EventResample::TouchState ts;
    ts.deviceId = 9;
    ts.source = 8;
    ts.historyCurrent = 3;
    ts.historySize = 4;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->ResampleTouchState(sampleTime, &event, &next));
    deviceId = 15;
    source = 13;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->ResampleTouchState(sampleTime, &event, &next));
}

/**
 * @tc.name: EventResampleTest_ResampleCoordinates_001
 * @tc.desc: Test the funcation ResampleCoordinates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_ResampleCoordinates_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t sampleTime = 6;
    EventResample::MotionEvent event;
    EventResample::TouchState touchState;
    EventResample::History current;
    EventResample::History other;
    float alpha = 1.0;
    EventResample::Pointer p;
    p.coordX = 20;
    p.coordY = 30;
    p.toolType = 2;
    p.id = 5;
    event.pointers.insert(std::make_pair(1, p));
    EventResample::TouchState ts;
    ts.deviceId = 5;
    ts.source = 2;
    ts.historyCurrent = 3;
    ts.historySize = 4;
    EventResampleHdr->touchStates_.push_back(ts);
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->ResampleCoordinates(sampleTime, &event, touchState, &current,
        &other, alpha));
}

/**
 * @tc.name: EventResampleTest_ResampleCoordinates_002
 * @tc.desc: Test the funcation ResampleCoordinates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_ResampleCoordinates_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t sampleTime = 2;
    EventResample::MotionEvent event;
    EventResample::TouchState touchState;
    EventResample::History current;
    EventResample::History other;
    float alpha = 5.0;
    EventResample::Pointer p;
    p.coordX = 5;
    p.coordY = 8;
    p.toolType = 9;
    p.id = 2;
    event.pointers.insert(std::make_pair(1, p));
    EventResample::TouchState ts;
    ts.deviceId = 3;
    ts.source = 4;
    ts.historyCurrent = 7;
    ts.historySize = 5;
    EventResampleHdr->touchStates_.push_back(ts);
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->ResampleCoordinates(sampleTime, &event, touchState, &current,
        &other, alpha));
}

/**
 * @tc.name: EventResampleTest_FindBatch_001
 * @tc.desc: Test the funcation FindBatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_FindBatch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t source = 3;
    EventResample::MotionEvent motionEvent;
    motionEvent.deviceId = 1;
    motionEvent.sourceType = 3;
    EventResample::Batch batch;
    batch.samples.push_back(motionEvent);
    EventResampleHdr->batches_.push_back(batch);
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->FindBatch(deviceId, source));
    deviceId = 5;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->FindBatch(deviceId, source));
    source = 6;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->FindBatch(deviceId, source));
}

/**
 * @tc.name: EventResampleTest_FindTouchState_001
 * @tc.desc: Test the funcation FindTouchState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_FindTouchState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t source = 2;
    EventResample::TouchState ts;
    ts.deviceId = 1;
    ts.source = 2;
    ts.historyCurrent = 3;
    ts.historySize = 4;
    EventResampleHdr->touchStates_.push_back(ts);
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->FindTouchState(deviceId, source));
    deviceId = 5;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->FindTouchState(deviceId, source));
    source = 6;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->FindTouchState(deviceId, source));
}

/**
 * @tc.name: EventResampleTest_RewriteMessage_001
 * @tc.desc: Test the funcation RewriteMessage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, EventResampleTest_RewriteMessage_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventResample::TouchState state;
    EventResample::MotionEvent event;
    EventResample::Pointer p;
    p.coordX = 20;
    p.coordY = 30;
    p.toolType = 2;
    p.id = 5;
    event.pointers.insert(std::make_pair(1, p));
    EventResample::TouchState ts;
    ts.deviceId = 3;
    ts.source = 2;
    ts.historyCurrent = 3;
    ts.historySize = 4;
    EventResampleHdr->touchStates_.push_back(ts);
    event.actionTime = 10;
    state.lastResample.actionTime = 5;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->RewriteMessage(state, event));
    event.actionTime = 5;
    state.lastResample.actionTime = 10;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->RewriteMessage(state, event));
}

/**
 * @tc.name: ShouldResampleToolTest1
 * @tc.desc: Test ShouldResampleTool
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(EventResampleTest, ShouldResampleToolTest1, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(EventResampleHdr->ShouldResampleTool(PointerEvent::TOOL_TYPE_RUBBER));
}
} // namespace MMI
} // namespace OHOS
