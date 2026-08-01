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

#include "define_multimodal.h"
#include "input_manager.h"
#include "input_manager_impl.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEventRecordTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t MAX_RECORD_COUNT = 100;
constexpr int32_t POINTER_ITEM_DISPLAY_X = 520;
constexpr int32_t POINTER_ITEM_DISPLAY_Y = 222;
} // namespace

class RecordEventConsumer : public IInputEventConsumer {
public:
    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override {}
    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
    {
        receivedCount_++;
    }
    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override {}
    uint32_t GetReceivedCount() const
    {
        return receivedCount_;
    }

private:
    mutable uint32_t receivedCount_ { 0 };
};

class PointerEventRecordTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        runner_ = AppExecFwk::EventRunner::Create("pointerEventRecordTest");
        ASSERT_TRUE(runner_ != nullptr);
        eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner_);
        ASSERT_TRUE(eventHandler_ != nullptr);
        consumer_ = std::make_shared<RecordEventConsumer>();
        ASSERT_TRUE(consumer_ != nullptr);
        int32_t ret = InputManager::GetInstance()->SetWindowInputEventConsumer(consumer_, eventHandler_);
        ASSERT_EQ(ret, RET_OK);
    }
    void TearDown() override
    {
        InputManager::GetInstance()->DisablePointerEventRecord();
    }

private:
    std::shared_ptr<AppExecFwk::EventRunner> runner_;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_;
    std::shared_ptr<RecordEventConsumer> consumer_;
};

/**
 * @tc.name: PointerEventRecord_EnableQueryDisable_001
 * @tc.desc: Drive OnPointerEvent with a pointer event, verify recording and query
 *           of the 6 fields, then disable and verify cleared
 * @tc.type: FUNC
 */
HWTEST_F(PointerEventRecordTest, PointerEventRecord_EnableQueryDisable_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(InputManager::GetInstance()->EnablePointerEventRecord(10), RET_OK);

    auto event = PointerEvent::Create();
    ASSERT_TRUE(event != nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    event->SetPointerId(0);
    event->SetDeviceId(1);
    event->SetActionTime(12345);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetToolType(PointerEvent::TOOL_TYPE_MOUSE);
    event->AddPointerItem(item);

    InputMgrImpl.OnPointerEvent(event);

    ASSERT_EQ(consumer_->GetReceivedCount(), 1u);
    std::vector<std::shared_ptr<PointerEvent>> records;
    EXPECT_EQ(InputManager::GetInstance()->GetPointerEventRecord(records), RET_OK);
    ASSERT_EQ(records.size(), 1u);
    auto &last = records.back();
    EXPECT_EQ(last->GetSourceType(), PointerEvent::SOURCE_TYPE_MOUSE);
    EXPECT_EQ(last->GetPointerAction(), PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    EXPECT_EQ(last->GetPointerId(), 0);
    EXPECT_EQ(last->GetDeviceId(), 1);
    EXPECT_EQ(last->GetActionTime(), 12345);
    auto items = last->GetAllPointerItems();
    ASSERT_EQ(items.size(), 1u);
    EXPECT_EQ(items.front().GetPointerId(), 0);
    EXPECT_EQ(items.front().GetToolType(), PointerEvent::TOOL_TYPE_MOUSE);

    EXPECT_EQ(InputManager::GetInstance()->DisablePointerEventRecord(), RET_OK);
    records.clear();
    EXPECT_EQ(InputManager::GetInstance()->GetPointerEventRecord(records), RET_OK);
    EXPECT_TRUE(records.empty());
}

/**
 * @tc.name: PointerEventRecord_MultiTouchItems_002
 * @tc.desc: Drive OnPointerEvent with a two-pointer touch event and verify
 *           both PointerItems are recorded with their toolTypes
 * @tc.type: FUNC
 */
HWTEST_F(PointerEventRecordTest, PointerEventRecord_MultiTouchItems_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(InputManager::GetInstance()->EnablePointerEventRecord(10), RET_OK);

    auto event = PointerEvent::Create();
    ASSERT_TRUE(event != nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    event->SetPointerId(0);
    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    item1.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    event->AddPointerItem(item1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(1);
    item2.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    event->AddPointerItem(item2);

    InputMgrImpl.OnPointerEvent(event);

    ASSERT_EQ(consumer_->GetReceivedCount(), 1u);
    std::vector<std::shared_ptr<PointerEvent>> records;
    EXPECT_EQ(InputManager::GetInstance()->GetPointerEventRecord(records), RET_OK);
    ASSERT_EQ(records.size(), 1u);
    auto &last = records.back();
    EXPECT_EQ(last->GetSourceType(), PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    auto items = last->GetAllPointerItems();
    ASSERT_EQ(items.size(), 2u);
    auto it = items.begin();
    EXPECT_EQ(it->GetPointerId(), 0);
    EXPECT_EQ(it->GetToolType(), PointerEvent::TOOL_TYPE_FINGER);
    ++it;
    EXPECT_EQ(it->GetPointerId(), 1);
    EXPECT_EQ(it->GetToolType(), PointerEvent::TOOL_TYPE_PEN);

    EXPECT_EQ(InputManager::GetInstance()->DisablePointerEventRecord(), RET_OK);
}

/**
 * @tc.name: PointerEventRecord_FifoEvict_003
 * @tc.desc: Drive OnPointerEvent with more events than capacity, verify FIFO
 *           keeps the most recent records
 * @tc.type: FUNC
 */
HWTEST_F(PointerEventRecordTest, PointerEventRecord_FifoEvict_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    constexpr int32_t recordCapacity = 5;
    constexpr int32_t driveCount = 8;
    EXPECT_EQ(InputManager::GetInstance()->EnablePointerEventRecord(recordCapacity), RET_OK);

    for (int32_t i = 0; i < driveCount; ++i) {
        auto event = PointerEvent::Create();
        ASSERT_TRUE(event != nullptr);
        event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
        event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
        event->SetPointerId(i);
        PointerEvent::PointerItem item;
        item.SetPointerId(i);
        item.SetDisplayX(POINTER_ITEM_DISPLAY_X + i);
        item.SetDisplayY(POINTER_ITEM_DISPLAY_Y);
        event->AddPointerItem(item);
        InputMgrImpl.OnPointerEvent(event);
    }

    ASSERT_EQ(consumer_->GetReceivedCount(), static_cast<uint32_t>(driveCount));
    std::vector<std::shared_ptr<PointerEvent>> records;
    EXPECT_EQ(InputManager::GetInstance()->GetPointerEventRecord(records), RET_OK);
    ASSERT_EQ(records.size(), recordCapacity);
    EXPECT_EQ(records.front()->GetPointerId(), driveCount - recordCapacity);
    EXPECT_EQ(records.back()->GetPointerId(), driveCount - 1);

    EXPECT_EQ(InputManager::GetInstance()->DisablePointerEventRecord(), RET_OK);
}

/**
 * @tc.name: PointerEventRecord_ClampAndReject_004
 * @tc.desc: Enable with maxCount > 100 clamps to 100; maxCount <= 0 rejected
 * @tc.type: FUNC
 */
HWTEST_F(PointerEventRecordTest, PointerEventRecord_ClampAndReject_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_EQ(InputManager::GetInstance()->EnablePointerEventRecord(MAX_RECORD_COUNT + 1), RET_OK);
    std::vector<std::shared_ptr<PointerEvent>> records;
    EXPECT_EQ(InputManager::GetInstance()->GetPointerEventRecord(records), RET_OK);
    EXPECT_TRUE(records.empty());
    EXPECT_EQ(InputManager::GetInstance()->DisablePointerEventRecord(), RET_OK);

    EXPECT_EQ(InputManager::GetInstance()->EnablePointerEventRecord(0), RET_ERR);
    EXPECT_EQ(InputManager::GetInstance()->EnablePointerEventRecord(-1), RET_ERR);
    records.clear();
    EXPECT_EQ(InputManager::GetInstance()->GetPointerEventRecord(records), RET_OK);
    EXPECT_TRUE(records.empty());
}

/**
 * @tc.name: PointerEventRecord_DisabledNoRecord_005
 * @tc.desc: When recording is disabled, events reaching OnPointerEvent are
 *           dispatched to the consumer but not recorded
 * @tc.type: FUNC
 */
HWTEST_F(PointerEventRecordTest, PointerEventRecord_DisabledNoRecord_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto event = PointerEvent::Create();
    ASSERT_TRUE(event != nullptr);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    event->SetPointerId(0);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(POINTER_ITEM_DISPLAY_X);
    item.SetDisplayY(POINTER_ITEM_DISPLAY_Y);
    event->AddPointerItem(item);

    InputMgrImpl.OnPointerEvent(event);

    ASSERT_EQ(consumer_->GetReceivedCount(), 1u);
    std::vector<std::shared_ptr<PointerEvent>> records;
    EXPECT_EQ(InputManager::GetInstance()->GetPointerEventRecord(records), RET_OK);
    EXPECT_TRUE(records.empty());
}
} // namespace MMI
} // namespace OHOS
