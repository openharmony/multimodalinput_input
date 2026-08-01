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
#include "event_util_test.h"
#include "input_manager.h"
#include "input_manager_util.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerEventRecordTest"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t TIME_WAIT_FOR_OP = 300;
constexpr int32_t MAX_RECORD_COUNT = 100;
constexpr int32_t SIMULATE_EVENT_START_ID = 10000;
constexpr int32_t POINTER_ITEM_DISPLAY_X = 520;
constexpr int32_t POINTER_ITEM_DISPLAY_Y = 222;

HapInfoParams infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "PointerEventRecordTest",
    .instIndex = 0,
    .appIDDesc = "test",
    .isSystemApp = true
};

PermissionDef infoManagerTestPermDef = {
    .permissionName = "ohos.permission.test",
    .bundleName = "PointerEventRecordTest",
    .grantMode = 1,
    .availableLevel = APL_SYSTEM_CORE,
    .label = "label",
    .labelId = 1,
    .description = "test pointer event record",
    .descriptionId = 1,
};

PermissionStateFull infoManagerTestState = {
    .permissionName = "ohos.permission.test",
    .isGeneral = true,
    .resDeviceID = { "local" },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .grantFlags = { 1 },
};

HapPolicyParams infoManagerTestPolicyPrams = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain",
    .permList = { infoManagerTestPermDef },
    .permStateList = { infoManagerTestState }
};
} // namespace

class AccessToken {
public:
    AccessToken()
    {
        currentID_ = GetSelfTokenID();
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfoParms, infoManagerTestPolicyPrams);
        accessID_ = tokenIdEx.tokenIDEx;
        SetSelfTokenID(accessID_);
    }
    ~AccessToken()
    {
        AccessTokenKit::DeleteToken(accessID_);
        SetSelfTokenID(currentID_);
    }
private:
    uint64_t currentID_ = 0;
    uint64_t accessID_ = 0;
};

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
    static void SetUpTestCase()
    {
        ASSERT_TRUE(TestUtil->Init());
    }
    static void TearDownTestCase() {}
    void SetUp() override
    {
        TestUtil->SetRecvFlag(RECV_FLAG::RECV_FOCUS);
        runner_ = AppExecFwk::EventRunner::Create("pointerEventRecordTest");
        ASSERT_TRUE(runner_ != nullptr);
        eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner_);
        ASSERT_TRUE(eventHandler_ != nullptr);
        consumer_ = GetPtr<RecordEventConsumer>();
        ASSERT_TRUE(consumer_ != nullptr);
        InputManager::GetInstance()->SetWindowInputEventConsumer(consumer_, eventHandler_);
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
 * @tc.desc: Enable recording, inject pointer event through UDS round trip, query records,
 *           verify 6 fields, then disable and verify cleared
 * @tc.type: FUNC
 */
HWTEST_F(PointerEventRecordTest, PointerEventRecord_EnableQueryDisable_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccessToken accessToken;
    EXPECT_EQ(InputManager::GetInstance()->EnablePointerEventRecord(10), RET_OK);

    auto injectEvent = InputManagerUtil::SetupPointerEvent005();
    ASSERT_TRUE(injectEvent != nullptr);
    injectEvent->AddFlag(PointerEvent::EVENT_FLAG_NO_INTERCEPT);
    InputManager::GetInstance()->SimulateInputEvent(injectEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    ASSERT_EQ(consumer_->GetReceivedCount(), 1u);

    std::vector<std::shared_ptr<PointerEvent>> records;
    EXPECT_EQ(InputManager::GetInstance()->GetPointerEventRecord(records), RET_OK);
    ASSERT_EQ(records.size(), 1u);
    auto &last = records.back();
    EXPECT_EQ(last->GetSourceType(), PointerEvent::SOURCE_TYPE_MOUSE);
    EXPECT_EQ(last->GetPointerAction(), PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    EXPECT_GE(last->GetPointerId(), SIMULATE_EVENT_START_ID);
    EXPECT_GT(last->GetActionTime(), 0);
    auto items = last->GetAllPointerItems();
    EXPECT_EQ(items.size(), 1u);
    EXPECT_GE(items.front().GetPointerId(), SIMULATE_EVENT_START_ID);

    EXPECT_EQ(InputManager::GetInstance()->DisablePointerEventRecord(), RET_OK);
    records.clear();
    EXPECT_EQ(InputManager::GetInstance()->GetPointerEventRecord(records), RET_OK);
    EXPECT_TRUE(records.empty());
}

/**
 * @tc.name: PointerEventRecord_MultiTouchItems_002
 * @tc.desc: Inject a two-pointer touch event and verify both PointerItems are recorded
 * @tc.type: FUNC
 */
HWTEST_F(PointerEventRecordTest, PointerEventRecord_MultiTouchItems_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccessToken accessToken;
    EXPECT_EQ(InputManager::GetInstance()->EnablePointerEventRecord(10), RET_OK);

    auto injectEvent = InputManagerUtil::SetupPointerEvent002();
    ASSERT_TRUE(injectEvent != nullptr);
    injectEvent->AddFlag(PointerEvent::EVENT_FLAG_NO_INTERCEPT);
    InputManager::GetInstance()->SimulateInputEvent(injectEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    ASSERT_EQ(consumer_->GetReceivedCount(), 1u);

    std::vector<std::shared_ptr<PointerEvent>> records;
    EXPECT_EQ(InputManager::GetInstance()->GetPointerEventRecord(records), RET_OK);
    ASSERT_EQ(records.size(), 1u);
    auto &last = records.back();
    EXPECT_EQ(last->GetSourceType(), PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    auto items = last->GetAllPointerItems();
    EXPECT_EQ(items.size(), 2u);
    for (const auto &item : items) {
        EXPECT_GE(item.GetPointerId(), SIMULATE_EVENT_START_ID);
    }

    EXPECT_EQ(InputManager::GetInstance()->DisablePointerEventRecord(), RET_OK);
}

/**
 * @tc.name: PointerEventRecord_FifoEvict_003
 * @tc.desc: Record more than capacity, verify FIFO keeps the most recent records
 * @tc.type: FUNC
 */
HWTEST_F(PointerEventRecordTest, PointerEventRecord_FifoEvict_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccessToken accessToken;
    constexpr int32_t recordCapacity = 5;
    constexpr int32_t injectCount = 8;
    EXPECT_EQ(InputManager::GetInstance()->EnablePointerEventRecord(recordCapacity), RET_OK);

    for (int32_t i = 0; i < injectCount; ++i) {
        auto injectEvent = PointerEvent::Create();
        ASSERT_TRUE(injectEvent != nullptr);
        injectEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
        injectEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
        injectEvent->SetPointerId(i);
        PointerEvent::PointerItem item;
        item.SetPointerId(i);
        item.SetDisplayX(POINTER_ITEM_DISPLAY_X + i);
        item.SetDisplayY(POINTER_ITEM_DISPLAY_Y);
        item.SetDeviceId(0);
        injectEvent->AddPointerItem(item);
        injectEvent->AddFlag(PointerEvent::EVENT_FLAG_NO_INTERCEPT);
        InputManager::GetInstance()->SimulateInputEvent(injectEvent);
        std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));
    }

    ASSERT_EQ(consumer_->GetReceivedCount(), static_cast<uint32_t>(injectCount));

    std::vector<std::shared_ptr<PointerEvent>> records;
    EXPECT_EQ(InputManager::GetInstance()->GetPointerEventRecord(records), RET_OK);
    ASSERT_EQ(records.size(), recordCapacity);
    EXPECT_GE(records.front()->GetPointerId(), SIMULATE_EVENT_START_ID + injectCount - recordCapacity);
    EXPECT_GE(records.back()->GetPointerId(), SIMULATE_EVENT_START_ID + injectCount - 1);

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
 * @tc.desc: When recording is disabled, injected events are not recorded
 * @tc.type: FUNC
 */
HWTEST_F(PointerEventRecordTest, PointerEventRecord_DisabledNoRecord_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AccessToken accessToken;
    auto injectEvent = InputManagerUtil::SetupPointerEvent005();
    ASSERT_TRUE(injectEvent != nullptr);
    injectEvent->AddFlag(PointerEvent::EVENT_FLAG_NO_INTERCEPT);
    InputManager::GetInstance()->SimulateInputEvent(injectEvent);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME_WAIT_FOR_OP));

    ASSERT_EQ(consumer_->GetReceivedCount(), 1u);

    std::vector<std::shared_ptr<PointerEvent>> records;
    EXPECT_EQ(InputManager::GetInstance()->GetPointerEventRecord(records), RET_OK);
    EXPECT_TRUE(records.empty());
}
} // namespace MMI
} // namespace OHOS
