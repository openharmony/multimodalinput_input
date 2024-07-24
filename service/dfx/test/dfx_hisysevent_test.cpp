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
 
#include <gtest/gtest.h>

#include "define_multimodal.h"
#include "dfx_hisysevent.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DfxHisysEventTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class DfxHisysEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: DfxHisysEventTest_OnClientConnectTest_001
 * @tc.desc: OnClientConnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnClientConnectTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::HiviewDFX::HiSysEvent::EventType type = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
    DfxHisysevent::ClientConnectData data;
    data.pid = 100;
    int32_t res = 100;
    DfxHisysevent::OnClientConnect(data, type);
    EXPECT_EQ(data.pid, res);
}

/**
 * @tc.name: DfxHisysEventTest_OnClientConnectTest_002
 * @tc.desc: OnClientConnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnClientConnectTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::HiviewDFX::HiSysEvent::EventType type = OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR;
    DfxHisysevent::ClientConnectData data;
    data.pid = 100;
    int32_t res = 100;
    DfxHisysevent::OnClientConnect(data, type);
    EXPECT_EQ(data.pid, res);
}

/**
 * @tc.name: DfxHisysEventTest_StatisticTouchpadGestureTest_001
 * @tc.desc: StatisticTouchpadGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_StatisticTouchpadGestureTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    int32_t fingerCount = 1;
    pointerEvent->SetFingerCount(fingerCount);
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::StatisticTouchpadGesture(pointerEvent));
}

/**
 * @tc.name: DfxHisysEventTest_ReportPowerInfoTest_001
 * @tc.desc: ReportPowerInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportPowerInfoTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    OHOS::HiviewDFX::HiSysEvent::EventType type = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportPowerInfo(keyEvent, type));
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportPowerInfo(keyEvent, type));
    keyEvent = nullptr;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportPowerInfo(keyEvent, type));
}

/**
 * @tc.name: DfxHisysEventTest_OnUpdateTargetPointerTest_001
 * @tc.desc: OnUpdateTargetPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnUpdateTargetPointerTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointer = PointerEvent::Create();
    ASSERT_NE(pointer, nullptr);
    int32_t fd = 1;
    OHOS::HiviewDFX::HiSysEvent::EventType type = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnUpdateTargetPointer(pointer, fd, type));
    type = OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnUpdateTargetPointer(pointer, fd, type));
}

/**
 * @tc.name: DfxHisysEventTest_OnUpdateTargetKeyTest_001
 * @tc.desc: OnUpdateTargetPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnUpdateTargetKeyTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t fd = 1;
    OHOS::HiviewDFX::HiSysEvent::EventType type = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnUpdateTargetKey(keyEvent, fd, type));
    type = OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnUpdateTargetKey(keyEvent, fd, type));
}

/**
 * @tc.name: DfxHisysEventTest_OnDeviceConnectTest_001
 * @tc.desc: OnDeviceConnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnDeviceConnectTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t id = 1;
    OHOS::HiviewDFX::HiSysEvent::EventType type = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnDeviceConnect(id, type));
    type = OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnDeviceConnect(id, type));
    id = INT32_MAX;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnDeviceConnect(id, type));
}

/**
 * @tc.name: DfxHisysEventTest_OnDeviceDisconnectTest_001
 * @tc.desc: OnDeviceDisconnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnDeviceDisconnectTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::HiviewDFX::HiSysEvent::EventType type = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
    int32_t id = -1;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnDeviceDisconnect(id, type));
    id = 1;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnDeviceDisconnect(id, type));
}

/**
 * @tc.name: DfxHisysEventTest_OnLidSwitchChangedTest_001
 * @tc.desc: OnLidSwitchChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnLidSwitchChangedTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t lidSwitch = 0;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnLidSwitchChanged(lidSwitch));
}

/**
 * @tc.name: DfxHisysEventTest_CalcKeyDispTimesTest_001
 * @tc.desc: CalcKeyDispTimes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_CalcKeyDispTimesTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::CalcKeyDispTimes());
}

/**
 * @tc.name: DfxHisysEventTest_CalcPointerDispTimesTest_001
 * @tc.desc: CalcPointerDispTimes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_CalcPointerDispTimesTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::CalcPointerDispTimes());
}

/**
 * @tc.name: DfxHisysEventTest_ReportDispTimesTest_001
 * @tc.desc: ReportDispTimes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportDispTimesTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportDispTimes());
}

/**
 * @tc.name: DfxHisysEventTest_ReportFailIfInvalidTimeTest_001
 * @tc.desc: ReportFailIfInvalidTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailIfInvalidTimeTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t intervalTime = 1000;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportFailIfInvalidTime(pointerEvent, intervalTime));

    item.SetPointerId(1);
    item.SetDeviceId(1);
    pointerEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportFailIfInvalidTime(pointerEvent, intervalTime));
}

/**
 * @tc.name: DfxHisysEventTest_ReportFailIfInvalidDistanceTest_001
 * @tc.desc: ReportFailIfInvalidDistance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailIfInvalidDistanceTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    float distance = 10;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportFailIfInvalidDistance(pointerEvent, distance));
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleClickEvent_001
 * @tc.desc: ReportKnuckleClickEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleClickEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportKnuckleClickEvent());
}

/**
 * @tc.name: DfxHisysEventTest_ReportScreenCaptureGesture_001
 * @tc.desc: ReportScreenCaptureGesture
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportScreenCaptureGesture_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportScreenCaptureGesture());
}

/**
 * @tc.name: DfxHisysEventTest_ReportSingleKnuckleDoubleClickEvent_001
 * @tc.desc: ReportSingleKnuckleDoubleClickEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSingleKnuckleDoubleClickEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t intervalTime = -1;
    int32_t distanceInterval = -1;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportSingleKnuckleDoubleClickEvent(intervalTime, distanceInterval));
}

/**
 * @tc.name: DfxHisysEventTest_ReportSingleKnuckleDoubleClickEvent_002
 * @tc.desc: ReportSingleKnuckleDoubleClickEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSingleKnuckleDoubleClickEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t intervalTime = 0;
    int32_t distanceInterval = 0;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportSingleKnuckleDoubleClickEvent(intervalTime, distanceInterval));
}

/**
 * @tc.name: DfxHisysEventTest_ReportSingleKnuckleDoubleClickEvent_003
 * @tc.desc: ReportSingleKnuckleDoubleClickEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSingleKnuckleDoubleClickEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t intervalTime = 10;
    int32_t distanceInterval = 10;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportSingleKnuckleDoubleClickEvent(intervalTime, distanceInterval));
}

/**
 * @tc.name: DfxHisysEventTest_ReportSingleKnuckleDoubleClickEvent_004
 * @tc.desc: ReportSingleKnuckleDoubleClickEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSingleKnuckleDoubleClickEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t intervalTime = 10000;
    int32_t distanceInterval = 10000;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportSingleKnuckleDoubleClickEvent(intervalTime, distanceInterval));
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSettingState_001
 * @tc.desc: ReportTouchpadSettingState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSettingState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportTouchpadSettingState(
        DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_ROTATE_SETTING, flag));
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSettingState_002
 * @tc.desc: ReportTouchpadSettingState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSettingState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportTouchpadSettingState(
        DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_SCROLL_SETTING, flag));
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSettingState_003
 * @tc.desc: ReportTouchpadSettingState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSettingState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = true;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportTouchpadSettingState(
          DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_SCROLL_SETTING, flag));
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSettingState_004
 * @tc.desc: ReportTouchpadSettingState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSettingState_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t value = -1;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportTouchpadSettingState(
        DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_ROTATE_SETTING, value));
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSettingState_005
 * @tc.desc: ReportTouchpadSettingState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSettingState_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t value = -1;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportTouchpadSettingState(
        DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_POINTER_SPEED_SETTING, value));
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSettingState_006
 * @tc.desc: ReportTouchpadSettingState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSettingState_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t value = 10;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportTouchpadSettingState(
        DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_POINTER_SPEED_SETTING, value));
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureFaildTimes_001
 * @tc.desc: ReportKnuckleGestureFaildTimes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureFaildTimes_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportKnuckleGestureFaildTimes());
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleDrawSSuccessTimes_001
 * @tc.desc: ReportKnuckleDrawSSuccessTimes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleDrawSSuccessTimes_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportKnuckleDrawSSuccessTimes());
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureFromFailToSuccessTime_001
 * @tc.desc: ReportKnuckleGestureFromFailToSuccessTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureFromFailToSuccessTime_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t intervalTime = 1;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportKnuckleGestureFromFailToSuccessTime(intervalTime));
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureFromSuccessToFailTime_001
 * @tc.desc: ReportKnuckleGestureFromSuccessToFailTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureFromSuccessToFailTime_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t intervalTime = 1;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportKnuckleGestureFromSuccessToFailTime(intervalTime));
}

/**
 * @tc.name: DfxHisysEventTest_ReportFailIfKnockTooFast_001
 * @tc.desc: ReportFailIfKnockTooFast
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailIfKnockTooFast_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportFailIfKnockTooFast());
}

} // namespace MMI
} // namespace OHOS