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

    intervalTime = 1000001;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportFailIfInvalidTime(pointerEvent, intervalTime));

    item.SetPointerId(2);
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

/**
 * @tc.name: DfxHisysEventTest_ReportFailIfOneSuccTwoFail_001
 * @tc.desc: ReportFailIfOneSuccTwoFail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailIfOneSuccTwoFail_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDeviceId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportFailIfOneSuccTwoFail(pointerEvent));

    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportFailIfOneSuccTwoFail(pointerEvent));
}

/**
 * @tc.name: DfxHisysEventTest_OnClientDisconnectTest_001
 * @tc.desc: OnClientDisconnect with FAULT type and nullptr secPtr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnClientDisconnectTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SessionPtr secPtr = nullptr;
    int32_t fd = 100;
    OHOS::HiviewDFX::HiSysEvent::EventType type = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
    DfxHisysevent::OnClientDisconnect(secPtr, fd, type);
    EXPECT_EQ(secPtr, nullptr);
}

/**
 * @tc.name: DfxHisysEventTest_OnFocusWindowChangedTest_001
 * @tc.desc: OnFocusWindowChanged with normal window ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnFocusWindowChangedTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t oldFocusWindowId = 100;
    int32_t newFocusWindowId = 200;
    int32_t oldFocusWindowPid = 1000;
    int32_t newFocusWindowPid = 2000;
    DfxHisysevent::OnFocusWindowChanged(oldFocusWindowId, newFocusWindowId,
        oldFocusWindowPid, newFocusWindowPid);
    EXPECT_EQ(newFocusWindowId, 200);
}

/**
 * @tc.name: DfxHisysEventTest_OnFocusWindowChangedTest_002
 * @tc.desc: OnFocusWindowChanged with same window ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnFocusWindowChangedTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t oldFocusWindowId = 100;
    int32_t newFocusWindowId = 100;
    int32_t oldFocusWindowPid = 1000;
    int32_t newFocusWindowPid = 1000;
    DfxHisysevent::OnFocusWindowChanged(oldFocusWindowId, newFocusWindowId,
        oldFocusWindowPid, newFocusWindowPid);
    EXPECT_EQ(oldFocusWindowId, newFocusWindowId);
}

/**
 * @tc.name: DfxHisysEventTest_OnFocusWindowChangedTest_003
 * @tc.desc: OnFocusWindowChanged with negative window ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnFocusWindowChangedTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t oldFocusWindowId = -1;
    int32_t newFocusWindowId = -1;
    int32_t oldFocusWindowPid = -1;
    int32_t newFocusWindowPid = -1;
    DfxHisysevent::OnFocusWindowChanged(oldFocusWindowId, newFocusWindowId,
        oldFocusWindowPid, newFocusWindowPid);
    EXPECT_EQ(oldFocusWindowId, -1);
}

/**
 * @tc.name: DfxHisysEventTest_OnZorderWindowChangedTest_001
 * @tc.desc: OnZorderWindowChanged with normal window ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnZorderWindowChangedTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t oldZorderFirstWindowId = 100;
    int32_t newZorderFirstWindowId = 200;
    int32_t oldZorderFirstWindowPid = 1000;
    int32_t newZorderFirstWindowPid = 2000;
    DfxHisysevent::OnZorderWindowChanged(oldZorderFirstWindowId, newZorderFirstWindowId,
        oldZorderFirstWindowPid, newZorderFirstWindowPid);
    EXPECT_EQ(newZorderFirstWindowId, 200);
}

/**
 * @tc.name: DfxHisysEventTest_OnZorderWindowChangedTest_002
 * @tc.desc: OnZorderWindowChanged with zero window ids
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnZorderWindowChangedTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t oldZorderFirstWindowId = 0;
    int32_t newZorderFirstWindowId = 0;
    int32_t oldZorderFirstWindowPid = 0;
    int32_t newZorderFirstWindowPid = 0;
    DfxHisysevent::OnZorderWindowChanged(oldZorderFirstWindowId, newZorderFirstWindowId,
        oldZorderFirstWindowPid, newZorderFirstWindowPid);
    EXPECT_EQ(oldZorderFirstWindowId, 0);
}

/**
 * @tc.name: DfxHisysEventTest_CalcKeyDispTimesTest_002
 * @tc.desc: CalcKeyDispTimes multiple calls for time level testing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_CalcKeyDispTimesTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    for (int i = 0; i < 5; i++) {
        DfxHisysevent::CalcKeyDispTimes();
    }
    EXPECT_EQ(5, 5);
}

/**
 * @tc.name: DfxHisysEventTest_CalcPointerDispTimesTest_002
 * @tc.desc: CalcPointerDispTimes multiple calls for sample count testing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_CalcPointerDispTimesTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    for (int i = 0; i < 15; i++) {
        DfxHisysevent::CalcPointerDispTimes();
    }
    EXPECT_EQ(15, 15);
}

/**
 * @tc.name: DfxHisysEventTest_ReportDispTimesTest_002
 * @tc.desc: ReportDispTimes with multiple calls to trigger report
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportDispTimesTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    for (int i = 0; i < 100; i++) {
        DfxHisysevent::CalcKeyDispTimes();
    }
    DfxHisysevent::ReportDispTimes();
    EXPECT_EQ(100, 100);
}

/**
 * @tc.name: DfxHisysEventTest_CalcComboStartTimesTest_001
 * @tc.desc: CalcComboStartTimes with zero keyDownDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_CalcComboStartTimesTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyDownDuration = 0;
    DfxHisysevent::CalcComboStartTimes(keyDownDuration);
    EXPECT_EQ(keyDownDuration, 0);
}

/**
 * @tc.name: DfxHisysEventTest_CalcComboStartTimesTest_002
 * @tc.desc: CalcComboStartTimes with negative keyDownDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_CalcComboStartTimesTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyDownDuration = -100;
    DfxHisysevent::CalcComboStartTimes(keyDownDuration);
    EXPECT_EQ(keyDownDuration, -100);
}

/**
 * @tc.name: DfxHisysEventTest_CalcComboStartTimesTest_003
 * @tc.desc: CalcComboStartTimes with large keyDownDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_CalcComboStartTimesTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyDownDuration = 10000;
    DfxHisysevent::CalcComboStartTimes(keyDownDuration);
    EXPECT_EQ(keyDownDuration, 10000);
}

/**
 * @tc.name: DfxHisysEventTest_ReportComboStartTimesTest_001
 * @tc.desc: ReportComboStartTimes with multiple calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportComboStartTimesTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    for (int i = 0; i < 100; i++) {
        DfxHisysevent::CalcComboStartTimes(0);
    }
    DfxHisysevent::ReportComboStartTimes();
    EXPECT_EQ(100, 100);
}

/**
 * @tc.name: DfxHisysEventTest_ReportPowerInfoTest_002
 * @tc.desc: ReportPowerInfo with nullptr keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportPowerInfoTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    OHOS::HiviewDFX::HiSysEvent::EventType type = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
    DfxHisysevent::ReportPowerInfo(keyEvent, type);
    EXPECT_EQ(keyEvent, nullptr);
}

/**
 * @tc.name: DfxHisysEventTest_StatisticTouchpadGestureTest_002
 * @tc.desc: StatisticTouchpadGesture with POINTER_ACTION_SWIPE_BEGIN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_StatisticTouchpadGestureTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    int32_t fingerCount = 2;
    pointerEvent->SetFingerCount(fingerCount);
    DfxHisysevent::StatisticTouchpadGesture(pointerEvent);
    EXPECT_EQ(fingerCount, 2);
}

/**
 * @tc.name: DfxHisysEventTest_StatisticTouchpadGestureTest_003
 * @tc.desc: StatisticTouchpadGesture with invalid pointer action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_StatisticTouchpadGestureTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    int32_t fingerCount = 1;
    pointerEvent->SetFingerCount(fingerCount);
    DfxHisysevent::StatisticTouchpadGesture(pointerEvent);
    EXPECT_EQ(fingerCount, 1);
}

/**
 * @tc.name: DfxHisysEventTest_StatisticTouchpadGestureTest_004
 * @tc.desc: StatisticTouchpadGesture with nullptr pointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_StatisticTouchpadGestureTest_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    DfxHisysevent::StatisticTouchpadGesture(pointerEvent);
    EXPECT_EQ(pointerEvent, nullptr);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSettingStateTest_007
 * @tc.desc: ReportTouchpadSettingState with TOUCHPAD_TAP_SETTING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSettingStateTest_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = true;
    DfxHisysevent::ReportTouchpadSettingState(
        DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_TAP_SETTING, flag);
    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSettingStateTest_008
 * @tc.desc: ReportTouchpadSettingState with TOUCHPAD_SWIPE_SETTING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSettingStateTest_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    DfxHisysevent::ReportTouchpadSettingState(
        DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_SWIPE_SETTING, flag);
    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSettingStateTest_009
 * @tc.desc: ReportTouchpadSettingState with TOUCHPAD_PINCH_SETTING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSettingStateTest_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = true;
    DfxHisysevent::ReportTouchpadSettingState(
        DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_PINCH_SETTING, flag);
    EXPECT_EQ(flag, true);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSettingStateTest_010
 * @tc.desc: ReportTouchpadSettingState with invalid settingCode for bool
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSettingStateTest_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool flag = false;
    DfxHisysevent::TOUCHPAD_SETTING_CODE invalidCode =
        static_cast<DfxHisysevent::TOUCHPAD_SETTING_CODE>(999);
    DfxHisysevent::ReportTouchpadSettingState(invalidCode, flag);
    EXPECT_EQ(flag, false);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSettingStateTest_011
 * @tc.desc: ReportTouchpadSettingState with TOUCHPAD_RIGHT_CLICK_SETTING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSettingStateTest_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t value = 1;
    DfxHisysevent::ReportTouchpadSettingState(
        DfxHisysevent::TOUCHPAD_SETTING_CODE::TOUCHPAD_RIGHT_CLICK_SETTING, value);
    EXPECT_EQ(value, 1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSettingStateTest_012
 * @tc.desc: ReportTouchpadSettingState with invalid settingCode for int32
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSettingStateTest_012, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t value = 0;
    DfxHisysevent::TOUCHPAD_SETTING_CODE invalidCode =
        static_cast<DfxHisysevent::TOUCHPAD_SETTING_CODE>(888);
    DfxHisysevent::ReportTouchpadSettingState(invalidCode, value);
    EXPECT_EQ(value, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportFailIfInvalidTimeTest_002
 * @tc.desc: ReportFailIfInvalidTime with nullptr touchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailIfInvalidTimeTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t intervalTime = 1000;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    DfxHisysevent::ReportFailIfInvalidTime(pointerEvent, intervalTime);
    EXPECT_EQ(pointerEvent, nullptr);
}

/**
 * @tc.name: DfxHisysEventTest_ReportFailIfInvalidTimeTest_003
 * @tc.desc: ReportFailIfInvalidTime with threshold exceeded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailIfInvalidTimeTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t intervalTime = 2000000;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    DfxHisysevent::ReportFailIfInvalidTime(pointerEvent, intervalTime);
    EXPECT_EQ(intervalTime, 2000000);
}

/**
 * @tc.name: DfxHisysEventTest_ReportFailIfInvalidDistanceTest_002
 * @tc.desc: ReportFailIfInvalidDistance with zero distance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailIfInvalidDistanceTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    float distance = 0.0f;
    DfxHisysevent::ReportFailIfInvalidDistance(pointerEvent, distance);
    EXPECT_EQ(distance, 0.0f);
}

/**
 * @tc.name: DfxHisysEventTest_ReportFailIfInvalidDistanceTest_003
 * @tc.desc: ReportFailIfInvalidDistance with negative distance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailIfInvalidDistanceTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    float distance = -10.5f;
    DfxHisysevent::ReportFailIfInvalidDistance(pointerEvent, distance);
    EXPECT_EQ(distance, -10.5f);
}

/**
 * @tc.name: DfxHisysEventTest_ReportFailIfInvalidDistanceTest_004
 * @tc.desc: ReportFailIfInvalidDistance with nullptr touchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailIfInvalidDistanceTest_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    float distance = 10.0f;
    DfxHisysevent::ReportFailIfInvalidDistance(pointerEvent, distance);
    EXPECT_EQ(pointerEvent, nullptr);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureFromFailToSuccessTimeTest_002
 * @tc.desc: ReportKnuckleGestureFromFailToSuccessTime with negative intervalTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureFromFailToSuccessTimeTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t intervalTime = -100;
    DfxHisysevent::ReportKnuckleGestureFromFailToSuccessTime(intervalTime);
    EXPECT_EQ(intervalTime, -100);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureFromFailToSuccessTimeTest_003
 * @tc.desc: ReportKnuckleGestureFromFailToSuccessTime with max threshold
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureFromFailToSuccessTimeTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t intervalTime = 180000;
    DfxHisysevent::ReportKnuckleGestureFromFailToSuccessTime(intervalTime);
    EXPECT_EQ(intervalTime, 180000);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureFromSuccessToFailTimeTest_002
 * @tc.desc: ReportKnuckleGestureFromSuccessToFailTime with negative intervalTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureFromSuccessToFailTimeTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t intervalTime = -100;
    DfxHisysevent::ReportKnuckleGestureFromSuccessToFailTime(intervalTime);
    EXPECT_EQ(intervalTime, -100);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureFromSuccessToFailTimeTest_003
 * @tc.desc: ReportKnuckleGestureFromSuccessToFailTime with max threshold
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureFromSuccessToFailTimeTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t intervalTime = 180000;
    DfxHisysevent::ReportKnuckleGestureFromSuccessToFailTime(intervalTime);
    EXPECT_EQ(intervalTime, 180000);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSubscribeKeyEventTest_001
 * @tc.desc: ReportSubscribeKeyEvent with normal parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSubscribeKeyEventTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t subscribeId = 1;
    int32_t finalKey = 100;
    std::string name = "test_subscribe";
    int32_t pid = 1000;
    DfxHisysevent::ReportSubscribeKeyEvent(subscribeId, finalKey, name, pid);
    EXPECT_EQ(subscribeId, 1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSubscribeKeyEventTest_002
 * @tc.desc: ReportSubscribeKeyEvent with zero parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSubscribeKeyEventTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t subscribeId = 0;
    int32_t finalKey = 0;
    std::string name = "";
    int32_t pid = 0;
    DfxHisysevent::ReportSubscribeKeyEvent(subscribeId, finalKey, name, pid);
    EXPECT_EQ(subscribeId, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportUnSubscribeKeyEventTest_001
 * @tc.desc: ReportUnSubscribeKeyEvent with normal parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportUnSubscribeKeyEventTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t subscribeId = 1;
    int32_t finalKey = 100;
    std::string name = "test_unsubscribe";
    int32_t pid = 1000;
    DfxHisysevent::ReportUnSubscribeKeyEvent(subscribeId, finalKey, name, pid);
    EXPECT_EQ(subscribeId, 1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKeyboardEventTest_001
 * @tc.desc: ReportKeyboardEvent with normal parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKeyboardEventTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t eventType = 1;
    int32_t keyCode = 100;
    int32_t keyAction = 0;
    DfxHisysevent::ReportKeyboardEvent(eventType, keyCode, keyAction);
    EXPECT_EQ(eventType, 1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKeyboardEventTest_002
 * @tc.desc: ReportKeyboardEvent with negative parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKeyboardEventTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t eventType = -1;
    int32_t keyCode = -1;
    int32_t keyAction = -1;
    DfxHisysevent::ReportKeyboardEvent(eventType, keyCode, keyAction);
    EXPECT_EQ(eventType, -1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportLaunchAbilityTest_001
 * @tc.desc: ReportLaunchAbility with valid bundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportLaunchAbilityTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string bundleName = "com.test.app";
    DfxHisysevent::ReportLaunchAbility(bundleName);
    EXPECT_EQ(bundleName, "com.test.app");
}

/**
 * @tc.name: DfxHisysEventTest_ReportLaunchAbilityTest_002
 * @tc.desc: ReportLaunchAbility with empty bundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportLaunchAbilityTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string bundleName = "";
    DfxHisysevent::ReportLaunchAbility(bundleName);
    EXPECT_EQ(bundleName, "");
}

/**
 * @tc.name: DfxHisysEventTest_ReportCommonActionTest_001
 * @tc.desc: ReportCommonAction with valid action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportCommonActionTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string action = "click";
    DfxHisysevent::ReportCommonAction(action);
    EXPECT_EQ(action, "click");
}

/**
 * @tc.name: DfxHisysEventTest_ReportCommonActionTest_002
 * @tc.desc: ReportCommonAction with empty action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportCommonActionTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string action = "";
    DfxHisysevent::ReportCommonAction(action);
    EXPECT_EQ(action, "");
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchEventTest_001
 * @tc.desc: ReportTouchEvent with normal parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchEventTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pointAction = 1;
    int32_t pointId = 0;
    int32_t windowId = 100;
    DfxHisysevent::ReportTouchEvent(pointAction, pointId, windowId);
    EXPECT_EQ(pointAction, 1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchEventTest_002
 * @tc.desc: ReportTouchEvent with negative windowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchEventTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pointAction = 1;
    int32_t pointId = 0;
    int32_t windowId = -1;
    DfxHisysevent::ReportTouchEvent(pointAction, pointId, windowId);
    EXPECT_EQ(windowId, -1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSetCustomCursorTest_001
 * @tc.desc: ReportSetCustomCursor with normal parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSetCustomCursorTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowPid = 1000;
    int32_t windowId = 100;
    DfxHisysevent::ReportSetCustomCursor(windowPid, windowId);
    EXPECT_EQ(windowPid, 1000);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSetMouseIconTest_001
 * @tc.desc: ReportSetMouseIcon with normal windowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSetMouseIconTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    DfxHisysevent::ReportSetMouseIcon(windowId);
    EXPECT_EQ(windowId, 100);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSetPointerStyleTest_001
 * @tc.desc: ReportSetPointerStyle with normal parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSetPointerStyleTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    int32_t pointerStyleId = 1;
    bool isUiExtension = false;
    DfxHisysevent::ReportSetPointerStyle(windowId, pointerStyleId, isUiExtension);
    EXPECT_EQ(windowId, 100);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSetPointerStyleTest_002
 * @tc.desc: ReportSetPointerStyle with uiExtension true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSetPointerStyleTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    int32_t pointerStyleId = 2;
    bool isUiExtension = true;
    DfxHisysevent::ReportSetPointerStyle(windowId, pointerStyleId, isUiExtension);
    EXPECT_EQ(isUiExtension, true);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSetPointerVisibleTest_001
 * @tc.desc: ReportSetPointerVisible with visible true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSetPointerVisibleTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool visible = true;
    int32_t priority = 1;
    DfxHisysevent::ReportSetPointerVisible(visible, priority);
    EXPECT_EQ(visible, true);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSetPointerVisibleTest_002
 * @tc.desc: ReportSetPointerVisible with visible false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSetPointerVisibleTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool visible = false;
    int32_t priority = 0;
    DfxHisysevent::ReportSetPointerVisible(visible, priority);
    EXPECT_EQ(visible, false);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSetPointerSpeedTest_001
 * @tc.desc: ReportSetPointerSpeed with normal speed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSetPointerSpeedTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t speed = 5;
    DfxHisysevent::ReportSetPointerSpeed(speed);
    EXPECT_EQ(speed, 5);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSetPointerSpeedTest_002
 * @tc.desc: ReportSetPointerSpeed with zero speed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSetPointerSpeedTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t speed = 0;
    DfxHisysevent::ReportSetPointerSpeed(speed);
    EXPECT_EQ(speed, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSetPointerSpeedTest_003
 * @tc.desc: ReportSetPointerSpeed with negative speed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSetPointerSpeedTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t speed = -1;
    DfxHisysevent::ReportSetPointerSpeed(speed);
    EXPECT_EQ(speed, -1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportAddInputHandlerTest_001
 * @tc.desc: ReportAddInputHandler with normal handlerType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportAddInputHandlerTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t handlerType = 1;
    DfxHisysevent::ReportAddInputHandler(handlerType);
    EXPECT_EQ(handlerType, 1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportAddInputHandlerTest_002
 * @tc.desc: ReportAddInputHandler with zero handlerType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportAddInputHandlerTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t handlerType = 0;
    DfxHisysevent::ReportAddInputHandler(handlerType);
    EXPECT_EQ(handlerType, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportRemoveInputHandlerTest_001
 * @tc.desc: ReportRemoveInputHandler with normal handlerType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportRemoveInputHandlerTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t handlerType = 1;
    DfxHisysevent::ReportRemoveInputHandler(handlerType);
    EXPECT_EQ(handlerType, 1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportInjectPointerEventTest_001
 * @tc.desc: ReportInjectPointerEvent with isNativeInject true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportInjectPointerEventTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isNativeInject = true;
    DfxHisysevent::ReportInjectPointerEvent(isNativeInject);
    EXPECT_EQ(isNativeInject, true);
}

/**
 * @tc.name: DfxHisysEventTest_ReportInjectPointerEventTest_002
 * @tc.desc: ReportInjectPointerEvent with isNativeInject false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportInjectPointerEventTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isNativeInject = false;
    DfxHisysevent::ReportInjectPointerEvent(isNativeInject);
    EXPECT_EQ(isNativeInject, false);
}

/**
 * @tc.name: DfxHisysEventTest_ReportEnableCombineKeyTest_001
 * @tc.desc: ReportEnableCombineKey with enable true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportEnableCombineKeyTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool enable = true;
    DfxHisysevent::ReportEnableCombineKey(enable);
    EXPECT_EQ(enable, true);
}

/**
 * @tc.name: DfxHisysEventTest_ReportEnableCombineKeyTest_002
 * @tc.desc: ReportEnableCombineKey with enable false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportEnableCombineKeyTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool enable = false;
    DfxHisysevent::ReportEnableCombineKey(enable);
    EXPECT_EQ(enable, false);
}

/**
 * @tc.name: DfxHisysEventTest_ReportAppendExtraDataTest_001
 * @tc.desc: ReportAppendExtraData normal call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportAppendExtraDataTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DfxHisysevent::ReportAppendExtraData();
    EXPECT_EQ(0, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTransmitInfraredTest_001
 * @tc.desc: ReportTransmitInfrared with positive number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTransmitInfraredTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t number = 100;
    DfxHisysevent::ReportTransmitInfrared(number);
    EXPECT_EQ(number, 100);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTransmitInfraredTest_002
 * @tc.desc: ReportTransmitInfrared with zero number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTransmitInfraredTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t number = 0;
    DfxHisysevent::ReportTransmitInfrared(number);
    EXPECT_EQ(number, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTransmitInfraredTest_003
 * @tc.desc: ReportTransmitInfrared with negative number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTransmitInfraredTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t number = -100;
    DfxHisysevent::ReportTransmitInfrared(number);
    EXPECT_EQ(number, -100);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSetCurrentUserTest_001
 * @tc.desc: ReportSetCurrentUser with normal userId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSetCurrentUserTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t userId = 100;
    DfxHisysevent::ReportSetCurrentUser(userId);
    EXPECT_EQ(userId, 100);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSetCurrentUserTest_002
 * @tc.desc: ReportSetCurrentUser with zero userId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSetCurrentUserTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t userId = 0;
    DfxHisysevent::ReportSetCurrentUser(userId);
    EXPECT_EQ(userId, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKeyEventTest_001
 * @tc.desc: ReportKeyEvent with NAME_FILTER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKeyEventTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "filter";
    DfxHisysevent::ReportKeyEvent(name);
    EXPECT_EQ(name, "filter");
}

/**
 * @tc.name: DfxHisysEventTest_ReportKeyEventTest_002
 * @tc.desc: ReportKeyEvent with NAME_INTERCEPT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKeyEventTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "intercept";
    DfxHisysevent::ReportKeyEvent(name);
    EXPECT_EQ(name, "intercept");
}

/**
 * @tc.name: DfxHisysEventTest_ReportKeyEventTest_003
 * @tc.desc: ReportKeyEvent with NAME_SUBCRIBER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKeyEventTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "subcriber";
    DfxHisysevent::ReportKeyEvent(name);
    EXPECT_EQ(name, "subcriber");
}

/**
 * @tc.name: DfxHisysEventTest_ReportKeyEventTest_004
 * @tc.desc: ReportKeyEvent with NAME_FINGERPRINT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKeyEventTest_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "fingerprint";
    DfxHisysevent::ReportKeyEvent(name);
    EXPECT_EQ(name, "fingerprint");
}

/**
 * @tc.name: DfxHisysEventTest_ReportKeyEventTest_005
 * @tc.desc: ReportKeyEvent with NAME_STYLUS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKeyEventTest_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "stylus";
    DfxHisysevent::ReportKeyEvent(name);
    EXPECT_EQ(name, "stylus");
}

/**
 * @tc.name: DfxHisysEventTest_ReportKeyEventTest_006
 * @tc.desc: ReportKeyEvent with NAME_CANCEL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKeyEventTest_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "cancel";
    DfxHisysevent::ReportKeyEvent(name);
    EXPECT_EQ(name, "cancel");
}

/**
 * @tc.name: DfxHisysEventTest_ReportKeyEventTest_007
 * @tc.desc: ReportKeyEvent with TOUCH_SCREEN_ON
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKeyEventTest_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "screen on";
    DfxHisysevent::ReportKeyEvent(name);
    EXPECT_EQ(name, "screen on");
}

/**
 * @tc.name: DfxHisysEventTest_ReportKeyEventTest_008
 * @tc.desc: ReportKeyEvent with unknown name (DISPATCH_KEY)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKeyEventTest_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "unknown";
    DfxHisysevent::ReportKeyEvent(name);
    EXPECT_EQ(name, "unknown");
}

/**
 * @tc.name: DfxHisysEventTest_ReportFailLaunchAbilityTest_001
 * @tc.desc: ReportFailLaunchAbility with normal parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailLaunchAbilityTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string bundleName = "com.test.app";
    int32_t errorCode = -1;
    DfxHisysevent::ReportFailLaunchAbility(bundleName, errorCode);
    EXPECT_EQ(errorCode, -1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportFailLaunchAbilityTest_002
 * @tc.desc: ReportFailLaunchAbility with zero errorCode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailLaunchAbilityTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string bundleName = "";
    int32_t errorCode = 0;
    DfxHisysevent::ReportFailLaunchAbility(bundleName, errorCode);
    EXPECT_EQ(errorCode, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportFailSubscribeKeyTest_001
 * @tc.desc: ReportFailSubscribeKey with normal parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailSubscribeKeyTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string functionName = "SubscribeKey";
    std::string subscribeName = "test";
    int32_t keyCode = 100;
    int32_t errorCode = -1;
    DfxHisysevent::ReportFailSubscribeKey(functionName, subscribeName, keyCode, errorCode);
    EXPECT_EQ(keyCode, 100);
}

/**
 * @tc.name: DfxHisysEventTest_ReportFailHandleKeyTest_001
 * @tc.desc: ReportFailHandleKey with normal parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportFailHandleKeyTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string name = "HandleKey";
    int32_t keyCode = 100;
    int32_t errorCode = -1;
    DfxHisysevent::ReportFailHandleKey(name, keyCode, errorCode);
    EXPECT_EQ(keyCode, 100);
}

/**
 * @tc.name: DfxHisysEventTest_ReportCallingMuteTest_001
 * @tc.desc: ReportCallingMute normal call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportCallingMuteTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DfxHisysevent::ReportCallingMute();
    EXPECT_EQ(0, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadKnuckleDoubleClickEventTest_001
 * @tc.desc: ReportTouchpadKnuckleDoubleClickEvent with fingerCount 1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadKnuckleDoubleClickEventTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t fingerCount = 1;
    DfxHisysevent::ReportTouchpadKnuckleDoubleClickEvent(fingerCount);
    EXPECT_EQ(fingerCount, 1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadKnuckleDoubleClickEventTest_002
 * @tc.desc: ReportTouchpadKnuckleDoubleClickEvent with fingerCount 2
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadKnuckleDoubleClickEventTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t fingerCount = 2;
    DfxHisysevent::ReportTouchpadKnuckleDoubleClickEvent(fingerCount);
    EXPECT_EQ(fingerCount, 2);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadKnuckleDoubleClickEventTest_003
 * @tc.desc: ReportTouchpadKnuckleDoubleClickEvent with fingerCount 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadKnuckleDoubleClickEventTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t fingerCount = 0;
    DfxHisysevent::ReportTouchpadKnuckleDoubleClickEvent(fingerCount);
    EXPECT_EQ(fingerCount, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadLeftEdgeSlideEventTest_001
 * @tc.desc: ReportTouchpadLeftEdgeSlideEvent normal call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadLeftEdgeSlideEventTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DfxHisysevent::ReportTouchpadLeftEdgeSlideEvent();
    EXPECT_EQ(0, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadRightEdgeSlideEventTest_001
 * @tc.desc: ReportTouchpadRightEdgeSlideEvent normal call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadRightEdgeSlideEventTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DfxHisysevent::ReportTouchpadRightEdgeSlideEvent();
    EXPECT_EQ(0, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportTouchpadSwipeInwardEventTest_001
 * @tc.desc: ReportTouchpadSwipeInwardEvent normal call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportTouchpadSwipeInwardEventTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DfxHisysevent::ReportTouchpadSwipeInwardEvent();
    EXPECT_EQ(0, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureTrackLengthTest_001
 * @tc.desc: ReportKnuckleGestureTrackLength with normal length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureTrackLengthTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t knuckleGestureTrackLength = 100;
    DfxHisysevent::ReportKnuckleGestureTrackLength(knuckleGestureTrackLength);
    EXPECT_EQ(knuckleGestureTrackLength, 100);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureTrackLengthTest_002
 * @tc.desc: ReportKnuckleGestureTrackLength with zero length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureTrackLengthTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t knuckleGestureTrackLength = 0;
    DfxHisysevent::ReportKnuckleGestureTrackLength(knuckleGestureTrackLength);
    EXPECT_EQ(knuckleGestureTrackLength, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureTrackTimeTest_001
 * @tc.desc: ReportKnuckleGestureTrackTime with valid timestamps
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureTrackTimeTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int64_t> gestureTimeStamps = {1000, 2000};
    DfxHisysevent::ReportKnuckleGestureTrackTime(gestureTimeStamps);
    EXPECT_EQ(gestureTimeStamps.size(), 2);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureTrackTimeTest_002
 * @tc.desc: ReportKnuckleGestureTrackTime with multiple timestamps
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureTrackTimeTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int64_t> gestureTimeStamps = {1000, 2000, 3000, 4000};
    DfxHisysevent::ReportKnuckleGestureTrackTime(gestureTimeStamps);
    EXPECT_EQ(gestureTimeStamps.size(), 4);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureTrackTimeTest_003
 * @tc.desc: ReportKnuckleGestureTrackTime with insufficient timestamps
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureTrackTimeTest_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int64_t> gestureTimeStamps = {1000};
    DfxHisysevent::ReportKnuckleGestureTrackTime(gestureTimeStamps);
    EXPECT_EQ(gestureTimeStamps.size(), 1);
}

/**
 * @tc.name: DfxHisysEventTest_ReportKnuckleGestureTrackTimeTest_004
 * @tc.desc: ReportKnuckleGestureTrackTime with empty timestamps
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportKnuckleGestureTrackTimeTest_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int64_t> gestureTimeStamps = {};
    DfxHisysevent::ReportKnuckleGestureTrackTime(gestureTimeStamps);
    EXPECT_EQ(gestureTimeStamps.size(), 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportScreenRecorderGestureTest_001
 * @tc.desc: ReportScreenRecorderGesture with normal intervalTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportScreenRecorderGestureTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t intervalTime = 1000;
    DfxHisysevent::ReportScreenRecorderGesture(intervalTime);
    EXPECT_EQ(intervalTime, 1000);
}

/**
 * @tc.name: DfxHisysEventTest_ReportScreenRecorderGestureTest_002
 * @tc.desc: ReportScreenRecorderGesture with zero intervalTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportScreenRecorderGestureTest_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t intervalTime = 0;
    DfxHisysevent::ReportScreenRecorderGesture(intervalTime);
    EXPECT_EQ(intervalTime, 0);
}

/**
 * @tc.name: DfxHisysEventTest_ReportSmartShotSuccTimesTest_001
 * @tc.desc: ReportSmartShotSuccTimes normal call
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_ReportSmartShotSuccTimesTest_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DfxHisysevent::ReportSmartShotSuccTimes();
    EXPECT_EQ(0, 0);
}
} // namespace MMI
} // namespace OHOS