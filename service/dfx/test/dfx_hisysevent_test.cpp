/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <fstream>
#include "define_multimodal.h"
#include "dfx_hisysevent.h"
#include "mmi_log.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "DfxHisysEventTest" };
} // namespace

class DfxHisysEventTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: DfxHisysEventTest_OnClientConnectTest_001
 * @tc.desc: OnClientConnect
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnClientConnectTest_001, TestSize.Level1)
{
    OHOS::HiviewDFX::HiSysEvent::EventType type = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
    DfxHisysevent::ClientConnectData data;
    data.pid = 100;
    int32_t res = 100;
    DfxHisysevent::OnClientConnect(data, type);
    type = OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR;
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
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::StatisticTouchpadGesture(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_BEGIN);
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::StatisticTouchpadGesture(pointerEvent));
    pointerEvent = nullptr;
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
    auto keyEvent = KeyEvent::Create();
    CHKPV(keyEvent);
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
    std::shared_ptr<PointerEvent> pointer = PointerEvent::Create();
    CHKPV(pointer);
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
    auto keyEvent = KeyEvent::Create();
    CHKPV(keyEvent);
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
    int32_t intervalTime = 1000;
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
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
    auto pointerEvent = PointerEvent::Create();
    CHKPV(pointerEvent);
    float distance = 10;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::ReportFailIfInvalidDistance(pointerEvent, distance));
}

/**
 * @tc.name: DfxHisysEventTest_OnDeviceConnectTest_002
 * @tc.desc: On device connect verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnDeviceConnectTest_002, TestSize.Level1)
{
    OHOS::HiviewDFX::HiSysEvent::EventType type = OHOS::HiviewDFX::HiSysEvent::EventType::FAULT;
    int32_t id = 2;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnDeviceConnect(id, type));
    id = INT32_MAX;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnDeviceConnect(id, type));
    type = OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR;
    id = 3;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnDeviceConnect(id, type));
    id = INT32_MAX;
    ASSERT_NO_FATAL_FAILURE(DfxHisysevent::OnDeviceConnect(id, type));
}

/**
 * @tc.name: DfxHisysEventTest_OnClientDisconnectTest_002
 * @tc.desc: On client disconnect verify
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DfxHisysEventTest, DfxHisysEventTest_OnClientDisconnectTest_002, TestSize.Level1)
{
    DfxHisysevent dfxHisysevent;
    SessionPtr secPtr = std::shared_ptr<OHOS::MMI::UDSSession>();
    secPtr->GetPid();
    secPtr->GetUid();
    secPtr->GetModuleType();
    secPtr->GetProgramName();
    ASSERT_NO_FATAL_FAILURE(dfxHisysevent.OnClientDisconnect(secPtr, 1,
OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR));
    ASSERT_NO_FATAL_FAILURE(dfxHisysevent.OnClientDisconnect(secPtr, 1, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT));
    secPtr = nullptr;
    ASSERT_NO_FATAL_FAILURE(dfxHisysevent.OnClientDisconnect(secPtr, 1, OHOS::HiviewDFX::HiSysEvent::EventType::FAULT));
}
} // namespace MMI
} // namespace OHOS