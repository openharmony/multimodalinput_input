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

#include "device_event_monitor.h"
#include "mmi_log.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "want.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DeviceEventMonitorTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class DeviceEventMonitorTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};


/**
 * @tc.name: InitCommonEventSubscriber_001
 * @tc.desc: Test the function InitCommonEventSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, InitCommonEventSubscriber_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->hasInit_ = true;
    EXPECT_NO_FATAL_FAILURE(DEVICE_MONITOR->InitCommonEventSubscriber());
}
/**
 * @tc.name: InitCommonEventSubscriber_002
 * @tc.desc: Test the function InitCommonEventSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, InitCommonEventSubscriber_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->hasInit_ = false;
    EXPECT_NO_FATAL_FAILURE(DEVICE_MONITOR->InitCommonEventSubscriber());
}
/**
 * @tc.name: SetCallState_001
 * @tc.desc: Test the function SetCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    want.SetParam("state", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    DEVICE_MONITOR->SetCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->callState_, -1);
    want.SetParam("state", 4);
    ced.SetWant(want);
    EXPECT_NO_FATAL_FAILURE(DEVICE_MONITOR->SetCallState(ced, 1));
    want.SetParam("state", 6);
    ced.SetWant(want);
    EXPECT_NO_FATAL_FAILURE(DEVICE_MONITOR->SetCallState(ced, 1));
    DEVICE_MONITOR->hasHandleRingMute_ = false;
    EXPECT_NO_FATAL_FAILURE(DEVICE_MONITOR->SetCallState(ced, 1));
}

/**
 * @tc.name: SetCallState_002
 * @tc.desc: Test the function SetCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    want.SetParam("state", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->callState_, 1);

    want.SetParam("state", 5);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->callState_, 5);
    
    want.SetParam("state", 4);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->callState_, 4);
}
/**
 * @tc.name: SetCallState_005
 * @tc.desc: Test the function SetCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    DEVICE_MONITOR->hasHandleRingMute_ = false;
    want.SetParam("state", 4);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->callState_, 4);
    want.SetParam("state", 5);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->callState_, 5);
}

/**
 * @tc.name: SetCallState_006
 * @tc.desc: Test the function SetCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    want.SetParam("state", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->callState_, 1);
    DEVICE_MONITOR->hasHandleRingMute_ = false;
    DEVICE_MONITOR->SetCallState(ced, 1);
}
/**
 * @tc.name: SetCallState_003
 * @tc.desc: Test the function SetCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->callState_, 1);
}

/**
 * @tc.name: SetCallState_004
 * @tc.desc: Test the function SetCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->callType_, 0);
}

/**
 * @tc.name: SetVoipCallState_001
 * @tc.desc: Test the function SetVoipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    want.SetParam("state", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->voipCallState_, -1);

    want.SetParam("state", 5);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->voipCallState_, -1);
    
    want.SetParam("state", 4);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->voipCallState_, -1);
}

/**
 * @tc.name: SetVoipCallState_002
 * @tc.desc: Test the function SetVoipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    want.SetParam("state", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->voipCallState_, 1);

    want.SetParam("state", 5);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->voipCallState_, 5);
    
    want.SetParam("state", 4);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->voipCallState_, 4);
}
/**
 * @tc.name: SetVoipCallState_005
 * @tc.desc: Test the function SetVoipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    DEVICE_MONITOR->hasHandleRingMute_ = false;
    want.SetParam("state", 4);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->voipCallState_, 4);
    want.SetParam("state", 5);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->voipCallState_, 5);
}

/**
 * @tc.name: SetVoipCallState_006
 * @tc.desc: Test the function SetVoipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    want.SetParam("state", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->voipCallState_, 1);
    DEVICE_MONITOR->hasHandleRingMute_ = false;
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
}

/**
 * @tc.name: SetVoipCallState_003
 * @tc.desc: Test the function SetVoipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->voipCallState_, 1);
}

/**
 * @tc.name: SetVoipCallState_004
 * @tc.desc: Test the function SetVoipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->callType_, 1);
}

/**
 * @tc.name: GetCallType_001
 * @tc.desc: Test the function GetCallType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetCallType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->GetCallType(), 0);
}

/**
 * @tc.name: GetCallType_002
 * @tc.desc: Test the function GetCallType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetCallType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->hasHandleRingMute_ = true;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->GetCallType(), 1);
}
/**
 * @tc.name: GetCallState_Initial_001
 * @tc.desc: Test GetCallState returns -1 initially
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetCallState_Initial_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData emptyEvent;
    EventFwk::Want emptyWant;
    emptyWant.SetParam("state", -1);
    emptyEvent.SetWant(emptyWant);
    DEVICE_MONITOR->SetCallState(emptyEvent, -1);
    
    int32_t initialState = DEVICE_MONITOR->GetCallState();
    ASSERT_EQ(initialState, -1);
}

/**
 * @tc.name: GetCallState_AfterSetIncoming_001
 * @tc.desc: Test GetCallState returns INCOMING after setting incoming state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetCallState_AfterSetIncoming_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    want.SetParam("state", CALL_STATUS_INCOMING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_INCOMING);
    
    int32_t newState = DEVICE_MONITOR->GetCallState();
    ASSERT_EQ(newState, CALL_STATUS_INCOMING);
}

/**
 * @tc.name: GetCallState_AfterSetActive_001
 * @tc.desc: Test GetCallState returns ACTIVE after setting active state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetCallState_AfterSetActive_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    want.SetParam("state", CALL_STATUS_ACTIVE);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_ACTIVE);
    
    int32_t newState = DEVICE_MONITOR->GetCallState();
    ASSERT_EQ(newState, CALL_STATUS_ACTIVE);
}

/**
 * @tc.name: GetVoipCallState_Initial_001
 * @tc.desc: Test GetVoipCallState returns -1 initially
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetVoipCallState_Initial_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData emptyEvent;
    EventFwk::Want emptyWant;
    emptyWant.SetParam("state", -1);
    emptyEvent.SetWant(emptyWant);
    DEVICE_MONITOR->SetVoipCallState(emptyEvent, -1);
    
    int32_t initialState = DEVICE_MONITOR->GetVoipCallState();
    ASSERT_EQ(initialState, -1);
}

/**
 * @tc.name: GetVoipCallState_AfterSetIncoming_001
 * @tc.desc: Test GetVoipCallState returns INCOMING after setting incoming state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetVoipCallState_AfterSetIncoming_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    want.SetParam("state", CALL_STATUS_INCOMING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_INCOMING);
    
    int32_t newState = DEVICE_MONITOR->GetVoipCallState();
    ASSERT_EQ(newState, CALL_STATUS_INCOMING);
}

/**
 * @tc.name: GetVoipCallState_AfterSetActive_001
 * @tc.desc: Test GetVoipCallState returns ACTIVE after setting active state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetVoipCallState_AfterSetActive_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    want.SetParam("state", CALL_STATUS_ACTIVE);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_ACTIVE);
    
    int32_t newState = DEVICE_MONITOR->GetVoipCallState();
    ASSERT_EQ(newState, CALL_STATUS_ACTIVE);
}

/**
 * @tc.name: GetHasHandleRingMute_Initial_001
 * @tc.desc: Test GetHasHandleRingMute returns false initially after reset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetHasHandleRingMute_Initial_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->SetHasHandleRingMute(false);
    bool initialValue = DEVICE_MONITOR->GetHasHandleRingMute();
    ASSERT_FALSE(initialValue);
}

/**
 * @tc.name: GetHasHandleRingMute_AfterSetTrue_001
 * @tc.desc: Test GetHasHandleRingMute returns true after setting true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetHasHandleRingMute_AfterSetTrue_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->SetHasHandleRingMute(true);
    bool newValue = DEVICE_MONITOR->GetHasHandleRingMute();
    ASSERT_TRUE(newValue);
}

/**
 * @tc.name: GetHasHandleRingMute_AfterSetFalse_001
 * @tc.desc: Test GetHasHandleRingMute returns false after setting false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetHasHandleRingMute_AfterSetFalse_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->SetHasHandleRingMute(false);
    bool newValue = DEVICE_MONITOR->GetHasHandleRingMute();
    ASSERT_FALSE(newValue);
}

/**
 * @tc.name: SetHasHandleRingMute_SetTrue_001
 * @tc.desc: Test SetHasHandleRingMute can set to true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetHasHandleRingMute_SetTrue_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->SetHasHandleRingMute(true);
    ASSERT_TRUE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetHasHandleRingMute_SetFalse_001
 * @tc.desc: Test SetHasHandleRingMute can set to false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetHasHandleRingMute_SetFalse_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DEVICE_MONITOR->SetHasHandleRingMute(false);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetCallState_Disconnected_001
 * @tc.desc: Test SetCallState with DISCONNECTED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_Disconnected_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    want.SetParam("state", CALL_STATUS_DISCONNECTED);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_DISCONNECTED);
    ASSERT_EQ(DEVICE_MONITOR->GetCallState(), CALL_STATUS_DISCONNECTED);
}

/**
 * @tc.name: SetCallState_Disconnecting_001
 * @tc.desc: Test SetCallState with DISCONNECTING state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_Disconnecting_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    want.SetParam("state", CALL_STATUS_DISCONNECTING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_DISCONNECTING);
    ASSERT_EQ(DEVICE_MONITOR->GetCallState(), CALL_STATUS_DISCONNECTING);
}

/**
 * @tc.name: SetVoipCallState_Disconnected_001
 * @tc.desc: Test SetVoipCallState with DISCONNECTED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_Disconnected_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    want.SetParam("state", CALL_STATUS_DISCONNECTED);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_DISCONNECTED);
    ASSERT_EQ(DEVICE_MONITOR->GetVoipCallState(), CALL_STATUS_DISCONNECTED);
}

/**
 * @tc.name: SetVoipCallState_Disconnecting_001
 * @tc.desc: Test SetVoipCallState with DISCONNECTING state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_Disconnecting_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    want.SetParam("state", CALL_STATUS_DISCONNECTING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_DISCONNECTING);
    ASSERT_EQ(DEVICE_MONITOR->GetVoipCallState(), CALL_STATUS_DISCONNECTING);
}

/**
 * @tc.name: SetCallState_WithSlotId_StateNotUpdated_001
 * @tc.desc: Test SetCallState with slotId does not update callState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_WithSlotId_StateNotUpdated_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    want.SetParam("state", CALL_STATUS_ACTIVE);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_ACTIVE);
    ASSERT_EQ(DEVICE_MONITOR->GetCallState(), CALL_STATUS_ACTIVE);
    
    want.SetParam("slotId", 1);
    want.SetParam("state", CALL_STATUS_INCOMING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_INCOMING);
    ASSERT_EQ(DEVICE_MONITOR->GetCallState(), CALL_STATUS_ACTIVE);
}

/**
 * @tc.name: SetVoipCallState_WithSlotId_StateNotUpdated_001
 * @tc.desc: Test SetVoipCallState with slotId does not update voipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_WithSlotId_StateNotUpdated_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    want.SetParam("state", CALL_STATUS_ACTIVE);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_ACTIVE);
    ASSERT_EQ(DEVICE_MONITOR->GetVoipCallState(), CALL_STATUS_ACTIVE);
    
    want.SetParam("slotId", 1);
    want.SetParam("state", CALL_STATUS_INCOMING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_INCOMING);
    ASSERT_EQ(DEVICE_MONITOR->GetVoipCallState(), CALL_STATUS_ACTIVE);
}

/**
 * @tc.name: SetCallState_RingMuteRemainsTrueWhenStateChangesToIncoming_001
 * @tc.desc: Test hasHandleRingMute_ remains true when state changes to INCOMING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_RingMuteRemainsTrueWhenStateChangesToIncoming_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("state", CALL_STATUS_INCOMING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_INCOMING);
    ASSERT_TRUE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetVoipCallState_RingMuteNotResetWhenStateChangesFromActive_001
 * @tc.desc: Test hasHandleRingMute_ not reset when voip state changes from ACTIVE to DISCONNECTED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_RingMuteNotResetWhenStateChangesFromActive_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    DEVICE_MONITOR->SetHasHandleRingMute(true);
    
    want.SetParam("state", CALL_STATUS_ACTIVE);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_ACTIVE);
    ASSERT_TRUE(DEVICE_MONITOR->GetHasHandleRingMute());
    
    want.SetParam("state", CALL_STATUS_DISCONNECTED);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_DISCONNECTED);
    ASSERT_TRUE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetVoipCallState_RingMuteRemainsTrueWhenStateChangesToIncoming_001
 * @tc.desc: Test hasHandleRingMute_ remains true when voip state changes to INCOMING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_RingMuteRemainsTrueWhenStateChangesToIncoming_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("state", CALL_STATUS_INCOMING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_INCOMING);
    ASSERT_TRUE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetCallState_ResetRingMuteOnIncomingOrWaiting_001
 * @tc.desc: Test hasHandleRingMute_ reset when state changes to INCOMING or WAITING with hasHandleRingMute true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_ResetRingMuteOnIncomingOrWaiting_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;

    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("state", CALL_STATUS_INCOMING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_INCOMING);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());

    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("state", CALL_STATUS_WAITING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_WAITING);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetCallState_ResetRingMuteOnDisconnected_001
 * @tc.desc: Test hasHandleRingMute_ reset when state changes to DISCONNECTED with hasHandleRingMute true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_ResetRingMuteOnDisconnected_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("state", CALL_STATUS_DISCONNECTED);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_DISCONNECTED);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetVoipCallState_ResetRingMuteOnIncomingOrWaiting_001
 * @tc.desc: Test hasHandleRingMute_ reset when voip state changes to INCOMING or WAITING with hasHandleRingMute true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_ResetRingMuteOnIncomingOrWaiting_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;

    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("state", CALL_STATUS_INCOMING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_INCOMING);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());

    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("state", CALL_STATUS_WAITING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_WAITING);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetVoipCallState_ResetRingMuteOnDisconnected_001
 * @tc.desc: Test hasHandleRingMute_ reset when voip state changes to DISCONNECTED with hasHandleRingMute true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_ResetRingMuteOnDisconnected_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("state", CALL_STATUS_DISCONNECTED);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_DISCONNECTED);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetCallState_WithSlotId_ResetRingMuteOnIncoming_001
 * @tc.desc: Test hasHandleRingMute_ reset when slotId present and state is INCOMING or DISCONNECTED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_WithSlotId_ResetRingMuteOnIncoming_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;

    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("slotId", 1);
    want.SetParam("state", CALL_STATUS_INCOMING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_INCOMING);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());

    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("slotId", 1);
    want.SetParam("state", CALL_STATUS_DISCONNECTED);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_DISCONNECTED);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());

    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("slotId", 1);
    want.SetParam("state", CALL_STATUS_ACTIVE);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_ACTIVE);
    ASSERT_TRUE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetVoipCallState_WithSlotId_ResetRingMuteOnIncoming_001
 * @tc.desc: Test hasHandleRingMute_ reset when slotId present and voip state is INCOMING or DISCONNECTED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_WithSlotId_ResetRingMuteOnIncoming_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;

    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("slotId", 1);
    want.SetParam("state", CALL_STATUS_INCOMING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_INCOMING);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());

    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("slotId", 1);
    want.SetParam("state", CALL_STATUS_DISCONNECTED);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_DISCONNECTED);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());

    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("slotId", 1);
    want.SetParam("state", CALL_STATUS_ACTIVE);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_ACTIVE);
    ASSERT_TRUE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetCallState_NoSlotId_NoRingMuteResetWhenStateNotMatching_001
 * @tc.desc: Test hasHandleRingMute_ not reset when state is not INCOMING, WAITING, or DISCONNECTED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_NoSlotId_NoRingMuteResetWhenStateNotMatching_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("state", CALL_STATUS_ACTIVE);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_ACTIVE);
    ASSERT_TRUE(DEVICE_MONITOR->GetHasHandleRingMute());
    
    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("state", CALL_STATUS_HOLDING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_HOLDING);
    ASSERT_TRUE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetVoipCallState_NoSlotId_NoRingMuteResetWhenStateNotMatching_001
 * @tc.desc: Test hasHandleRingMute_ not reset when voip state is not INCOMING, WAITING, or DISCONNECTED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_NoSlotId_NoRingMuteResetWhenStateNotMatching_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("state", CALL_STATUS_ACTIVE);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_ACTIVE);
    ASSERT_TRUE(DEVICE_MONITOR->GetHasHandleRingMute());
    
    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("state", CALL_STATUS_HOLDING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_HOLDING);
    ASSERT_TRUE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetCallState_UpdateCallType_001
 * @tc.desc: Test callType_ is set to NORMAL_CALL when SetCallState is called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_UpdateCallType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->GetCallType(), 1);
    
    DEVICE_MONITOR->SetCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->GetCallType(), 0);
}

/**
 * @tc.name: SetVoipCallState_UpdateCallType_001
 * @tc.desc: Test callType_ is set to VOIP_CALL when SetVoipCallState is called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_UpdateCallType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->GetCallType(), 0);
    
    DEVICE_MONITOR->SetVoipCallState(ced, 1);
    ASSERT_EQ(DEVICE_MONITOR->GetCallType(), 1);
}

/**
 * @tc.name: SetCallState_WithSlotId_StateNotUpdatedButRingMuteReset_001
 * @tc.desc: Test with slotId, callState not updated but hasHandleRingMute_ can be reset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_WithSlotId_StateNotUpdatedButRingMuteReset_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;

    want.SetParam("state", CALL_STATUS_ACTIVE);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_ACTIVE);
    ASSERT_EQ(DEVICE_MONITOR->GetCallState(), CALL_STATUS_ACTIVE);

    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("slotId", 1);
    want.SetParam("state", CALL_STATUS_INCOMING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetCallState(ced, CALL_STATUS_INCOMING);

    ASSERT_EQ(DEVICE_MONITOR->GetCallState(), CALL_STATUS_ACTIVE);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());
}

/**
 * @tc.name: SetVoipCallState_WithSlotId_StateNotUpdatedButRingMuteReset_001
 * @tc.desc: Test with slotId, voipCallState not updated but hasHandleRingMute_ can be reset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_WithSlotId_StateNotUpdatedButRingMuteReset_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;

    want.SetParam("state", CALL_STATUS_ACTIVE);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_ACTIVE);
    ASSERT_EQ(DEVICE_MONITOR->GetVoipCallState(), CALL_STATUS_ACTIVE);

    DEVICE_MONITOR->SetHasHandleRingMute(true);
    want.SetParam("slotId", 1);
    want.SetParam("state", CALL_STATUS_INCOMING);
    ced.SetWant(want);
    DEVICE_MONITOR->SetVoipCallState(ced, CALL_STATUS_INCOMING);

    ASSERT_EQ(DEVICE_MONITOR->GetVoipCallState(), CALL_STATUS_ACTIVE);
    ASSERT_FALSE(DEVICE_MONITOR->GetHasHandleRingMute());
}
} // namespace MMI
} // namespace OHOS