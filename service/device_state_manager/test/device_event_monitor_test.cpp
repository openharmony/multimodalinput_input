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
 * @tc.desc: Test the funcation InitCommonEventSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, InitCommonEventSubscriber_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    deviceEventMonitor.hasInit_ = true;
    EXPECT_NO_FATAL_FAILURE(deviceEventMonitor.InitCommonEventSubscriber());
}
/**
 * @tc.name: InitCommonEventSubscriber_002
 * @tc.desc: Test the funcation InitCommonEventSubscriber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, InitCommonEventSubscriber_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    deviceEventMonitor.hasInit_ = false;
    EXPECT_NO_FATAL_FAILURE(deviceEventMonitor.InitCommonEventSubscriber());
}
/**
 * @tc.name: SetCallState_001
 * @tc.desc: Test the funcation SetCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    want.SetParam("state", 1);
    ced.SetWant(want);
    deviceEventMonitor.hasHandleRingMute_ = true;
    deviceEventMonitor.SetCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.callState_, -1);
    want.SetParam("state", 4);
    ced.SetWant(want);
    EXPECT_NO_FATAL_FAILURE(deviceEventMonitor.SetCallState(ced, 1));
    want.SetParam("state", 6);
    ced.SetWant(want);
    EXPECT_NO_FATAL_FAILURE(deviceEventMonitor.SetCallState(ced, 1));
    deviceEventMonitor.hasHandleRingMute_ = false;
    EXPECT_NO_FATAL_FAILURE(deviceEventMonitor.SetCallState(ced, 1));
}

/**
 * @tc.name: SetCallState_002
 * @tc.desc: Test the funcation SetCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    deviceEventMonitor.hasHandleRingMute_ = true;
    want.SetParam("state", 1);
    ced.SetWant(want);
    deviceEventMonitor.SetCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.callState_, 1);

    want.SetParam("state", 5);
    ced.SetWant(want);
    deviceEventMonitor.SetCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.callState_, 5);
    
    want.SetParam("state", 4);
    ced.SetWant(want);
    deviceEventMonitor.SetCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.callState_, 4);
}
/**
 * @tc.name: SetCallState_005
 * @tc.desc: Test the funcation SetCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    deviceEventMonitor.hasHandleRingMute_ = false;
    want.SetParam("state", 4);
    ced.SetWant(want);
    deviceEventMonitor.SetCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.callState_, 4);
    want.SetParam("state", 5);
    ced.SetWant(want);
    deviceEventMonitor.SetCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.callState_, 5);
}

/**
 * @tc.name: SetCallState_006
 * @tc.desc: Test the funcation SetCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    deviceEventMonitor.hasHandleRingMute_ = true;
    want.SetParam("state", 1);
    ced.SetWant(want);
    deviceEventMonitor.SetCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.callState_, 1);
    deviceEventMonitor.hasHandleRingMute_ = false;
    deviceEventMonitor.SetCallState(ced, 1);
}
/**
 * @tc.name: SetCallState_003
 * @tc.desc: Test the funcation SetCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    deviceEventMonitor.hasHandleRingMute_ = true;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    deviceEventMonitor.SetCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.callState_, -1);
}

/**
 * @tc.name: SetCallState_004
 * @tc.desc: Test the funcation SetCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetCallState_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    deviceEventMonitor.hasHandleRingMute_ = true;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    deviceEventMonitor.SetCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.callType_, 0);
}

/**
 * @tc.name: SetVoipCallState_001
 * @tc.desc: Test the funcation SetVoipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    want.SetParam("state", 1);
    ced.SetWant(want);
    deviceEventMonitor.hasHandleRingMute_ = true;
    deviceEventMonitor.SetVoipCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.voipCallState_, 1);
 
    want.SetParam("state", 5);
    ced.SetWant(want);
    deviceEventMonitor.SetVoipCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.voipCallState_, 5);
    
    want.SetParam("state", 4);
    ced.SetWant(want);
    deviceEventMonitor.SetVoipCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.voipCallState_, 4);
}
 
/**
 * @tc.name: SetVoipCallState_002
 * @tc.desc: Test the funcation SetVoipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    deviceEventMonitor.hasHandleRingMute_ = true;
    want.SetParam("state", 1);
    ced.SetWant(want);
    deviceEventMonitor.SetVoipCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.voipCallState_, 1);
 
    want.SetParam("state", 5);
    ced.SetWant(want);
    deviceEventMonitor.SetVoipCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.voipCallState_, 5);
    
    want.SetParam("state", 4);
    ced.SetWant(want);
    deviceEventMonitor.SetVoipCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.voipCallState_, 4);
}
/**
 * @tc.name: SetVoipCallState_005
 * @tc.desc: Test the funcation SetVoipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    deviceEventMonitor.hasHandleRingMute_ = false;
    want.SetParam("state", 4);
    ced.SetWant(want);
    deviceEventMonitor.SetVoipCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.voipCallState_, 4);
    want.SetParam("state", 5);
    ced.SetWant(want);
    deviceEventMonitor.SetVoipCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.voipCallState_, 5);
}
 
/**
 * @tc.name: SetVoipCallState_006
 * @tc.desc: Test the funcation SetVoipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    deviceEventMonitor.hasHandleRingMute_ = true;
    want.SetParam("state", 1);
    ced.SetWant(want);
    deviceEventMonitor.SetVoipCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.voipCallState_, 1);
    deviceEventMonitor.hasHandleRingMute_ = false;
    deviceEventMonitor.SetVoipCallState(ced, 1);
}

/**
 * @tc.name: SetVoipCallState_003
 * @tc.desc: Test the funcation SetVoipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    deviceEventMonitor.hasHandleRingMute_ = true;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    deviceEventMonitor.SetVoipCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.voipCallState_, -1);
}

/**
 * @tc.name: SetVoipCallState_004
 * @tc.desc: Test the funcation SetVoipCallState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, SetVoipCallState_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    deviceEventMonitor.hasHandleRingMute_ = true;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    deviceEventMonitor.SetVoipCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.callType_, 1);
}

/**
 * @tc.name: GetCallType_001
 * @tc.desc: Test the funcation GetCallType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetCallType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    deviceEventMonitor.hasHandleRingMute_ = true;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    deviceEventMonitor.SetCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.GetCallType(), 0);
}

/**
 * @tc.name: GetCallType_002
 * @tc.desc: Test the funcation GetCallType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DeviceEventMonitorTest, GetCallType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DeviceEventMonitor deviceEventMonitor;
    deviceEventMonitor.hasHandleRingMute_ = true;
    EventFwk::CommonEventData ced;
    EventFwk::Want want;
    want.SetParam("slotId", 1);
    ced.SetWant(want);
    deviceEventMonitor.SetVoipCallState(ced, 1);
    ASSERT_EQ(deviceEventMonitor.GetCallType(), 1);
}
} // namespace MMI
} // namespace OHOS