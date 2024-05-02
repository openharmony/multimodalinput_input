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
#include <libinput.h>

#include "multimodal_input_connect_stub.h"
#include "mmi_service.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class MultimodalInputConnectStubTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDoen() {}
};

/**
 * @tc.name: StubHandleAllocSocketFd_001
 * @tc.desc: Test the function StubHandleAllocSocketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubHandleAllocSocketFd_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubHandleAllocSocketFd(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubAddInputEventFilter_001
 * @tc.desc: Test the function StubAddInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputEventFilter_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 22;
    int32_t ret = stub->StubAddInputEventFilter(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubRemoveInputEventFilter_001
 * @tc.desc: Test the function StubRemoveInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputEventFilter_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 201;
    int32_t ret = stub->StubRemoveInputEventFilter(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetMouseScrollRows_001
 * @tc.desc: Test the function StubSetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseScrollRows_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetMouseScrollRows(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetCustomCursor_001
 * @tc.desc: Test the function StubSetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetCustomCursor_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetCustomCursor(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetMouseIcon_001
 * @tc.desc: Test the function StubSetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseIcon_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetMouseIcon(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetMouseHotSpot_001
 * @tc.desc: Test the function StubSetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseHotSpot_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetMouseHotSpot(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubGetMouseScrollRows_001
 * @tc.desc: Test the function StubGetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetMouseScrollRows_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubGetMouseScrollRows(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetPointerSize_001
 * @tc.desc: Test the function StubSetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerSize_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetPointerSize(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetNapStatus_001
 * @tc.desc: Test the function StubSetNapStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetNapStatus_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetNapStatus(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubGetPointerSize_001
 * @tc.desc: Test the function StubGetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetPointerSize_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubGetPointerSize(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetPointerSize_002
 * @tc.desc: Test the function StubGetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetPointerSize_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubGetPointerSize(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubGetPointerSize(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetMousePrimaryButton_001
 * @tc.desc: Test the function StubSetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetMousePrimaryButton_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetMousePrimaryButton(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetMousePrimaryButton_001
 * @tc.desc: Test the function StubGetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetMousePrimaryButton_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetMousePrimaryButton(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetHoverScrollState_001
 * @tc.desc: Test the function StubSetHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetHoverScrollState_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetHoverScrollState(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetHoverScrollState_001
 * @tc.desc: Test the function StubGetHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetHoverScrollState_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetHoverScrollState(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetPointerVisible_001
 * @tc.desc: Test the function StubSetPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetPointerVisible_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetPointerVisible(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubIsPointerVisible_001
 * @tc.desc: Test the function StubIsPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubIsPointerVisible_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubIsPointerVisible(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubMarkProcessed_001
 * @tc.desc: Test the function StubMarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubMarkProcessed_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubMarkProcessed(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetPointerColor_001
 * @tc.desc: Test the function StubSetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetPointerColor_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetPointerColor(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetPointerColor(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetPointerColor_001
 * @tc.desc: Test the function StubGetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetPointerColor_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubGetPointerColor(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubGetPointerColor(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetPointerSpeed_001
 * @tc.desc: Test the function StubSetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetPointerSpeed_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetPointerSpeed(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetPointerSpeed_001
 * @tc.desc: Test the function StubGetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetPointerSpeed_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetPointerSpeed(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubNotifyNapOnline_001
 * @tc.desc: Test the function StubNotifyNapOnline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubNotifyNapOnline_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubNotifyNapOnline(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubRemoveInputEventObserver_001
 * @tc.desc: Test the function StubRemoveInputEventObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputEventObserver_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubRemoveInputEventObserver(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetPointerStyle_001
 * @tc.desc: Test the function StubSetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetPointerStyle_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetPointerStyle(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubClearWindowPointerStyle_001
 * @tc.desc: Test the function StubClearWindowPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubClearWindowPointerStyle_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubClearWindowPointerStyle(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetPointerStyle_001
 * @tc.desc: Test the function StubGetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetPointerStyle_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetPointerStyle(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSupportKeys_001
 * @tc.desc: Test the function StubSupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSupportKeys_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSupportKeys(data, reply);
    EXPECT_NE(ret, RET_OK);
}
/**
 * @tc.name: StubGetDevice_001
 * @tc.desc: Test the function StubGetDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetDevice_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 201;
    int32_t ret = stub->StubGetDevice(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubRegisterInputDeviceMonitor_001
 * @tc.desc: Test the function StubRegisterInputDeviceMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRegisterInputDeviceMonitor_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubRegisterInputDeviceMonitor(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: StubGetKeyboardType_001
 * @tc.desc: Test the function StubGetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetKeyboardType_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 201;
    int32_t ret = stub->StubGetKeyboardType(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubAddInputHandler_001
 * @tc.desc: Test the function StubAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAddInputHandler_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubAddInputHandler(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubRemoveInputHandler_001
 * @tc.desc: Test the function StubRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubRemoveInputHandler_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubRemoveInputHandler(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubMarkEventConsumed_001
 * @tc.desc: Test the function StubMarkEventConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMarkEventConsumed_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubMarkEventConsumed(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSubscribeKeyEvent_001
 * @tc.desc: Test the function StubSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSubscribeKeyEvent_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSubscribeKeyEvent(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubUnsubscribeKeyEvent_001
 * @tc.desc: Test the function StubUnsubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubUnsubscribeKeyEvent_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubUnsubscribeKeyEvent(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSubscribeSwitchEvent_001
 * @tc.desc: Test the function StubSubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSubscribeSwitchEvent_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSubscribeSwitchEvent(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubUnsubscribeSwitchEvent_001
 * @tc.desc: Test the function StubUnsubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubUnsubscribeSwitchEvent_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubUnsubscribeSwitchEvent(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubMoveMouseEvent_001
 * @tc.desc: Test the function StubMoveMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubMoveMouseEvent_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubMoveMouseEvent(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubInjectKeyEvent_001
 * @tc.desc: Test the function StubInjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectKeyEvent_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubInjectKeyEvent(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetAnrListener_001
 * @tc.desc: Test the function StubSetAnrListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetAnrListener_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetAnrListener(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubGetDisplayBindInfo_001
 * @tc.desc: Test the function StubGetDisplayBindInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetDisplayBindInfo_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubGetDisplayBindInfo(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubGetAllMmiSubscribedEvents_001
 * @tc.desc: Test the function StubGetAllMmiSubscribedEvents
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetAllMmiSubscribedEvents_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubGetAllMmiSubscribedEvents(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetDisplayBind_001
 * @tc.desc: Test the function StubSetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetDisplayBind_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetDisplayBind(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubGetFunctionKeyState_001
 * @tc.desc: Test the function StubGetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetFunctionKeyState_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubGetFunctionKeyState(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetFunctionKeyState_001
 * @tc.desc: Test the function StubSetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetFunctionKeyState_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetFunctionKeyState(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetPointerLocation_001
 * @tc.desc: Test the function StubSetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerLocation_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetPointerLocation(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetMouseCaptureMode_001
 * @tc.desc: Test the function StubSetMouseCaptureMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseCaptureMode_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 201;
    int32_t ret = stub->StubSetMouseCaptureMode(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetWindowPid_001
 * @tc.desc: Test the function StubGetWindowPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetWindowPid_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubGetWindowPid(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubGetWindowPid(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubAppendExtraData_001
 * @tc.desc: Test the function StubAppendExtraData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubAppendExtraData_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubAppendExtraData(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubAppendExtraData(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubEnableCombineKey_001
 * @tc.desc: Test the function StubEnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubEnableCombineKey_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubEnableCombineKey(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubEnableCombineKey(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubEnableInputDevice_001
 * @tc.desc: Test the function StubEnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubEnableInputDevice_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubEnableInputDevice(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubEnableInputDevice(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetKeyDownDuration_001
 * @tc.desc: Test the function StubSetKeyDownDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetKeyDownDuration_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetKeyDownDuration(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetKeyDownDuration(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_VerifyTouchPadSetting_001
 * @tc.desc: Test the function VerifyTouchPadSetting
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_VerifyTouchPadSetting_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->VerifyTouchPadSetting();
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->VerifyTouchPadSetting();
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetTouchpadScrollSwitch_001
 * @tc.desc: Test the function StubSetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadScrollSwitch_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetTouchpadScrollSwitch(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetTouchpadScrollSwitch_001
 * @tc.desc: Test the function StubGetTouchpadScrollSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadScrollSwitch_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetTouchpadScrollSwitch(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetTouchpadScrollDirection_001
 * @tc.desc: Test the function StubSetTouchpadScrollDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadScrollDirection_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetTouchpadScrollDirection(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetTouchpadScrollDirection_001
 * @tc.desc: Test the function StubGetTouchpadScrollDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadScrollDirection_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetTouchpadScrollDirection(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetTouchpadTapSwitch_001
 * @tc.desc: Test the function StubSetTouchpadTapSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetTouchpadTapSwitch_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetTouchpadTapSwitch(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetTouchpadTapSwitch_001
 * @tc.desc: Test the function StubGetTouchpadTapSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetTouchpadTapSwitch_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetTouchpadTapSwitch(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetTouchpadPointerSpeed_001
 * @tc.desc: Test the function StubSetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadPointerSpeed_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetTouchpadPointerSpeed(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetTouchpadPointerSpeed_001
 * @tc.desc: Test the function StubGetTouchpadPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadPointerSpeed_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetTouchpadPointerSpeed(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetKeyboardRepeatDelay_001
 * @tc.desc: Test the function StubSetKeyboardRepeatDelay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetKeyboardRepeatDelay_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetKeyboardRepeatDelay(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetKeyboardRepeatDelay(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetKeyboardRepeatRate_001
 * @tc.desc: Test the function StubSetKeyboardRepeatRate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetKeyboardRepeatRate_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetKeyboardRepeatRate(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetKeyboardRepeatRate(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetKeyboardRepeatDelay_001
 * @tc.desc: Test the function StubGetKeyboardRepeatDelay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetKeyboardRepeatDelay_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubGetKeyboardRepeatDelay(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubGetKeyboardRepeatDelay(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetKeyboardRepeatRate_001
 * @tc.desc: Test the function StubGetKeyboardRepeatRate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetKeyboardRepeatRate_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubGetKeyboardRepeatRate(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubGetKeyboardRepeatRate(data, reply);
    EXPECT_NE(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS