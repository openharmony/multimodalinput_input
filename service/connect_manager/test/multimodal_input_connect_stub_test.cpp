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
    void TearDown() {}
};

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetMouseHotSpot
 * @tc.desc: Test the function StubSetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetMouseHotSpot, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    std::shared_ptr<MMIService> service = std::static_pointer_cast<MMIService>(stub);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    MessageParcel data;
    MessageParcel reply;
    int32_t pid = 100;
    int32_t windowId = -1;
    int32_t hotSpotX = 300;
    int32_t hotSpotY = 300;
    data.WriteInt32(pid);
    data.WriteInt32(windowId);
    EXPECT_EQ(stub->StubSetMouseHotSpot(data, reply), MMISERVICE_NOT_RUNNING);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_NE(stub->StubSetMouseHotSpot(data, reply), RET_OK);
    windowId = 30;
    data.WriteInt32(pid);
    data.WriteInt32(windowId);
    data.WriteInt32(hotSpotX);
    data.WriteInt32(hotSpotY);
    EXPECT_NE(stub->StubSetMouseHotSpot(data, reply), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetMouseScrollRows
 * @tc.desc: Test the function StubGetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetMouseScrollRows, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    std::shared_ptr<MMIService> service = std::static_pointer_cast<MMIService>(stub);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(stub->StubGetMouseScrollRows(data, reply), MMISERVICE_NOT_RUNNING);

    service->state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_NE(stub->StubGetMouseScrollRows(data, reply), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetPointerSize
 * @tc.desc: Test the function StubSetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetPointerSize, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    std::shared_ptr<MMIService> service = std::static_pointer_cast<MMIService>(stub);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(stub->StubSetPointerSize(data, reply), MMISERVICE_NOT_RUNNING);
    int32_t size = 10;
    data.WriteInt32(size);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_NE(stub->StubSetPointerSize(data, reply), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetNapStatus
 * @tc.desc: Test the function StubSetNapStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetNapStatus, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    std::shared_ptr<MMIService> service = std::static_pointer_cast<MMIService>(stub);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(stub->StubSetNapStatus(data, reply), MMISERVICE_NOT_RUNNING);

    int32_t pid = 1000;
    int32_t uid = 1500;
    std::string bundleName = "abc";
    int32_t napStatus = 100;
    data.WriteInt32(pid);
    data.WriteInt32(uid);
    data.WriteString(bundleName);
    data.WriteInt32(napStatus);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_NE(stub->StubSetNapStatus(data, reply), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetPointerSize
 * @tc.desc: Test the function StubGetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetPointerSize, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    std::shared_ptr<MMIService> service = std::static_pointer_cast<MMIService>(stub);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(stub->StubGetPointerSize(data, reply), MMISERVICE_NOT_RUNNING);

    service->state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_NE(stub->StubGetPointerSize(data, reply), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetMousePrimaryButton
 * @tc.desc: Test the function StubSetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetMousePrimaryButton, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t primaryButton = 2072;
    data.WriteInt32(primaryButton);
    EXPECT_NE(stub->StubSetMousePrimaryButton(data, reply), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetHoverScrollState
 * @tc.desc: Test the function StubSetHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetHoverScrollState, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    bool state = false;
    data.WriteBool(state);
    EXPECT_NE(stub->StubSetHoverScrollState(data, reply), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetPointerVisible
 * @tc.desc: Test the function StubSetPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetPointerVisible, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    bool visible = true;
    int32_t priority = 1;
    data.WriteBool(visible);
    data.WriteInt32(priority);
    EXPECT_NE(stub->StubSetPointerVisible(data, reply), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubMarkProcessed
 * @tc.desc: Test the function StubMarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubMarkProcessed, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    std::shared_ptr<MMIService> service = std::static_pointer_cast<MMIService>(stub);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(stub->StubMarkProcessed(data, reply), RET_OK);

    int32_t eventType = 1;
    int32_t eventId = 100;
    data.WriteInt32(eventType);
    data.WriteInt32(eventId);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_NE(stub->StubMarkProcessed(data, reply), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetPointerColor
 * @tc.desc: Test the function StubSetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetPointerColor, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    std::shared_ptr<MMIService> service = std::static_pointer_cast<MMIService>(stub);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(stub->StubSetPointerColor(data, reply), RET_OK);

    int32_t color = 123456;
    data.WriteInt32(color);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_NE(stub->StubSetPointerColor(data, reply), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetPointerColor
 * @tc.desc: Test the function StubGetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetPointerColor, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    std::shared_ptr<MMIService> service = std::static_pointer_cast<MMIService>(stub);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(stub->StubGetPointerColor(data, reply), RET_OK);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_NE(stub->StubGetPointerColor(data, reply), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubAddInputHandler
 * @tc.desc: Test the function StubAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubAddInputHandler, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    std::shared_ptr<MMIService> service = std::static_pointer_cast<MMIService>(stub);
    service->state_ = ServiceRunningState::STATE_NOT_START;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(stub->StubAddInputHandler(data, reply), RET_OK);

    int32_t handlerType = InputHandlerType::NONE;
    uint32_t eventType = 0x1;
    int32_t priority = 1;
    uint32_t deviceTags = 100;
    data.WriteInt32(handlerType);
    data.WriteUint32(eventType);
    data.WriteInt32(priority);
    data.WriteUint32(deviceTags);
    service->state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_NE(stub->StubAddInputHandler(data, reply), RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_OnRemoteRequest_001
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ALLOC_SOCKET_FD);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubHandleAllocSocketFd(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ADD_INPUT_EVENT_FILTER);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubAddInputEventFilter(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::RMV_INPUT_EVENT_FILTER);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubRemoveInputEventFilter(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_MOUSE_SCROLL_ROWS);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetMouseScrollRows(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_MOUSE_SCROLL_ROWS);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetMouseScrollRows(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_SIZE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetPointerSize(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_SIZE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetPointerSize(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_CUSTOM_CURSOR);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetCustomCursor(data, reply);
    EXPECT_EQ(ret, temp);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_OnRemoteRequest_002
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_MOUSE_ICON);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubSetMouseIcon(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_MOUSE_PRIMARY_BUTTON);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetMousePrimaryButton(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_MOUSE_PRIMARY_BUTTON);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetMousePrimaryButton(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_HOVER_SCROLL_STATE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetHoverScrollState(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_HOVER_SCROLL_STATE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetHoverScrollState(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_VISIBLE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetPointerVisible(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_STYLE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetPointerStyle(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NOTIFY_NAP_ONLINE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubNotifyNapOnline(data, reply);
    EXPECT_EQ(ret, temp);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_OnRemoteRequest_003
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_003, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::RMV_INPUT_EVENT_OBSERVER);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubRemoveInputEventObserver(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_NAP_STATUS);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetNapStatus(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::CLEAN_WIDNOW_STYLE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubClearWindowPointerStyle(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_STYLE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetPointerStyle(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::IS_POINTER_VISIBLE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubIsPointerVisible(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::REGISTER_DEV_MONITOR);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubRegisterInputDeviceMonitor(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::REGISTER_DEV_MONITOR);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubRegisterInputDeviceMonitor(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::UNREGISTER_DEV_MONITOR);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubUnregisterInputDeviceMonitor(data, reply);
    EXPECT_EQ(ret, temp);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_OnRemoteRequest_004
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_004, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_DEVICE_IDS);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubGetDeviceIds(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_DEVICE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetDevice(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SUPPORT_KEYS);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSupportKeys(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_KEYBOARD_TYPE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetKeyboardType(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_COLOR);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetPointerColor(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_COLOR);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetPointerColor(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_SPEED);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetPointerSpeed(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_POINTER_SPEED);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetPointerSpeed(data, reply);
    EXPECT_EQ(ret, temp);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_OnRemoteRequest_005
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_005, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SUBSCRIBE_KEY_EVENT);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubSubscribeKeyEvent(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::UNSUBSCRIBE_KEY_EVENT);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubUnsubscribeKeyEvent(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SUBSCRIBE_SWITCH_EVENT);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSubscribeSwitchEvent(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::UNSUBSCRIBE_SWITCH_EVENT);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubUnsubscribeSwitchEvent(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::MARK_PROCESSED);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubMarkProcessed(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ADD_INPUT_HANDLER);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubAddInputHandler(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::REMOVE_INPUT_HANDLER);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubRemoveInputHandler(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::MARK_EVENT_CONSUMED);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubMarkEventConsumed(data, reply);
    EXPECT_EQ(ret, temp);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_OnRemoteRequest_006
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_006, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::MOVE_MOUSE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubMoveMouseEvent(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::INJECT_KEY_EVENT);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubInjectKeyEvent(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::INJECT_POINTER_EVENT);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubInjectPointerEvent(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_ANR_OBSERVER);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetAnrListener(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_DISPLAY_BIND_INFO);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetDisplayBindInfo(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_ALL_NAPSTATUS_DATA);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetAllMmiSubscribedEvents(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_DISPLAY_BIND);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetDisplayBind(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_FUNCTION_KEY_STATE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetFunctionKeyState(data, reply);
    EXPECT_EQ(ret, temp);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_OnRemoteRequest_007
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_007, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_FUNCTION_KEY_STATE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubSetFunctionKeyState(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_POINTER_LOCATION);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetPointerLocation(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_CAPTURE_MODE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetMouseCaptureMode(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_WINDOW_PID);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetWindowPid(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::APPEND_EXTRA_DATA);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubAppendExtraData(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ENABLE_INPUT_DEVICE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubEnableInputDevice(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ENABLE_COMBINE_KEY);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubEnableCombineKey(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_KEY_DOWN_DURATION);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetKeyDownDuration(data, reply);
    EXPECT_EQ(ret, temp);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_OnRemoteRequest_008
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_008, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_SCROLL_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubSetTouchpadScrollSwitch(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_SCROLL_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetTouchpadScrollSwitch(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_SCROLL_DIRECT_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetTouchpadScrollDirection(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_SCROLL_DIRECT_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetTouchpadScrollDirection(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_TAP_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetTouchpadTapSwitch(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_TAP_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetTouchpadTapSwitch(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_POINTER_SPEED);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetTouchpadPointerSpeed(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_POINTER_SPEED);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetTouchpadPointerSpeed(data, reply);
    EXPECT_EQ(ret, temp);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_OnRemoteRequest_009
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_009, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_KEYBOARD_REPEAT_DELAY);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubSetKeyboardRepeatDelay(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_KEYBOARD_REPEAT_RATE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetKeyboardRepeatRate(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_PINCH_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetTouchpadPinchSwitch(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_PINCH_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetTouchpadPinchSwitch(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_SWIPE_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetTouchpadSwipeSwitch(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_SWIPE_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetTouchpadSwipeSwitch(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_RIGHT_CLICK_TYPE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetTouchpadRightClickType(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_RIGHT_CLICK_TYPE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetTouchpadRightClickType(data, reply);
    EXPECT_EQ(ret, temp);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_OnRemoteRequest_010
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_010, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TP_ROTATE_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubSetTouchpadRotateSwitch(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TP_ROTATE_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetTouchpadRotateSwitch(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_KEYBOARD_REPEAT_DELAY);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetKeyboardRepeatDelay(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_KEYBOARD_REPEAT_RATE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetKeyboardRepeatRate(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_MOUSE_HOT_SPOT);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetMouseHotSpot(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_SHIELD_STATUS);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetShieldStatus(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_SHIELD_STATUS);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetShieldStatus(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_KEY_STATE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetKeyState(data, reply);
    EXPECT_EQ(ret, temp);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_OnRemoteRequest_011
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_011, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_AUTHORIZE);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubAuthorize(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_CANCEL_INJECTION);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubCancelInjection(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_INFRARED_OWN);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubHasIrEmitter(data, reply);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_INFRARED_FREQUENCY);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetInfraredFrequencies(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::NATIVE_CANCEL_TRANSMIT);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubTransmitInfrared(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_PIXEL_MAP_DATA);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetPixelMapData(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_CURRENT_USERID);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetCurrentUser(data, reply);
    EXPECT_EQ(ret, temp);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_OnRemoteRequest_012
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, OnRemoteRequest_012, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_TOUCHPAD_SCROLL_ROWS);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubSetTouchpadScrollRows(data, reply);
    EXPECT_EQ(ret, temp);
    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::GET_TOUCHPAD_SCROLL_ROWS);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubGetTouchpadScrollRows(data, reply);
    EXPECT_EQ(ret, temp);
}

/**
 * @tc.name: StubHandleAllocSocketFd_001
 * @tc.desc: Test the function StubHandleAllocSocketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubHandleAllocSocketFd_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetMousePrimaryButton(data, reply);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetHoverScrollState_001
 * @tc.desc: Test the function StubSetHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetHoverScrollState_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubIsPointerVisible(data, reply);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubMarkProcessed_001
 * @tc.desc: Test the function StubMarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubMarkProcessed_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    EXPECT_NE(ret, RET_ERR);
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
    int32_t returnCode = 201;
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
    int32_t returnCode = 201;
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
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
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubGetKeyboardRepeatRate(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubGetKeyboardRepeatRate(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetTouchpadPinchSwitch_001
 * @tc.desc: Test the function StubSetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadPinchSwitch_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetTouchpadPinchSwitch(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetTouchpadPinchSwitch_001
 * @tc.desc: Test the function StubGetTouchpadPinchSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadPinchSwitch_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetTouchpadPinchSwitch(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetTouchpadSwipeSwitch_001
 * @tc.desc: Test the function StubSetTouchpadSwipeSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadSwipeSwitch_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetTouchpadSwipeSwitch(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetTouchpadSwipeSwitch_001
 * @tc.desc: Test the function StubGetTouchpadSwipeSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadSwipeSwitch_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetTouchpadSwipeSwitch(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetTouchpadRightClickType_001
 * @tc.desc: Test the function StubSetTouchpadRightClickType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadRightClickType_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetTouchpadRightClickType(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetTouchpadRightClickType_001
 * @tc.desc: Test the function StubGetTouchpadRightClickType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadRightClickType_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetTouchpadRightClickType(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetTouchpadRotateSwitch_001
 * @tc.desc: Test the function StubSetTouchpadRotateSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadRotateSwitch_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetTouchpadRotateSwitch(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetTouchpadRotateSwitch_001
 * @tc.desc: Test the function StubGetTouchpadRotateSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadRotateSwitch_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetTouchpadRotateSwitch(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetShieldStatus_001
 * @tc.desc: Test the function StubSetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetShieldStatus_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetShieldStatus(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetShieldStatus_001
 * @tc.desc: Test the function StubSetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetShieldStatus_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetShieldStatus(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetShieldStatus(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetShieldStatus_001
 * @tc.desc: Test the function StubGetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubGetShieldStatus_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubGetShieldStatus(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubGetShieldStatus(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetKeyState_001
 * @tc.desc: Test the function StubGetKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetKeyState_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetKeyState(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubAuthorize_001
 * @tc.desc: Test the function StubAuthorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubAuthorize_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubAuthorize(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubCancelInjection_001
 * @tc.desc: Test the function StubCancelInjection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubCancelInjection_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubCancelInjection(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubHasIrEmitter_001
 * @tc.desc: Test the function StubHasIrEmitter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubHasIrEmitter_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubHasIrEmitter(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubGetInfraredFrequencies_001
 * @tc.desc: Test the function StubGetInfraredFrequencies
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetInfraredFrequencies_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubGetInfraredFrequencies(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubTransmitInfrared_001
 * @tc.desc: Test the function StubTransmitInfrared
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubTransmitInfrared_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubTransmitInfrared(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetPixelMapData_001
 * @tc.desc: Test the function StubSetPixelMapData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, MultimodalInputConnectStubTest_StubSetPixelMapData_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetPixelMapData(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetPixelMapData(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MultimodalInputConnectStubTest_StubSetCurrentUser_001
 * @tc.desc: Test the function StubSetCurrentUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetCurrentUser_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSetCurrentUser(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: StubHandleAllocSocketFd_002
 * @tc.desc: Test the function StubHandleAllocSocketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubHandleAllocSocketFd_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubHandleAllocSocketFd(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubHandleAllocSocketFd(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: StubSetMouseScrollRows_002
 * @tc.desc: Test the function StubSetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseScrollRows_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetMouseScrollRows(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetMouseScrollRows(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: StubSetCustomCursor_002
 * @tc.desc: Test the function StubSetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetCustomCursor_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetCustomCursor(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetCustomCursor(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: StubSetMouseIcon_002
 * @tc.desc: Test the function StubSetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseIcon_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetMouseIcon(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetMouseIcon(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: StubSetMouseHotSpot_002
 * @tc.desc: Test the function StubSetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetMouseHotSpot_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetMouseHotSpot(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetMouseHotSpot(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: StubGetMouseScrollRows_002
 * @tc.desc: Test the function StubGetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetMouseScrollRows_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubGetMouseScrollRows(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubGetMouseScrollRows(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: StubSetPointerSize_002
 * @tc.desc: Test the function StubSetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetPointerSize_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetPointerSize(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetPointerSize(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: StubSetNapStatus_002
 * @tc.desc: Test the function StubSetNapStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetNapStatus_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetNapStatus(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetNapStatus(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: StubInjectKeyEvent_002
 * @tc.desc: Test the function StubInjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectKeyEvent_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubInjectKeyEvent(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubInjectKeyEvent(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: StubInjectPointerEvent_001
 * @tc.desc: Test the function StubInjectPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubInjectPointerEvent_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubInjectPointerEvent(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubInjectPointerEvent(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: StubSetTouchpadScrollRows_001
 * @tc.desc: Test the function StubSetTouchpadScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadScrollRows_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubSetTouchpadScrollRows(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubSetTouchpadScrollRows_002
 * @tc.desc: Test the function StubSetTouchpadScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubSetTouchpadScrollRows_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubSetTouchpadScrollRows(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubSetTouchpadScrollRows(data, reply);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: StubGetTouchpadScrollRows_001
 * @tc.desc: Test the function StubGetTouchpadScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadScrollRows_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    int32_t returnCode = 65142800;
    int32_t ret = stub->StubGetTouchpadScrollRows(data, reply);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: StubGetTouchpadScrollRows_002
 * @tc.desc: Test the function StubGetTouchpadScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubTest, StubGetTouchpadScrollRows_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub>stub = std::make_shared<MMIService>();
    MessageParcel data;
    MessageParcel reply;
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t ret = stub->StubGetTouchpadScrollRows(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    state_ = ServiceRunningState::STATE_RUNNING;
    ret = stub->StubGetTouchpadScrollRows(data, reply);
    EXPECT_NE(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS