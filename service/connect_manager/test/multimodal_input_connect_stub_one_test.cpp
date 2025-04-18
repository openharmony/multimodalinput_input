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

#include <gmock/gmock.h>
#include <libinput.h>

#include "multimodal_input_connect_stub.h"
#include "mock_multimodal_input_connect_stub.h"

#include "extra_data.h"
#ifdef OHOS_BUILD_ENABLE_ANCO
#include "i_anco_channel.h"
#endif // OHOS_BUILD_ENABLE_ANCO
#include "i_event_filter.h"
#include "infrared_frequency_info.h"
#include "input_device.h"
#include "key_event.h"
#include "key_option.h"
#include "long_press_event.h"
#include "nap_process.h"
#include "permission_helper.h"
#include "pointer_style.h"
#include "shift_info.h"
#include "token_setproc.h"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

constexpr int32_t KEY_MAX_LIST_SIZE{ 5 };
static bool g_mockCheckMonitorReturnBooleanValue = false;
static bool g_mockReadFromParcelReturnBooleanValue = false;
static bool g_mockPointerEventReadFromParcelReturnBooleanValue = false;

bool PermissionHelper::CheckMonitor()
{
    return g_mockCheckMonitorReturnBooleanValue;
}

bool KeyOption::ReadFromParcel(Parcel &in)
{
    return g_mockReadFromParcelReturnBooleanValue;
}

bool PointerEvent::ReadFromParcel(Parcel &in)
{
    return g_mockPointerEventReadFromParcelReturnBooleanValue;
}

class MultimodalInputConnectStubOneTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp()
    {
        g_mockCheckMonitorReturnBooleanValue = false;
        g_mockReadFromParcelReturnBooleanValue = false;
        g_mockPointerEventReadFromParcelReturnBooleanValue = false;
    }
    void TearDown()
    {
        g_mockCheckMonitorReturnBooleanValue = false;
        g_mockReadFromParcelReturnBooleanValue = false;
        g_mockPointerEventReadFromParcelReturnBooleanValue = false;
    }
};

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSetPointerVisible_001
 * @tc.desc: Test the function StubSetPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSetPointerVisible_001,
    TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MockMultimodalInputConnectStub>();
    MessageParcel data;
    MessageParcel reply;
    data.WriteBool(false);
    int32_t priority = -1;
    data.WriteInt32(priority);
    int32_t ret = stub->StubSetPointerVisible(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubClearWindowPointerStyle_001
 * @tc.desc: Test the function StubClearWindowPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubClearWindowPointerStyle_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, ClearWindowPointerStyle).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    int32_t windowId = 1;
    data.WriteInt32(windowId);
    int32_t ret = stub->StubClearWindowPointerStyle(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubClearWindowPointerStyle_002
 * @tc.desc: Test the function StubClearWindowPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubClearWindowPointerStyle_002,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, ClearWindowPointerStyle).WillOnce(Return(RET_ERR));
    MessageParcel data;
    MessageParcel reply;
    int32_t windowId = 1;
    data.WriteInt32(windowId);
    int32_t ret = stub->StubClearWindowPointerStyle(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSupportKeys_001
 * @tc.desc: Test the function StubSupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSupportKeys_001, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MockMultimodalInputConnectStub>();
    MessageParcel data;
    MessageParcel reply;
    int32_t deviceId = 1;
    data.WriteInt32(deviceId);
    int32_t size = -1;
    data.WriteInt32(size);
    int32_t ret = stub->StubSupportKeys(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSupportKeys_002
 * @tc.desc: Test the function StubSupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSupportKeys_002, TestSize.Level1)
{
    std::shared_ptr<MultimodalInputConnectStub> stub = std::make_shared<MockMultimodalInputConnectStub>();
    MessageParcel data;
    MessageParcel reply;
    int32_t deviceId = 1;
    data.WriteInt32(deviceId);
    int32_t size = ExtraData::MAX_BUFFER_SIZE + 1;
    data.WriteInt32(size);
    int32_t ret = stub->StubSupportKeys(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSupportKeys_003
 * @tc.desc: Test the function StubSupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSupportKeys_003, TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, SupportKeys).WillOnce(Return(RET_ERR));
    MessageParcel data;
    MessageParcel reply;
    int32_t deviceId = 1;
    data.WriteInt32(deviceId);
    int32_t size = 0;
    data.WriteInt32(size);
    int32_t ret = stub->StubSupportKeys(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSetCustomCursor_001
 * @tc.desc: Test the function StubSetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSetCustomCursor_001, TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    MessageParcel data;
    MessageParcel reply;
    int32_t windowId = 1;
    int32_t focusX = 0;
    int32_t focusY = 0;
    data.WriteInt32(windowId);
    data.WriteInt32(focusX);
    data.WriteInt32(focusY);
    int32_t ret = stub->StubSetCustomCursor(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_OnRemoteRequest_001
 * @tc.desc: Test the function OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_OnRemoteRequest_001, TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, SubscribeTabletProximity).WillRepeatedly(Return(RET_ERR));
    EXPECT_CALL(*mock, UnsubscribetabletProximity).WillRepeatedly(Return(RET_ERR));
    EXPECT_CALL(*mock, SetKnuckleSwitch).WillRepeatedly(Return(RET_ERR));
    EXPECT_CALL(*mock, LaunchAiScreenAbility).WillRepeatedly(Return(RET_ERR));
    EXPECT_CALL(*mock, SubscribeKeyMonitor).WillRepeatedly(Return(RET_ERR));
    EXPECT_CALL(*mock, UnsubscribeKeyMonitor).WillRepeatedly(Return(RET_ERR));
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SUBSCRIBE_TABLET_EVENT);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    int32_t temp = stub->StubSubscribeTabletProximity(data, reply);
    EXPECT_EQ(ret, temp);

    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::UNSUBSCRIBE_TABLET_EVENT);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubUnSubscribetabletProximity(data, reply);
    EXPECT_EQ(ret, temp);

    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SET_KNUCKLE_SWITCH);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSetKnuckleSwitch(data, reply);
    EXPECT_EQ(ret, temp);

    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::LAUNCH_AI_SCREEN_ABILITY);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubLaunchAiScreenAbility(data, reply);
    EXPECT_EQ(ret, temp);

    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::SUBSCRIBE_KEY_MONITOR);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubSubscribeKeyMonitor(data, reply);
    EXPECT_EQ(ret, temp);

    code = static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::UNSUBSCRIBE_KEY_MONITOR);
    data.WriteInterfaceToken(IMultimodalInputConnect::GetDescriptor());
    ret = stub->OnRemoteRequest(code, data, reply, option);
    temp = stub->StubUnsubscribeKeyMonitor(data, reply);
    EXPECT_EQ(ret, temp);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubAddPreInputHandler_001
 * @tc.desc: Test the function StubShiftAppPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubAddPreInputHandler_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    MessageParcel data;
    MessageParcel reply;
    int32_t handlerId = 0;
    data.WriteInt32(handlerId);
    int32_t eventType = 0;
    data.WriteInt32(eventType);
    int32_t keysLen = KEY_MAX_LIST_SIZE + 1;
    data.WriteInt32(keysLen);
    g_mockCheckMonitorReturnBooleanValue = true;
    EXPECT_EQ(stub->StubAddPreInputHandler(data, reply), RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubAddPreInputHandler_002
 * @tc.desc: Test the function StubShiftAppPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubAddPreInputHandler_002,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    MessageParcel data;
    MessageParcel reply;
    int32_t handlerId = 0;
    data.WriteInt32(handlerId);
    int32_t eventType = 0;
    data.WriteInt32(eventType);
    int32_t keysLen = KEY_MAX_LIST_SIZE + 1;
    data.WriteInt32(keysLen);
    g_mockCheckMonitorReturnBooleanValue = true;
    EXPECT_EQ(stub->StubAddPreInputHandler(data, reply), RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubAddPreInputHandler_003
 * @tc.desc: Test the function StubShiftAppPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubAddPreInputHandler_003,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, AddPreInputHandler).WillOnce(Return(RET_ERR));
    MessageParcel data;
    MessageParcel reply;
    int32_t handlerId = 0;
    data.WriteInt32(handlerId);
    int32_t eventType = 0;
    data.WriteInt32(eventType);
    int32_t keysLen = 1;
    data.WriteInt32(keysLen);
    int32_t key = 0;
    data.WriteInt32(key);
    g_mockCheckMonitorReturnBooleanValue = true;
    EXPECT_EQ(stub->StubAddPreInputHandler(data, reply), RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubAddPreInputHandler_004
 * @tc.desc: Test the function StubShiftAppPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubAddPreInputHandler_004,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, AddPreInputHandler).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    int32_t handlerId = 0;
    data.WriteInt32(handlerId);
    int32_t eventType = 0;
    data.WriteInt32(eventType);
    int32_t keysLen = 1;
    data.WriteInt32(keysLen);
    int32_t key = 0;
    data.WriteInt32(key);
    g_mockCheckMonitorReturnBooleanValue = true;
    EXPECT_EQ(stub->StubAddPreInputHandler(data, reply), RET_OK);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_HandleGestureMonitor_001
 * @tc.desc: Test the function HandleGestureMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_HandleGestureMonitor_001, TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, AddGestureMonitor).WillOnce(Return(RET_ERR));
    MessageParcel data;
    MessageParcel reply;
    int32_t handlerType = InputHandlerType::MONITOR;
    data.WriteInt32(handlerType);
    uint32_t eventType = 0;
    data.WriteUint32(eventType);
    uint32_t gestureType = 0;
    data.WriteUint32(gestureType);
    int32_t fingers = 0;
    data.WriteInt32(fingers);
    EXPECT_EQ(stub->HandleGestureMonitor(MultimodalinputConnectInterfaceCode::ADD_GESTURE_MONITOR, data, reply),
        RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_HandleGestureMonitor_002
 * @tc.desc: Test the function HandleGestureMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_HandleGestureMonitor_002, TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, RemoveGestureMonitor).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    int32_t handlerType = InputHandlerType::MONITOR;
    data.WriteInt32(handlerType);
    uint32_t eventType = 0;
    data.WriteUint32(eventType);
    uint32_t gestureType = 0;
    data.WriteUint32(gestureType);
    int32_t fingers = 0;
    data.WriteInt32(fingers);
    EXPECT_EQ(stub->HandleGestureMonitor(MultimodalinputConnectInterfaceCode::ALLOC_SOCKET_FD, data, reply), RET_OK);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSubscribeKeyEvent_001
 * @tc.desc: Test the function StubSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSubscribeKeyEvent_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, SubscribeKeyEvent).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    int32_t subscribeId = 0;
    data.WriteInt32(subscribeId);
    g_mockReadFromParcelReturnBooleanValue = true;
    int32_t ret = stub->StubSubscribeKeyEvent(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubUnsubscribeKeyEvent_001
 * @tc.desc: Test the function StubUnsubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubUnsubscribeKeyEvent_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, UnsubscribeKeyEvent).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    int32_t subscribeId = 0;
    data.WriteInt32(subscribeId);
    int32_t ret = stub->StubUnsubscribeKeyEvent(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSubscribeHotkey_001
 * @tc.desc: Test the function StubSubscribeHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSubscribeHotkey_001, TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    MessageParcel data;
    MessageParcel reply;
    int32_t subscribeId = -1;
    data.WriteInt32(subscribeId);
    int32_t ret = stub->StubSubscribeHotkey(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSubscribeHotkey_002
 * @tc.desc: Test the function StubSubscribeHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSubscribeHotkey_002, TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    MessageParcel data;
    MessageParcel reply;
    int32_t subscribeId = 1;
    data.WriteInt32(subscribeId);
    g_mockReadFromParcelReturnBooleanValue = false;
    int32_t ret = stub->StubSubscribeHotkey(data, reply);
    EXPECT_EQ(ret, IPC_PROXY_DEAD_OBJECT_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSubscribeHotkey_003
 * @tc.desc: Test the function StubSubscribeHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSubscribeHotkey_003, TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, SubscribeHotkey).WillOnce(Return(RET_ERR));
    MessageParcel data;
    MessageParcel reply;
    int32_t subscribeId = 1;
    data.WriteInt32(subscribeId);
    g_mockReadFromParcelReturnBooleanValue = true;
    int32_t ret = stub->StubSubscribeHotkey(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSubscribeHotkey_004
 * @tc.desc: Test the function StubUnsubscribeHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSubscribeHotkey_004, TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, SubscribeHotkey).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    int32_t subscribeId = 1;
    data.WriteInt32(subscribeId);
    g_mockReadFromParcelReturnBooleanValue = true;
    int32_t ret = stub->StubSubscribeHotkey(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubUnsubscribeHotkey_001
 * @tc.desc: Test the function StubUnsubscribeHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubUnsubscribeHotkey_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, UnsubscribeHotkey).WillOnce(Return(RET_ERR)).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    int32_t subscribeId = -1;
    data.WriteInt32(subscribeId);
    int32_t ret = stub->StubUnsubscribeHotkey(data, reply);
    EXPECT_EQ(ret, RET_ERR);

    subscribeId = 1;
    data.WriteInt32(subscribeId);
    ret = stub->StubUnsubscribeHotkey(data, reply);
    EXPECT_EQ(ret, RET_ERR);

    subscribeId = 1;
    data.WriteInt32(subscribeId);
    ret = stub->StubUnsubscribeHotkey(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

#ifdef OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSubscribeKeyMonitor_001
 * @tc.desc: Test the function StubSubscribeKeyMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSubscribeKeyMonitor_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, SubscribeKeyMonitor).WillOnce(Return(RET_ERR)).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSubscribeKeyMonitor(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);

    ret = stub->StubSubscribeKeyMonitor(data, reply);
    EXPECT_EQ(ret, IPC_PROXY_DEAD_OBJECT_ERR);

    KeyMonitorOption keyOption;
    keyOption.key_ = 0;
    keyOption.action_ = 0;
    keyOption.isRepeat_ = false;
    keyOption.Marshalling(data);
    ret = stub->StubSubscribeKeyMonitor(data, reply);
    EXPECT_EQ(ret, RET_ERR);

    keyOption.Marshalling(data);
    ret = stub->StubSubscribeKeyMonitor(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubUnsubscribeKeyMonitor_001
 * @tc.desc: Test the function StubUnsubscribeKeyMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubUnsubscribeKeyMonitor_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mock, UnsubscribeKeyMonitor).WillOnce(Return(RET_ERR)).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubUnsubscribeKeyMonitor(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);

    ret = stub->StubUnsubscribeKeyMonitor(data, reply);
    EXPECT_EQ(ret, IPC_PROXY_DEAD_OBJECT_ERR);

    KeyMonitorOption keyOption;
    keyOption.key_ = 0;
    keyOption.action_ = 0;
    keyOption.isRepeat_ = false;
    keyOption.Marshalling(data);
    ret = stub->StubUnsubscribeKeyMonitor(data, reply);
    EXPECT_EQ(ret, RET_ERR);

    keyOption.Marshalling(data);
    ret = stub->StubUnsubscribeKeyMonitor(data, reply);
    EXPECT_EQ(ret, RET_OK);
}
#endif // OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubUnsubscribeSwitchEvent_001
 * @tc.desc: Test the function StubUnsubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubUnsubscribeSwitchEvent_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, UnsubscribeSwitchEvent).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    int32_t subscribeId = 1;
    data.WriteInt32(subscribeId);
    int32_t ret = stub->StubUnsubscribeSwitchEvent(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubQuerySwitchStatus_001
 * @tc.desc: Test the function StubQuerySwitchStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubQuerySwitchStatus_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, QuerySwitchStatus).WillOnce(Return(RET_ERR));
    MessageParcel data;
    MessageParcel reply;
    int32_t type = 1;
    data.WriteInt32(type);
    int32_t ret = stub->StubQuerySwitchStatus(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSubscribeTabletProximity_001
 * @tc.desc: Test the function StubSubscribeTabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSubscribeTabletProximity_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(false)).WillRepeatedly(Return(true));
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubSubscribeTabletProximity(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);

    int32_t subscribeId = 1;
    data.WriteInt32(subscribeId);
    EXPECT_CALL(*mock, SubscribeTabletProximity).WillOnce(Return(RET_ERR)).WillOnce(Return(RET_OK));
    ret = stub->StubSubscribeTabletProximity(data, reply);
    EXPECT_EQ(ret, RET_ERR);

    data.WriteInt32(subscribeId);
    ret = stub->StubSubscribeTabletProximity(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubUnSubscribetabletProximity_001
 * @tc.desc: Test the function StubUnSubscribetabletProximity
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubUnSubscribetabletProximity_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(false)).WillRepeatedly(Return(true));
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = stub->StubUnSubscribetabletProximity(data, reply);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);

    int32_t subscribeId = -1;
    data.WriteInt32(subscribeId);
    ret = stub->StubUnSubscribetabletProximity(data, reply);
    EXPECT_EQ(ret, RET_ERR);

    subscribeId = 1;
    data.WriteInt32(subscribeId);
    EXPECT_CALL(*mock, UnsubscribetabletProximity).WillOnce(Return(RET_ERR)).WillOnce(Return(RET_OK));
    ret = stub->StubUnSubscribetabletProximity(data, reply);
    EXPECT_EQ(ret, RET_ERR);

    data.WriteInt32(subscribeId);
    ret = stub->StubUnSubscribetabletProximity(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubSubscribeLongPressEvent_001
 * @tc.desc: Test the function StubSubscribeLongPressEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubSubscribeLongPressEvent_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, SubscribeLongPressEvent).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    int32_t subscribeId = 0;
    int32_t fingerCount = 0;
    int32_t duration = 0;
    data.WriteInt32(subscribeId);
    data.WriteInt32(fingerCount);
    data.WriteInt32(duration);
    int32_t ret = stub->StubSubscribeLongPressEvent(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubUnsubscribeLongPressEvent_001
 * @tc.desc: Test the function StubUnsubscribeLongPressEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubUnsubscribeLongPressEvent_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, UnsubscribeLongPressEvent).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    int32_t subscribeId = 0;
    int32_t fingerCount = 0;
    int32_t duration = 0;
    data.WriteInt32(subscribeId);
    data.WriteInt32(fingerCount);
    data.WriteInt32(duration);
    int32_t ret = stub->StubUnsubscribeLongPressEvent(data, reply);
    EXPECT_EQ(ret, RET_OK);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubInjectPointerEvent_001
 * @tc.desc: Test the function StubInjectPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubInjectPointerEvent_001,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, InjectPointerEvent).WillOnce(Return(RET_ERR));
    MessageParcel data;
    MessageParcel reply;
    g_mockPointerEventReadFromParcelReturnBooleanValue = true;
    data.WriteBool(false);
    int32_t ret = stub->StubInjectPointerEvent(data, reply);
    EXPECT_EQ(ret, RET_ERR);
}

/* *
 * @tc.name: MultimodalInputConnectStubOneTest_StubInjectPointerEvent_002
 * @tc.desc: Test the function StubInjectPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MultimodalInputConnectStubOneTest, MultimodalInputConnectStubOneTest_StubInjectPointerEvent_002,
    TestSize.Level1)
{
    std::shared_ptr<MockMultimodalInputConnectStub> mock = std::make_shared<MockMultimodalInputConnectStub>();
    std::shared_ptr<MultimodalInputConnectStub> stub = mock;
    EXPECT_CALL(*mock, IsRunning).WillOnce(Return(true));
    EXPECT_CALL(*mock, InjectPointerEvent).WillOnce(Return(RET_OK));
    MessageParcel data;
    MessageParcel reply;
    g_mockPointerEventReadFromParcelReturnBooleanValue = true;
    data.WriteBool(true);
    int32_t ret = stub->StubInjectPointerEvent(data, reply);
    EXPECT_EQ(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS
