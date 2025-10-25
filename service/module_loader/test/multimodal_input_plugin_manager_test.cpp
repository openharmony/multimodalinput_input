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
 
#include <cstdio>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "multimodal_input_plugin_manager.h"
#include "general_mouse.h"
#include "general_touchpad.h"
#include "input_event_handler.h"
#include "libinput_interface.h"
#include "libinput_mock.h"
#include "libinput_wrapper.h"
#include "net_packet.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MultimodalInputPluginManagerTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
} // namespace

const std::string PATH { "/system/lib64/multimodalinput/autorun" };

class MultimodalInputPluginManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void MultimodalInputPluginManagerTest::SetUpTestCase(void)
{}

void MultimodalInputPluginManagerTest::TearDownTestCase(void)
{}

class MockInputPluginContext : public IPluginContext {
public:
    virtual ~MockInputPluginContext() = default;
    MOCK_METHOD(std::string, GetName, (), (override));
    MOCK_METHOD(int32_t, GetPriority, (), (override));
    MOCK_METHOD(std::shared_ptr<IInputPlugin>, GetPlugin, (), (override));
    MOCK_METHOD(void, SetCallback, (std::function<void(PluginEventType, int64_t)> callback), (override));
    MOCK_METHOD(int32_t, AddTimer, (std::function<void()> func, int32_t intervalMs, int32_t repeatCount), (override));
    MOCK_METHOD(int32_t, RemoveTimer, (int32_t id), (override));
    MOCK_METHOD(void, DispatchEvent, (PluginEventType pluginEvent, int64_t frameTime), (override));
    MOCK_METHOD(void, DispatchEvent, (PluginEventType pluginEvent, InputDispatchStage stage), (override));
    MOCK_METHOD(void, DispatchEvent, (NetPacket& pkt, int32_t pid), (override));
    MOCK_METHOD(PluginResult, HandleEvent,
                (libinput_event * event, std::shared_ptr<IPluginData> data), (override));
    MOCK_METHOD(PluginResult, HandleEvent,
                (std::shared_ptr<PointerEvent> pointerEvent, std::shared_ptr<IPluginData> data), (override));
    MOCK_METHOD(PluginResult, HandleEvent,
                (std::shared_ptr<KeyEvent> keyEvent, std::shared_ptr<IPluginData> data), (override));
    MOCK_METHOD(PluginResult, HandleEvent, (std::shared_ptr<AxisEvent> axisEvent,
                std::shared_ptr<IPluginData> data), (override));
    MOCK_METHOD(void, HandleMonitorStatus, (bool monitorStatus, const std::string &monitorType), (override));
    MOCK_METHOD(std::string, GetFocusedAppInfo, (), (override));
};

class MockInputPlugin : public IInputPlugin {
public:
    virtual ~MockInputPlugin() = default;
    MOCK_METHOD(int32_t, GetPriority, (), (override, const));
    MOCK_METHOD(const std::string, GetVersion, (), (override, const));
    MOCK_METHOD(const std::string, GetName, (), (override, const));
    MOCK_METHOD(InputPluginStage, GetStage, (), (override, const));
    MOCK_METHOD(void, DeviceWillAdded, (std::shared_ptr<InputDevice> inputDevice), (override));
    MOCK_METHOD(void, DeviceDidAdded, (std::shared_ptr<InputDevice> inputDevice), (override));
    MOCK_METHOD(void, DeviceWillRemoved, (std::shared_ptr<InputDevice> inputDevice), (override));
    MOCK_METHOD(void, DeviceDidRemoved, (std::shared_ptr<InputDevice> inputDevice), (override));
    MOCK_METHOD(sptr<IRemoteObject>, GetExternalObject, (), (override));
    MOCK_METHOD(
        PluginResult, HandleEvent, (libinput_event * event, std::shared_ptr<IPluginData> data), (override, const));
    MOCK_METHOD(PluginResult, HandleEvent,
        (std::shared_ptr<KeyEvent> keyEvent, std::shared_ptr<IPluginData> data), (override, const));
    MOCK_METHOD(PluginResult, HandleEvent,
        (std::shared_ptr<PointerEvent> pointerEvent, std::shared_ptr<IPluginData> data), (override, const));
    MOCK_METHOD(PluginResult, HandleEvent,
        (std::shared_ptr<AxisEvent> axisEvent, std::shared_ptr<IPluginData> data), (override, const));
    MOCK_METHOD(void, HandleMonitorStatus, (bool monitorStatus, const std::string &monitorType), (override, const));
};

class MockUDSSession : public UDSSession {
public:
    MOCK_METHOD(bool, SendMsg, (NetPacket& pkt));
    MockUDSSession(const std::string& programName, const int32_t moduleType, const int32_t fd, const int32_t uid,
        const int32_t pid) : UDSSession(programName, moduleType, fd, uid, pid) {}
};

class RemoteObjectTest : public IRemoteObject {
public:
    explicit RemoteObjectTest(std::u16string descriptor) : IRemoteObject(descriptor) {}
    ~RemoteObjectTest() {}

    int32_t GetObjectRefCount() { return 0; }
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) { return 0; }
};

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_Init_001
 * @tc.desc: Init will return RET_OK when directory_ is valid path
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_Init_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    int32_t result = InputPluginManager::GetInstance()->Init(udsServer);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_HandleEvent_001
 * @tc.desc: Test_HandleEvent_001
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_HandleEvent_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event;
    std::shared_ptr<IPluginData> data = std::make_shared<IPluginData>();
    data->stage = InputPluginStage::INPUT_AFTER_FILTER;
    int32_t result = InputPluginManager::GetInstance()->HandleEvent(&event, data);
    EXPECT_GE(result, RET_NOTDO);

    data->stage = InputPluginStage::INPUT_BEFORE_LIBINPUT_ADAPTER_ON_EVENT;
    EXPECT_GE(result, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_IntermediateEndEvent_001
 * @tc.desc: Test_IntermediateEndEvent_001
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_IntermediateEndEvent_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_POINTER_MOTION));
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    libinput_event_keyboard keyboardEvent;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_KEYBOARD_KEY));
    EXPECT_CALL(libinputMock, LibinputEventGetKeyboardEvent).WillOnce(Return(&keyboardEvent));
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKeyState).WillOnce(Return(LIBINPUT_KEY_STATE_RELEASED));
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    libinput_event_pointer pointerEvent;
    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD));
    EXPECT_CALL(libinputMock, LibinputGetPointerEvent).WillOnce(Return(&pointerEvent));
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    EXPECT_CALL(libinputMock, GetEventType).WillOnce(Return(LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY));
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillOnce(Return(nullptr));
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TABLET_TOOL_TIP));
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillRepeatedly(Return(nullptr));
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    std::shared_ptr<AxisEvent> axisEvent = std::make_shared<AxisEvent>(AxisEvent::AXIS_ACTION_START);
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(axisEvent));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_GetExternalObject_001
 * @tc.desc: Test_GetExternalObject_001
 * @tc.require: test GetExternalObject
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_GetExternalObject_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string pluginName = "yunshuiqiao";
    sptr<IRemoteObject> inputDevicePluginStub = nullptr;
    int32_t result = InputPluginManager::GetInstance()->GetExternalObject(pluginName, inputDevicePluginStub);
    EXPECT_EQ(result, ERROR_NULL_POINTER);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_GetExternalObject_002
 * @tc.desc: Test_GetExternalObject_002
 * @tc.require: test GetExternalObject
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_GetExternalObject_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string pluginName = "pc.pointer.inputDeviceConsumer.202507";
    sptr<IRemoteObject> inputDevicePluginStub = nullptr;
    std::shared_ptr<MockInputPluginContext> mockInputPluginContext = std::make_shared<MockInputPluginContext>();
    std::shared_ptr<MockInputPlugin> mockInputPlugin = std::make_shared<MockInputPlugin>();
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");

    EXPECT_CALL(*mockInputPlugin, GetName()).WillOnce(Return(pluginName));
    EXPECT_CALL(*mockInputPlugin, GetExternalObject()).WillOnce(Return(remote));
    EXPECT_CALL(*mockInputPluginContext, GetPlugin()).WillRepeatedly(Return(mockInputPlugin));
    std::list<std::shared_ptr<IPluginContext>> pluginLists;
    pluginLists.push_back(mockInputPluginContext);
    InputPluginManager::GetInstance()->plugins_[InputPluginStage::INPUT_AFTER_NORMALIZED] = pluginLists;

    int32_t ret = InputPluginManager::GetInstance()->GetExternalObject(pluginName, inputDevicePluginStub);
    EXPECT_EQ(ret, RET_OK);
    InputPluginManager::GetInstance()->plugins_.clear();
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_GetExternalObject_003
 * @tc.desc: Test_GetExternalObject_003
 * @tc.require: test GetExternalObject
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_GetExternalObject_003,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string pluginName = "pc.pointer.inputDeviceConsumer.202507";
    sptr<IRemoteObject> inputDevicePluginStub = nullptr;
    std::shared_ptr<MockInputPluginContext> mockInputPluginContext = std::make_shared<MockInputPluginContext>();
    std::shared_ptr<MockInputPlugin> mockInputPlugin = std::make_shared<MockInputPlugin>();
    sptr<RemoteObjectTest> remote = new RemoteObjectTest(u"test");

    EXPECT_CALL(*mockInputPlugin, GetName()).WillOnce(Return(pluginName));
    EXPECT_CALL(*mockInputPlugin, GetExternalObject()).WillOnce(Return(nullptr));
    EXPECT_CALL(*mockInputPluginContext, GetPlugin()).WillRepeatedly(Return(mockInputPlugin));
    std::list<std::shared_ptr<IPluginContext>> pluginLists;
    pluginLists.push_back(mockInputPluginContext);
    InputPluginManager::GetInstance()->plugins_[InputPluginStage::INPUT_AFTER_NORMALIZED] = pluginLists;

    int32_t ret = InputPluginManager::GetInstance()->GetExternalObject(pluginName, inputDevicePluginStub);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    InputPluginManager::GetInstance()->plugins_.clear();
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_GetPluginDataFromLibInput_001
 * @tc.desc: Test_GetPluginDataFromLibInput_001
 * @tc.require: test GetPluginDataFromLibInput
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPluginManager_GetPluginDataFromLibInput_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_device touchpadDevice;
    libinput_event_touch touchEvent;
    NiceMock<LibinputInterfaceMock> libinputMock;

    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&touchpadDevice));
    EXPECT_CALL(libinputMock, TouchEventGetToolType).WillOnce(Return(11));
    EXPECT_CALL(libinputMock, GetTouchEvent).WillOnce(Return(&touchEvent));
    char deviceName[] = "yunshuiqiao";
    EXPECT_CALL(libinputMock, DeviceGetName).WillOnce(Return(deviceName));

    libinput_event event;
    IPluginData* data = InputPluginManager::GetInstance()->GetPluginDataFromLibInput(&event).get();
    EXPECT_EQ(data->libInputEventData.toolType, 11);
    EXPECT_EQ(data->libInputEventData.deviceName, deviceName);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_GetPluginDataFromLibInput_002
 * @tc.desc: Test_GetPluginDataFromLibInput_002
 * @tc.require: test GetPluginDataFromLibInput
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPluginManager_GetPluginDataFromLibInput_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event;
    libinput_event_touch touchEvent;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTouchEvent).WillOnce(Return(&touchEvent));
    IPluginData* data = InputPluginManager::GetInstance()->GetPluginDataFromLibInput(&event).get();
    EXPECT_EQ(data->libInputEventData.toolType, 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_GetPluginDataFromLibInput_003
 * @tc.desc: Test_GetPluginDataFromLibInput_003
 * @tc.require: test GetPluginDataFromLibInput
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPluginManager_GetPluginDataFromLibInput_003, TestSize.Level1) {
    CALL_TEST_DEBUG;
    libinput_event event;
    IPluginData *data = InputPluginManager::GetInstance()->GetPluginDataFromLibInput(&event).get();
    EXPECT_EQ(data->libInputEventData.toolType, 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_ProcessEvent_001
 * @tc.desc: Test_ProcessEvent_001
 * @tc.require: test ProcessEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_ProcessEvent_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<MockInputPluginContext> mockInputPluginContext = std::make_shared<MockInputPluginContext>();
    std::shared_ptr<IPluginData> data = std::make_shared<IPluginData>();

    libinput_event *event = nullptr;
    EXPECT_CALL(*mockInputPluginContext, HandleEvent(event, data)).WillOnce(Return(PluginResult::NotUse));
    PluginResult result = InputPluginManager::GetInstance()->ProcessEvent(event, mockInputPluginContext, data);
    EXPECT_EQ(result, PluginResult::NotUse);

    std::shared_ptr<PointerEvent> pointerEvent =
        std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    EXPECT_CALL(*mockInputPluginContext, HandleEvent(pointerEvent, data)).WillOnce(Return(PluginResult::NotUse));
    result = InputPluginManager::GetInstance()->ProcessEvent(pointerEvent, mockInputPluginContext, data);
    EXPECT_EQ(result, PluginResult::NotUse);

    std::shared_ptr<AxisEvent> axisEvent =
        std::make_shared<AxisEvent>(AxisEvent::AXIS_ACTION_START);
    EXPECT_CALL(*mockInputPluginContext, HandleEvent(axisEvent, data)).WillOnce(Return(PluginResult::NotUse));
    result = InputPluginManager::GetInstance()->ProcessEvent(axisEvent, mockInputPluginContext, data);
    EXPECT_EQ(result, PluginResult::NotUse);

    std::shared_ptr<KeyEvent> keyEvent =
        std::make_shared<KeyEvent>(KeyEvent::KEYCODE_BRIGHTNESS_DOWN);
    EXPECT_CALL(*mockInputPluginContext, HandleEvent(keyEvent, data)).WillOnce(Return(PluginResult::NotUse));
    result = InputPluginManager::GetInstance()->ProcessEvent(keyEvent, mockInputPluginContext, data);
    EXPECT_EQ(result, PluginResult::NotUse);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_DoHandleEvent_001
 * @tc.desc: Test_DoHandleEvent_001
 * @tc.require: test DoHandleEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_DoHandleEvent_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<IPluginData> data = std::make_shared<IPluginData>();
    data->stage = InputPluginStage::INPUT_GLOBAL_INIT;
    libinput_event* event = nullptr;
    int32_t result = InputPluginManager::GetInstance()->DoHandleEvent(event, data, nullptr);
    EXPECT_EQ(result, RET_NOTDO);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_DoHandleEvent_002
 * @tc.desc: Test_DoHandleEvent_002
 * @tc.require: test DoHandleEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_DoHandleEvent_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<IPluginData> data = std::make_shared<IPluginData>();
    data->stage = InputPluginStage::INPUT_AFTER_NORMALIZED;
    std::shared_ptr<KeyEvent> keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_BRIGHTNESS_DOWN);
    int32_t result = InputPluginManager::GetInstance()->DoHandleEvent(keyEvent, data, nullptr);
    EXPECT_EQ(result, RET_NOTDO);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_GetUdsServer_001
 * @tc.desc: Test_GetUdsServer_001
 * @tc.require: test GetUdsServer
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_GetUdsServer_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto instance = InputPluginManager::GetInstance();
    UDSServer* result = instance->GetUdsServer();
    EXPECT_EQ(result, InputPluginManager::GetInstance()->udsServer_);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_DispatchEvent_001
 * @tc.desc: Test_DispatchEvent_001
 * @tc.require: test DispatchEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_DispatchEvent_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>();
    libinput_event* event = nullptr;
    int64_t frameTime = 100;
    inputPluginContext->DispatchEvent(event, frameTime);
    EXPECT_EQ(frameTime, 100);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_DispatchEvent_002
 * @tc.desc: Test_DispatchEvent_002
 * @tc.require: test DispatchEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_DispatchEvent_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>();
    int32_t pid = 1;
    UDSServer udsServer;
    InputPluginManager::GetInstance()->udsServer_ = &udsServer;
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    inputPluginContext->DispatchEvent(pkt, pid);
    EXPECT_EQ(pid, 1);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_DispatchEvent_003
 * @tc.desc: Test_DispatchEvent_003
 * @tc.require: test DispatchEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_DispatchEvent_003,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>();
    std::shared_ptr<UDSServer> udsServer = std::make_shared<UDSServer>();
    std::string programName = "program";
    int32_t moduleType = 1;
    int32_t fd = 2;
    int32_t uid = 3;
    int32_t pid = 4;
    std::shared_ptr<MockUDSSession> session = std::make_shared<MockUDSSession>
        (programName, moduleType, fd, uid, pid);
    InputPluginManager::GetInstance()->udsServer_ = udsServer.get();
    NetPacket pkt(MmiMessageId::ON_KEY_EVENT);
    inputPluginContext->DispatchEvent(pkt, pid);
    EXPECT_EQ(pid, 4);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_DispatchEvent_004
 * @tc.desc: Test_DispatchEvent_004
 * @tc.require: test DispatchEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_DispatchEvent_004,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputDispatchStage filterStage = InputDispatchStage::Filter;
    InputDispatchStage interceptStage = InputDispatchStage::Intercept;
    InputDispatchStage keyCommandStage = InputDispatchStage::KeyCommand;
    InputDispatchStage monitorStage = InputDispatchStage::Monitor;

    libinput_event* event = nullptr;
    std::shared_ptr<PointerEvent> pointerEvent =
        std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    std::shared_ptr<AxisEvent> axisEvent = std::make_shared<AxisEvent>(AxisEvent::AXIS_ACTION_START);
    std::shared_ptr<KeyEvent> keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_BRIGHTNESS_DOWN);

    InputHandler->eventFilterHandler_ = std::make_shared<EventFilterHandler>();
    InputHandler->eventInterceptorHandler_ = std::make_shared<EventInterceptorHandler>();
    InputHandler->eventKeyCommandHandler_ = std::make_shared<KeyCommandHandler>();
    InputHandler->eventMonitorHandler_ = std::make_shared<EventMonitorHandler>();

    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>();
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->DispatchEvent(event, filterStage));
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->DispatchEvent(event, interceptStage));
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->DispatchEvent(event, keyCommandStage));
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->DispatchEvent(event, monitorStage));
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->DispatchEvent(pointerEvent, monitorStage));
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->DispatchEvent(axisEvent, monitorStage));
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->DispatchEvent(keyEvent, monitorStage));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleEvent_001
 * @tc.desc: Test_HandleEvent_001
 * @tc.require: test HandleEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_HandleEvent_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>();
    libinput_event* event = nullptr;
    std::shared_ptr<IPluginData> data = std::make_shared<IPluginData>();
    PluginResult result = inputPluginContext->HandleEvent(event, data);
    EXPECT_EQ(result, PluginResult::NotUse);

    std::shared_ptr<MockInputPlugin> mockInputPlugin = std::make_shared<MockInputPlugin>();
    EXPECT_CALL(*mockInputPlugin, GetName()).WillOnce(Return("yunshuiqiao"));
    EXPECT_CALL(*mockInputPlugin, GetPriority()).WillOnce(Return(201));
    EXPECT_CALL(*mockInputPlugin, GetStage()).WillOnce(Return(InputPluginStage::INPUT_AFTER_NORMALIZED));
    inputPluginContext->Init(mockInputPlugin);

    EXPECT_CALL(*mockInputPlugin, HandleEvent(event, data)).WillOnce(Return(PluginResult::UseNeedReissue));
    result = inputPluginContext->HandleEvent(event, data);
    EXPECT_EQ(result, PluginResult::UseNeedReissue);

    std::shared_ptr<PointerEvent> pointerEvent =
        std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    EXPECT_CALL(*mockInputPlugin, HandleEvent(pointerEvent, data)).WillOnce(Return(PluginResult::UseNeedReissue));
    result = inputPluginContext->HandleEvent(pointerEvent, data);
    EXPECT_EQ(result, PluginResult::UseNeedReissue);

    std::shared_ptr<AxisEvent> axisEvent =
        std::make_shared<AxisEvent>(AxisEvent::AXIS_ACTION_START);
    EXPECT_CALL(*mockInputPlugin, HandleEvent(axisEvent, data)).WillOnce(Return(PluginResult::UseNeedReissue));
    result = inputPluginContext->HandleEvent(axisEvent, data);
    EXPECT_EQ(result, PluginResult::UseNeedReissue);

    std::shared_ptr<KeyEvent> keyEvent =
        std::make_shared<KeyEvent>(KeyEvent::KEYCODE_BRIGHTNESS_DOWN);
    EXPECT_CALL(*mockInputPlugin, HandleEvent(keyEvent, data)).WillOnce(Return(PluginResult::UseNeedReissue));
    result = inputPluginContext->HandleEvent(keyEvent, data);
    EXPECT_EQ(result, PluginResult::UseNeedReissue);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_GetName_001
 * @tc.desc: Test_GetName_001
 * @tc.require: test GetName
 */
HWTEST_F(
    MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_GetName_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>();
    inputPluginContext->name_ = "yunshuiqiao";
    std::string pluginName = inputPluginContext->GetName();
    EXPECT_EQ(pluginName, "yunshuiqiao");
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_GetPriority_001
 * @tc.desc: Test_GetPriority_001
 * @tc.require: test GetPriority
 */
HWTEST_F(
    MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_GetPriority_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>();
    inputPluginContext->prio_ = 300;
    int32_t priority = inputPluginContext->GetPriority();
    EXPECT_EQ(priority, 300);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_SetCallback_001
 * @tc.desc: Test_SetCallback_001
 * @tc.require: test SetCallback
 */
HWTEST_F(
    MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_SetCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>();
    std::function<void(PluginEventType, int64_t)> callback = [](PluginEventType, int64_t) {};
    inputPluginContext->SetCallback(callback);
    EXPECT_NE(inputPluginContext->callback_, nullptr);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_GetPlugin_001
 * @tc.desc: Test_GetPlugin_001
 * @tc.require: test GetPlugin
 */
HWTEST_F(
    MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_GetPlugin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>();
    std::shared_ptr<MockInputPlugin> mockInputPlugin = std::make_shared<MockInputPlugin>();
    EXPECT_CALL(*mockInputPlugin, GetName()).WillOnce(Return("yunshuiqiao"));
    EXPECT_CALL(*mockInputPlugin, GetPriority()).WillOnce(Return(201));
    EXPECT_CALL(*mockInputPlugin, GetStage()).WillOnce(Return(InputPluginStage::INPUT_AFTER_NORMALIZED));
    inputPluginContext->Init(mockInputPlugin);
    std::shared_ptr<IInputPlugin> inputPlugin = inputPluginContext->GetPlugin();
    EXPECT_NE(inputPlugin, nullptr);
}
} // namespace MMI
} // namespace OHOS
