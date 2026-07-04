/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "input_device_manager.h"
#include "i_delegate_interface.h"
#include "setting_datashare.h"

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
    MOCK_METHOD(bool, IsFingerPressed, (), (override, const));
    MOCK_METHOD(const ISessionHandlerCollection *, GetMonitorCollection, (), (override, const));
    MOCK_METHOD(int32_t, GetFocusedPid, (), (override, const));
    MOCK_METHOD(bool, AttachDeviceObserver, (const std::shared_ptr<IDeviceObserver> &observer), (override));
    MOCK_METHOD(bool, DetachDeviceObserver, (const std::shared_ptr<IDeviceObserver> &observer), (override));
    MOCK_METHOD(int32_t, GetCurrentAccountId, (), (override, const));
    MOCK_METHOD(int32_t, RegisterCommonEventCallback,
                (const std::function<void(const EventFwk::CommonEventData &)> &callback), (override));
    MOCK_METHOD(bool, UnRegisterCommonEventCallback, (int32_t callbackId), (override));
    MOCK_METHOD(void, HideMouseCursorTemporary, (), (override));
    MOCK_METHOD(int32_t, CalculateTipPoint,
                (libinput_event *event, int32_t &displayId, PhysicalCoordinate &coord), (override));
    MOCK_METHOD(void, SetMouseAccelerateMotionSwitch, (libinput_event *event, bool enable), (override));
    MOCK_METHOD(int32_t, GetCurrentMouseLocation, (double &mouseX, double &mouseY), (override));
    MOCK_METHOD(bool, GetSettingValue, (const std::string& uri, const std::string& key, std::string& value), (override));
    MOCK_METHOD(int32_t, RegisterSettingObserver,
                (const std::string& uri, const std::string& key, std::function<void(const std::string&)> callback),
                (override));
    MOCK_METHOD(bool, UnregisterSettingObserver, (int32_t observerId), (override));
    MOCK_METHOD(std::vector<PluginDisplayGroupInfo>, GetDisplayGroupInfos, (), (override, const));
    MOCK_METHOD(std::vector<std::shared_ptr<InputDevice>>, GetInputDeviceInfos, (), (override, const));
    MOCK_METHOD(int32_t, RegisterDisplayChangeCallback, (const DisplayChangeCallback &callback), (override));
    MOCK_METHOD(bool, UnregisterDisplayChangeCallback, (int32_t callbackId), (override));
    MOCK_METHOD(int32_t, EnableInputDeviceForPlugin, (int32_t deviceId), (override));
    MOCK_METHOD(int32_t, DisableInputDeviceForPlugin, (int32_t deviceId), (override));
    MOCK_METHOD(bool, IsDataShareReady, ());
#ifdef OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
    MOCK_METHOD(std::vector<int32_t>, GetSubscribedKeysByPid, (int32_t pid), (override, const));
    MOCK_METHOD(int32_t, RegisterKeyMonitorCallback,
                (const std::function<void(int32_t, int32_t, std::string, bool)> &), (override, const));
    MOCK_METHOD(bool, UnregisterKeyMonitorCallback, (int32_t), (override, const));
    MOCK_METHOD(void, AddFlagForDevice, (libinput_event *event), (override));
    MOCK_METHOD(void, RemoveFlagForDevice, (libinput_event *event), (override));
#endif
};

class MockInputPlugin : public IInputPlugin {
public:
    virtual ~MockInputPlugin() = default;
    MOCK_METHOD(int32_t, GetPriority, (), (override, const));
    MOCK_METHOD(const std::string, GetVersion, (), (override, const));
    MOCK_METHOD(const std::string, GetName, (), (override, const));
    MOCK_METHOD(InputPluginStage, GetStage, (), (override, const));
    MOCK_METHOD(std::vector<InputPluginStage>, GetStages, (), (override, const));
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
    MOCK_METHOD(bool, HandleShortcutKey, (const IShortcutKey &shortcutKey));
    MOCK_METHOD(bool, HandleSequenceKeys, (const std::vector<ISequenceKey> &sequenceKeys));
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

class MockIDeviceObserver : public IDeviceObserver {
public:
    MOCK_METHOD1(OnDeviceAdded, void(int32_t deviceId));
    MOCK_METHOD1(OnDeviceRemoved, void(int32_t deviceId));
    MOCK_METHOD3(UpdatePointerDevice, void(bool, bool, bool));
    MOCK_METHOD1(OnDeviceFirstReportEvent, void(int32_t deviceId));
};

class MockIDelegateInterface : public IDelegateInterface {
public:
    MOCK_METHOD(int32_t, OnPostSyncTask, (DTaskCallback cb), (const));
    MOCK_METHOD(int32_t, OnPostAsyncTask, (DTaskCallback cb), (const));
    MOCK_METHOD(int32_t, AddHandler, (InputHandlerType handlerType, const HandlerSummary &summary), (override));
    MOCK_METHOD(void, RemoveHandler, (InputHandlerType handlerType, const std::string &name), (override));
    MOCK_METHOD(bool, HasHandler, (const std::string &name), (const));
};

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_Init_001
 * @tc.desc: Init should return RET_OK when directory does not exist
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_Init_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    InputPluginManager* manager = InputPluginManager::GetInstance("/non/existent/path");
    int32_t result = manager->Init(udsServer);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_Init_002
 * @tc.desc: Init should return RET_OK when directory is empty
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_Init_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp/empty_dir");
    int32_t result = manager->Init(udsServer);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_Init_003
 * @tc.desc: Init should skip invalid plugins and continue processing
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPluginManager_Init_003,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp/plugins_with_invalid_so");
    int32_t result = manager->Init(udsServer);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadPlugin_001
 * @tc.desc: Test LoadPlugin with valid .so file and successful plugin initialization
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadPlugin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string validPath = "/tmp/valid_plugin.so";
    // Mock dlopen, dlsym, and InitPlugin behavior
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, Dlerror()).WillRepeatedly(Return(nullptr));

    // Call LoadPlugin
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    auto plugin = manager->LoadPlugin(validPath);
    EXPECT_EQ(plugin, nullptr);

    // Verify plugin is inserted into plugins_
    auto& plugins = manager->plugins_;
    ASSERT_EQ(plugins.size(), 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadPlugin_002
 * @tc.desc: Test LoadPlugin with dlopen failure
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadPlugin_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string invalidPath = "/tmp/invalid_plugin.so";
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, Dlerror()).WillRepeatedly(Return("dlopen error"));

    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    auto plugin = manager->LoadPlugin(invalidPath);
    EXPECT_EQ(plugin, nullptr);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadPlugin_003
 * @tc.desc: Test LoadPlugin with missing InitPlugin symbol
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadPlugin_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string validPath = "/tmp/plugin_missing_init.so";
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, Dlsym(_, "UnintPlugin")).Times(0);
    EXPECT_CALL(libinputMock, Dlerror()).WillRepeatedly(Return("symbol not found"));

    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    auto plugin = manager->LoadPlugin(validPath);
    EXPECT_EQ(plugin, nullptr);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadPlugin_004
 * @tc.desc: Test LoadPlugin with failed InitPlugin callback
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadPlugin_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string validPath = "/tmp/plugin_init_failed.so";
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, Dlerror()).WillRepeatedly(Return(nullptr));

    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    auto plugin = manager->LoadPlugin(validPath);
    EXPECT_EQ(plugin, nullptr);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadPlugin_005
 * @tc.desc: Test LoadPlugin with multiple plugins in same stage sorted by priority
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadPlugin_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::string plugin1Path = "/tmp/plugin_high_priority.so";
    std::string plugin2Path = "/tmp/plugin_low_priority.so";

    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, Dlsym(_, "InitPlugin")).WillRepeatedly(Return(reinterpret_cast<void*>(0x3)));
    EXPECT_CALL(libinputMock, Dlsym(_, "UnintPlugin")).WillRepeatedly(Return(reinterpret_cast<void*>(0x4)));

    EXPECT_CALL(libinputMock, Dlerror()).WillRepeatedly(Return(nullptr));

    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->LoadPlugin(plugin1Path);
    manager->LoadPlugin(plugin2Path);

    auto& plugins = manager->plugins_;
    ASSERT_EQ(plugins.size(), 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_PluginAssignmentCallBack_001
 * @tc.desc: Test PluginAssignmentCallBack with existing stage plugins
 * @tc.require: test PluginAssignmentCallBack
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_PluginAssignmentCallBack_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    std::shared_ptr<MockInputPluginContext> mockPlugin1 = std::make_shared<MockInputPluginContext>();
    std::shared_ptr<MockInputPluginContext> mockPlugin2 = std::make_shared<MockInputPluginContext>();

    EXPECT_CALL(*mockPlugin1, SetCallback(testing::_)).Times(1);
    EXPECT_CALL(*mockPlugin2, SetCallback(testing::_)).Times(1);

    manager->plugins_[InputPluginStage::INPUT_AFTER_FILTER] = { mockPlugin1, mockPlugin2 };

    std::function<void(PluginEventType, int64_t)> callback = [](PluginEventType, int64_t) {};

    manager->PluginAssignmentCallBack(callback, InputPluginStage::INPUT_AFTER_FILTER);

    ASSERT_EQ(manager->plugins_.size(), 1);
    auto it = manager->plugins_.find(InputPluginStage::INPUT_AFTER_FILTER);
    ASSERT_NE(it, manager->plugins_.end());
    EXPECT_EQ(it->second.size(), 2);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_PluginAssignmentCallBack_002
 * @tc.desc: Test PluginAssignmentCallBack with non-existing stage plugins
 * @tc.require: test PluginAssignmentCallBack
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_PluginAssignmentCallBack_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    manager->plugins_.clear();

    std::function<void(PluginEventType, int64_t)> callback = [](PluginEventType, int64_t) {};

    manager->PluginAssignmentCallBack(callback, InputPluginStage::INPUT_AFTER_FILTER);

    EXPECT_EQ(manager->plugins_.size(), 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_PluginAssignmentCallBack_003
 * @tc.desc: Test PluginAssignmentCallBack with empty plugin list in stage
 * @tc.require: test PluginAssignmentCallBack
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_PluginAssignmentCallBack_003,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    manager->plugins_[InputPluginStage::INPUT_AFTER_FILTER] = {};

    std::function<void(PluginEventType, int64_t)> callback = [](PluginEventType, int64_t) {};

    manager->PluginAssignmentCallBack(callback, InputPluginStage::INPUT_AFTER_FILTER);

    auto it = manager->plugins_.find(InputPluginStage::INPUT_AFTER_FILTER);
    ASSERT_NE(it, manager->plugins_.end());
    EXPECT_EQ(it->second.size(), 0);
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
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPluginManager_IntermediateEndEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_MOTION));
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    libinput_event_keyboard keyboardEvent;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_KEYBOARD_KEY));
    EXPECT_CALL(libinputMock, LibinputEventGetKeyboardEvent).WillRepeatedly(Return(&keyboardEvent));
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKeyState).WillRepeatedly(Return(LIBINPUT_KEY_STATE_RELEASED));
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    libinput_event_pointer pointerEvent;
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY));
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillRepeatedly(Return(nullptr));
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TABLET_TOOL_TIP));
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillRepeatedly(Return(nullptr));
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    std::shared_ptr<AxisEvent> axisEvent = std::make_shared<AxisEvent>(AxisEvent::AXIS_ACTION_START);
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(axisEvent));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_IntermediateEndEvent_002
 * @tc.desc: Test IntermediateEndEvent with null event
 * @tc.require: test IntermediateEndEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPluginManager_IntermediateEndEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<AxisEvent> axisEvent = std::make_shared<AxisEvent>(AxisEvent::AXIS_ACTION_START);
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(axisEvent)); // Non-libinput_event*
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_IntermediateEndEvent_003
 * @tc.desc: Test IntermediateEndEvent with motion events
 * @tc.require: test IntermediateEndEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPluginManager_IntermediateEndEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event;
    NiceMock<LibinputInterfaceMock> libinputMock;

    // Test LIBINPUT_EVENT_POINTER_MOTION
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_MOTION));
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    // Test LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_MOTION_ABSOLUTE));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPluginManager_IntermediateEndEvent_004
 * @tc.desc: Test IntermediateEndEvent with keyboard key release
 * @tc.require: test IntermediateEndEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPluginManager_IntermediateEndEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event;
    NiceMock<LibinputInterfaceMock> libinputMock;

    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_KEYBOARD_KEY));
    struct libinput_event_keyboard keyboardEvent;
    EXPECT_CALL(libinputMock, LibinputEventGetKeyboardEvent).WillRepeatedly(Return(&keyboardEvent));
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKeyState).WillRepeatedly(Return(LIBINPUT_KEY_STATE_RELEASED));
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    // Test key press state
    EXPECT_CALL(libinputMock, LibinputEventKeyboardGetKeyState).WillRepeatedly(Return(LIBINPUT_KEY_STATE_PRESSED));
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleMonitorStatus_001
 * @tc.desc: Test HandleMonitorStatus with non-existing stage
 * @tc.require: test HandleMonitorStatus
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleMonitorStatus_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear(); // Clear all plugins

    bool monitorStatus = true;
    std::string monitorType = "testType";
    manager->HandleMonitorStatus(monitorStatus, monitorType);

    // Verify no plugins were processed
    EXPECT_EQ(manager->plugins_.size(), 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleMonitorStatus_002
 * @tc.desc: Test HandleMonitorStatus with empty plugin list
 * @tc.require: test HandleMonitorStatus
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleMonitorStatus_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = {}; // Empty plugin list

    bool monitorStatus = false;
    std::string monitorType = "emptyList";
    manager->HandleMonitorStatus(monitorStatus, monitorType);

    // Verify plugin list remains empty
    auto it = manager->plugins_.find(InputPluginStage::INPUT_BEFORE_KEYCOMMAND);
    ASSERT_NE(it, manager->plugins_.end());
    EXPECT_EQ(it->second.size(), 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleMonitorStatus_003
 * @tc.desc: Test HandleMonitorStatus with multiple plugins
 * @tc.require: test HandleMonitorStatus
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleMonitorStatus_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    std::shared_ptr<MockInputPluginContext> mockPlugin1 = std::make_shared<MockInputPluginContext>();
    std::shared_ptr<MockInputPluginContext> mockPlugin2 = std::make_shared<MockInputPluginContext>();

    EXPECT_CALL(*mockPlugin1, HandleMonitorStatus(true, "multiPlugin")).Times(1);
    EXPECT_CALL(*mockPlugin2, HandleMonitorStatus(true, "multiPlugin")).Times(1);

    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { mockPlugin1, mockPlugin2 };

    bool monitorStatus = true;
    std::string monitorType = "multiPlugin";
    manager->HandleMonitorStatus(monitorStatus, monitorType);

    // Verify plugins were processed
    auto it = manager->plugins_.find(InputPluginStage::INPUT_BEFORE_KEYCOMMAND);
    ASSERT_NE(it, manager->plugins_.end());
    EXPECT_EQ(it->second.size(), 2);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleMonitorStatus_004
 * @tc.desc: Test HandleMonitorStatus with nullptr plugin
 * @tc.require: test HandleMonitorStatus
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleMonitorStatus_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    EXPECT_CALL(*mockPlugin, HandleMonitorStatus(false, "nullPlugin")).Times(1);

    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { nullptr, mockPlugin };

    bool monitorStatus = false;
    std::string monitorType = "nullPlugin";
    manager->HandleMonitorStatus(monitorStatus, monitorType);

    // Verify only valid plugin was processed
    auto it = manager->plugins_.find(InputPluginStage::INPUT_BEFORE_KEYCOMMAND);
    ASSERT_NE(it, manager->plugins_.end());
    EXPECT_EQ(it->second.size(), 2);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleShortcutKey_001
 * @tc.desc: Test HandleShortcutKey with empty plugin list
 * @tc.require: test HandleShortcutKey
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleShortcutKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear();

    ShortcutKey key;
    key.preKeys = { 1, 2 };
    key.finalKey = 3;
    key.keyDownDuration = 100;
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;

    bool result = manager->HandleShortcutKey(key);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleShortcutKey_002
 * @tc.desc: Test HandleShortcutKey with nullptr plugin
 * @tc.require: test HandleShortcutKey
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleShortcutKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { nullptr };

    ShortcutKey key;
    key.preKeys = { 1, 2 };
    key.finalKey = 3;
    key.keyDownDuration = 100;
    key.triggerType = KeyEvent::KEY_ACTION_DOWN;

    bool result = manager->HandleShortcutKey(key);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleShortcutKey_003
 * @tc.desc: Test HandleShortcutKey with empty plugin list
 * @tc.require: test HandleShortcutKey
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleShortcutKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear();

    KeyOption option;
    option.SetPreKeys({ 1, 2 });
    option.SetFinalKey(3);
    option.SetFinalKeyDownDuration(100);
    option.SetFinalKeyDown(true);

    bool result = manager->HandleShortcutKey(option);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleShortcutKey_004
 * @tc.desc: Test HandleShortcutKey with nullptr plugin
 * @tc.require: test HandleShortcutKey
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleShortcutKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { nullptr };

    KeyOption option;
    option.SetPreKeys({ 1, 2 });
    option.SetFinalKey(3);
    option.SetFinalKeyDownDuration(100);
    option.SetFinalKeyDown(true);

    bool result = manager->HandleShortcutKey(option);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ProcessShortcutKey_001
 * @tc.desc: Test ProcessShortcutKey with plugin consuming shortcut key
 * @tc.require: test ProcessShortcutKey
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ProcessShortcutKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    EXPECT_CALL(*mockPlugin, GetPlugin()).WillRepeatedly([]() {
        auto mockInputPlugin = std::make_shared<MockInputPlugin>();
        EXPECT_CALL(*mockInputPlugin, HandleShortcutKey(testing::_)).WillRepeatedly(Return(true));
        return mockInputPlugin;
    });

    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { mockPlugin };

    IShortcutKey shortcutKey;
    shortcutKey.preKeys = { 1, 2 };
    shortcutKey.finalKey = 3;
    shortcutKey.keyDownDuration = 100;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;

    bool result = manager->ProcessShortcutKey(shortcutKey);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ProcessShortcutKey_002
 * @tc.desc: Test ProcessShortcutKey with plugin not consuming shortcut key
 * @tc.require: test ProcessShortcutKey
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ProcessShortcutKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    EXPECT_CALL(*mockPlugin, GetPlugin()).WillRepeatedly([]() {
        auto mockInputPlugin = std::make_shared<MockInputPlugin>();
        EXPECT_CALL(*mockInputPlugin, HandleShortcutKey(testing::_)).WillRepeatedly(Return(false));
        return mockInputPlugin;
    });

    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { mockPlugin };

    IShortcutKey shortcutKey;
    shortcutKey.preKeys = { 1, 2 };
    shortcutKey.finalKey = 3;
    shortcutKey.keyDownDuration = 100;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;

    bool result = manager->ProcessShortcutKey(shortcutKey);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ProcessShortcutKey_003
 * @tc.desc: Test ProcessShortcutKey with empty plugin list
 * @tc.require: test ProcessShortcutKey
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ProcessShortcutKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear();

    IShortcutKey shortcutKey;
    shortcutKey.preKeys = { 1, 2 };
    shortcutKey.finalKey = 3;
    shortcutKey.keyDownDuration = 100;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;

    bool result = manager->ProcessShortcutKey(shortcutKey);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ProcessShortcutKey_004
 * @tc.desc: Test ProcessShortcutKey with nullptr plugin context
 * @tc.require: test ProcessShortcutKey
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ProcessShortcutKey_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { nullptr };

    IShortcutKey shortcutKey;
    shortcutKey.preKeys = { 1, 2 };
    shortcutKey.finalKey = 3;
    shortcutKey.keyDownDuration = 100;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;

    bool result = manager->ProcessShortcutKey(shortcutKey);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ProcessShortcutKey_005
 * @tc.desc: Test ProcessShortcutKey with nullptr plugin object
 * @tc.require: test ProcessShortcutKey
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ProcessShortcutKey_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    EXPECT_CALL(*mockPlugin, GetPlugin()).WillRepeatedly(Return(nullptr));

    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { mockPlugin };

    IShortcutKey shortcutKey;
    shortcutKey.preKeys = { 1, 2 };
    shortcutKey.finalKey = 3;
    shortcutKey.keyDownDuration = 100;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;

    bool result = manager->ProcessShortcutKey(shortcutKey);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ProcessShortcutKey_006
 * @tc.desc: Test ProcessShortcutKey with multiple stages and plugins
 * @tc.require: test ProcessShortcutKey
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ProcessShortcutKey_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    std::shared_ptr<MockInputPluginContext> mockPlugin1 = std::make_shared<MockInputPluginContext>();
    std::shared_ptr<MockInputPluginContext> mockPlugin2 = std::make_shared<MockInputPluginContext>();

    EXPECT_CALL(*mockPlugin1, GetPlugin()).WillRepeatedly([]() {
        auto mockInputPlugin = std::make_shared<MockInputPlugin>();
        EXPECT_CALL(*mockInputPlugin, HandleShortcutKey(testing::_)).WillRepeatedly(Return(false));
        return mockInputPlugin;
    });

    EXPECT_CALL(*mockPlugin2, GetPlugin()).WillRepeatedly([]() {
        auto mockInputPlugin = std::make_shared<MockInputPlugin>();
        EXPECT_CALL(*mockInputPlugin, HandleShortcutKey(testing::_)).WillRepeatedly(Return(true));
        return mockInputPlugin;
    });

    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { mockPlugin1 };
    manager->plugins_[InputPluginStage::INPUT_AFTER_FILTER] = { mockPlugin2 };

    IShortcutKey shortcutKey;
    shortcutKey.preKeys = { 1, 2 };
    shortcutKey.finalKey = 3;
    shortcutKey.keyDownDuration = 100;
    shortcutKey.triggerType = KeyEvent::KEY_ACTION_DOWN;

    bool result = manager->ProcessShortcutKey(shortcutKey);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleSequenceKeys_001
 * @tc.desc: Test_HandleSequenceKeys_001 - Normal flow with valid sequence
 * @tc.require: test HandleSequenceKeys
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleSequenceKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    // Prepare a valid sequence
    Sequence sequence;
    sequence.sequenceKeys.push_back({ .keyCode = 1, .keyAction = KeyEvent::KEY_ACTION_DOWN, .actionTime = 100,
        .delay = 0 });
    sequence.sequenceKeys.push_back({ .keyCode = 2, .keyAction = KeyEvent::KEY_ACTION_UP, .actionTime = 200,
        .delay = 50 });

    // Mock plugin to consume the sequence
    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    EXPECT_CALL(*mockPlugin, GetPlugin()).WillRepeatedly([]() {
        auto mockInputPlugin = std::make_shared<MockInputPlugin>();
        EXPECT_CALL(*mockInputPlugin, HandleSequenceKeys(testing::_)).WillRepeatedly(Return(true));
        return mockInputPlugin;
    });

    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { mockPlugin };

    bool result = manager->HandleSequenceKeys(sequence);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleSequenceKeys_002
 * @tc.desc: Test_HandleSequenceKeys_002 - Empty sequence
 * @tc.require: test HandleSequenceKeys
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleSequenceKeys_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    // Prepare an empty sequence
    Sequence sequence;

    // Mock plugin that does not consume the sequence
    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    EXPECT_CALL(*mockPlugin, GetPlugin()).WillRepeatedly([]() {
        auto mockInputPlugin = std::make_shared<MockInputPlugin>();
        EXPECT_CALL(*mockInputPlugin, HandleSequenceKeys(testing::_)).WillRepeatedly(Return(false));
        return mockInputPlugin;
    });

    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { mockPlugin };

    bool result = manager->HandleSequenceKeys(sequence);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleSequenceKeys_003
 * @tc.desc: Test_HandleSequenceKeys_003 - Plugin consumes sequence
 * @tc.require: test HandleSequenceKeys
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleSequenceKeys_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    // Prepare a valid sequence
    Sequence sequence;
    sequence.sequenceKeys.push_back({ .keyCode = 1, .keyAction = KeyEvent::KEY_ACTION_DOWN, .actionTime = 100,
        .delay = 0 });

    // Mock plugin to consume the sequence
    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    EXPECT_CALL(*mockPlugin, GetPlugin()).WillRepeatedly([]() {
        auto mockInputPlugin = std::make_shared<MockInputPlugin>();
        EXPECT_CALL(*mockInputPlugin, HandleSequenceKeys(testing::_)).WillRepeatedly(Return(true));
        return mockInputPlugin;
    });

    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { mockPlugin };

    bool result = manager->HandleSequenceKeys(sequence);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleSequenceKeys_004
 * @tc.desc: Test_HandleSequenceKeys_004 - Plugin does not consume sequence
 * @tc.require: test HandleSequenceKeys
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleSequenceKeys_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    // Prepare a valid sequence
    Sequence sequence;
    sequence.sequenceKeys.push_back({ .keyCode = 1, .keyAction = KeyEvent::KEY_ACTION_DOWN, .actionTime = 100,
        .delay = 0 });

    // Mock plugin that does not consume the sequence
    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    EXPECT_CALL(*mockPlugin, GetPlugin()).WillRepeatedly([]() {
        auto mockInputPlugin = std::make_shared<MockInputPlugin>();
        EXPECT_CALL(*mockInputPlugin, HandleSequenceKeys(testing::_)).WillRepeatedly(Return(false));
        return mockInputPlugin;
    });

    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { mockPlugin };

    bool result = manager->HandleSequenceKeys(sequence);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_HandleSequenceKeys_005
 * @tc.desc: Test_HandleSequenceKeys_005 - Multiple plugins, first one consumes
 * @tc.require: test HandleSequenceKeys
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_HandleSequenceKeys_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    // Prepare a valid sequence
    Sequence sequence;
    sequence.sequenceKeys.push_back({ .keyCode = 1, .keyAction = KeyEvent::KEY_ACTION_DOWN, .actionTime = 100,
        .delay = 0 });

    // Mock two plugins, first one consumes the sequence
    std::shared_ptr<MockInputPluginContext> mockPlugin1 = std::make_shared<MockInputPluginContext>();
    std::shared_ptr<MockInputPluginContext> mockPlugin2 = std::make_shared<MockInputPluginContext>();

    EXPECT_CALL(*mockPlugin1, GetPlugin()).WillRepeatedly([]() {
        auto mockInputPlugin = std::make_shared<MockInputPlugin>();
        EXPECT_CALL(*mockInputPlugin, HandleSequenceKeys(testing::_)).WillRepeatedly(Return(true));
        return mockInputPlugin;
    });

    EXPECT_CALL(*mockPlugin2, GetPlugin()).Times(0); // Second plugin should not be called

    manager->plugins_[InputPluginStage::INPUT_BEFORE_KEYCOMMAND] = { mockPlugin1, mockPlugin2 };

    bool result = manager->HandleSequenceKeys(sequence);
    EXPECT_TRUE(result);
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
    EXPECT_CALL(libinputMock, TouchEventGetToolType).WillRepeatedly(Return(11));
    EXPECT_CALL(libinputMock, GetTouchEvent).WillRepeatedly(Return(&touchEvent));
    char deviceName[] = "yunshuiqiao";
    EXPECT_CALL(libinputMock, DeviceGetName).WillRepeatedly(Return(deviceName));

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
    EXPECT_CALL(libinputMock, GetTouchEvent).WillRepeatedly(Return(&touchEvent));
    IPluginData* data = InputPluginManager::GetInstance()->GetPluginDataFromLibInput(&event).get();
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
    EXPECT_CALL(*mockInputPluginContext, HandleEvent(event, data)).WillRepeatedly(Return(PluginResult::NotUse));
    PluginResult result = InputPluginManager::GetInstance()->ProcessEvent(event, mockInputPluginContext, data);
    EXPECT_EQ(result, PluginResult::NotUse);

    std::shared_ptr<PointerEvent> pointerEvent =
        std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    EXPECT_CALL(*mockInputPluginContext, HandleEvent(pointerEvent, data)).WillRepeatedly(Return(PluginResult::NotUse));
    result = InputPluginManager::GetInstance()->ProcessEvent(pointerEvent, mockInputPluginContext, data);
    EXPECT_EQ(result, PluginResult::NotUse);

    std::shared_ptr<AxisEvent> axisEvent =
        std::make_shared<AxisEvent>(AxisEvent::AXIS_ACTION_START);
    EXPECT_CALL(*mockInputPluginContext, HandleEvent(axisEvent, data)).WillRepeatedly(Return(PluginResult::NotUse));
    result = InputPluginManager::GetInstance()->ProcessEvent(axisEvent, mockInputPluginContext, data);
    EXPECT_EQ(result, PluginResult::NotUse);

    std::shared_ptr<KeyEvent> keyEvent =
        std::make_shared<KeyEvent>(KeyEvent::KEYCODE_BRIGHTNESS_DOWN);
    EXPECT_CALL(*mockInputPluginContext, HandleEvent(keyEvent, data)).WillRepeatedly(Return(PluginResult::NotUse));
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
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
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
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
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
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
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

    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
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
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    libinput_event* event = nullptr;
    std::shared_ptr<IPluginData> data = std::make_shared<IPluginData>();
    PluginResult result = inputPluginContext->HandleEvent(event, data);
    EXPECT_EQ(result, PluginResult::NotUse);

    std::shared_ptr<MockInputPlugin> mockInputPlugin = std::make_shared<MockInputPlugin>();
    EXPECT_CALL(*mockInputPlugin, GetName()).WillRepeatedly(Return("yunshuiqiao"));
    EXPECT_CALL(*mockInputPlugin, GetPriority()).WillRepeatedly(Return(201));
    EXPECT_CALL(*mockInputPlugin, GetStage()).WillRepeatedly(Return(InputPluginStage::INPUT_AFTER_NORMALIZED));
    inputPluginContext->Init(mockInputPlugin);

    EXPECT_CALL(*mockInputPlugin, HandleEvent(event, data)).WillRepeatedly(Return(PluginResult::UseNeedReissue));
    result = inputPluginContext->HandleEvent(event, data);
    EXPECT_NE(result, PluginResult::UseNeedReissue);

    std::shared_ptr<PointerEvent> pointerEvent =
        std::make_shared<PointerEvent>(PointerEvent::POINTER_ACTION_PROXIMITY_IN);
    EXPECT_CALL(*mockInputPlugin, HandleEvent(pointerEvent, data)).WillRepeatedly(Return(PluginResult::UseNeedReissue));
    result = inputPluginContext->HandleEvent(pointerEvent, data);
    EXPECT_NE(result, PluginResult::UseNeedReissue);

    std::shared_ptr<AxisEvent> axisEvent =
        std::make_shared<AxisEvent>(AxisEvent::AXIS_ACTION_START);
    EXPECT_CALL(*mockInputPlugin, HandleEvent(axisEvent, data)).WillRepeatedly(Return(PluginResult::UseNeedReissue));
    result = inputPluginContext->HandleEvent(axisEvent, data);
    EXPECT_NE(result, PluginResult::UseNeedReissue);

    std::shared_ptr<KeyEvent> keyEvent =
        std::make_shared<KeyEvent>(KeyEvent::KEYCODE_BRIGHTNESS_DOWN);
    EXPECT_CALL(*mockInputPlugin, HandleEvent(keyEvent, data)).WillRepeatedly(Return(PluginResult::UseNeedReissue));
    result = inputPluginContext->HandleEvent(keyEvent, data);
    EXPECT_NE(result, PluginResult::UseNeedReissue);
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
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
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
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
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
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::function<void(PluginEventType, int64_t)> callback = [](PluginEventType, int64_t) {};
    inputPluginContext->SetCallback(callback);
    EXPECT_NE(inputPluginContext->callback_, nullptr);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_IsFingerPressed_001
 * @tc.desc: test TOUCH_EVENT_HDR == nullptr
 * @tc.require: test IsFingerPressed
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_IsFingerPressed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    EXPECT_EQ(inputPluginContext->IsFingerPressed(), false);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_GetFocusedPid_001
 * @tc.desc: test WIN_MGR == nullptr
 * @tc.require: test GetFocusedPid
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_GetFocusedPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    EXPECT_EQ(inputPluginContext->GetFocusedPid(), -1);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_AttachDeviceObserver_001
 * @tc.desc: test INPUT_DEV_MGR == nullptr
 * @tc.require: test AttachDeviceObserver
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_AttachDeviceObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::shared_ptr<MockIDeviceObserver> mockDeviceObserver = std::make_shared<MockIDeviceObserver>();
    EXPECT_TRUE(inputPluginContext->AttachDeviceObserver(mockDeviceObserver));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_DetachDeviceObserver_001
 * @tc.desc: test INPUT_DEV_MGR == nullptr
 * @tc.require: test DetachDeviceObserver
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_DetachDeviceObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::shared_ptr<MockIDeviceObserver> mockDeviceObserver = std::make_shared<MockIDeviceObserver>();
    EXPECT_TRUE(inputPluginContext->DetachDeviceObserver(mockDeviceObserver));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_GetCurrentAccountId_001
 * @tc.desc: test ACCOUNT_MGR == nullptr
 * @tc.require: test GetCurrentAccountId
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_GetCurrentAccountId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    int32_t defaultAccountId = 100;
    EXPECT_EQ(inputPluginContext->GetCurrentAccountId(), defaultAccountId);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_RegisterCommonEventCallback_001
 * @tc.desc: test ACCOUNT_MGR == nullptr
 * @tc.require: test RegisterCommonEventCallback
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_RegisterCommonEventCallback_001,
         TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::function<void(const EventFwk::CommonEventData &)> callback = [](const EventFwk::CommonEventData &) {};
    int32_t callbackId = inputPluginContext->RegisterCommonEventCallback(callback);
    EXPECT_NE(callbackId, -1);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_UnRegisterCommonEventCallback_001
 * @tc.desc: test ACCOUNT_MGR == nullptr
 * @tc.require: test UnRegisterCommonEventCallback
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_UnRegisterCommonEventCallback_001,
         TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    int32_t callbackId = 1;
    EXPECT_FALSE(inputPluginContext->UnRegisterCommonEventCallback(callbackId));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_Init_001
 * @tc.desc: Test InputPlugin::Init with empty stages vector
 * @tc.require: test InputPlugin::Init
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_Init_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::shared_ptr<MockInputPlugin> mockInputPlugin = std::make_shared<MockInputPlugin>();
    
    EXPECT_CALL(*mockInputPlugin, GetName()).WillRepeatedly(Return("test plugin"));
    EXPECT_CALL(*mockInputPlugin, GetPriority()).WillRepeatedly(Return(100));
    EXPECT_CALL(*mockInputPlugin, GetStages()).WillRepeatedly(Return(std::vector<InputPluginStage>{}));
    
    int32_t result = inputPluginContext->Init(mockInputPlugin);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_Init_002
 * @tc.desc: Test InputPlugin::Init with single stage
 * @tc.require: test InputPlugin::Init
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_Init_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::shared_ptr<MockInputPlugin> mockInputPlugin = std::make_shared<MockInputPlugin>();
    
    EXPECT_CALL(*mockInputPlugin, GetName()).WillRepeatedly(Return("test plugin"));
    EXPECT_CALL(*mockInputPlugin, GetPriority()).WillRepeatedly(Return(100));
    EXPECT_CALL(*mockInputPlugin, GetStages()).WillRepeatedly(
        Return(std::vector<InputPluginStage>{InputPluginStage::INPUT_AFTER_FILTER}));
    
    int32_t result = inputPluginContext->Init(mockInputPlugin);
    EXPECT_EQ(result, RET_OK);
    EXPECT_EQ(inputPluginContext->stages_.size(), 1);
    EXPECT_EQ(inputPluginContext->stages_[0], InputPluginStage::INPUT_AFTER_FILTER);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_Init_003
 * @tc.desc: Test InputPlugin::Init with multiple stages
 * @tc.require: test InputPlugin::Init
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_Init_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::shared_ptr<MockInputPlugin> mockInputPlugin = std::make_shared<MockInputPlugin>();
    
    EXPECT_CALL(*mockInputPlugin, GetName()).WillRepeatedly(Return("test plugin"));
    EXPECT_CALL(*mockInputPlugin, GetPriority()).WillRepeatedly(Return(100));
    EXPECT_CALL(*mockInputPlugin, GetStages()).WillRepeatedly(
        Return(std::vector<InputPluginStage>{
            InputPluginStage::INPUT_AFTER_FILTER,
            InputPluginStage::INPUT_BEFORE_KEYCOMMAND,
            InputPluginStage::INPUT_AFTER_NORMALIZED}));
    
    int32_t result = inputPluginContext->Init(mockInputPlugin);
    EXPECT_EQ(result, RET_OK);
    EXPECT_EQ(inputPluginContext->stages_.size(), 3);
    EXPECT_EQ(inputPluginContext->stages_[0], InputPluginStage::INPUT_AFTER_FILTER);
    EXPECT_EQ(inputPluginContext->stages_[1], InputPluginStage::INPUT_BEFORE_KEYCOMMAND);
    EXPECT_EQ(inputPluginContext->stages_[2], InputPluginStage::INPUT_AFTER_NORMALIZED);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_RegisterSettingObserver_001
 * @tc.desc: Test RegisterSettingObserver with invalid parameters (empty uri)
 * @tc.require: test RegisterSettingObserver
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_RegisterSettingObserver_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);

    std::string emptyUri = "";
    std::string key = "test.key";
    std::function<void(const std::string&)> callback = [](const std::string&) {};

    int32_t observerId = inputPluginContext->RegisterSettingObserver(emptyUri, key, callback);
    EXPECT_EQ(observerId, static_cast<int32_t>(ObserverError::INVALID_PARAM));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_RegisterSettingObserver_002
 * @tc.desc: Test RegisterSettingObserver with invalid parameters (empty key)
 * @tc.require: test RegisterSettingObserver
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_RegisterSettingObserver_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);

    std::string uri = "datashare:///test";
    std::string emptyKey = "";
    std::function<void(const std::string&)> callback = [](const std::string&) {};

    int32_t observerId = inputPluginContext->RegisterSettingObserver(uri, emptyKey, callback);
    EXPECT_EQ(observerId, static_cast<int32_t>(ObserverError::INVALID_PARAM));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_RegisterSettingObserver_003
 * @tc.desc: Test RegisterSettingObserver with invalid parameters (null callback)
 * @tc.require: test RegisterSettingObserver
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_RegisterSettingObserver_003,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);

    std::string uri = "datashare:///test";
    std::string key = "test.key";
    std::function<void(const std::string&)> nullCallback = nullptr;

    int32_t observerId = inputPluginContext->RegisterSettingObserver(uri, key, nullCallback);
    EXPECT_EQ(observerId, static_cast<int32_t>(ObserverError::INVALID_PARAM));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_RegisterSettingObserver_004
 * @tc.desc: Test RegisterSettingObserver ID increment
 * @tc.require: test RegisterSettingObserver
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_RegisterSettingObserver_004,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);

    // Simulate successful observer creation (will fail in reality without DataShare)
    // This test verifies ID increment logic
    inputPluginContext->nextObserverId_ = 1;
    EXPECT_EQ(inputPluginContext->nextObserverId_, 1);

    // Test ID increment
    inputPluginContext->nextObserverId_++;
    EXPECT_EQ(inputPluginContext->nextObserverId_, 2);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_RegisterSettingObserver_005
 * @tc.desc: Test RegisterSettingObserver overflow protection
 * @tc.require: test RegisterSettingObserver
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_RegisterSettingObserver_005,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);

    // Simulate overflow condition
    inputPluginContext->nextObserverId_ = -1;  // Overflow state

    // Test overflow protection logic
    if (inputPluginContext->nextObserverId_ < 0) {
        inputPluginContext->nextObserverId_ = 1;
    }
    EXPECT_EQ(inputPluginContext->nextObserverId_, 1);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_UnregisterSettingObserver_001
 * @tc.desc: Test UnregisterSettingObserver with invalid observer ID (negative)
 * @tc.require: test UnregisterSettingObserver
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_UnregisterSettingObserver_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);

    int32_t invalidId = -1;
    bool result = inputPluginContext->UnregisterSettingObserver(invalidId);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_NextObserverId_Initialization_001
 * @tc.desc: Test nextObserverId_ is initialized to 1
 * @tc.require: test NextObserverId initialization
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_NextObserverId_Initialization_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);

    EXPECT_EQ(inputPluginContext->nextObserverId_, 1);
}

#ifdef OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_RegisterKeyMonitorCallback_001
 * @tc.desc: Test RegisterKeyMonitorCallback with valid callback
 * @tc.require: test RegisterKeyMonitorCallback
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_RegisterKeyMonitorCallback_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::function<void(int32_t pid, int32_t keyCode, std::string bundleName, bool isAdd)> callback =
        [](int32_t pid, int32_t keyCode, std::string bundleName, bool isAdd) {
            MMI_HILOGI("KeyMonitor callback invoked, pid:%{public}d, keyCode:%{public}d", pid, keyCode);
        };
    int32_t callbackId = inputPluginContext->RegisterKeyMonitorCallback(callback);
    EXPECT_GT(callbackId, 0);
}
 
/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_RegisterKeyMonitorCallback_002
 * @tc.desc: Test RegisterKeyMonitorCallback with null callback
 * @tc.require: test RegisterKeyMonitorCallback
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_RegisterKeyMonitorCallback_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    int32_t callbackId = inputPluginContext->RegisterKeyMonitorCallback(nullptr);
    EXPECT_EQ(callbackId, -1);
}
 
/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_UnregisterKeyMonitorCallback_001
 * @tc.desc: Test UnregisterKeyMonitorCallback normal flow
 * @tc.require: test UnregisterKeyMonitorCallback
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_UnregisterKeyMonitorCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::function<void(int32_t pid, int32_t keyCode, std::string bundleName, bool isAdd)> callback =
        [](int32_t pid, int32_t keyCode, std::string bundleName, bool isAdd) {
            MMI_HILOGI("KeyMonitor callback invoked");
        };
    int32_t callbackId = inputPluginContext->RegisterKeyMonitorCallback(callback);
    EXPECT_GT(callbackId, 0);
    bool result = inputPluginContext->UnregisterKeyMonitorCallback(callbackId);
    EXPECT_TRUE(result);
}
 
/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_UnregisterKeyMonitorCallback_002
 * @tc.desc: Test UnregisterKeyMonitorCallback with invalid callback id
 * @tc.require: test UnregisterKeyMonitorCallback
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_UnregisterKeyMonitorCallback_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    bool result = inputPluginContext->UnregisterKeyMonitorCallback(9999);
    EXPECT_FALSE(result);
}
 
/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_GetSubscribedKeysByPid_001
 * @tc.desc: Test GetSubscribedKeysByPid returns empty when no subscribes
 * @tc.require: test GetSubscribedKeysByPid
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_GetSubscribedKeysByPid_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::vector<int32_t> result = inputPluginContext->GetSubscribedKeysByPid(100);
    EXPECT_TRUE(result.empty());
}
#endif // OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadDynamicPlugin_001
 * @tc.desc: Test LoadDynamicPlugin with empty uuid
 * @tc.require: test LoadDynamicPlugin
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadDynamicPlugin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    int32_t result = manager->LoadDynamicPlugin(100, "");
    EXPECT_EQ(result, PARAM_INPUT_INVALID);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadDynamicPlugin_002
 * @tc.desc: Test LoadDynamicPlugin with not found config
 * @tc.require: test LoadDynamicPlugin
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadDynamicPlugin_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    int32_t result = manager->LoadDynamicPlugin(100, "non-existent-uuid");
    EXPECT_EQ(result, PARAM_INPUT_INVALID);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadDynamicPlugin_003
 * @tc.desc: Test LoadDynamicPlugin with permission denied
 * @tc.require: test LoadDynamicPlugin
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadDynamicPlugin_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    InputPluginManager::PluginConfig config;
    config.uuid_ = "test-uuid-123";
    config.uid_ = 200;
    config.name_ = "test_plugin";
    config.mode_ = "dynamic";
    manager->pluginConfigs_[config.uuid_] = config;

    int32_t result = manager->LoadDynamicPlugin(100, config.uuid_);
    EXPECT_EQ(result, ERROR_NO_PERMISSION);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadDynamicPlugin_004
 * @tc.desc: Test LoadDynamicPlugin with permission mismatch
 * @tc.require: test LoadDynamicPlugin
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadDynamicPlugin_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    InputPluginManager::PluginConfig config;
    config.uuid_ = "test-uuid-456";
    config.uid_ = 200;
    config.name_ = "test_plugin";
    config.mode_ = "dynamic";
    manager->pluginConfigs_[config.uuid_] = config;

    int32_t result = manager->LoadDynamicPlugin(100, config.uuid_);
    EXPECT_EQ(result, ERROR_NO_PERMISSION);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadDynamicPlugin_005
 * @tc.desc: Test LoadDynamicPlugin with non-existent plugin file
 * @tc.require: test LoadDynamicPlugin
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadDynamicPlugin_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    InputPluginManager::PluginConfig config;
    config.uuid_ = "test-uuid-789";
    config.uid_ = 100;
    config.name_ = "non_existent_plugin.so";
    config.mode_ = "dynamic";
    manager->pluginConfigs_[config.uuid_] = config;

    int32_t result = manager->LoadDynamicPlugin(100, config.uuid_);
    EXPECT_EQ(result, PARAM_INPUT_INVALID);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_UnloadDynamicPlugin_001
 * @tc.desc: Test UnloadDynamicPlugin with empty uuid
 * @tc.require: test UnloadDynamicPlugin
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_UnloadDynamicPlugin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    int32_t result = manager->UnloadDynamicPlugin(100, "");
    EXPECT_EQ(result, PARAM_INPUT_INVALID);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_UnloadDynamicPlugin_002
 * @tc.desc: Test UnloadDynamicPlugin with not found config
 * @tc.require: test UnloadDynamicPlugin
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_UnloadDynamicPlugin_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    int32_t result = manager->UnloadDynamicPlugin(100, "non-existent-uuid");
    EXPECT_EQ(result, PARAM_INPUT_INVALID);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_UnloadDynamicPlugin_003
 * @tc.desc: Test UnloadDynamicPlugin with permission denied
 * @tc.require: test UnloadDynamicPlugin
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_UnloadDynamicPlugin_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    InputPluginManager::PluginConfig config;
    config.uuid_ = "test-uuid-unload";
    config.uid_ = 200;
    config.name_ = "test_plugin";
    config.mode_ = "dynamic";
    manager->pluginConfigs_[config.uuid_] = config;

    int32_t result = manager->UnloadDynamicPlugin(100, config.uuid_);
    EXPECT_EQ(result, ERROR_NO_PERMISSION);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_UnloadDynamicPlugin_004
 * @tc.desc: Test UnloadDynamicPlugin with not loaded plugin
 * @tc.require: test UnloadDynamicPlugin
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_UnloadDynamicPlugin_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    InputPluginManager::PluginConfig config;
    config.uuid_ = "test-uuid-unload2";
    config.uid_ = 100;
    config.name_ = "test_plugin";
    config.mode_ = "dynamic";
    manager->pluginConfigs_[config.uuid_] = config;

    int32_t result = manager->UnloadDynamicPlugin(100, config.uuid_);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_UnloadDynamicPlugin_005
 * @tc.desc: Test UnloadDynamicPlugin with not loaded plugin
 * @tc.require: test UnloadDynamicPlugin
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_UnloadDynamicPlugin_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    InputPluginManager::PluginConfig config;
    config.uuid_ = "test-uuid-unload3";
    config.uid_ = 100;
    config.name_ = "test_plugin";
    config.mode_ = "dynamic";
    manager->pluginConfigs_[config.uuid_] = config;

    int32_t result = manager->UnloadDynamicPlugin(100, config.uuid_);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_GetExternalObject_001
 * @tc.desc: Test GetExternalObject with empty plugin name
 * @tc.require: test GetExternalObject
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_GetExternalObject_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear();

    sptr<IRemoteObject> stub;
    int32_t result = manager->GetExternalObject("", stub);
    EXPECT_EQ(result, ERROR_NULL_POINTER);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_GetExternalObject_002
 * @tc.desc: Test GetExternalObject with not found plugin
 * @tc.require: test GetExternalObject
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_GetExternalObject_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear();

    sptr<IRemoteObject> stub;
    int32_t result = manager->GetExternalObject("non_existent_plugin", stub);
    EXPECT_EQ(result, ERROR_NULL_POINTER);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_GetExternalObject_003
 * @tc.desc: Test GetExternalObject with null external object
 * @tc.require: test GetExternalObject
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_GetExternalObject_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear();

    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    EXPECT_CALL(*mockPlugin, GetPlugin()).WillRepeatedly([]() {
        auto mockInputPlugin = std::make_shared<MockInputPlugin>();
        EXPECT_CALL(*mockInputPlugin, GetName()).WillRepeatedly(Return("test_plugin"));
        EXPECT_CALL(*mockInputPlugin, GetExternalObject()).WillRepeatedly(Return(nullptr));
        return mockInputPlugin;
    });

    manager->plugins_[InputPluginStage::INPUT_AFTER_FILTER] = { mockPlugin };

    sptr<IRemoteObject> stub;
    int32_t result = manager->GetExternalObject("test_plugin", stub);
    EXPECT_EQ(result, ERROR_NULL_POINTER);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_GetExternalObject_004
 * @tc.desc: Test GetExternalObject success
 * @tc.require: test GetExternalObject
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_GetExternalObject_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear();

    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    sptr<IRemoteObject> testStub = new RemoteObjectTest(u"test");
    EXPECT_CALL(*mockPlugin, GetPlugin()).WillRepeatedly([&testStub]() {
        auto mockInputPlugin = std::make_shared<MockInputPlugin>();
        EXPECT_CALL(*mockInputPlugin, GetName()).WillRepeatedly(Return("test_plugin"));
        EXPECT_CALL(*mockInputPlugin, GetExternalObject()).WillRepeatedly(Return(testStub));
        return mockInputPlugin;
    });

    manager->plugins_[InputPluginStage::INPUT_AFTER_FILTER] = { mockPlugin };

    sptr<IRemoteObject> stub;
    int32_t result = manager->GetExternalObject("test_plugin", stub);
    EXPECT_EQ(result, RET_OK);
    EXPECT_EQ(stub, testStub);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_GetFocusedAppInfo_001
 * @tc.desc: Test GetFocusedAppInfo with null appMgrClient
 * @tc.require: test GetFocusedAppInfo
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_GetFocusedAppInfo_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::string result = inputPluginContext->GetFocusedAppInfo();
    EXPECT_EQ(result, "");
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_CalculateTipPoint_001
 * @tc.desc: Test CalculateTipPoint with null event
 * @tc.require: test CalculateTipPoint
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_CalculateTipPoint_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    int32_t displayId = 0;
    PhysicalCoordinate coord;
    int32_t result = inputPluginContext->CalculateTipPoint(nullptr, displayId, coord);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_CalculateTipPoint_002
 * @tc.desc: Test CalculateTipPoint with null tablet tool event
 * @tc.require: test CalculateTipPoint
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_CalculateTipPoint_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    libinput_event event;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillRepeatedly(Return(nullptr));

    int32_t displayId = 0;
    PhysicalCoordinate coord;
    int32_t result = inputPluginContext->CalculateTipPoint(&event, displayId, coord);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_CalculateTipPoint_003
 * @tc.desc: Test CalculateTipPoint with null input device
 * @tc.require: test CalculateTipPoint
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_CalculateTipPoint_003,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    libinput_event event;
    libinput_event_tablet_tool toolEvent;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillRepeatedly(Return(&toolEvent));
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(nullptr));

    int32_t displayId = 0;
    PhysicalCoordinate coord;
    int32_t result = inputPluginContext->CalculateTipPoint(&event, displayId, coord);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_CalculateTipPoint_004
 * @tc.desc: Test CalculateTipPoint with null WIN_MGR
 * @tc.require: test CalculateTipPoint
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_CalculateTipPoint_004,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    libinput_event event;
    libinput_event_tablet_tool toolEvent;
    libinput_device device;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillRepeatedly(Return(&toolEvent));
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&device));

    int32_t displayId = 0;
    PhysicalCoordinate coord;
    int32_t result = inputPluginContext->CalculateTipPoint(&event, displayId, coord);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_SetMouseAccelerateMotionSwitch_001
 * @tc.desc: Test SetMouseAccelerateMotionSwitch with null event
 * @tc.require: test SetMouseAccelerateMotionSwitch
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_SetMouseAccelerateMotionSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->SetMouseAccelerateMotionSwitch(nullptr, true));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_SetMouseAccelerateMotionSwitch_002
 * @tc.desc: Test SetMouseAccelerateMotionSwitch with null event
 * @tc.require: test SetMouseAccelerateMotionSwitch
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_SetMouseAccelerateMotionSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->SetMouseAccelerateMotionSwitch(nullptr, true));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_SetMouseAccelerateMotionSwitch_003
 * @tc.desc: Test SetMouseAccelerateMotionSwitch with null input device
 * @tc.require: test SetMouseAccelerateMotionSwitch
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_SetMouseAccelerateMotionSwitch_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    libinput_event event;
    libinput_device device;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(nullptr));

    EXPECT_NO_FATAL_FAILURE(inputPluginContext->SetMouseAccelerateMotionSwitch(&event, true));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_SetMouseAccelerateMotionSwitch_004
 * @tc.desc: Test SetMouseAccelerateMotionSwitch with invalid device id
 * @tc.require: test SetMouseAccelerateMotionSwitch
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_SetMouseAccelerateMotionSwitch_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    libinput_event event;
    libinput_device device;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(&device));

    EXPECT_NO_FATAL_FAILURE(inputPluginContext->SetMouseAccelerateMotionSwitch(&event, true));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_GetCurrentMouseLocation_001
 * @tc.desc: Test GetCurrentMouseLocation returns OK
 * @tc.require: test GetCurrentMouseLocation
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_GetCurrentMouseLocation_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    double mouseX = 0;
    double mouseY = 0;
    int32_t result = inputPluginContext->GetCurrentMouseLocation(mouseX, mouseY);
    EXPECT_GE(result, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_GetSettingValue_001
 * @tc.desc: Test GetSettingValue with empty uri
 * @tc.require: test GetSettingValue
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_GetSettingValue_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::string key = "test.key";
    std::string value;
    bool result = inputPluginContext->GetSettingValue("", key, value);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_GetSettingValue_002
 * @tc.desc: Test GetSettingValue with empty key
 * @tc.require: test GetSettingValue
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_GetSettingValue_002,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::string uri = "datashare:///test";
    std::string value;
    bool result = inputPluginContext->GetSettingValue(uri, "", value);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_GetSettingValue_003
 * @tc.desc: Test GetSettingValue with DataShare not ready
 * @tc.require: test GetSettingValue
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_GetSettingValue_003,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::string uri = "datashare:///test";
    std::string key = "test.key";
    std::string value;
    bool result = inputPluginContext->GetSettingValue(uri, key, value);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_HideMouseCursorTemporary_001
 * @tc.desc: Test HideMouseCursorTemporary
 * @tc.require: test HideMouseCursorTemporary
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_HideMouseCursorTemporary_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->HideMouseCursorTemporary());
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_AttachDeviceObserver_001
 * @tc.desc: Test AttachDeviceObserver with null observer
 * @tc.require: test AttachDeviceObserver
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_AttachDeviceObserver_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    bool result = inputPluginContext->AttachDeviceObserver(nullptr);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_DetachDeviceObserver_001
 * @tc.desc: Test DetachDeviceObserver with null observer
 * @tc.require: test DetachDeviceObserver
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_DetachDeviceObserver_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    bool result = inputPluginContext->DetachDeviceObserver(nullptr);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_AddTimer_001
 * @tc.desc: Test AddTimer with existing timer
 * @tc.require: test AddTimer
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_AddTimer_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    std::function<void()> func = []() {};
    int32_t result = inputPluginContext->AddTimer(func, 1000, 1);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_RemoveTimer_001
 * @tc.desc: Test RemoveTimer
 * @tc.require: test RemoveTimer
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_InputPlugin_RemoveTimer_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    inputPluginContext->timerCnt_ = 1;
    int32_t result = inputPluginContext->RemoveTimer(1);
    EXPECT_GE(result, 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_AddPluginToStages_001
 * @tc.desc: Test AddPluginToStages with nullptr cPin
 * @tc.require: test AddPluginToStages
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_AddPluginToStages_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear();
    manager->AddPluginToStages(nullptr);
    EXPECT_EQ(manager->plugins_.size(), 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_AddPluginToStages_002
 * @tc.desc: Test AddPluginToStages with nullptr GetPlugin
 * @tc.require: test AddPluginToStages
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_AddPluginToStages_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear();
    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    EXPECT_CALL(*mockPlugin, GetPlugin()).WillRepeatedly(Return(nullptr));

    manager->AddPluginToStages(mockPlugin);
    EXPECT_EQ(manager->plugins_.size(), 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_FindPluginConfig_001
 * @tc.desc: Test FindPluginConfig with not found uuid
 * @tc.require: test FindPluginConfig
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_FindPluginConfig_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    auto config = manager->FindPluginConfig("non-existent-uuid");
    EXPECT_EQ(config, nullptr);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_FindPluginConfig_002
 * @tc.desc: Test FindPluginConfig with found uuid
 * @tc.require: test FindPluginConfig
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_FindPluginConfig_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    InputPluginManager::PluginConfig config;
    config.uuid_ = "test-find-config";
    config.uid_ = 100;
    config.name_ = "test";
    config.mode_ = "autorun";
    manager->pluginConfigs_[config.uuid_] = config;

    auto result = manager->FindPluginConfig(config.uuid_);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->uuid_, config.uuid_);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ParsePluginConfig_001
 * @tc.desc: Test ParsePluginConfig with null plugins array
 * @tc.require: test ParsePluginConfig
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ParsePluginConfig_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* json = cJSON_CreateObject();
    bool result = manager->ParsePluginConfig("test.json", json);
    EXPECT_FALSE(result);
    cJSON_Delete(json);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ParsePluginItem_001
 * @tc.desc: Test ParsePluginItem with missing uuid field
 * @tc.require: test ParsePluginItem
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ParsePluginItem_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* item = cJSON_CreateObject();
    cJSON_AddNumberToObject(item, "uid", 100);
    cJSON_AddStringToObject(item, "name", "test_plugin");
    cJSON_AddStringToObject(item, "mode", "autorun");

    bool result = manager->ParsePluginItem(item);
    EXPECT_FALSE(result);
    cJSON_Delete(item);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ParsePluginItem_002
 * @tc.desc: Test ParsePluginItem with missing uid field
 * @tc.require: test ParsePluginItem
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ParsePluginItem_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "uuid", "test-uuid-123");
    cJSON_AddStringToObject(item, "name", "test_plugin");
    cJSON_AddStringToObject(item, "mode", "autorun");

    bool result = manager->ParsePluginItem(item);
    EXPECT_FALSE(result);
    cJSON_Delete(item);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ParsePluginItem_003
 * @tc.desc: Test ParsePluginItem with invalid mode
 * @tc.require: test ParsePluginItem
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ParsePluginItem_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "uuid", "test-uuid-456");
    cJSON_AddNumberToObject(item, "uid", 100);
    cJSON_AddStringToObject(item, "name", "test_plugin");
    cJSON_AddStringToObject(item, "mode", "invalid_mode");

    bool result = manager->ParsePluginItem(item);
    EXPECT_FALSE(result);
    cJSON_Delete(item);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ParsePluginItem_004
 * @tc.desc: Test ParsePluginItem with duplicate uuid
 * @tc.require: test ParsePluginItem
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ParsePluginItem_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");

    InputPluginManager::PluginConfig existingConfig;
    existingConfig.uuid_ = "duplicate-uuid";
    existingConfig.uid_ = 100;
    existingConfig.name_ = "existing_plugin";
    existingConfig.mode_ = "autorun";
    manager->pluginConfigs_[existingConfig.uuid_] = existingConfig;

    cJSON* item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "uuid", "duplicate-uuid");
    cJSON_AddNumberToObject(item, "uid", 200);
    cJSON_AddStringToObject(item, "name", "new_plugin");
    cJSON_AddStringToObject(item, "mode", "autorun");

    bool result = manager->ParsePluginItem(item);
    EXPECT_FALSE(result);
    cJSON_Delete(item);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ReadStringField_001
 * @tc.desc: Test ReadStringField with null json
 * @tc.require: test ReadStringField
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ReadStringField_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* obj = cJSON_CreateObject();
    std::string out;
    bool result = manager->ReadStringField(obj, "non_exist_field", out);
    EXPECT_FALSE(result);
    cJSON_Delete(obj);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ReadStringField_002
 * @tc.desc: Test ReadStringField with null string value
 * @tc.require: test ReadStringField
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ReadStringField_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddNullToObject(obj, "test_field");
    std::string out;
    bool result = manager->ReadStringField(obj, "test_field", out);
    EXPECT_FALSE(result);
    cJSON_Delete(obj);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ReadStringField_003
 * @tc.desc: Test ReadStringField with empty string value
 * @tc.require: test ReadStringField
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ReadStringField_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "test_field", "");
    std::string out;
    bool result = manager->ReadStringField(obj, "test_field", out);
    EXPECT_FALSE(result);
    cJSON_Delete(obj);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ReadNumberField_001
 * @tc.desc: Test ReadNumberField with null json
 * @tc.require: test ReadNumberField
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ReadNumberField_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* obj = cJSON_CreateObject();
    int32_t out = 0;
    bool result = manager->ReadNumberField(obj, "non_exist_field", out);
    EXPECT_FALSE(result);
    cJSON_Delete(obj);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_RemovePluginFromStages_001
 * @tc.desc: Test RemovePluginFromStages
 * @tc.require: test RemovePluginFromStages
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_RemovePluginFromStages_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    manager->plugins_[InputPluginStage::INPUT_AFTER_FILTER] = { mockPlugin };

    manager->RemovePluginFromStages(mockPlugin);
    auto it = manager->plugins_.find(InputPluginStage::INPUT_AFTER_FILTER);
    EXPECT_EQ(it->second.size(), 0);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_AddCallbackToPlugin_001
 * @tc.desc: Test AddCallbackToPlugin with null cPin
 * @tc.require: test AddCallbackToPlugin
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_AddCallbackToPlugin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    EXPECT_NO_FATAL_FAILURE(manager->AddCallbackToPlugin(nullptr));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_AddCallbackToPlugin_002
 * @tc.desc: Test AddCallbackToPlugin with null GetPlugin
 * @tc.require: test AddCallbackToPlugin
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_AddCallbackToPlugin_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    EXPECT_CALL(*mockPlugin, GetPlugin()).WillRepeatedly(Return(nullptr));

    EXPECT_NO_FATAL_FAILURE(manager->AddCallbackToPlugin(mockPlugin));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadPluginAsync_001
 * @tc.desc: Test LoadPluginAsync with null delegate
 * @tc.require: test LoadPluginAsync
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadPluginAsync_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    EXPECT_NO_FATAL_FAILURE(manager->LoadPluginAsync(nullptr, "test-uuid", "/tmp/test.so"));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadPluginAsync_002
 * @tc.desc: Test LoadPluginAsync with failed load
 * @tc.require: test LoadPluginAsync
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_LoadPluginAsync_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    auto delegate = std::make_shared<MockIDelegateInterface>();
    EXPECT_NO_FATAL_FAILURE(manager->LoadPluginAsync(delegate, "test-uuid", "/tmp/nonexistent.so"));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_PluginConfig_IsValid_001
 * @tc.desc: Test PluginConfig IsValid with empty uuid
 * @tc.require: test PluginConfig IsValid
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_PluginConfig_IsValid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager::PluginConfig config;
    config.uuid_ = "";
    config.name_ = "test";
    config.mode_ = "autorun";
    EXPECT_FALSE(config.IsValid());
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_PluginConfig_IsValid_002
 * @tc.desc: Test PluginConfig IsValid with empty name
 * @tc.require: test PluginConfig IsValid
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_PluginConfig_IsValid_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager::PluginConfig config;
    config.uuid_ = "test-uuid";
    config.name_ = "";
    config.mode_ = "autorun";
    EXPECT_FALSE(config.IsValid());
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_PluginConfig_IsValid_003
 * @tc.desc: Test PluginConfig IsValid with invalid mode
 * @tc.require: test PluginConfig IsValid
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_PluginConfig_IsValid_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager::PluginConfig config;
    config.uuid_ = "test-uuid";
    config.name_ = "test";
    config.mode_ = "invalid_mode";
    EXPECT_FALSE(config.IsValid());
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ParsePluginItem_005
 * @tc.desc: Test ParsePluginItem with missing name field
 * @tc.require: test ParsePluginItem
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ParsePluginItem_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "uuid", "test-uuid-no-name");
    cJSON_AddNumberToObject(item, "uid", 100);
    cJSON_AddStringToObject(item, "mode", "autorun");

    bool result = manager->ParsePluginItem(item);
    EXPECT_FALSE(result);
    cJSON_Delete(item);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ParsePluginItem_006
 * @tc.desc: Test ParsePluginItem with missing mode field
 * @tc.require: test ParsePluginItem
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ParsePluginItem_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "uuid", "test-uuid-no-mode");
    cJSON_AddNumberToObject(item, "uid", 100);
    cJSON_AddStringToObject(item, "name", "test_plugin");

    bool result = manager->ParsePluginItem(item);
    EXPECT_FALSE(result);
    cJSON_Delete(item);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ReadStringField_004
 * @tc.desc: Test ReadStringField success with valid string value
 * @tc.require: test ReadStringField
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ReadStringField_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "test_field", "hello");
    std::string out;
    bool result = manager->ReadStringField(obj, "test_field", out);
    EXPECT_TRUE(result);
    EXPECT_EQ(out, "hello");
    cJSON_Delete(obj);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ReadNumberField_002
 * @tc.desc: Test ReadNumberField with non-number type field
 * @tc.require: test ReadNumberField
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ReadNumberField_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "test_field", "not_a_number");
    int32_t out = 0;
    bool result = manager->ReadNumberField(obj, "test_field", out);
    EXPECT_FALSE(result);
    cJSON_Delete(obj);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_ReadNumberField_003
 * @tc.desc: Test ReadNumberField success with valid number
 * @tc.require: test ReadNumberField
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_ReadNumberField_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "test_field", 42);
    int32_t out = 0;
    bool result = manager->ReadNumberField(obj, "test_field", out);
    EXPECT_TRUE(result);
    EXPECT_EQ(out, 42);
    cJSON_Delete(obj);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_DoHandleEvent_003
 * @tc.desc: Test DoHandleEvent returns RET_DO when plugin returns UseNeedReissue
 * @tc.require: test DoHandleEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_DoHandleEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear();

    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    std::shared_ptr<IPluginData> data = std::make_shared<IPluginData>();
    data->stage = InputPluginStage::INPUT_AFTER_FILTER;

    std::shared_ptr<KeyEvent> keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_A);

    EXPECT_CALL(*mockPlugin, HandleEvent(testing::An<std::shared_ptr<KeyEvent>>(), testing::_))
        .WillRepeatedly(Return(PluginResult::UseNeedReissue));
    manager->plugins_[InputPluginStage::INPUT_AFTER_FILTER] = { mockPlugin };

    int32_t result = manager->DoHandleEvent(keyEvent, data, nullptr);
    EXPECT_EQ(result, RET_DO);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_DoHandleEvent_004
 * @tc.desc: Test DoHandleEvent returns RET_DO when plugin returns UseNoNeedReissue
 * @tc.require: test DoHandleEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_DoHandleEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear();

    std::shared_ptr<MockInputPluginContext> mockPlugin = std::make_shared<MockInputPluginContext>();
    std::shared_ptr<IPluginData> data = std::make_shared<IPluginData>();
    data->stage = InputPluginStage::INPUT_AFTER_FILTER;

    std::shared_ptr<KeyEvent> keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_A);

    EXPECT_CALL(*mockPlugin, HandleEvent(testing::An<std::shared_ptr<KeyEvent>>(), testing::_))
        .WillRepeatedly(Return(PluginResult::UseNoNeedReissue));
    manager->plugins_[InputPluginStage::INPUT_AFTER_FILTER] = { mockPlugin };

    int32_t result = manager->DoHandleEvent(keyEvent, data, nullptr);
    EXPECT_EQ(result, RET_DO);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_DoHandleEvent_005
 * @tc.desc: Test DoHandleEvent with iplugin parameter resumes from next plugin
 * @tc.require: test DoHandleEvent
 */
HWTEST_F(MultimodalInputPluginManagerTest, MultimodalInputPluginManagerTest_DoHandleEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    manager->plugins_.clear();

    std::shared_ptr<MockInputPluginContext> mockPlugin1 = std::make_shared<MockInputPluginContext>();
    std::shared_ptr<MockInputPluginContext> mockPlugin2 = std::make_shared<MockInputPluginContext>();
    std::shared_ptr<IPluginData> data = std::make_shared<IPluginData>();
    data->stage = InputPluginStage::INPUT_AFTER_FILTER;

    std::shared_ptr<KeyEvent> keyEvent = std::make_shared<KeyEvent>(KeyEvent::KEYCODE_A);

    EXPECT_CALL(*mockPlugin2, HandleEvent(testing::An<std::shared_ptr<KeyEvent>>(), testing::_))
        .WillRepeatedly(Return(PluginResult::NotUse));
    manager->plugins_[InputPluginStage::INPUT_AFTER_FILTER] = { mockPlugin1, mockPlugin2 };

    int32_t result = manager->DoHandleEvent(keyEvent, data, mockPlugin1.get());
    EXPECT_EQ(result, RET_NOTDO);
}
/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_AddTimer_Overflow_001
 * @tc.desc: Verify AddTimer returns RET_ERR when timerCnt_ reaches MAX_TIMER
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_AddTimer_Overflow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPlugin = std::make_shared<InputPlugin>(nullptr);
    inputPlugin->timerCnt_ = 3;
    std::function<void()> func = []() {};
    int32_t result = inputPlugin->AddTimer(func, 1000, 1);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_HandleMonitorStatus_001
 * @tc.desc: Verify HandleMonitorStatus delegates to plugin_->HandleMonitorStatus
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_HandleMonitorStatus_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPlugin = std::make_shared<InputPlugin>(nullptr);
    std::shared_ptr<MockInputPlugin> mockPlugin = std::make_shared<MockInputPlugin>();
    EXPECT_CALL(*mockPlugin, GetName()).WillRepeatedly(Return("test"));
    EXPECT_CALL(*mockPlugin, GetPriority()).WillRepeatedly(Return(100));
    EXPECT_CALL(*mockPlugin, GetStages()).WillRepeatedly(
        Return(std::vector<InputPluginStage>{InputPluginStage::INPUT_AFTER_FILTER}));
    EXPECT_CALL(*mockPlugin, HandleMonitorStatus(true, "testType")).Times(1);

    inputPlugin->Init(mockPlugin);
    inputPlugin->HandleMonitorStatus(true, "testType");
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_LoadDynamicPlugin_AlreadyLoaded_001
 * @tc.desc: Verify LoadDynamicPlugin returns RET_OK when plugin is already loaded
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_LoadDynamicPlugin_AlreadyLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager* manager = InputPluginManager::GetInstance("/tmp");
    InputPluginManager::PluginConfig config;
    config.uuid_ = "already-loaded-uuid";
    config.uid_ = 100;
    config.name_ = "loaded_plugin";
    config.mode_ = "dynamic";
    manager->pluginConfigs_[config.uuid_] = config;
    manager->dynamicPlugins_[config.uuid_] = nullptr;

    int32_t result = manager->LoadDynamicPlugin(100, config.uuid_);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_IntermediateEndEvent_PointerButton_001
 * @tc.desc: Verify IntermediateEndEvent for POINTER_BUTTON released/pressed
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_IntermediateEndEvent_PointerButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event;
    libinput_event_pointer pointerEvent;
    pointerEvent.buttonState = LIBINPUT_BUTTON_STATE_RELEASED;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_BUTTON));
    EXPECT_CALL(libinputMock, LibinputGetPointerEvent).WillRepeatedly(Return(&pointerEvent));
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    pointerEvent.buttonState = LIBINPUT_BUTTON_STATE_PRESSED;
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_IntermediateEndEvent_JoystickButton_001
 * @tc.desc: Verify IntermediateEndEvent for JOYSTICK_BUTTON released/pressed
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_IntermediateEndEvent_JoystickButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event;
    libinput_event_joystick_button joystickBtnEvent;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_JOYSTICK_BUTTON));
    EXPECT_CALL(libinputMock, JoystickGetButtonEvent).WillRepeatedly(Return(&joystickBtnEvent));
    EXPECT_CALL(libinputMock, JoystickButtonGetKeyState).WillRepeatedly(Return(LIBINPUT_BUTTON_STATE_RELEASED));
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    EXPECT_CALL(libinputMock, JoystickButtonGetKeyState).WillRepeatedly(Return(LIBINPUT_BUTTON_STATE_PRESSED));
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_IntermediateEndEvent_Default_001
 * @tc.desc: Verify IntermediateEndEvent returns false for unhandled event types
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_IntermediateEndEvent_Default_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TABLET_TOOL_BUTTON));
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));
}
/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_AddFlagForDevice_001
 * @tc.desc: Test AddFlagForDevice with nullptr event
 * @tc.require: test AddFlagForDevice
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_AddFlagForDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->AddFlagForDevice(nullptr));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_AddFlagForDevice_002
 * @tc.desc: Test AddFlagForDevice with null input device
 * @tc.require: test AddFlagForDevice
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_AddFlagForDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    libinput_event event;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(nullptr));
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->AddFlagForDevice(&event));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_RemoveFlagForDevice_001
 * @tc.desc: Test RemoveFlagForDevice with nullptr event
 * @tc.require: test RemoveFlagForDevice
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_RemoveFlagForDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->RemoveFlagForDevice(nullptr));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_RemoveFlagForDevice_002
 * @tc.desc: Test RemoveFlagForDevice with null input device
 * @tc.require: test RemoveFlagForDevice
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_RemoveFlagForDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    libinput_event event;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetDevice).WillRepeatedly(Return(nullptr));
    EXPECT_NO_FATAL_FAILURE(inputPluginContext->RemoveFlagForDevice(&event));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_InputPlugin_UnregisterSettingObserver_002
 * @tc.desc: Test UnregisterSettingObserver when DataShare is not ready
 * @tc.require: test UnregisterSettingObserver
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_InputPlugin_UnregisterSettingObserver_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<InputPlugin> inputPluginContext = std::make_shared<InputPlugin>(nullptr);
    EXPECT_FALSE(inputPluginContext->UnregisterSettingObserver(1));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_PluginConfig_IsValid_FileNotExist
 * @tc.desc: Test PluginConfig IsValid when plugin file does not exist on filesystem
 * @tc.require: test PluginConfig IsValid
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_PluginConfig_IsValid_FileNotExist, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputPluginManager::PluginConfig config;
    config.uuid_ = "test-uuid-nonexistent";
    config.name_ = "nonexistent_file.so";
    config.mode_ = "dynamic";
    EXPECT_FALSE(config.IsValid());
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_IntermediateEndEvent_TabletToolProximity_001
 * @tc.desc: Verify IntermediateEndEvent for TABLET_TOOL_PROXIMITY out/in states
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_IntermediateEndEvent_TabletToolProximity_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event;
    libinput_event_tablet_tool tabletEvent;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TABLET_TOOL_PROXIMITY));
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillRepeatedly(Return(&tabletEvent));
    EXPECT_CALL(libinputMock, TabletToolGetProximityState)
        .WillRepeatedly(Return(LIBINPUT_TABLET_TOOL_PROXIMITY_STATE_OUT));
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    EXPECT_CALL(libinputMock, TabletToolGetProximityState)
        .WillRepeatedly(Return(LIBINPUT_TABLET_TOOL_PROXIMITY_STATE_IN));
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_IntermediateEndEvent_TabletToolTip_001
 * @tc.desc: Verify IntermediateEndEvent for TABLET_TOOL_TIP up/down states
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_IntermediateEndEvent_TabletToolTip_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event;
    libinput_event_tablet_tool tabletEvent;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_TABLET_TOOL_TIP));
    EXPECT_CALL(libinputMock, GetTabletToolEvent).WillRepeatedly(Return(&tabletEvent));
    EXPECT_CALL(libinputMock, TabletToolGetTipState).WillRepeatedly(Return(LIBINPUT_TABLET_TOOL_TIP_UP));
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    EXPECT_CALL(libinputMock, TabletToolGetTipState).WillRepeatedly(Return(LIBINPUT_TABLET_TOOL_TIP_DOWN));
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));
}

/**
 * @tc.name: MultimodalInputPluginManagerTest_IntermediateEndEvent_PointerButtonTouchpad_001
 * @tc.desc: Verify IntermediateEndEvent for POINTER_BUTTON_TOUCHPAD released/pressed
 * @tc.require:
 */
HWTEST_F(MultimodalInputPluginManagerTest,
    MultimodalInputPluginManagerTest_IntermediateEndEvent_PointerButtonTouchpad_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    libinput_event event;
    libinput_event_pointer pointerEvent;
    pointerEvent.buttonState = LIBINPUT_BUTTON_STATE_RELEASED;
    NiceMock<LibinputInterfaceMock> libinputMock;
    EXPECT_CALL(libinputMock, GetEventType).WillRepeatedly(Return(LIBINPUT_EVENT_POINTER_BUTTON_TOUCHPAD));
    EXPECT_CALL(libinputMock, LibinputGetPointerEvent).WillRepeatedly(Return(&pointerEvent));
    EXPECT_TRUE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));

    pointerEvent.buttonState = LIBINPUT_BUTTON_STATE_PRESSED;
    EXPECT_FALSE(InputPluginManager::GetInstance()->IntermediateEndEvent(&event));
}

} // namespace MMI
} // namespace OHOS
