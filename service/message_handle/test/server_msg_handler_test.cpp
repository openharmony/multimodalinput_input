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

#include <cstdio>
#include <cinttypes>

#include <gtest/gtest.h>
#include "display_event_monitor.h"
#include "input_event_handler.h"
#include "libinput.h"
#include "pixel_map.h"
#include "sec_comp_enhance_kit.h"

#include "authorize_helper.h"
#include "define_multimodal.h"
#include "event_log_helper.h"
#include "image_source.h"
#include "inject_notice_manager.h"
#include "input_device_manager.h"
#include "input_manager_impl.h"
#include "mmi_log.h"
#include "pointer_event.h"
#include "running_process_info.h"
#include "server_msg_handler.h"
#include "stream_buffer.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ServerMsgHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t UID_ROOT {0};
static constexpr char PROGRAM_NAME[] = "uds_sesion_test";
int32_t g_moduleType = 3;
int32_t g_pid = 0;
int32_t g_writeFd = -1;
constexpr int32_t NUM_LOCK_FUNCTION_KEY = 0;
constexpr int32_t CAPS_LOCK_FUNCTION_KEY = 1;
constexpr int32_t SCROLL_LOCK_FUNCTION_KEY = 2;
constexpr int32_t SECURITY_COMPONENT_SERVICE_ID = 3050;
constexpr int32_t MOUSE_ICON_SIZE = 64;
constexpr int32_t COMMON_PERMISSION_CHECK_ERROR {201};
constexpr int32_t ERR_DEVICE_NOT_EXIST {3900002};
constexpr int32_t ERR_NON_INPUT_APPLICATION {3900003};
constexpr int32_t CAST_INPUT_DEVICEID {0xAAAAAAFF};
constexpr float FACTOR_0 {1.0f};
constexpr float FACTOR_8 {0.7f};
constexpr float FACTOR_18 {1.0f};
constexpr float FACTOR_27 {1.2f};
constexpr float FACTOR_55 {1.6f};
constexpr float FACTOR_MAX {2.4f};
class RemoteObjectTest : public IRemoteObject {
public:
    explicit RemoteObjectTest(std::u16string descriptor) : IRemoteObject(descriptor) {}
    ~RemoteObjectTest() {}

    int32_t GetObjectRefCount()
    {
        return 0;
    }
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    {
        return 0;
    }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient)
    {
        return true;
    }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient)
    {
        return true;
    }
    int Dump(int fd, const std::vector<std::u16string> &args)
    {
        return 0;
    }
};
} // namespace

class ServerMsgHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDoen() {}
    std::unique_ptr<OHOS::Media::PixelMap> SetMouseIconTest(const std::string iconPath);
};

std::unique_ptr<OHOS::Media::PixelMap> ServerMsgHandlerTest::SetMouseIconTest(const std::string iconPath)
{
    CALL_DEBUG_ENTER;
    OHOS::Media::SourceOptions opts;
    opts.formatHint = "image/svg+xml";
    uint32_t ret = 0;
    auto imageSource = OHOS::Media::ImageSource::CreateImageSource(iconPath, opts, ret);
    CHKPP(imageSource);
    std::set<std::string> formats;
    ret = imageSource->GetSupportedFormats(formats);
    MMI_HILOGD("Get supported format ret:%{public}u", ret);
    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {.width = MOUSE_ICON_SIZE, .height = MOUSE_ICON_SIZE};
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, ret);
    CHKPL(pixelMap);
    return pixelMap;
}

/**
 * @tc.name: ServerMsgHandlerTest_SetPixelMapData
 * @tc.desc: Test SetPixelMapData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SetPixelMapData, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    int32_t infoId = -1;
    void *pixelMap = nullptr;
    int32_t result = servermsghandler.SetPixelMapData(infoId, pixelMap);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/**
 * @tc.name: ServerMsgHandlerTest_SetShieldStatus_01
 * @tc.desc: Test SetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SetShieldStatus_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    int32_t shieldMode = -1;
    bool isShield = false;
    int32_t result = servermsghandler.SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_SetShieldStatus_02
 * @tc.desc: Test SetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SetShieldStatus_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    int32_t shieldMode = 1;
    bool isShield = true;
    int32_t result = servermsghandler.SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_GetShieldStatus_01
 * @tc.desc: Test GetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_GetShieldStatus_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    int32_t shieldMode = -1;
    bool isShield = false;
    int32_t result = servermsghandler.GetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_GetShieldStatus_02
 * @tc.desc: Test GetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_GetShieldStatus_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    int32_t shieldMode = 1;
    bool isShield = true;
    int32_t result = servermsghandler.GetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectPointerEvent
 * @tc.desc: Test OnInjectPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectPointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t pid = 1;
    bool isNativeInject = true;
    int32_t result = servermsghandler.OnInjectPointerEvent(
        pointerEvent, pid, isNativeInject, false, PointerEvent::DISPLAY_COORDINATE);
    EXPECT_EQ(result, COMMON_PERMISSION_CHECK_ERROR);
}

/**
 * @tc.name: ServerMsgHandlerTest_FixTargetWindowId_01
 * @tc.desc: Test FixTargetWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_ACTION_HOVER_ENTER;
    bool result = servermsghandler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: ServerMsgHandlerTest_FixTargetWindowId_02
 * @tc.desc: Test FixTargetWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_ACTION_DOWN;
    bool result = servermsghandler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: ServerMsgHandlerTest_FixTargetWindowId_03
 * @tc.desc: Test FixTargetWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_ACTION_UNKNOWN;
    auto pointerIds = pointerEvent->GetPointerIds();
    EXPECT_TRUE(pointerIds.empty());
    bool result = servermsghandler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: ServerMsgHandlerTest_Init
 * @tc.desc: Test Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_Init, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    UDSServer udsServerFirst;
    ASSERT_NO_FATAL_FAILURE(servermsghandler.Init(udsServerFirst));
    UDSServer udsServerSecond;
    ASSERT_NO_FATAL_FAILURE(servermsghandler.Init(udsServerSecond));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAddInputHandlerWithNullSession
 * @tc.desc: Test OnAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAddInputHandlerWithNullSession, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = nullptr;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    EXPECT_EQ(
        servermsghandler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAddInputHandlerWithInterceptorHandler001
 * @tc.desc: Test OnAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAddInputHandlerWithInterceptorHandler001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    EXPECT_EQ(
        servermsghandler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAddInputHandlerWithMonitorHandler001
 * @tc.desc: Test OnAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAddInputHandlerWithMonitorHandler001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    EXPECT_EQ(
        servermsghandler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnRemoveInputHandlerWithNullSession
 * @tc.desc: Test OnRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnRemoveInputHandlerWithNullSession, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = nullptr;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    EXPECT_EQ(
        servermsghandler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnRemoveInputHandlerWithInterceptorHandler001
 * @tc.desc: Test OnRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnRemoveInputHandlerWithInterceptorHandler001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    EXPECT_EQ(
        servermsghandler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnRemoveInputHandlerWithMonitorHandler001
 * @tc.desc: Test OnRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnRemoveInputHandlerWithMonitorHandler001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    EXPECT_EQ(
        servermsghandler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnMarkConsumedWithNullSession
 * @tc.desc: Test OnMarkConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnMarkConsumedWithNullSession, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = nullptr;
    int32_t eventId = 11;
    EXPECT_EQ(servermsghandler.OnMarkConsumed(sess, eventId), ERROR_NULL_POINTER);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
/**
 * @tc.name: ServerMsgHandlerTest_OnSubscribeKeyEvent
 * @tc.desc: Test OnSubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnSubscribeKeyEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    UDSServer udsServer;
    int32_t pid = 0;
    int32_t subscribeId = 0;
    std::shared_ptr<KeyOption> option = std::make_shared<KeyOption>();
    option->SetPreKeys({1, 2, 3});
    EXPECT_EQ(servermsghandler.OnSubscribeKeyEvent(&udsServer, pid, subscribeId, option), ERROR_NULL_POINTER);
    EXPECT_EQ(servermsghandler.OnUnsubscribeKeyEvent(&udsServer, pid, subscribeId), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnSubscribeHotkey
 * @tc.desc: Test OnSubscribeHotkey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnSubscribeHotkey, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    UDSServer udsServer;
    int32_t pid = 0;
    int32_t subscribeId = 0;
    std::shared_ptr<KeyOption> option = std::make_shared<KeyOption>();
    option->SetPreKeys({1, 2, 3});
    EXPECT_EQ(servermsghandler.OnSubscribeHotkey(&udsServer, pid, subscribeId, option), ERROR_NULL_POINTER);
    EXPECT_EQ(servermsghandler.OnUnsubscribeHotkey(&udsServer, pid, subscribeId), ERROR_NULL_POINTER);
}
#endif

#ifdef OHOS_BUILD_ENABLE_SWITCH
/**
 * @tc.name: ServerMsgHandlerTest_OnSubscribeSwitchEvent
 * @tc.desc: Test OnSubscribeSwitchEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnSubscribeSwitchEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    UDSServer udsServer;
    int32_t pid = 0;
    int32_t subscribeId = 0;
    int32_t switchType = 0;
    EXPECT_EQ(servermsghandler.OnSubscribeSwitchEvent(&udsServer, pid, subscribeId, switchType), ERROR_NULL_POINTER);
    EXPECT_EQ(servermsghandler.OnUnsubscribeSwitchEvent(&udsServer, pid, subscribeId), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnQuerySwitchStatus
 * @tc.desc: Test OnQuerySwitchStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnQuerySwitchStatus, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    int32_t switchType = 0;
    int32_t state = 0;
    EXPECT_EQ(servermsghandler.OnQuerySwitchStatus(switchType, state), ERROR_NULL_POINTER);
}
#endif

/**
 * @tc.name: ServerMsgHandlerTest_OnSubscribeLongPressEvent
 * @tc.desc: Test OnSubscribeLongPressEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnSubscribeLongPressEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    UDSServer udsServer;
    int32_t pid = 1;
    int32_t subscribeId = 1;
    LongPressRequest longPressRequest;
    EXPECT_EQ(servermsghandler.OnSubscribeLongPressEvent(&udsServer, pid, subscribeId, longPressRequest),
        ERROR_NULL_POINTER);
    EXPECT_EQ(servermsghandler.OnUnsubscribeLongPressEvent(&udsServer, pid, subscribeId), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnMarkConsumedWithMonitorHandler001
 * @tc.desc: Test OnMarkConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnMarkConsumedWithMonitorHandler001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    int32_t eventId = 11;
    EXPECT_EQ(servermsghandler.OnMarkConsumed(sess, eventId), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAddInputHandlerWithInterceptorHandler002
 * @tc.desc: Test OnAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAddInputHandlerWithInterceptorHandler002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    InputHandler->BuildInputHandlerChain();
    EXPECT_EQ(
        servermsghandler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAddInputHandlerWithMonitorHandler002
 * @tc.desc: Test OnAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAddInputHandlerWithMonitorHandler002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    EXPECT_EQ(
        servermsghandler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnRemoveInputHandlerWithInterceptorHandler002
 * @tc.desc: Test OnRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnRemoveInputHandlerWithInterceptorHandler002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    EXPECT_EQ(
        servermsghandler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnRemoveInputHandlerWithMonitorHandler002
 * @tc.desc: Test OnRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnRemoveInputHandlerWithMonitorHandler002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    EXPECT_EQ(
        servermsghandler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnMarkConsumedWithMonitorHandler002
 * @tc.desc: Test OnMarkConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnMarkConsumedWithMonitorHandler002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    int32_t eventId = 11;
    EXPECT_EQ(servermsghandler.OnMarkConsumed(sess, eventId), ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnGetFunctionKeyState_001
 * @tc.desc: Test the function OnGetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnGetFunctionKeyState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t funcKey = NUM_LOCK_FUNCTION_KEY;
    bool state = false;
    int32_t ret = handler.OnGetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, ERR_DEVICE_NOT_EXIST);
    funcKey = CAPS_LOCK_FUNCTION_KEY;
    ret = handler.OnGetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, ERR_DEVICE_NOT_EXIST);
    funcKey = SCROLL_LOCK_FUNCTION_KEY;
    ret = handler.OnGetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, ERR_DEVICE_NOT_EXIST);
    funcKey = 10;
    state = true;
    ret = handler.OnGetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, ERR_DEVICE_NOT_EXIST);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectPointerEventExt_001
 * @tc.desc: Test the function OnInjectPointerEventExt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectPointerEventExt_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    int32_t ret = handler.OnInjectPointerEventExt(pointerEvent, false, PointerEvent::DISPLAY_COORDINATE);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    int32_t sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    ret = handler.OnInjectPointerEventExt(pointerEvent, false, PointerEvent::DISPLAY_COORDINATE);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    EXPECT_NO_FATAL_FAILURE(handler.OnInjectPointerEventExt(pointerEvent, false, PointerEvent::DISPLAY_COORDINATE));
    sourceType = PointerEvent::SOURCE_TYPE_JOYSTICK;
    EXPECT_NO_FATAL_FAILURE(handler.OnInjectPointerEventExt(pointerEvent, false, PointerEvent::DISPLAY_COORDINATE));
    sourceType = PointerEvent::SOURCE_TYPE_TOUCHPAD;
    EXPECT_NO_FATAL_FAILURE(handler.OnInjectPointerEventExt(pointerEvent, false, PointerEvent::DISPLAY_COORDINATE));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnEnhanceConfig_001
 * @tc.desc: Test the function OnEnhanceConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnEnhanceConfig_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = nullptr;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    int32_t ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    int32_t uid = 1;
    ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    uid = SECURITY_COMPONENT_SERVICE_ID;
    CircleStreamBuffer::ErrorStatus rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    EXPECT_NO_FATAL_FAILURE(handler.OnEnhanceConfig(sess, pkt));
}

/**
 * @tc.name: ServerMsgHandlerTest_AccelerateMotion_001
 * @tc.desc: Test the function AccelerateMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_AccelerateMotion_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    int32_t ret = handler.AccelerateMotion(pointerEvent);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_AccelerateMotion_002
 * @tc.desc: Test the function AccelerateMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_AccelerateMotion_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    int32_t ret = handler.AccelerateMotion(pointerEvent);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_AccelerateMotion_003
 * @tc.desc: Test the function AccelerateMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_AccelerateMotion_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    int32_t ret = handler.AccelerateMotion(pointerEvent);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_AccelerateMotion_004
 * @tc.desc: Test the function AccelerateMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_AccelerateMotion_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    int32_t ret = handler.AccelerateMotion(pointerEvent);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_AccelerateMotion_005
 * @tc.desc: Test the function AccelerateMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_AccelerateMotion_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    int32_t ret = handler.AccelerateMotion(pointerEvent);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_UpdatePointerEvent_001
 * @tc.desc: Test the function UpdatePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_UpdatePointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    ASSERT_NO_FATAL_FAILURE(handler.UpdatePointerEvent(pointerEvent));
}

/**
 * @tc.name: ServerMsgHandlerTest_UpdatePointerEvent_002
 * @tc.desc: Test the function UpdatePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_UpdatePointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    ASSERT_NO_FATAL_FAILURE(handler.UpdatePointerEvent(pointerEvent));
}

/**
 * @tc.name: ServerMsgHandlerTest_UpdatePointerEvent_003
 * @tc.desc: Test the function UpdatePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_UpdatePointerEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    ASSERT_NO_FATAL_FAILURE(handler.UpdatePointerEvent(pointerEvent));
}

/**
 * @tc.name: ServerMsgHandlerTest_SaveTargetWindowId_001
 * @tc.desc: Test the function SaveTargetWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SaveTargetWindowId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    int32_t ret = handler.SaveTargetWindowId(pointerEvent, false);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_SaveTargetWindowId_002
 * @tc.desc: Test the function SaveTargetWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SaveTargetWindowId_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    int32_t ret = handler.SaveTargetWindowId(pointerEvent, false);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_SaveTargetWindowId_003
 * @tc.desc: Test the function SaveTargetWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SaveTargetWindowId_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_MOVE);
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    int32_t ret = handler.SaveTargetWindowId(pointerEvent, false);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_SaveTargetWindowId_004
 * @tc.desc: Test the function SaveTargetWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SaveTargetWindowId_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t ret = handler.SaveTargetWindowId(pointerEvent, false);
    EXPECT_EQ(ret, RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_SaveTargetWindowId_005
@tc.desc: Test the function SaveTargetWindowId
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SaveTargetWindowId_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_ENTER);
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    int32_t ret = handler.SaveTargetWindowId(pointerEvent, false);
    EXPECT_EQ(ret, RET_OK);
    ret = handler.SaveTargetWindowId(pointerEvent, true);
    EXPECT_EQ(ret, RET_OK);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ret = handler.SaveTargetWindowId(pointerEvent, true);
    EXPECT_EQ(ret, RET_OK);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ret = handler.SaveTargetWindowId(pointerEvent, true);
    EXPECT_EQ(ret, RET_OK);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_ENTER);
    ret = handler.SaveTargetWindowId(pointerEvent, true);
    EXPECT_EQ(ret, RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_SaveTargetWindowId_006
@tc.desc: Test the function SaveTargetWindowId
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SaveTargetWindowId_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_ENTER);
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetDeviceId(0xAAAAAAFF);
    pointerEvent->SetZOrder(1);
    int32_t ret = handler.SaveTargetWindowId(pointerEvent, false);
    EXPECT_EQ(ret, RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_SaveTargetWindowId_007
@tc.desc: Test the function SaveTargetWindowId
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SaveTargetWindowId_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_ENTER);
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetDeviceId(0xAAAAAAFF);
    pointerEvent->SetZOrder(-1);
    int32_t ret = handler.SaveTargetWindowId(pointerEvent, false);
    EXPECT_EQ(ret, RET_OK);
    pointerEvent->SetDeviceId(0);
    pointerEvent->SetZOrder(1);
    ret = handler.SaveTargetWindowId(pointerEvent, false);
    EXPECT_EQ(ret, RET_OK);
    pointerEvent->SetDeviceId(0);
    pointerEvent->SetZOrder(-1);
    ret = handler.SaveTargetWindowId(pointerEvent, false);
    EXPECT_EQ(ret, RET_OK);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    ret = handler.SaveTargetWindowId(pointerEvent, false);
    EXPECT_EQ(ret, RET_OK);
    pointerEvent->ClearFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    ret = handler.SaveTargetWindowId(pointerEvent, false);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_FixTargetWindowId_001
 * @tc.desc: Test FixTargetWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_ACTION_UNKNOWN;
    pointerEvent->SetPointerId(1);
    bool result = handler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: ServerMsgHandlerTest_FixTargetWindowId_002
 * @tc.desc: Test FixTargetWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_ACTION_HOVER_ENTER;
    bool result = handler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: ServerMsgHandlerTest_FixTargetWindowId_003
 * @tc.desc: Test FixTargetWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_ACTION_HOVER_MOVE;
    pointerEvent->SetPointerId(1);
    std::vector<int32_t> pointerIds {pointerEvent->GetPointerIds()};
    bool result = handler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: ServerMsgHandlerTest_FixTargetWindowId_004
 * @tc.desc: Test FixTargetWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_ACTION_HOVER_MOVE;
    pointerEvent->SetPointerId(1);
    std::vector<int32_t> pointerIds {pointerEvent->GetPointerIds()};
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    bool result = handler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_TRUE(result);
}

/**
 * @tc.name: ServerMsgHandlerTest_FixTargetWindowId_005
 * @tc.desc: Test FixTargetWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_ACTION_HOVER_MOVE;
    pointerEvent->SetPointerId(1);
    std::vector<int32_t> pointerIds {pointerEvent->GetPointerIds()};
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    bool result = handler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_FALSE(result);
}

/**
@tc.name: ServerMsgHandlerTest_FixTargetWindowId_006
@tc.desc: Test FixTargetWindowId
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.shellTargetWindowIds_.clear();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_ACTION_HOVER_MOVE;
    pointerEvent->SetPointerId(1);
    std::vector<int32_t> pointerIds {pointerEvent->GetPointerIds()};
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    bool result = handler.FixTargetWindowId(pointerEvent, action, true);
    ASSERT_FALSE(result);
    handler.shellTargetWindowIds_[0] = 0;
    result = handler.FixTargetWindowId(pointerEvent, action, true);
    ASSERT_FALSE(result);
    handler.shellTargetWindowIds_[0] = 1;
    result = handler.FixTargetWindowId(pointerEvent, action, true);
    ASSERT_FALSE(result);
    pointerEvent->pointers_.clear();
    action = PointerEvent::POINTER_ACTION_HOVER_MOVE;
    result = handler.FixTargetWindowId(pointerEvent, action, true);
    ASSERT_FALSE(result);
}

/**
@tc.name: ServerMsgHandlerTest_FixTargetWindowId_007
@tc.desc: Test FixTargetWindowId
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.shellTargetWindowIds_.clear();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_ACTION_DOWN;
    int32_t pointerId = -1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(-1);
    handler.shellTargetWindowIds_[0] = -1;
    int32_t result = handler.FixTargetWindowId(pointerEvent, action, true);
    ASSERT_TRUE(result);
}

/**
@tc.name: ServerMsgHandlerTest_OnUiExtentionWindowInfo_001
@tc.desc: Test the function OnUiExtentionWindowInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnUiExtentionWindowInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    NetPacket pkt(MmiMessageId::ADD_INPUT_DEVICE_LISTENER);
    WindowInfo info;
    pkt << 2;
    pkt << 1 << 1 << 1 << 1 << 1 << 1 << 1 << 1 << 1 << 1 << 1 << 1 << 1 << 1 << 1 << 1 << 1 << 1;
    int32_t ret = handler.OnUiExtentionWindowInfo(pkt, info);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnRemoveInputHandler_001
 * @tc.desc: Test the function OnRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnRemoveInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = nullptr;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 2;
    uint32_t deviceTags = 3;
    int32_t ret = handler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ret = handler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    handlerType = InputHandlerType::MONITOR;
    ret = handler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    handlerType = InputHandlerType::NONE;
    ret = handler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAddInputHandler_001
 * @tc.desc: Test the function OnAddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAddInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = nullptr;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 2;
    uint32_t deviceTags = 3;
    int32_t ret = handler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ret = handler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    handlerType = InputHandlerType::MONITOR;
    ret = handler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    handlerType = InputHandlerType::NONE;
    ret = handler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnMoveMouse_001
 * @tc.desc: Test the function OnMoveMouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnMoveMouse_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t offsetX = 10;
    int32_t offsetY = 20;
    std::shared_ptr<PointerEvent> pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(pointerEvent_, nullptr);
    int32_t ret = handler.OnMoveMouse(offsetX, offsetY);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnCancelInjection_001
 * @tc.desc: Test the function OnCancelInjection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnCancelInjection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.authorizationCollection_.insert(std::make_pair(12, AuthorizationStatus::AUTHORIZED));
    handler.CurrentPID_ = 12;
    int32_t ret = handler.OnCancelInjection();
    EXPECT_EQ(ret, ERR_OK);
    handler.CurrentPID_ = 1;
    ret = handler.OnCancelInjection();
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_SetWindowInfo_001
 * @tc.desc: Test the function SetWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SetWindowInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t infoId = 1;
    WindowInfo info;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    handler.transparentWins_.insert(std::make_pair(1, SetMouseIconTest(iconPath)));
    EXPECT_NO_FATAL_FAILURE(handler.SetWindowInfo(infoId, info));
    infoId = 2;
    EXPECT_NO_FATAL_FAILURE(handler.SetWindowInfo(infoId, info));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnEnhanceConfig_002
 * @tc.desc: Test the function OnEnhanceConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnEnhanceConfig_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = nullptr;
    MmiMessageId idMsg = MmiMessageId::ADD_INPUT_DEVICE_LISTENER;
    NetPacket pkt(idMsg);
    int32_t ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    int32_t uid = 123;
    ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    uid = SECURITY_COMPONENT_SERVICE_ID;
    CircleStreamBuffer::ErrorStatus rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    EXPECT_NO_FATAL_FAILURE(handler.OnEnhanceConfig(sess, pkt));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnEnhanceConfig_003
 * @tc.desc: Test the function OnEnhanceConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnEnhanceConfig_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    MmiMessageId idMsg = MmiMessageId::ADD_INPUT_DEVICE_LISTENER;
    NetPacket pkt(idMsg);
    SessionPtr sess =
        std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, SECURITY_COMPONENT_SERVICE_ID - 1, g_pid);
    int32_t ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, SECURITY_COMPONENT_SERVICE_ID, g_pid);
    CircleStreamBuffer::ErrorStatus rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    EXPECT_NO_FATAL_FAILURE(handler.OnEnhanceConfig(sess, pkt));
}

/**
@tc.name: ServerMsgHandlerTest_OnEnhanceConfig_004
@tc.desc: Test the function OnEnhanceConfig
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnEnhanceConfig_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    MmiMessageId idMsg = MmiMessageId::ADD_INPUT_DEVICE_LISTENER;
    NetPacket pkt(idMsg);
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    pkt << 1 << 1;
    SessionPtr sess =
        std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, SECURITY_COMPONENT_SERVICE_ID, g_pid);
    int32_t ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnMsgHandler
 * @tc.desc: Test if (callback == nullptr) branch success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnMsgHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    EXPECT_NO_FATAL_FAILURE(msgHandler.OnMsgHandler(sess, pkt));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectPointerEventExt
 * @tc.desc: Test OnInjectPointerEventExt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectPointerEventExt, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    InputHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    pointerEvent->SetId(1);
    pointerEvent->eventType_ = 1;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    msgHandler.nativeTargetWindowIds_.insert(std::make_pair(pointerEvent->GetPointerId(), 10));
    EXPECT_NE(msgHandler.OnInjectPointerEventExt(pointerEvent, false, PointerEvent::DISPLAY_COORDINATE), RET_ERR);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT;
    EXPECT_NE(msgHandler.OnInjectPointerEventExt(pointerEvent, false, PointerEvent::DISPLAY_COORDINATE), RET_ERR);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NONE);
    EXPECT_NE(msgHandler.OnInjectPointerEventExt(pointerEvent, false, PointerEvent::DISPLAY_COORDINATE), RET_OK);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_HIDE_POINTER;
    EXPECT_NE(msgHandler.OnInjectPointerEventExt(pointerEvent, false, PointerEvent::DISPLAY_COORDINATE), RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectKeyEvent_001
 * @tc.desc: Test if (iter->second == AuthorizationStatus::UNAUTHORIZED) branch success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t pid = 15;
    bool isNativeInject = true;
    keyEvent->SetId(1);
    keyEvent->eventType_ = 1;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    msgHandler.authorizationCollection_.insert(std::make_pair(pid, AuthorizationStatus::UNAUTHORIZED));
    EXPECT_EQ(msgHandler.OnInjectKeyEvent(keyEvent, pid, isNativeInject), COMMON_PERMISSION_CHECK_ERROR);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectKeyEvent_002
 * @tc.desc: Test if (iter->second == AuthorizationStatus::UNAUTHORIZED) branch failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t pid = 15;
    bool isNativeInject = true;
    keyEvent->SetId(1);
    keyEvent->eventType_ = 1;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    msgHandler.authorizationCollection_.insert(std::make_pair(pid, AuthorizationStatus::UNKNOWN));
    InputHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    EXPECT_NE(msgHandler.OnInjectKeyEvent(keyEvent, pid, isNativeInject), RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectKeyEvent_003
 * @tc.desc: Test if (isNativeInject) branch failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectKeyEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t pid = 15;
    bool isNativeInject = false;
    keyEvent->SetId(1);
    keyEvent->eventType_ = 1;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    InputHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    EXPECT_NE(msgHandler.OnInjectKeyEvent(keyEvent, pid, isNativeInject), RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_OnInjectKeyEvent_004
@tc.desc: Test OnInjectKeyEvent
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectKeyEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t pid = 15;
    bool isNativeInject = false;
    keyEvent->SetId(1);
    keyEvent->eventType_ = 1;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_TOUCHPAD_POINTER);
    InputHandler->BuildInputHandlerChain();
    EventLogHelper::userType_ = "beta";
    EXPECT_NE(msgHandler.OnInjectKeyEvent(keyEvent, pid, isNativeInject), RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_OnInjectKeyEvent_005
@tc.desc: Test OnInjectKeyEvent
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectKeyEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t pid = 15;
    bool isNativeInject = false;
    keyEvent->SetId(1);
    keyEvent->eventType_ = 1;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
    InputHandler->BuildInputHandlerChain();
    EventLogHelper::userType_ = "beta";
    EXPECT_NE(msgHandler.OnInjectKeyEvent(keyEvent, pid, isNativeInject), RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_OnInjectKeyEvent_006
@tc.desc: Test OnInjectKeyEvent
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectKeyEvent_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t pid = 15;
    bool isNativeInject = false;
    keyEvent->SetId(1);
    keyEvent->eventType_ = 1;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE);
    InputHandler->BuildInputHandlerChain();
    EventLogHelper::userType_ = "default";
    EXPECT_NE(msgHandler.OnInjectKeyEvent(keyEvent, pid, isNativeInject), RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_OnInjectKeyEvent_007
@tc.desc: Test OnInjectKeyEvent
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectKeyEvent_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t pid = 15;
    bool isNativeInject = false;
    keyEvent->SetId(1);
    keyEvent->eventType_ = 1;
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddFlag(InputEvent::EVENT_FLAG_TOUCHPAD_POINTER);
    InputHandler->BuildInputHandlerChain();
    EventLogHelper::userType_ = "default";
    EXPECT_NE(msgHandler.OnInjectKeyEvent(keyEvent, pid, isNativeInject), RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectPointerEvent_002
 * @tc.desc: Test if (iter->second == AuthorizationStatus::UNAUTHORIZED) branch success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectPointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t pid = 15;
    bool isNativeInject = true;
    pointerEvent->SetId(1);
    pointerEvent->eventType_ = 1;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    msgHandler.authorizationCollection_.insert(std::make_pair(pid, AuthorizationStatus::UNAUTHORIZED));
    EXPECT_EQ(
        msgHandler.OnInjectPointerEvent(pointerEvent, pid, isNativeInject, false, PointerEvent::DISPLAY_COORDINATE),
        COMMON_PERMISSION_CHECK_ERROR);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectPointerEvent_003
 * @tc.desc: Test if (iter->second == AuthorizationStatus::UNAUTHORIZED) branch failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectPointerEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t pid = 15;
    bool isNativeInject = true;
    pointerEvent->SetId(1);
    pointerEvent->eventType_ = 1;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    msgHandler.authorizationCollection_.insert(std::make_pair(pid, AuthorizationStatus::UNKNOWN));
    InputHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    EXPECT_NE(
        msgHandler.OnInjectPointerEvent(pointerEvent, pid, isNativeInject, false, PointerEvent::DISPLAY_COORDINATE),
        RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectPointerEvent_004
 * @tc.desc: Test if (isNativeInject) branch failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectPointerEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t pid = 15;
    bool isNativeInject = false;
    pointerEvent->SetId(1);
    pointerEvent->eventType_ = 1;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    InputHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    EXPECT_NE(
        msgHandler.OnInjectPointerEvent(pointerEvent, pid, isNativeInject, false, PointerEvent::DISPLAY_COORDINATE),
        RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnWindowGroupInfo_001
 * @tc.desc: Test the function OnWindowGroupInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnWindowGroupInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = nullptr;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    int32_t ret = handler.OnWindowGroupInfo(sess, pkt);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    CircleStreamBuffer::ErrorStatus rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    ret = handler.OnWindowGroupInfo(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    ret = handler.OnWindowGroupInfo(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_OnWindowGroupInfo_002
@tc.desc: Test the function OnWindowGroupInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnWindowGroupInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    sess->SetTokenType(TOKEN_NATIVE);
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    int32_t ret = handler.OnWindowGroupInfo(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    sess->SetTokenType(TOKEN_SHELL);
    ret = handler.OnWindowGroupInfo(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    sess->SetTokenType(TOKEN_SYSTEM_HAP);
    ret = handler.OnWindowGroupInfo(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_OnWindowGroupInfo_003
@tc.desc: Test the function OnWindowGroupInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnWindowGroupInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    sess->SetTokenType(TOKEN_NATIVE);
    MmiMessageId idMsg = MmiMessageId::DISPLAY_INFO;
    NetPacket pkt(idMsg);
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    pkt << 1 << 1 << 2;
    int32_t ret = handler.OnWindowGroupInfo(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_OnWindowGroupInfo_004
@tc.desc: Test the function OnWindowGroupInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnWindowGroupInfo_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    sess->SetTokenType(TOKEN_NATIVE);
    MmiMessageId idMsg = MmiMessageId::DISPLAY_INFO;
    NetPacket pkt(idMsg);
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    pkt << 1 << 1 << 2;

    Rect rec = {1, 1, 1, 1};
    std::vector recVec = {rec, rec};
    std::vector<int32_t> pChangeAreas = {1, 1, 1};
    std::vector transform = {1.0, 1.0, 1.0};
    pkt << 1 << 1 << 1 << rec << recVec << recVec << 1 << 1 << WINDOW_UPDATE_ACTION::ADD << 1 << 1.0 << pChangeAreas
        << transform << 1 << 1 << 1 << false;
    int32_t ret = handler.OnWindowGroupInfo(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_RegisterWindowStateErrorCallback_001
@tc.desc: Test the function RegisterWindowStateErrorCallback
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_RegisterWindowStateErrorCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    MmiMessageId idMsg = MmiMessageId::ADD_INPUT_DEVICE_LISTENER;
    NetPacket pkt(idMsg);
    SessionPtr sess = nullptr;
    int32_t ret = handler.RegisterWindowStateErrorCallback(sess, pkt);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ret = handler.RegisterWindowStateErrorCallback(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    sess->SetTokenType(TOKEN_HAP);
    ret = handler.RegisterWindowStateErrorCallback(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    sess->SetTokenType(TOKEN_NATIVE);
    ret = handler.RegisterWindowStateErrorCallback(sess, pkt);
    EXPECT_EQ(ret, RET_OK);
    sess->SetTokenType(TOKEN_SHELL);
    ret = handler.RegisterWindowStateErrorCallback(sess, pkt);
    EXPECT_EQ(ret, RET_OK);
    sess->SetTokenType(TOKEN_SYSTEM_HAP);
    ret = handler.RegisterWindowStateErrorCallback(sess, pkt);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_SetPixelMapData_001
 * @tc.desc: Test the function SetPixelMapData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SetPixelMapData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t infoId = -5;
    void *pixelMap = nullptr;
    int32_t result = handler.SetPixelMapData(infoId, pixelMap);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    infoId = 2;
    result = handler.SetPixelMapData(infoId, pixelMap);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/**
 * @tc.name: ServerMsgHandlerTest_InitInjectNoticeSource_001
 * @tc.desc: Test the function InitInjectNoticeSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_InitInjectNoticeSource_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    InjectNoticeManager manager;
    handler.injectNotice_ = nullptr;
    bool ret = handler.InitInjectNoticeSource();
    EXPECT_FALSE(ret);
    handler.injectNotice_ = std::make_shared<InjectNoticeManager>();
    manager.isStartSrv_ = false;
    ret = handler.InitInjectNoticeSource();
    EXPECT_FALSE(ret);
    manager.isStartSrv_ = true;
    ret = handler.InitInjectNoticeSource();
    EXPECT_FALSE(ret);
    manager.connectionCallback_ = new (std::nothrow) InjectNoticeManager::InjectNoticeConnection;
    ASSERT_NE(manager.connectionCallback_, nullptr);
    manager.connectionCallback_->isConnected_ = false;
    ret = handler.InitInjectNoticeSource();
    EXPECT_FALSE(ret);
    manager.connectionCallback_->isConnected_ = true;
    ret = handler.InitInjectNoticeSource();
    EXPECT_FALSE(ret);
    delete(manager.connectionCallback_);
    manager.connectionCallback_ = nullptr;
}

/**
 * @tc.name: ServerMsgHandlerTest_CalculateOffset
 * @tc.desc: Test the function CalculateOffset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_CalculateOffset, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    Direction direction = DIRECTION90;
    Offset offset;
    offset.dx = 100;
    offset.dy = 100;
    EXPECT_NO_FATAL_FAILURE(handler.CalculateOffset(direction, offset));
    direction = DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(handler.CalculateOffset(direction, offset));
    direction = DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(handler.CalculateOffset(direction, offset));
    direction = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(handler.CalculateOffset(direction, offset));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnDisplayInfo
 * @tc.desc: Test the function OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t num = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    OLD::DisplayGroupInfo displayGroupInfo {
        .focusWindowId = 10,
        .currentUserId = 20,
    };
    pkt << displayGroupInfo.focusWindowId << displayGroupInfo.currentUserId << num;
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_WRITE;
    EXPECT_EQ(handler.OnDisplayInfo(sess, pkt), RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnDisplayInfo_01
 * @tc.desc: Test the function OnDisplayInfo_01
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    DisplayGroupInfo group;
    group.id = 1;
    group.name = "MainGroup";
    group.type = GroupType::GROUP_DEFAULT;
    group.mainDisplayId = 2;
    group.focusWindowId = 123;
    group.windowsInfo.push_back(WindowInfo());
    group.displaysInfo.push_back(DisplayInfo());
    DisplayInfo display;
    display.width = 1920;
    display.height = 1080;
    group.displaysInfo.push_back(display);
    WindowInfo window;
    window.groupId = 0;
    window.id = 123;
    group.windowsInfo.push_back(window);
    userScreenInfo.displayGroups.push_back(group);
    userScreenInfo.screens.push_back(ScreenInfo());

    ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    int32_t result = InputMgrImpl.PackDisplayData(pkt, userScreenInfo);
    EXPECT_EQ(result, 0);
    int32_t msgId;
    pkt >> msgId;
    EXPECT_NO_FATAL_FAILURE(handler.OnDisplayInfo(sess, pkt));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnDisplayInfo_02
 * @tc.desc: Test the function OnDisplayInfo_02
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    DisplayGroupInfo group;
    group.id = 1;
    group.name = "MainGroup";
    group.type = GroupType::GROUP_DEFAULT;
    group.mainDisplayId = 2;
    group.focusWindowId = 123;
    group.windowsInfo.push_back(WindowInfo());
    for (int32_t i = 0; i <= 1000; i++) {
        group.displaysInfo.push_back(DisplayInfo());
    }
    DisplayInfo display;
    display.width = 1920;
    display.height = 1080;
    group.displaysInfo.push_back(display);
    WindowInfo window;
    window.groupId = 0;
    window.id = 123;
    group.windowsInfo.push_back(window);
    userScreenInfo.screens.push_back(ScreenInfo());
    ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    int32_t result = InputMgrImpl.PackDisplayData(pkt, userScreenInfo);
    EXPECT_EQ(result, 0);
    int32_t msgId;
    pkt >> msgId;
    EXPECT_NO_FATAL_FAILURE(handler.OnDisplayInfo(sess, pkt));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnDisplayInfo_03
 * @tc.desc: Test the function OnDisplayInfo_03
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    DisplayGroupInfo group;
    group.id = 1;
    group.name = "MainGroup";
    group.type = GroupType::GROUP_DEFAULT;
    group.mainDisplayId = 2;
    group.focusWindowId = 123;
    group.windowsInfo.push_back(WindowInfo());
    group.displaysInfo.push_back(DisplayInfo());
    DisplayInfo display;
    display.width = 1920;
    display.height = 1080;
    group.displaysInfo.push_back(display);
    WindowInfo window;
    window.groupId = 0;
    window.id = 123;
    for (int32_t i = 0; i <= 1000; i++) {
        group.windowsInfo.push_back(window);
    }
    userScreenInfo.screens.push_back(ScreenInfo());
    ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    int32_t result = InputMgrImpl.PackDisplayData(pkt, userScreenInfo);
    EXPECT_EQ(result, 0);
    int32_t msgId;
    pkt >> msgId;
    EXPECT_NO_FATAL_FAILURE(handler.OnDisplayInfo(sess, pkt));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnTransferBinderClientSrv_001
 * @tc.desc: Test OnTransferBinderClientSrv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnTransferBinderClientSrv_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    sptr<RemoteObjectTest> binderClientObject = new RemoteObjectTest(u"test");
    int32_t pid = 12345;
    EXPECT_EQ(RET_OK, handler.OnTransferBinderClientSrv(binderClientObject, pid));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnTransferBinderClientSrv_002
 * @tc.desc: Test OnTransferBinderClientSrv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnTransferBinderClientSrv_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    sptr<IRemoteObject> binderClientObject = nullptr;
    int32_t pid = 12345;
    EXPECT_EQ(RET_ERR, handler.OnTransferBinderClientSrv(binderClientObject, pid));
}

/**
 * @tc.name: ServerMsgHandlerTest_CloseInjectNotice_001
 * @tc.desc: Test CloseInjectNotice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_CloseInjectNotice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.InitInjectNoticeSource();
    int32_t pid = 12345;
    bool result = handler.CloseInjectNotice(pid);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: ServerMsgHandlerTest_InitInjectNoticeSource_002
 * @tc.desc: Test the function InitInjectNoticeSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_InitInjectNoticeSource_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    InjectNoticeManager manager;
    handler.injectNotice_ = nullptr;
    bool ret = handler.InitInjectNoticeSource();
    handler.injectNotice_->isStartSrv_ = true;
    manager.connectionCallback_ = new (std::nothrow) InjectNoticeManager::InjectNoticeConnection;
    EXPECT_NE(nullptr, manager.connectionCallback_);
    auto connection = handler.injectNotice_->GetConnection();
    connection->isConnected_ = false;
    ret = handler.InitInjectNoticeSource();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ServerMsgHandlerTest_InitInjectNoticeSource_003
 * @tc.desc: Test the function InitInjectNoticeSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_InitInjectNoticeSource_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    InjectNoticeManager manager;
    handler.injectNotice_ = nullptr;
    bool ret = handler.InitInjectNoticeSource();
    handler.injectNotice_->isStartSrv_ = true;
    manager.connectionCallback_ = new (std::nothrow) InjectNoticeManager::InjectNoticeConnection;
    EXPECT_NE(nullptr, manager.connectionCallback_);
    auto connection = handler.injectNotice_->GetConnection();
    connection->isConnected_ = true;
    ret = handler.InitInjectNoticeSource();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ServerMsgHandlerTest_AddInjectNotice_001
 * @tc.desc: Test the function AddInjectNotice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_AddInjectNotice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    InjectNoticeManager manager;
    InjectNoticeInfo noticeInfo;
    handler.injectNotice_ = nullptr;
    bool ret = handler.InitInjectNoticeSource();
    handler.injectNotice_->isStartSrv_ = true;
    manager.connectionCallback_ = new (std::nothrow) InjectNoticeManager::InjectNoticeConnection;
    EXPECT_NE(nullptr, manager.connectionCallback_);
    auto connection = handler.injectNotice_->GetConnection();
    connection->isConnected_ = false;
    ret = handler.AddInjectNotice(noticeInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnCancelInjection_002
 * @tc.desc: Test the function OnCancelInjection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnCancelInjection_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_UNAUTHORIZE;
    int32_t ret = handler.OnCancelInjection();
    EXPECT_FALSE(ret != ERR_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAuthorize_002
 * @tc.desc: Test the function OnAuthorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAuthorize_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_UNAUTHORIZE;
    int32_t result = handler.OnAuthorize(false);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_QueryAuthorizedStatus
 * @tc.desc: Test the function QueryAuthorizedStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_QueryAuthorizedStatus, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_UNAUTHORIZE;
    int32_t callingPid = 1;
    int32_t status = 1;
    int32_t result = handler.QueryAuthorizedStatus(callingPid, status);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_GetRequestInjectionCallbackReqId
 * @tc.desc: Test the function GetRequestInjectionCallbackReqId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_GetRequestInjectionCallbackReqId, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_UNAUTHORIZE;
    int32_t result = handler.GetRequestInjectionCallbackReqId();
    EXPECT_EQ(result, 1);
}

/**
 * @tc.name: ServerMsgHandlerTest_CheckForRequestInjectionFrequentAccess
 * @tc.desc: Test the function CheckForRequestInjectionFrequentAccess
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_CheckForRequestInjectionFrequentAccess, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_UNAUTHORIZE;
    int32_t callingPid = 1;
    int64_t interval = 1;
    int32_t result = handler.CheckForRequestInjectionFrequentAccess(callingPid, interval);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_RequestInjection_001
 * @tc.desc: Test the function RequestInjection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_RequestInjection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t callingPid = 100000;
    int32_t status = 0;
    int32_t reqId = 0;
    auto isPC = handler.IsPC();
    int32_t result = ERR_OK;
    if (!isPC) {
        result = handler.RequestInjection(callingPid, status, reqId);
        EXPECT_EQ(result, ERROR_DEVICE_NOT_SUPPORTED);
        return;
    }
    handler.OnCancelInjection(callingPid);
    result = handler.OnAuthorize(false);
    EXPECT_EQ(result, ERR_OK);
    result = handler.RequestInjection(callingPid, status, reqId);
    EXPECT_EQ(result, ERR_OK);
    result = handler.OnAuthorize(true);
    EXPECT_EQ(result, ERR_OK);
    result = handler.OnAuthorize(false);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnMoveMouse_002
 * @tc.desc: Test the function OnMoveMouse
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnMoveMouse_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t offsetX = 0;
    int32_t offsetY = 0;
    std::shared_ptr<PointerEvent> pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(pointerEvent_, nullptr);
    int32_t ret = handler.OnMoveMouse(offsetX, offsetY);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAuthorize_004
 * @tc.desc: Test the function OnAuthorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAuthorize_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.CurrentPID_ = 12345;
    handler.authorizationCollection_[12345] = AuthorizationStatus::UNAUTHORIZED;
    int32_t result = handler.OnAuthorize(false);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(handler.authorizationCollection_[12345], AuthorizationStatus::UNAUTHORIZED);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnMsgHandler_001
 * @tc.desc: Test if (callback == nullptr) branch success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnMsgHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    MsgHandler<int, int> handler;
    handler.callbacks_[0] = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    EXPECT_NO_FATAL_FAILURE(msgHandler.OnMsgHandler(sess, pkt));
}

/**
@tc.name: ServerMsgHandlerTest_OnMsgHandler_002
@tc.desc: Test if callback branch success
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnMsgHandler_002, TestSize.Level1)
{
    OHOS::MMI::ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    ServerMsgFun msgFunc = [](SessionPtr sess, NetPacket &pkt) {
        return 0;
    };
    ServerMsgHandler::MsgCallback msgCallback = {MmiMessageId::DISPLAY_INFO, msgFunc};
    handler.RegistrationEvent(msgCallback);
    EXPECT_NO_FATAL_FAILURE(handler.OnMsgHandler(sess, pkt));
}

/**
@tc.name: ServerMsgHandlerTest_OnMsgHandler_003
@tc.desc: Test if callback branch failed
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnMsgHandler_003, TestSize.Level1)
{
    OHOS::MMI::ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    NetPacket pkt(MmiMessageId::ADD_INPUT_DEVICE_LISTENER);
    ServerMsgFun msgFunc = [](SessionPtr sess, NetPacket &pkt) {
        return -1;
    };
    ServerMsgHandler::MsgCallback msgCallback = {MmiMessageId::DISPLAY_INFO, msgFunc};
    handler.RegistrationEvent(msgCallback);
    EXPECT_NO_FATAL_FAILURE(handler.OnMsgHandler(sess, pkt));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnSetFunctionKeyState_002
 * @tc.desc: Test the function OnSetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnSetFunctionKeyState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t funcKey = 1;
    int32_t pid = 15;
    bool enable = true;
    INPUT_DEV_MGR->IsKeyboardDevice(nullptr);
    EXPECT_EQ(handler.OnSetFunctionKeyState(pid, funcKey, enable), ERR_NON_INPUT_APPLICATION);
}

/**
 * @tc.name: ServerMsgHandlerTest_IsNavigationWindowInjectEvent
 * @tc.desc: Test the function IsNavigationWindowInjectEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_IsNavigationWindowInjectEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->zOrder_ = 1;
    bool ret = false;
    ret = handler.IsNavigationWindowInjectEvent(pointerEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnRemoveGestureMonitor
 * @tc.desc: Test the function OnRemoveGestureMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnRemoveGestureMonitor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto udsSe = std::make_shared<UDSSession>("mytest", 2, 3, 4, 5);
    InputHandlerType inputHandlerType = InputHandlerType::MONITOR;
    uint32_t eventType = HANDLE_EVENT_TYPE_KEY;
    uint32_t gestureType = TOUCH_GESTURE_TYPE_PINCH;
    uint32_t fingers = 3;
    InputHandler->eventMonitorHandler_ = std::make_shared<EventMonitorHandler>();
    int32_t ret = handler.OnRemoveGestureMonitor(udsSe, inputHandlerType, eventType, gestureType, fingers);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAddGestureMonitor
 * @tc.desc: Test the function OnAddGestureMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAddGestureMonitor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto udsSe = std::make_shared<UDSSession>("mytest", 2, 3, 4, 5);
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    uint32_t eventType = HANDLE_EVENT_TYPE_KEY;
    uint32_t gestureType = TOUCH_GESTURE_TYPE_PINCH;
    uint32_t fingers = 3;
    InputHandler->eventMonitorHandler_ = std::make_shared<EventMonitorHandler>();
    int32_t ret = handler.OnAddGestureMonitor(udsSe, handlerType, eventType, gestureType, fingers);
    ASSERT_NE(ret, RET_OK);

    handlerType = InputHandlerType::NONE;
    ret = handler.OnAddGestureMonitor(udsSe, handlerType, eventType, gestureType, fingers);
    ASSERT_EQ(ret, RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_OnDisplayInfo_001
@tc.desc: Test the function OnDisplayInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t num = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    sess->SetTokenType(TOKEN_HAP);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    OLD::DisplayGroupInfo displayGroupInfo {
        .focusWindowId = 10,
        .currentUserId = 20,
    };
    pkt << displayGroupInfo.focusWindowId << displayGroupInfo.currentUserId << num;
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_WRITE;
    EXPECT_EQ(handler.OnDisplayInfo(sess, pkt), RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_OnDisplayInfo_002
@tc.desc: Test the function OnDisplayInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t num = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    sess->SetTokenType(TOKEN_NATIVE);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    OLD::DisplayGroupInfo displayGroupInfo {
        .focusWindowId = 10,
        .currentUserId = 20,
    };
    pkt << displayGroupInfo.focusWindowId << displayGroupInfo.currentUserId << num;
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    EXPECT_EQ(handler.OnDisplayInfo(sess, pkt), RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_OnDisplayInfo_003
@tc.desc: Test the function OnDisplayInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t num = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    sess->SetTokenType(TOKEN_SYSTEM_HAP);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    OLD::DisplayGroupInfo displayGroupInfo {
        .focusWindowId = 10,
        .currentUserId = 20,
    };
    pkt << displayGroupInfo.focusWindowId << displayGroupInfo.currentUserId << num;
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    EXPECT_EQ(handler.OnDisplayInfo(sess, pkt), RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_OnDisplayInfo_004
@tc.desc: Test the function OnDisplayInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t num = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    sess->SetTokenType(TOKEN_SHELL);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    OLD::DisplayGroupInfo displayGroupInfo {
        .focusWindowId = 10,
        .currentUserId = 20,
    };
    pkt << displayGroupInfo.focusWindowId << displayGroupInfo.currentUserId << num;
    Rect rec = {1, 1, 1, 1};
    std::vector recVec = {rec, rec};
    std::vector<int32_t> pChangeAreas = {1, 1, 1};
    std::vector transform = {1.0, 1.0, 1.0};
    pkt << 1 << 1 << 1 << rec << recVec << recVec << 1 << 1 << WINDOW_UPDATE_ACTION::ADD << 1 << 1.0 << pChangeAreas
        << transform << 1 << 1 << 1 << 1 << false;
    EXPECT_EQ(handler.OnDisplayInfo(sess, pkt), RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_DealGesturePointers
 * @tc.desc: Test the function DealGesturePointers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_DealGesturePointers, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetId(1);
    pointerEvent->SetPointerId(10001);
    auto touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(10002);
    item.SetOriginPointerId(10002);
    item.SetPressed(true);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler.DealGesturePointers(pointerEvent));
}

/**
@tc.name: ServerMsgHandlerTest_DealGesturePointers_001
@tc.desc: Test the function DealGesturePointers
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_DealGesturePointers_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetId(1);
    pointerEvent->SetPointerId(10001);
    ASSERT_NO_FATAL_FAILURE(handler.DealGesturePointers(pointerEvent));
}

/**
@tc.name: ServerMsgHandlerTest_ScreenFactor_001
@tc.desc: Test the function ScreenFactor
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ScreenFactor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t diagonalInch = 0;
    EXPECT_EQ(handler.ScreenFactor(diagonalInch), FACTOR_0);
    diagonalInch = 5;
    EXPECT_EQ(handler.ScreenFactor(diagonalInch), FACTOR_8);
    diagonalInch = 10;
    EXPECT_EQ(handler.ScreenFactor(diagonalInch), FACTOR_18);
    diagonalInch = 20;
    EXPECT_EQ(handler.ScreenFactor(diagonalInch), FACTOR_27);
    diagonalInch = 30;
    EXPECT_EQ(handler.ScreenFactor(diagonalInch), FACTOR_55);
    diagonalInch = 55;
    EXPECT_EQ(handler.ScreenFactor(diagonalInch), FACTOR_MAX);
}

/**
@tc.name: ServerMsgHandlerTest_UpdateTouchEvent_001
@tc.desc: Test the function UpdateTouchEvent
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_UpdateTouchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetId(1);
    pointerEvent->SetPointerId(10001);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_ENTER);
    pointerEvent->SetTargetWindowId(10);
    PointerEvent::PointerItem item;
    item.SetPointerId(10001);
    pointerEvent->AddPointerItem(item);
    int32_t action = PointerEvent::POINTER_ACTION_HOVER_ENTER;
    int32_t targetWindowId = 10;
    bool result = handler.UpdateTouchEvent(pointerEvent, action, targetWindowId);
    EXPECT_TRUE(result);
}

/**
@tc.name: ServerMsgHandlerTest_UpdateTouchEvent_002
@tc.desc: Test the function UpdateTouchEvent
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_UpdateTouchEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetId(1);
    pointerEvent->SetPointerId(10001);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetTargetWindowId(10);
    PointerEvent::PointerItem item;
    item.SetPointerId(10001);
    pointerEvent->AddPointerItem(item);
    int32_t action = PointerEvent::POINTER_ACTION_DOWN;
    int32_t targetWindowId = 10;
    bool result = handler.UpdateTouchEvent(pointerEvent, action, targetWindowId);
    EXPECT_TRUE(result);
}

/**
@tc.name: ServerMsgHandlerTest_UpdateTouchEvent_003
@tc.desc: Test the function UpdateTouchEvent
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_UpdateTouchEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetId(1);
    pointerEvent->SetPointerId(10001);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetTargetWindowId(-1);
    PointerEvent::PointerItem item;
    item.SetPointerId(10001);
    pointerEvent->AddPointerItem(item);
    int32_t action = PointerEvent::POINTER_ACTION_CANCEL;
    int32_t targetWindowId = -1;
    bool result = handler.UpdateTouchEvent(pointerEvent, action, targetWindowId);
    EXPECT_TRUE(result);
}

/**
@tc.name: ServerMsgHandlerTest_UpdateTouchEvent_004
@tc.desc: Test the function UpdateTouchEvent
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_UpdateTouchEvent_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetId(1);
    pointerEvent->SetPointerId(10001);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetTargetWindowId(10);
    PointerEvent::PointerItem item;
    item.SetPointerId(10001);
    pointerEvent->AddPointerItem(item);
    int32_t action = PointerEvent::POINTER_ACTION_CANCEL;
    int32_t targetWindowId = 10;
    bool result = handler.UpdateTouchEvent(pointerEvent, action, targetWindowId);
    EXPECT_TRUE(result);
    pointerEvent->RemoveAllPointerItems();
    EXPECT_FALSE(handler.UpdateTouchEvent(pointerEvent, action, targetWindowId));
}

/**
@tc.name: ServerMsgHandlerTest_SubscribeKeyMonitor_001
@tc.desc: Test the function SubscribeKeyMonitor
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SubscribeKeyMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler serverMsgHandler;
    int32_t session = 1;
    KeyMonitorOption keyOption;
    ASSERT_NO_FATAL_FAILURE(serverMsgHandler.SubscribeKeyMonitor(session, keyOption));
}

/**
@tc.name: ServerMsgHandlerTest_UnsubscribeKeyMonitor
@tc.desc: Test the function UnsubscribeKeyMonitor
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_UnsubscribeKeyMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler serverMsgHandler;
    int32_t session = 1;
    KeyMonitorOption keyOption;
    ASSERT_NO_FATAL_FAILURE(serverMsgHandler.UnsubscribeKeyMonitor(session, keyOption));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAuthorize_005
 * @tc.desc: Test the function OnAuthorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAuthorize_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.CurrentPID_ = 12345;
    handler.authorizationCollection_[12345] = AuthorizationStatus::UNAUTHORIZED;
    int32_t result = handler.OnAuthorize(true);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAuthorize_006
 * @tc.desc: Test the function OnAuthorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAuthorize_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.CurrentPID_ = 12345;
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_SELECTION_AUTHORIZE;
    int32_t result = handler.OnAuthorize(false);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnCancelInjection_005
 * @tc.desc: Test the function OnCancelInjection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnCancelInjection_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_AUTHORIZE;
    int callPid = 12345;
    int32_t ret = handler.OnCancelInjection(callPid);
    EXPECT_EQ(ret, COMMON_PERMISSION_CHECK_ERROR);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnCancelInjection_006
 * @tc.desc: Test the function OnCancelInjection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnCancelInjection_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_AUTHORIZE;
    int callPid = 0;
    ASSERT_NO_FATAL_FAILURE(handler.OnCancelInjection(callPid));
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_SELECTION_AUTHORIZE;
    ASSERT_NO_FATAL_FAILURE(handler.OnCancelInjection(callPid));
}

/**
@tc.name: ServerMsgHandlerTest_OnMsgHandler04
@tc.desc: Test if callback branch failed
@tc.type: FUNC
@tc.require: nhj
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnMsgHandler04, TestSize.Level1)
{
    OHOS::MMI::ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    NetPacket pkt(MmiMessageId::ADD_INPUT_DEVICE_LISTENER);
    ServerMsgFun msgFunc = [](SessionPtr sess, NetPacket &pkt) {
        return -2;
    };
    ServerMsgHandler::MsgCallback msgCallback = {MmiMessageId::DISPLAY_INFO, msgFunc};
    handler.RegistrationEvent(msgCallback);
    EXPECT_NO_FATAL_FAILURE(handler.OnMsgHandler(sess, pkt));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnGetFunctionKeyState
 * @tc.desc: Test the function OnGetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnGetFunctionKeyState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t funcKey = MOUSE_ICON_SIZE;
    bool state = true;
    auto ret = handler.OnGetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, ERR_DEVICE_NOT_EXIST);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnSetFunctionKeyState
 * @tc.desc: Test the function OnSetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnSetFunctionKeyState, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t funcKey = NUM_LOCK_FUNCTION_KEY;
    int32_t pid = 15;
    bool enable = false;
    auto ret = handler.OnSetFunctionKeyState(pid, funcKey, enable);
    EXPECT_EQ(ret, ERR_NON_INPUT_APPLICATION);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectPointerEvent_005
 * @tc.desc: Test if (iter->second == AuthorizationStatus::UNAUTHORIZED) branch failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectPointerEvent_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t pid = 0;
    bool isNativeInject = true;
    pointerEvent->SetId(1);
    pointerEvent->eventType_ = 1;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    msgHandler.authorizationCollection_.insert(std::make_pair(pid, AuthorizationStatus::UNKNOWN));
    InputHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    int32_t result =
        msgHandler.OnInjectPointerEvent(pointerEvent, pid, isNativeInject, false, PointerEvent::DISPLAY_COORDINATE);
    EXPECT_EQ(result, COMMON_PERMISSION_CHECK_ERROR);
}

/**
 * @tc.name: ServerMsgHandlerTest_DealGesturePointers
 * @tc.desc: Test the function DealGesturePointers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, DealGesturePointers001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetId(1);
    pointerEvent->eventType_ = 1;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    handler.nativeTargetWindowIds_.insert(std::make_pair(pointerEvent->GetPointerId(), 10));
    auto touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(10002);
    item.SetOriginPointerId(10002);
    item.SetPressed(true);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler.DealGesturePointers(pointerEvent));
}

/**
 * @tc.name: ServerMsgHandlerTest_ScreenFactor
 * @tc.desc: Test the function ScreenFactor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ScreenFactor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t diagonalInch = -1;
    auto ret = handler.ScreenFactor(diagonalInch);
    EXPECT_EQ(ret, FACTOR_0);
    diagonalInch = 1;
    ret = handler.ScreenFactor(diagonalInch);
    EXPECT_EQ(ret, FACTOR_8);
    diagonalInch = 10;
    ret = handler.ScreenFactor(diagonalInch);
    EXPECT_EQ(ret, FACTOR_18);
    diagonalInch = 20;
    ret = handler.ScreenFactor(diagonalInch);
    EXPECT_EQ(ret, FACTOR_27);
    diagonalInch = 40;
    ret = handler.ScreenFactor(diagonalInch);
    EXPECT_EQ(ret, FACTOR_55);
    diagonalInch = 100;
    ret = handler.ScreenFactor(diagonalInch);
    EXPECT_EQ(ret, FACTOR_MAX);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectTouchPadEventExt
 * @tc.desc: Test OnInjectTouchPadEventExt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectTouchPadEventExt, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t pid = 0;
    bool isNativeInject = true;
    OHOS::MMI::TouchpadCDG touchpadCDG;
    touchpadCDG.frequency = 1;
    pointerEvent->SetId(1);
    pointerEvent->eventType_ = 1;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    msgHandler.authorizationCollection_.insert(std::make_pair(pid, AuthorizationStatus::UNKNOWN));
    InputHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    int32_t result = msgHandler.OnInjectTouchPadEventExt(pointerEvent, touchpadCDG, false);
    EXPECT_EQ(result, ERROR_NULL_POINTER);
}

/**
 * @tc.name: ServerMsgHandlerTest_AccelerateMotion_006
 * @tc.desc: Test the function AccelerateMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_AccelerateMotion_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    int32_t ret = handler.AccelerateMotion(pointerEvent);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_AccelerateMotion_008
 * @tc.desc: Test the function AccelerateMotion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_AccelerateMotion_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_TOUCHPAD_POINTER);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetRawDx(1);
    item.SetRawDy(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    int32_t ret = handler.AccelerateMotion(pointerEvent);
    EXPECT_EQ(ret, RET_OK);
}

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH) || defined(OHOS_BUILD_ENABLE_KEYBOARD)
/**
@tc.name: ServerMsgHandlerTest_AddInputEventFilter
@tc.desc: Test the function AddInputEventFilter
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_AddInputEventFilter, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t filterId = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 1;
    int32_t clientPid = 1;
    EXPECT_EQ(handler.AddInputEventFilter({}, filterId, priority, deviceTags, clientPid), ERROR_NULL_POINTER);
    EXPECT_EQ(handler.RemoveInputEventFilter(clientPid, filterId), ERROR_NULL_POINTER);
}
#endif

/**
 * @tc.name: ServerMsgHandlerTest_AccelerateMotionTouchpad
 * @tc.desc: Test the function AccelerateMotionTouchpad
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_AccelerateMotionTouchpad, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    DisplayInfo displayInfo;
    displayInfo.id = -1;
    OHOS::MMI::TouchpadCDG touchpadCDG;
    touchpadCDG.frequency = 1;
    int32_t ret = handler.AccelerateMotionTouchpad(pointerEvent, touchpadCDG);
    EXPECT_EQ(ret, RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_SaveTargetWindowId_008
@tc.desc: Test the function SaveTargetWindowId
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SaveTargetWindowId_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    int32_t ret = handler.SaveTargetWindowId(pointerEvent, true);
    EXPECT_EQ(ret, RET_OK);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_EXIT);
    ret = handler.SaveTargetWindowId(pointerEvent, true);
    EXPECT_EQ(ret, RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_UpdateTouchEvent
@tc.desc: Test the function UpdateTouchEvent
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_UpdateTouchEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_ENTER);
    int32_t action = PointerEvent::POINTER_ACTION_HOVER_ENTER;
    int32_t targetWindowId = -1;
    auto pointerIds = pointerEvent->GetPointerIds();
    EXPECT_TRUE(pointerIds.empty());
    auto ret = handler.UpdateTouchEvent(pointerEvent, action, targetWindowId);
    EXPECT_EQ(ret, false);
}

/**
@tc.name: ServerMsgHandlerTest_UpdateTouchEvent
@tc.desc: Test the function UpdateTouchEvent
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_UpdateTouchEvent001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    int32_t action = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    int32_t targetWindowId = -1;
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    item.SetTargetWindowId(2);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    auto pointerIds = pointerEvent->GetPointerIds();
    EXPECT_FALSE(pointerIds.empty());
    int32_t id = 1;
    EXPECT_TRUE(pointerEvent->GetPointerItem(id, item));
    auto ret = handler.UpdateTouchEvent(pointerEvent, action, targetWindowId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnRemoveInputHandler_003
 * @tc.desc: Test the function OnRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnRemoveInputHandler_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    InputHandlerType handlerType = InputHandlerType::NONE;
    HandleEventType eventType = 1;
    int32_t priority = 2;
    uint32_t deviceTags = 3;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    int32_t ret = handler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_SubscribeKeyMonitor
 * @tc.desc: Test the function SubscribeKeyMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SubscribeKeyMonitor002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    OHOS::MMI::KeyMonitorOption keyOption;
    int32_t session {-1};
    int32_t ret = handler.SubscribeKeyMonitor(session, keyOption);
    EXPECT_EQ(ret, -CAPABILITY_NOT_SUPPORTED);
}

/**
 * @tc.name: ServerMsgHandlerTest_UnsubscribeKeyMonitor
 * @tc.desc: Test the function UnsubscribeKeyMonitor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_UnsubscribeKeyMonitor002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    OHOS::MMI::KeyMonitorOption keyOption;
    int32_t session {-1};
    int32_t ret = handler.UnsubscribeKeyMonitor(session, keyOption);
    EXPECT_EQ(ret, -CAPABILITY_NOT_SUPPORTED);
}

/**
 * @tc.name: ServerMsgHandlerTest_DealGesturePointers002
 * @tc.desc: Test the function DealGesturePointers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_DealGesturePointers002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetId(1);
    pointerEvent->SetPointerId(10001);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_ACCESSIBILITY;
    ASSERT_NO_FATAL_FAILURE(handler.DealGesturePointers(pointerEvent));
    auto touchEvent = PointerEvent::Create();
    ASSERT_NE(touchEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(10002);
    item.SetOriginPointerId(10002);
    item.SetPressed(true);
    touchEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(handler.DealGesturePointers(pointerEvent));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnSetFunctionKeyState003
 * @tc.desc: Test the function OnSetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnSetFunctionKeyState003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    AppExecFwk::RunningProcessInfo processInfo;
    processInfo.extensionType_ = AppExecFwk::ExtensionAbilityType::INPUTMETHOD;
    int32_t funcKey = 1;
    int32_t pid = 15;
    bool enable = true;
    INPUT_DEV_MGR->IsKeyboardDevice(nullptr);
    ASSERT_NO_FATAL_FAILURE(handler.OnSetFunctionKeyState(pid, funcKey, enable));
    enable = false;
    ASSERT_NO_FATAL_FAILURE(handler.OnSetFunctionKeyState(pid, funcKey, enable));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnInjectPointerEventExt002
 * @tc.desc: Test OnInjectPointerEventExt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnInjectPointerEventExt002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler msgHandler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    InputHandler->eventNormalizeHandler_ = std::make_shared<EventNormalizeHandler>();
    pointerEvent->SetId(1);
    pointerEvent->eventType_ = 1;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    msgHandler.nativeTargetWindowIds_.insert(std::make_pair(pointerEvent->GetPointerId(), 10));
    ASSERT_NO_FATAL_FAILURE(msgHandler.OnInjectPointerEventExt(pointerEvent, true, PointerEvent::DISPLAY_COORDINATE));

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT;
    ASSERT_NO_FATAL_FAILURE(msgHandler.OnInjectPointerEventExt(pointerEvent, true, PointerEvent::DISPLAY_COORDINATE));

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NONE);
    ASSERT_NO_FATAL_FAILURE(msgHandler.OnInjectPointerEventExt(pointerEvent, true, PointerEvent::DISPLAY_COORDINATE));

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_HIDE_POINTER;
    ASSERT_NO_FATAL_FAILURE(msgHandler.OnInjectPointerEventExt(pointerEvent, true, PointerEvent::DISPLAY_COORDINATE));
}

/**
@tc.name: ServerMsgHandlerTest_FixTargetWindowId_008
@tc.desc: Test FixTargetWindowId
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.shellTargetWindowIds_.clear();
    handler.castTargetWindowIds_.clear();
    handler.accessTargetWindowIds_.clear();
    handler.nativeTargetWindowIds_.clear();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetDeviceId(CAST_INPUT_DEVICEID);
    int32_t action = PointerEvent::POINTER_ACTION_DOWN;
    int32_t pointerId = -1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(-1);
    handler.shellTargetWindowIds_[0] = -1;
    pointerEvent->SetZOrder(1);
    ASSERT_NO_FATAL_FAILURE(handler.FixTargetWindowId(pointerEvent, action, true));
    handler.castTargetWindowIds_[0] = -1;
    ASSERT_NO_FATAL_FAILURE(handler.FixTargetWindowId(pointerEvent, action, true));
    pointerEvent->SetZOrder(-1);
    ASSERT_NO_FATAL_FAILURE(handler.FixTargetWindowId(pointerEvent, action, true));
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_ACCESSIBILITY);
    ASSERT_NO_FATAL_FAILURE(handler.FixTargetWindowId(pointerEvent, action, true));
    handler.accessTargetWindowIds_[0] = -1;
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    ASSERT_NO_FATAL_FAILURE(handler.FixTargetWindowId(pointerEvent, action, true));
    handler.nativeTargetWindowIds_[0] = -1;
    ASSERT_NO_FATAL_FAILURE(handler.FixTargetWindowId(pointerEvent, action, true));
}

/**
@tc.name: ServerMsgHandlerTest_ReadScreensInfo_001
@tc.desc: Test ReadScreensInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ReadScreensInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    UserScreenInfo userScreenInfo;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    uint32_t num = MAX_SCREEN_SIZE + 1;
    pkt << num;
    EXPECT_EQ(handler.ReadScreensInfo(pkt, userScreenInfo), RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_ReadScreensInfo_002
@tc.desc: Test ReadScreensInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ReadScreensInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    UserScreenInfo userScreenInfo;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    ScreenInfo info;
    uint32_t num = 1;
    pkt << num << info.id << info.uniqueId << info.screenType << info.width << info.height << info.physicalWidth
        << info.physicalHeight << info.tpDirection << info.dpi << info.ppi << info.rotation;
    EXPECT_EQ(handler.ReadScreensInfo(pkt, userScreenInfo), RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_ReadScreensInfo_003
@tc.desc: Test ReadScreensInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ReadScreensInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    UserScreenInfo userScreenInfo;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    ScreenInfo info;
    uint32_t num = 1;
    pkt << num << info.id << info.uniqueId << info.screenType << info.width << info.height << info.physicalWidth
        << info.physicalHeight << info.tpDirection << info.dpi << info.ppi << info.rotation;
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    EXPECT_EQ(handler.ReadScreensInfo(pkt, userScreenInfo), RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_ReadDisplayGroupsInfo_001
@tc.desc: Test ReadDisplayGroupsInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ReadDisplayGroupsInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    UserScreenInfo userScreenInfo;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    uint32_t num = MAX_SCREEN_SIZE + 1;
    pkt << num;
    EXPECT_EQ(handler.ReadDisplayGroupsInfo(pkt, userScreenInfo), RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_ReadDisplayGroupsInfo_002
@tc.desc: Test ReadDisplayGroupsInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ReadDisplayGroupsInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    UserScreenInfo userScreenInfo;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    DisplayGroupInfo info;
    uint32_t num = 1;
    pkt << num << info.id << info.name << info.type << info.mainDisplayId << info.focusWindowId;
    EXPECT_EQ(handler.ReadDisplayGroupsInfo(pkt, userScreenInfo), RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_ReadDisplayGroupsInfo_003
@tc.desc: Test ReadDisplayGroupsInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ReadDisplayGroupsInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    UserScreenInfo userScreenInfo;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    DisplayGroupInfo info;
    uint32_t num = 1;
    pkt << num << info.id << info.name << info.type << info.mainDisplayId << info.focusWindowId;
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    EXPECT_EQ(handler.ReadDisplayGroupsInfo(pkt, userScreenInfo), RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_ReadDisplaysInfo_001
@tc.desc: Test ReadDisplaysInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ReadDisplaysInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    DisplayGroupInfo displayGroupInfo;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    uint32_t num = MAX_SCREEN_SIZE + 1;
    pkt << num;
    EXPECT_EQ(handler.ReadDisplaysInfo(pkt, displayGroupInfo), RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_ReadDisplaysInfo_002
@tc.desc: Test ReadDisplaysInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ReadDisplaysInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    DisplayGroupInfo displayGroupInfo;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    DisplayInfo info;
    uint32_t num = 1;
    pkt << num << info.id << info.x << info.y << info.width << info.height << info.dpi << info.name << info.direction
        << info.displayDirection << info.displayMode << info.transform << info.scalePercent << info.expandHeight
        << info.isCurrentOffScreenRendering << info.displaySourceMode << info.oneHandX << info.oneHandY
        << info.screenArea << info.rsId << info.offsetX << info.offsetY << info.pointerActiveWidth
        << info.pointerActiveHeight;
    ;
    EXPECT_EQ(handler.ReadDisplaysInfo(pkt, displayGroupInfo), RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_ReadWindowsInfo_001
@tc.desc: Test ReadWindowsInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ReadWindowsInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    DisplayGroupInfo displayGroupInfo;
    OLD::DisplayGroupInfo oldDisplayGroupInfo {
        .focusWindowId = 10,
        .currentUserId = 20,
    };
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    uint32_t num = MAX_SCREEN_SIZE + 1;
    pkt << num;
    EXPECT_EQ(handler.ReadWindowsInfo(pkt, displayGroupInfo, oldDisplayGroupInfo), RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_ReadWindowsInfo_002
@tc.desc: Test ReadWindowsInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ReadWindowsInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    DisplayGroupInfo displayGroupInfo;
    OLD::DisplayGroupInfo oldDisplayGroupInfo {
        .focusWindowId = 10,
        .currentUserId = 20,
    };
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    WindowInfo info;
    uint32_t num = 1;
    int32_t byteCount = 0;
    pkt << num << info.id << info.pid << info.uid << info.area << info.defaultHotAreas << info.pointerHotAreas
        << info.agentWindowId << info.flags << info.action << info.displayId << info.groupId << info.zOrder
        << info.pointerChangeAreas << info.transform << info.windowInputType << info.privacyMode << info.windowType
        << info.isSkipSelfWhenShowOnVirtualScreen << info.windowNameType << info.agentPid << byteCount;
    EXPECT_EQ(handler.ReadWindowsInfo(pkt, displayGroupInfo, oldDisplayGroupInfo), RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_ReadWindowsInfo_003
@tc.desc: Test ReadWindowsInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ReadWindowsInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    DisplayGroupInfo displayGroupInfo;
    OLD::DisplayGroupInfo oldDisplayGroupInfo {
        .focusWindowId = 10,
        .currentUserId = 20,
    };
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    WindowInfo info;
    uint32_t num = 1;
    int32_t byteCount = 0;
    pkt << num << info.id << info.pid << info.uid << info.area << info.defaultHotAreas << info.pointerHotAreas
        << info.agentWindowId << info.flags << info.action << info.displayId << info.groupId << info.zOrder
        << info.pointerChangeAreas << info.transform << info.windowInputType << info.privacyMode << info.windowType
        << info.isSkipSelfWhenShowOnVirtualScreen << info.windowNameType << info.agentPid << byteCount;
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    EXPECT_EQ(handler.ReadWindowsInfo(pkt, displayGroupInfo, oldDisplayGroupInfo), RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_TestChangeToOld_001
 * @tc.desc: Test ChangeToOld
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_TestChangeToOld_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    DisplayGroupInfo group;
    group.id = 1;
    group.name = "MainGroup";
    group.type = GroupType::GROUP_DEFAULT;
    group.mainDisplayId = 2;
    group.focusWindowId = 123;
    group.windowsInfo.push_back(WindowInfo());
    group.displaysInfo.push_back(DisplayInfo());
    DisplayInfo display;
    display.width = 1920;
    display.height = 1080;
    group.displaysInfo.push_back(display);
    WindowInfo window;
    window.groupId = 0;
    window.id = 123;
    group.windowsInfo.push_back(window);
    userScreenInfo.displayGroups.push_back(group);
    userScreenInfo.screens.push_back(ScreenInfo());
    ServerMsgHandler handler;
    EXPECT_EQ(handler.ChangeToOld(userScreenInfo), false);
}

/**
 * @tc.name: ServerMsgHandlerTest_TestChangeToOld_002
 * @tc.desc: Test ChangeToOld
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_TestChangeToOld_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    size_t num {1};
    std::vector<DisplayInfo> displaysInfos;
    DisplayInfo display;
    display.width = 1920;
    display.height = 1080;
    display.direction = DIRECTION0;
    display.screenArea.id = 1;
    display.screenArea.area.width = 100;
    display.screenArea.area.height = 100;
    displaysInfos.push_back(display);
    std::vector<ScreenInfo> screens;
    ScreenInfo screenInfo;
    screenInfo.id = 1;
    screens.push_back(screenInfo);
    ServerMsgHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.ChangeToOld(num, displaysInfos, screens));
    display.direction = DIRECTION90;
    displaysInfos = {display};
    ASSERT_NO_FATAL_FAILURE(handler.ChangeToOld(num, displaysInfos, screens));
}

/**
 * @tc.name: ServerMsgHandlerTest_TestPrintf
 * @tc.desc: Test Printf
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_TestPrintf, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    DisplayGroupInfo group;
    group.id = 1;
    group.name = "MainGroup";
    group.type = GroupType::GROUP_DEFAULT;
    group.mainDisplayId = 2;
    group.focusWindowId = 123;
    group.windowsInfo.push_back(WindowInfo());
    group.displaysInfo.push_back(DisplayInfo());
    DisplayInfo display;
    display.width = 1920;
    display.height = 1080;
    display.transform = {0, 0, 0, 0};
    group.displaysInfo.push_back(display);
    WindowInfo window;
    window.groupId = 0;
    window.id = 123;
    group.windowsInfo.push_back(window);
    userScreenInfo.displayGroups.push_back(group);
    userScreenInfo.screens.push_back(ScreenInfo());
    ServerMsgHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.Printf(userScreenInfo));
}

/**
 * @tc.name: ServerMsgHandlerTest_TestChangeToOld_003
 * @tc.desc: Test ChangeToOld
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_TestChangeToOld_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    DisplayGroupInfo group;
    group.id = 1;
    group.name = "MainGroup";
    group.type = GroupType::GROUP_DEFAULT;
    group.mainDisplayId = 2;
    group.focusWindowId = 123;
    group.windowsInfo.push_back(WindowInfo());
    group.displaysInfo.push_back(DisplayInfo());
    DisplayInfo display;
    display.width = 1920;
    display.height = 1080;
    group.displaysInfo.push_back(display);
    WindowInfo window;
    window.groupId = 0;
    window.id = 123;
    group.windowsInfo.push_back(window);
    userScreenInfo.displayGroups.push_back(group);
    userScreenInfo.screens.push_back(ScreenInfo());
    ServerMsgHandler handler;
    OLD::DisplayGroupInfo oldInfo;
    handler.oldDisplayGroupInfos_.push_back(oldInfo);
    EXPECT_EQ(handler.ChangeToOld(userScreenInfo), true);
}

/**
@tc.name: ServerMsgHandlerTest_ChangeToOld_001
@tc.desc: Test ChangeToOld
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ChangeToOld_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 0;
    displayInfo.y = 0;
    displayInfo.width = 100;
    displayInfo.height = 200;
    displayInfo.dpi = 300;
    displayInfo.name = "TestDisplay";
    displayInfo.direction = Direction::DIRECTION0;
    displayInfo.displayDirection = Direction::DIRECTION0;
    displayInfo.displayMode = DisplayMode::FULL;
    displayInfo.transform = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    displayInfo.scalePercent = 100;
    displayInfo.expandHeight = 0;
    displayInfo.isCurrentOffScreenRendering = false;
    displayInfo.displaySourceMode = DisplaySourceMode::SCREEN_MAIN;
    displayInfo.oneHandX = 0;
    displayInfo.oneHandY = 0;
    displayInfo.screenArea.id = 1;
    displayInfo.screenArea.area = {0, 0, 100, 200};
    displayInfo.rsId = 1;
    displayInfo.offsetX = 0;
    displayInfo.offsetY = 0;
    displayInfo.pointerActiveWidth = 0;
    displayInfo.pointerActiveHeight = 0;

    ScreenInfo screenInfo;
    screenInfo.id = 1;
    screenInfo.uniqueId = "TestScreen";
    screenInfo.screenType = ScreenType::REAL;
    screenInfo.width = 100;
    screenInfo.height = 200;
    screenInfo.physicalWidth = 100;
    screenInfo.physicalHeight = 200;

    std::vector<DisplayInfo> displaysInfo = {displayInfo};
    std::vector<ScreenInfo> screens = {screenInfo};

    ServerMsgHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.ChangeToOld(1, displaysInfo, screens));
}

/**
@tc.name: ServerMsgHandlerTest_ChangeToOld_002
@tc.desc: Test ChangeToOld
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ChangeToOld_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;

    DisplayGroupInfo displayGroupInfo1;
    displayGroupInfo1.id = 0;
    displayGroupInfo1.type = GroupType::GROUP_DEFAULT;
    displayGroupInfo1.mainDisplayId = 0;
    displayGroupInfo1.focusWindowId = GLOBAL_WINDOW_ID;

    DisplayGroupInfo displayGroupInfo2;
    displayGroupInfo2.id = 1;
    displayGroupInfo2.type = GroupType::GROUP_SPECIAL;
    displayGroupInfo2.mainDisplayId = 1;
    displayGroupInfo2.focusWindowId = GLOBAL_WINDOW_ID;

    userScreenInfo.displayGroups = {displayGroupInfo1, displayGroupInfo2};

    ServerMsgHandler handler;
    EXPECT_FALSE(handler.ChangeToOld(userScreenInfo));
}

/**
@tc.name: ServerMsgHandlerTest_ChangeToOld_003
@tc.desc: Test ChangeToOld
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ChangeToOld_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;

    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.id = 0;
    displayGroupInfo.type = GroupType::GROUP_DEFAULT;
    displayGroupInfo.mainDisplayId = 0;
    displayGroupInfo.focusWindowId = GLOBAL_WINDOW_ID;

    userScreenInfo.displayGroups = {displayGroupInfo, displayGroupInfo};

    ServerMsgHandler handler;
    EXPECT_FALSE(handler.ChangeToOld(userScreenInfo));
}

/**
@tc.name: ServerMsgHandlerTest_ChangeToOld_004
@tc.desc: Test ChangeToOld
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ChangeToOld_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    userScreenInfo.displayGroups.clear();

    ServerMsgHandler handler;
    EXPECT_TRUE(handler.ChangeToOld(userScreenInfo));
}

/**
@tc.name: ServerMsgHandlerTest_ChangeToOld_005
@tc.desc: Test ChangeToOld
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ChangeToOld_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;

    DisplayGroupInfo displayGroupInfo1;
    displayGroupInfo1.id = 0;
    displayGroupInfo1.type = GroupType::GROUP_DEFAULT;
    displayGroupInfo1.mainDisplayId = 0;
    displayGroupInfo1.focusWindowId = GLOBAL_WINDOW_ID;

    DisplayGroupInfo displayGroupInfo2;
    displayGroupInfo2.id = 1;
    displayGroupInfo2.type = GroupType::GROUP_SPECIAL;
    displayGroupInfo2.mainDisplayId = 1;
    displayGroupInfo2.focusWindowId = GLOBAL_WINDOW_ID;

    DisplayGroupInfo displayGroupInfo3;
    displayGroupInfo3.id = 2;
    displayGroupInfo3.type = GroupType::GROUP_DEFAULT;
    displayGroupInfo3.mainDisplayId = 2;
    displayGroupInfo3.focusWindowId = GLOBAL_WINDOW_ID;

    userScreenInfo.displayGroups = {displayGroupInfo1, displayGroupInfo2, displayGroupInfo3};

    ServerMsgHandler handler;
    EXPECT_FALSE(handler.ChangeToOld(userScreenInfo));
}

/**
@tc.name: ServerMsgHandlerTest_ChangeToOld_006
@tc.desc: Test ChangeToOld
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ChangeToOld_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;

    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.id = 0;
    displayGroupInfo.type = GroupType::GROUP_DEFAULT;
    displayGroupInfo.mainDisplayId = 0;
    displayGroupInfo.focusWindowId = GLOBAL_WINDOW_ID;

    userScreenInfo.displayGroups = {displayGroupInfo};
    ServerMsgHandler handler;
    EXPECT_FALSE(handler.ChangeToOld(userScreenInfo));
}

/**
@tc.name: ServerMsgHandlerTest_OnDisplayInfo_005
@tc.desc: Test the function OnDisplayInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t num = 1;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    sess->SetTokenType(TOKEN_SHELL);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    ScreenInfo info;
    pkt << num;
    pkt << info.id << info.uniqueId << info.screenType << info.width << info.height << info.physicalWidth
        << info.physicalHeight << info.tpDirection << info.dpi << info.ppi << info.rotation;
    EXPECT_EQ(handler.OnDisplayInfo(sess, pkt), RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_OnDisplayInfo_006
@tc.desc: Test the function OnDisplayInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t num = 1;
    int32_t num2 = 10;
    int32_t num3 = 0;
    bool ret = false;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    sess->SetTokenType(TOKEN_SHELL);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    {
        ScreenInfo info;
        pkt << num2 << num << info.id << info.uniqueId << info.screenType << info.width << info.height
            << info.physicalWidth << info.physicalHeight << info.tpDirection << info.dpi << info.ppi << info.rotation;
    }
    {
        DisplayGroupInfo info;
        pkt << num << info.id << info.name << info.type << info.mainDisplayId << info.focusWindowId;
    }
    {
        DisplayInfo info;
        pkt << num << info.id << info.x << info.y << info.width << info.height << info.dpi << info.name
            << info.direction << info.displayDirection << info.displayMode << info.transform << info.scalePercent
            << info.expandHeight << info.isCurrentOffScreenRendering << info.displaySourceMode << info.oneHandX
            << info.oneHandY << info.screenArea << info.rsId << info.offsetX << info.offsetY<< info.pointerActiveWidth
            << info.pointerActiveHeight;
    }
    {
        WindowInfo info;
        pkt << num << info.id << info.pid << info.uid << info.area << info.defaultHotAreas << info.pointerHotAreas
            << info.agentWindowId << info.flags << info.action << info.displayId << info.groupId << info.zOrder
            << info.pointerChangeAreas << info.transform << info.windowInputType << info.privacyMode << info.windowType
            << info.isSkipSelfWhenShowOnVirtualScreen << info.windowNameType << num3;
    }
    {
        WindowInfo extensionInfo;
        pkt << num << extensionInfo.id << extensionInfo.pid << extensionInfo.uid << extensionInfo.area
            << extensionInfo.defaultHotAreas << extensionInfo.pointerHotAreas << extensionInfo.agentWindowId
            << extensionInfo.flags << extensionInfo.action << extensionInfo.displayId << extensionInfo.groupId
            << extensionInfo.zOrder << extensionInfo.pointerChangeAreas << extensionInfo.transform
            << extensionInfo.windowInputType << extensionInfo.privacyMode << extensionInfo.windowType
            << extensionInfo.privacyUIFlag << extensionInfo.rectChangeBySystem
            << extensionInfo.isSkipSelfWhenShowOnVirtualScreen << extensionInfo.windowNameType;
    }
    pkt << ret;
    EXPECT_EQ(handler.OnDisplayInfo(sess, pkt), RET_OK);
}

/**
@tc.name: ServerMsgHandlerTest_NativeInjectCheck
@tc.desc: Test the function NativeInjectCheck
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_NativeInjectCheck, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.InitInjectNoticeSource();
    int32_t pid = -1;
    auto result = handler.NativeInjectCheck(pid);
    EXPECT_EQ(result, COMMON_PERMISSION_CHECK_ERROR);
    pid = 0;
    result = handler.NativeInjectCheck(pid);
    EXPECT_EQ(result, COMMON_PERMISSION_CHECK_ERROR);
}

/**
@tc.name: ServerMsgHandlerTest_NativeInjectCheck001
@tc.desc: Test the function NativeInjectCheck
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_NativeInjectCheck001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t pid = 1234;
    auto isPC = handler.IsPC();
    if (!isPC) {
        auto result = handler.NativeInjectCheck(pid);
        EXPECT_EQ(result, COMMON_PERMISSION_CHECK_ERROR);
    }
}

/**
@tc.name: ServerMsgHandlerTest_NativeInjectCheck002
@tc.desc: Test the function NativeInjectCheck
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_NativeInjectCheck002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t pid = 1234;
    auto isPC = handler.IsPC();
    EXPECT_EQ(isPC, false);
    DISPLAY_MONITOR->SetScreenLocked(true);
    auto result = handler.NativeInjectCheck(pid);
    EXPECT_EQ(result, COMMON_PERMISSION_CHECK_ERROR);
}

/**
@tc.name: ServerMsgHandlerTest_NativeInjectCheck003
@tc.desc: Test the function NativeInjectCheck
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_NativeInjectCheck003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t pid = 1234;
    auto isPC = handler.IsPC();
    EXPECT_EQ(isPC, false);
    DISPLAY_MONITOR->SetScreenLocked(false);
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_UNAUTHORIZE;
    auto result = handler.NativeInjectCheck(pid);
    EXPECT_EQ(result, COMMON_PERMISSION_CHECK_ERROR);
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_AUTHORIZE;
    result = handler.NativeInjectCheck(pid);
    EXPECT_EQ(result, COMMON_PERMISSION_CHECK_ERROR);
}

/**
 * @tc.name: ServerMsgHandlerTest_CloseInjectNotice_002
 * @tc.desc: Test CloseInjectNotice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_CloseInjectNotice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.InitInjectNoticeSource();
    int32_t pid = 0;
    bool result = handler.CloseInjectNotice(pid);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: ServerMsgHandlerTest_CloseInjectNotice_003
 * @tc.desc: Test the function CloseInjectNotice
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_CloseInjectNotice_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    InjectNoticeManager manager;
    handler.InitInjectNoticeSource();
    int32_t pid = 1234;
    handler.injectNotice_ = nullptr;
    bool ret = handler.InitInjectNoticeSource();
    handler.injectNotice_->isStartSrv_ = true;
    manager.connectionCallback_ = new (std::nothrow) InjectNoticeManager::InjectNoticeConnection;
    EXPECT_NE(nullptr, manager.connectionCallback_);
    auto connection = handler.injectNotice_->GetConnection();
    connection->isConnected_ = false;
    ret = handler.CloseInjectNotice(pid);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ServerMsgHandlerTest_InitInjectNoticeSource_004
 * @tc.desc: Test the function InitInjectNoticeSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_InitInjectNoticeSource_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    InjectNoticeManager manager;
    bool ret = handler.InitInjectNoticeSource();
    handler.injectNotice_ = std::make_shared<InjectNoticeManager>();
    manager.isStartSrv_ = false;
    ret = handler.InitInjectNoticeSource();
    EXPECT_FALSE(ret);
    manager.isStartSrv_ = true;
    ret = handler.InitInjectNoticeSource();
    EXPECT_FALSE(ret);
    manager.connectionCallback_ = new (std::nothrow) InjectNoticeManager::InjectNoticeConnection;
    manager.connectionCallback_->isConnected_ = false;
    ret = handler.InitInjectNoticeSource();
    EXPECT_FALSE(ret);
    manager.connectionCallback_->isConnected_ = true;
    ret = handler.InitInjectNoticeSource();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ServerMsgHandlerTest_QueryAuthorizedStatus001
 * @tc.desc: Test the function QueryAuthorizedStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_QueryAuthorizedStatus001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_SELECTION_AUTHORIZE;
    int32_t callingPid = 1;
    int32_t status = 1;
    int32_t result = handler.QueryAuthorizedStatus(callingPid, status);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_RequestInjection_002
 * @tc.desc: Test the function RequestInjection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_RequestInjection_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t callingPid = 1;
    int32_t status = 1;
    int32_t reqId = 1;
    auto isPC = handler.IsPC();
    if (!isPC) {
        auto result = handler.RequestInjection(callingPid, status, reqId);
        EXPECT_EQ(result, ERROR_DEVICE_NOT_SUPPORTED);
        return;
    }
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_AUTHORIZE;
    handler.OnCancelInjection(callingPid);
    auto result = handler.OnAuthorize(false);
    EXPECT_EQ(result, ERR_OK);
    result = handler.RequestInjection(callingPid, status, reqId);
    EXPECT_EQ(result, ERR_OK);
    result = handler.OnAuthorize(true);
    EXPECT_EQ(result, ERR_OK);
}

/**
@tc.name: ServerMsgHandlerTest_ChangeToOld_007
@tc.desc: Test ChangeToOld
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_ChangeToOld_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;

    DisplayGroupInfo displayGroupInfo1;
    displayGroupInfo1.id = 0;
    displayGroupInfo1.type = GroupType::GROUP_DEFAULT;
    displayGroupInfo1.mainDisplayId = 0;
    displayGroupInfo1.focusWindowId = GLOBAL_WINDOW_ID;

    DisplayGroupInfo displayGroupInfo2;
    displayGroupInfo2.id = 1;
    displayGroupInfo2.type = GroupType::GROUP_SPECIAL;
    displayGroupInfo2.mainDisplayId = 1;
    displayGroupInfo2.focusWindowId = GLOBAL_WINDOW_ID;

    DisplayGroupInfo displayGroupInfo3;
    displayGroupInfo3.id = 2;
    displayGroupInfo3.type = GroupType::GROUP_DEFAULT;
    displayGroupInfo3.mainDisplayId = 2;
    displayGroupInfo3.focusWindowId = GLOBAL_WINDOW_ID;

    DisplayGroupInfo displayGroupInfo4;
    displayGroupInfo3.id = 3;
    displayGroupInfo3.type = GroupType::GROUP_SPECIAL;
    displayGroupInfo3.mainDisplayId = 3;
    displayGroupInfo3.focusWindowId = DEFAULT_GROUP_ID;

    userScreenInfo.displayGroups = {displayGroupInfo1, displayGroupInfo2, displayGroupInfo3, displayGroupInfo4};

    ServerMsgHandler handler;
    EXPECT_FALSE(handler.ChangeToOld(userScreenInfo));
}

/**
 * @tc.name: ServerMsgHandlerTest_TestChangeToOld_008
 * @tc.desc: Test ChangeToOld
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_TestChangeToOld_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    size_t num {1};
    std::vector<DisplayInfo> displaysInfos;
    DisplayInfo display;
    display.width = 1920;
    display.height = 1080;
    display.direction = DIRECTION180;
    display.screenArea.id = 2;
    display.screenArea.area.width = 0;
    display.screenArea.area.height = 0;
    displaysInfos.push_back(display);
    std::vector<ScreenInfo> screens;
    ScreenInfo screenInfo;
    screenInfo.id = 1;
    screens.push_back(screenInfo);
    ServerMsgHandler handler;
    ASSERT_NO_FATAL_FAILURE(handler.ChangeToOld(num, displaysInfos, screens));
    display.direction = DIRECTION90;
    displaysInfos = {display};
    ASSERT_NO_FATAL_FAILURE(handler.ChangeToOld(num, displaysInfos, screens));
    display.direction = DIRECTION270;
    displaysInfos = {display};
    ASSERT_NO_FATAL_FAILURE(handler.ChangeToOld(num, displaysInfos, screens));
}

/**
@tc.name: ServerMsgHandlerTest_OnWindowGroupInfo_005
@tc.desc: Test the function OnWindowGroupInfo
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnWindowGroupInfo_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    sess->SetTokenType(TOKEN_INVALID);
    int32_t p1 = 112;
    std::string p2 = "test111";
    NetPacket pkt(MmiMessageId::INVALID);
    pkt << p1 << p2;
    EXPECT_FALSE(pkt.ChkRWError());

    int32_t r1 = 0;
    std::string r2;
    pkt >> r1 >> r2;
    EXPECT_FALSE(pkt.ChkRWError());
    int32_t r3;
    pkt >> r3;
    EXPECT_TRUE(pkt.ChkRWError());

    Rect rec = {1, 1, 1, 1};
    std::vector recVec = {rec, rec};
    std::vector<int32_t> pChangeAreas = {1, 1, 1};
    std::vector transform = {1.0, 1.0, 1.0};

    int32_t ret = handler.OnWindowGroupInfo(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnGetFunctionKeyState_003
 * @tc.desc: Test the function OnGetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnGetFunctionKeyState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    int32_t funcKey = CAPS_LOCK_FUNCTION_KEY;
    bool state = true;
    AppExecFwk::RunningProcessInfo processInfo;
    processInfo.extensionType_ = AppExecFwk::ExtensionAbilityType::INPUTMETHOD;
    int32_t pid = 15;
    bool enable = true;
    AUTHORIZE_HELPER->state_ = AuthorizeState::STATE_UNAUTHORIZE;
    auto result = handler.NativeInjectCheck(pid);
    EXPECT_EQ(result, COMMON_PERMISSION_CHECK_ERROR);
    int32_t ret = handler.OnGetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, ERR_DEVICE_NOT_EXIST);
    ASSERT_NO_FATAL_FAILURE(handler.OnSetFunctionKeyState(pid, funcKey, enable));
    funcKey = 0;
    enable = false;
    ret = handler.OnGetFunctionKeyState(funcKey, state);
    ASSERT_NO_FATAL_FAILURE(handler.OnSetFunctionKeyState(pid, funcKey, enable));
    EXPECT_EQ(ret, ERR_DEVICE_NOT_EXIST);
    state = false;
    funcKey = 30;
    ret = handler.OnGetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, ERR_DEVICE_NOT_EXIST);
    funcKey = 10;
    state = false;
    ret = handler.OnGetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, ERR_DEVICE_NOT_EXIST);
}

/**
@tc.name: ServerMsgHandlerTest_SaveTargetWindowId_009
@tc.desc: Test the function SaveTargetWindowId
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SaveTargetWindowId_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    auto pointer = PointerEvent::Create();
    ASSERT_NE(pointer, nullptr);
    pointer->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointer->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    int32_t id = 100;
    PointerEvent::PointerItem item;
    item.SetPointerId(id);
    pointer->AddPointerItem(item);
    pointer->SetPointerId(0);
    pointer->SetZOrder(-1);
    int32_t ret = handler.SaveTargetWindowId(pointer, false);
    EXPECT_EQ(ret, RET_ERR);
    pointer->SetDeviceId(111);
    pointer->SetZOrder(1);
    pointer->SetPointerAction(PointerEvent::POINTER_ACTION_HOVER_ENTER);
    ret = handler.SaveTargetWindowId(pointer, false);
    EXPECT_EQ(ret, RET_ERR);
    pointer->SetDeviceId(-1);
    pointer->SetZOrder(-1);
    ret = handler.SaveTargetWindowId(pointer, false);
    EXPECT_EQ(ret, RET_ERR);
    ret = handler.SaveTargetWindowId(pointer, false);
    EXPECT_EQ(ret, RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_FixTargetWindowId_009
@tc.desc: Test FixTargetWindowId
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.shellTargetWindowIds_.clear();
    handler.castTargetWindowIds_.clear();
    handler.accessTargetWindowIds_.clear();
    handler.nativeTargetWindowIds_.clear();
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = PointerEvent::POINTER_INITIAL_VALUE;
    std::vector<int32_t> pointerIds {pointerEvent->GetPointerIds()};
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetDeviceId(111);
    pointerEvent->SetZOrder(1);
    bool result = handler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_FALSE(result);
    handler.shellTargetWindowIds_[0] = 0;
    action = PointerEvent::POINTER_ACTION_UNKNOWN;
    pointerEvent->SetDeviceId(CAST_INPUT_DEVICEID);
    pointerEvent->SetZOrder(-1);
    result = handler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_FALSE(result);
    handler.shellTargetWindowIds_[0] = 1;
    action = PointerEvent::POINTER_ACTION_CANCEL;
    pointerEvent->SetZOrder(0);
    result = handler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_FALSE(result);
    pointerEvent->pointers_.clear();
    action = PointerEvent::POINTER_ACTION_DOWN;
    pointerEvent->SetZOrder(1);
    result = handler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: ServerMsgHandlerTest_DealGesturePointers
 * @tc.desc: Test the function DealGesturePointers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, DealGesturePointers003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetId(1);
    pointerEvent->eventType_ = 1;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    handler.nativeTargetWindowIds_.insert(std::make_pair(pointerEvent->GetPointerId(), 10));
    std::list<PointerEvent::PointerItem> pointers_;
    PointerEvent::PointerItem item1;
    item1.SetPointerId(1);
    PointerEvent::PointerItem item2;
    item2.SetPointerId(2);
    pointers_.push_back(item1);
    pointers_.push_back(item2);
    pointerEvent->AddPointerItem(item1);
    pointerEvent->AddPointerItem(item2);
    bool ret = pointerEvent->GetPointerItem(pointerEvent->pointerId_, item2);
    EXPECT_FALSE(ret);
    ASSERT_NO_FATAL_FAILURE(handler.DealGesturePointers(pointerEvent));
}

/**
@tc.name: ServerMsgHandlerTest_FixTargetWindowId_01
@tc.desc: Test FixTargetWindowId
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.shellTargetWindowIds_.clear();
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    std::map<int32_t, int32_t> targetWindowIdMap = {
        {PointerEvent::SOURCE_TYPE_MOUSE, PointerEvent::SOURCE_TYPE_TOUCHSCREEN},
        {PointerEvent::POINTER_ACTION_BUTTON_DOWN, PointerEvent::POINTER_ACTION_DOWN},
        {PointerEvent::MOUSE_BUTTON_LEFT, PointerEvent::POINTER_INITIAL_VALUE}
    };
    bool bNeedResetPointerId = false;
    int32_t diffPointerId = 0;
    int32_t result = handler.FixTargetWindowId(pointerEvent, targetWindowIdMap, bNeedResetPointerId, diffPointerId);
    EXPECT_EQ(result, RET_ERR);
}

/**
@tc.name: ServerMsgHandlerTest_FixTargetWindowId_02
@tc.desc: Test FixTargetWindowId
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_FixTargetWindowId02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    handler.shellTargetWindowIds_.clear();
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    pointerEvent->SetPointerId(999);
    std::map<int32_t, int32_t> targetWindowIdMap;
    bool bNeedResetPointerId = true;
    int32_t diffPointerId = 0;
    int32_t result = handler.FixTargetWindowId(pointerEvent, targetWindowIdMap, bNeedResetPointerId, diffPointerId);
    EXPECT_EQ(result, RET_ERR);

    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    bNeedResetPointerId = true;
    diffPointerId = -5;
    result = handler.FixTargetWindowId(pointerEvent, targetWindowIdMap, bNeedResetPointerId, diffPointerId);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnDisplayInfo_08
 * @tc.desc: Test the function OnDisplayInfo_08
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo_08, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    sess->SetTokenType(TokenType::TOKEN_NATIVE);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    int32_t userId = 0;
    pkt << userId;
    uint32_t screenNum = 1;
    pkt << screenNum;
    ScreenInfo screenInfo;
    pkt << screenInfo.id << screenInfo.uniqueId << screenInfo.screenType << screenInfo.width << screenInfo.height
        << screenInfo.physicalWidth << screenInfo.physicalHeight << screenInfo.tpDirection << screenInfo.dpi
        << screenInfo.ppi << screenInfo.rotation;
    uint32_t groupNum = 1;
    pkt << groupNum;
    DisplayGroupInfo groupInfo;
    pkt << groupInfo.id << groupInfo.name << groupInfo.type << groupInfo.mainDisplayId << groupInfo.focusWindowId;
    uint32_t displayNum = 1;
    pkt << displayNum;
    DisplayInfo displayInfo;
    pkt << displayInfo.id << displayInfo.x << displayInfo.y << displayInfo.width << displayInfo.height
        << displayInfo.dpi << displayInfo.name << displayInfo.direction << displayInfo.displayDirection
        << displayInfo.displayMode << displayInfo.transform << displayInfo.scalePercent << displayInfo.expandHeight
        << displayInfo.isCurrentOffScreenRendering << displayInfo.displaySourceMode << displayInfo.oneHandX
        << displayInfo.oneHandY << displayInfo.screenArea << displayInfo.rsId << displayInfo.offsetX
        << displayInfo.offsetY << displayInfo.pointerActiveWidth << displayInfo.pointerActiveHeight;
    uint32_t windowNum = 1;
    pkt << windowNum;
    WindowInfo windowInfo;
    int32_t byteCount = 0;
    pkt << windowInfo.id << windowInfo.pid << windowInfo.uid << windowInfo.area << windowInfo.defaultHotAreas
        << windowInfo.pointerHotAreas << windowInfo.agentWindowId << windowInfo.flags << windowInfo.action
        << windowInfo.displayId << windowInfo.groupId << windowInfo.zOrder << windowInfo.pointerChangeAreas
        << windowInfo.transform << windowInfo.windowInputType << windowInfo.privacyMode << windowInfo.windowType
        << windowInfo.isSkipSelfWhenShowOnVirtualScreen << windowInfo.windowNameType << byteCount;
    int32_t result = handler.OnDisplayInfo(sess, pkt);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnDisplayInfo_09
 * @tc.desc: Test the function OnDisplayInfo_09
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo_09, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    sess->SetTokenType(TokenType::TOKEN_HAP);
    NetPacket pkt(MmiMessageId::DISPLAY_INFO);
    int32_t result = handler.OnDisplayInfo(sess, pkt);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnRemoveInputHandler_002
 * @tc.desc: Test the function OnRemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnRemoveInputHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = nullptr;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 0x01;
    EXPECT_EQ(
        handler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags), ERROR_NULL_POINTER);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    handlerType = InputHandlerType::NONE;
    priority = 2;
    deviceTags = 3;
    auto ret = handler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, RET_OK);
    ret = handler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS
