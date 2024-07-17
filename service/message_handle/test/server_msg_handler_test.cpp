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

#include <cinttypes>
#include <cstdio>

#include <gtest/gtest.h>
#include "input_event_handler.h"
#include "libinput.h"
#include "pixel_map.h"
#include "sec_comp_enhance_kit.h"

#include "define_multimodal.h"
#include "image_source.h"
#include "inject_notice_manager.h"
#include "mmi_log.h"
#include "pointer_event.h"
#include "server_msg_handler.h"
#include "stream_buffer.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ServerMsgHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t UID_ROOT { 0 };
static constexpr char PROGRAM_NAME[] = "uds_sesion_test";
int32_t g_moduleType = 3;
int32_t g_pid = 0;
int32_t g_writeFd = -1;
constexpr int32_t NUM_LOCK_FUNCTION_KEY = 0;
constexpr int32_t CAPS_LOCK_FUNCTION_KEY = 1;
constexpr int32_t SCROLL_LOCK_FUNCTION_KEY = 2;
constexpr int32_t SECURITY_COMPONENT_SERVICE_ID = 3050;
constexpr int32_t MOUSE_ICON_SIZE = 64;
constexpr int32_t COMMON_PERMISSION_CHECK_ERROR { 201 };
} // namespace

class ServerMsgHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
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
 * @tc.name: ServerMsgHandlerTest_SetPixelMapData_01
 * @tc.desc: Test SetPixelMapData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SetPixelMapData_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    int32_t infoId = -1;
    void* pixelMap = nullptr;
    int32_t result = servermsghandler.SetPixelMapData(infoId, pixelMap);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/**
 * @tc.name: ServerMsgHandlerTest_SetPixelMapData_02
 * @tc.desc: Test SetPixelMapData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SetPixelMapData_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    int32_t infoId = 2;
    void* pixelMap = nullptr;
    int32_t result = servermsghandler.SetPixelMapData(infoId, pixelMap);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/**
 * @tc.name: ServerMsgHandlerTest_SetPixelMapData_03
 * @tc.desc: Test SetPixelMapData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_SetPixelMapData_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    int32_t infoId = -1;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    PointerStyle pointerStyle;
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = ServerMsgHandlerTest::SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    int32_t result = servermsghandler.SetPixelMapData(infoId, (void *)pixelMap.get());
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
    int32_t result = servermsghandler.OnInjectPointerEvent(pointerEvent, pid, isNativeInject, false);
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
    EXPECT_EQ(servermsghandler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags),
        ERROR_NULL_POINTER);
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
    EXPECT_EQ(servermsghandler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags),
        ERROR_NULL_POINTER);
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
    EXPECT_EQ(servermsghandler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags),
        ERROR_NULL_POINTER);
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
    EXPECT_EQ(servermsghandler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags),
        ERROR_NULL_POINTER);
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
    EXPECT_EQ(servermsghandler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags),
        ERROR_NULL_POINTER);
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
    EXPECT_EQ(servermsghandler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags),
        ERROR_NULL_POINTER);
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
    EXPECT_EQ(servermsghandler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags), RET_OK);
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
    EXPECT_EQ(servermsghandler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags), RET_OK);
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
    EXPECT_EQ(servermsghandler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags), RET_OK);
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
    EXPECT_EQ(servermsghandler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags), RET_OK);
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
    EXPECT_EQ(servermsghandler.OnMarkConsumed(sess, eventId), RET_OK);
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
    EXPECT_EQ(ret, RET_OK);
    funcKey = CAPS_LOCK_FUNCTION_KEY;
    ret = handler.OnGetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, RET_OK);
    funcKey = SCROLL_LOCK_FUNCTION_KEY;
    ret = handler.OnGetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, RET_OK);
    funcKey = 10;
    state = true;
    ret = handler.OnGetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, RET_OK);
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
    int32_t ret = handler.OnInjectPointerEventExt(pointerEvent, false);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    int32_t sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    ret = handler.OnInjectPointerEventExt(pointerEvent, false);
    EXPECT_EQ(ret, RET_OK);
    sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    EXPECT_NO_FATAL_FAILURE(handler.OnInjectPointerEventExt(pointerEvent, false));
    sourceType = PointerEvent::SOURCE_TYPE_JOYSTICK;
    EXPECT_NO_FATAL_FAILURE(handler.OnInjectPointerEventExt(pointerEvent, false));
    sourceType = PointerEvent::SOURCE_TYPE_TOUCHPAD;
    EXPECT_NO_FATAL_FAILURE(handler.OnInjectPointerEventExt(pointerEvent, false));
}

/**
 * @tc.name: ServerMsgHandlerTest_OnWindowAreaInfo_001
 * @tc.desc: Test the function OnWindowAreaInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnWindowAreaInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = nullptr;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    int32_t ret = handler.OnWindowAreaInfo(sess, pkt);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    CircleStreamBuffer::ErrorStatus rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    ret = handler.OnWindowAreaInfo(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    ret = handler.OnWindowAreaInfo(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
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
    int32_t uid_ = 1;
    ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    uid_ = SECURITY_COMPONENT_SERVICE_ID;
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
    DisplayInfo displayInfo;
    displayInfo.id = -1;
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
    DisplayInfo displayInfo;
    displayInfo.id = -1;
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
    DisplayInfo displayInfo;
    displayInfo.id = -1;
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
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.displayDirection = DIRECTION0;
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
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.displayDirection = DIRECTION90;
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
    DisplayInfo displayInfo;
    displayInfo.id = 1;
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
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    int32_t ret = handler.SaveTargetWindowId(pointerEvent, false);
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
    std::vector<int32_t> pointerIds { pointerEvent->GetPointerIds() };
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
    std::vector<int32_t> pointerIds { pointerEvent->GetPointerIds() };
    int32_t pointerId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    DisplayInfo displayInfo;
    displayInfo.id = 1;
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
    std::vector<int32_t> pointerIds { pointerEvent->GetPointerIds() };
    int32_t pointerId = 1;
    PointerEvent::PointerItem item;
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    bool result = handler.FixTargetWindowId(pointerEvent, action, false);
    ASSERT_FALSE(result);
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
    HandleEventType eventType =1;
    int32_t priority = 2;
    uint32_t deviceTags = 3;
    int32_t ret = handler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ret = handler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, RET_OK);
    handlerType = InputHandlerType::MONITOR;
    ret = handler.OnRemoveInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, RET_OK);
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
    HandleEventType eventType =1;
    int32_t priority = 2;
    uint32_t deviceTags = 3;
    int32_t ret = handler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    ret = handler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, RET_OK);
    handlerType = InputHandlerType::MONITOR;
    ret = handler.OnAddInputHandler(sess, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, RET_OK);
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
    int32_t CurrentPID_ = 12;
    int32_t ret = handler.OnCancelInjection();
    EXPECT_EQ(ret, ERR_OK);
    CurrentPID_ = 1;
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
    int32_t uid_ = 123;
    ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    uid_ = SECURITY_COMPONENT_SERVICE_ID;
    CircleStreamBuffer::ErrorStatus rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    EXPECT_NO_FATAL_FAILURE(handler.OnEnhanceConfig(sess, pkt));
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
    EXPECT_NE(msgHandler.OnInjectPointerEventExt(pointerEvent, false), RET_ERR);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_RAW_POINTER_MOVEMENT;
    EXPECT_NE(msgHandler.OnInjectPointerEventExt(pointerEvent, false), RET_ERR);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NONE);
    EXPECT_NE(msgHandler.OnInjectPointerEventExt(pointerEvent, false), RET_OK);

    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_HIDE_POINTER;
    EXPECT_NE(msgHandler.OnInjectPointerEventExt(pointerEvent, false), RET_OK);
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
    EXPECT_EQ(msgHandler.OnInjectPointerEvent(pointerEvent, pid, isNativeInject, false), COMMON_PERMISSION_CHECK_ERROR);
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
    EXPECT_NE(msgHandler.OnInjectPointerEvent(pointerEvent, pid, isNativeInject, false), RET_OK);
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
    EXPECT_NE(msgHandler.OnInjectPointerEvent(pointerEvent, pid, isNativeInject, false), RET_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_CalculateOffset_01
 * @tc.desc: Test CalculateOffset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_CalculateOffset_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    Direction direction;
    Offset offset;
    direction = DIRECTION90;
    ASSERT_NO_FATAL_FAILURE(servermsghandler.CalculateOffset(direction, offset));
}

/**
 * @tc.name: ServerMsgHandlerTest_CalculateOffset_02
 * @tc.desc: Test CalculateOffset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_CalculateOffset_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    Direction direction;
    Offset offset;
    direction = DIRECTION180;
    ASSERT_NO_FATAL_FAILURE(servermsghandler.CalculateOffset(direction, offset));
}

/**
 * @tc.name: ServerMsgHandlerTest_CalculateOffset_03
 * @tc.desc: Test CalculateOffset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_CalculateOffset_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    Direction direction;
    Offset offset;
    direction = DIRECTION270;
    ASSERT_NO_FATAL_FAILURE(servermsghandler.CalculateOffset(direction, offset));
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
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME,
        g_moduleType, g_writeFd, SECURITY_COMPONENT_SERVICE_ID - 1, g_pid);
    int32_t ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd,
        SECURITY_COMPONENT_SERVICE_ID, g_pid);
    CircleStreamBuffer::ErrorStatus rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    ret = handler.OnEnhanceConfig(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
    rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    EXPECT_NO_FATAL_FAILURE(handler.OnEnhanceConfig(sess, pkt));
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
    void* pixelMap = nullptr;
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
    handler.injectNotice_ =nullptr;
    bool ret = handler.InitInjectNoticeSource();
    EXPECT_TRUE(ret);
    handler.injectNotice_ = std::make_shared<InjectNoticeManager>();
    manager.isStartSrv_ = false;
    ret = handler.InitInjectNoticeSource();
    EXPECT_TRUE(ret);
    manager.isStartSrv_ = true;
    ret = handler.InitInjectNoticeSource();
    EXPECT_TRUE(ret);
    manager.connectionCallback_ = new (std::nothrow) InjectNoticeManager::InjectNoticeConnection;
    manager.connectionCallback_->isConnected_ = false;
    ret = handler.InitInjectNoticeSource();
    EXPECT_TRUE(ret);
    manager.connectionCallback_->isConnected_ = true;
    ret = handler.InitInjectNoticeSource();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ServerMsgHandlerTest_InitInjectNoticeSource_01
 * @tc.desc: Test InitInjectNoticeSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_InitInjectNoticeSource_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    servermsghandler.injectNotice_ = nullptr;

    bool ret = servermsghandler.InitInjectNoticeSource();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnDisplayInfo_01
 * @tc.desc: Test the function OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnDisplayInfo_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler handler;
    SessionPtr sess = nullptr;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    int32_t ret = handler.OnDisplayInfo(sess, pkt);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);

    sess = std::make_shared<UDSSession>(PROGRAM_NAME, g_moduleType, g_writeFd, UID_ROOT, g_pid);
    CircleStreamBuffer::ErrorStatus rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_READ;
    ret = handler.OnDisplayInfo(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);

    rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_OK;
    ret = handler.OnDisplayInfo(sess, pkt);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnWindowGroupInfo_01
 * @tc.desc: Test the function OnWindowGroupInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnWindowGroupInfo_01, TestSize.Level1)
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
    DisplayGroupInfo displayGroupInfo {
        .width = 100,
        .height = 100,
        .focusWindowId = 10,
        .currentUserId = 20,
    };
    pkt << displayGroupInfo.width << displayGroupInfo.height
        << displayGroupInfo.focusWindowId << displayGroupInfo.currentUserId << num;
    pkt.rwErrorStatus_ = CircleStreamBuffer::ErrorStatus::ERROR_STATUS_WRITE;
    EXPECT_EQ(handler.OnDisplayInfo(sess, pkt), RET_ERR);
}
} // namespace MMI
} // namespace OHOS
