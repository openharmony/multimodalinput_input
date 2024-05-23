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
#include "util_napi_error.h"

#include "define_multimodal.h"
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
const int32_t NUM_LOCK_FUNCTION_KEY = 0;
const int32_t CAPS_LOCK_FUNCTION_KEY = 1;
const int32_t SCROLL_LOCK_FUNCTION_KEY = 2;
constexpr int32_t SECURITY_COMPONENT_SERVICE_ID = 3050;
} // namespace

class ServerMsgHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

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
    void* pixelMap = nullptr;
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
    int32_t result = servermsghandler.OnInjectPointerEvent(pointerEvent, pid, isNativeInject);
    EXPECT_EQ(result, COMMON_PERMISSION_CHECK_ERROR);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAuthorize_01
 * @tc.desc: Test OnAuthorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAuthorize_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    bool isAuthorize = true;
    InjectionType InjectionType_ = InjectionType::KEYEVENT;
    int32_t result = servermsghandler.OnAuthorize(isAuthorize);
    EXPECT_EQ(result, ERR_OK);
    InjectionType_ = InjectionType::POINTEREVENT;
    result = servermsghandler.OnAuthorize(isAuthorize);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ServerMsgHandlerTest_OnAuthorize_02
 * @tc.desc: Test OnAuthorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ServerMsgHandlerTest, ServerMsgHandlerTest_OnAuthorize_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ServerMsgHandler servermsghandler;
    bool isAuthorize = false;
    int32_t result = servermsghandler.OnAuthorize(isAuthorize);
    EXPECT_EQ(result, ERR_OK);
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
    bool result = servermsghandler.FixTargetWindowId(pointerEvent, action);
    ASSERT_TRUE(result);
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
    bool result = servermsghandler.FixTargetWindowId(pointerEvent, action);
    ASSERT_TRUE(result);
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
    bool result = servermsghandler.FixTargetWindowId(pointerEvent, action);
    ASSERT_TRUE(result);
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
    int32_t ret = handler.OnInjectPointerEventExt(pointerEvent);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
    pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    int32_t sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    ret = handler.OnInjectPointerEventExt(pointerEvent);
    EXPECT_EQ(ret, RET_OK);
    sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    EXPECT_NO_FATAL_FAILURE(handler.OnInjectPointerEventExt(pointerEvent));
    sourceType = PointerEvent::SOURCE_TYPE_JOYSTICK;
    EXPECT_NO_FATAL_FAILURE(handler.OnInjectPointerEventExt(pointerEvent));
    sourceType = PointerEvent::SOURCE_TYPE_TOUCHPAD;
    EXPECT_NO_FATAL_FAILURE(handler.OnInjectPointerEventExt(pointerEvent));
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
} // namespace MMI
} // namespace OHOS