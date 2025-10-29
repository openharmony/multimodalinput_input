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
#include <gtest/gtest.h>

#include <fstream>

#include "error_multimodal.h"
#include "i_input_event_consumer.h"
#include "input_event_hook_handler.h"
#include "input_event_stager.h"
#include "mmi_log.h"
#include "multimodal_input_connect_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEventHookHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
using namespace testing;
std::shared_ptr<MultimodalInputConnectManager> g_instance = nullptr;
} // namespace

std::shared_ptr<MultimodalInputConnectManager> MultimodalInputConnectManager::GetInstance()
{
    if (g_instance == nullptr) {
        g_instance = std::make_shared<MultimodalInputConnectManager>();
    }
    return g_instance;
}

int32_t MultimodalInputConnectManager::AddInputEventHook(HookEventType hookEventType)
{
    if (hookEventType > HOOK_EVENT_TYPE_KEY + HOOK_EVENT_TYPE_MOUSE + HOOK_EVENT_TYPE_TOUCH) {
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectManager::RemoveInputEventHook(HookEventType hookEventType)
{
    if (hookEventType > HOOK_EVENT_TYPE_KEY + HOOK_EVENT_TYPE_MOUSE + HOOK_EVENT_TYPE_TOUCH) {
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectManager::DispatchToNextHandler(const std::shared_ptr<KeyEvent> keyEvent)
{
    if (keyEvent == nullptr) {
        return RET_ERR;
    }
    return RET_OK;
}

int32_t MultimodalInputConnectManager::DispatchToNextHandler(const std::shared_ptr<PointerEvent> pointerEvent)
{
    if (pointerEvent == nullptr) {
        return RET_ERR;
    }
    return RET_OK;
}

InputEventStager &InputEventStager::GetInstance()
{
    static InputEventStager instance;
    return instance;
}

std::shared_ptr<KeyEvent> InputEventStager::GetKeyEvent(int32_t eventId)
{
    if (eventId == 0) {
        return nullptr;
    } else {
        auto keyEvent = KeyEvent::Create();
        return keyEvent;
    }
}

std::shared_ptr<PointerEvent> InputEventStager::GetTouchEvent(int32_t eventId)
{
    if (eventId == 0) {
        return nullptr;
    } else {
        auto keyEvent = PointerEvent::Create();
        return keyEvent;
    }
}

std::shared_ptr<PointerEvent> InputEventStager::GetMouseEvent(int32_t eventId)
{
    if (eventId == 0) {
        return nullptr;
    } else {
        auto keyEvent = PointerEvent::Create();
        return keyEvent;
    }
}

int32_t InputEventStager::UpdateKeyEvent(std::shared_ptr<KeyEvent> event)
{
    return RET_OK;
}

int32_t InputEventStager::UpdateTouchEvent(std::shared_ptr<PointerEvent> event)
{
    return RET_OK;
}

int32_t InputEventStager::UpdateMouseEvent(std::shared_ptr<PointerEvent> event)
{
    return RET_OK;
}

void InputEventStager::ClearStashEvents(HookEventType hookEventType) {}

class HookConsumer : public IInputEventConsumer {
public:
    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const { g_flag = 1; }
    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const { g_flag = 2; }
    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const { g_flag = 4; }
public:
    static int32_t g_flag;
};

int32_t HookConsumer::g_flag = 0;

class InputEventHookHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

void ClearData()
{
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 0;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = nullptr;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = nullptr;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = nullptr;
}

/**
 * @tc.name: InputEventHookHandlerTest_AddInputEventHookLocal_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_AddInputEventHookLocal_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    HookEventType hookEventType = 7;
    auto ret = INPUT_EVENT_HOOK_HANDLER.AddInputEventHookLocal(consumer, hookEventType);
    EXPECT_EQ(ret, RET_OK);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_AddInputEventHookLocal_002
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_AddInputEventHookLocal_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    HookEventType hookEventType = 0;
    auto ret = INPUT_EVENT_HOOK_HANDLER.AddInputEventHookLocal(consumer, hookEventType);
    EXPECT_EQ(ret, RET_OK);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_AddInputEventHook_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_AddInputEventHook_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    HookEventType hookEventType = 1;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 1;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    auto ret = INPUT_EVENT_HOOK_HANDLER.AddInputEventHook(consumer, hookEventType);
    EXPECT_EQ(ret, ERROR_REPEAT_INTERCEPTOR);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_AddInputEventHook_002
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_AddInputEventHook_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    HookEventType hookEventType = 8;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 0;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    auto ret = INPUT_EVENT_HOOK_HANDLER.AddInputEventHook(consumer, hookEventType);
    EXPECT_EQ(ret, RET_ERR);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_AddInputEventHook_003
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_AddInputEventHook_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    HookEventType hookEventType = 0;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 0;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    auto ret = INPUT_EVENT_HOOK_HANDLER.AddInputEventHook(consumer, hookEventType);
    EXPECT_EQ(ret, RET_OK);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_RemoveInputEventHookLocal_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_RemoveInputEventHookLocal_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    HookEventType hookEventType = 7;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 7;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    auto ret = INPUT_EVENT_HOOK_HANDLER.RemoveInputEventHookLocal(hookEventType);
    EXPECT_EQ(ret, RET_OK);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_RemoveInputEventHookLocal_002
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_RemoveInputEventHookLocal_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    HookEventType hookEventType = 0;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 0;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    auto ret = INPUT_EVENT_HOOK_HANDLER.RemoveInputEventHookLocal(hookEventType);
    EXPECT_EQ(ret, RET_OK);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_RemoveInputEventHook_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_RemoveInputEventHook_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    HookEventType hookEventType = 8;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 0;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    auto ret = INPUT_EVENT_HOOK_HANDLER.RemoveInputEventHook(hookEventType);
    EXPECT_EQ(ret, RET_ERR);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_RemoveInputEventHook_002
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_RemoveInputEventHook_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    HookEventType hookEventType = 0;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 0;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    auto ret = INPUT_EVENT_HOOK_HANDLER.RemoveInputEventHook(hookEventType);
    EXPECT_EQ(ret, RET_OK);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_DispatchToNextHandler_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_DispatchToNextHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    int32_t eventId = 0;
    HookEventType hookEventType = 1;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 1;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    auto ret = INPUT_EVENT_HOOK_HANDLER.DispatchToNextHandler(eventId, hookEventType);
    EXPECT_EQ(ret, ERROR_INVALID_PARAMETER);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_DispatchToNextHandler_002
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_DispatchToNextHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    int32_t eventId = 0;
    HookEventType hookEventType = 4;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 4;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    auto ret = INPUT_EVENT_HOOK_HANDLER.DispatchToNextHandler(eventId, hookEventType);
    EXPECT_EQ(ret, ERROR_INVALID_PARAMETER);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_DispatchToNextHandler_003
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_DispatchToNextHandler_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    int32_t eventId = 0;
    HookEventType hookEventType = 2;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 2;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    auto ret = INPUT_EVENT_HOOK_HANDLER.DispatchToNextHandler(eventId, hookEventType);
    EXPECT_EQ(ret, ERROR_INVALID_PARAMETER);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_DispatchToNextHandler_004
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_DispatchToNextHandler_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    int32_t eventId = 0;
    HookEventType hookEventType = 8;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 0;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    auto ret = INPUT_EVENT_HOOK_HANDLER.DispatchToNextHandler(eventId, hookEventType);
    EXPECT_EQ(ret, RET_ERR);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_DispatchToNextHandler_005
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_DispatchToNextHandler_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    auto ret = INPUT_EVENT_HOOK_HANDLER.DispatchToNextHandler(keyEvent);
    EXPECT_EQ(ret, RET_ERR);
    ClearData();

    keyEvent = KeyEvent::Create();
    ret = INPUT_EVENT_HOOK_HANDLER.DispatchToNextHandler(keyEvent);
    EXPECT_EQ(ret, RET_OK);
    ClearData();

    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    ret = INPUT_EVENT_HOOK_HANDLER.DispatchToNextHandler(pointerEvent);
    EXPECT_EQ(ret, RET_ERR);
    ClearData();

    pointerEvent = PointerEvent::Create();
    ret = INPUT_EVENT_HOOK_HANDLER.DispatchToNextHandler(pointerEvent);
    EXPECT_EQ(ret, RET_OK);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_OnPointerEvent_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_OnPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 2;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.OnPointerEvent(pointerEvent);
    EXPECT_EQ(consumer->g_flag, 2);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_OnPointerEvent_002
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_OnPointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 4;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.OnPointerEvent(pointerEvent);
    EXPECT_EQ(consumer->g_flag, 2);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_OnPointerEvent_003
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_OnPointerEvent_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 0;
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.keyHookCallback_ = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.mouseHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.hookConsumer_.touchHookCallback_ = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.OnPointerEvent(pointerEvent);
    EXPECT_EQ(consumer->g_flag, 0);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_AddKeyHook_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_AddKeyHook_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 0;
    INPUT_EVENT_HOOK_HANDLER.OnConnected();
    std::function<void(std::shared_ptr<KeyEvent>)> keyHook = [consumer](std::shared_ptr<KeyEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.AddKeyHook(keyHook);
    INPUT_EVENT_HOOK_HANDLER.OnConnected();
    EXPECT_EQ(INPUT_EVENT_HOOK_HANDLER.currentHookStats_, 1);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_AddMouseHook_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_AddMouseHook_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 0;
    std::function<void(std::shared_ptr<PointerEvent>)> mouseHook = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.AddMouseHook(mouseHook);
    INPUT_EVENT_HOOK_HANDLER.OnConnected();
    EXPECT_EQ(INPUT_EVENT_HOOK_HANDLER.currentHookStats_, 4);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_AddTouchHook_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_AddTouchHook_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto consumer = std::make_shared<HookConsumer>();
    consumer->g_flag = 0;
    INPUT_EVENT_HOOK_HANDLER.currentHookStats_ = 0;
    std::function<void(std::shared_ptr<PointerEvent>)> touchHook = [consumer](std::shared_ptr<PointerEvent> event) {
        consumer->OnInputEvent(event);
    };
    INPUT_EVENT_HOOK_HANDLER.AddTouchHook(touchHook);
    INPUT_EVENT_HOOK_HANDLER.OnConnected();
    EXPECT_EQ(INPUT_EVENT_HOOK_HANDLER.currentHookStats_, 2);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_AddInputEventHookToServer_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_AddInputEventHookToServer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    HookEventType hookEventType = 0;
    auto ret = INPUT_EVENT_HOOK_HANDLER.AddInputEventHookToServer(hookEventType);
    EXPECT_EQ(ret, RET_OK);
    ClearData();

    hookEventType = 8;
    ret = INPUT_EVENT_HOOK_HANDLER.AddInputEventHookToServer(hookEventType);
    EXPECT_EQ(ret, RET_ERR);
    ClearData();
}

/**
 * @tc.name: InputEventHookHandlerTest_RemoveInputEventHookOfServer_001
 * @tc.desc: Test the function NotifyDevCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookHandlerTest, InputEventHookHandlerTest_RemoveInputEventHookOfServer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    HookEventType hookEventType = 0;
    auto ret = INPUT_EVENT_HOOK_HANDLER.RemoveInputEventHookOfServer(hookEventType);
    EXPECT_EQ(ret, RET_OK);
    ClearData();

    hookEventType = 8;
    ret = INPUT_EVENT_HOOK_HANDLER.RemoveInputEventHookOfServer(hookEventType);
    EXPECT_EQ(ret, RET_ERR);
    ClearData();
}
} // namespace MMI
} // namespace OHOS
