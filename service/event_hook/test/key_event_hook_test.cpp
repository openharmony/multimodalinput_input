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
#include <gmock/gmock.h>
#include "key_event_hook_manager.h"
#include "key_event_hook.h"
#include "input_event_hook.h"
#include "event_dispatch_handler.h"
#include "event_loop_closure_checker.h"
#include "event_dispatch_order_checker.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_event_handler.h"
#include "uds_server.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventHookTest"

namespace OHOS {
namespace MMI {
namespace {
const std::string PROGRAM_NAME = "uds_server_test";
constexpr int32_t MODULE_TYPE = 1;
constexpr int32_t UDS_FD = -1;
constexpr int32_t UDS_UID = 456;
constexpr int32_t UDS_PID = 123;
constexpr int32_t NANOSECOND_TO_MILLISECOND = 1000000;
constexpr int32_t SEC_TO_NANOSEC = 1000000000;
using namespace testing::ext;
} // namespace

class KeyEventHookTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

int64_t GetNanoTime()
{
    struct timespec time = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (static_cast<int64_t>(time.tv_sec) * SEC_TO_NANOSEC) + static_cast<int64_t>(time.tv_nsec);
}

/**
 * @tc.name: KeyEventHookTest001
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookTest, KeyEventHookTest001, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    KeyEventHook hook(sess, nextHookGetter);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetRepeatKey(true);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_A);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->AddPressedKeyItems(kitDown);
    bool result = hook.OnKeyEvent(keyEvent);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: KeyEventHookTest002
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookTest, KeyEventHookTest002, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [this] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetRepeatKey(true);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_A);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddPressedKeyItems(kitDown);
    KeyEventHook hook(sess, nextHookGetter);
    int32_t eventId = 1;
    int32_t eventId1 = 0;
    keyEvent->SetId(eventId);
    hook.orderChecker_.UpdateEvent(eventId1);
    int32_t result = hook.DispatchToNextHandler(keyEvent);
    EXPECT_EQ(result, ERROR_INVALID_PARAMETER);
}

/**
 * @tc.name: KeyEventHookTest003
 * @tc.desc: Test the function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookTest, KeyEventHookTest003, TestSize.Level0)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    NextHookGetter nextHookGetter = [this] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> {
        return nullptr;
    };
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_VOLUME_DOWN);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->SetRepeatKey(true);
    int64_t downTime = GetNanoTime() / NANOSECOND_TO_MILLISECOND;
    KeyEvent::KeyItem kitDown;
    kitDown.SetKeyCode(KeyEvent::KEYCODE_A);
    kitDown.SetPressed(true);
    kitDown.SetDownTime(downTime);
    keyEvent->SetKeyCode(KeyEvent::KEYCODE_A);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    keyEvent->AddPressedKeyItems(kitDown);
    KeyEventHook hook(sess, nextHookGetter);
    int32_t eventId = 1;
    int32_t eventId1 = 0;
    keyEvent->SetId(eventId);
    hook.orderChecker_.UpdateEvent(eventId1);
    bool result = hook.DispatchDirectly(keyEvent);
    EXPECT_FALSE(result);
}
} // namespace MMI
} // namespace OHOS