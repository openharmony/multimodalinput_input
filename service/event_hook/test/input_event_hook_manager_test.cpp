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
#include "input_event_hook.h"
#include "key_event_hook.h"
#include "pointer_event_hook.h"
#include "input_event_hook_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputEventHookManagerTest"

namespace OHOS {
namespace MMI {
namespace {
const std::string PROGRAM_NAME = "uds_server_test";
constexpr int32_t MODULE_TYPE = 1;
constexpr int32_t UDS_FD = -1;
constexpr int32_t UDS_UID = 456;
constexpr int32_t UDS_PID = 123;
using namespace testing::ext;
} // namespace
class InputEventHookManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: InputEventHookManagerTest_IsHookExisted001
 * @tc.desc: Test the function IsHookExisted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_IsHookExisted001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    hookMgr.hooks_[HOOK_EVENT_TYPE_TOUCH].push_back(
        std::make_shared<PointerEventHook>(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter));
    EXPECT_EQ(hookMgr.IsHookExisted(UDS_PID, HOOK_EVENT_TYPE_KEY), true);
    EXPECT_EQ(hookMgr.IsHookExisted(UDS_PID, HOOK_EVENT_TYPE_MOUSE), false);
}

/**
 * @tc.name: InputEventHookManagerTest_AddInputEventHook001
 * @tc.desc: Test the function AddInputEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_AddInputEventHook001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    EXPECT_EQ(hookMgr.AddInputEventHook(UDS_PID, HOOK_EVENT_TYPE_TOUCH), RET_ERR);
}

/**
 * @tc.name: InputEventHookManagerTest_RemoveKeyEventHook001
 * @tc.desc: Test the function AddInputEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_RemoveKeyEventHook001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    EXPECT_EQ(hookMgr.RemoveInputEventHook(UDS_PID, HOOK_EVENT_TYPE_TOUCH), RET_OK);
    EXPECT_EQ(hookMgr.RemoveInputEventHook(UDS_PID, HOOK_EVENT_TYPE_MOUSE), RET_OK);
    EXPECT_EQ(hookMgr.RemoveInputEventHook(UDS_PID, HOOK_EVENT_TYPE_KEY), RET_OK);
}

/**
 * @tc.name: InputEventHookManagerTest_DispatchToNextHandler001
 * @tc.desc: Test the function DispatchToNextHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_DispatchToNextHandler001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(1);
    EXPECT_EQ(hookMgr.DispatchToNextHandler(UDS_PID, keyEvent), ERROR_INVALID_PARAMETER);
}

/**
 * @tc.name: InputEventHookManagerTest_DispatchMouseToNextHandler001
 * @tc.desc: Test the function DispatchMouseToNextHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_DispatchMouseToNextHandler001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_MOUSE].push_back(
        std::make_shared<PointerEventHook>(sess, HOOK_EVENT_TYPE_MOUSE, nextHookGetter));
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    EXPECT_EQ(hookMgr.DispatchMouseToNextHandler(UDS_PID, pointerEvent), ERROR_INVALID_PARAMETER);
}

/**
 * @tc.name: InputEventHookManagerTest_DispatchTouchToNextHandler001
 * @tc.desc: Test the function DispatchTouchToNextHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_DispatchTouchToNextHandler001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_TOUCH].push_back(
        std::make_shared<PointerEventHook>(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter));
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    EXPECT_EQ(hookMgr.DispatchTouchToNextHandler(UDS_PID, pointerEvent), ERROR_INVALID_PARAMETER);
}

/**
 * @tc.name: InputEventHookManagerTest_HandleHooks001
 * @tc.desc: Test the function HandleHooks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandleHooks001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(1);
    EXPECT_FALSE(hookMgr.HandleHooks(keyEvent));
}

/**
 * @tc.name: InputEventHookManagerTest_HandleHooks002
 * @tc.desc: Test the function HandleHooks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandleHooks002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_TOUCH].push_back(
        std::make_shared<PointerEventHook>(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter));
    hookMgr.hooks_[HOOK_EVENT_TYPE_MOUSE].push_back(
        std::make_shared<PointerEventHook>(sess, HOOK_EVENT_TYPE_MOUSE, nextHookGetter));
    std::shared_ptr<PointerEvent> touchEvent = PointerEvent::Create();
    touchEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    EXPECT_FALSE(hookMgr.HandleHooks(touchEvent));
    std::shared_ptr<PointerEvent> mouseEvent = PointerEvent::Create();
    mouseEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    EXPECT_FALSE(hookMgr.HandleHooks(mouseEvent));
    std::shared_ptr<PointerEvent> otherEvent = PointerEvent::Create();
    otherEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    EXPECT_FALSE(hookMgr.HandleHooks(otherEvent));
}

/**
 * @tc.name: InputEventHookManagerTest_AddInputEventHook002
 * @tc.desc: Test AddInputEventHook with HOOK_EVENT_TYPE_KEY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_AddInputEventHook002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    EXPECT_EQ(hookMgr.AddInputEventHook(UDS_PID, HOOK_EVENT_TYPE_KEY), RET_ERR);
}

/**
 * @tc.name: InputEventHookManagerTest_AddInputEventHook003
 * @tc.desc: Test AddInputEventHook with combined hook event types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_AddInputEventHook003, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    int32_t combinedType = HOOK_EVENT_TYPE_KEY | HOOK_EVENT_TYPE_MOUSE | HOOK_EVENT_TYPE_TOUCH;
    EXPECT_EQ(hookMgr.AddInputEventHook(UDS_PID, combinedType), RET_ERR);
}

/**
 * @tc.name: InputEventHookManagerTest_AddInputEventHook004
 * @tc.desc: Test AddInputEventHook with invalid pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_AddInputEventHook004, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    EXPECT_EQ(hookMgr.AddInputEventHook(-1, HOOK_EVENT_TYPE_TOUCH), RET_ERR);
}

/**
 * @tc.name: InputEventHookManagerTest_RemoveInputEventHook002
 * @tc.desc: Test RemoveInputEventHook with combined hook event types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_RemoveInputEventHook002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    int32_t combinedType = HOOK_EVENT_TYPE_KEY | HOOK_EVENT_TYPE_MOUSE | HOOK_EVENT_TYPE_TOUCH;
    EXPECT_EQ(hookMgr.RemoveInputEventHook(UDS_PID, combinedType), RET_OK);
}

/**
 * @tc.name: InputEventHookManagerTest_RemoveInputEventHook003
 * @tc.desc: Test RemoveInputEventHook with invalid pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_RemoveInputEventHook003, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    EXPECT_EQ(hookMgr.RemoveInputEventHook(-1, HOOK_EVENT_TYPE_KEY), RET_OK);
}

/**
 * @tc.name: InputEventHookManagerTest_HandleKeyEvent001
 * @tc.desc: Test HandleKeyEvent with no hooks existed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandleKeyEvent001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(1);
    // Should not crash when nextHandler_ is null
    hookMgr.HandleKeyEvent(keyEvent);
}

/**
 * @tc.name: InputEventHookManagerTest_HandleKeyEvent002
 * @tc.desc: Test HandleKeyEvent with null keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandleKeyEvent002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    // Should not crash with null event
    hookMgr.HandleKeyEvent(keyEvent);
}

/**
 * @tc.name: InputEventHookManagerTest_HandlePointerEvent001
 * @tc.desc: Test HandlePointerEvent with no hooks existed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandlePointerEvent001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    // Should not crash when nextHandler_ is null
    hookMgr.HandlePointerEvent(pointerEvent);
}

/**
 * @tc.name: InputEventHookManagerTest_HandlePointerEvent002
 * @tc.desc: Test HandlePointerEvent with null pointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandlePointerEvent002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    // Should not crash with null event
    hookMgr.HandlePointerEvent(pointerEvent);
}

/**
 * @tc.name: InputEventHookManagerTest_HandleTouchEvent001
 * @tc.desc: Test HandleTouchEvent with no hooks existed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandleTouchEvent001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    // Should not crash when nextHandler_ is null
    hookMgr.HandleTouchEvent(pointerEvent);
}

/**
 * @tc.name: InputEventHookManagerTest_HandleTouchEvent002
 * @tc.desc: Test HandleTouchEvent with null pointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandleTouchEvent002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    // Should not crash with null event
    hookMgr.HandleTouchEvent(pointerEvent);
}

/**
 * @tc.name: InputEventHookManagerTest_DispatchToNextHandler002
 * @tc.desc: Test DispatchToNextHandler with non-existent pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_DispatchToNextHandler002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(1);
    EXPECT_EQ(hookMgr.DispatchToNextHandler(999, keyEvent), RET_ERR);
}

/**
 * @tc.name: InputEventHookManagerTest_DispatchToNextHandler003
 * @tc.desc: Test DispatchToNextHandler with null keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_DispatchToNextHandler003, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    EXPECT_EQ(hookMgr.DispatchToNextHandler(UDS_PID, keyEvent), RET_ERR);
}

/**
 * @tc.name: InputEventHookManagerTest_DispatchMouseToNextHandler002
 * @tc.desc: Test DispatchMouseToNextHandler with non-existent pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_DispatchMouseToNextHandler002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    EXPECT_EQ(hookMgr.DispatchMouseToNextHandler(999, pointerEvent), RET_ERR);
}

/**
 * @tc.name: InputEventHookManagerTest_DispatchMouseToNextHandler003
 * @tc.desc: Test DispatchMouseToNextHandler with null pointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_DispatchMouseToNextHandler003, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_MOUSE].push_back(
        std::make_shared<PointerEventHook>(sess, HOOK_EVENT_TYPE_MOUSE, nextHookGetter));
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    EXPECT_EQ(hookMgr.DispatchMouseToNextHandler(UDS_PID, pointerEvent), RET_ERR);
}

/**
 * @tc.name: InputEventHookManagerTest_DispatchTouchToNextHandler002
 * @tc.desc: Test DispatchTouchToNextHandler with non-existent pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_DispatchTouchToNextHandler002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    EXPECT_EQ(hookMgr.DispatchTouchToNextHandler(999, pointerEvent), RET_ERR);
}

/**
 * @tc.name: InputEventHookManagerTest_DispatchTouchToNextHandler003
 * @tc.desc: Test DispatchTouchToNextHandler with null pointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_DispatchTouchToNextHandler003, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_TOUCH].push_back(
        std::make_shared<PointerEventHook>(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter));
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    EXPECT_EQ(hookMgr.DispatchTouchToNextHandler(UDS_PID, pointerEvent), RET_ERR);
}

/**
 * @tc.name: InputEventHookManagerTest_IsHooksExisted001
 * @tc.desc: Test IsHooksExisted with empty hooks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_IsHooksExisted001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    EXPECT_EQ(hookMgr.IsHooksExisted(HOOK_EVENT_TYPE_KEY), false);
    EXPECT_EQ(hookMgr.IsHooksExisted(HOOK_EVENT_TYPE_MOUSE), false);
    EXPECT_EQ(hookMgr.IsHooksExisted(HOOK_EVENT_TYPE_TOUCH), false);
}

/**
 * @tc.name: InputEventHookManagerTest_IsHooksExisted002
 * @tc.desc: Test IsHooksExisted with hooks existed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_IsHooksExisted002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    EXPECT_EQ(hookMgr.IsHooksExisted(HOOK_EVENT_TYPE_KEY), true);
    EXPECT_EQ(hookMgr.IsHooksExisted(HOOK_EVENT_TYPE_MOUSE), false);
}

/**
 * @tc.name: InputEventHookManagerTest_Dump001
 * @tc.desc: Test Dump function with empty hooks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_Dump001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    int32_t fd = 1;
    std::vector<std::string> args;
    // Should not crash with empty hooks
    hookMgr.Dump(fd, args);
}

/**
 * @tc.name: InputEventHookManagerTest_Dump002
 * @tc.desc: Test Dump function with hooks existed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_Dump002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    hookMgr.hooks_[HOOK_EVENT_TYPE_TOUCH].push_back(
        std::make_shared<PointerEventHook>(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter));
    int32_t fd = 1;
    std::vector<std::string> args;
    // Should not crash with hooks existed
    hookMgr.Dump(fd, args);
}

/**
 * @tc.name: InputEventHookManagerTest_Init001
 * @tc.desc: Test Init function multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_Init001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    // First init
    hookMgr.Init();
    // Second init should return early
    hookMgr.Init();
}

/**
 * @tc.name: InputEventHookManagerTest_OnSessionLost001
 * @tc.desc: Test OnSessionLost with null session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_OnSessionLost001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr session = nullptr;
    // Should not crash with null session
    hookMgr.OnSessionLost(session);
}

/**
 * @tc.name: InputEventHookManagerTest_OnSessionLost002
 * @tc.desc: Test OnSessionLost with valid session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_OnSessionLost002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    hookMgr.hooks_[HOOK_EVENT_TYPE_MOUSE].push_back(
        std::make_shared<PointerEventHook>(sess, HOOK_EVENT_TYPE_MOUSE, nextHookGetter));
    hookMgr.hooks_[HOOK_EVENT_TYPE_TOUCH].push_back(
        std::make_shared<PointerEventHook>(sess, HOOK_EVENT_TYPE_TOUCH, nextHookGetter));
    // Should remove all hooks for the session pid
    hookMgr.OnSessionLost(sess);
    EXPECT_EQ(hookMgr.IsHookExisted(UDS_PID, HOOK_EVENT_TYPE_KEY), false);
    EXPECT_EQ(hookMgr.IsHookExisted(UDS_PID, HOOK_EVENT_TYPE_MOUSE), false);
    EXPECT_EQ(hookMgr.IsHookExisted(UDS_PID, HOOK_EVENT_TYPE_TOUCH), false);
}

/**
 * @tc.name: InputEventHookManagerTest_PrependHook001
 * @tc.desc: Test PrependHook function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_PrependHook001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    auto hook1 = std::make_shared<KeyEventHook>(sess, nextHookGetter);
    auto hook2 = std::make_shared<KeyEventHook>(sess, nextHookGetter);
    hookMgr.PrependHook(HOOK_EVENT_TYPE_KEY, hook1);
    hookMgr.PrependHook(HOOK_EVENT_TYPE_KEY, hook2);
    // hook2 should be at front
    auto firstHook = hookMgr.GetFirstValidHook(HOOK_EVENT_TYPE_KEY);
    EXPECT_EQ(firstHook, hook2);
}

/**
 * @tc.name: InputEventHookManagerTest_IsHookExisted002
 * @tc.desc: Test IsHookExisted with non-existent pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_IsHookExisted002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    EXPECT_EQ(hookMgr.IsHookExisted(999, HOOK_EVENT_TYPE_KEY), false);
}

/**
 * @tc.name: InputEventHookManagerTest_IsHookExisted003
 * @tc.desc: Test IsHookExisted with empty hooks map
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_IsHookExisted003, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    EXPECT_EQ(hookMgr.IsHookExisted(UDS_PID, HOOK_EVENT_TYPE_KEY), false);
}

/**
 * @tc.name: InputEventHookManagerTest_GetHookByPid001
 * @tc.desc: Test GetHookByPid with non-existent hook type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_GetHookByPid001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    auto hook = hookMgr.GetHookByPid(UDS_PID, HOOK_EVENT_TYPE_KEY);
    EXPECT_EQ(hook, nullptr);
}

/**
 * @tc.name: InputEventHookManagerTest_GetHookByPid002
 * @tc.desc: Test GetHookByPid with non-existent pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_GetHookByPid002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    auto hook = hookMgr.GetHookByPid(999, HOOK_EVENT_TYPE_KEY);
    EXPECT_EQ(hook, nullptr);
}

/**
 * @tc.name: InputEventHookManagerTest_GetHookByPid003
 * @tc.desc: Test GetHookByPid with valid pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_GetHookByPid003, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    auto hook = hookMgr.GetHookByPid(UDS_PID, HOOK_EVENT_TYPE_KEY);
    EXPECT_NE(hook, nullptr);
    EXPECT_EQ(hook->GetHookPid(), UDS_PID);
}

/**
 * @tc.name: InputEventHookManagerTest_RemoveHookByPid001
 * @tc.desc: Test RemoveHookByPid with non-existent hook type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_RemoveHookByPid001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    EXPECT_EQ(hookMgr.RemoveHookByPid(UDS_PID, HOOK_EVENT_TYPE_KEY), RET_OK);
}

/**
 * @tc.name: InputEventHookManagerTest_RemoveHookByPid002
 * @tc.desc: Test RemoveHookByPid with non-existent pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_RemoveHookByPid002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    EXPECT_EQ(hookMgr.RemoveHookByPid(999, HOOK_EVENT_TYPE_KEY), RET_OK);
    // Hook should still exist
    EXPECT_EQ(hookMgr.IsHookExisted(UDS_PID, HOOK_EVENT_TYPE_KEY), true);
}

/**
 * @tc.name: InputEventHookManagerTest_RemoveHookByPid003
 * @tc.desc: Test RemoveHookByPid with valid pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_RemoveHookByPid003, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    EXPECT_EQ(hookMgr.RemoveHookByPid(UDS_PID, HOOK_EVENT_TYPE_KEY), RET_OK);
    // Hook should be removed
    EXPECT_EQ(hookMgr.IsHookExisted(UDS_PID, HOOK_EVENT_TYPE_KEY), false);
}

/**
 * @tc.name: InputEventHookManagerTest_GetHookNum001
 * @tc.desc: Test GetHookNum with non-existent hook type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_GetHookNum001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    EXPECT_EQ(hookMgr.GetHookNum(HOOK_EVENT_TYPE_KEY), 0);
}

/**
 * @tc.name: InputEventHookManagerTest_GetHookNum002
 * @tc.desc: Test GetHookNum with hooks existed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_GetHookNum002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    EXPECT_EQ(hookMgr.GetHookNum(HOOK_EVENT_TYPE_KEY), 2);
}

/**
 * @tc.name: InputEventHookManagerTest_GetFirstValidHook001
 * @tc.desc: Test GetFirstValidHook with non-existent hook type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_GetFirstValidHook001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    auto hook = hookMgr.GetFirstValidHook(HOOK_EVENT_TYPE_KEY);
    EXPECT_EQ(hook, nullptr);
}

/**
 * @tc.name: InputEventHookManagerTest_GetFirstValidHook002
 * @tc.desc: Test GetFirstValidHook with hooks existed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_GetFirstValidHook002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    auto hook1 = std::make_shared<KeyEventHook>(sess, nextHookGetter);
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(hook1);
    auto hook = hookMgr.GetFirstValidHook(HOOK_EVENT_TYPE_KEY);
    EXPECT_EQ(hook, hook1);
}

/**
 * @tc.name: InputEventHookManagerTest_GetNextHook001
 * @tc.desc: Test GetNextHook with null hook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_GetNextHook001, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<InputEventHook> hook = nullptr;
    auto nextHook = hookMgr.GetNextHook(hook);
    EXPECT_EQ(nextHook, nullptr);
}

/**
 * @tc.name: InputEventHookManagerTest_GetNextHook002
 * @tc.desc: Test GetNextHook with non-existent hook type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_GetNextHook002, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    auto hook = std::make_shared<KeyEventHook>(sess, nextHookGetter);
    auto result = hookMgr.GetNextHook(hook);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHookManagerTest_GetNextHook003
 * @tc.desc: Test GetNextHook with hook not in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_GetNextHook003, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess1 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    SessionPtr sess2 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID + 1);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    auto hook1 = std::make_shared<KeyEventHook>(sess1, nextHookGetter);
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(hook1);
    auto hook2 = std::make_shared<KeyEventHook>(sess2, nextHookGetter);
    auto result = hookMgr.GetNextHook(hook2);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHookManagerTest_GetNextHook004
 * @tc.desc: Test GetNextHook with no next hook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_GetNextHook004, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    auto hook = std::make_shared<KeyEventHook>(sess, nextHookGetter);
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(hook);
    auto result = hookMgr.GetNextHook(hook);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: InputEventHookManagerTest_GetNextHook005
 * @tc.desc: Test GetNextHook with next hook existed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_GetNextHook005, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess1 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    SessionPtr sess2 = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID + 1);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    auto hook1 = std::make_shared<KeyEventHook>(sess1, nextHookGetter);
    auto hook2 = std::make_shared<KeyEventHook>(sess2, nextHookGetter);
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(hook1);
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(hook2);
    auto result = hookMgr.GetNextHook(hook1);
    EXPECT_EQ(result, hook2);
}

/**
 * @tc.name: InputEventHookManagerTest_HandleHooks003
 * @tc.desc: Test HandleHooks with null keyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandleHooks003, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<KeyEvent> keyEvent = nullptr;
    EXPECT_FALSE(hookMgr.HandleHooks(keyEvent));
}

/**
 * @tc.name: InputEventHookManagerTest_HandleHooks004
 * @tc.desc: Test HandleHooks with no key hooks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandleHooks004, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(1);
    EXPECT_FALSE(hookMgr.HandleHooks(keyEvent));
}

/**
 * @tc.name: InputEventHookManagerTest_HandleHooks005
 * @tc.desc: Test HandleHooks with null pointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandleHooks005, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    EXPECT_FALSE(hookMgr.HandleHooks(pointerEvent));
}

/**
 * @tc.name: InputEventHookManagerTest_HandleHooks006
 * @tc.desc: Test HandleHooks with no pointer hooks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandleHooks006, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    EXPECT_FALSE(hookMgr.HandleHooks(pointerEvent));
}

/**
 * @tc.name: InputEventHookManagerTest_HandleHooks007
 * @tc.desc: Test HandleHooks with unsupported sourceType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_HandleHooks007, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    EXPECT_FALSE(hookMgr.HandleHooks(pointerEvent));
}

/**
 * @tc.name: InputEventHookManagerTest_IsHookExisted004
 * @tc.desc: Test IsHookExisted with multiple hooks same pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_IsHookExisted004, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    EXPECT_EQ(hookMgr.IsHookExisted(UDS_PID, HOOK_EVENT_TYPE_KEY), true);
}

/**
 * @tc.name: InputEventHookManagerTest_IsHookExisted005
 * @tc.desc: Test IsHookExisted with null hook in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputEventHookManagerTest, InputEventHookManagerTest_IsHookExisted005, TestSize.Level1)
{
    InputEventHookManager hookMgr;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto nextHookGetter = [&hookMgr] (std::shared_ptr<InputEventHook> hook) -> std::shared_ptr<InputEventHook> const {
        return hookMgr.GetNextHook(hook);
    };
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(nullptr);
    hookMgr.hooks_[HOOK_EVENT_TYPE_KEY].push_back(
        std::make_shared<KeyEventHook>(sess, nextHookGetter));
    EXPECT_EQ(hookMgr.IsHookExisted(UDS_PID, HOOK_EVENT_TYPE_KEY), true);
}
} // namespace MMI
} // namespace OHOS