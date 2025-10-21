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

} // namespace MMI
} // namespace OHOS