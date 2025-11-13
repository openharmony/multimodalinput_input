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
#include "event_dispatch_handler.h"
#include "event_loop_closure_checker.h"
#include "event_dispatch_order_checker.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_event_handler.h"
#include "uds_server.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventHookManagerTest"

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

class KeyEventHookManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class MockKeyEventHookManager {
public:
    MockKeyEventHookManager() = default;
    ~MockKeyEventHookManager() = default;
    MOCK_METHOD1(IsHookExisted, bool(int32_t pid));
    MOCK_METHOD1(RemoveHookById, int32_t(int32_t hookId));
    MOCK_METHOD1(RemoveChecker, int32_t(int32_t hookId));
};

/**
 * @tc.name: KeyEventHookManagerTest_Init001
 * @tc.desc: Test the function Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookManagerTest, KeyEventHookManagerTest_Init001, TestSize.Level0)
{
    KEY_EVENT_HOOK_MGR.isInitialized_ = true;
    KEY_EVENT_HOOK_MGR.Init();
    KEY_EVENT_HOOK_MGR.isInitialized_ = false;
    KEY_EVENT_HOOK_MGR.Init();
    EXPECT_TRUE(KEY_EVENT_HOOK_MGR.isInitialized_);
}

/**
 * @tc.name: KeyEventHookManagerTest_OnKeyEvent
 * @tc.desc: Test the function OnKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookManagerTest, KeyEventHookManagerTest_OnKeyEvent, TestSize.Level1)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto hook = std::make_shared<KeyEventHookManager::Hook>(KEY_EVENT_HOOK_MGR.GenerateHookId(), sess,
        [sess] (std::shared_ptr<KeyEventHookManager::Hook> hook, std::shared_ptr<KeyEvent> keyEvent) -> bool {
            return KEY_EVENT_HOOK_MGR.HookHandler(sess, hook, keyEvent);
        }
    );
    KEY_EVENT_HOOK_MGR.hooks_.push_front(hook);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    keyEvent->SetKeyCode(-1);
    bool result = KEY_EVENT_HOOK_MGR.IsValidKeyEvent(keyEvent);
    KEY_EVENT_HOOK_MGR.OnKeyEvent(keyEvent);
    EXPECT_FALSE(result);
    keyEvent->SetKeyCode(1);
    KEY_EVENT_HOOK_MGR.OnKeyEvent(keyEvent);
    result = KEY_EVENT_HOOK_MGR.IsValidKeyEvent(keyEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: KeyEventHookManagerTest_RemoveKeyEventHook001
 * @tc.desc: Test the function RemoveKeyEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookManagerTest, KeyEventHookManagerTest_RemoveKeyEventHook001, TestSize.Level1)
{
    int32_t pid = 100;
    int32_t hookId = 200;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto hook = std::make_shared<KeyEventHookManager::Hook>(KEY_EVENT_HOOK_MGR.GenerateHookId(), sess,
        [sess] (std::shared_ptr<KeyEventHookManager::Hook> hook, std::shared_ptr<KeyEvent> keyEvent) -> bool {
            return KEY_EVENT_HOOK_MGR.HookHandler(sess, hook, keyEvent);
        }
    );
    KEY_EVENT_HOOK_MGR.hooks_.push_front(hook);
    int32_t result = KEY_EVENT_HOOK_MGR.RemoveKeyEventHook(pid, hookId);
    EXPECT_EQ(result, RET_OK);
    pid = 123;
    hookId = 456;
    KEY_EVENT_HOOK_MGR.hooks_.push_front(hook);
    result = KEY_EVENT_HOOK_MGR.RemoveKeyEventHook(pid, hookId);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: KeyEventHookManagerTest_RemoveKeyEventHook002
 * @tc.desc: Test the function RemoveKeyEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookManagerTest, KeyEventHookManagerTest_RemoveKeyEventHook002, TestSize.Level1)
{
    int32_t pid = UDS_PID;
    int32_t hookId = UDS_PID;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto hook = std::make_shared<KeyEventHookManager::Hook>(KEY_EVENT_HOOK_MGR.GenerateHookId(), sess,
        [sess] (std::shared_ptr<KeyEventHookManager::Hook> hook, std::shared_ptr<KeyEvent> keyEvent) -> bool {
            return KEY_EVENT_HOOK_MGR.HookHandler(sess, hook, keyEvent);
        }
    );
    hook->id = UDS_PID;
    KEY_EVENT_HOOK_MGR.hooks_.push_front(hook);
    int32_t result = KEY_EVENT_HOOK_MGR.RemoveKeyEventHook(pid, hookId);
    EXPECT_EQ(result, RET_OK);

    KEY_EVENT_HOOK_MGR.hooks_.push_front(hook);
    EVENT_LOOP_CLOSURE_CHECKER.pendingDownKeys_[hookId].insert(hookId);
    result = KEY_EVENT_HOOK_MGR.RemoveKeyEventHook(pid, hookId);
    EXPECT_EQ(result, RET_OK);

    KEY_EVENT_HOOK_MGR.hooks_.push_front(hook);
    result = KEY_EVENT_HOOK_MGR.RemoveKeyEventHook(pid, hookId);
    EXPECT_EQ(result, RET_OK);

    EVENT_DISPATCH_ORDER_CHECKER.dispatchedEventIds_[hookId] = hookId;
    KEY_EVENT_HOOK_MGR.hooks_.push_front(hook);
    result = KEY_EVENT_HOOK_MGR.RemoveKeyEventHook(pid, hookId);
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name: KeyEventHookManagerTest_DispatchToNextHandler001
 * @tc.desc: Test the function DispatchToNextHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookManagerTest, KeyEventHookManagerTest_DispatchToNextHandler001, TestSize.Level1)
{
    int32_t pid = 100;
    int32_t eventId = 456;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto hook = std::make_shared<KeyEventHookManager::Hook>(KEY_EVENT_HOOK_MGR.GenerateHookId(), sess,
        [sess] (std::shared_ptr<KeyEventHookManager::Hook> hook, std::shared_ptr<KeyEvent> keyEvent) -> bool {
            return KEY_EVENT_HOOK_MGR.HookHandler(sess, hook, keyEvent);
        }
    );
    KEY_EVENT_HOOK_MGR.hooks_.push_front(hook);
    int32_t result = KEY_EVENT_HOOK_MGR.DispatchToNextHandler(pid, eventId);
    EXPECT_EQ(result, ERROR_INVALID_PARAMETER);
}

/**
 * @tc.name: KeyEventHookManagerTest_OnSessionLost001
 * @tc.desc: Test the function Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookManagerTest, KeyEventHookManagerTest_OnSessionLost001, TestSize.Level0)
{
    int32_t hookId = 123;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto hook = std::make_shared<KeyEventHookManager::Hook>(KEY_EVENT_HOOK_MGR.GenerateHookId(), sess,
        [sess] (std::shared_ptr<KeyEventHookManager::Hook> hook, std::shared_ptr<KeyEvent> keyEvent) -> bool {
            return KEY_EVENT_HOOK_MGR.HookHandler(sess, hook, keyEvent);
        }
    );
    KEY_EVENT_HOOK_MGR.hooks_.push_front(hook);
    EVENT_LOOP_CLOSURE_CHECKER.pendingDownKeys_[hookId].insert(hookId);
    KEY_EVENT_HOOK_MGR.OnSessionLost(sess);
    EXPECT_FALSE(EVENT_LOOP_CLOSURE_CHECKER.pendingDownKeys_[hookId].empty());

    EVENT_DISPATCH_ORDER_CHECKER.dispatchedEventIds_[hookId] = hookId;
    KEY_EVENT_HOOK_MGR.OnSessionLost(sess);
    EXPECT_FALSE(EVENT_DISPATCH_ORDER_CHECKER.dispatchedEventIds_.empty());

    KEY_EVENT_HOOK_MGR.RemoveHookById(hookId);
    KEY_EVENT_HOOK_MGR.OnSessionLost(sess);
    EXPECT_FALSE(KEY_EVENT_HOOK_MGR.hooks_.empty());
}

/**
 * @tc.name: KeyEventHookManagerTest_GetNextHook001
 * @tc.desc: Test the function GetNextHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookManagerTest, KeyEventHookManagerTest_GetNextHook001, TestSize.Level1)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    auto hook = std::make_shared<KeyEventHookManager::Hook>(KEY_EVENT_HOOK_MGR.GenerateHookId(), sess,
        [sess] (std::shared_ptr<KeyEventHookManager::Hook> hook, std::shared_ptr<KeyEvent> keyEvent) -> bool {
            return KEY_EVENT_HOOK_MGR.HookHandler(sess, hook, keyEvent);
        }
    );
    EXPECT_EQ(KEY_EVENT_HOOK_MGR.GetNextHook(hook), nullptr);
    KEY_EVENT_HOOK_MGR.hooks_.push_front(hook);
    KEY_EVENT_HOOK_MGR.GetNextHook(hook);
    KEY_EVENT_HOOK_MGR.hooks_.push_front(hook);
    EXPECT_NE(KEY_EVENT_HOOK_MGR.GetNextHook(hook), nullptr);
}

/**
 * @tc.name: KeyEventHookManagerTest_HandleHooks
 * @tc.desc: Test the function HandleHooks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookManagerTest, KeyEventHookManagerTest_HandleHooks, TestSize.Level1)
{
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    auto hooks = KEY_EVENT_HOOK_MGR.hooks_;
    KEY_EVENT_HOOK_MGR.hooks_.clear();
    bool ret = KEY_EVENT_HOOK_MGR.HandleHooks(keyEvent);
    EXPECT_FALSE(ret);

    KEY_EVENT_HOOK_MGR.hooks_ = hooks;
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    int32_t pid = 1;
    int32_t hookId = 1;
    KEY_EVENT_HOOK_MGR.AddKeyEventHook(pid, sess, hookId);
    ret = KEY_EVENT_HOOK_MGR.HandleHooks(keyEvent);
    EXPECT_FALSE(ret);

    pid = UDS_PID;
    int32_t result = KEY_EVENT_HOOK_MGR.AddKeyEventHook(pid, sess, hookId);
    EXPECT_EQ(result, ERROR_REPEAT_INTERCEPTOR);
}

/**
 * @tc.name: KeyEventHookManagerTest_DispatchDirectly
 * @tc.desc: Test the function DispatchDirectly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookManagerTest, KeyEventHookManagerTest_DispatchDirectly, TestSize.Level1)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    int32_t pid = 1;
    int32_t hookId = 1;
    KEY_EVENT_HOOK_MGR.AddKeyEventHook(pid, sess, hookId);
    auto udsServer = std::make_unique<UDSServer>();
    InputHandler->udsServer_ = udsServer.get();
    EXPECT_NE(InputHandler->udsServer_, nullptr);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    std::shared_ptr<EventDispatchHandler> handler = std::make_shared<EventDispatchHandler>();
    InputHandler->eventDispatchHandler_ = handler;
    bool ret = KEY_EVENT_HOOK_MGR.DispatchDirectly(keyEvent);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: KeyEventHookManagerTest_CheckAndUpdateEventLoopClosure
 * @tc.desc: Test the function CheckAndUpdateEventLoopClosure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookManagerTest, KeyEventHookManagerTest_CheckAndUpdateEventLoopClosure, TestSize.Level1)
{
    SessionPtr sess = std::make_shared<UDSSession>(PROGRAM_NAME, MODULE_TYPE, UDS_FD, UDS_UID, UDS_PID);
    int32_t pid = 1;
    int32_t hookId = 1;

    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EVENT_LOOP_CLOSURE_CHECKER.pendingDownKeys_[hookId].insert(hookId);
    KEY_EVENT_HOOK_MGR.AddKeyEventHook(pid, sess, hookId);
    keyEvent->SetId(100);
    keyEvent->SetKeyCode(1);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UNKNOWN);
    int32_t ret = KEY_EVENT_HOOK_MGR.CheckAndUpdateEventLoopClosure(hookId, keyEvent);
    EXPECT_EQ(ret, RET_ERR);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    ret = KEY_EVENT_HOOK_MGR.CheckAndUpdateEventLoopClosure(hookId, keyEvent);
    EXPECT_EQ(ret, RET_ERR);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_CANCEL);
    ret = KEY_EVENT_HOOK_MGR.CheckAndUpdateEventLoopClosure(hookId, keyEvent);
    EXPECT_EQ(ret, RET_ERR);

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    ret = KEY_EVENT_HOOK_MGR.CheckAndUpdateEventLoopClosure(hookId, keyEvent);
    EXPECT_EQ(ret, RET_OK);
}


/**
 * @tc.name: KeyEventHookManagerTest_HandleEventLoopClosureKeyUpOrCancel
 * @tc.desc: Test the function HandleEventLoopClosureKeyUpOrCancel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookManagerTest, KeyEventHookManagerTest_HandleEventLoopClosureKeyUpOrCancel, TestSize.Level1)
{
    int32_t hookId = 1;
    int32_t keyCode1 = 2;
    bool ret = EVENT_LOOP_CLOSURE_CHECKER.CheckLoopClosure(hookId, keyCode1);
    KEY_EVENT_HOOK_MGR.HandleEventLoopClosureKeyUpOrCancel(hookId, keyCode1);
    EXPECT_TRUE(ret);

    std::unordered_set<int32_t> uset;
    int32_t keyCode2 = 10;
    uset.insert(keyCode2);
    EVENT_LOOP_CLOSURE_CHECKER.pendingDownKeys_.insert(std::make_pair(hookId, uset));
    ret = EVENT_LOOP_CLOSURE_CHECKER.CheckLoopClosure(hookId, keyCode1);
    KEY_EVENT_HOOK_MGR.HandleEventLoopClosureKeyUpOrCancel(hookId, keyCode1);
    EXPECT_TRUE(ret);

    EVENT_LOOP_CLOSURE_CHECKER.pendingDownKeys_.clear();
    uset.insert(keyCode1);
    EVENT_LOOP_CLOSURE_CHECKER.pendingDownKeys_.insert(std::make_pair(hookId, uset));
    ret = EVENT_LOOP_CLOSURE_CHECKER.CheckLoopClosure(hookId, keyCode1);
    KEY_EVENT_HOOK_MGR.HandleEventLoopClosureKeyUpOrCancel(hookId, keyCode1);
    EXPECT_FALSE(ret);
}
} // namespace MMI
} // namespace OHOS