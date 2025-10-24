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

#include <gtest/gtest.h>

#include "delegate_tasks.h"
#include "error_multimodal.h"
#include "key_event_napi.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DelegateTasksTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class DelegateTasksTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: DelegateTasksTest_Init_001
 * @tc.desc: Test the function Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_Init_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DelegateTasks delegateTasks;
    EXPECT_TRUE(delegateTasks.Init());
    ASSERT_NO_FATAL_FAILURE(delegateTasks.ProcessTasks());
    EXPECT_EQ(delegateTasks.PostSyncTask(nullptr), ERROR_NULL_POINTER);
}

/**
 * @tc.name: DelegateTasksTest_PostSyncTask_002
 * @tc.desc: Test the function PostSyncTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_PostSyncTask_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DelegateTasks delegateTasks;
    auto callback = []() { return 0; };
    EXPECT_EQ(delegateTasks.PostSyncTask(callback), 65142804);
}

/**
 * @tc.name: DelegateTasksTest_PostSyncTask_003
 * @tc.desc: Test the function PostSyncTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_PostSyncTask_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DelegateTasks delegateTasks;
    auto callback = []() { return 0; };
    EXPECT_EQ(delegateTasks.PostSyncTask(callback), ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: DelegateTasksTest_PostSyncTask_004
 * @tc.desc: Test the function PostSyncTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_PostSyncTask_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DelegateTasks delegateTasks;
    auto callback = []() { std::this_thread::sleep_for(std::chrono::seconds(4)); return 0; };
    EXPECT_NE(delegateTasks.PostSyncTask(callback), ETASKS_WAIT_TIMEOUT);
}

/**
 * @tc.name: DelegateTasksTest_PostSyncTask_005
 * @tc.desc: Test the function PostSyncTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_PostSyncTask_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DelegateTasks delegateTasks;
    auto callback = []() { return 0; };
    EXPECT_NE(delegateTasks.PostSyncTask(callback), ETASKS_WAIT_DEFERRED);
}

/**
 * @tc.name: DelegateTasksTest_PostAsyncTask_001
 * @tc.desc: Test the function PostAsyncTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_PostAsyncTask_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DelegateTasks delegateTasks;
    EXPECT_EQ(delegateTasks.PostAsyncTask(nullptr), ERROR_NULL_POINTER);
}

/**
 * @tc.name: DelegateTasksTest_PopPendingTaskList_001
 * @tc.desc: Test the function PopPendingTaskList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_PopPendingTaskList_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DelegateTasks delegateTasks;
    std::vector<DelegateTasks::TaskPtr> tasks;
    ASSERT_NO_FATAL_FAILURE(delegateTasks.PopPendingTaskList(tasks));
}

/**
 * @tc.name: DelegateTasksTest_PopPendingTaskList_002
 * @tc.desc: Test the function PopPendingTaskList
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_PopPendingTaskList_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DelegateTasks delegateTasks;
    std::vector<DelegateTasks::TaskPtr> tasks;
    for (int32_t i = 0; i < 15; i++) {
        delegateTasks.PopPendingTaskList(tasks);
    }
    ASSERT_NO_FATAL_FAILURE(delegateTasks.PopPendingTaskList(tasks));
}

/**
 * @tc.name: DelegateTasksTest_PostTask_001
 * @tc.desc: Test the function PostTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_PostTask_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DelegateTasks delegateTasks;
    for (int32_t i = 0; i < 1001; i++) {
        delegateTasks.PostTask(nullptr, nullptr);
    }
    auto task = delegateTasks.PostTask(nullptr, nullptr);
    EXPECT_EQ(task, nullptr);
}

/**
 * @tc.name: DelegateTasksTest_PostTask_002
 * @tc.desc: Test the function PostTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_PostTask_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DelegateTasks delegateTasks;
    std::shared_ptr<DelegateTasks::Promise> promise;
    auto task = delegateTasks.PostTask(nullptr, promise);
    EXPECT_EQ(task, nullptr);
}

/**
 * @tc.name:DelegateTasksTest_CreateKeyEvent_001
 * @tc.desc:Test the function CreateKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_CreateKeyEvent_001, TestSize.Level1)
{
    KeyEventNapi napi;
    napi_env env = nullptr;
    std::shared_ptr<KeyEvent> in = KeyEvent::Create();
    ASSERT_NE(in, nullptr);
    napi_value out = nullptr;
    napi_status status = napi.CreateKeyEvent(env, in, out);
    ASSERT_NE(status, napi_ok);
}

/**
 * @tc.name:DelegateTasksTest_GetKeyEvent_001
 * @tc.desc:Test the function GetKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_GetKeyEvent_001, TestSize.Level1)
{
    KeyEventNapi napi;
    napi_env env = nullptr;
    napi_value in = nullptr;
    std::shared_ptr<KeyEvent> out = KeyEvent::Create();
    ASSERT_NE(out, nullptr);
    napi_status status = napi.GetKeyEvent(env, in, out);
    ASSERT_NE(status, napi_ok);
}

/**
 * @tc.name:DelegateTasksTest_CreateKeyItem_001
 * @tc.desc:Test the function CreateKeyItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_CreateKeyItem_001, TestSize.Level1)
{
    KeyEventNapi napi;
    napi_env env = nullptr;
    KeyEvent::KeyItem item;
    std::optional<KeyEvent::KeyItem> in;
    item.SetKeyCode(2018);
    item.SetPressed(false);
    in.emplace(item);
    napi_value out = nullptr;
    napi_status status = napi.CreateKeyItem(env, in, out);
    ASSERT_NE(status, napi_ok);
}

/**
 * @tc.name:DelegateTasksTest_GetKeyItem_001
 * @tc.desc:Test the function GetKeyItem
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_GetKeyItem_001, TestSize.Level1)
{
    KeyEventNapi napi;
    napi_env env = nullptr;
    napi_value in = nullptr;
    KeyEvent::KeyItem out;
    out.SetKeyCode(2024);
    out.SetPressed(false);
    napi_status status = napi.GetKeyItem(env, in, out);
    ASSERT_EQ(status, napi_ok);
}

/**
 * @tc.name: DelegateTasksTest_PostAsyncTask_002
 * @tc.desc: Test the function PostAsyncTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_PostAsyncTask_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DelegateTasks delegateTasks;
    auto callback = []() { return 0; };
    ASSERT_NO_FATAL_FAILURE(delegateTasks.PostAsyncTask(callback));
}
/**
 * @tc.name: DelegateTasksTest_ProcessTask_001
 * @tc.desc: Test the function ProcessTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_ProcessTask_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callback = []() { return 0; };
    int32_t id = 1;
    DelegateTasks::Task task(id, callback);
    task.hasWaited_ = true;
    ASSERT_NO_FATAL_FAILURE(task.ProcessTask());
}
/**
 * @tc.name: DelegateTasksTest_ProcessTask_002
 * @tc.desc: Test the function ProcessTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_ProcessTask_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callback = []() { return 42; };
    int32_t id = 3;
    auto pro = std::make_shared<std::promise<int32_t>>();
    DelegateTasks::Task task(id, callback, pro);
    task.hasWaited_ = false;
    ASSERT_NO_FATAL_FAILURE(task.ProcessTask());
}
/**
 * @tc.name: DelegateTasksTest_ProcessTask_003
 * @tc.desc: Test the function ProcessTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateTasksTest, DelegateTasksTest_ProcessTask_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto callback = []() { return 42; };
    int32_t id = 2;
    DelegateTasks::Task task(id, callback);
    task.hasWaited_ = false;
    ASSERT_NO_FATAL_FAILURE(task.ProcessTask());
}
} // namespace MMI
} // namespace OHOS