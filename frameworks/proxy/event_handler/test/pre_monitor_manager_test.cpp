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

#include "input_scene_board_judgement.h"
#include "pre_monitor_manager.h"
#include "multimodal_event_handler.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PreMonitorManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class PreMonitorManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: PreMonitorManagerTest_FindHandler_001
 * @tc.desc: Test FindHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreMonitorManagerTest, PreMonitorManagerTest_FindHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PreMonitorManager manager;
    int32_t handlerId = 1;
    ASSERT_NO_FATAL_FAILURE(manager.FindHandler(handlerId));
    handlerId = -1;
    ASSERT_NO_FATAL_FAILURE(manager.FindHandler(handlerId));
}

/**
 * @tc.name: PreMonitorManagerTest_FindHandler_002
 * @tc.desc: Test FindHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreMonitorManagerTest, PreMonitorManagerTest_FindHandler_002, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    PreMonitorManager manager;
    int32_t handlerId = 1;
    PreMonitorManager::Handler handler;
    std::shared_ptr<IInputEventConsumer> consumer = nullptr;
    handler.callback_ = consumer;
    manager.monitorHandlers_[handlerId] = handler;
    std::shared_ptr<IInputEventConsumer> result = manager.FindHandler(handlerId);
    ASSERT_EQ(result, consumer);
}

/**
 * @tc.name: PreMonitorManagerTest_AddHandler_001
 * @tc.desc: Test AddHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreMonitorManagerTest, PreMonitorManagerTest_AddHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PreMonitorManager manager;
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    std::vector<int32_t> keys = {1, 2, 3};
    std::shared_ptr<IInputEventConsumer> consumer = nullptr;
    int32_t ret = manager.AddHandler(consumer, eventType, keys);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PreMonitorManagerTest_RemoveHandler_001
 * @tc.desc: Test RemoveHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreMonitorManagerTest, PreMonitorManagerTest_RemoveHandler_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    PreMonitorManager manager;
    int32_t handlerId = 1;
    PreMonitorManager::Handler handler;
    std::shared_ptr<IInputEventConsumer> consumer = nullptr;
    handler.callback_ = consumer;
    manager.monitorHandlers_[handlerId] = handler;
    int32_t ret = manager.RemoveHandler(0);
    EXPECT_EQ(ret, RET_ERR);
    ASSERT_NO_FATAL_FAILURE(manager.RemoveHandler(1));
}

/**
 * @tc.name: PreMonitorManagerTest_AddLocal_001
 * @tc.desc: Test AddLocal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreMonitorManagerTest, PreMonitorManagerTest_AddLocal_001, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    PreMonitorManager manager;
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    int32_t handlerId = 1;
    std::shared_ptr<IInputEventConsumer> consumer = nullptr;
    std::vector<int32_t> keys = {1, 2, 3};
    int32_t ret = manager.AddLocal(handlerId, eventType, keys, consumer);
    EXPECT_EQ(ret, RET_OK);
    ret = manager.AddLocal(handlerId, eventType, keys, consumer);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PreMonitorManagerTest_RemoveLocal_001
 * @tc.desc: Test RemoveLocal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreMonitorManagerTest, PreMonitorManagerTest_RemoveLocal_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PreMonitorManager manager;
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    int32_t handlerId = 1;
    std::shared_ptr<IInputEventConsumer> consumer = nullptr;
    std::vector<int32_t> keys = {1, 2, 3};
    int32_t ret = manager.AddLocal(handlerId, eventType, keys, consumer);
    ret = manager.RemoveLocal(handlerId);
    EXPECT_EQ(ret, RET_OK);
    ret = manager.RemoveLocal(handlerId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PreMonitorManagerTest_AddToServer_001
 * @tc.desc: Test AddToServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreMonitorManagerTest, PreMonitorManagerTest_AddToServer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PreMonitorManager manager;
    HandleEventType eventType = HANDLE_EVENT_TYPE_PRE_KEY;
    int32_t handlerId = 1;
    std::vector<int32_t> keys = {1, 2, 3};
    ASSERT_NO_FATAL_FAILURE(manager.AddToServer(handlerId, eventType, keys));
}

/**
 * @tc.name: PreMonitorManagerTest_RemoveFromServer_001
 * @tc.desc: Test RemoveFromServer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreMonitorManagerTest, PreMonitorManagerTest_RemoveFromServer_001, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    PreMonitorManager manager;
    int32_t handlerId = 1;
    ASSERT_NO_FATAL_FAILURE(manager.RemoveFromServer(handlerId));
}

/**
 * @tc.name: PreMonitorManagerTest_OnPreKeyEvent_001
 * @tc.desc: Test OnPreKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreMonitorManagerTest, PreMonitorManagerTest_OnPreKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    int32_t handlerId = 1;
    ASSERT_NO_FATAL_FAILURE(PRE_MONITOR_MGR.OnPreKeyEvent(keyEvent, handlerId));
}

/**
 * @tc.name: PreMonitorManagerTest_GetNextId_001
 * @tc.desc: Test GetNextId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreMonitorManagerTest, PreMonitorManagerTest_GetNextId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PreMonitorManager manager;
    manager.nextId_ = std::numeric_limits<int32_t>::max();
    int32_t result = manager.GetNextId();
    ASSERT_EQ(result, INVALID_HANDLER_ID);
}

/**
 * @tc.name: PreMonitorManagerTest_GetNextId_002
 * @tc.desc: Test GetNextId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PreMonitorManagerTest, PreMonitorManagerTest_GetNextId_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PreMonitorManager manager;
    manager.nextId_ = 5;
    int32_t result = manager.GetNextId();
    ASSERT_EQ(result, 5);
}
} // namespace MMI
} // namespace OHOS
