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
 
#include "key_event_hook_handler.h"
#include "key_event_hook_manager.h"
#include "multimodal_input_connect_manager.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "multimodal_event_handler.h"
 
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyEventHookHandlerTest"
 
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
 
class KeyEventHookHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};
 
class MockEventHookHandler {
public:
    MockEventHookHandler() = default;
    ~MockEventHookHandler() = default;
 
    MOCK_METHOD0(InitClient, bool());
    MOCK_METHOD1(AddKeyEventHook, int32_t(int32_t hookId));
    MOCK_METHOD1(RemoveKeyEventHook, int32_t(int32_t hookId));
    MOCK_METHOD1(DispatchToNextHandler, int32_t(int32_t eventId));
};
 
/**
 * @tc.name: AddKeyEventHook_Test_001
 * @tc.desc: Test AddKeyEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookHandlerTest, AddKeyEventHook_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEventHookHandler hookHandler;
    int32_t hookId = 1;
    auto callback = [](std::shared_ptr<KeyEvent>) {};
    std::shared_ptr<MockEventHookHandler> mockHook = std::make_shared<MockEventHookHandler>();
    EXPECT_CALL(*mockHook, InitClient()).WillRepeatedly(testing::Return(false));
    int32_t ret = hookHandler.AddKeyEventHook(callback, hookId);
    EXPECT_EQ(ret, RET_OK);
}
 
/**
 * @tc.name: AddKeyEventHook_Test_002
 * @tc.desc: Test AddKeyEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookHandlerTest, AddKeyEventHook_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEventHookHandler hookHandler;
    int32_t hookId = 1;
    auto callback = [](std::shared_ptr<KeyEvent>) {};
    std::shared_ptr<MockEventHookHandler> mockHook = std::make_shared<MockEventHookHandler>();
    EXPECT_CALL(*mockHook, InitClient()).WillRepeatedly(testing::Return(true));
    hookHandler.AddKeyEventHook(callback, hookId);
    EXPECT_CALL(*mockHook, AddKeyEventHook(testing::_)).WillRepeatedly(testing::Return(RET_ERR));
    int32_t ret = hookHandler.AddKeyEventHook(callback, hookId);
    EXPECT_EQ(ret, ERROR_REPEAT_INTERCEPTOR);
    EXPECT_CALL(*mockHook, AddKeyEventHook(testing::_)).WillRepeatedly(testing::Return(RET_OK));
    ret = hookHandler.AddKeyEventHook(callback, hookId);
    EXPECT_EQ(ret, ERROR_REPEAT_INTERCEPTOR);
}
 
/**
 * @tc.name: RemoveKeyEventHook_Test_001
 * @tc.desc: Test RemoveKeyEventHook
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookHandlerTest, RemoveKeyEventHook_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEventHookHandler hookHandler;
    int32_t hookId = 1;
    std::shared_ptr<MockEventHookHandler> mockHook = std::make_shared<MockEventHookHandler>();
    EXPECT_CALL(*mockHook, RemoveKeyEventHook(hookId)).WillRepeatedly(testing::Return(RET_ERR));
    int32_t ret = hookHandler.RemoveKeyEventHook(hookId);
    EXPECT_EQ(ret, RET_ERR);
}
 
/**
 * @tc.name: DispatchToNextHandler_Test_001
 * @tc.desc: Test DispatchToNextHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookHandlerTest, DispatchToNextHandler_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEventHookHandler hookHandler;
    int32_t eventId = 1;
    hookHandler.RemoveAllPendingKeys();
    int32_t ret = hookHandler.DispatchToNextHandler(eventId);
    EXPECT_EQ(ret, ERROR_INVALID_PARAMETER);
}
 
/**
 * @tc.name: DispatchToNextHandler_Test_002
 * @tc.desc: Test DispatchToNextHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookHandlerTest, DispatchToNextHandler_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEventHookHandler hookHandler;
    int32_t eventId = 1;
    long long timeStamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count() + 4000;
    hookHandler.AppendPendingKeys(eventId, timeStamp);
    std::shared_ptr<MockEventHookHandler> mockHook = std::make_shared<MockEventHookHandler>();
    EXPECT_CALL(*mockHook, DispatchToNextHandler(eventId)).WillRepeatedly(testing::Return(RET_ERR));
    int32_t ret = hookHandler.DispatchToNextHandler(eventId);
    EXPECT_EQ(ret, ERROR_INVALID_PARAMETER);
}
 
/**
 * @tc.name: UpdatePendingKeys_Test_001
 * @tc.desc: Test UpdatePendingKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookHandlerTest, UpdatePendingKeys_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEventHookHandler hookHandler;
    hookHandler.RemoveAllPendingKeys();
    hookHandler.UpdatePendingKeys();
    int32_t eventId = 1;
    long long timeStamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count() - 5000;
    hookHandler.AppendPendingKeys(eventId, timeStamp);
    eventId = 2;
    timeStamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count() + 2000;
    hookHandler.AppendPendingKeys(eventId, timeStamp);
    hookHandler.UpdatePendingKeys();
    EXPECT_FALSE(hookHandler.pendingKeys_.empty());
}
 
/**
 * @tc.name: RemoveExpiredPendingKeys_Test_001
 * @tc.desc: Test RemoveExpiredPendingKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookHandlerTest, RemoveExpiredPendingKeys_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEventHookHandler hookHandler;
    int32_t eventId = 1;
    hookHandler.RemoveAllPendingKeys();
    hookHandler.RemoveExpiredPendingKeys(eventId);
 
    long long timeStamp = 10;
    hookHandler.AppendPendingKeys(eventId, timeStamp);
    hookHandler.RemoveExpiredPendingKeys(eventId);
 
    hookHandler.AppendPendingKeys(eventId, timeStamp);
    eventId = 0;
    hookHandler.RemoveExpiredPendingKeys(eventId);
    EXPECT_FALSE(hookHandler.pendingKeys_.empty());
}
 
/**
 * @tc.name: IsValidEvent_Test_001
 * @tc.desc: Test IsValidEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookHandlerTest, IsValidEvent_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEventHookHandler hookHandler;
    int32_t eventId = 1;
    long long timeStamp = 10;
    hookHandler.RemoveAllPendingKeys();
    int32_t ret = hookHandler.IsValidEvent(eventId);
    EXPECT_EQ(ret, false);
    hookHandler.AppendPendingKeys(eventId, timeStamp);
    ret = hookHandler.IsValidEvent(1);
    EXPECT_EQ(ret, false);
    ret = hookHandler.IsValidEvent(2);
    EXPECT_EQ(ret, false);
}
 
/**
 * @tc.name: OnConnected_Test_001
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookHandlerTest, OnConnected_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEventHookHandler hookHandler;
    hookHandler.ResetHookCallback();
    hookHandler.OnConnected();
    EXPECT_EQ(hookHandler.hookCallback_, nullptr);
}
 
/**
 * @tc.name: OnConnected_Test_002
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KeyEventHookHandlerTest, OnConnected_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEventHookHandler hookHandler;
    auto callback = [](std::shared_ptr<KeyEvent>) {};
    hookHandler.SetHookCallback(callback);
 
    std::shared_ptr<MockEventHookHandler> mockHook = std::make_shared<MockEventHookHandler>();
    EXPECT_CALL(*mockHook, InitClient()).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(*mockHook, AddKeyEventHook(testing::_)).WillRepeatedly(testing::Return(RET_ERR));
    hookHandler.OnConnected();
    EXPECT_EQ(hookHandler.hookCallback_, nullptr);
}
} // namespace MMI
} // namespace OHOS