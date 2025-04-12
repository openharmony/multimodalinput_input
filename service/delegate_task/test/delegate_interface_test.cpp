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

#include "delegate_interface.h"
#include "error_multimodal.h"

#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "DelegateInterfaceTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class DelegateInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: DelegateInterfaceTest_GetDeviceTags_01
 * @tc.desc: Test the function GetDeviceTags
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_GetDeviceTags_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    InputHandlerType type = InputHandlerType::MONITOR;
    uint32_t ret = delegateInterface.GetDeviceTags(type);
    EXPECT_EQ(ret, 0);

    type = InputHandlerType::NONE;
    EXPECT_TRUE(delegateInterface.handlers_.empty());
    uint32_t ret2 = delegateInterface.GetDeviceTags(type);
    EXPECT_EQ(ret2, 0);
}

/**
 * @tc.name: DelegateInterfaceTest_GetDeviceTags_02
 * @tc.desc: Test the function GetDeviceTags
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_GetDeviceTags_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    InputHandlerType type = InputHandlerType::INTERCEPTOR;
    DelegateInterface::HandlerSummary handler1 = {"handler1", 0x1, HandlerMode::SYNC, 1, 2};
    DelegateInterface::HandlerSummary handler2 = {"handler2", 0x2, HandlerMode::ASYNC, 2, 3};
    delegateInterface.handlers_.insert({INTERCEPTOR, handler1});
    delegateInterface.handlers_.insert({MONITOR, handler2});
    EXPECT_FALSE(delegateInterface.handlers_.empty());
    uint32_t ret1 = delegateInterface.GetDeviceTags(type);
    EXPECT_EQ(ret1, 2);

    type = InputHandlerType::NONE;
    uint32_t ret2 = delegateInterface.GetDeviceTags(type);
    EXPECT_EQ(ret2, 0);
}

/**
 * @tc.name: DelegateInterfaceTest_RemoveLocal_01
 * @tc.desc: Test the function RemoveLocal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_RemoveLocal_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    InputHandlerType type = InputHandlerType::NONE;
    std::string name = "handler";
    uint32_t deviceTags = 1;
    DelegateInterface::HandlerSummary handler1 = {"handler1", 0x1, HandlerMode::SYNC, 1, 2};
    DelegateInterface::HandlerSummary handler2 = {"handler2", 0x2, HandlerMode::ASYNC, 2, 3};
    delegateInterface.handlers_.insert({INTERCEPTOR, handler1});
    delegateInterface.handlers_.insert({MONITOR, handler2});
    ASSERT_NO_FATAL_FAILURE(delegateInterface.RemoveLocal(type, name, deviceTags));

    type = InputHandlerType::INTERCEPTOR;
    name = "handler3";
    ASSERT_NO_FATAL_FAILURE(delegateInterface.RemoveLocal(type, name, deviceTags));

    type = InputHandlerType::INTERCEPTOR;
    name = "handler1";
    ASSERT_NO_FATAL_FAILURE(delegateInterface.RemoveLocal(type, name, deviceTags));
}

/**
 * @tc.name: DelegateInterfaceTest_GetPriority_01
 * @tc.desc: Test the function GetPriority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_GetPriority_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    InputHandlerType type = InputHandlerType::INTERCEPTOR;
    DelegateInterface::HandlerSummary handler1 = {"handler1", 0x1, HandlerMode::SYNC, 1, 2};
    DelegateInterface::HandlerSummary handler2 = {"handler2", 0x2, HandlerMode::ASYNC, 2, 3};
    delegateInterface.handlers_.insert({INTERCEPTOR, handler1});
    delegateInterface.handlers_.insert({MONITOR, handler2});

    int32_t ret = delegateInterface.GetPriority(type);
    EXPECT_EQ(ret, 1);

    type = InputHandlerType::NONE;
    int32_t ret2 = delegateInterface.GetPriority(type);
    EXPECT_EQ(ret2, 500);
}

/**
 * @tc.name: DelegateInterfaceTest_GetEventType_01
 * @tc.desc: Test the function GetEventType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_GetEventType_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    InputHandlerType type = InputHandlerType::MONITOR;
    EXPECT_TRUE(delegateInterface.handlers_.empty());
    uint32_t ret = delegateInterface.GetEventType(type);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: DelegateInterfaceTest_GetEventType_02
 * @tc.desc: Test the function GetEventType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_GetEventType_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    InputHandlerType type = InputHandlerType::MONITOR;
    DelegateInterface::HandlerSummary handler1 = {"handler1", 0x1, HandlerMode::SYNC, 1, 2};
    DelegateInterface::HandlerSummary handler2 = {"handler2", 0x2, HandlerMode::ASYNC, 2, 3};
    delegateInterface.handlers_.insert({INTERCEPTOR, handler1});
    delegateInterface.handlers_.insert({MONITOR, handler2});
    uint32_t ret = delegateInterface.GetEventType(type);
    EXPECT_EQ(ret, 2);
}

/**
 * @tc.name: DelegateInterfaceTest_OnPostSyncTask_01
 * @tc.desc: Test the function OnPostSyncTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_OnPostSyncTask_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    DTaskCallback myCallback = []() -> int32_t {
        return RET_OK;
    };
    uint32_t ret = delegateInterface.OnPostSyncTask(myCallback);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: DelegateInterfaceTest_OnInputEventHandler_01
 * @tc.desc: Test the function OnInputEventHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_OnInputEventHandler_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    InputHandlerType type = InputHandlerType::NONE;
    DelegateInterface::HandlerSummary handler1 = {"handler1", 0x1, HandlerMode::SYNC, 1, 2};
    DelegateInterface::HandlerSummary handler2 = {"handler2", 0x2, HandlerMode::ASYNC, 2, 3};
    delegateInterface.handlers_.insert({INTERCEPTOR, handler1});
    delegateInterface.handlers_.insert({MONITOR, handler2});
    ASSERT_NO_FATAL_FAILURE(delegateInterface.OnInputEventHandler(type, pointerEvent));
#ifdef OHOS_BUILD_ENABLE_MONITOR
    type = InputHandlerType::MONITOR;
    ASSERT_NO_FATAL_FAILURE(delegateInterface.OnInputEventHandler(type, pointerEvent));
#endif // OHOS_BUILD_ENABLE_MONITOR

#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    type = InputHandlerType::INTERCEPTOR;
    ASSERT_NO_FATAL_FAILURE(delegateInterface.OnInputEventHandler(type, pointerEvent));
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
}

/**
 * @tc.name: DelegateInterfaceTest_AddHandler_01
 * @tc.desc: Test the function AddHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_AddHandler_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    DelegateInterface::HandlerSummary summary;
    summary.handlerName = "handler1";
    auto callback = [](std::shared_ptr<PointerEvent> event) -> int32_t {
        return RET_OK;
    };
    summary.cb = callback;
    DelegateInterface::HandlerSummary handler1 = {"handler1", 0x1, HandlerMode::SYNC, 1, 2};
    DelegateInterface::HandlerSummary handler2 = {"handler2", 0x2, HandlerMode::ASYNC, 2, 3};
    delegateInterface.handlers_.insert({INTERCEPTOR, handler1});
    delegateInterface.handlers_.insert({MONITOR, handler2});

    InputHandlerType type = InputHandlerType::MONITOR;
    int32_t ret = delegateInterface.AddHandler(type, summary);
    EXPECT_EQ(ret, RET_OK);

    summary.handlerName = "handler";
    int32_t ret2 = delegateInterface.AddHandler(type, summary);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: DelegateInterfaceTest_AddHandler_02
 * @tc.desc: Test the function AddHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_AddHandler_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    DelegateInterface::HandlerSummary summary;
    summary.handlerName = "handler";
    auto callback = [](std::shared_ptr<PointerEvent> event) -> int32_t {
        return RET_OK;
    };
    summary.cb = callback;
    DelegateInterface::HandlerSummary handler1 = {"handler1", 0x1, HandlerMode::SYNC, 1, 2};
    DelegateInterface::HandlerSummary handler2 = {"handler2", 0x2, HandlerMode::ASYNC, 2, 3};
    delegateInterface.handlers_.insert({INTERCEPTOR, handler1});
    delegateInterface.handlers_.insert({MONITOR, handler2});

    InputHandlerType type = InputHandlerType::MONITOR;
    HandleEventType currentType = delegateInterface.GetEventType(type);
    type = InputHandlerType::INTERCEPTOR;
    HandleEventType newType = delegateInterface.GetEventType(type);
    EXPECT_TRUE(currentType != newType);

    uint32_t currentTags = delegateInterface.GetDeviceTags(type);
    summary.deviceTags = 1;
    EXPECT_TRUE((currentTags & summary.deviceTags) != summary.deviceTags);

    int32_t ret = delegateInterface.AddHandler(type, summary);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);

    type = InputHandlerType::MONITOR;
    currentType = delegateInterface.GetEventType(type);
    newType = delegateInterface.GetEventType(type);
    EXPECT_FALSE(currentType != newType);
    int32_t ret2 = delegateInterface.AddHandler(type, summary);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: DelegateInterfaceTest_OnPostAsyncTask_01
 * @tc.desc: Test the function OnPostAsyncTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_OnPostAsyncTask_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    DTaskCallback myCallback = []() -> int32_t {
        return RET_OK;
    };
    int32_t ret = delegateInterface.OnPostAsyncTask(myCallback);
    EXPECT_EQ(ret, RET_OK);
}
/**
 * @tc.name: DelegateInterfaceTest_OnPostAsyncTask_02
 * @tc.desc: Test the function OnPostAsyncTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_OnPostAsyncTask_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    DTaskCallback myCallback = []() -> int32_t {
        return RET_ERR;
    };
    ASSERT_NO_FATAL_FAILURE(delegateInterface.OnPostAsyncTask(myCallback));
}

/**
 * @tc.name: DelegateInterfaceTest_OnPostSyncTask_02
 * @tc.desc: Test the function OnPostSyncTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_OnPostSyncTask_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    DTaskCallback myCallback = []() -> int32_t {
        return RET_ERR;
    };
    ASSERT_NO_FATAL_FAILURE(delegateInterface.OnPostSyncTask(myCallback));
}

/**
 * @tc.name: DelegateInterfaceTest_OnInputEventHandler_02
 * @tc.desc: Test the function OnInputEventHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_OnInputEventHandler_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    InputHandlerType type = InputHandlerType::NONE;
    DelegateInterface::HandlerSummary handler1 = {"handler1", 0x1, HandlerMode::SYNC, 1, 2};
    DelegateInterface::HandlerSummary handler2 = {"handler2", 0x2, HandlerMode::ASYNC, 2, 3};
    delegateInterface.handlers_.insert({INTERCEPTOR, handler1});
    delegateInterface.handlers_.insert({MONITOR, handler2});
    ASSERT_NO_FATAL_FAILURE(delegateInterface.OnInputEventHandler(type, pointerEvent));
#ifdef OHOS_BUILD_ENABLE_MONITOR
    type = InputHandlerType::MONITOR;
    ASSERT_NO_FATAL_FAILURE(delegateInterface.OnInputEventHandler(type, pointerEvent));
#endif // OHOS_BUILD_ENABLE_MONITOR

#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    type = InputHandlerType::INTERCEPTOR;
    ASSERT_NO_FATAL_FAILURE(delegateInterface.OnInputEventHandler(type, pointerEvent));
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    auto callback = [](std::shared_ptr<PointerEvent> event) -> int32_t {
        return RET_OK;
    };
    handler1.cb = callback;
    ASSERT_NO_FATAL_FAILURE(delegateInterface.OnInputEventHandler(type, pointerEvent));
    handler1.mode = HandlerMode::ASYNC;
    ASSERT_NO_FATAL_FAILURE(delegateInterface.OnInputEventHandler(type, pointerEvent));
}

/**
 * @tc.name: DelegateInterfaceTest_RemoveHandler_01
 * @tc.desc: Test the function RemoveHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_RemoveHandler_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    DelegateInterface delegateInterface(delegate, asyncFun);
    DelegateInterface::HandlerSummary summary;
    summary.handlerName = "handler1";
    auto callback = [](std::shared_ptr<PointerEvent> event) -> int32_t {
        return RET_OK;
    };
    summary.cb = callback;
    DelegateInterface::HandlerSummary handler1 = {"handler1", 0x1, HandlerMode::SYNC, 1, 2};
    DelegateInterface::HandlerSummary handler2 = {"handler2", 0x2, HandlerMode::ASYNC, 2, 3};
    delegateInterface.handlers_.insert({INTERCEPTOR, handler1});
    delegateInterface.handlers_.insert({MONITOR, handler2});

    InputHandlerType type = InputHandlerType::MONITOR;
    delegateInterface.AddHandler(type, summary);
    ASSERT_NO_FATAL_FAILURE(delegateInterface.RemoveHandler(type, summary.handlerName));
    type = InputHandlerType::INTERCEPTOR;
    ASSERT_NO_FATAL_FAILURE(delegateInterface.RemoveHandler(type, summary.handlerName));
}

} // namespace MMI
} // namespace OHOS