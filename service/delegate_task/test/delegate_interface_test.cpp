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
    DelegateInterface& CreateDelegateInterface();
    DelegateInterface::HandlerSummary CreateHandlerSummary01();
    DelegateInterface::HandlerSummary CreateHandlerSummary02();
    void TearDown();
};

DelegateInterface& DelegateInterfaceTest::CreateDelegateInterface()
{
    std::function<int32_t(DTaskCallback)> delegate = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    std::function<int32_t(DTaskCallback)> asyncFun = [this](DTaskCallback cb) -> int32_t {
        return 0;
    };
    static DelegateInterface delegateInterface_(delegate, asyncFun);
    return delegateInterface_;
}

DelegateInterface::HandlerSummary DelegateInterfaceTest::CreateHandlerSummary01()
{
    auto callback = [](std::shared_ptr<PointerEvent> event) -> int32_t {
        return RET_OK;
    };
    DelegateInterface::HandlerSummary handler = {
        .handlerName = "handler1",
        .deviceTags = 0,
        .cb = callback
    };
    return handler;
}

DelegateInterface::HandlerSummary DelegateInterfaceTest::CreateHandlerSummary02()
{
    auto callback = [](std::shared_ptr<PointerEvent> event) -> int32_t {
        return RET_OK;
    };
    DelegateInterface::HandlerSummary handler = {
        .handlerName = "handler2",
        .deviceTags = 0,
        .cb = callback
    };
    return handler;
}

void DelegateInterfaceTest::TearDown()
{
    CreateDelegateInterface().handlers_.clear();
}

/**
 * @tc.name: DelegateInterfaceTest_GetDeviceTags_01
 * @tc.desc: Test the function GetDeviceTags
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DelegateInterfaceTest, DelegateInterfaceTest_GetDeviceTags_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputHandlerType type = InputHandlerType::MONITOR;
    uint32_t ret = CreateDelegateInterface().GetDeviceTags(type);
    EXPECT_EQ(ret, 0);

    type = InputHandlerType::NONE;
    EXPECT_TRUE(CreateDelegateInterface().handlers_.empty());
    uint32_t ret2 = CreateDelegateInterface().GetDeviceTags(type);
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
    InputHandlerType type = InputHandlerType::INTERCEPTOR;
    DelegateInterface::HandlerSummary handler1 = CreateHandlerSummary01();
    DelegateInterface::HandlerSummary handler2 = CreateHandlerSummary02();
    int32_t ret = CreateDelegateInterface().AddHandler(INTERCEPTOR, handler1);
    EXPECT_EQ(ret, RET_OK);
    ret = CreateDelegateInterface().AddHandler(MONITOR, handler2);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_FALSE(CreateDelegateInterface().handlers_.empty());
    uint32_t ret1 = CreateDelegateInterface().GetDeviceTags(type);
    EXPECT_EQ(ret1, 0);

    type = InputHandlerType::NONE;
    uint32_t ret2 = CreateDelegateInterface().GetDeviceTags(type);
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
    InputHandlerType type = InputHandlerType::NONE;
    std::string name = "handler";
    uint32_t deviceTags = 1;
    DelegateInterface::HandlerSummary handler1 = CreateHandlerSummary01();
    DelegateInterface::HandlerSummary handler2 = CreateHandlerSummary02();
    int32_t ret = CreateDelegateInterface().AddHandler(INTERCEPTOR, handler1);
    EXPECT_EQ(ret, RET_OK);
    ret = CreateDelegateInterface().AddHandler(MONITOR, handler2);
    EXPECT_EQ(ret, RET_OK);
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().RemoveLocal(type, name, deviceTags));
    bool result = CreateDelegateInterface().HasHandler(name);
    EXPECT_FALSE(result);

    type = InputHandlerType::INTERCEPTOR;
    name = "handler3";
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().RemoveLocal(type, name, deviceTags));
    result = CreateDelegateInterface().HasHandler(name);
    EXPECT_FALSE(result);

    type = InputHandlerType::INTERCEPTOR;
    name = "handler1";
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().RemoveLocal(type, name, deviceTags));
    result = CreateDelegateInterface().HasHandler(name);
    EXPECT_FALSE(result);
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
    InputHandlerType type = InputHandlerType::INTERCEPTOR;
    DelegateInterface::HandlerSummary handler1 = CreateHandlerSummary01();
    handler1.priority = 1;
    DelegateInterface::HandlerSummary handler2 = CreateHandlerSummary02();
    int32_t ret = CreateDelegateInterface().AddHandler(INTERCEPTOR, handler1);
    EXPECT_EQ(ret, RET_OK);
    ret = CreateDelegateInterface().AddHandler(MONITOR, handler2);
    EXPECT_EQ(ret, RET_OK);

    ret = CreateDelegateInterface().GetPriority(type);
    EXPECT_EQ(ret, 1);

    type = InputHandlerType::NONE;
    int32_t ret2 = CreateDelegateInterface().GetPriority(type);
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
    InputHandlerType type = InputHandlerType::MONITOR;
    EXPECT_TRUE(CreateDelegateInterface().handlers_.empty());
    uint32_t ret = CreateDelegateInterface().GetEventType(type);
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
    InputHandlerType type = InputHandlerType::MONITOR;
    DelegateInterface::HandlerSummary handler1 = CreateHandlerSummary01();
    DelegateInterface::HandlerSummary handler2 = CreateHandlerSummary02();
    handler2.eventType = HANDLE_EVENT_TYPE_TOUCH;
    int32_t ret = CreateDelegateInterface().AddHandler(INTERCEPTOR, handler1);
    EXPECT_EQ(ret, RET_OK);
    CreateDelegateInterface().handlers_.emplace(type, handler2);
    uint32_t result = CreateDelegateInterface().GetEventType(type);
    EXPECT_EQ(result, HANDLE_EVENT_TYPE_TOUCH);
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
    DTaskCallback myCallback = []() -> int32_t {
        return RET_OK;
    };
    uint32_t ret = CreateDelegateInterface().OnPostSyncTask(myCallback);
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
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    InputHandlerType type = InputHandlerType::NONE;
    DelegateInterface::HandlerSummary handler1 = CreateHandlerSummary01();
    DelegateInterface::HandlerSummary handler2 = CreateHandlerSummary02();
    int32_t ret = CreateDelegateInterface().AddHandler(INTERCEPTOR, handler1);
    EXPECT_EQ(ret, RET_OK);
    ret = CreateDelegateInterface().AddHandler(MONITOR, handler2);
    EXPECT_EQ(ret, RET_OK);
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().OnInputEventHandler(type, pointerEvent));
#ifdef OHOS_BUILD_ENABLE_MONITOR
    type = InputHandlerType::MONITOR;
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().OnInputEventHandler(type, pointerEvent));
#endif // OHOS_BUILD_ENABLE_MONITOR

#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    type = InputHandlerType::INTERCEPTOR;
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().OnInputEventHandler(type, pointerEvent));
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
    DelegateInterface::HandlerSummary summary;
    summary.handlerName = "handler1";
    auto callback = [](std::shared_ptr<PointerEvent> event) -> int32_t {
        return RET_OK;
    };
    summary.cb = callback;
    DelegateInterface::HandlerSummary handler1 = CreateHandlerSummary01();
    DelegateInterface::HandlerSummary handler2 = CreateHandlerSummary02();
    int32_t ret = CreateDelegateInterface().AddHandler(INTERCEPTOR, handler1);
    EXPECT_EQ(ret, RET_OK);
    ret = CreateDelegateInterface().AddHandler(MONITOR, handler2);
    EXPECT_EQ(ret, RET_OK);

    InputHandlerType type = InputHandlerType::MONITOR;
    ret = CreateDelegateInterface().AddHandler(type, summary);
    EXPECT_EQ(ret, RET_OK);

    summary.handlerName = "handler";
    int32_t ret2 = CreateDelegateInterface().AddHandler(type, summary);
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
    DelegateInterface::HandlerSummary summary;
    summary.handlerName = "handler";
    auto callback = [](std::shared_ptr<PointerEvent> event) -> int32_t {
        return RET_OK;
    };
    summary.cb = callback;
    DelegateInterface::HandlerSummary handler1 = CreateHandlerSummary01();
    DelegateInterface::HandlerSummary handler2 = CreateHandlerSummary02();
    handler2.eventType = HANDLE_EVENT_TYPE_MOUSE;
    int32_t ret = CreateDelegateInterface().AddHandler(INTERCEPTOR, handler1);
    EXPECT_EQ(ret, RET_OK);
    CreateDelegateInterface().handlers_.emplace(MONITOR, handler2);

    InputHandlerType type = InputHandlerType::MONITOR;
    HandleEventType currentType = CreateDelegateInterface().GetEventType(type);
    type = InputHandlerType::INTERCEPTOR;
    HandleEventType newType = CreateDelegateInterface().GetEventType(type);
    EXPECT_TRUE(currentType != newType);

    uint32_t currentTags = CreateDelegateInterface().GetDeviceTags(type);
    summary.deviceTags = 1;
    EXPECT_TRUE((currentTags & summary.deviceTags) != summary.deviceTags);

    ret = CreateDelegateInterface().AddHandler(type, summary);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);

    currentType = CreateDelegateInterface().GetEventType(type);
    newType = CreateDelegateInterface().GetEventType(type);
    EXPECT_FALSE(currentType != newType);
    int32_t ret2 = CreateDelegateInterface().AddHandler(type, summary);
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
    DTaskCallback myCallback = []() -> int32_t {
        return RET_OK;
    };
    int32_t ret = CreateDelegateInterface().OnPostAsyncTask(myCallback);
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
    DTaskCallback myCallback = []() -> int32_t {
        return RET_ERR;
    };
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().OnPostAsyncTask(myCallback));
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
    DTaskCallback myCallback = []() -> int32_t {
        return RET_ERR;
    };
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().OnPostSyncTask(myCallback));
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
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);

    InputHandlerType type = InputHandlerType::NONE;
    DelegateInterface::HandlerSummary handler1 = CreateHandlerSummary01();
    DelegateInterface::HandlerSummary handler2 = CreateHandlerSummary02();
    int32_t ret = CreateDelegateInterface().AddHandler(INTERCEPTOR, handler1);
    EXPECT_EQ(ret, RET_OK);
    ret = CreateDelegateInterface().AddHandler(MONITOR, handler2);
    EXPECT_EQ(ret, RET_OK);
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().OnInputEventHandler(type, pointerEvent));
#ifdef OHOS_BUILD_ENABLE_MONITOR
    type = InputHandlerType::MONITOR;
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().OnInputEventHandler(type, pointerEvent));
#endif // OHOS_BUILD_ENABLE_MONITOR

#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    type = InputHandlerType::INTERCEPTOR;
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().OnInputEventHandler(type, pointerEvent));
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR
    auto callback = [](std::shared_ptr<PointerEvent> event) -> int32_t {
        return RET_OK;
    };
    handler1.cb = callback;
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().OnInputEventHandler(type, pointerEvent));
    handler1.mode = HandlerMode::ASYNC;
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().OnInputEventHandler(type, pointerEvent));
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
    DelegateInterface::HandlerSummary summary;
    summary.handlerName = "handler2";
    auto callback = [](std::shared_ptr<PointerEvent> event) -> int32_t {
        return RET_OK;
    };
    summary.cb = callback;
    DelegateInterface::HandlerSummary handler1 = CreateHandlerSummary01();
    DelegateInterface::HandlerSummary handler2 = CreateHandlerSummary02();
    int32_t ret = CreateDelegateInterface().AddHandler(INTERCEPTOR, handler1);
    EXPECT_EQ(ret, RET_OK);
    ret = CreateDelegateInterface().AddHandler(MONITOR, handler2);
    EXPECT_EQ(ret, RET_OK);

    InputHandlerType type = InputHandlerType::MONITOR;
    ret = CreateDelegateInterface().AddHandler(type, summary);
    EXPECT_EQ(ret, RET_OK);
    CreateDelegateInterface().AddHandler(type, summary);
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().RemoveHandler(type, summary.handlerName));
    bool result = CreateDelegateInterface().HasHandler(summary.handlerName);
    EXPECT_FALSE(result);
    type = InputHandlerType::INTERCEPTOR;
    ASSERT_NO_FATAL_FAILURE(CreateDelegateInterface().RemoveHandler(type, summary.handlerName));
    result = CreateDelegateInterface().HasHandler(summary.handlerName);
    EXPECT_FALSE(result);
}

} // namespace MMI
} // namespace OHOS