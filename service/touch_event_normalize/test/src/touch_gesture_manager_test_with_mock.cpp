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

#include <cstdio>
#include <gtest/gtest.h>

#include "delegate_interface.h"
#include "input_event_handler.h"
#include "touch_gesture_manager.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchGestureManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
}
class TouchGestureManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: AddHandler_Test_001
 * @tc.desc: Test when AddHandler is called with valid parameters, it should add the handler to the handlers_ set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureManagerTest, AddHandler_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto delegateFunc = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    auto asyncFunc = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    auto delegate = std::make_shared<DelegateInterface>(delegateFunc, asyncFunc);
    TouchGestureManager touchGestureManager(delegate);
    int32_t session = 1;
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t nFingers = 0;
    touchGestureManager.AddHandler(session, gestureType, nFingers);
    EXPECT_EQ(touchGestureManager.handlers_.size(), 1);
    EXPECT_EQ(touchGestureManager.handlers_.begin()->session_, session);
}

/**
 * @tc.name  : AddHandler_Test_003
 * @tc.desc  : Test when AddHandler is called with different parameters, it should add the handler to the handlers_ set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureManagerTest, AddHandler_Test_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto delegateFunc = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    auto asyncFunc = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    auto delegate = std::make_shared<DelegateInterface>(delegateFunc, asyncFunc);
    TouchGestureManager touchGestureManager(delegate);
    int32_t session = 1;
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t nFingers = 0;
    touchGestureManager.AddHandler(session, gestureType, nFingers);
    int32_t newSession = 2;
    TouchGestureType newGestureType = TOUCH_GESTURE_TYPE_NONE;
    int32_t newNFingers = 0;
    touchGestureManager.AddHandler(newSession, newGestureType, newNFingers);
    EXPECT_EQ(touchGestureManager.handlers_.size(), 2);
    touchGestureManager.RemoveHandler(session, gestureType, nFingers);
    EXPECT_EQ(touchGestureManager.handlers_.size(), 1);
    touchGestureManager.RemoveHandler(session, gestureType, nFingers);
    EXPECT_EQ(touchGestureManager.handlers_.size(), 1);
}

/**
 * @tc.name  : AddHandler_Test_003
 * @tc.desc  : Test when AddHandler is called with different parameters, it should add the handler to the handlers_ set
 * @tc.type: FUNC
 * @tc.require:
  */
HWTEST_F(TouchGestureManagerTest, StartRecognization_ShouldNotAddHandler_WhenHandlerExists, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto delegateFunc = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    auto asyncFunc = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    auto delegate = std::make_shared<DelegateInterface>(delegateFunc, asyncFunc);
    TouchGestureManager touchGestureManager(delegate);
    TouchGestureType gestureType = TOUCH_GESTURE_TYPE_ALL;
    int32_t nFingers = 1;
    EXPECT_NO_FATAL_FAILURE(touchGestureManager.StartRecognization(gestureType, nFingers));
    touchGestureManager.AddHandler(1, gestureType, nFingers);
    EXPECT_NO_FATAL_FAILURE(touchGestureManager.StartRecognization(gestureType, nFingers));
}

/**
 * @tc.name  : StopRecognization_Test_002
 * @tc.desc  : Test when the handler does not exist in the handlers_ set, the function should continue to execute
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureManagerTest, StopRecognization_Test_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto delegateFunc = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    auto asyncFunc = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    auto delegate = std::make_shared<DelegateInterface>(delegateFunc, asyncFunc);
    TouchGestureManager touchGestureManager(delegate);
    TouchGestureType gestureType = 1;
    int32_t nFingers = 0;
    EXPECT_NO_FATAL_FAILURE(touchGestureManager.StopRecognization(gestureType, nFingers));
    touchGestureManager.AddHandler(1, gestureType, nFingers);
    EXPECT_NO_FATAL_FAILURE(touchGestureManager.StopRecognization(gestureType, nFingers));
}

/**
 * @tc.name  : OnSessionLost_Test_001
 * @tc.desc  : Test when session is valid then RemoveHandler is called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TouchGestureManagerTest, OnSessionLost_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto delegateFunc = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    auto asyncFunc = [](DTaskCallback cb) -> int32_t {
        return 0;
    };
    auto delegate = std::make_shared<DelegateInterface>(delegateFunc, asyncFunc);
    TouchGestureManager manager(delegate);
    int32_t session = 1;
    TouchGestureType gestureType = 1;
    int32_t nFingers = 0;
    manager.AddHandler(session, gestureType, nFingers);
    EXPECT_NO_FATAL_FAILURE(manager.OnSessionLost(session));
}

} // namespace MMI
} // namespace OHOS