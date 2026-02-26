/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "pointer_loop_closure_checker.h"
#include "event_dispatch_handler.h"
#include "event_loop_closure_checker.h"
#include "event_dispatch_order_checker.h"
#include "define_multimodal.h"
#include "error_multimodal.h"
#include "input_event_handler.h"
#include "uds_server.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerLoopClosureCheckerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class PointerLoopClosureCheckerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: PointerLoopClosureCheckerTest_001
 * @tc.desc: Test the function CheckAndUpdateEventLoopClosure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, PointerLoopClosureCheckerTest_001, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    int32_t flag = 10;
    int32_t ret = closureChecker.closureChecker_.HandleDown(flag);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: PointerLoopClosureCheckerTest_002
 * @tc.desc: Test the function CheckAndUpdateEventLoopClosure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, PointerLoopClosureCheckerTest_002, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    int32_t flag = 10;
    int32_t ret = closureChecker.closureChecker_.HandleUpOrCancel(flag);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PointerLoopClosureCheckerTest_003
 * @tc.desc: Test the function CheckAndUpdateEventLoopClosure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, PointerLoopClosureCheckerTest_003, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    int32_t flag = 10;
    int32_t ret = closureChecker.closureChecker_.HandleMove(flag);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PointerLoopClosureCheckerTest_004
 * @tc.desc: Test the function CheckAndUpdateEventLoopClosure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, PointerLoopClosureCheckerTest_004, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    int32_t flag = 10;
    int32_t ret = closureChecker.closureChecker_.CheckLoopClosure(flag);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PointerLoopClosureCheckerTest_005
 * @tc.desc: Test the function CheckAndUpdateEventLoopClosure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, PointerLoopClosureCheckerTest_005, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    int32_t flag = 10;
    int32_t ret = closureChecker.closureChecker_.UpdatePendingDownFlags(flag);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: PointerLoopClosureCheckerTest_006
 * @tc.desc: Test the function CheckAndUpdateEventLoopClosure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, PointerLoopClosureCheckerTest_006, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    int32_t flag = 10;
    int32_t ret = closureChecker.closureChecker_.RemovePendingDownFlags(flag);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PointerLoopClosureCheckerTest_007
 * @tc.desc: Test the function CheckAndUpdateEventLoopClosure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, PointerLoopClosureCheckerTest_007, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    ASSERT_NE(event, nullptr);
    int32_t ret = closureChecker.CheckAndUpdateEventLoopClosure(event);
    EXPECT_EQ(ret, RET_OK);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ret = closureChecker.CheckAndUpdateEventLoopClosure(event);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: PointerLoopClosureCheckerTest_008
 * @tc.desc: Test the function CheckAndUpdateEventLoopClosure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, PointerLoopClosureCheckerTest_008, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    ASSERT_NE(event, nullptr);
    int32_t ret = closureChecker.HandleMouseEvent(event);
    EXPECT_EQ(ret, RET_OK);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ret = closureChecker.HandleMouseEvent(event);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: PointerLoopClosureCheckerTest_009
 * @tc.desc: Test the function CheckAndUpdateEventLoopClosure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, PointerLoopClosureCheckerTest_009, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    ASSERT_NE(event, nullptr);
    int32_t ret = closureChecker.HandleTouchEvent(event);
    EXPECT_EQ(ret, RET_OK);
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    ret = closureChecker.HandleTouchEvent(event);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: HandleMouseEventTest_001
 * @tc.desc: Test HandleMouseEvent with POINTER_ACTION_BUTTON_DOWN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, HandleMouseEventTest_001, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    event->SetButtonId(5);
    ASSERT_NE(event, nullptr);

    int32_t ret = closureChecker.HandleMouseEvent(event);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: HandleMouseEventTest_002
 * @tc.desc: Test HandleMouseEvent with POINTER_ACTION_BUTTON_UP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, HandleMouseEventTest_002, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    event->SetButtonId(5);
    ASSERT_NE(event, nullptr);

    int32_t ret = closureChecker.HandleMouseEvent(event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: HandleMouseEventTest_003
 * @tc.desc: Test HandleMouseEvent with unsupported action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, HandleMouseEventTest_003, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    event->SetButtonId(5);
    ASSERT_NE(event, nullptr);

    int32_t ret = closureChecker.HandleMouseEvent(event);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: HandleTouchEventTest_001
 * @tc.desc: Test HandleTouchEvent with POINTER_ACTION_DOWN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, HandleTouchEventTest_001, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    event->SetPointerId(1);
    ASSERT_NE(event, nullptr);

    int32_t ret = closureChecker.HandleTouchEvent(event);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: HandleTouchEventTest_002
 * @tc.desc: Test HandleTouchEvent with POINTER_ACTION_UP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, HandleTouchEventTest_002, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    event->SetPointerId(1);
    ASSERT_NE(event, nullptr);

    int32_t ret = closureChecker.HandleTouchEvent(event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: HandleTouchEventTest_003
 * @tc.desc: Test HandleTouchEvent with unsupported action
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, HandleTouchEventTest_003, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    event->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    event->SetPointerId(1);
    ASSERT_NE(event, nullptr);

    int32_t ret = closureChecker.HandleTouchEvent(event);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CheckAndUpdateEventLoopClosureTest_001
 * @tc.desc: Test CheckAndUpdateEventLoopClosure with SOURCE_TYPE_TOUCHSCREEN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, CheckAndUpdateEventLoopClosureTest_001, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ASSERT_NE(event, nullptr);

    int32_t ret = closureChecker.CheckAndUpdateEventLoopClosure(event);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CheckAndUpdateEventLoopClosureTest_002
 * @tc.desc: Test CheckAndUpdateEventLoopClosure with unsupported source type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, CheckAndUpdateEventLoopClosureTest_002, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    std::shared_ptr<PointerEvent> event = PointerEvent::Create();
    event->SetSourceType(PointerEvent::SOURCE_TYPE_UNKNOWN);
    ASSERT_NE(event, nullptr);

    int32_t ret = closureChecker.CheckAndUpdateEventLoopClosure(event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CheckAndUpdateEventLoopClosureTest_003
 * @tc.desc: Test CheckAndUpdateEventLoopClosure with null event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, CheckAndUpdateEventLoopClosureTest_003, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    std::shared_ptr<PointerEvent> event = nullptr;

    int32_t ret = closureChecker.CheckAndUpdateEventLoopClosure(event);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: ClosureChecker_CheckLoopClosureTest_001
 * @tc.desc: Test CheckLoopClosure with existing flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, ClosureChecker_CheckLoopClosureTest_001, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    int32_t flag = 10;
    closureChecker.closureChecker_.UpdatePendingDownFlags(flag);

    int32_t ret = closureChecker.closureChecker_.CheckLoopClosure(flag);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ClosureChecker_RemovePendingDownFlagsTest_001
 * @tc.desc: Test RemovePendingDownFlags with non-existing flag
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerLoopClosureCheckerTest, ClosureChecker_RemovePendingDownFlagsTest_001, TestSize.Level0)
{
    PointerLoopClosureChecker closureChecker;
    int32_t flag = 10;

    int32_t ret = closureChecker.closureChecker_.RemovePendingDownFlags(flag);
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace MMI
} // namespace OHOS
