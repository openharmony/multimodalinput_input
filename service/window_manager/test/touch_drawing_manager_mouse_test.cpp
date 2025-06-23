/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include <fstream>
#include <gtest/gtest.h>

#include "mmi_log.h"
#include "pointer_event.h"
#ifndef USE_ROSEN_DRAWING
#define USE_ROSEN_DRAWING
#endif
#include "touch_drawing_manager.h"
#include "window_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchDrawingManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class TouchDrawingManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void)
    {
        DisplayInfo info;
        info.id = 1;
        info.x =1;
        info.y = 1;
        info.width = 1;
        info.height = 1;
        int32_t displayDpi = 240;
        info.dpi = displayDpi;
        info.name = "xx";
        info.uniq = "xx";
        info.direction = DIRECTION0;
        TOUCH_DRAWING_MGR->UpdateDisplayInfo(info);
    }
};

/**
 * @tc.name: TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_001
 * @tc.desc: Test GetOriginalTouchScreenCoordinates
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t width = 100;
    int32_t height = 200;
    int32_t physicalX = 50;
    int32_t physicalY = 60;
    TOUCH_DRAWING_MGR->GetOriginalTouchScreenCoordinates(DIRECTION0, width, height, physicalX, physicalY);
    EXPECT_EQ(physicalX, 50);
    EXPECT_EQ(physicalY, 60);
}

/**
 * @tc.name: TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_002
 * @tc.desc: Test GetOriginalTouchScreenCoordinates
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t width = 100;
    int32_t height = 200;
    int32_t physicalX = 50;
    int32_t physicalY = 60;
    TOUCH_DRAWING_MGR->GetOriginalTouchScreenCoordinates(DIRECTION90, width, height, physicalX, physicalY);
    EXPECT_EQ(physicalX, 60);
    EXPECT_EQ(physicalY, 50);
}

/**
 * @tc.name: TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_003
 * @tc.desc: Test GetOriginalTouchScreenCoordinates
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t width = 100;
    int32_t height = 200;
    int32_t physicalX = 50;
    int32_t physicalY = 60;
    TOUCH_DRAWING_MGR->GetOriginalTouchScreenCoordinates(DIRECTION180, width, height, physicalX, physicalY);
    EXPECT_EQ(physicalX, 50);
    EXPECT_EQ(physicalY, 140);
}

/**
 * @tc.name: TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_004
 * @tc.desc: Test GetOriginalTouchScreenCoordinates
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t width = 100;
    int32_t height = 200;
    int32_t physicalX = 50;
    int32_t physicalY = 60;
    TOUCH_DRAWING_MGR->GetOriginalTouchScreenCoordinates(DIRECTION270, width, height, physicalX, physicalY);
    EXPECT_EQ(physicalX, 140);
    EXPECT_EQ(physicalY, 50);
}

/**
 * @tc.name: TouchDrawingManagerTest_IsValidAction_001
 * @tc.desc: Test is valid action
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_IsValidAction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager manager;
    bool ret = manager.IsValidAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_TRUE(ret);
    ret = manager.IsValidAction(PointerEvent::POINTER_ACTION_PULL_DOWN);
    EXPECT_TRUE(ret);
    ret = manager.IsValidAction(PointerEvent::POINTER_ACTION_MOVE);
    EXPECT_TRUE(ret);
    ret = manager.IsValidAction(PointerEvent::POINTER_ACTION_PULL_MOVE);
    EXPECT_TRUE(ret);
    ret = manager.IsValidAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_TRUE(ret);
    ret = manager.IsValidAction(PointerEvent::POINTER_ACTION_PULL_UP);
    EXPECT_TRUE(ret);
    ret = manager.IsValidAction(100);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubbleHandler_001
 * @tc.desc: Test DrawBubbleHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawBubbleHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    EXPECT_NE(pointerEvent, nullptr);
    TOUCH_DRAWING_MGR->pointerEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawBubbleHandler());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubbleHandler_002
 * @tc.desc: Test DrawBubbleHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawBubbleHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    EXPECT_NE(pointerEvent, nullptr);
    TOUCH_DRAWING_MGR->pointerEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawBubbleHandler());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubbleHandler_003
 * @tc.desc: Test DrawBubbleHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawBubbleHandler_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_NE(pointerEvent, nullptr);
    TOUCH_DRAWING_MGR->pointerEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawBubbleHandler());
}