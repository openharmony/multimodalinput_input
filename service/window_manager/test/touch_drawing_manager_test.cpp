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
constexpr int32_t DENSITY_BASELINE = 160;
constexpr int32_t INDEPENDENT_INNER_PIXELS = 20;
constexpr int32_t INDEPENDENT_OUTER_PIXELS = 21;
constexpr int32_t INDEPENDENT_WIDTH_PIXELS = 2;
constexpr int32_t CALCULATE_MIDDLE = 2;
} // namespace
class TouchDrawingManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void)
    {
        // 创建displayInfo_
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
    } // void SetUp(void)
};

/**
 * @tc.name: TouchDrawingManagerTest_TouchDrawHandler_001
 * @tc.desc: Test TouchDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_TouchDrawHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    int32_t displayX = 100;
    int32_t displayY = 100;
    item.SetDisplayX(displayX);
    item.SetDisplayY(displayY);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->TouchDrawHandler(pointerEvent));
}

/**
 * @tc.name: TouchDrawingManagerTest_TouchDrawHandler_002
 * @tc.desc: Test TouchDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_TouchDrawHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    int32_t displayX = 200;
    int32_t displayY = 200;
    item.SetDisplayX(displayX);
    item.SetDisplayY(displayY);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->TouchDrawHandler(pointerEvent));
}

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
 * @tc.name: TouchDrawingManagerTest_UpdateDisplayInfo_001
 * @tc.desc: Test update display info
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager manager;
    DisplayInfo displayInfo;
    displayInfo.dpi = 160;
    manager.UpdateDisplayInfo(displayInfo);
    EXPECT_EQ(manager.bubble_.innerCircleRadius,
    displayInfo.dpi * INDEPENDENT_INNER_PIXELS / DENSITY_BASELINE / CALCULATE_MIDDLE);
    EXPECT_EQ(manager.bubble_.outerCircleRadius,
    displayInfo.dpi * INDEPENDENT_OUTER_PIXELS / DENSITY_BASELINE / CALCULATE_MIDDLE);
    EXPECT_EQ(manager.bubble_.outerCircleWidth,
    static_cast<float>(displayInfo.dpi * INDEPENDENT_WIDTH_PIXELS) / DENSITY_BASELINE);
    EXPECT_NO_FATAL_FAILURE(manager.UpdateDisplayInfo(displayInfo));
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateLabels_001
 * @tc.desc: Test TouchDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateLabels_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateLabels());
}

/**
 * @tc.name: TouchDrawingManagerTest_RecordLabelsInfo_001
 * @tc.desc: Test RecordLabelsInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RecordLabelsInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    TOUCH_DRAWING_MGR->currentPointerId_ = 5;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->RecordLabelsInfo(pointerEvent));
}

/**
 * @tc.name: TouchDrawingManagerTest_RecordLabelsInfo_002
 * @tc.desc: Test RecordLabelsInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RecordLabelsInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetPressed(true);
    pointerEvent->UpdatePointerItem(0, item);
    TOUCH_DRAWING_MGR->currentPointerId_ = 0;
    TOUCH_DRAWING_MGR->isFirstDownAction_ = true;
    pointerEvent->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->RecordLabelsInfo(pointerEvent));
}

/**
 * @tc.name: TouchDrawingManagerTest_RecordLabelsInfo_003
 * @tc.desc: Test RecordLabelsInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RecordLabelsInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetPressed(true);
    pointerEvent->UpdatePointerItem(0, item);
    TOUCH_DRAWING_MGR->currentPointerId_ = 0;
    TOUCH_DRAWING_MGR->isFirstDownAction_ = true;
    pointerEvent->SetPointerId(0);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->RecordLabelsInfo(pointerEvent));
}

/**
 * @tc.name: TouchDrawingManagerTest_RecordLabelsInfo_004
 * @tc.desc: Test RecordLabelsInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RecordLabelsInfo_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetPressed(true);
    pointerEvent->UpdatePointerItem(0, item);
    TOUCH_DRAWING_MGR->currentPointerId_ = 0;
    TOUCH_DRAWING_MGR->isFirstDownAction_ = true;
    pointerEvent->SetPointerId(0);
    TOUCH_DRAWING_MGR->lastPointerItem_.emplace_back(item);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->RecordLabelsInfo(pointerEvent));
}

/**
 * @tc.name: TouchDrawingManagerTest_RecordLabelsInfo_005
 * @tc.desc: Test RecordLabelsInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RecordLabelsInfo_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetPressed(true);
    pointerEvent->UpdatePointerItem(0, item);
    TOUCH_DRAWING_MGR->currentPointerId_ = 0;
    TOUCH_DRAWING_MGR->isFirstDownAction_ = true;
    pointerEvent->SetPointerId(0);
    int64_t actionTime = pointerEvent->GetActionTime();
    TOUCH_DRAWING_MGR->lastActionTime_ = actionTime;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->RecordLabelsInfo(pointerEvent));
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
    TOUCH_DRAWING_MGR->pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
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
    TOUCH_DRAWING_MGR->pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
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
    TOUCH_DRAWING_MGR->pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawBubbleHandler());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubble_001
 * @tc.desc: Test DrawBubble
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawBubble_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawBubble());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubble_002
 * @tc.desc: Test DrawBubble
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawBubble_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawBubble());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawPointerPositionHandler_001
 * @tc.desc: Test DrawPointerPositionHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawPointerPositionHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawPointerPositionHandler(TOUCH_DRAWING_MGR->pointerEvent_));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawPointerPositionHandler_002
 * @tc.desc: Test DrawPointerPositionHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawPointerPositionHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawPointerPositionHandler(TOUCH_DRAWING_MGR->pointerEvent_));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawTracker_001
 * @tc.desc: Test DrawTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawTracker_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 10;
    int32_t y = 10;
    int32_t pointerId = 0;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawTracker(x, y, pointerId));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawTracker_002
 * @tc.desc: Test DrawTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawTracker_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 11;
    int32_t y = 11;
    int32_t pointerId = 5;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawTracker(x, y, pointerId));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawCrosshairs_001
 * @tc.desc: Test DrawCrosshairs
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawCrosshairs_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 11;
    int32_t y = 11;
    auto canvas = static_cast<TouchDrawingManager::RosenCanvas *>
        (TOUCH_DRAWING_MGR->crosshairCanvasNode_->BeginRecording(TOUCH_DRAWING_MGR->displayInfo_.width,
        TOUCH_DRAWING_MGR->displayInfo_.height));
    ASSERT_NE(canvas, nullptr);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawCrosshairs(canvas, x, y));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawCrosshairs_002
 * @tc.desc: Test DrawCrosshairs
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawCrosshairs_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 11;
    int32_t y = 11;
    auto canvas = static_cast<TouchDrawingManager::RosenCanvas *>
        (TOUCH_DRAWING_MGR->crosshairCanvasNode_->BeginRecording(TOUCH_DRAWING_MGR->displayInfo_.width,
        TOUCH_DRAWING_MGR->displayInfo_.height));
    ASSERT_NE(canvas, nullptr);
    TOUCH_DRAWING_MGR->displayInfo_.direction = DIRECTION90;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawCrosshairs(canvas, x, y));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawCrosshairs_003
 * @tc.desc: Test DrawCrosshairs
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawCrosshairs_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 11;
    int32_t y = 11;
    auto canvas = static_cast<TouchDrawingManager::RosenCanvas *>
        (TOUCH_DRAWING_MGR->crosshairCanvasNode_->BeginRecording(TOUCH_DRAWING_MGR->displayInfo_.width,
        TOUCH_DRAWING_MGR->displayInfo_.height));
    ASSERT_NE(canvas, nullptr);
    TOUCH_DRAWING_MGR->displayInfo_.direction = DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->DrawCrosshairs(canvas, x, y));
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdatePointerPosition_001
 * @tc.desc: Test UpdatePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdatePointerPosition_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->pointerEvent_->SetPointerId(5);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdatePointerPosition());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdatePointerPosition_002
 * @tc.desc: Test UpdatePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdatePointerPosition_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->pointerEvent_->SetPointerId(5);
    TOUCH_DRAWING_MGR->currentPointerId_ = 5;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdatePointerPosition());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdatePointerPosition_003
 * @tc.desc: Test UpdatePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdatePointerPosition_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->pointerEvent_->SetPointerId(0);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdatePointerPosition());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdatePointerPosition_004
 * @tc.desc: Test UpdatePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdatePointerPosition_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdatePointerPosition());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdatePointerPosition_005
 * @tc.desc: Test UpdatePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdatePointerPosition_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetPressed(true);
    TOUCH_DRAWING_MGR->lastPointerItem_.emplace_back(item);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdatePointerPosition());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateVelocity_001
 * @tc.desc: Test UpdateVelocity
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateVelocity_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateVelocity());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateVelocity_002
 * @tc.desc: Test UpdateVelocity
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateVelocity_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int64_t actionTime = TOUCH_DRAWING_MGR->pointerEvent_->GetActionTime();
    TOUCH_DRAWING_MGR->lastActionTime_ = actionTime;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateVelocity());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateVelocity_003
 * @tc.desc: Test UpdateVelocity
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateVelocity_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->pointerEvent_->SetPointerId(5);
    TOUCH_DRAWING_MGR->currentPointerId_ = 5;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateVelocity());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateVelocity_004
 * @tc.desc: Test UpdateVelocity
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateVelocity_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->pointerEvent_->SetPointerId(0);
    TOUCH_DRAWING_MGR->currentPointerId_ = 5;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateVelocity());
}

/**
 * @tc.name: TouchDrawingManagerTest_ClearTracker_001
 * @tc.desc: Test ClearTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_ClearTracker_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->ClearTracker());
}

/**
 * @tc.name: TouchDrawingManagerTest_ClearTracker_002
 * @tc.desc: Test ClearTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_ClearTracker_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->lastPointerItem_.clear();
    TOUCH_DRAWING_MGR->isDownAction_ = false;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->ClearTracker());
}

/**
 * @tc.name: TouchDrawingManagerTest_ClearTracker_003
 * @tc.desc: Test ClearTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_ClearTracker_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->isDownAction_ = true;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->ClearTracker());
}
} // namespace MMI
} // namespace OHOS
