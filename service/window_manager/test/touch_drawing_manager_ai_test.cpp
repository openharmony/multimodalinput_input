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
    void SetUp(void) {};
};

/**
 * @tc.name: TouchDrawingManagerTest_RecordLabelsInfo
 * @tc.desc: Test RecordLabelsInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RecordLabelsInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawMgr;
    touchDrawMgr.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawMgr.pointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetPressed(true);
    item.SetDisplayX(100);
    item.SetDisplayY(100);
    touchDrawMgr.pointerEvent_->AddPointerItem(item);
    touchDrawMgr.pointerEvent_->SetPointerId(0);
    touchDrawMgr.currentPointerId_ = 1;
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.RecordLabelsInfo());

    touchDrawMgr.currentPointerId_ = 0;
    touchDrawMgr.isFirstDownAction_ = true;
    touchDrawMgr.lastPointerItem_.push_back(item);
    touchDrawMgr.pointerEvent_->SetActionTime(150);
    touchDrawMgr.lastActionTime_ = 300;
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.RecordLabelsInfo());

    touchDrawMgr.pointerEvent_->SetActionTime(50);
    touchDrawMgr.lastActionTime_ = 50;
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.RecordLabelsInfo());

    item.SetPressed(false);
    touchDrawMgr.isFirstDownAction_ = false;
    touchDrawMgr.pointerEvent_->SetPointerId(10);
    touchDrawMgr.pointerEvent_->UpdatePointerItem(0, item);
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.RecordLabelsInfo());
}

/**
 * @tc.name: TouchDrawingManagerTest_TouchDrawHandler
 * @tc.desc: Test TouchDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_TouchDrawHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    touchDrawMgr.bubbleMode_.isShow = true;
    touchDrawMgr.stopRecord_ = false;
    touchDrawMgr.pointerMode_.isShow = true;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.TouchDrawHandler(pointerEvent));

    touchDrawMgr.bubbleMode_.isShow = false;
    touchDrawMgr.pointerMode_.isShow = false;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.TouchDrawHandler(pointerEvent));
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateDisplayInfo
 * @tc.desc: Test UpdateDisplayInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateDisplayInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawMgr;
    DisplayInfo displayInfo;
    displayInfo.direction = Direction::DIRECTION0;
    touchDrawMgr.displayInfo_.direction = Direction::DIRECTION0;
    displayInfo.width = 700;
    displayInfo.height = 500;
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.UpdateDisplayInfo(displayInfo));

    displayInfo.direction = Direction::DIRECTION180;
    touchDrawMgr.displayInfo_.direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.UpdateDisplayInfo(displayInfo));

    displayInfo.direction = Direction::DIRECTION270;
    touchDrawMgr.displayInfo_.direction = Direction::DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(touchDrawMgr.UpdateDisplayInfo(displayInfo));
}

/**
 * @tc.name: TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates
 * @tc.desc: Test GetOriginalTouchScreenCoordinates
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    int32_t width = 720;
    int32_t height = 1800;
    int32_t physicalX = 300;
    int32_t physicalY = 600;
    Direction direction = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.GetOriginalTouchScreenCoordinates(direction, width, height,
        physicalX, physicalY));
    direction = DIRECTION90;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.GetOriginalTouchScreenCoordinates(direction, width, height,
        physicalX, physicalY));
    direction = DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.GetOriginalTouchScreenCoordinates(direction, width, height,
        physicalX, physicalY));
    direction = DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.GetOriginalTouchScreenCoordinates(direction, width, height,
        physicalX, physicalY));
    direction = static_cast<Direction>(10);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.GetOriginalTouchScreenCoordinates(direction, width, height,
        physicalX, physicalY));
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateLabels
 * @tc.desc: Test UpdateLabels
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateLabels, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(touchDrawingMgr.surfaceNode_, nullptr);
    touchDrawingMgr.labelsCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.labelsCanvasNode_, nullptr);
    touchDrawingMgr.pointerMode_.isShow = true;
    EXPECT_EQ(touchDrawingMgr.UpdateLabels(), RET_OK);
    touchDrawingMgr.pointerMode_.isShow = false;
    EXPECT_EQ(touchDrawingMgr.UpdateLabels(), RET_OK);
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateBubbleData
 * @tc.desc: Test UpdateBubbleData
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateBubbleData, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(touchDrawingMgr.surfaceNode_, nullptr);
    touchDrawingMgr.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.bubbleCanvasNode_, nullptr);
    touchDrawingMgr.bubbleMode_.isShow = false;
    EXPECT_EQ(touchDrawingMgr.UpdateBubbleData(), RET_OK);

    touchDrawingMgr.bubbleMode_.isShow = true;
    EXPECT_EQ(touchDrawingMgr.UpdateBubbleData(), RET_OK);
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationScreen
 * @tc.desc: Test RotationScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RotationScreen, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.isChangedRotation_ = false;
    touchDrawingMgr.isChangedMode_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationScreen());

    touchDrawingMgr.trackerCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.trackerCanvasNode_, nullptr);
    touchDrawingMgr.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.crosshairCanvasNode_, nullptr);
    touchDrawingMgr.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.bubbleCanvasNode_, nullptr);
    touchDrawingMgr.labelsCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.labelsCanvasNode_, nullptr);
    touchDrawingMgr.isChangedRotation_ = true;
    touchDrawingMgr.isChangedMode_ = true;
    touchDrawingMgr.pointerMode_.isShow = true;
    touchDrawingMgr.bubbleMode_.isShow = true;
    PointerEvent::PointerItem item;
    touchDrawingMgr.lastPointerItem_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationScreen());

    touchDrawingMgr.lastPointerItem_.clear();
    touchDrawingMgr.stopRecord_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationScreen());

    touchDrawingMgr.bubbleMode_.isShow = false;
    touchDrawingMgr.stopRecord_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationScreen());

    touchDrawingMgr.pointerMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationScreen());
}

/**
 * @tc.name: TouchDrawingManagerTest_CreateObserver
 * @tc.desc: Test CreateObserver
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_CreateObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.hasBubbleObserver_ = false;
    touchDrawingMgr.hasPointerObserver_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.CreateObserver());
}

/**
 * @tc.name: TouchDrawingManagerTest_CreateObserver_001
 * @tc.desc: Test CreateObserver
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_CreateObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.hasBubbleObserver_ = true;
    touchDrawingMgr.hasPointerObserver_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.CreateObserver());
}

/**
 * @tc.name: TouchDrawingManagerTest_AddCanvasNode
 * @tc.desc: Test AddCanvasNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_AddCanvasNode, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode = Rosen::RSCanvasNode::Create();
    ASSERT_NE(canvasNode, nullptr);
    bool isTrackerNode = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.AddCanvasNode(canvasNode, isTrackerNode));

    canvasNode = nullptr;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.AddCanvasNode(canvasNode, isTrackerNode));
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationCanvasNode
 * @tc.desc: Test RotationCanvasNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RotationCanvasNode, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode = Rosen::RSCanvasNode::Create();
    ASSERT_NE(canvasNode, nullptr);
    touchDrawingMgr.displayInfo_.width = 720;
    touchDrawingMgr.displayInfo_.height = 1800;
    touchDrawingMgr.displayInfo_.direction = Direction::DIRECTION90;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationCanvasNode(canvasNode));
    touchDrawingMgr.displayInfo_.direction = Direction::DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationCanvasNode(canvasNode));
    touchDrawingMgr.displayInfo_.direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationCanvasNode(canvasNode));
    touchDrawingMgr.displayInfo_.direction = Direction::DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationCanvasNode(canvasNode));
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationCanvas
 * @tc.desc: Test RotationCanvas
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RotationCanvas, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    int32_t width = 720;
    int32_t height = 1800;
    touchDrawingMgr.displayInfo_.width = 300;
    touchDrawingMgr.displayInfo_.height = 100;
    Direction direction = Direction::DIRECTION90;
    touchDrawingMgr.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    auto canvas = static_cast<TouchDrawingManager::RosenCanvas *>
        (touchDrawingMgr.labelsCanvasNode_->BeginRecording(width, height));
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationCanvas(canvas, direction));
    direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationCanvas(canvas, direction));
    direction = Direction::DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationCanvas(canvas, direction));
    direction = Direction::DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.RotationCanvas(canvas, direction));
}

/**
 * @tc.name: TouchDrawingManagerTest_CreateTouchWindow
 * @tc.desc: Test CreateTouchWindow
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_CreateTouchWindow, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(touchDrawingMgr.surfaceNode_, nullptr);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.CreateTouchWindow());
    touchDrawingMgr.surfaceNode_ = nullptr;
    touchDrawingMgr.scaleW_ = 0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.CreateTouchWindow());
    touchDrawingMgr.scaleW_ = 100;
    touchDrawingMgr.scaleH_ = 0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.CreateTouchWindow());
    touchDrawingMgr.scaleH_ = 500;
    touchDrawingMgr.displayInfo_.id = 1000;
    touchDrawingMgr.displayInfo_.displayMode = DisplayMode::MAIN;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.CreateTouchWindow());
}

/**
 * @tc.name: TouchDrawingManagerTest_CreateTouchWindow_001
 * @tc.desc: Test CreateTouchWindow
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_CreateTouchWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.surfaceNode_ = nullptr;
    touchDrawingMgr.scaleW_ = 100;
    touchDrawingMgr.scaleH_ = 500;
    touchDrawingMgr.displayInfo_.id = 1000;
    touchDrawingMgr.displayInfo_.displayMode = DisplayMode::FULL;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.CreateTouchWindow());
}

/**
 * @tc.name: TouchDrawingManagerTest_CreateTouchWindow_002
 * @tc.desc: Test CreateTouchWindow
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_CreateTouchWindow_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.surfaceNode_ = nullptr;
    touchDrawingMgr.scaleW_ = 100;
    touchDrawingMgr.scaleH_ = 500;
    touchDrawingMgr.displayInfo_.id = 1000;
    touchDrawingMgr.displayInfo_.displayMode = DisplayMode::UNKNOWN;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.CreateTouchWindow());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubbleHandler
 * @tc.desc: Test DrawBubbleHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawBubbleHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingMgr.pointerEvent_, nullptr);
    touchDrawingMgr.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.bubbleCanvasNode_, nullptr);
    touchDrawingMgr.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawBubbleHandler());

    touchDrawingMgr.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawBubbleHandler());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubble
 * @tc.desc: Test DrawBubble
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawBubble, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    touchDrawingMgr.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingMgr.pointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    touchDrawingMgr.pointerEvent_->SetPointerId(1);
    touchDrawingMgr.pointerEvent_->AddPointerItem(item);
    touchDrawingMgr.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawBubble());
    touchDrawingMgr.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawBubble());
    touchDrawingMgr.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawBubble());
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
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    touchDrawingMgr.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingMgr.pointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    touchDrawingMgr.pointerEvent_->AddPointerItem(item);
    touchDrawingMgr.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    item.SetPointerId(2);
    touchDrawingMgr.pointerEvent_->SetPointerId(2);
    touchDrawingMgr.pointerEvent_->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawBubble());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawPointerPositionHandler
 * @tc.desc: Test DrawPointerPositionHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawPointerPositionHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    touchDrawingMgr.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingMgr.pointerEvent_, nullptr);
    touchDrawingMgr.trackerCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.trackerCanvasNode_, nullptr);
    touchDrawingMgr.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.crosshairCanvasNode_, nullptr);
    touchDrawingMgr.labelsCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.labelsCanvasNode_, nullptr);
    PointerEvent::PointerItem item;
    item.SetDisplayX(300);
    item.SetDisplayY(500);
    item.SetPointerId(100);
    touchDrawingMgr.scaleW_ = 720;
    touchDrawingMgr.scaleH_ = 1800;
    touchDrawingMgr.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    touchDrawingMgr.pointerEvent_->SetPointerId(100);
    touchDrawingMgr.pointerEvent_->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawPointerPositionHandler());

    touchDrawingMgr.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawPointerPositionHandler());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawTracker
 * @tc.desc: Test DrawTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawTracker, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    int32_t x = 100;
    int32_t y = 300;
    int32_t pointerId = 10;
    PointerEvent::PointerItem item;
    item.SetPointerId(10);
    item.SetDisplayX(100);
    item.SetDisplayY(300);
    touchDrawingMgr.isDownAction_ = true;
    touchDrawingMgr.xVelocity_ = 200;
    touchDrawingMgr.yVelocity_ = 400;
    touchDrawingMgr.lastPointerItem_.push_back(item);
    touchDrawingMgr.trackerCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.trackerCanvasNode_, nullptr);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawTracker(x, y, pointerId));

    pointerId = 20;
    touchDrawingMgr.isDownAction_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawTracker(x, y, pointerId));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawLabels
 * @tc.desc: Test DrawLabels
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawLabels, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.labelsCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.labelsCanvasNode_, nullptr);
    PointerEvent::PointerItem item;
    touchDrawingMgr.currentPointerCount_ = 10;
    touchDrawingMgr.maxPointerCount_ = 20;
    touchDrawingMgr.scaleW_ = 30;
    touchDrawingMgr.scaleH_ = 50;
    touchDrawingMgr.xVelocity_ = 30;
    touchDrawingMgr.yVelocity_ = 50;
    touchDrawingMgr.pressure_ = 10;
    touchDrawingMgr.rectTopPosition_ = 100;
    touchDrawingMgr.itemRectW_ = 100.0;
    touchDrawingMgr.isDownAction_ = true;
    touchDrawingMgr.lastPointerItem_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawLabels());
    touchDrawingMgr.isDownAction_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawLabels());
    touchDrawingMgr.lastPointerItem_.clear();
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DrawLabels());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdatePointerPosition
 * @tc.desc: Test UpdatePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdatePointerPosition, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingMgr.pointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    touchDrawingMgr.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    touchDrawingMgr.pointerEvent_->SetPointerId(10);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.UpdatePointerPosition());
    touchDrawingMgr.lastPointerItem_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.UpdatePointerPosition());
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
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingMgr.pointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    touchDrawingMgr.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    touchDrawingMgr.pointerEvent_->SetPointerId(10);
    item.SetPointerId(20);
    touchDrawingMgr.lastPointerItem_.push_back(item);
    item.SetPointerId(10);
    touchDrawingMgr.lastPointerItem_.push_back(item);
    touchDrawingMgr.currentPointerId_ = 10;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.UpdatePointerPosition());
    touchDrawingMgr.lastPointerItem_.clear();
    touchDrawingMgr.currentPointerId_ = 50;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.UpdatePointerPosition());
    touchDrawingMgr.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.UpdatePointerPosition());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateLastPointerItem
 * @tc.desc: Test UpdateLastPointerItem
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateLastPointerItem, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    PointerEvent::PointerItem item;
    item.SetPressed(false);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.UpdateLastPointerItem(item));
    item.SetPressed(true);
    item.SetPointerId(10);
    touchDrawingMgr.lastPointerItem_.push_back(item);
    item.SetPointerId(20);
    touchDrawingMgr.lastPointerItem_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.UpdateLastPointerItem(item));
}

/**
 * @tc.name: TouchDrawingManagerTest_DestoryTouchWindow
 * @tc.desc: Test DestoryTouchWindow
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DestoryTouchWindow, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(touchDrawingMgr.surfaceNode_, nullptr);
    touchDrawingMgr.bubbleMode_.isShow = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DestoryTouchWindow());
    touchDrawingMgr.bubbleMode_.isShow = false;
    touchDrawingMgr.pointerMode_.isShow = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DestoryTouchWindow());
    touchDrawingMgr.pointerMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.DestoryTouchWindow());
}

/**
 * @tc.name: TouchDrawingManagerTest_ClearTracker
 * @tc.desc: Test ClearTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_ClearTracker, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.trackerCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingMgr.trackerCanvasNode_, nullptr);
    touchDrawingMgr.scaleW_ = 300;
    touchDrawingMgr.scaleH_ = 500;
    touchDrawingMgr.isDownAction_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.ClearTracker());
    touchDrawingMgr.isDownAction_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.ClearTracker());
}

/**
 * @tc.name: TouchDrawingManagerTest_IsValidAction
 * @tc.desc: Test IsValidAction
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_IsValidAction, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    int32_t action = PointerEvent::POINTER_ACTION_DOWN;
    EXPECT_TRUE(touchDrawingMgr.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_PULL_DOWN;
    EXPECT_TRUE(touchDrawingMgr.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_MOVE;
    EXPECT_TRUE(touchDrawingMgr.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_PULL_MOVE;
    EXPECT_TRUE(touchDrawingMgr.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_UP;
    EXPECT_TRUE(touchDrawingMgr.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_PULL_UP;
    EXPECT_TRUE(touchDrawingMgr.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_CANCEL;
    EXPECT_TRUE(touchDrawingMgr.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_UNKNOWN;
    EXPECT_FALSE(touchDrawingMgr.IsValidAction(action));
}
} // namespace MMI
} // namespace OHOS