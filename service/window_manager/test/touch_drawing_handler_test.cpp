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

#include <cstdio>
#include <fstream>
#include <gtest/gtest.h>

#include "mmi_log.h"
#include "pointer_event.h"
#ifndef USE_ROSEN_DRAWING
#define USE_ROSEN_DRAWING
#endif
#include "touch_drawing_handler.h"
#include "window_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchDrawingHandlerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

#ifdef USE_ROSEN_DRAWING
using RosenRecordingCanvas = Rosen::Drawing::RecordingCanvas;
#else
using RosenRecordingCanvas = Rosen::RSRecordingCanvas;
#endif // USE_ROSEN_DRAWING

class TouchDrawingHandlerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {};
};

/**
 * @tc.name: TouchDrawingHandlerTest_RecordLabelsInfo
 * @tc.desc: Test RecordLabelsInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_RecordLabelsInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawMgr;
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
 * @tc.name: TouchDrawingHandlerTest_TouchDrawHandler
 * @tc.desc: Test TouchDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_TouchDrawHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawMgr;
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
 * @tc.name: TouchDrawingHandlerTest_UpdateDisplayInfo_001
 * @tc.desc: Test UpdateDisplayInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_UpdateDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawMgr;
    OLD::DisplayInfo displayInfo;
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
 * @tc.name: TouchDrawingHandlerTest_UpdateDisplayInfo_002
 * @tc.desc: Test UpdateDisplayInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_UpdateDisplayInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    OLD::DisplayInfo displayInfo;
    displayInfo.direction = Direction::DIRECTION0;
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION0;
    displayInfo.width = 700;
    displayInfo.height = 500;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));
    displayInfo.direction = Direction::DIRECTION180;
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));
    displayInfo.direction = Direction::DIRECTION270;
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));
    displayInfo.displaySourceMode = DisplaySourceMode::SCREEN_MAIN;
    touchDrawingHandler.displayInfo_.displaySourceMode = DisplaySourceMode::SCREEN_MAIN;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));
    displayInfo.rsId = 1;
    touchDrawingHandler.displayInfo_.rsId = 2;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));
    touchDrawingHandler.isChangedMode_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));
    touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create();
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateBubbleData_001
 * @tc.desc: Test UpdateBubbleData
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_UpdateBubbleData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateBubbleData(true));
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateBubbleData_002
 * @tc.desc: Test UpdateBubbleData
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_UpdateBubbleData_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateBubbleData(false));
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateBubbleData_003
 * @tc.desc: Test UpdateBubbleData
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_UpdateBubbleData_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(touchDrawingHandler.surfaceNode_, nullptr);
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingHandler.bubbleCanvasNode_, nullptr);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateBubbleData(false));
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateBubbleData(true));
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationScreen_001
 * @tc.desc: Test RotationScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationScreen_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.isChangedRotation_ = true;
    touchDrawingHandler.displayInfo_.displayDirection = DIRECTION0;
    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.bubbleMode_.isShow = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationScreen_002
 * @tc.desc: Test RotationScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationScreen_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.isChangedRotation_ = false;
    touchDrawingHandler.displayInfo_.displayDirection = DIRECTION0;
    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.bubbleMode_.isShow = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationScreen_003
 * @tc.desc: Test RotationScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationScreen_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.isChangedRotation_ = true;
    touchDrawingHandler.displayInfo_.displayDirection = DIRECTION90;
    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.bubbleMode_.isShow = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationScreen_004
 * @tc.desc: Test RotationScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationScreen_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.isChangedRotation_ = true;
    touchDrawingHandler.displayInfo_.displayDirection = DIRECTION0;
    touchDrawingHandler.pointerMode_.isShow = false;
    touchDrawingHandler.bubbleMode_.isShow = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationScreen_005
 * @tc.desc: Test RotationScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationScreen_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.isChangedRotation_ = true;
    touchDrawingHandler.displayInfo_.displayDirection = DIRECTION0;
    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.bubbleMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationScreen_006
 * @tc.desc: Test RotationScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationScreen_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.isChangedRotation_ = false;
    touchDrawingHandler.isChangedMode_ = true;
    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.bubbleMode_.isShow = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationScreen_007
 * @tc.desc: Test RotationScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationScreen_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.isChangedRotation_ = false;
    touchDrawingHandler.isChangedMode_ = true;
    touchDrawingHandler.pointerMode_.isShow = false;
    touchDrawingHandler.bubbleMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationScreen_008
 * @tc.desc: Test RotationScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationScreen_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.isChangedRotation_ = false;
    touchDrawingHandler.isChangedMode_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationScreen_009
 * @tc.desc: Test RotationScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationScreen_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.isChangedRotation_ = false;
    touchDrawingHandler.isChangedMode_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());

    touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingHandler.trackerCanvasNode_, nullptr);
    touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingHandler.crosshairCanvasNode_, nullptr);
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingHandler.bubbleCanvasNode_, nullptr);
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingHandler.labelsCanvasNode_, nullptr);
    touchDrawingHandler.isChangedRotation_ = true;
    touchDrawingHandler.isChangedMode_ = true;
    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.bubbleMode_.isShow = true;
    PointerEvent::PointerItem item;
    touchDrawingHandler.lastPointerItem_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());

    touchDrawingHandler.lastPointerItem_.clear();
    touchDrawingHandler.stopRecord_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());

    touchDrawingHandler.bubbleMode_.isShow = false;
    touchDrawingHandler.stopRecord_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());

    touchDrawingHandler.pointerMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationScreen_010
 * @tc.desc: Test RotationScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationScreen_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.isChangedRotation_ = true;
    touchDrawingHandler.isChangedMode_ = false;
    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.bubbleMode_.isShow = true;
    touchDrawingHandler.stopRecord_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
    touchDrawingHandler.stopRecord_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    touchDrawingHandler.lastPointerItem_.emplace_back(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
    touchDrawingHandler.stopRecord_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
    touchDrawingHandler.stopRecord_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationScreen());
}

/**
 * @tc.name: TouchDrawingManagerTest_AddCanvasNode_001
 * @tc.desc: Test AddCanvasNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_AddCanvasNode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);

    std::shared_ptr<Rosen::RSCanvasNode> canvasNode = nullptr;
    bool isTrackerNode = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.AddCanvasNode(canvasNode, isTrackerNode));
}

/**
 * @tc.name: TouchDrawingManagerTest_AddCanvasNode_002
 * @tc.desc: Test AddCanvasNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_AddCanvasNode_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);

    std::shared_ptr<Rosen::RSCanvasNode> canvasNode = nullptr;
    bool isTrackerNode = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.AddCanvasNode(canvasNode, isTrackerNode));
}

/**
 * @tc.name: TouchDrawingManagerTest_AddCanvasNode_003
 * @tc.desc: Test AddCanvasNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_AddCanvasNode_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode = Rosen::RSCanvasNode::Create();
    ASSERT_NE(canvasNode, nullptr);
    bool isTrackerNode = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.AddCanvasNode(canvasNode, isTrackerNode));

    canvasNode = nullptr;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.AddCanvasNode(canvasNode, isTrackerNode));
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationCanvasNode_001
 * @tc.desc: Test RotationCanvasNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationCanvasNode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode = Rosen::RSCanvasNode::Create();
    ASSERT_NE(canvasNode, nullptr);
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION90;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvasNode(canvasNode));
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationCanvasNode_002
 * @tc.desc: Test RotationCanvasNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationCanvasNode_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode = Rosen::RSCanvasNode::Create();
    ASSERT_NE(canvasNode, nullptr);
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvasNode(canvasNode));
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationCanvasNode_003
 * @tc.desc: Test RotationCanvasNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationCanvasNode_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode = Rosen::RSCanvasNode::Create();
    ASSERT_NE(canvasNode, nullptr);
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvasNode(canvasNode));
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationCanvasNode_004
 * @tc.desc: Test RotationCanvasNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationCanvasNode_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode = Rosen::RSCanvasNode::Create();
    ASSERT_NE(canvasNode, nullptr);
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvasNode(canvasNode));
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationCanvasNode_005
 * @tc.desc: Test RotationCanvasNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RotationCanvasNode_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode = Rosen::RSCanvasNode::Create();
    ASSERT_NE(canvasNode, nullptr);
    touchDrawingHandler.displayInfo_.width = 720;
    touchDrawingHandler.displayInfo_.height = 1800;
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION90;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvasNode(canvasNode));
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvasNode(canvasNode));
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvasNode(canvasNode));
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvasNode(canvasNode));
}

/**
 * @tc.name: TouchDrawingHandlerTest_RotationCanvas_001
 * @tc.desc: Test RotationCanvas
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_RotationCanvas_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    int32_t width = 720;
    int32_t height = 1800;
    touchDrawingHandler.displayInfo_.width = 300;
    touchDrawingHandler.displayInfo_.height = 100;
    Direction direction = Direction::DIRECTION90;
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    auto canvas = static_cast<RosenRecordingCanvas *>(
        touchDrawingHandler.labelsCanvasNode_->BeginRecording(width, height));
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvas(canvas, direction));
    direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvas(canvas, direction));
    direction = Direction::DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvas(canvas, direction));
    direction = Direction::DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvas(canvas, direction));
}

/**
 * @tc.name: TouchDrawingHandlerTest_RotationCanvas_002
 * @tc.desc: Test RotationCanvas
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_RotationCanvas_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    int32_t width = 300;
    int32_t height = 100;
    Direction direction = Direction::DIRECTION90;
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    auto canvas = static_cast<RosenRecordingCanvas *>(
        touchDrawingHandler.labelsCanvasNode_->BeginRecording(width, height));
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvas(canvas, direction));
    direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvas(canvas, direction));
    direction = Direction::DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvas(canvas, direction));
    direction = Direction::DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RotationCanvas(canvas, direction));
}

/**
 * @tc.name: TouchDrawingManagerTest_CreateTouchWindow_001
 * @tc.desc: Test CreateTouchWindow
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_CreateTouchWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.CreateTouchWindow());
}

/**
 * @tc.name: TouchDrawingHandlerTest_CreateTouchWindow_002
 * @tc.desc: Test CreateTouchWindow
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_CreateTouchWindow_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.surfaceNode_ = nullptr;
    touchDrawingHandler.scaleW_ = 100;
    touchDrawingHandler.scaleH_ = 500;
    touchDrawingHandler.displayInfo_.id = 1000;
    touchDrawingHandler.displayInfo_.displayMode = DisplayMode::FULL;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.CreateTouchWindow());
}

/**
 * @tc.name: TouchDrawingHandlerTest_CreateTouchWindow_003
 * @tc.desc: Test CreateTouchWindow
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_CreateTouchWindow_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.surfaceNode_ = nullptr;
    touchDrawingHandler.scaleW_ = 100;
    touchDrawingHandler.scaleH_ = 500;
    touchDrawingHandler.displayInfo_.id = 1000;
    touchDrawingHandler.displayInfo_.displayMode = DisplayMode::UNKNOWN;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.CreateTouchWindow());
}

/**
 * @tc.name: TouchDrawingHandlerTest_CreateTouchWindow_004
 * @tc.desc: Test CreateTouchWindow
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_CreateTouchWindow_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(touchDrawingHandler.surfaceNode_, nullptr);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.CreateTouchWindow());
    touchDrawingHandler.surfaceNode_ = nullptr;
    touchDrawingHandler.scaleW_ = 0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.CreateTouchWindow());
    touchDrawingHandler.scaleW_ = 100;
    touchDrawingHandler.scaleH_ = 0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.CreateTouchWindow());
    touchDrawingHandler.scaleH_ = 500;
    touchDrawingHandler.displayInfo_.id = 1000;
    touchDrawingHandler.displayInfo_.displayMode = DisplayMode::MAIN;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.CreateTouchWindow());
}

/**
 * @tc.name: TouchDrawingManagerTest_DestoryTouchWindow_001
 * @tc.desc: Test DestoryTouchWindow
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DestoryTouchWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleMode_.isShow = true;
    touchDrawingHandler.pointerMode_.isShow = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DestoryTouchWindow());
}

/**
 * @tc.name: TouchDrawingManagerTest_DestoryTouchWindow_002
 * @tc.desc: Test DestoryTouchWindow
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DestoryTouchWindow_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleMode_.isShow = false;
    touchDrawingHandler.pointerMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DestoryTouchWindow());
}

/**
 * @tc.name: TouchDrawingManagerTest_DestoryTouchWindow_003
 * @tc.desc: Test DestoryTouchWindow
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DestoryTouchWindow_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleMode_.isShow = false;
    touchDrawingHandler.pointerMode_.isShow = false;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DestoryTouchWindow());
}

/**
 * @tc.name: TouchDrawingHandlerTest_DrawBubbleHandler
 * @tc.desc: Test DrawBubbleHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_DrawBubbleHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingHandler.bubbleCanvasNode_, nullptr);
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawBubbleHandler());

    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawBubbleHandler());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubbleHandler_001
 * @tc.desc: Test DrawBubbleHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawBubbleHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_BEGIN);
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawBubbleHandler());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubbleHandler_002
 * @tc.desc: Test DrawBubbleHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawBubbleHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawBubbleHandler());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubbleHandler_003
 * @tc.desc: Test DrawBubbleHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawBubbleHandler_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawBubbleHandler());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubble_001
 * @tc.desc: Test DrawBubble
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawBubble_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawBubble());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubble_002
 * @tc.desc: Test DrawBubble
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawBubble_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);

    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawBubble());
}

/**
 * @tc.name: TouchDrawingHandlerTest_DrawBubble_001
 * @tc.desc: Test DrawBubble
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_DrawBubble_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);

    int32_t pointerId { 1 };
    PointerEvent::PointerItem item {};
    item.SetPointerId(pointerId);
    touchDrawingHandler.pointerEvent_->SetPointerId(pointerId);
    touchDrawingHandler.pointerEvent_->AddPointerItem(item);
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawBubble());
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawBubble());
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawBubble());
}

/**
 * @tc.name: TouchDrawingHandlerTest_DrawBubble_002
 * @tc.desc: Test DrawBubble
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_DrawBubble_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    touchDrawingHandler.pointerEvent_->AddPointerItem(item);
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    item.SetPointerId(2);
    touchDrawingHandler.pointerEvent_->SetPointerId(2);
    touchDrawingHandler.pointerEvent_->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawBubble());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawBubble_003
 * @tc.desc: Test DrawBubble
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawBubble_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    touchDrawingHandler.pointerEvent_->AddPointerItem(item);
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    item.SetPointerId(2);
    touchDrawingHandler.pointerEvent_->SetPointerId(2);
    touchDrawingHandler.pointerEvent_->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawBubble());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawPointerPositionHandler_001
 * @tc.desc: Test DrawPointerPositionHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawPointerPositionHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawPointerPositionHandler());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawPointerPositionHandler_002
 * @tc.desc: Test DrawPointerPositionHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawPointerPositionHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawPointerPositionHandler());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawPointerPositionHandler_003
 * @tc.desc: Test DrawPointerPositionHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawPointerPositionHandler_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create();
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);
    touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingHandler.trackerCanvasNode_, nullptr);
    touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingHandler.crosshairCanvasNode_, nullptr);
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingHandler.labelsCanvasNode_, nullptr);
    PointerEvent::PointerItem item;
    item.SetDisplayX(300);
    item.SetDisplayY(500);
    item.SetPointerId(100);
    touchDrawingHandler.scaleW_ = 720;
    touchDrawingHandler.scaleH_ = 1800;
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    touchDrawingHandler.pointerEvent_->SetPointerId(100);
    touchDrawingHandler.pointerEvent_->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawPointerPositionHandler());

    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawPointerPositionHandler());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawTracker_001
 * @tc.desc: Test DrawTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawTracker_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 10;
    int32_t y = 10;
    int32_t pointerId = 0;
    TouchDrawingHandler touchDrawingHandler;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawTracker(x, y, pointerId));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawTracker_002
 * @tc.desc: Test DrawTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawTracker_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 11;
    int32_t y = 11;
    int32_t pointerId = 5;
    TouchDrawingHandler touchDrawingHandler;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawTracker(x, y, pointerId));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawTracker_003
 * @tc.desc: Test DrawTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawTracker_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    int32_t x = 100;
    int32_t y = 300;
    int32_t pointerId = 10;
    PointerEvent::PointerItem item;
    item.SetPointerId(10);
    item.SetDisplayX(100);
    item.SetDisplayY(300);
    touchDrawingHandler.isDownAction_ = true;
    touchDrawingHandler.xVelocity_ = 200;
    touchDrawingHandler.yVelocity_ = 400;
    touchDrawingHandler.lastPointerItem_.push_back(item);
    touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingHandler.trackerCanvasNode_, nullptr);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawTracker(x, y, pointerId));

    pointerId = 20;
    touchDrawingHandler.isDownAction_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawTracker(x, y, pointerId));
}


/**
 * @tc.name: TouchDrawingManagerTest_DrawCrosshairs_001
 * @tc.desc: Test DrawCrosshairs
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawCrosshairs_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 11;
    int32_t y = 11;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.crosshairCanvasNode_ == nullptr) {
        touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create();
    }
    ASSERT_NE(touchDrawingHandler.crosshairCanvasNode_, nullptr);
    auto canvas = static_cast<RosenRecordingCanvas *>(
        touchDrawingHandler.crosshairCanvasNode_->BeginRecording(touchDrawingHandler.displayInfo_.width,
        touchDrawingHandler.displayInfo_.height));
    ASSERT_NE(canvas, nullptr);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawCrosshairs(canvas, x, y));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawCrosshairs_002
 * @tc.desc: Test DrawCrosshairs
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawCrosshairs_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 11;
    int32_t y = 11;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.crosshairCanvasNode_ == nullptr) {
        touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create();
    }
    auto canvas = static_cast<RosenRecordingCanvas *>(
        touchDrawingHandler.crosshairCanvasNode_->BeginRecording(touchDrawingHandler.displayInfo_.width,
        touchDrawingHandler.displayInfo_.height));
    ASSERT_NE(canvas, nullptr);
    touchDrawingHandler.displayInfo_.direction = DIRECTION90;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawCrosshairs(canvas, x, y));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawCrosshairs_003
 * @tc.desc: Test DrawCrosshairs
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawCrosshairs_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 11;
    int32_t y = 11;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.crosshairCanvasNode_ == nullptr) {
        touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create();
    }
    auto canvas = static_cast<RosenRecordingCanvas *>(
        touchDrawingHandler.crosshairCanvasNode_->BeginRecording(touchDrawingHandler.displayInfo_.width,
        touchDrawingHandler.displayInfo_.height));
    ASSERT_NE(canvas, nullptr);
    touchDrawingHandler.displayInfo_.direction = DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawCrosshairs(canvas, x, y));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawLabels_001
 * @tc.desc: Test DrawLabels
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawLabels_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.isDownAction_ = true;
    touchDrawingHandler.displayInfo_.direction = DIRECTION90;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawLabels());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawLabels_002
 * @tc.desc: Test DrawLabels
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawLabels_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.labelsCanvasNode_ == nullptr) {
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    }
    touchDrawingHandler.isDownAction_ = true;
    touchDrawingHandler.displayInfo_.direction = DIRECTION180;
    touchDrawingHandler.displayInfo_.displayDirection = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawLabels());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawLabels_003
 * @tc.desc: Test DrawLabels
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawLabels_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.labelsCanvasNode_ == nullptr) {
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    }
    touchDrawingHandler.isDownAction_ = true;
    touchDrawingHandler.displayInfo_.direction = DIRECTION270;
    touchDrawingHandler.displayInfo_.displayDirection = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawLabels());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawLabels_004
 * @tc.desc: Test DrawLabels
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawLabels_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.labelsCanvasNode_ == nullptr) {
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    }
    touchDrawingHandler.isDownAction_ = true;
    touchDrawingHandler.displayInfo_.direction = DIRECTION270;
    touchDrawingHandler.displayInfo_.displayDirection = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawLabels());
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawLabels_005
 * @tc.desc: Test DrawLabels
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawLabels_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingHandler.labelsCanvasNode_, nullptr);
    PointerEvent::PointerItem item;
    touchDrawingHandler.currentPointerCount_ = 10;
    touchDrawingHandler.maxPointerCount_ = 20;
    touchDrawingHandler.scaleW_ = 30;
    touchDrawingHandler.scaleH_ = 50;
    touchDrawingHandler.xVelocity_ = 30;
    touchDrawingHandler.yVelocity_ = 50;
    touchDrawingHandler.pressure_ = 10;
    touchDrawingHandler.rectTopPosition_ = 100;
    touchDrawingHandler.itemRectW_ = 100.0;
    touchDrawingHandler.isDownAction_ = true;
    touchDrawingHandler.lastPointerItem_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawLabels());
    touchDrawingHandler.isDownAction_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawLabels());
    touchDrawingHandler.lastPointerItem_.clear();
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawLabels());
}

/**
 * @tc.name: TouchDrawingHandlerTest_UpdatePointerPosition_001
 * @tc.desc: Test UpdatePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_UpdatePointerPosition_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    touchDrawingHandler.pointerEvent_->SetPointerId(10);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdatePointerPosition());
    touchDrawingHandler.lastPointerItem_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdatePointerPosition());
}

/**
 * @tc.name: TouchDrawingHandlerTest_UpdatePointerPosition_002
 * @tc.desc: Test UpdatePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_UpdatePointerPosition_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    touchDrawingHandler.pointerEvent_->SetPointerId(10);
    item.SetPointerId(20);
    touchDrawingHandler.lastPointerItem_.push_back(item);
    item.SetPointerId(10);
    touchDrawingHandler.lastPointerItem_.push_back(item);
    touchDrawingHandler.currentPointerId_ = 10;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdatePointerPosition());
    touchDrawingHandler.lastPointerItem_.clear();
    touchDrawingHandler.currentPointerId_ = 50;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdatePointerPosition());
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdatePointerPosition());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdatePointerPosition_003
 * @tc.desc: Test UpdatePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_UpdatePointerPosition_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(5);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdatePointerPosition());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdatePointerPosition_004
 * @tc.desc: Test UpdatePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_UpdatePointerPosition_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(5);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);

    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = pointerEvent;
    touchDrawingHandler.currentPointerId_ = 5;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdatePointerPosition());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdatePointerPosition_005
 * @tc.desc: Test UpdatePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_UpdatePointerPosition_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);

    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = pointerEvent;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdatePointerPosition());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdatePointerPosition_006
 * @tc.desc: Test UpdatePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_UpdatePointerPosition_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(0);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetPressed(true);

    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = pointerEvent;
    touchDrawingHandler.lastPointerItem_.emplace_back(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdatePointerPosition());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateLastPointerItem_001
 * @tc.desc: Test UpdateLastPointerItem
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_UpdateLastPointerItem_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    PointerEvent::PointerItem item;
    item.SetPressed(false);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateLastPointerItem(item));
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateLastPointerItem_002
 * @tc.desc: Test UpdateLastPointerItem
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_UpdateLastPointerItem_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    PointerEvent::PointerItem item;
    item.SetPressed(true);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateLastPointerItem(item));
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateLastPointerItem_003
 * @tc.desc: Test UpdateLastPointerItem
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_UpdateLastPointerItem_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    PointerEvent::PointerItem item;
    item.SetPressed(false);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateLastPointerItem(item));
    item.SetPressed(true);
    item.SetPointerId(10);
    touchDrawingHandler.lastPointerItem_.push_back(item);
    item.SetPointerId(20);
    touchDrawingHandler.lastPointerItem_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateLastPointerItem(item));
}

/**
 * @tc.name: TouchDrawingManagerTest_RemovePointerPosition_001
 * @tc.desc: Test RemovePointerPosition
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_RemovePointerPosition_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.RemovePointerPosition());
}

/**
 * @tc.name: TouchDrawingManagerTest_ClearTracker_001
 * @tc.desc: Test ClearTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_ClearTracker_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.trackerCanvasNode_ == nullptr) {
        touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    }
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.ClearTracker());
}

/**
 * @tc.name: TouchDrawingManagerTest_ClearTracker_002
 * @tc.desc: Test ClearTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_ClearTracker_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.trackerCanvasNode_ == nullptr) {
        touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    }
    touchDrawingHandler.lastPointerItem_.clear();
    touchDrawingHandler.isDownAction_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.ClearTracker());
}

/**
 * @tc.name: TouchDrawingManagerTest_ClearTracker_003
 * @tc.desc: Test ClearTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_ClearTracker_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.trackerCanvasNode_ == nullptr) {
        touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    }
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayY(200);
    touchDrawingHandler.lastPointerItem_.emplace_back(item);
    touchDrawingHandler.isDownAction_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.ClearTracker());
}

/**
 * @tc.name: TouchDrawingManagerTest_ClearTracker_004
 * @tc.desc: Test ClearTracker
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_ClearTracker_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasNode::Create();
    ASSERT_NE(touchDrawingHandler.trackerCanvasNode_, nullptr);
    touchDrawingHandler.scaleW_ = 300;
    touchDrawingHandler.scaleH_ = 500;
    touchDrawingHandler.isDownAction_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.ClearTracker());
    touchDrawingHandler.isDownAction_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.ClearTracker());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateLabels_001
 * @tc.desc: Test UpdateLabels
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_UpdateLabels_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.labelsCanvasNode_ == nullptr) {
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    }
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateLabels(true));
}

/**
 * @tc.name: TouchDrawingHandlerTest_IsValidAction
 * @tc.desc: Test IsValidAction
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_IsValidAction, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    int32_t action = PointerEvent::POINTER_ACTION_DOWN;
    EXPECT_TRUE(touchDrawingHandler.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_PULL_DOWN;
    EXPECT_TRUE(touchDrawingHandler.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_MOVE;
    EXPECT_TRUE(touchDrawingHandler.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_PULL_MOVE;
    EXPECT_TRUE(touchDrawingHandler.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_UP;
    EXPECT_TRUE(touchDrawingHandler.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_PULL_UP;
    EXPECT_TRUE(touchDrawingHandler.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_CANCEL;
    EXPECT_TRUE(touchDrawingHandler.IsValidAction(action));
    action = PointerEvent::POINTER_ACTION_UNKNOWN;
    EXPECT_FALSE(touchDrawingHandler.IsValidAction(action));
    int32_t unknownAction { 100 };
    EXPECT_FALSE(touchDrawingHandler.IsValidAction(unknownAction));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawRectItem_001
 * @tc.desc: Test DrawRectItem
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawRectItem_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    RosenRecordingCanvas *canvas = nullptr;
    std::string text;
    Rosen::Drawing::Rect rect {};
    Rosen::Drawing::Color color {};
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawRectItem(canvas, text, rect, color));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawRectItem_002
 * @tc.desc: Test DrawRectItem
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_DrawRectItem_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.labelsCanvasNode_ == nullptr) {
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasNode::Create();
    }
    auto canvas = static_cast<RosenRecordingCanvas *>(
        touchDrawingHandler.labelsCanvasNode_->BeginRecording(touchDrawingHandler.displayInfo_.width,
        touchDrawingHandler.displayInfo_.height));
    ASSERT_NE(canvas, nullptr);
    std::string text = "test";
    Rosen::Drawing::Rect rect { 1, 1, 10, 10 };
    Rosen::Drawing::Color color = Rosen::Drawing::Color::ColorQuadSetARGB(192, 255, 255, 255);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.DrawRectItem(canvas, text, rect, color));
    touchDrawingHandler.labelsCanvasNode_->FinishRecording();
    Rosen::RSTransaction::FlushImplicitTransaction();
}

/**
 * @tc.name: TouchDrawingManagerTest_Snapshot_001
 * @tc.desc: Test Snapshot
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_Snapshot_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.labelsCanvasNode_ == nullptr) {
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    }
    touchDrawingHandler.isChangedRotation_ = true;
    touchDrawingHandler.displayInfo_.direction = DIRECTION90;
    touchDrawingHandler.displayInfo_.displayDirection = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.Snapshot());
}

/**
 * @tc.name: TouchDrawingManagerTest_Snapshot_002
 * @tc.desc: Test Snapshot
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_Snapshot_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.labelsCanvasNode_ == nullptr) {
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    }
    touchDrawingHandler.isChangedRotation_ = true;
    touchDrawingHandler.displayInfo_.direction = DIRECTION180;
    touchDrawingHandler.displayInfo_.displayDirection = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.Snapshot());
}

/**
 * @tc.name: TouchDrawingManagerTest_Snapshot_003
 * @tc.desc: Test Snapshot
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_Snapshot_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    if (touchDrawingHandler.labelsCanvasNode_ == nullptr) {
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    }
    touchDrawingHandler.isChangedRotation_ = true;
    touchDrawingHandler.displayInfo_.direction = DIRECTION270;
    touchDrawingHandler.displayInfo_.displayDirection = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.Snapshot());
}

/**
 * @tc.name: TouchDrawingManagerTest_InitLabels_001
 * @tc.desc: Test InitLabels
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_InitLabels_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.InitLabels();
    EXPECT_EQ(touchDrawingHandler.isFirstDownAction_, true);
    EXPECT_EQ(touchDrawingHandler.isDownAction_, true);
    EXPECT_EQ(touchDrawingHandler.maxPointerCount_, 0);
}
} // namespace MMI
} // namespace OHOS