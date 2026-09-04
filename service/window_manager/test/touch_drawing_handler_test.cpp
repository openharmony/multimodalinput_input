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

#include <cstdio>
#include <fstream>
#include <gtest/gtest.h>
#include <tuple>

#include "mmi_log.h"
#include "pointer_event.h"
#ifndef USE_ROSEN_DRAWING
#define USE_ROSEN_DRAWING
#endif
#include "touch_drawing_handler.h"
#include "window_info.h"
#include "ui/rs_ui_context.h"
#include "ui/rs_ui_director.h"
#include "transaction/rs_interfaces.h"

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
    static std::shared_ptr<OHOS::Rosen::RSUIContext> rsUIContext_;
    static std::shared_ptr<OHOS::Rosen::RSUIContext> GetRSUIContext(uint64_t screenId = 0)
    {
        sptr<IRemoteObject> renderToken = Rosen::RSInterfaces::GetInstance().GetConnectToRenderToken(screenId);
        if (renderToken == nullptr) {
            return nullptr;
        }
        auto rsUIDirector = Rosen::RSUIDirector::Create(renderToken);
        if (rsUIDirector == nullptr) {
            return nullptr;
        }
        return rsUIDirector->GetRSUIContext();
    }
    static void SetUpTestCase(void)
    {
        rsUIContext_ = GetRSUIContext(0);
    }
    static void TearDownTestCase(void)
    {
        rsUIContext_ = nullptr;
    }
    void SetUp(void) {};
};

std::shared_ptr<OHOS::Rosen::RSUIContext> TouchDrawingHandlerTest::rsUIContext_ = nullptr;

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
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));
    touchDrawingHandler.isChangedMode_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));
    touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
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
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);

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
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);

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
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    ASSERT_NE(canvasNode, nullptr);
    bool isTrackerNode = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.AddCanvasNode(canvasNode, isTrackerNode));

    canvasNode = nullptr;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.AddCanvasNode(canvasNode, isTrackerNode));
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
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
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
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
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
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);
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
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);
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
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);
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
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
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
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
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
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
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
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
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
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t deviceId { 6 };
    pointerEvent->SetDeviceId(deviceId);
    int32_t pointerId { 1 };
    pointerEvent->SetPointerId(pointerId);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
 
    PointerEvent::PointerItem item {};
    item.SetDeviceId(deviceId);
    item.SetPointerId(pointerId);
    pointerEvent->AddPointerItem(item);
 
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerEvent_ = pointerEvent;
    if (touchDrawingHandler.crosshairCanvasNode_ == nullptr) {
        touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    }
    if (touchDrawingHandler.trackerCanvasNode_ == nullptr) {
        touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
    }
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);
    
    touchDrawingHandler.DrawPointerPositionHandler();
    EXPECT_EQ(touchDrawingHandler.currentDeviceId_, deviceId);
    EXPECT_EQ(touchDrawingHandler.currentPointerId_, pointerId);
 
    PointerEvent::PointerItem item1 {};
    item1.SetDeviceId(deviceId);
    item1.SetPointerId(2);
    pointerEvent->AddPointerItem(item);
    touchDrawingHandler.pointerEvent_ = pointerEvent;
    touchDrawingHandler.DrawPointerPositionHandler();
    EXPECT_EQ(touchDrawingHandler.currentDeviceId_, deviceId);
    EXPECT_EQ(touchDrawingHandler.currentPointerId_, pointerId);
 
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    touchDrawingHandler.pointerEvent_ = pointerEvent;
    touchDrawingHandler.DrawPointerPositionHandler();
    EXPECT_EQ(touchDrawingHandler.currentDeviceId_, deviceId);
    EXPECT_EQ(touchDrawingHandler.currentPointerId_, pointerId);
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
    touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
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
        touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
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
        touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
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
        touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
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
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
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
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
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
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
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
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
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
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);
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
        touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
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
        touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
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
        touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
    }
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayY(200);
    touchDrawingHandler.lastPointerItem_.emplace_back(item);
    touchDrawingHandler.isDownAction_ = true;
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
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
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
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
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
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
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
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
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
        touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
    }
    touchDrawingHandler.isChangedRotation_ = true;
    touchDrawingHandler.displayInfo_.direction = DIRECTION270;
    touchDrawingHandler.displayInfo_.displayDirection = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.Snapshot());
}

/**
 * @tc.name: TouchDrawingManagerTest_SetMultiWindowScreenId
 * @tc.desc: Test SetMultiWindowScreenId
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_SetMultiWindowScreenId, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    touchDrawingHandler.pointerEvent_->AddPointerItem(item);
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    uint64_t screenId = 1;
    uint64_t displayNodeScreenId = 1000;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.SetMultiWindowScreenId(screenId, displayNodeScreenId));
}

/**
 * @tc.name: TouchDrawingManagerTest_Dump
 * @tc.desc: Test Dump
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_Dump, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    touchDrawingHandler.pointerEvent_->AddPointerItem(item);
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    int32_t fd = 1;
    std::vector<std::string> args;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.Dump(fd, args));
}

/**
 * @tc.name: TouchDrawingManagerTest_CalcDrawCoordinate
 * @tc.desc: Test CalcDrawCoordinate
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_CalcDrawCoordinate, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.width = 1920;
    displayInfo.height = 1080;
    displayInfo.name = "Main Display";
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.rawDisplayX_ = 0;
    item.rawDisplayY_ = 0;
    touchDrawingHandler.pointerEvent_->AddPointerItem(item);
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_TRUE(displayInfo.transform.empty());
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.CalcDrawCoordinate(displayInfo, item));

    std::vector<float> transform = {1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0};
    displayInfo.transform = transform;
    EXPECT_FALSE(displayInfo.transform.empty());
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.CalcDrawCoordinate(displayInfo, item));
}

/**
 * @tc.name: TouchDrawingManagerTest_TransformDisplayXY
 * @tc.desc: Test TransformDisplayXY
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_TransformDisplayXY, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.width = 10;
    displayInfo.height = 20;
    displayInfo.validWidth = displayInfo.width;
    displayInfo.validHeight = displayInfo.height;
    displayInfo.direction = DIRECTION90;
    displayInfo.name = "Main Display";

    double logicX = 1280.00;
    double logicY = 960.00;
    auto transformSize = 9;
    EXPECT_NE(displayInfo.transform.size(), transformSize);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.TransformDisplayXY(displayInfo, logicX, logicY));
}

/**
 * @tc.name: TouchDrawingManagerTest_TransformDisplayXY_001
 * @tc.desc: Test TransformDisplayXY
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_TransformDisplayXY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.width = 10;
    displayInfo.height = 20;
    displayInfo.validWidth = displayInfo.width;
    displayInfo.validHeight = displayInfo.height;
    displayInfo.direction = DIRECTION90;
    displayInfo.name = "Main Display";
    double logicX = 1280.00;
    double logicY = 960.00;
    std::vector<float> transform = {1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0};
    displayInfo.transform = transform;
    EXPECT_FALSE(displayInfo.transform.empty());
    auto transformSize = 9;
    EXPECT_EQ(displayInfo.transform.size(), transformSize);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.TransformDisplayXY(displayInfo, logicX, logicY));
}

/**
 * @tc.name: TouchDrawingManagerTest_StartTrace
 * @tc.desc: Test StartTrace
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_StartTrace, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.pointerEvent_ = PointerEvent::Create();
    ASSERT_NE(touchDrawingHandler.pointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    touchDrawingHandler.pointerEvent_->AddPointerItem(item);
    touchDrawingHandler.pointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    int32_t pointerId = 1;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.StartTrace(pointerId));
}

/**
 * @tc.name: TouchDrawingHandlerTest_IsValidScaleInfo_001
 * @tc.desc: Test IsValidScaleInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_IsValidScaleInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler handler;
    handler.scaleW_ = 10;
    handler.scaleH_ = 20;
    bool result = handler.IsValidScaleInfo();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: TouchDrawingHandlerTest_IsValidScaleInfo_002
 * @tc.desc: Test IsValidScaleInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_IsValidScaleInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler handler;
    handler.scaleW_ = 0;
    handler.scaleH_ = 0;
    bool result = handler.IsValidScaleInfo();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TouchDrawingHandlerTest_IsValidScaleInfo_003
 * @tc.desc: Test IsValidScaleInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_IsValidScaleInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler handler;
    handler.scaleW_ = 0;
    handler.scaleH_ = 2700;
    bool result = handler.IsValidScaleInfo();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TouchDrawingHandlerTest_IsValidScaleInfo_004
 * @tc.desc: Test IsValidScaleInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_IsValidScaleInfo_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler handler;
    handler.scaleW_ = 2700;
    handler.scaleH_ = 0;
    bool result = handler.IsValidScaleInfo();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TouchDrawingHandlerTest_RsFlushImplicitTransaction_001
 * @tc.desc: Test RsFlushImplicitTransaction with null rsUIDirector_
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_RsFlushImplicitTransaction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.rsUIDirector_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(touchDrawingHandler.RsFlushImplicitTransaction());
}

/**
 * @tc.name: TouchDrawingHandlerTest_RsFlushImplicitTransaction_002
 * @tc.desc: Test RsFlushImplicitTransaction with valid rsUIDirector_
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_RsFlushImplicitTransaction_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    ASSERT_NO_FATAL_FAILURE(touchDrawingHandler.RsFlushImplicitTransaction());
}

/**
 * @tc.name: TouchDrawingHandlerTest_InitRSUIContext_001
 * @tc.desc: Test InitRSUIContext with screenId
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_InitRSUIContext_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    uint64_t screenId = 0;
    bool ret = touchDrawingHandler.InitRSUIContext(screenId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TouchDrawingHandlerTest_GetScreenWidthHeight_001
 * @tc.desc: Test GetScreenWidthHeight with different directions
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_GetScreenWidthHeight_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    OLD::DisplayInfo displayInfo;
    displayInfo.validWidth = 720;
    displayInfo.validHeight = 1800;
    int32_t width = 0;
    int32_t height = 0;
    displayInfo.displayDirection = Direction::DIRECTION0;

    displayInfo.direction = Direction::DIRECTION0;
    std::tie(width, height) = touchDrawingHandler.GetScreenWidthHeight(displayInfo);
    EXPECT_EQ(width, 720);
    EXPECT_EQ(height, 1800);

    displayInfo.direction = Direction::DIRECTION90;
    std::tie(width, height) = touchDrawingHandler.GetScreenWidthHeight(displayInfo);
    EXPECT_EQ(width, 1800);
    EXPECT_EQ(height, 720);

    displayInfo.direction = Direction::DIRECTION270;
    std::tie(width, height) = touchDrawingHandler.GetScreenWidthHeight(displayInfo);
    EXPECT_EQ(width, 1800);
    EXPECT_EQ(height, 720);

    displayInfo.direction = Direction::DIRECTION180;
    std::tie(width, height) = touchDrawingHandler.GetScreenWidthHeight(displayInfo);
    EXPECT_EQ(width, 720);
    EXPECT_EQ(height, 1800);
}

/**
 * @tc.name: TouchDrawingHandlerTest_WindowCoordinateToScreenCoordinate_001
 * @tc.desc: Test WindowCoordinateToScreenCoordinate with different directions
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_WindowCoordinateToScreenCoordinate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    OLD::DisplayInfo displayInfo;
    displayInfo.validWidth = 720;
    displayInfo.validHeight = 1800;
    displayInfo.displayDirection = Direction::DIRECTION0;
    double x = 100.0;
    double y = 200.0;

    displayInfo.direction = Direction::DIRECTION0;
    double tx = x;
    double ty = y;
    touchDrawingHandler.WindowCoordinateToScreenCoordinate(displayInfo, tx, ty);
    EXPECT_DOUBLE_EQ(tx, 100.0);
    EXPECT_DOUBLE_EQ(ty, 200.0);

    displayInfo.direction = Direction::DIRECTION90;
    tx = x;
    ty = y;
    touchDrawingHandler.WindowCoordinateToScreenCoordinate(displayInfo, tx, ty);
    EXPECT_DOUBLE_EQ(tx, 200.0);
    EXPECT_DOUBLE_EQ(ty, 620.0);

    displayInfo.direction = Direction::DIRECTION180;
    tx = x;
    ty = y;
    touchDrawingHandler.WindowCoordinateToScreenCoordinate(displayInfo, tx, ty);
    EXPECT_DOUBLE_EQ(tx, 620.0);
    EXPECT_DOUBLE_EQ(ty, 1600.0);

    displayInfo.direction = Direction::DIRECTION270;
    tx = x;
    ty = y;
    touchDrawingHandler.WindowCoordinateToScreenCoordinate(displayInfo, tx, ty);
    EXPECT_DOUBLE_EQ(tx, 1600.0);
    EXPECT_DOUBLE_EQ(ty, 100.0);
}

/**
 * @tc.name: TouchDrawingHandlerTest_OnDisplayModeChange_001
 * @tc.desc: Test OnDisplayModeChange resets nodes
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_OnDisplayModeChange_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);
    touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasDrawingNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    ASSERT_NE(touchDrawingHandler.surfaceNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.trackerCanvasNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.bubbleCanvasNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.crosshairCanvasNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.labelsCanvasNode_, nullptr);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnDisplayModeChange());
}

/**
 * @tc.name: TouchDrawingHandlerTest_OnScreenAreaChange_001
 * @tc.desc: Test OnScreenAreaChange updates bounds and handles pointer/bubble modes
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_OnScreenAreaChange_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    ASSERT_NE(touchDrawingHandler.surfaceNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.labelsCanvasNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.crosshairCanvasNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.trackerCanvasNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.bubbleCanvasNode_, nullptr);
    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.screenWidth_ = 720;
    touchDrawingHandler.screenHeight_ = 1800;
    touchDrawingHandler.scaleW_ = 720;
    touchDrawingHandler.scaleH_ = 1800;
    touchDrawingHandler.displayInfo_.rsId = 1;
    touchDrawingHandler.rsId_ = 1;
    // lastPointerItem_ empty, stopRecord_ false -> UpdateLabels
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenAreaChange());

    // lastPointerItem_ empty, stopRecord_ true -> Snapshot
    touchDrawingHandler.stopRecord_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenAreaChange());

    // lastPointerItem_ non-empty -> Snapshot
    touchDrawingHandler.stopRecord_ = false;
    PointerEvent::PointerItem item;
    touchDrawingHandler.lastPointerItem_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenAreaChange());

    // bubble mode show
    touchDrawingHandler.bubbleMode_.isShow = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenAreaChange());

    // pointer mode off
    touchDrawingHandler.pointerMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenAreaChange());
}

/**
 * @tc.name: TouchDrawingHandlerTest_OnScreenAreaChange_002
 * @tc.desc: Test OnScreenAreaChange updates bounds and handles pointer/bubble modes
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_OnScreenAreaChange_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;

    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.labelsCanvasNode_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenAreaChange());

    touchDrawingHandler.lastPointerItem_.clear();
    touchDrawingHandler.stopRecord_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenAreaChange());

    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.bubbleMode_.isShow = true;
    touchDrawingHandler.crosshairCanvasNode_ = nullptr;
    touchDrawingHandler.trackerCanvasNode_ = nullptr;
    touchDrawingHandler.bubbleCanvasNode_ = nullptr;
    touchDrawingHandler.surfaceNode_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenAreaChange());
}

/**
 * @tc.name: TouchDrawingHandlerTest_OnWindowRotation_001
 * @tc.desc: Test OnWindowRotation with pointer mode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_OnWindowRotation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    ASSERT_NE(touchDrawingHandler.labelsCanvasNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.crosshairCanvasNode_, nullptr);
    touchDrawingHandler.screenWidth_ = 720;
    touchDrawingHandler.screenHeight_ = 1800;
    touchDrawingHandler.scaleW_ = 720;
    touchDrawingHandler.scaleH_ = 1800;
    touchDrawingHandler.pointerMode_.isShow = true;
    // lastPointerItem_ empty, stopRecord_ false -> UpdateLabels
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnWindowRotation());

    // lastPointerItem_ non-empty -> Snapshot
    PointerEvent::PointerItem item;
    touchDrawingHandler.lastPointerItem_.push_back(item);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnWindowRotation());

    // stopRecord_ true -> Snapshot
    touchDrawingHandler.stopRecord_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnWindowRotation());

    // pointer mode off
    touchDrawingHandler.pointerMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnWindowRotation());
}

/**
 * @tc.name: TouchDrawingHandlerTest_OnWindowRotation_002
 * @tc.desc: Test OnWindowRotation with pointer mode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_OnWindowRotation_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.labelsCanvasNode_ = nullptr;
    touchDrawingHandler.lastPointerItem_.push_back(PointerEvent::PointerItem());
    touchDrawingHandler.stopRecord_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnWindowRotation());

    touchDrawingHandler.lastPointerItem_.clear();
    touchDrawingHandler.stopRecord_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnWindowRotation());
}

/**
 * @tc.name: TouchDrawingHandlerTest_OnScreenRotation_001
 * @tc.desc: Test OnScreenRotation with pointer and bubble modes
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_OnScreenRotation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);
    touchDrawingHandler.labelsCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.crosshairCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.bubbleCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    touchDrawingHandler.transformModifier_ = std::make_shared<Rosen::ModifierNG::RSTransformModifier>();
    ASSERT_NE(touchDrawingHandler.surfaceNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.labelsCanvasNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.crosshairCanvasNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.trackerCanvasNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.bubbleCanvasNode_, nullptr);
    ASSERT_NE(touchDrawingHandler.transformModifier_, nullptr);
    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.bubbleMode_.isShow = true;
    touchDrawingHandler.screenWidth_ = 720;
    touchDrawingHandler.screenHeight_ = 1800;
    touchDrawingHandler.scaleW_ = 720;
    touchDrawingHandler.scaleH_ = 1800;
    touchDrawingHandler.displayInfo_.rsId = 1;
    touchDrawingHandler.rsId_ = 1;
    touchDrawingHandler.displayInfo_.validWidth = 720;
    touchDrawingHandler.displayInfo_.validHeight = 1800;
    // lastPointerItem_ empty, stopRecord_ false -> UpdateLabels + TrackerSnapshot
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenRotation());

    touchDrawingHandler.lastPointerItem_.push_back(PointerEvent::PointerItem());
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenRotation());

    // pointer mode off, bubble mode on
    touchDrawingHandler.pointerMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenRotation());

    // bubble mode off, pointer mode on
    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.bubbleMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenRotation());

    // both off
    touchDrawingHandler.pointerMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenRotation());
}

/**
 * @tc.name: TouchDrawingHandlerTest_OnScreenRotation_002
 * @tc.desc: Test OnScreenRotation with pointer and bubble modes
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_OnScreenRotation_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;

    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.labelsCanvasNode_ = nullptr;
    touchDrawingHandler.lastPointerItem_.push_back(PointerEvent::PointerItem());
    touchDrawingHandler.stopRecord_ = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenRotation());

    touchDrawingHandler.lastPointerItem_.clear();
    touchDrawingHandler.stopRecord_ = false;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenRotation());

    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.bubbleMode_.isShow = true;
    touchDrawingHandler.crosshairCanvasNode_ = nullptr;
    touchDrawingHandler.trackerCanvasNode_ = nullptr;
    touchDrawingHandler.bubbleCanvasNode_ = nullptr;
    touchDrawingHandler.surfaceNode_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.OnScreenRotation());
}

/**
 * @tc.name: TouchDrawingHandlerTest_TrackerSnapshot_001
 * @tc.desc: Test TrackerSnapshot with null transformModifier_
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_TrackerSnapshot_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.TrackerSnapshot());
}

/**
 * @tc.name: TouchDrawingHandlerTest_TrackerSnapshot_002
 * @tc.desc: Test TrackerSnapshot with different directions
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_TrackerSnapshot_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.transformModifier_ = std::make_shared<Rosen::ModifierNG::RSTransformModifier>();
    ASSERT_NE(touchDrawingHandler.transformModifier_, nullptr);
    touchDrawingHandler.displayInfo_.validWidth = 720;
    touchDrawingHandler.displayInfo_.validHeight = 1800;
    touchDrawingHandler.prevDirection_ = Direction::DIRECTION0;
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.TrackerSnapshot());
    EXPECT_TRUE(touchDrawingHandler.needResetTracker_);

    touchDrawingHandler.prevDirection_ = Direction::DIRECTION0;
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION90;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.TrackerSnapshot());

    touchDrawingHandler.prevDirection_ = Direction::DIRECTION0;
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION180;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.TrackerSnapshot());

    touchDrawingHandler.prevDirection_ = Direction::DIRECTION0;
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.TrackerSnapshot());
}

/**
 * @tc.name: TouchDrawingHandlerTest_UpdateDisplayInfo_003
 * @tc.desc: Test UpdateDisplayInfo with screen area and mode changes
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_UpdateDisplayInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    OLD::DisplayInfo displayInfo;
    displayInfo.direction = Direction::DIRECTION0;
    displayInfo.displayDirection = Direction::DIRECTION0;
    displayInfo.displayMode = DisplayMode::UNKNOWN;
    displayInfo.displaySourceMode = DisplaySourceMode::SCREEN_MAIN;
    displayInfo.rsId = 1;
    displayInfo.validWidth = 720;
    displayInfo.validHeight = 1800;
    // initialize
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));

    // change validWidth only -> screen area changed
    displayInfo.validWidth = 800;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));

    // change displayMode -> mode changed, OnDisplayModeChange
    displayInfo.displayMode = DisplayMode::FULL;
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.UpdateDisplayInfo(displayInfo));
}

/**
 * @tc.name: TouchDrawingHandlerTest_TouchDrawHandler_needResetTracker_001
 * @tc.desc: Test TouchDrawHandler resets tracker when needResetTracker_ is true
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingHandlerTest_TouchDrawHandler_needResetTracker_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    touchDrawingHandler.pointerMode_.isShow = true;
    touchDrawingHandler.stopRecord_ = false;
    touchDrawingHandler.trackerCanvasNode_ = Rosen::RSCanvasNode::Create(false, false, rsUIContext_);
    ASSERT_NE(touchDrawingHandler.trackerCanvasNode_, nullptr);
    touchDrawingHandler.needResetTracker_ = true;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    EXPECT_NO_FATAL_FAILURE(touchDrawingHandler.TouchDrawHandler(pointerEvent));
    EXPECT_FALSE(touchDrawingHandler.needResetTracker_);
}

/**
 * @tc.name: TouchDrawingManagerTest_AddCanvasNode_004
 * @tc.desc: Test AddCanvasNode creates transformModifier_ for tracker node
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingHandlerTest, TouchDrawingManagerTest_AddCanvasNode_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingHandler touchDrawingHandler;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    touchDrawingHandler.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType, true, false,
        rsUIContext_);
    std::shared_ptr<Rosen::RSCanvasNode> canvasNode = nullptr;
    bool isTrackerNode = true;
    touchDrawingHandler.screenWidth_ = 720;
    touchDrawingHandler.screenHeight_ = 1800;
    touchDrawingHandler.displayInfo_.direction = Direction::DIRECTION0;
    touchDrawingHandler.displayInfo_.rsId = 1;
    touchDrawingHandler.AddCanvasNode(canvasNode, isTrackerNode, "Tracker CanvasNode");
    EXPECT_NE(canvasNode, nullptr);
    EXPECT_NE(touchDrawingHandler.transformModifier_, nullptr);
    EXPECT_EQ(touchDrawingHandler.prevDirection_, Direction::DIRECTION0);
}
} // namespace MMI
} // namespace OHOS