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
} // namespace MMI
} // namespace OHOS