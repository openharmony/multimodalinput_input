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

#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"

#include "mmi_log.h"
#include "pointer_event.h"
#include "knuckle_dynamic_drawing_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleDynamicDrawingManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t POINT_SYSTEM_SIZE = 50;
constexpr int32_t MAX_DIVERGENCE_NUM = 10;
constexpr int32_t MAX_POINTER_COLOR = 0xff00ff;
} // namespace

class KnuckleDynamicDrawingManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void)
    {
        DisplayInfo displayInfo = { .id = 1, .x = 1, .y = 1, .width = 1, .height = 1,
            .dpi = 240, .name = "display", .uniq = "xx" };
        if (knuckleDynamicDrawingMgr == nullptr) {
            knuckleDynamicDrawingMgr = std::make_shared<KnuckleDynamicDrawingManager>();
        }
        knuckleDynamicDrawingMgr->UpdateDisplayInfo(displayInfo);
    }

    std::shared_ptr<Media::PixelMap> DecodeImageToPixelMap(const std::string &imagePath);
private:
    std::shared_ptr<KnuckleDynamicDrawingManager> knuckleDynamicDrawingMgr { nullptr };
};

std::shared_ptr<Media::PixelMap> KnuckleDynamicDrawingManagerTest::DecodeImageToPixelMap(const std::string &imagePath)
{
    CALL_DEBUG_ENTER;
    OHOS::Media::SourceOptions opts;
    uint32_t ret = 0;
    auto imageSource = OHOS::Media::ImageSource::CreateImageSource(imagePath, opts, ret);
    CHKPP(imageSource);
    std::set<std::string> formats;
    ret = imageSource->GetSupportedFormats(formats);
    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {
        .width = 80,
        .height = 80
    };

    decodeOpts.SVGOpts.fillColor = {.isValidColor = false, .color = MAX_POINTER_COLOR};
    decodeOpts.SVGOpts.strokeColor = {.isValidColor = false, .color = MAX_POINTER_COLOR};

    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, ret);
    if (pixelMap == nullptr) {
        MMI_HILOGE("The pixelMap is nullptr");
    }
    return pixelMap;
}

/**
 * @tc.name: KnuckleDrawingManagerTest_KnuckleDynamicDrawHandler
 * @tc.desc: Test Normal branch of covering KnuckleDynamicDrawHandler function
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest,
    KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_Normal, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDynamicDrawingManager knuckleDynamicDrawMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_MOUSE);
    pointerEvent->SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    ASSERT_NO_FATAL_FAILURE(knuckleDynamicDrawMgr.KnuckleDynamicDrawHandler(pointerEvent));
}

/**
 * @tc.name: KnuckleDrawingManagerTest_KnuckleDynamicDrawHandler_001
 * @tc.desc: Test Abnormal branch of covering KnuckleDynamicDrawHandler function
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest,
    KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_Abnormal, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDynamicDrawingManager knuckleDynamicDrawMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetTargetDisplayId(50);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_DOWN);
    ASSERT_NO_FATAL_FAILURE(knuckleDynamicDrawMgr.KnuckleDynamicDrawHandler(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_SWIPE_END);
    ASSERT_NO_FATAL_FAILURE(knuckleDynamicDrawMgr.KnuckleDynamicDrawHandler(pointerEvent));
}

/**
 * @tc.name: KnuckleDrawingManagerTest_InitPointerPathPaint
 * @tc.desc: Test Overrides InitPointerPathPaint function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_InitPointerPathPaint, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDynamicDrawingManager knuckleDynamicDrawMgr;
    knuckleDynamicDrawMgr.glowTraceSystem_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(knuckleDynamicDrawMgr.InitPointerPathPaint());
    std::string imagePath = "/system/etc/multimodalinput/mouse_icon/Default.svg";
    auto pixelMap = DecodeImageToPixelMap(imagePath);
    knuckleDynamicDrawMgr.glowTraceSystem_ =
        std::make_shared<KnuckleGlowTraceSystem>(POINT_SYSTEM_SIZE, pixelMap, MAX_DIVERGENCE_NUM);
    ASSERT_NO_FATAL_FAILURE(knuckleDynamicDrawMgr.InitPointerPathPaint());
}

/**
 * @tc.name: KnuckleDrawingManagerTest_IsSingleKnuckle
 * @tc.desc: Test Overrides IsSingleKnuckle function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_IsSingleKnuckle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDynamicDrawingManager knuckleDynamicDrawMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    ASSERT_TRUE(knuckleDynamicDrawMgr.IsSingleKnuckle(pointerEvent));

    item.SetPointerId(2);
    item.SetToolType(PointerEvent::TOOL_TYPE_TOUCHPAD);
    pointerEvent->SetPointerId(2);
    pointerEvent->AddPointerItem(item);
    knuckleDynamicDrawMgr.canvasNode_ = nullptr;
    ASSERT_FALSE(knuckleDynamicDrawMgr.IsSingleKnuckle(pointerEvent));

    knuckleDynamicDrawMgr.canvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    ASSERT_NE(knuckleDynamicDrawMgr.canvasNode_, nullptr);
    ASSERT_FALSE(knuckleDynamicDrawMgr.IsSingleKnuckle(pointerEvent));
}

/**
 * @tc.name: KnuckleDrawingManagerTest_CheckPointerAction
 * @tc.desc: Test Overrides CheckPointerAction function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_CheckPointerAction, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDynamicDrawingManager knuckleDynamicDrawMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    pointerEvent->SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    ASSERT_TRUE(knuckleDynamicDrawMgr.CheckPointerAction(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP);
    ASSERT_TRUE(knuckleDynamicDrawMgr.CheckPointerAction(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    ASSERT_TRUE(knuckleDynamicDrawMgr.CheckPointerAction(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_DOWN);
    ASSERT_TRUE(knuckleDynamicDrawMgr.CheckPointerAction(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    ASSERT_TRUE(knuckleDynamicDrawMgr.CheckPointerAction(pointerEvent));
    knuckleDynamicDrawMgr.isStop_ = true;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_MOVE);
    ASSERT_FALSE(knuckleDynamicDrawMgr.CheckPointerAction(pointerEvent));
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UNKNOWN);
    ASSERT_FALSE(knuckleDynamicDrawMgr.CheckPointerAction(pointerEvent));
    item.SetPointerId(2);
    pointerEvent->SetPointerId(2);
    pointerEvent->AddPointerItem(item);
    std::string imagePath = "/system/etc/multimodalinput/mouse_icon/Default.svg";
    auto pixelMap = DecodeImageToPixelMap(imagePath);
    knuckleDynamicDrawMgr.glowTraceSystem_ =
        std::make_shared<KnuckleGlowTraceSystem>(POINT_SYSTEM_SIZE, pixelMap, MAX_DIVERGENCE_NUM);
    ASSERT_FALSE(knuckleDynamicDrawMgr.CheckPointerAction(pointerEvent));
}

/**
 * @tc.name: KnuckleDrawingManagerTest_StartTouchDraw
 * @tc.desc: Test Overrides StartTouchDraw function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_StartTouchDraw, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDynamicDrawingManager knuckleDynamicDrawMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(1);
    ASSERT_NO_FATAL_FAILURE(knuckleDynamicDrawMgr.StartTouchDraw(pointerEvent));

    knuckleDynamicDrawMgr.canvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    ASSERT_NE(knuckleDynamicDrawMgr.canvasNode_, nullptr);
    knuckleDynamicDrawMgr.displayInfo_.width = 200;
    knuckleDynamicDrawMgr.displayInfo_.height = 200;
    std::string imagePath = "/system/etc/multimodalinput/mouse_icon/Default.svg";
    auto pixelMap = DecodeImageToPixelMap(imagePath);
    knuckleDynamicDrawMgr.glowTraceSystem_ =
        std::make_shared<KnuckleGlowTraceSystem>(POINT_SYSTEM_SIZE, pixelMap, MAX_DIVERGENCE_NUM);
    knuckleDynamicDrawMgr.isDrawing_ = true;
    ASSERT_NO_FATAL_FAILURE(knuckleDynamicDrawMgr.StartTouchDraw(pointerEvent));
}

/**
 * @tc.name: KnuckleDrawingManagerTest_ProcessMoveEvent
 * @tc.desc: Test Overrides ProcessMoveEvent function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_ProcessMoveEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDynamicDrawingManager knuckleDynamicDrawMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    knuckleDynamicDrawMgr.pointCounter_ = 6;
    ASSERT_NO_FATAL_FAILURE(knuckleDynamicDrawMgr.ProcessMoveEvent(pointerEvent));

    std::string imagePath = "/system/etc/multimodalinput/mouse_icon/Default.svg";
    auto pixelMap = DecodeImageToPixelMap(imagePath);
    knuckleDynamicDrawMgr.glowTraceSystem_ =
        std::make_shared<KnuckleGlowTraceSystem>(POINT_SYSTEM_SIZE, pixelMap, MAX_DIVERGENCE_NUM);
    PointerEvent::PointerItem item;
    item.SetDisplayX(200);
    item.SetDisplayY(200);
    pointerEvent->AddPointerItem(item);
    knuckleDynamicDrawMgr.pointCounter_ = 2;
    ASSERT_NO_FATAL_FAILURE(knuckleDynamicDrawMgr.ProcessMoveEvent(pointerEvent));

    Rosen::Drawing::Point point;
    point.SetX(100);
    point.SetY(100);
    knuckleDynamicDrawMgr.traceControlPoints_.push_back(point);
    point.SetX(150);
    point.SetY(150);
    knuckleDynamicDrawMgr.traceControlPoints_.push_back(point);
    point.SetX(200);
    point.SetY(200);
    knuckleDynamicDrawMgr.traceControlPoints_.push_back(point);
    point.SetX(300);
    point.SetY(300);
    knuckleDynamicDrawMgr.traceControlPoints_.push_back(point);
    knuckleDynamicDrawMgr.lastUpdateTimeMillis_ = 50;
    pointerEvent->SetActionTime(100);
    ASSERT_NO_FATAL_FAILURE(knuckleDynamicDrawMgr.ProcessMoveEvent(pointerEvent));
}

/**
 * @tc.name: KnuckleDrawingManagerTest_DrawGraphic
 * @tc.desc: Test Overrides DrawGraphic function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_DrawGraphic, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDynamicDrawingManager knuckleDynamicDrawMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerId(1);

    knuckleDynamicDrawMgr.canvasNode_ = Rosen::RSCanvasDrawingNode::Create();
    ASSERT_NE(knuckleDynamicDrawMgr.canvasNode_, nullptr);
    knuckleDynamicDrawMgr.displayInfo_.width = 200;
    knuckleDynamicDrawMgr.displayInfo_.height = 200;
    std::string imagePath = "/system/etc/multimodalinput/mouse_icon/Default.svg";
    auto pixelMap = DecodeImageToPixelMap(imagePath);
    knuckleDynamicDrawMgr.glowTraceSystem_ =
        std::make_shared<KnuckleGlowTraceSystem>(POINT_SYSTEM_SIZE, pixelMap, MAX_DIVERGENCE_NUM);
    knuckleDynamicDrawMgr.isDrawing_ = false;
    ASSERT_EQ(knuckleDynamicDrawMgr.DrawGraphic(pointerEvent), RET_OK);
    knuckleDynamicDrawMgr.isDrawing_ = true;
    ASSERT_EQ(knuckleDynamicDrawMgr.DrawGraphic(pointerEvent), RET_OK);
}

/**
 * @tc.name: KnuckleDrawingManagerTest_CreateTouchWindow
 * @tc.desc: Test Overrides CreateTouchWindow function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_CreateTouchWindow, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDynamicDrawingManager knuckleDynamicDrawMgr;
    int32_t displayId = 10;
    knuckleDynamicDrawMgr.surfaceNode_ = nullptr;
    knuckleDynamicDrawMgr.displayInfo_.width = 200;
    knuckleDynamicDrawMgr.displayInfo_.height = 200;
    ASSERT_NO_FATAL_FAILURE(knuckleDynamicDrawMgr.CreateTouchWindow(displayId));

    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    knuckleDynamicDrawMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(knuckleDynamicDrawMgr.surfaceNode_, nullptr);
    ASSERT_NO_FATAL_FAILURE(knuckleDynamicDrawMgr.CreateTouchWindow(displayId));
}

/**
 * @tc.name: KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_001
 * @tc.desc: Test KnuckleDynamicDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_001,
    TestSize.Level1)
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
    item.SetToolType(PointerEvent::TOOL_TYPE_FINGER);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(knuckleDynamicDrawingMgr->KnuckleDynamicDrawHandler(pointerEvent));
}

/**
 * @tc.name: KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_002
 * @tc.desc: Test KnuckleDynamicDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_002,
    TestSize.Level1)
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
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(knuckleDynamicDrawingMgr->KnuckleDynamicDrawHandler(pointerEvent));
}

/**
 * @tc.name: KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_003
 * @tc.desc: Test KnuckleDynamicDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_003,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item1;
    item1.SetPointerId(0);
    int32_t displayX = 100;
    int32_t displayY = 200;
    item1.SetDisplayX(displayX);
    item1.SetDisplayY(displayY);
    item1.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item1);

    PointerEvent::PointerItem item2;
    item2.SetPointerId(1);
    displayX = 200;
    displayY = 200;
    item2.SetDisplayX(displayX);
    item2.SetDisplayY(displayY);
    item2.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->AddPointerItem(item2);
    EXPECT_NO_FATAL_FAILURE(knuckleDynamicDrawingMgr->KnuckleDynamicDrawHandler(pointerEvent));
}

/**
 * @tc.name: KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_004
 * @tc.desc: Test KnuckleDynamicDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_004,
    TestSize.Level1)
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
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(knuckleDynamicDrawingMgr->KnuckleDynamicDrawHandler(pointerEvent));
}

/**
 * @tc.name: KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_005
 * @tc.desc: Test KnuckleDynamicDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_005,
    TestSize.Level1)
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
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(knuckleDynamicDrawingMgr->KnuckleDynamicDrawHandler(pointerEvent));
}

/**
 * @tc.name: KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_006
 * @tc.desc: Test KnuckleDynamicDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_KnuckleDynamicDrawHandler_006,
    TestSize.Level1)
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
    item.SetToolType(PointerEvent::TOOL_TYPE_KNUCKLE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(knuckleDynamicDrawingMgr->KnuckleDynamicDrawHandler(pointerEvent));
}

/**
 * @tc.name: KnuckleDynamicDrawingManagerTest_UpdateDisplayInfo_001
 * @tc.desc: Test UpdateDisplayInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_UpdateDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo displayInfo = { .id = 1, .x = 1, .y = 1, .width = 1, .height = 1,
        .dpi = 240, .name = "display", .uniq = "xx" };
    EXPECT_NO_FATAL_FAILURE(knuckleDynamicDrawingMgr->UpdateDisplayInfo(displayInfo));
}

/**
 * @tc.name: KnuckleDynamicDrawingManagerTest_UpdateDisplayInfo_002
 * @tc.desc: Test UpdateDisplayInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_UpdateDisplayInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo displayInfo;
    EXPECT_NO_FATAL_FAILURE(knuckleDynamicDrawingMgr->UpdateDisplayInfo(displayInfo));
}
} // namespace MMI
} // namespace OHOS