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

#include "knuckle_dynamic_drawing_manager.h"

#include <cstdio>
#include <fstream>
#include <gtest/gtest.h>

#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleDynamicDrawingManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t POINT_SYSTEM_SIZE = 50;
constexpr int32_t MAX_DIVERGENCE_NUM = 10;
} // namespace

class KnuckleDynamicDrawingManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
};

/**
 * @tc.name: KnuckleDrawingManagerTest_AlphaTypeToAlphaType
 * @tc.desc: Test Overrides AlphaTypeToAlphaType function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_AlphaTypeToAlphaType, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDynamicDrawingManager knuckleDynamicDrawMgr;
    Media::AlphaType alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    ASSERT_EQ(knuckleDynamicDrawMgr.AlphaTypeToAlphaType(alphaType), Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN);
    alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    ASSERT_EQ(knuckleDynamicDrawMgr.AlphaTypeToAlphaType(alphaType), Rosen::Drawing::AlphaType::ALPHATYPE_OPAQUE);
    alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    ASSERT_EQ(knuckleDynamicDrawMgr.AlphaTypeToAlphaType(alphaType), Rosen::Drawing::AlphaType::ALPHATYPE_PREMUL);
    alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    ASSERT_EQ(knuckleDynamicDrawMgr.AlphaTypeToAlphaType(alphaType), Rosen::Drawing::AlphaType::ALPHATYPE_UNPREMUL);
    alphaType = static_cast<Media::AlphaType>(5);
    ASSERT_EQ(knuckleDynamicDrawMgr.AlphaTypeToAlphaType(alphaType), Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN);
}

/**
 * @tc.name: KnuckleDrawingManagerTest_PixelFormatToColorType
 * @tc.desc: Test Overrides PixelFormatToColorType function branches
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDynamicDrawingManagerTest, KnuckleDynamicDrawingManagerTest_PixelFormatToColorType, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KnuckleDynamicDrawingManager knuckleDynamicDrawMgr;
    Media::PixelFormat pixelFmt = Media::PixelFormat::RGB_565;
    ASSERT_EQ(knuckleDynamicDrawMgr.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_RGB_565);
    pixelFmt = Media::PixelFormat::RGBA_8888;
    ASSERT_EQ(knuckleDynamicDrawMgr.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_RGBA_8888);
    pixelFmt = Media::PixelFormat::BGRA_8888;
    ASSERT_EQ(knuckleDynamicDrawMgr.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_BGRA_8888);
    pixelFmt = Media::PixelFormat::ALPHA_8;
    ASSERT_EQ(knuckleDynamicDrawMgr.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_ALPHA_8);
    pixelFmt = Media::PixelFormat::RGBA_F16;
    ASSERT_EQ(knuckleDynamicDrawMgr.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_RGBA_F16);
    pixelFmt = Media::PixelFormat::UNKNOWN;
    ASSERT_EQ(knuckleDynamicDrawMgr.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::ARGB_8888;
    ASSERT_EQ(knuckleDynamicDrawMgr.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::RGB_888;
    ASSERT_EQ(knuckleDynamicDrawMgr.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::NV21;
    ASSERT_EQ(knuckleDynamicDrawMgr.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::NV12;
    ASSERT_EQ(knuckleDynamicDrawMgr.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::CMYK;
    ASSERT_EQ(knuckleDynamicDrawMgr.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = static_cast<Media::PixelFormat>(100);
    ASSERT_EQ(knuckleDynamicDrawMgr.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
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
    Rosen::Drawing::Bitmap bitmap;
    knuckleDynamicDrawMgr.glowTraceSystem_ =
        std::make_shared<KnuckleGlowTraceSystem>(POINT_SYSTEM_SIZE, bitmap, MAX_DIVERGENCE_NUM);
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
} // namespace MMI
} // namespace OHOS