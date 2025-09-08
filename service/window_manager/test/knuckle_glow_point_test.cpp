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

#include "ui/rs_canvas_drawing_node.h"
#include "ui/rs_surface_node.h"

#include "i_input_windows_manager.h"
#include "mmi_log.h"
#include "knuckle_glow_point.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleGlowPointTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t MAX_POINTER_COLOR = 0xff0000;
} // namespace

class KnuckleGlowPointTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void)
    {
        std::string imagePath = "/system/etc/multimodalinput/mouse_icon/Default.svg";
        pixelMap = DecodeImageToPixelMap(imagePath);
    };
    void TearDown(void) {};

private:
    std::shared_ptr<OHOS::Media::PixelMap> DecodeImageToPixelMap(const std::string &imagePath)
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

    std::shared_ptr<OHOS::Media::PixelMap> pixelMap {nullptr};
};

/**
 * @tc.name: KnuckleGlowPoint_Update_001
 * @tc.desc: Test Update
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowPointTest, KnuckleGlowPointTest_Update_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto knuckleGlowPoint = KnuckleGlowPoint(pixelMap);
    knuckleGlowPoint.Update();
    EXPECT_EQ(knuckleGlowPoint.lifespan_, -1);
}

/**
 * @tc.name: KnuckleGlowPoint_Update_002
 * @tc.desc: Test Update
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowPointTest, KnuckleGlowPointTest_Update_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto knuckleGlowPoint = KnuckleGlowPoint(pixelMap);
    knuckleGlowPoint.lifespan_ = 1;
    knuckleGlowPoint.Update();
    EXPECT_LT(knuckleGlowPoint.lifespan_, 1);
}

/**
 * @tc.name: KnuckleGlowPointTest_Draw_001
 * @tc.desc: Test Draw
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowPointTest, KnuckleGlowPointTest_Draw_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto knuckleGlowPoint = KnuckleGlowPoint(pixelMap);
    std::shared_ptr<Rosen::RSCanvasDrawingNode> canvasNode = Rosen::RSCanvasDrawingNode::Create();
    auto canvas = static_cast<Rosen::ExtendRecordingCanvas *>(canvasNode->BeginRecording(0, 0));
    knuckleGlowPoint.Draw(canvas);
    EXPECT_EQ(knuckleGlowPoint.lifespan_, -1);
}

/**
 * @tc.name: KnuckleGlowPointTest_Draw_002
 * @tc.desc: Test Draw
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowPointTest, KnuckleGlowPointTest_Draw_002, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto knuckleGlowPoint = KnuckleGlowPoint(pixelMap);
    knuckleGlowPoint.lifespan_ = 1;
    knuckleGlowPoint.pointX_ = 1;
    knuckleGlowPoint.pointY_ = 1;
    std::shared_ptr<Rosen::RSCanvasDrawingNode> canvasNode = Rosen::RSCanvasDrawingNode::Create();
    EXPECT_NE(canvasNode, nullptr);
    auto canvas = static_cast<Rosen::ExtendRecordingCanvas *>(canvasNode->BeginRecording(0, 0));
    knuckleGlowPoint.Draw(canvas);
}

/**
 * @tc.name: KnuckleGlowPointTest_Reset_001
 * @tc.desc: Test Reset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowPointTest, KnuckleGlowPointTest_Reset_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto knuckleGlowPoint = KnuckleGlowPoint(pixelMap);
    double pointX = 0.1;
    double pointY = 0.1;
    float lifespanoffset = 0.1f;
    knuckleGlowPoint.Reset(pointX, pointY, lifespanoffset);
    EXPECT_DOUBLE_EQ(knuckleGlowPoint.pointX_, 0.1);
}

/**
 * @tc.name: KnuckleGlowPointTest_IsEnded_001
 * @tc.desc: Test Reset
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(KnuckleGlowPointTest, KnuckleGlowPointTest_IsEnded_001, TestSize.Level1)
{
    CALL_DEBUG_ENTER;
    auto knuckleGlowPoint = KnuckleGlowPoint(pixelMap);
    double pointX = 0.1;
    double pointY = 0.1;
    float lifespanoffset = -0.1f;
    knuckleGlowPoint.Reset(pointX, pointY, lifespanoffset);
    ASSERT_FALSE(knuckleGlowPoint.IsEnded());
}
} // namespace MMI
} // namespace OHOS