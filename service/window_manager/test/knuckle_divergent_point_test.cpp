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

#include "pipeline/rs_recording_canvas.h"
#include "render/rs_pixel_map_util.h"

#include "mmi_log.h"
#include "pointer_event.h"
#include "ui/rs_canvas_drawing_node.h"
#include "knuckle_divergent_point.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleDivergentPointTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t MAX_POINTER_COLOR = 0xffffff;
} // namespace
class KnuckleDivergentPointTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void)
    {
        if (knuckleDivergentPoint == nullptr) {
            std::string imagePath = "/system/etc/multimodalinput/mouse_icon/Default.svg";
            auto pixelMap = DecodeImageToPixelMap(imagePath);
            CHKPV(pixelMap);
            knuckleDivergentPoint = std::make_shared<KnuckleDivergentPoint>(pixelMap);
        }
    }
    void TearDown(void) {}
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

    std::shared_ptr<KnuckleDivergentPoint> knuckleDivergentPoint { nullptr };
};

/**
 * @tc.name: KnuckleDivergentPointTest_IsEnded_001
 * @tc.desc: Test IsEnded
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDivergentPointTest, KnuckleDivergentPointTest_IsEnded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(knuckleDivergentPoint->IsEnded());
}

/**
 * @tc.name: KnuckleDivergentPointTest_IsEnded_002
 * @tc.desc: Test IsEnded
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDivergentPointTest, KnuckleDivergentPointTest_IsEnded_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    knuckleDivergentPoint->lifespan_ = 1;
    EXPECT_FALSE(knuckleDivergentPoint->IsEnded());
}

/**
 * @tc.name: KnuckleDivergentPointTest_Update_001
 * @tc.desc: Test Update
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDivergentPointTest, KnuckleDivergentPointTest_Update_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    knuckleDivergentPoint->Update();
    EXPECT_LT(knuckleDivergentPoint->lifespan_, 0);
}

/**
 * @tc.name: KnuckleDivergentPointTest_Update_002
 * @tc.desc: Test Update
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDivergentPointTest, KnuckleDivergentPointTest_Update_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    knuckleDivergentPoint->lifespan_ = 1;
    knuckleDivergentPoint->Update();
    EXPECT_EQ(knuckleDivergentPoint->lifespan_, 0);
}

/**
 * @tc.name: KnuckleDivergentPointTest_Clear_001
 * @tc.desc: Test Clear
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDivergentPointTest, KnuckleDivergentPointTest_Clear_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    knuckleDivergentPoint->Clear();
    EXPECT_EQ(knuckleDivergentPoint->lifespan_, -1);
}

/**
 * @tc.name: KnuckleDivergentPointTest_Draw_001
 * @tc.desc: Test Draw
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDivergentPointTest, KnuckleDivergentPointTest_Draw_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    knuckleDivergentPoint->Draw(nullptr);
    EXPECT_EQ(knuckleDivergentPoint->lifespan_, -1);
}

/**
 * @tc.name: KnuckleDivergentPointTest_Draw_002
 * @tc.desc: Test Draw
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDivergentPointTest, KnuckleDivergentPointTest_Draw_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<Rosen::RSCanvasDrawingNode> canvasNode = Rosen::RSCanvasDrawingNode::Create();
    auto canvas = static_cast<Rosen::ExtendRecordingCanvas *>(canvasNode->BeginRecording(10, 10));
    knuckleDivergentPoint->Draw(canvas);
    EXPECT_EQ(knuckleDivergentPoint->lifespan_, -1);
}

/**
 * @tc.name: KnuckleDivergentPointTest_Draw_003
 * @tc.desc: Test Draw
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDivergentPointTest, KnuckleDivergentPointTest_Draw_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    knuckleDivergentPoint->lifespan_ = 1;
    knuckleDivergentPoint->pointX_ = 1;
    knuckleDivergentPoint->pointY_ = 1;
    std::shared_ptr<Rosen::RSCanvasDrawingNode> canvasNode = Rosen::RSCanvasDrawingNode::Create();
    auto canvas = static_cast<Rosen::ExtendRecordingCanvas *>(canvasNode->BeginRecording(0, 0));
    knuckleDivergentPoint->Draw(canvas);
    EXPECT_EQ(knuckleDivergentPoint->lifespan_, 1);
}

/**
 * @tc.name: KnuckleDivergentPointTest_Reset_001
 * @tc.desc: Test Reset
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDivergentPointTest, KnuckleDivergentPointTest_Reset_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    double pointX = 10.0;
    double pointY = 5.0;
    knuckleDivergentPoint->Reset(pointX, pointY);
    EXPECT_DOUBLE_EQ(knuckleDivergentPoint->pointX_, 10.0);
    EXPECT_DOUBLE_EQ(knuckleDivergentPoint->pointY_, 5.0);
}
} // namespace MMI
} // namespace OHOS