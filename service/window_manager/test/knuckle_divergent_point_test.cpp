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

#include "image/bitmap.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"

#ifndef USE_ROSEN_DRAWING
#include "pipeline/rs_recording_canvas.h"
#else
#include "recording/recording_canvas.h"
#include "ui/rs_canvas_drawing_node.h"
#endif // USE_ROSEN_DRAWING
#include "render/rs_pixel_map_util.h"

#include "mmi_log.h"
#include "pointer_event.h"
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
            auto bitmap = PixelMapToBitmap(pixelMap);
            CHKPV(bitmap);
            knuckleDivergentPoint = std::make_shared<KnuckleDivergentPoint>(*bitmap);
        }
    }
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

    std::shared_ptr<Rosen::Drawing::Bitmap> PixelMapToBitmap(std::shared_ptr<Media::PixelMap>& pixelMap)
    {
        CALL_DEBUG_ENTER;
        auto data = pixelMap->GetPixels();
        Rosen::Drawing::Bitmap bitmap;
        Rosen::Drawing::ColorType colorType = PixelFormatToColorType(pixelMap->GetPixelFormat());
        Rosen::Drawing::AlphaType alphaType = AlphaTypeToAlphaType(pixelMap->GetAlphaType());
        Rosen::Drawing::ImageInfo imageInfo(pixelMap->GetWidth(), pixelMap->GetHeight(), colorType, alphaType);
        bitmap.Build(imageInfo);
        bitmap.SetPixels(const_cast<uint8_t*>(data));
        return std::make_shared<Rosen::Drawing::Bitmap>(bitmap);
    }

    Rosen::Drawing::ColorType PixelFormatToColorType(Media::PixelFormat pixelFormat)
    {
        switch (pixelFormat) {
            case Media::PixelFormat::RGB_565:
                return Rosen::Drawing::ColorType::COLORTYPE_RGB_565;
            case Media::PixelFormat::RGBA_8888:
                return Rosen::Drawing::ColorType::COLORTYPE_RGBA_8888;
            case Media::PixelFormat::BGRA_8888:
                return Rosen::Drawing::ColorType::COLORTYPE_BGRA_8888;
            case Media::PixelFormat::ALPHA_8:
                return Rosen::Drawing::ColorType::COLORTYPE_ALPHA_8;
            case Media::PixelFormat::RGBA_F16:
                return Rosen::Drawing::ColorType::COLORTYPE_RGBA_F16;
            case Media::PixelFormat::UNKNOWN:
            case Media::PixelFormat::ARGB_8888:
            case Media::PixelFormat::RGB_888:
            case Media::PixelFormat::NV21:
            case Media::PixelFormat::NV12:
            case Media::PixelFormat::CMYK:
            default:
                return Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN;
        }
    }

    Rosen::Drawing::AlphaType AlphaTypeToAlphaType(Media::AlphaType alphaType)
    {
        CALL_DEBUG_ENTER;
        switch (alphaType) {
            case Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN:
                return Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN;
            case Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE:
                return Rosen::Drawing::AlphaType::ALPHATYPE_OPAQUE;
            case Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL:
                return Rosen::Drawing::AlphaType::ALPHATYPE_PREMUL;
            case Media::AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL:
                return Rosen::Drawing::AlphaType::ALPHATYPE_UNPREMUL;
            default:
                return Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN;
        }
    }

    std::shared_ptr<KnuckleDivergentPoint> knuckleDivergentPoint { nullptr };
};

/**
 * @tc.name: KnuckleDivergentPointTest_Update_001
 * @tc.desc: Test Update
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDivergentPointTest, KnuckleDivergentPointTest_Update_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(knuckleDivergentPoint->Update());
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
    EXPECT_NO_FATAL_FAILURE(knuckleDivergentPoint->Clear());
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
    Rosen::Drawing::RecordingCanvas* canvas = nullptr;
    EXPECT_NO_FATAL_FAILURE(knuckleDivergentPoint->Draw(canvas));
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
    double pointX = 0.0;
    double pointY = 0.0;
    EXPECT_NO_FATAL_FAILURE(knuckleDivergentPoint->Reset(pointX, pointY));
}

/**
 * @tc.name: KnuckleDivergentPointTest_Reset_002
 * @tc.desc: Test Reset
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDivergentPointTest, KnuckleDivergentPointTest_Reset_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    double pointX = 1.0;
    double pointY = 1.0;
    EXPECT_NO_FATAL_FAILURE(knuckleDivergentPoint->Reset(pointX, pointY));
}

/**
 * @tc.name: KnuckleDivergentPointTest_IsEnded_001
 * @tc.desc: Test IsEnded
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(KnuckleDivergentPointTest, KnuckleDivergentPointTest_IsEnded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(knuckleDivergentPoint->IsEnded());
}

} // namespace MMI
} // namespace OHOS