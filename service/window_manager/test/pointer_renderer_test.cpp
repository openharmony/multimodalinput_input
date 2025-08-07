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

#include "input_manager_util.h"
#include "mmi_log.h"
#include "pointer_renderer.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerRendererTest"
constexpr int32_t MIN_POINTER_COLOR{0x000000};
constexpr int32_t MAX_POINTER_COLOR{0xFFFFFF};
constexpr int32_t OTHER_POINTER_COLOR{0x171717};
constexpr int32_t MIDDLE_POINTER_COLOR{0x7F7F7F};

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class PointerRendererTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {};
};

/**
 * @tc.name: PointerRendererTest_GetOffsetX_001
 * @tc.desc: Test GetOffsetX
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_GetOffsetX_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    config.align_ = ICON_TYPE::ANGLE_E;
    int32_t ret = config.GetOffsetX();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_S;
    ret = config.GetOffsetX();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_W;
    ret = config.GetOffsetX();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_N;
    ret = config.GetOffsetX();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_SE;
    ret = config.GetOffsetX();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_NE;
    ret = config.GetOffsetX();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_SW;
    ret = config.GetOffsetX();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_NW;
    ret = config.GetOffsetX();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_CENTER;
    ret = config.GetOffsetX();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_NW_RIGHT;
    ret = config.GetOffsetX();
    EXPECT_EQ(ret, 256);
}

/**
 * @tc.name: PointerRendererTest_GetOffsetY_001
 * @tc.desc: Test GetOffsetY
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_GetOffsetY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    config.align_ = ICON_TYPE::ANGLE_E;
    int32_t ret = config.GetOffsetY();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_S;
    ret = config.GetOffsetY();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_W;
    ret = config.GetOffsetY();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_N;
    ret = config.GetOffsetY();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_SE;
    ret = config.GetOffsetY();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_NE;
    ret = config.GetOffsetY();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_SW;
    ret = config.GetOffsetY();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_NW;
    ret = config.GetOffsetY();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_CENTER;
    ret = config.GetOffsetY();
    EXPECT_EQ(ret, 256);
    config.align_ = ICON_TYPE::ANGLE_NW_RIGHT;
    ret = config.GetOffsetY();
    EXPECT_EQ(ret, 256);
}

/**
 * @tc.name: PointerRendererTest_UserIconScale_001
 * @tc.desc: Test UserIconScale
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_UserIconScale_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    uint32_t width = 100;
    uint32_t height = 200;
    config.userIconFollowSystem = true;
    PointerRenderer renderer;
    image_ptr_t ret = renderer.UserIconScale(width, height, config);
    EXPECT_EQ(ret, nullptr);
    config.userIconFollowSystem = false;
    ret = renderer.UserIconScale(width, height, config);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: PointerRendererTest_Render_001
 * @tc.desc: Test Render
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_Render_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    uint32_t width = 10;
    uint32_t height = 20;
    uint8_t addr[800] = {10};
    config.style_ = MOUSE_ICON::TRANSPARENT_ICON;
    int32_t ret = renderer.Render(addr, width, height, config);
    EXPECT_EQ(ret, RET_OK);
    config.style_ = MOUSE_ICON::AECH_DEVELOPER_DEFINED_ICON;
    ret = renderer.Render(addr, width, height, config);
    config.direction = 5;
    EXPECT_EQ(ret, RET_ERR);
    config.direction = 0;
    config.style_ = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ret = renderer.Render(addr, width, height, config);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PointerRendererTest_Render_002
 * @tc.desc: Test Render
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_Render_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    uint32_t width = 10;
    uint32_t height = 20;
    uint8_t addr[800] = {10};
    config.style_ = MOUSE_ICON::AECH_DEVELOPER_DEFINED_ICON;

    std::string imagePath = "/system/etc/multimodalinput/mouse_icon/Default.svg";
    OHOS::Media::SourceOptions opts;
    uint32_t ret = 0;
    auto imageSource = OHOS::Media::ImageSource::CreateImageSource(imagePath, opts, ret);
    ASSERT_NE(imageSource, nullptr);
    std::set<std::string> formats;
    ret = imageSource->GetSupportedFormats(formats);
    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {
        .width = 80,
        .height = 80
    };
    decodeOpts.SVGOpts.fillColor = {.isValidColor = false, .color = 0xff00ff};
    decodeOpts.SVGOpts.strokeColor = {.isValidColor = false, .color = 0xff00ff};
    config.userIconPixelMap = imageSource->CreatePixelMap(decodeOpts, ret);
    ASSERT_NE(config.userIconPixelMap, nullptr);
    ret = renderer.Render(addr, width, height, config);
    config.direction = 5;
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: PointerRendererTest_DynamicRender_001
 * @tc.desc: Test DynamicRender
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_DynamicRender_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    uint32_t width = 10;
    uint32_t height = 20;
    uint8_t addr[800] = {10};
    config.style_ = MOUSE_ICON::TRANSPARENT_ICON;
    int32_t ret = renderer.DynamicRender(addr, width, height, config);
    EXPECT_EQ(ret, RET_OK);
    config.style_ = MOUSE_ICON::AECH_DEVELOPER_DEFINED_ICON;
    ret = renderer.DynamicRender(addr, width, height, config);
    config.direction = 5;
    EXPECT_EQ(ret, RET_OK);
    config.direction = 0;
    config.style_ = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ret = renderer.DynamicRender(addr, width, height, config);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: PointerRendererTest_DynamicRender_002
 * @tc.desc: Test DynamicRender
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_DynamicRender_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    uint32_t width = 10;
    uint32_t height = 20;
    uint8_t addr[800] = {10};
    config.style_ = MOUSE_ICON::LOADING;
    int32_t ret = renderer.DynamicRender(addr, width, height, config);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PointerRendererTest_ExtractDrawingImage_001
 * @tc.desc: Test ExtractDrawingImage
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_ExtractDrawingImage_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerRenderer renderer;
    pixelmap_ptr_t pixelMap = std::make_shared<OHOS::Media::PixelMap>();
    ASSERT_NE(pixelMap, nullptr);
    Media::ImageInfo imageInfo;
    imageInfo.size.width = 280;
    imageInfo.size.height = 280;
    imageInfo.pixelFormat = Media::PixelFormat::RGB_565;
    imageInfo.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    imageInfo.colorSpace = Media::ColorSpace::DISPLAY_P3;
    pixelMap->SetImageInfo(imageInfo);
    image_ptr_t ret = renderer.ExtractDrawingImage(pixelMap);
    ASSERT_EQ(ret, nullptr);
    imageInfo.pixelFormat = Media::PixelFormat::RGBA_8888;
    imageInfo.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    imageInfo.colorSpace = Media::ColorSpace::LINEAR_SRGB;
    pixelMap->SetImageInfo(imageInfo);
    ret = renderer.ExtractDrawingImage(pixelMap);
    ASSERT_EQ(ret, nullptr);
    imageInfo.pixelFormat = Media::PixelFormat::BGRA_8888;
    imageInfo.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    imageInfo.colorSpace = Media::ColorSpace::SRGB;
    pixelMap->SetImageInfo(imageInfo);
    ret = renderer.ExtractDrawingImage(pixelMap);
    ASSERT_EQ(ret, nullptr);
    imageInfo.pixelFormat = Media::PixelFormat::ALPHA_8;
    imageInfo.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    imageInfo.colorSpace = Media::ColorSpace::UNKNOWN;
    pixelMap->SetImageInfo(imageInfo);
    ret = renderer.ExtractDrawingImage(pixelMap);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: PointerRendererTest_ExtractDrawingImage_002
 * @tc.desc: Test ExtractDrawingImage
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_ExtractDrawingImage_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerRenderer renderer;
    pixelmap_ptr_t pixelMap = std::make_shared<OHOS::Media::PixelMap>();
    ASSERT_NE(pixelMap, nullptr);
    Media::ImageInfo imageInfo;
    imageInfo.size.width = 280;
    imageInfo.size.height = 280;
    imageInfo.pixelFormat = Media::PixelFormat::RGBA_F16;
    imageInfo.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    imageInfo.colorSpace = Media::ColorSpace::DISPLAY_P3;
    pixelMap->SetImageInfo(imageInfo);
    image_ptr_t ret = renderer.ExtractDrawingImage(pixelMap);
    ASSERT_EQ(ret, nullptr);
    imageInfo.pixelFormat = Media::PixelFormat::UNKNOWN;
    imageInfo.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    imageInfo.colorSpace = Media::ColorSpace::LINEAR_SRGB;
    pixelMap->SetImageInfo(imageInfo);
    ret = renderer.ExtractDrawingImage(pixelMap);
    ASSERT_EQ(ret, nullptr);
    imageInfo.pixelFormat = Media::PixelFormat::ARGB_8888;
    imageInfo.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    imageInfo.colorSpace = Media::ColorSpace::SRGB;
    pixelMap->SetImageInfo(imageInfo);
    ret = renderer.ExtractDrawingImage(pixelMap);
    ASSERT_EQ(ret, nullptr);
    imageInfo.pixelFormat = Media::PixelFormat::RGB_888;
    imageInfo.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    imageInfo.colorSpace = Media::ColorSpace::UNKNOWN;
    pixelMap->SetImageInfo(imageInfo);
    ret = renderer.ExtractDrawingImage(pixelMap);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: PointerRendererTest_ExtractDrawingImage_003
 * @tc.desc: Test ExtractDrawingImage
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_ExtractDrawingImage_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerRenderer renderer;
    pixelmap_ptr_t pixelMap = std::make_shared<OHOS::Media::PixelMap>();
    ASSERT_NE(pixelMap, nullptr);
    Media::ImageInfo imageInfo;
    imageInfo.size.width = 280;
    imageInfo.size.height = 280;
    imageInfo.pixelFormat = Media::PixelFormat::NV21;
    imageInfo.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    imageInfo.colorSpace = Media::ColorSpace::DISPLAY_P3;
    pixelMap->SetImageInfo(imageInfo);
    image_ptr_t ret = renderer.ExtractDrawingImage(pixelMap);
    ASSERT_EQ(ret, nullptr);
    imageInfo.pixelFormat = Media::PixelFormat::NV12;
    imageInfo.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    imageInfo.colorSpace = Media::ColorSpace::LINEAR_SRGB;
    pixelMap->SetImageInfo(imageInfo);
    ret = renderer.ExtractDrawingImage(pixelMap);
    ASSERT_EQ(ret, nullptr);
    imageInfo.pixelFormat = Media::PixelFormat::CMYK;
    imageInfo.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    imageInfo.colorSpace = Media::ColorSpace::SRGB;
    pixelMap->SetImageInfo(imageInfo);
    ret = renderer.ExtractDrawingImage(pixelMap);
    ASSERT_EQ(ret, nullptr);
    imageInfo.pixelFormat = Media::PixelFormat::RGBA_1010102;
    imageInfo.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    imageInfo.colorSpace = Media::ColorSpace::SRGB;
    pixelMap->SetImageInfo(imageInfo);
    ret = renderer.ExtractDrawingImage(pixelMap);
    ASSERT_EQ(ret, nullptr);
}

/**
 * @tc.name: PointerRendererTest_DrawImage_001
 * @tc.desc: Test DrawImage
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_DrawImage_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerRenderer renderer;
    OHOS::Rosen::Drawing::Canvas canvas;
    RenderConfig config;
    config.style_ = MOUSE_ICON::LOADING;
    int32_t ret = renderer.DrawImage(canvas, config);
    EXPECT_EQ(ret, RET_ERR);
    config.style_ = MOUSE_ICON::DEFAULT;
    ret = renderer.DrawImage(canvas, config);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: PointerRendererTest_DrawImage_002
 * @tc.desc: Test DrawImage
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_DrawImage_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerRenderer renderer;
    OHOS::Rosen::Drawing::Canvas canvas;
    RenderConfig config;
    config.style_ = MOUSE_ICON::LOADING;
    config.path_ = "/system/etc/multimodalinput/mouse_icon/Default.svg";
    int32_t ret = renderer.DrawImage(canvas, config);
    EXPECT_EQ(ret, RET_OK);

    config.style_ = MOUSE_ICON::DEFAULT;
    ret = renderer.DrawImage(canvas, config);
    EXPECT_EQ(ret, RET_OK);
}
 
/**
 * @tc.name: PointerRendererTest_LoadCursorSvgWithColor_001
 * @tc.desc: Test LoadCursorSvgWithColor
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_LoadCursorSvgWithColor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    pixelmap_ptr_t ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_EQ(ret, nullptr);
    config.color = 0xFFFFFF;
    ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_EQ(ret, nullptr);
    config.style_ = CURSOR_COPY;
    config.color = 0x000123;
    ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_EQ(ret, nullptr);
    config.color = 0xFFFFFF;
    ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_EQ(ret, nullptr);
    config.style_ = HAND_GRABBING;
    config.color = 0xFFFFFF;
    ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_EQ(ret, nullptr);
    config.style_ = HAND_GRABBING;
    config.color = 0x000123;
    ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: PointerRendererTest_LoadCursorSvgWithColor_002
 * @tc.desc: Test LoadCursorSvgWithColor && ChangeSvgCursorColor
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_LoadCursorSvgWithColor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    config.path_ = "/system/etc/multimodalinput/mouse_icon/Default.svg";
    config.style_ = MOUSE_ICON::CURSOR_COPY;
    config.color = MAX_POINTER_COLOR;
    pixelmap_ptr_t ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_NE(ret, nullptr);

    config.color = MIN_POINTER_COLOR;
    ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name: PointerRendererTest_LoadCursorSvgWithColor_003
 * @tc.desc: Test LoadCursorSvgWithColor && SetCursorColorBaseOnStyle
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_LoadCursorSvgWithColor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    config.path_ = "/system/etc/multimodalinput/mouse_icon/Default.svg";

    config.style_ = MOUSE_ICON::DEFAULT;
    config.color = MIN_POINTER_COLOR;
    pixelmap_ptr_t ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_NE(ret, nullptr);

    config.style_ = MOUSE_ICON::HAND_GRABBING;
    config.color = MIN_POINTER_COLOR;
    ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_NE(ret, nullptr);

    config.style_ = MOUSE_ICON::HAND_OPEN;
    config.color = MAX_POINTER_COLOR;
    ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_NE(ret, nullptr);

    config.style_ = MOUSE_ICON::HAND_POINTING;
    config.color = OTHER_POINTER_COLOR;
    ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_NE(ret, nullptr);

    config.style_ = MOUSE_ICON::HAND_POINTING;
    config.color = MIDDLE_POINTER_COLOR;
    ret = renderer.LoadCursorSvgWithColor(config);
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name: PointerRendererTest_AdjustIncreaseRatio_001
 * @tc.desc: Test AdjustIncreaseRatio
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_AdjustIncreaseRatio_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    float originDpi = 0.0f;
    float ret = config.AdjustIncreaseRatio(originDpi);
    EXPECT_EQ(ret, 1.22f);
    originDpi = 1.9f;
    ret = config.AdjustIncreaseRatio(originDpi);
    EXPECT_EQ(ret, 1.22f);
    originDpi = 2.125f;
    ret = config.AdjustIncreaseRatio(originDpi);
    EXPECT_NE(ret, 1.22f);
}
} // namespace MMI
} // namespace OHOS