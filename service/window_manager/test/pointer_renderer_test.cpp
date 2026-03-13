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

#include "image_source.h"
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
 * @tc.name: PointerRendererTest_Render_003
 * @tc.desc: Test Render
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_Render_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    uint32_t width = 10;
    uint32_t height = 20;
    uint8_t addr[800] = {10};
    config.style_ = MOUSE_ICON::DEFAULT;
    config.isHard = true;
    config.isBlur = true;
    int32_t ret = renderer.Render(addr, width, height, config);
    EXPECT_EQ(ret, RET_OK);
    config.isBlur = false;
    ret = renderer.Render(addr, width, height, config);
    EXPECT_EQ(ret, RET_ERR);
    config.isHard = false;
    ret = renderer.Render(addr, width, height, config);
    EXPECT_EQ(ret, RET_ERR);
    config.isBlur = true;
    ret = renderer.Render(addr, width, height, config);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PointerRendererTest_DefaultRender_001
 * @tc.desc: Test DefaultRender
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_DefaultRender_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    uint32_t width = 10;
    uint32_t height = 20;
    uint8_t addr[800] = {10};
    constexpr uint32_t renderStride = 4;
    uint32_t addrSize = width * height * renderStride;
    config.style_ = MOUSE_ICON::DEFAULT;
    config.isBlur = false;
    int32_t ret = renderer.DefaultRender(addr, addrSize, width, height, config);
    EXPECT_EQ(ret, RET_ERR);
    config.isBlur = true;
    renderer.defaultInit_ = false;
    ret = renderer.DefaultRender(addr, addrSize, width, height, config);
    EXPECT_EQ(renderer.defaultInit_, true);
    EXPECT_EQ(ret, RET_OK);
    renderer.defaultInit_ = true;
    ret = renderer.DefaultRender(addr, addrSize, width, height, config);
    EXPECT_EQ(renderer.defaultInit_, true);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: PointerRendererTest_DefaultRender_002
 * @tc.desc: Test DefaultRender
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_DefaultRender_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    uint32_t width = 10;
    uint32_t height = 20;
    uint8_t addr[800] = {10};
    config.isBlur = true;
    constexpr uint32_t renderStride = 4;
    uint32_t addrSize = width * height * renderStride;
    config.style_ = MOUSE_ICON::TRANSPARENT_ICON;
    int32_t ret = renderer.DefaultRender(addr, addrSize, width, height, config);
    EXPECT_EQ(ret, RET_OK);
    config.style_ = MOUSE_ICON::AECH_DEVELOPER_DEFINED_ICON;
    ret = renderer.DefaultRender(addr, addrSize, width, height, config);
    config.direction = 5;
    EXPECT_EQ(ret, RET_OK);
    config.direction = 0;
    config.style_ = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ret = renderer.DefaultRender(addr, addrSize, width, height, config);
    EXPECT_EQ(ret, RET_OK);
    width = 0;
    height = 0;
    config.direction = 0;
    addrSize = width * height * renderStride;
    config.style_ = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ret = renderer.DefaultRender(addr, addrSize, width, height, config);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PointerRendererTest_DrawDefaultPointer_001
 * @tc.desc: Test DrawDefaultPointer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_DrawDefaultPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    config.screenId = 0;
    renderer.screenImages_ = {
        {0, {nullptr, nullptr, nullptr, nullptr}}
    };
    renderer.DrawDefaultPointer(config);
    EXPECT_EQ(renderer.screenImages_[0][0], nullptr);
    renderer.screenImages_ = {
        {0, {nullptr, nullptr, nullptr}}
    };
    renderer.DrawDefaultPointer(config);
    EXPECT_EQ(renderer.screenImages_[0][0], nullptr);
    image_ptr_t img = std::make_shared<OHOS::Rosen::Drawing::Image>();
    renderer.screenImages_ = {
        {0, {img, nullptr, nullptr, nullptr}}
    };
    renderer.DrawDefaultPointer(config);
    EXPECT_EQ(renderer.screenImages_[0][0], img);
}

/**
 * @tc.name: PointerRendererTest_DrawBlurPointer_001
 * @tc.desc: Test DrawBlurPointer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_DrawBlurPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    uint32_t width = 10;
    uint32_t height = 20;
    RenderConfig lastConfig;
    config.screenId = 0;
    renderer.screenImages_ = {
        {0, {nullptr, nullptr, nullptr, nullptr}}
    };
    renderer.DrawBlurPointer(width, height, lastConfig, config);
    EXPECT_EQ(renderer.screenImages_[0][0], nullptr);
    renderer.screenImages_ = {
        {0, {nullptr, nullptr, nullptr}}
    };
    renderer.DrawBlurPointer(width, height, lastConfig, config);
    EXPECT_EQ(renderer.screenImages_[0][0], nullptr);
    image_ptr_t img = std::make_shared<OHOS::Rosen::Drawing::Image>();
    renderer.screenImages_ = {
        {0, {img, img, img, img}}
    };
    renderer.DrawBlurPointer(width, height, lastConfig, config);
    EXPECT_EQ(renderer.screenImages_[0][0], img);
}

/**
 * @tc.name: PointerRendererTest_HasPointerCfg_001
 * @tc.desc: Test HasPointerCfg
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_HasPointerCfg_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    RenderConfig config1;
    PointerRenderer renderer;
    config.screenId = 0;
    config1.screenId = 1;
    bool ret = renderer.HasPointerCfg(config);
    EXPECT_EQ(ret, false);
    renderer.screenConfigs_ = {
        {0, config}
    };
    ret = renderer.HasPointerCfg(config);
    EXPECT_EQ(ret, true);
    renderer.screenConfigs_ = {
        {1, config1}
    };
    ret = renderer.HasPointerCfg(config);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: PointerRendererTest_SetPointerCfg_001
 * @tc.desc: Test SetPointerCfg
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_SetPointerCfg_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    config.screenId = 0;
    renderer.SetPointerCfg(config);
    EXPECT_EQ(renderer.screenConfigs_[0], config);
}

/**
 * @tc.name: PointerRendererTest_GetPointerCfg_001
 * @tc.desc: Test GetPointerCfg
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_GetPointerCfg_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    RenderConfig defaultConfig;
    PointerRenderer renderer;
    config.isHard = true;
    defaultConfig.isHard = true;
    config.screenId = 1;
    defaultConfig.screenId = 0;
    auto cfg = renderer.GetPointerCfg(defaultConfig);
    EXPECT_EQ(cfg.screenId, defaultConfig.screenId);
    renderer.screenConfigs_ = {
        {0, config}
    };
    auto cfg1 = renderer.GetPointerCfg(defaultConfig);
    EXPECT_EQ(cfg1.screenId, config.screenId);
}

/**
 * @tc.name: PointerRendererTest_GetPointerImage_001
 * @tc.desc: Test GetPointerImage
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_GetPointerImage_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    config.screenId = 0;
    auto img = renderer.GetPointerImage(config);
    EXPECT_EQ(img.size(), 0);
    renderer.screenImages_ = {
        {0, {nullptr}}
    };
    img = renderer.GetPointerImage(config);
    EXPECT_EQ(img.size(), 1);
}

/**
 * @tc.name: PointerRendererTest_LoadDefaultPointerImage_001
 * @tc.desc: Test LoadDefaultPointerImage
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_LoadDefaultPointerImage_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    RenderConfig config;
    PointerRenderer renderer;
    config.screenId = 1;
    renderer.screenImages_ = {
        {0, {nullptr, nullptr, nullptr, nullptr}}
    };
    renderer.LoadDefaultPointerImage(config);
    EXPECT_EQ(renderer.screenImages_[0][0], nullptr);
}

/**
 * @tc.name: PointerRendererTest_ApplyAlpha_001
 * @tc.desc: Test ApplyAlpha
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_ApplyAlpha_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerRenderer renderer;
    uint8_t pixel[4] = {255, 255, 255, 255};
    float pecent = 0.5f;
    renderer.ApplyAlpha(pixel, 4, true, pecent);
    EXPECT_EQ(pixel[3], 255);
    EXPECT_EQ(pixel[0], static_cast<uint8_t>(255 * pecent));
    renderer.ApplyAlpha(pixel, 4, false, pecent);
    EXPECT_EQ(pixel[3], 255);
    uint8_t* pixel1 = nullptr;
    ASSERT_NO_FATAL_FAILURE(renderer.ApplyAlpha(pixel1, 0, false, pecent));
}

/**
 * @tc.name: PointerRendererTest_SetAlpha_001
 * @tc.desc: Test SetAlpha
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_SetAlpha001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerRenderer renderer;
    pixelmap_ptr_t img = nullptr;
    float pecent = 0.5f;
    ASSERT_NO_FATAL_FAILURE(renderer.SetAlpha(img, pecent));
    img = std::make_shared<OHOS::Media::PixelMap>();
    ASSERT_NO_FATAL_FAILURE(renderer.SetAlpha(img, pecent));
}

/**
 * @tc.name: PointerRendererTest_LoadPointerToCache_001
 * @tc.desc: Test LoadPointerToCache
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_LoadPointerToCache_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerRenderer renderer;
    const std::string path = "/system/etc/multimodalinput/mouse_icon/";
    EXPECT_TRUE(renderer.mouseIcons_.empty());
    std::map<MOUSE_ICON, IconStyle> mouseIcons = {};
    renderer.LoadPointerToCache(mouseIcons);
    EXPECT_TRUE(renderer.mouseIcons_.empty());
    mouseIcons = {
        {DEFAULT, {ANGLE_NW, path + "Default.svg"}},
    };
    renderer.LoadPointerToCache(mouseIcons);
    EXPECT_FALSE(renderer.mouseIcons_.empty());
}

/**
 * @tc.name: PointerRendererTest_GetPointerFromCache_001
 * @tc.desc: Test GetPointerFromCache
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerRendererTest, PointerRendererTest_GetPointerFromCache_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerRenderer renderer;
    RenderConfig config;
    std::string svgContent;
    config.style_ = MOUSE_ICON::DEFAULT;
    config.path_ = "/system/etc/multimodalinput/mouse_icon/Default.svg";
    EXPECT_TRUE(renderer.mouseIcons_.empty());
    bool ret = renderer.GetPointerFromCache(config, svgContent);
    EXPECT_EQ(ret, true);
    EXPECT_FALSE(renderer.mouseIcons_.empty());
    ret = renderer.GetPointerFromCache(config, svgContent);
    EXPECT_EQ(ret, true);
    config.path_ = "test";
    config.style_ = MOUSE_ICON::AECH_DEVELOPER_DEFINED_ICON;
    ret = renderer.GetPointerFromCache(config, svgContent);
    EXPECT_EQ(ret, false);
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