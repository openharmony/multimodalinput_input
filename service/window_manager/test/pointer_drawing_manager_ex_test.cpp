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
#include "input_windows_manager_mock.h"
#include "i_preference_manager.h"
#include "knuckle_drawing_manager.h"
#include "libinput_mock.h"
#include "mmi_log.h"
#include "parameters.h"
#include "pixel_map.h"
#include "pointer_drawing_manager.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerDrawingManagerExTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t MOUSE_ICON_SIZE = 64;
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr int32_t INT32_BYTE { 4 };
constexpr int32_t WINDOW_ROTATE { 0 };
constexpr int32_t FOLDABLE_DEVICE { 2 };
const std::string MOUSE_FILE_NAME { "mouse_settings.xml" };
const int32_t ROTATE_POLICY = system::GetIntParameter("const.window.device.rotate_policy", 0);
} // namespace

class PointerDrawingManagerExTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    static std::shared_ptr<Media::PixelMap> CreatePixelMap(int32_t width, int32_t height);
    void SetUp(void)
    {}
    void TearDown(void)
    {}

    std::unique_ptr<OHOS::Media::PixelMap> SetMouseIconTest(const std::string iconPath);
private:
};

std::unique_ptr<OHOS::Media::PixelMap> PointerDrawingManagerExTest::SetMouseIconTest(const std::string iconPath)
{
    CALL_DEBUG_ENTER;
    OHOS::Media::SourceOptions opts;
    opts.formatHint = "image/svg+xml";
    uint32_t ret = 0;
    auto imageSource = OHOS::Media::ImageSource::CreateImageSource(iconPath, opts, ret);
    CHKPP(imageSource);
    std::set<std::string> formats;
    ret = imageSource->GetSupportedFormats(formats);
    MMI_HILOGD("Get supported format ret:%{public}u", ret);

    OHOS::Media::DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {.width = MOUSE_ICON_SIZE, .height = MOUSE_ICON_SIZE};

    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, ret);
    CHKPL(pixelMap);
    return pixelMap;
}

std::shared_ptr<Media::PixelMap> PointerDrawingManagerExTest::CreatePixelMap(int32_t width, int32_t height)
{
    CALL_DEBUG_ENTER;
    if (width <= 0 || width > MAX_PIXEL_MAP_WIDTH || height <= 0 || height > MAX_PIXEL_MAP_HEIGHT) {
        return nullptr;
    }
    Media::InitializationOptions opts;
    opts.size.height = height;
    opts.size.width = width;
    opts.pixelFormat = Media::PixelFormat::BGRA_8888;
    opts.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.scaleMode = Media::ScaleMode::FIT_TARGET_SIZE;

    int32_t colorLen = width * height;
    uint32_t *pixelColors = new (std::nothrow) uint32_t[colorLen];
    CHKPP(pixelColors);
    int32_t colorByteCount = colorLen * INT32_BYTE;
    errno_t ret = memset_s(pixelColors, colorByteCount, DEFAULT_ICON_COLOR, colorByteCount);
    if (ret != EOK) {
        delete[] pixelColors;
        return nullptr;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(pixelColors, colorLen, opts);
    if (pixelMap == nullptr) {
        delete[] pixelColors;
        return nullptr;
    }
    delete[] pixelColors;
    return pixelMap;
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerLocation_01
 * @tc.desc: Test SetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetPointerLocation_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t x = 100;
    int32_t y = 100;
    pointerDrawingManager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetPointerLocation(x, y));
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerLocation_02
 * @tc.desc: Test SetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetPointerLocation_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t x = 100;
    int32_t y = 100;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetPointerLocation(x, y));
}

    int32_t windowId = GLOBAL_WINDOW_ID;

/**
 * @tc.name: InputWindowsManagerTest_UpdateDefaultPointerStyle_01
 * @tc.desc: Test UpdateDefaultPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_UpdateDefaultPointerStyle_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = 2;
    EXPECT_TRUE(windowId != GLOBAL_WINDOW_ID);
    PointerStyle pointerStyle;
    bool isUiExtension = true;
    pointerStyle.id = 1;
    int32_t ret1 = pointerDrawingManager.UpdateDefaultPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret1, RET_OK);

    PointerStyle style;
    windowId = -1;
    EXPECT_FALSE(windowId != GLOBAL_WINDOW_ID);
    pointerStyle.id = 2;
    style.id = 3;
    EXPECT_TRUE(pointerStyle.id != style.id);
    int32_t ret2 = pointerDrawingManager.UpdateDefaultPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret2, RET_OK);

    pointerStyle.id = MOUSE_ICON::DEFAULT;
    int32_t ret3 = pointerDrawingManager.UpdateDefaultPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret3, RET_OK);

    pointerStyle.id = 3;
    EXPECT_TRUE(pointerStyle.id == style.id);
    int32_t ret4 = pointerDrawingManager.UpdateDefaultPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret4, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateIconPath_01
 * @tc.desc: Test UpdateIconPath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_UpdateIconPath_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.mouseIcons_[DEFAULT] = {0, "/system/etc/multimodalinput/mouse_icon/default_icon.svg"};
    pointerDrawingManager.mouseIcons_[EAST] = {1, "/system/etc/multimodalinput/mouse_icon/east_icon.png"};
    pointerDrawingManager.mouseIcons_[WEST] = {2, "/system/etc/multimodalinput/mouse_icon/west_icon.png"};
    pointerDrawingManager.mouseIcons_[SOUTH] = {3, "/system/etc/multimodalinput/mouse_icon/south_icon.png"};
    pointerDrawingManager.mouseIcons_[NORTH] = {4, "/system/etc/multimodalinput/mouse_icon/north_icon.png"};

    MOUSE_ICON mouseStyle = EAST;
    std::string iconPath = ("/system/etc/multimodalinput/mouse_icon/Loading_Left.svg");
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateIconPath(mouseStyle, iconPath));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateIconPath_02
 * @tc.desc: Test UpdateIconPath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_UpdateIconPath_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.mouseIcons_[DEFAULT] = {0, "/system/etc/multimodalinput/mouse_icon/default_icon.svg"};
    pointerDrawingManager.mouseIcons_[EAST] = {1, "/system/etc/multimodalinput/mouse_icon/east_icon.png"};
    pointerDrawingManager.mouseIcons_[WEST] = {2, "/system/etc/multimodalinput/mouse_icon/west_icon.png"};
    pointerDrawingManager.mouseIcons_[SOUTH] = {3, "/system/etc/multimodalinput/mouse_icon/south_icon.png"};
    pointerDrawingManager.mouseIcons_[NORTH] = {4, "/system/etc/multimodalinput/mouse_icon/north_icon.png"};

    MOUSE_ICON mouseStyle = WEST_EAST;
    std::string iconPath = ("/system/etc/multimodalinput/mouse_icon/Loading_Left.svg");
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateIconPath(mouseStyle, iconPath));
}

/**
 * @tc.name: InputWindowsManagerTest_CheckPointerStyleParam_01
 * @tc.desc: Test CheckPointerStyleParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_CheckPointerStyleParam_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t windowId = 2;
    PointerStyle pointerStyle;
    pointerStyle.id = -2;
    bool ret1 = pointerDrawingManager.CheckPointerStyleParam(windowId, pointerStyle);
    EXPECT_FALSE(ret1);

    pointerStyle.id = 46;
    bool ret2 = pointerDrawingManager.CheckPointerStyleParam(windowId, pointerStyle);
    EXPECT_FALSE(ret2);

    windowId = -3;
    bool ret3 = pointerDrawingManager.CheckPointerStyleParam(windowId, pointerStyle);
    EXPECT_FALSE(ret3);
}

/**
 * @tc.name: PointerDrawingManagerTest_UpdateStyleOptions_01
 * @tc.desc: Test UpdateStyleOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerTest_UpdateStyleOptions_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    pointerDrawMgr.pid_ = 3;
    PointerStyle curPointerStyle;
    curPointerStyle.options = 1;
    int ret = WIN_MGR->SetPointerStyle(pointerDrawMgr.pid_, GLOBAL_WINDOW_ID, curPointerStyle);
    EXPECT_EQ(ret, RET_OK);
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.UpdateStyleOptions());
}

/**
 * @tc.name: PointerDrawingManagerTest_AdjustMouseFocus_01
 * @tc.desc: Test AdjustMouseFocus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerTest_AdjustMouseFocus_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    Direction direction;
    ICON_TYPE iconType = ANGLE_SW;
    int32_t physicalX = 50;
    int32_t physicalY = 60;

    direction = DIRECTION0;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AdjustMouseFocus(direction, iconType, physicalX, physicalY));
    direction = DIRECTION90;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AdjustMouseFocus(direction, iconType, physicalX, physicalY));
    direction = DIRECTION180;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AdjustMouseFocus(direction, iconType, physicalX, physicalY));
    direction = DIRECTION270;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AdjustMouseFocus(direction, iconType, physicalX, physicalY));
}

/**
 * @tc.name: PointerDrawingManagerExTest_ConvertToColorSpace
 * @tc.desc: Test ConvertToColorSpace
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_ConvertToColorSpace, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Media::ColorSpace colorSpace = Media::ColorSpace::DISPLAY_P3;
    EXPECT_NE(pointerDrawingManager.ConvertToColorSpace(colorSpace), nullptr);
    colorSpace = Media::ColorSpace::LINEAR_SRGB;
    EXPECT_NE(pointerDrawingManager.ConvertToColorSpace(colorSpace), nullptr);
    colorSpace = Media::ColorSpace::SRGB;
    EXPECT_NE(pointerDrawingManager.ConvertToColorSpace(colorSpace), nullptr);
    colorSpace = static_cast<Media::ColorSpace>(5);
    EXPECT_NE(pointerDrawingManager.ConvertToColorSpace(colorSpace), nullptr);
}

/**
 * @tc.name: PointerDrawingManagerExTest_PixelFormatToColorType
 * @tc.desc: Test PixelFormatToColorType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_PixelFormatToColorType, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Media::PixelFormat pixelFmt = Media::PixelFormat::RGB_565;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt),
        Rosen::Drawing::ColorType::COLORTYPE_RGB_565);
    pixelFmt = Media::PixelFormat::RGBA_8888;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt),
        Rosen::Drawing::ColorType::COLORTYPE_RGBA_8888);
    pixelFmt = Media::PixelFormat::BGRA_8888;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt),
        Rosen::Drawing::ColorType::COLORTYPE_BGRA_8888);
    pixelFmt = Media::PixelFormat::ALPHA_8;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt),
        Rosen::Drawing::ColorType::COLORTYPE_ALPHA_8);
    pixelFmt = Media::PixelFormat::RGBA_F16;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt),
        Rosen::Drawing::ColorType::COLORTYPE_RGBA_F16);
    pixelFmt = Media::PixelFormat::UNKNOWN;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt),
        Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::ARGB_8888;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt),
        Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::RGB_888;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt),
        Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::NV21;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt),
        Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::NV12;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt),
        Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::CMYK;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt),
        Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = static_cast<Media::PixelFormat>(100);
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt),
        Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
}

/**
 * @tc.name: PointerDrawingManagerExTest__AlphaTypeToAlphaType
 * @tc.desc: Test AlphaTypeToAlphaType
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_AlphaTypeToAlphaType, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Media::AlphaType alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    EXPECT_EQ(pointerDrawingManager.AlphaTypeToAlphaType(alphaType),
        Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN);
    alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    EXPECT_EQ(pointerDrawingManager.AlphaTypeToAlphaType(alphaType),
        Rosen::Drawing::AlphaType::ALPHATYPE_OPAQUE);
    alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    EXPECT_EQ(pointerDrawingManager.AlphaTypeToAlphaType(alphaType),
        Rosen::Drawing::AlphaType::ALPHATYPE_PREMUL);
    alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    EXPECT_EQ(pointerDrawingManager.AlphaTypeToAlphaType(alphaType),
        Rosen::Drawing::AlphaType::ALPHATYPE_UNPREMUL);
    alphaType = static_cast<Media::AlphaType>(5);
    EXPECT_EQ(pointerDrawingManager.AlphaTypeToAlphaType(alphaType),
        Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN);
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_01
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_DrawPointerStyle_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;

    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    pointerStyle.color = 1;
    pointerStyle.size = 2;

    int32_t ROTATE_POLICY;
    ROTATE_POLICY = WINDOW_ROTATE;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_02
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_DrawPointerStyle_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;

    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    pointerStyle.color = 1;
    pointerStyle.size = 2;

    int32_t ROTATE_POLICY;
    ROTATE_POLICY = FOLDABLE_DEVICE;
    pointerDrawingManager.lastPhysicalX_ = -1;
    pointerDrawingManager.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_03
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_DrawPointerStyle_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;

    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    pointerStyle.color = 1;
    pointerStyle.size = 2;

    int32_t ROTATE_POLICY;
    ROTATE_POLICY = FOLDABLE_DEVICE;
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_04
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_DrawPointerStyle_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;

    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    pointerStyle.color = 1;
    pointerStyle.size = 2;

    int32_t ROTATE_POLICY;
    ROTATE_POLICY = FOLDABLE_DEVICE;
    pointerDrawingManager.lastPhysicalX_ = 2;
    pointerDrawingManager.lastPhysicalY_ = 2;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerStyle_01
 * @tc.desc: Test SetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetPointerStyle_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    bool isUiExtension = false;

    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    pointerStyle.color = 0;
    pointerStyle.size = 2;

    int32_t pid = 1;
    int32_t windowId = -2;
    bool ret = pointerDrawingManager.CheckPointerStyleParam(windowId, pointerStyle);
    EXPECT_FALSE(ret);

    int32_t ret2 = pointerDrawingManager.SetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret2, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerStyle_02
 * @tc.desc: Test SetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetPointerStyle_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    bool isUiExtension = true;

    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    pointerStyle.color = 0;
    pointerStyle.size = 2;

    int32_t pid = 1;
    int32_t windowId = GLOBAL_WINDOW_ID;
    bool ret = pointerDrawingManager.CheckPointerStyleParam(windowId, pointerStyle);
    EXPECT_TRUE(ret);

    int32_t ret2 = pointerDrawingManager.SetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerStylePreference_01
 * @tc.desc: Test SetPointerStylePreference
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetPointerStylePreference_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    pointerStyle.color = 1;
    pointerStyle.size = 2;

    std::string name = "pointerStyle";
    int32_t ret = PREFERENCES_MGR->SetIntValue(name, MOUSE_FILE_NAME, pointerStyle.id);
    EXPECT_EQ(ret, RET_OK);

    int32_t ret2 = pointerDrawingManager.SetPointerStylePreference(pointerStyle);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseHotSpot_01
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetMouseHotSpot_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = -1;
    int32_t windowId = 2;
    int32_t hotSpotX = 3;
    int32_t hotSpotY = 4;
    int32_t ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseHotSpot_02
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetMouseHotSpot_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = -2;
    int32_t hotSpotX = 3;
    int32_t hotSpotY = 4;
    int32_t ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseHotSpot_03
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetMouseHotSpot_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = 2;
    EXPECT_CALL(*WIN_MGR_MOCK, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_ERR));
    int32_t hotSpotX = 3;
    int32_t hotSpotY = 4;
    int32_t ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseHotSpot_04
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetMouseHotSpot_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = 2;
    EXPECT_CALL(*WIN_MGR_MOCK, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_OK));
    int32_t hotSpotX = -3;
    int32_t hotSpotY = -4;
    pointerDrawingManager.userIcon_ = nullptr;
    int32_t ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseIcon_01
 * @tc.desc: Test SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetMouseIcon_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = -1;
    int32_t windowId = -2;
    void* pixelMap = nullptr;
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, pixelMap);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseIcon_02
 * @tc.desc: Test SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetMouseIcon_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = -2;
    void* pixelMap = nullptr;
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, pixelMap);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseIcon_03
 * @tc.desc: Test SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetMouseIcon_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = 2;
    PointerStyle style;
    int32_t ret1 = pointerDrawingManager.SetPointerStyle(pid, windowId, style);
    EXPECT_EQ(ret1, RET_OK);

    void* pixelMap = nullptr;
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, pixelMap);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection270_01
 * @tc.desc: Test AdjustMouseFocusByDirection270
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_AdjustMouseFocusByDirection270_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    ICON_TYPE iconType = ANGLE_SW;
    int32_t physicalX = 150;
    int32_t physicalY = 200;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection270(iconType, physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection270_02
 * @tc.desc: Test AdjustMouseFocusByDirection270
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_AdjustMouseFocusByDirection270_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    ICON_TYPE iconType = ANGLE_CENTER;
    int32_t physicalX = 100;
    int32_t physicalY = 150;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection270(iconType, physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection270_03
 * @tc.desc: Test AdjustMouseFocusByDirection270
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_AdjustMouseFocusByDirection270_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    ICON_TYPE iconType = ANGLE_NW_RIGHT;
    int32_t physicalX = 50;
    int32_t physicalY = 150;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection270(iconType, physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection270_04
 * @tc.desc: Test AdjustMouseFocusByDirection270
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_AdjustMouseFocusByDirection270_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    ICON_TYPE iconType = ANGLE_NW;
    int32_t physicalX = 100;
    int32_t physicalY = 50;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection270(iconType, physicalX, physicalY));
}
} // namespace MMI
} // namespace OHOS