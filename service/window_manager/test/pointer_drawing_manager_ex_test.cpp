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

#include "event_log_helper.h"
#include "image_source.h"
#include "input_device_manager.h"
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
using namespace testing;
using namespace testing::ext;
constexpr int32_t MOUSE_ICON_SIZE = 64;
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
constexpr int32_t MIDDLE_PIXEL_MAP_WIDTH { 400 };
constexpr int32_t MIDDLE_PIXEL_MAP_HEIGHT { 400 };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr int32_t INT32_BYTE { 4 };
constexpr int32_t WINDOW_ROTATE { 0 };
constexpr int32_t FOLDABLE_DEVICE { 2 };
const std::string POINTER_COLOR { "pointerColor" };
const std::string POINTER_SIZE { "pointerSize" };
constexpr uint32_t RGB_CHANNEL_BITS_LENGTH { 24 };
constexpr float MAX_ALPHA_VALUE { 255.f };
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
 * @tc.name: InputWindowsManagerTest_SwitchPointerStyle_01
 * @tc.desc: Test SwitchPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SwitchPointerStyle_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t size = pointerDrawingManager.GetPointerSize();
    size = -1;
    int32_t ret = pointerDrawingManager.SwitchPointerStyle();
    EXPECT_EQ(ret, RET_ERR);
    size = 8;
    int32_t ret2 = pointerDrawingManager.SwitchPointerStyle();
    EXPECT_EQ(ret2, RET_ERR);

    size = 5;
    EXPECT_FALSE(pointerDrawingManager.HasMagicCursor());
    int32_t ret3 = pointerDrawingManager.SwitchPointerStyle();
    EXPECT_EQ(ret3, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateMouseStyle_01
 * @tc.desc: Test UpdateMouseStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_UpdateMouseStyle_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle curPointerStyle;
    curPointerStyle.id = 41;
    pointerDrawingManager.pid_ = 2;
    int ret = pointerDrawingManager.SetPointerStyle(pointerDrawingManager.pid_, GLOBAL_WINDOW_ID, curPointerStyle);
    EXPECT_EQ(ret, RET_OK);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateMouseStyle());

    curPointerStyle.id = 10;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateMouseStyle());
}

/**
 * @tc.name: InputWindowsManagerTest_DrawMovePointer_01
 * @tc.desc: Test DrawMovePointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_DrawMovePointer_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = 1;
    int32_t physicalX = 100;
    int32_t physicalY = 150;
    PointerDrawingManager pointerDrawingManager;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawMovePointer(displayId, physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawMovePointer_02
 * @tc.desc: Test DestroyPointerWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_DrawMovePointer_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = 2;
    int32_t physicalX = 60;
    int32_t physicalY = 80;
    PointerDrawingManager pointerDrawingManager;
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ == nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawMovePointer(displayId, physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawMovePointer_04
 * @tc.desc: Test DestroyPointerWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_DrawMovePointer_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = 2;
    int32_t physicalX = 60;
    int32_t physicalY = 80;
    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    pointerStyle.color = 0;

    Direction direction;
    direction = DIRECTION90;
    PointerDrawingManager pointerDrawingManager;
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ == nullptr);
    int32_t ret = pointerDrawingManager.DrawMovePointer(displayId, physicalX, physicalY, pointerStyle, direction);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_DestroyPointerWindow_01
 * @tc.desc: Test DestroyPointerWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_DestroyPointerWindow_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DestroyPointerWindow());
}

/**
 * @tc.name: InputWindowsManagerTest_DestroyPointerWindow_02
 * @tc.desc: Test DestroyPointerWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_DestroyPointerWindow_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DestroyPointerWindow());
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerStyle_001
 * @tc.desc: Test SetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    bool isUiExtension = true;
    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    pointerStyle.color = 0;
    pointerStyle.size = 2;

    int32_t pid = 1;
    int32_t windowId = 2;
    bool ret1 = pointerDrawingManager.CheckPointerStyleParam(windowId, pointerStyle);
    EXPECT_TRUE(ret1);
    int32_t ret2 = pointerDrawingManager.UpdateDefaultPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret2, RET_OK);
    int32_t ret3 = WIN_MGR->SetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret3, RET_OK);

    EXPECT_FALSE(INPUT_DEV_MGR->HasPointerDevice());
    EXPECT_FALSE(WIN_MGR->IsMouseSimulate());
    EXPECT_FALSE(WIN_MGR->IsNeedRefreshLayer(windowId));
    int32_t ret4 = pointerDrawingManager.SetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret4, RET_OK);
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
    int32_t displayId = 0;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetPointerLocation(x, y, displayId));
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
    int32_t displayId = 0;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetPointerLocation(x, y, displayId));
}

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
    EXPECT_TRUE(ret2);

    windowId = -3;
    bool ret3 = pointerDrawingManager.CheckPointerStyleParam(windowId, pointerStyle);
    EXPECT_FALSE(ret3);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateStyleOptions_01
 * @tc.desc: Test UpdateStyleOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_UpdateStyleOptions_01, TestSize.Level1)
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
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocus_01
 * @tc.desc: Test AdjustMouseFocus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_AdjustMouseFocus_01, TestSize.Level1)
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
 * @tc.name: InputWindowsManagerTest_SetMouseHotSpot_05
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetMouseHotSpot_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = 2;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    EXPECT_CALL(*winmgrmock, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_OK));

    int32_t hotSpotX = -3;
    int32_t hotSpotY = -4;
    int32_t ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseHotSpot_06
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetMouseHotSpot_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = 2;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    EXPECT_CALL(*winmgrmock, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_OK));
    int32_t hotSpotX = 3;
    int32_t hotSpotY = 4;
    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    pointerStyle.size = 2;
    EXPECT_TRUE(pointerStyle.id != MOUSE_ICON::DEVELOPER_DEFINED_ICON);
    int32_t ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
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

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection180
 * @tc.desc: Test AdjustMouseFocusByDirection180
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_AdjustMouseFocusByDirection180, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t physicalX = 100;
    int32_t physicalY = 50;
    ICON_TYPE iconType = ANGLE_SW;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection180(iconType, physicalX, physicalY));

    iconType = ANGLE_CENTER;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection180(iconType, physicalX, physicalY));

    iconType = ANGLE_NW_RIGHT;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection180(iconType, physicalX, physicalY));

    iconType = ANGLE_NW;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection180(iconType, physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection90
 * @tc.desc: Test AdjustMouseFocusByDirection90
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_AdjustMouseFocusByDirection90, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t physicalX = 100;
    int32_t physicalY = 150;
    ICON_TYPE iconType = ANGLE_SW;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection90(iconType, physicalX, physicalY));

    iconType = ANGLE_CENTER;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection90(iconType, physicalX, physicalY));

    iconType = ANGLE_NW_RIGHT;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection90(iconType, physicalX, physicalY));

    iconType = ANGLE_NW;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection90(iconType, physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection0
 * @tc.desc: Test AdjustMouseFocusByDirection0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_AdjustMouseFocusByDirection0, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t physicalX = 150;
    int32_t physicalY = 200;
    ICON_TYPE iconType = ANGLE_SW;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection0(iconType, physicalX, physicalY));

    iconType = ANGLE_CENTER;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection0(iconType, physicalX, physicalY));

    iconType = ANGLE_NW_RIGHT;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection0(iconType, physicalX, physicalY));

    iconType = ANGLE_NW;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection0(iconType, physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPixelmap_001
 * @tc.desc: Test DrawPixelmap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_DrawPixelmap_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    OHOS::Rosen::Drawing::Canvas canvas;
    MOUSE_ICON mouseStyle = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPixelmap(canvas, mouseStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPixelmap_002
 * @tc.desc: Test DrawPixelmap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_DrawPixelmap_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    OHOS::Rosen::Drawing::Canvas canvas;
    MOUSE_ICON mouseStyle = MOUSE_ICON::RUNNING;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPixelmap(canvas, mouseStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPixelmap_003
 * @tc.desc: Test DrawPixelmap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_DrawPixelmap_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    OHOS::Rosen::Drawing::Canvas canvas;
    MOUSE_ICON mouseStyle = MOUSE_ICON::WEST_EAST;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPixelmap(canvas, mouseStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_SetCustomCursor_001
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetCustomCursor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    int32_t pid = -1;
    int32_t windowId = 1;
    int32_t focusX = 2;
    int32_t focusY = 3;
    int32_t ret = pointerDrawingManager.SetCustomCursor((void *)pixelMap.get(), pid, windowId, focusX, focusY);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetCustomCursor_002
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetCustomCursor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    int32_t pid = 1;
    int32_t windowId = 1;
    int32_t focusX = 2;
    int32_t focusY = 3;
    int32_t ret = pointerDrawingManager.SetCustomCursor((void *)pixelMap.get(), pid, windowId, focusX, focusY);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerColor_01
 * @tc.desc: Test SetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetPointerColor_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    EXPECT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    int32_t color = 0;
    float alphaRatio = (static_cast<uint32_t>(color) >> RGB_CHANNEL_BITS_LENGTH) / MAX_ALPHA_VALUE;
    EXPECT_FALSE(alphaRatio > 1);
    int32_t ret = pointerDrawingManager.SetPointerColor(color);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerColor_02
 * @tc.desc: Test SetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetPointerColor_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.surfaceNode_ = nullptr;
    std::string name = POINTER_COLOR;
    int32_t color = 0;
    int32_t ret = PREFERENCES_MGR->SetIntValue(name, MOUSE_FILE_NAME, color);
    EXPECT_EQ(ret, RET_OK);
    int32_t ret2 = pointerDrawingManager.SetPointerColor(color);
    EXPECT_EQ(ret2, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerSize_01
 * @tc.desc: Test SetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetPointerSize_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t size = 0;
    EXPECT_EQ(pointerDrawingManager.SetPointerSize(size), RET_OK);
    size = 9;
    EXPECT_EQ(pointerDrawingManager.SetPointerSize(size), RET_OK);

    size = 3;
    std::string name = POINTER_SIZE;
    int32_t ret = PREFERENCES_MGR->SetIntValue(name, MOUSE_FILE_NAME, size);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(pointerDrawingManager.SetPointerSize(size), RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerSize_02
 * @tc.desc: Test SetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetPointerSize_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t size = 5;
    std::string name = POINTER_SIZE;
    int32_t ret = PREFERENCES_MGR->SetIntValue(name, MOUSE_FILE_NAME, size);
    EXPECT_EQ(ret, RET_OK);
    pointerDrawingManager.surfaceNode_ = nullptr;
    EXPECT_EQ(pointerDrawingManager.SetPointerSize(size), RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerSize_03
 * @tc.desc: Test SetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_SetPointerSize_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t size = 5;
    std::string name = POINTER_SIZE;
    int32_t ret = PREFERENCES_MGR->SetIntValue(name, MOUSE_FILE_NAME, size);
    EXPECT_EQ(ret, RET_OK);

    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    EXPECT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    EXPECT_EQ(pointerDrawingManager.SetPointerSize(size), RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerDevice_01
 * @tc.desc: Test UpdatePointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_UpdatePointerDevice_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager manager;
    bool hasPointerDevice = true;
    bool isPointerVisible = true;
    bool isHotPlug = false;
    ASSERT_NO_FATAL_FAILURE(manager.UpdatePointerDevice(hasPointerDevice, isPointerVisible, isHotPlug));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerDevice_02
 * @tc.desc: Test UpdatePointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_UpdatePointerDevice_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager manager;
    bool hasPointerDevice = true;
    bool isPointerVisible = true;
    bool isHotPlug = true;
    ASSERT_NO_FATAL_FAILURE(manager.UpdatePointerDevice(hasPointerDevice, isPointerVisible, isHotPlug));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerDevice_03
 * @tc.desc: Test UpdatePointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_UpdatePointerDevice_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager manager;
    bool hasPointerDevice = false;
    bool isPointerVisible = false;
    bool isHotPlug = true;

    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    manager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    EXPECT_TRUE(manager.surfaceNode_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(manager.UpdatePointerDevice(hasPointerDevice, isPointerVisible, isHotPlug));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerDevice_04
 * @tc.desc: Test UpdatePointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, InputWindowsManagerTest_UpdatePointerDevice_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager manager;
    bool hasPointerDevice = false;
    bool isPointerVisible = false;
    bool isHotPlug = true;
    manager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(manager.UpdatePointerDevice(hasPointerDevice, isPointerVisible, isHotPlug));
}

/**
 * @tc.name: PointerDrawingManagerExTest_OnDisplayInfo
 * @tc.desc: Test OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_OnDisplayInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    DisplayInfo displayInfo;
    DisplayGroupInfo displayGroupInfo;
    displayInfo.id = 10;
    displayInfo.width = 600;
    displayInfo.height = 600;
    displayGroupInfo.displaysInfo.push_back(displayInfo);
    pointerDrawMgr.displayInfo_.id = 15;
    pointerDrawMgr.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.OnDisplayInfo(displayGroupInfo));

    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(pointerDrawMgr.surfaceNode_, nullptr);
    pointerDrawMgr.displayInfo_.id = 30;
    pointerDrawMgr.screenId_ = 100;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.OnDisplayInfo(displayGroupInfo));
}

/**
 * @tc.name: PointerDrawingManagerExTest_DrawManager
 * @tc.desc: Test DrawManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_DrawManager, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    pointerDrawMgr.hasDisplay_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.DrawManager());
    pointerDrawMgr.hasDisplay_ = true;
    pointerDrawMgr.hasPointerDevice_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.DrawManager());
    pointerDrawMgr.hasPointerDevice_ = true;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(pointerDrawMgr.surfaceNode_, nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.DrawManager());
    pointerDrawMgr.surfaceNode_ = nullptr;
    pointerDrawMgr.displayInfo_.id = 100;
    pointerDrawMgr.displayInfo_.width = 600;
    pointerDrawMgr.displayInfo_.height = 600;
    pointerDrawMgr.displayInfo_.direction = DIRECTION0;
    pointerDrawMgr.lastPhysicalX_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.DrawManager());
    pointerDrawMgr.surfaceNode_ = nullptr;
    pointerDrawMgr.lastPhysicalY_ = 100;
    pointerDrawMgr.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.DrawManager());
    pointerDrawMgr.surfaceNode_ = nullptr;
    pointerDrawMgr.lastPhysicalY_ = 100;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.DrawManager());
}

/**
 * @tc.name: PointerDrawingManagerExTest_DeletePointerVisible
 * @tc.desc: Test DeletePointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_DeletePointerVisible, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    int32_t pid = 100;
    PointerDrawingManager::PidInfo pidInfo;
    pidInfo.pid = 50;
    pointerDrawMgr.pidInfos_.push_back(pidInfo);
    pidInfo.pid = 100;
    pointerDrawMgr.pidInfos_.push_back(pidInfo);
    pidInfo.pid = 300;
    pidInfo.visible = true;
    pointerDrawMgr.hapPidInfos_.push_back(pidInfo);
    pointerDrawMgr.pid_ = 300;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.DeletePointerVisible(pid));
}

/**
 * @tc.name: PointerDrawingManagerExTest_DeletePointerVisible_001
 * @tc.desc: Test DeletePointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_DeletePointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    int32_t pid = 100;
    PointerDrawingManager::PidInfo pidInfo;
    pidInfo.pid = 100;
    pointerDrawMgr.pidInfos_.push_back(pidInfo);
    pidInfo.visible = false;
    pointerDrawMgr.hapPidInfos_.push_back(pidInfo);
    pointerDrawMgr.pid_ = 100;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.DeletePointerVisible(pid));
}

/**
 * @tc.name: PointerDrawingManagerExTest_DeletePointerVisible_002
 * @tc.desc: Test DeletePointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_DeletePointerVisible_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    int32_t pid = 100;
    PointerDrawingManager::PidInfo pidInfo;
    pidInfo.pid = 500;
    pointerDrawMgr.pidInfos_.push_back(pidInfo);
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.DeletePointerVisible(pid));
}

/**
 * @tc.name: PointerDrawingManagerExTest_OnSessionLost
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_OnSessionLost, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    int32_t pid = 100;
    PointerDrawingManager::PidInfo pidInfo;
    pidInfo.pid = 200;
    pointerDrawMgr.hapPidInfos_.push_back(pidInfo);
    pidInfo.pid = 100;
    pointerDrawMgr.hapPidInfos_.push_back(pidInfo);
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.OnSessionLost(pid));
}

/**
 * @tc.name: PointerDrawingManagerExTest_GetIconStyle
 * @tc.desc: Test GetIconStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_GetIconStyle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    MOUSE_ICON mouseStyle = CURSOR_MOVE;
    IconStyle iconStyle;
    pointerDrawMgr.mouseIcons_.insert(std::make_pair(mouseStyle, iconStyle));
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.GetIconStyle(mouseStyle));
    mouseStyle = static_cast<MOUSE_ICON>(100);
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.GetIconStyle(mouseStyle));
}

/**
 * @tc.name: PointerDrawingManagerExTest_SetPointerVisible
 * @tc.desc: Test SetPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_SetPointerVisible, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    int32_t pid = 1;
    bool visible = true;
    int32_t priority = 0;
    bool isHap = true;
    int32_t count = 101;
    PointerDrawingManager::PidInfo pidInfo;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(pointerDrawMgr.surfaceNode_, nullptr);
    for (int32_t i = 0; i < count; ++i) {
        pidInfo.pid = i;
        pointerDrawMgr.hapPidInfos_.push_back(pidInfo);
    }
    ASSERT_EQ(pointerDrawMgr.SetPointerVisible(pid, visible, priority, isHap), RET_OK);
    pid = 5;
    pointerDrawMgr.hapPidInfos_.pop_front();
    ASSERT_EQ(pointerDrawMgr.SetPointerVisible(pid, visible, priority, isHap), RET_OK);
}

/**
 * @tc.name: PointerDrawingManagerExTest_SetPointerVisible_001
 * @tc.desc: Test SetPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_SetPointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    int32_t pid = 0;
    bool visible = true;
    int32_t priority = 50;
    bool isHap = false;
    int32_t count = 105;
    PointerDrawingManager::PidInfo pidInfo;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(pointerDrawMgr.surfaceNode_, nullptr);
    for (int32_t i = 0; i < count; ++i) {
        pidInfo.pid = i;
        pointerDrawMgr.pidInfos_.push_back(pidInfo);
    }
    ASSERT_EQ(pointerDrawMgr.SetPointerVisible(pid, visible, priority, isHap), RET_OK);
}

/**
 * @tc.name: PointerDrawingManagerExTest_SetCustomCursor
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_SetCustomCursor, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    EXPECT_CALL(*winmgrmock, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_ERR));
    PointerDrawingManager pointerDrawMgr;
    std::shared_ptr<Media::PixelMap> pixelMapPtr = CreatePixelMap(MIDDLE_PIXEL_MAP_WIDTH, MIDDLE_PIXEL_MAP_HEIGHT);
    int32_t pid = 50;
    int32_t windowId = 100;
    int32_t focusX = 300;
    int32_t focusY = 300;
    EXPECT_EQ(pointerDrawMgr.SetCustomCursor((void *)pixelMapPtr.get(), pid, windowId, focusX, focusY), RET_ERR);
    testing::Mock::AllowLeak(winmgrmock.get());
}

/**
 * @tc.name: PointerDrawingManagerExTest_SetMouseIcon
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_SetMouseIcon, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    std::shared_ptr<Media::PixelMap> pixelMapPtr = CreatePixelMap(MIDDLE_PIXEL_MAP_WIDTH, MIDDLE_PIXEL_MAP_HEIGHT);
    int32_t pid = 50;
    int32_t windowId = -1;
    EXPECT_EQ(pointerDrawMgr.SetMouseIcon(pid, windowId, (void *)pixelMapPtr.get()), RET_ERR);
}

/**
 * @tc.name: PointerDrawingManagerExTest_SetMouseHotSpot
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_SetMouseHotSpot, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    EXPECT_CALL(*winmgrmock, CheckWindowIdPermissionByPid).WillRepeatedly(Return(RET_OK));
    PointerDrawingManager pointerDrawMgr;
    int32_t pid = 10;
    int32_t windowId = 100;
    int32_t hotSpotX = -1;
    int32_t hotSpotY = 100;
    EXPECT_EQ(pointerDrawMgr.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY), RET_ERR);
}

/**
 * @tc.name: PointerDrawingManagerExTest_SetMouseHotSpot_001
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_SetMouseHotSpot_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    EXPECT_CALL(*winmgrmock, CheckWindowIdPermissionByPid).WillRepeatedly(Return(RET_OK));
    PointerDrawingManager pointerDrawMgr;
    int32_t pid = 10;
    int32_t windowId = 100;
    int32_t hotSpotX = 100;
    int32_t hotSpotY = -1;
    EXPECT_EQ(pointerDrawMgr.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY), RET_ERR);
}

/**
 * @tc.name: PointerDrawingManagerExTest_SetMouseHotSpot_002
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_SetMouseHotSpot_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    EXPECT_CALL(*winmgrmock, CheckWindowIdPermissionByPid).WillRepeatedly(Return(RET_OK));
    PointerDrawingManager pointerDrawMgr;
    int32_t pid = 10;
    int32_t windowId = 100;
    int32_t hotSpotX = 100;
    int32_t hotSpotY = 100;
    pointerDrawMgr.userIcon_ = nullptr;
    EXPECT_EQ(pointerDrawMgr.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY), RET_ERR);
}

/**
 * @tc.name: PointerDrawingManagerExTest_SetMouseHotSpot_003
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_SetMouseHotSpot_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerStyle pointerStyle;
    pointerStyle.id = MOUSE_ICON::DEFAULT;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    EXPECT_CALL(*winmgrmock, CheckWindowIdPermissionByPid).WillRepeatedly(Return(RET_OK));
    PointerDrawingManager pointerDrawMgr;
    int32_t pid = 10;
    int32_t windowId = 100;
    int32_t hotSpotX = 100;
    int32_t hotSpotY = 100;
    pointerDrawMgr.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    EXPECT_EQ(pointerDrawMgr.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY), RET_ERR);
}

/**
 * @tc.name: PointerDrawingManagerExTest_AttachToDisplay_001
 * @tc.desc: Test the funcation AttachToDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_AttachToDisplay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*WIN_MGR_MOCK, GetDisplayMode).WillRepeatedly(testing::Return(DisplayMode::MAIN));
    PointerDrawingManager pointerDrawMgr;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    EXPECT_TRUE(pointerDrawMgr.surfaceNode_ != nullptr);
    pointerDrawMgr.screenId_ = 0;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AttachToDisplay());
    pointerDrawMgr.screenId_ = 10;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AttachToDisplay());
}

/**
 * @tc.name: PointerDrawingManagerExTest_AttachToDisplay_002
 * @tc.desc: Test the funcation AttachToDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_AttachToDisplay_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_CALL(*WIN_MGR_MOCK, GetDisplayMode).WillRepeatedly(testing::Return(DisplayMode::SUB));
    PointerDrawingManager pointerDrawMgr;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    EXPECT_TRUE(pointerDrawMgr.surfaceNode_ != nullptr);
    pointerDrawMgr.screenId_ = 5;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AttachToDisplay());
    pointerDrawMgr.screenId_ = 0;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AttachToDisplay());
}

/**
 * @tc.name: PointerDrawingManagerExTest_SkipPointerLayer_001
 * @tc.desc: Test the funcation SkipPointerLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_SkipPointerLayer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    bool isSkip = true;
    pointerDrawMgr.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.SkipPointerLayer(isSkip));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawMgr.surfaceNode_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.SkipPointerLayer(isSkip));
}

/**
 * @tc.name: PointerDrawingManagerExTest_SkipPointerLayer_002
 * @tc.desc: Test the funcation SkipPointerLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_SkipPointerLayer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    bool isSkip = false;
    pointerDrawMgr.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.SkipPointerLayer(isSkip));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "SkipPointerLayer";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawMgr.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawMgr.surfaceNode_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.SkipPointerLayer(isSkip));
}

/**
@tc.name: PointerDrawingManagerExTest_PixelFormatToColorType_001
@tc.desc: Test the funcation PixelFormatToColorType
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_PixelFormatToColorType_001, TestSize.Level1)
{
CALL_TEST_DEBUG;
PointerDrawingManager pointerDrawMgr;
Media::PixelFormat pixelFormat = Media::PixelFormat::RGB_565;
auto value = Rosen::Drawing::ColorType::COLORTYPE_RGB_565;
Rosen::Drawing::ColorType ret = pointerDrawMgr.PixelFormatToColorType(pixelFormat);
EXPECT_EQ(ret, value);
pixelFormat = Media::PixelFormat::RGBA_8888;
value = Rosen::Drawing::ColorType::COLORTYPE_RGBA_8888;
ret = pointerDrawMgr.PixelFormatToColorType(pixelFormat);
EXPECT_EQ(ret, value);
pixelFormat = Media::PixelFormat::BGRA_8888;
value = Rosen::Drawing::ColorType::COLORTYPE_BGRA_8888;
ret = pointerDrawMgr.PixelFormatToColorType(pixelFormat);
EXPECT_EQ(ret, value);
pixelFormat = Media::PixelFormat::ALPHA_8;
value = Rosen::Drawing::ColorType::COLORTYPE_ALPHA_8;
ret = pointerDrawMgr.PixelFormatToColorType(pixelFormat);
EXPECT_EQ(ret, value);
pixelFormat = Media::PixelFormat::RGBA_F16;
value = Rosen::Drawing::ColorType::COLORTYPE_RGBA_F16;
ret = pointerDrawMgr.PixelFormatToColorType(pixelFormat);
EXPECT_EQ(ret, value);
pixelFormat = Media::PixelFormat::UNKNOWN;
value = Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN;
ret = pointerDrawMgr.PixelFormatToColorType(pixelFormat);
EXPECT_EQ(ret, value);
pixelFormat = Media::PixelFormat::ARGB_8888;
ret = pointerDrawMgr.PixelFormatToColorType(pixelFormat);
EXPECT_EQ(ret, value);
pixelFormat = Media::PixelFormat::RGB_888;
ret = pointerDrawMgr.PixelFormatToColorType(pixelFormat);
EXPECT_EQ(ret, value);
pixelFormat = Media::PixelFormat::NV21;
ret = pointerDrawMgr.PixelFormatToColorType(pixelFormat);
EXPECT_EQ(ret, value);
pixelFormat = Media::PixelFormat::NV12;
ret = pointerDrawMgr.PixelFormatToColorType(pixelFormat);
EXPECT_EQ(ret, value);
pixelFormat = Media::PixelFormat::CMYK;
ret = pointerDrawMgr.PixelFormatToColorType(pixelFormat);
EXPECT_EQ(ret, value);
}

/**
@tc.name: PointerDrawingManagerExTest_AlphaTypeToAlphaType_001
@tc.desc: Test the funcation AlphaTypeToAlphaType
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_AlphaTypeToAlphaType_001, TestSize.Level1)
{
CALL_TEST_DEBUG;
PointerDrawingManager pointerDrawMgr;
Media::AlphaType alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
auto value = Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN;
Rosen::Drawing::AlphaType ret = pointerDrawMgr.AlphaTypeToAlphaType(alphaType);
EXPECT_EQ(ret, value);
alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
value = Rosen::Drawing::AlphaType::ALPHATYPE_OPAQUE;
ret = pointerDrawMgr.AlphaTypeToAlphaType(alphaType);
EXPECT_EQ(ret, value);
alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
value = Rosen::Drawing::AlphaType::ALPHATYPE_PREMUL;
ret = pointerDrawMgr.AlphaTypeToAlphaType(alphaType);
EXPECT_EQ(ret, value);
alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
value = Rosen::Drawing::AlphaType::ALPHATYPE_UNPREMUL;
ret = pointerDrawMgr.AlphaTypeToAlphaType(alphaType);
EXPECT_EQ(ret, value);
}

/**
@tc.name: PointerDrawingManagerExTest_ClearWindowPointerStyle_001
@tc.desc: Test the funcation ClearWindowPointerStyle
@tc.type: FUNC
@tc.require:
*/
HWTEST_F(PointerDrawingManagerExTest, PointerDrawingManagerExTest_ClearWindowPointerStyle_001, TestSize.Level1)
{
CALL_TEST_DEBUG;
PointerDrawingManager pointerDrawMgr;
int32_t pid = 2;
int32_t windowId = 1;
ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.ClearWindowPointerStyle(pid, windowId));
}
} // namespace MMI
} // namespace OHOS