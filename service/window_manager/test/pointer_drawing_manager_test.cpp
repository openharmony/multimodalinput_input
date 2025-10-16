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

#include "common_event_data.h"
#include "common_event_subscribe_info.h"
#include "image_source.h"
#include "input_windows_manager_mock.h"
#include "i_preference_manager.h"
#include "knuckle_drawing_manager.h"
#include "libinput_mock.h"
#include "mmi_log.h"
#include "parameters.h"
#include "pixel_map.h"
#define private public
#include "pointer_drawing_manager.h"
#undef private
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerDrawingManagerTest"

namespace OHOS {
namespace MMI {
namespace {
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
constexpr int32_t MIN_POINTER_COLOR { 0x000000 };
const std::string MOUSE_FILE_NAME { "mouse_settings.xml" };
const int32_t ROTATE_POLICY = system::GetIntParameter("const.window.device.rotate_policy", 0);
const std::string IMAGE_POINTER_DEFAULT_PATH = "/system/etc/multimodalinput/mouse_icon/";
const std::string CURSOR_ICON_PATH = IMAGE_POINTER_DEFAULT_PATH + "Cursor_Circle.png";
const std::string CUSTOM_CURSOR_ICON_PATH = IMAGE_POINTER_DEFAULT_PATH + "Custom_Cursor_Circle.svg";
const std::string DEFAULT_ICON_PATH = IMAGE_POINTER_DEFAULT_PATH + "Default.svg";
constexpr int32_t AECH_DEVELOPER_DEFINED_STYLE { 47 };
constexpr int32_t AECH_DEVELOPER_DEFINED { 4 };
std::atomic<bool> g_isRsRestart;
} // namespace

class PointerDrawingManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    static std::shared_ptr<Media::PixelMap> CreatePixelMap(int32_t width, int32_t height);
    void SetUp(void) {}
    void TearDown(void) {}

    std::unique_ptr<OHOS::Media::PixelMap> SetMouseIconTest(const std::string iconPath);

private:
};

std::unique_ptr<OHOS::Media::PixelMap> PointerDrawingManagerTest::SetMouseIconTest(const std::string iconPath)
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

std::shared_ptr<Media::PixelMap> PointerDrawingManagerTest::CreatePixelMap(int32_t width, int32_t height)
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
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_01
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointerStyle_01, TestSize.Level1)
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
 * @tc.desc: Test DrawManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointerStyle_02, TestSize.Level1)
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
 * @tc.desc: Test DrawManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointerStyle_03, TestSize.Level1)
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
 * @tc.desc: Test DrawManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointerStyle_04, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerStyle_01, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerStyle_02, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerStylePreference_01, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseHotSpot_01, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseHotSpot_02, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseHotSpot_03, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseHotSpot_04, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseIcon_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = -1;
    int32_t windowId = -2;
    CursorPixelMap curPixelMap;
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, curPixelMap);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseIcon_02
 * @tc.desc: Test SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseIcon_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = -2;
    CursorPixelMap curPixelMap;
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, curPixelMap);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseIcon_03
 * @tc.desc: Test SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseIcon_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = 2;
    PointerStyle style;
    int32_t ret1 = pointerDrawingManager.SetPointerStyle(pid, windowId, style);
    EXPECT_EQ(ret1, RET_OK);

    CursorPixelMap curPixelMap;
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, curPixelMap);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection270_01
 * @tc.desc: Test AdjustMouseFocusByDirection270
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusByDirection270_01, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusByDirection270_02, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusByDirection270_03, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusByDirection270_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    ICON_TYPE iconType = ANGLE_NW;
    int32_t physicalX = 100;
    int32_t physicalY = 50;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AdjustMouseFocusByDirection270(iconType, physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawMovePointer_001
 * @tc.desc: Test the funcation DrawMovePointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawMovePointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager manager;
    uint64_t displayId = 1;
    int32_t physicalX = 2;
    int32_t physicalY = 3;
    PointerStyle pointerStyle;
    Direction direction = DIRECTION0;
    manager.surfaceNode_ = nullptr;
    int32_t ret = manager.DrawMovePointer(displayId, physicalX, physicalY, pointerStyle, direction);
    EXPECT_EQ(ret, RET_ERR);
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    manager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(manager.surfaceNode_ != nullptr);
    ret = manager.DrawMovePointer(displayId, physicalX, physicalY, pointerStyle, direction);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_DrawCursor_002
 * @tc.desc: Test the funcation DrawCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawCursor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager manager;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    manager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(manager.surfaceNode_ != nullptr);
    MOUSE_ICON mouseStyle = EAST;
    int32_t ret = manager.DrawCursor(mouseStyle);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseHotSpot_003
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseHotSpot_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    int32_t pid = 1;
    int32_t windowId = -2;
    EXPECT_CALL(*winmgrmock, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_OK));
    int32_t hotSpotX = -1;
    int32_t hotSpotY = 2;
    pointerDrawingManager.userIcon_ = nullptr;
    int32_t ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    hotSpotX = 1;
    hotSpotY = -2;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    hotSpotX = 1;
    hotSpotY = 2;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    ASSERT_NE(pointerDrawingManager.userIcon_, nullptr);
    hotSpotX = -1;
    hotSpotY = 2;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    hotSpotX = -1;
    hotSpotY = -2;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    hotSpotX = 1;
    hotSpotY = -2;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    hotSpotX = 3;
    hotSpotY = 4;
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    ASSERT_NE(pointerDrawingManager.userIcon_, nullptr);
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    testing::Mock::AllowLeak(winmgrmock.get());
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerColor_002
 * @tc.desc: Test SetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerColor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager->surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager->surfaceNode_ != nullptr);
    pointerDrawingManager->SetPointerColor(16777216);
    int32_t color = pointerDrawingManager->GetPointerColor();
    EXPECT_EQ(color, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerDevice_002
 * @tc.desc: Test UpdatePointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_UpdatePointerDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    EXPECT_EQ(pointerDrawingManager->pidInfos_.size(), 0);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager->UpdatePointerDevice(true, false, true));
    EXPECT_EQ(pointerDrawingManager->pidInfos_.size(), 1);
    pointerDrawingManager->surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager->UpdatePointerDevice(false, false, true));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager->surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager->surfaceNode_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager->UpdatePointerDevice(false, false, true));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawManager_005
 * @tc.desc: Test DrawManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawManager_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;
    EXPECT_CALL(*winmgrmock, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_ERR));
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    EXPECT_CALL(*winmgrmock, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_OK));
    pointerDrawingManager.lastPhysicalX_ = -1;
    pointerDrawingManager.lastPhysicalY_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.lastPhysicalX_ = -1;
    pointerDrawingManager.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    EXPECT_CALL(*winmgrmock, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_OK));
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    testing::Mock::AllowLeak(winmgrmock.get());
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerVisible_002
 * @tc.desc: Test SetPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerVisible_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    ExtraData data1;
    data1.appended = true;
    EXPECT_CALL(*winmgrmock, GetExtraData).WillRepeatedly(testing::Return(data1));
    int32_t pid = 1;
    bool visible = true;
    int32_t priority = 0;
    int32_t ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority, false);
    ASSERT_EQ(ret, RET_OK);
    visible = false;
    priority = 0;
    ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority, false);
    ASSERT_EQ(ret, RET_OK);
    visible = true;
    priority = 1;
    ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority, false);
    ASSERT_EQ(ret, RET_OK);
    visible = false;
    priority = 1;
    ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority, false);
    ASSERT_EQ(ret, RET_OK);
    ExtraData data2;
    data2.appended = false;
    EXPECT_CALL(*winmgrmock, GetExtraData).WillRepeatedly(testing::Return(data2));
    visible = false;
    priority = 0;
    ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority, false);
    ASSERT_EQ(ret, RET_OK);
    visible = true;
    priority = 1;
    ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority, false);
    ASSERT_EQ(ret, RET_OK);
    visible = false;
    priority = 1;
    ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority, false);
    ASSERT_EQ(ret, RET_OK);
    testing::Mock::AllowLeak(winmgrmock.get());
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerLocation_002
 * @tc.desc: Test SetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerLocation_002, TestSize.Level1)
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
    uint64_t displayId = 0;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetPointerLocation(x, y, displayId));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDefaultPointerStyle_002
 * @tc.desc: Test UpdateDefaultPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_UpdateDefaultPointerStyle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = -1;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    EXPECT_CALL(*winmgrmock, GetPointerStyle).WillRepeatedly(testing::Return(RET_ERR));
    int32_t ret = pointerDrawingManager.UpdateDefaultPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, RET_OK);
    testing::Mock::AllowLeak(winmgrmock.get());
}

/**
 * @tc.name: InputWindowsManagerTest_GetPointerStyle_001
 * @tc.desc: Test GetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_GetPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    int32_t pid = 1;
    int32_t windowId = 2;
    bool isUiExtension = true;
    PointerStyle pointerStyle;
    EXPECT_CALL(*winmgrmock, GetPointerStyle).WillRepeatedly(testing::Return(RET_ERR));
    int32_t ret = pointerDrawingManager->GetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret, RET_OK);
    testing::Mock::AllowLeak(winmgrmock.get());
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_002
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointerStyle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    pointerDrawingManager.hasDisplay_ = false;
    pointerDrawingManager.hasPointerDevice_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.hasDisplay_ = false;
    pointerDrawingManager.hasPointerDevice_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;
    pointerDrawingManager.lastPhysicalX_ = -1;
    pointerDrawingManager.lastPhysicalY_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.lastPhysicalX_ = -1;
    pointerDrawingManager.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_003
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointerStyle_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_004
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointerStyle_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION90;
    pointerDrawingManager.lastPhysicalX_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_006
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointerStyle_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION90;
    pointerDrawingManager.lastPhysicalX_ = 2;
    pointerDrawingManager.lastPhysicalY_ = 2;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_007
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointerStyle_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    pointerDrawingManager.hasDisplay_ = false;
    pointerDrawingManager.hasPointerDevice_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.hasDisplay_ = false;
    pointerDrawingManager.hasPointerDevice_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;
    pointerDrawingManager.lastPhysicalX_ = -1;
    pointerDrawingManager.lastPhysicalY_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.lastPhysicalX_ = -1;
    pointerDrawingManager.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_Init_001
 * @tc.desc: Test Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_Init_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isSucess = IPointerDrawingManager::GetInstance()->Init();
    EXPECT_EQ(isSucess, true);
    IconStyle iconStyle = IPointerDrawingManager::GetInstance()->GetIconStyle(MOUSE_ICON(MOUSE_ICON::DEFAULT));
    EXPECT_EQ(iconStyle.alignmentWay, 7);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseDisplayState_001
 * @tc.desc: Test SetMouseDisplayState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseDisplayState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->SetMouseDisplayState(true);
    bool mouseDisplayState = pointerDrawingManager->GetMouseDisplayState();
    EXPECT_EQ(mouseDisplayState, true);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerDevice_001
 * @tc.desc: Test UpdatePointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_UpdatePointerDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    EXPECT_EQ(pointerDrawingManager->pidInfos_.size(), 0);
    pointerDrawingManager->UpdatePointerDevice(true, true, true);
    EXPECT_EQ(pointerDrawingManager->pidInfos_.size(), 1);
    pointerDrawingManager->UpdatePointerDevice(false, true, true);
    EXPECT_EQ(pointerDrawingManager->pidInfos_.size(), 0);
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection0_001
 * @tc.desc: Test AdjustMouseFocusByDirection0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusByDirection0_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    pointerDrawingManager->userIconHotSpotX_ = 5;
    pointerDrawingManager->userIconHotSpotY_ = 5;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection0(ANGLE_SW, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection0(ANGLE_CENTER, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection0(ANGLE_NW_RIGHT, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager->currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerDrawingManager->AdjustMouseFocusByDirection0(ANGLE_NW, physicalX, physicalY);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection0(ANGLE_E, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection90_001
 * @tc.desc: Test AdjustMouseFocusByDirection90
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusByDirection90_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    pointerDrawingManager->userIconHotSpotX_ = 5;
    pointerDrawingManager->userIconHotSpotY_ = 5;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection90(ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 50);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection90(ANGLE_CENTER, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection90(ANGLE_NW_RIGHT, physicalX, physicalY);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager->currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerDrawingManager->AdjustMouseFocusByDirection90(ANGLE_NW, physicalX, physicalY);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection90(ANGLE_E, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection180_001
 * @tc.desc: Test AdjustMouseFocusByDirection180
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusByDirection180_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    pointerDrawingManager->userIconHotSpotX_ = 5;
    pointerDrawingManager->userIconHotSpotY_ = 5;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection180(ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalY, 150);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection180(ANGLE_CENTER, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection180(ANGLE_NW_RIGHT, physicalX, physicalY);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager->currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerDrawingManager->AdjustMouseFocusByDirection180(ANGLE_NW, physicalX, physicalY);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection180(ANGLE_E, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection270_001
 * @tc.desc: Test AdjustMouseFocusByDirection270
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusByDirection270_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    pointerDrawingManager->userIconHotSpotX_ = 5;
    pointerDrawingManager->userIconHotSpotY_ = 5;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection270(ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 150);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection270(ANGLE_CENTER, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection270(ANGLE_NW_RIGHT, physicalX, physicalY);
    EXPECT_EQ(physicalY, 92);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager->currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerDrawingManager->AdjustMouseFocusByDirection270(ANGLE_NW, physicalX, physicalY);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection270(ANGLE_E, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocus_001
 * @tc.desc: Test AdjustMouseFocus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocus_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION0);
    pointerDrawingManager->AdjustMouseFocus(DIRECTION0, ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalY, 50);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION90);
    pointerDrawingManager->AdjustMouseFocus(DIRECTION90, ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 50);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION180);
    pointerDrawingManager->AdjustMouseFocus(DIRECTION180, ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalY, 150);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION270);
    pointerDrawingManager->AdjustMouseFocus(DIRECTION270, ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 150);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(static_cast<Direction>(4));
    pointerDrawingManager->AdjustMouseFocus(static_cast<Direction>(4), ANGLE_SW, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
}

/**
 * @tc.name: InputWindowsManagerTest_SetCursorLocation_001
 * @tc.desc: Test SetCursorLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetCursorLocation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    auto align = pointerDrawingManager.MouseIcon2IconType(MOUSE_ICON(2));
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager.lastMouseStyle_.id = 2;
    auto visible = pointerDrawingManager.SetCursorLocation(physicalX, physicalY, align);
    EXPECT_EQ(visible, false);
    physicalX = 200;
    physicalY = 200;
    pointerDrawingManager.lastMouseStyle_.id = 4;
    visible = pointerDrawingManager.SetCursorLocation(physicalX, physicalY, align);
    EXPECT_EQ(visible, false);
    physicalX = 300;
    physicalY = 300;
    pointerDrawingManager.lastMouseStyle_.id = 8;
    visible = pointerDrawingManager.SetCursorLocation(physicalX, physicalY, align);
    EXPECT_EQ(visible, false);
    physicalX = 400;
    physicalY = 400;
    pointerDrawingManager.lastMouseStyle_.id = 12;
    visible = pointerDrawingManager.SetCursorLocation(physicalX, physicalY, align);
    EXPECT_EQ(visible, false);
}

/**
 * @tc.name: InputWindowsManagerTest_SetHardwareCursorPosition_001
 * @tc.desc: Test SetHardwareCursorPosition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetHardwareCursorPosition_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager.lastMouseStyle_.id = 2;
    ASSERT_NO_FATAL_FAILURE(
        pointerDrawingManager.SetHardwareCursorPosition(physicalX, physicalY, pointerDrawingManager.lastMouseStyle_));
}

/**
 * @tc.name: InputWindowsManagerOneTest_GetMainScreenDisplayInfo
 * @tc.desc: Test GetMainScreenDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerOneTest_GetMainScreenDisplayInfo, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayGroupInfo displayGroupInfo;
    OLD::DisplayInfo mainScreenDisplayInfo;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager.GetMainScreenDisplayInfo(displayGroupInfo, mainScreenDisplayInfo));
    displayGroupInfo.displaysInfo.push_back(mainScreenDisplayInfo);
    displayGroupInfo.displaysInfo.push_back(mainScreenDisplayInfo);
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager.GetMainScreenDisplayInfo(displayGroupInfo, mainScreenDisplayInfo));
}

/**
 * @tc.name: InputWindowsManagerOneTest_CreatePointerWindowForScreenPointer
 * @tc.desc: Test CreatePointerWindowForScreenPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerOneTest_CreatePointerWindowForScreenPointer, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.displayInfo_.rsId = 2;
    int32_t rsId = 2;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager.CreatePointerWindowForScreenPointer(rsId, physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerOneTest_CreatePointerWindow
 * @tc.desc: Test CreatePointerWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerOneTest_CreatePointerWindow, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t rsId = 10;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    EXPECT_NO_FATAL_FAILURE(
        pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION90));
    EXPECT_NO_FATAL_FAILURE(
        pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION180));
    EXPECT_NO_FATAL_FAILURE(
        pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION270));
}

/**
 * @tc.name: InputWindowsManagerTest_IsWindowRotation_001
 * @tc.desc: Test IsWindowRotation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_IsWindowRotation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displayInfo;
    displayInfo.direction = DIRECTION0;
    displayInfo.displayDirection = DIRECTION90;
    auto color = pointerDrawingManager.IsWindowRotation(&displayInfo);
    EXPECT_EQ(color, true);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerColor_001
 * @tc.desc: Test SetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerColor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->SetPointerColor(-1);
    int32_t color = pointerDrawingManager->GetPointerColor();
    EXPECT_EQ(color, 0);
    pointerDrawingManager->SetPointerColor(16777216);
    color = pointerDrawingManager->GetPointerColor();
    EXPECT_EQ(color, 0);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerVisible_001
 * @tc.desc: Test SetPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    for (int32_t i = 1; i < 102; i++) {
        pointerDrawingManager->SetPointerVisible(i, false, 0, false);
    }
    bool visible = pointerDrawingManager->GetPointerVisible(1);
    EXPECT_EQ(visible, true);
    pointerDrawingManager->SetPointerVisible(11, true, 0, false);
    visible = pointerDrawingManager->GetPointerVisible(11);
    EXPECT_EQ(visible, true);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerStyle_001
 * @tc.desc: Test SetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerDrawingManager->SetPointerStyle(1, -1, pointerStyle);
    PointerStyle pointerStyleTmp;
    pointerDrawingManager->GetPointerStyle(1, -1, pointerStyleTmp);
    EXPECT_EQ(pointerStyleTmp.id, pointerStyle.id);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerSize_001
 * @tc.desc: Test SetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerSize_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->SetPointerSize(0);
    int32_t pointerSize = pointerDrawingManager->GetPointerSize();
    EXPECT_EQ(pointerSize, 0);
    pointerDrawingManager->SetPointerSize(8);
    pointerSize = pointerDrawingManager->GetPointerSize();
    EXPECT_EQ(pointerSize, 0);
}

/**
 * @tc.name: InputWindowsManagerTest_FixCursorPosition_001
 * @tc.desc: Test FixCursorPosition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_FixCursorPosition_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager->displayInfo_.direction = DIRECTION0;
    pointerDrawingManager->displayInfo_.width = 500;
    pointerDrawingManager->displayInfo_.height = 1100;
    pointerDrawingManager->imageWidth_ = 48;
    pointerDrawingManager->imageHeight_ = 48;
    int32_t physicalX = 500;
    int32_t physicalY = 1100;
    pointerDrawingManager->FixCursorPosition(physicalX, physicalY);
    EXPECT_NE(physicalX, 497);
    EXPECT_NE(physicalY, 1097);
    pointerDrawingManager->displayInfo_.direction = DIRECTION90;
    physicalX = 1100;
    physicalY = 500;
    pointerDrawingManager->FixCursorPosition(physicalX, physicalY);
    EXPECT_NE(physicalX, 1097);
    pointerDrawingManager->displayInfo_.displayDirection = DIRECTION90;
    pointerDrawingManager->displayInfo_.direction = DIRECTION0;
    physicalX = 500;
    physicalY = 1100;
    pointerDrawingManager->FixCursorPosition(physicalX, physicalY);
    EXPECT_NE(physicalY, 497);
}

/**
 * @tc.name: InputWindowsManagerTest_CreatePointerSwitchObserver_001
 * @tc.desc: Test CreatePointerSwitchObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_CreatePointerSwitchObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    isMagicCursor item;
    item.isShow = true;
    item.name = "test";
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.CreatePointerSwitchObserver(item));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawCursor_001
 * @tc.desc: Test DrawCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawCursor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    MOUSE_ICON mouseStyle = EAST;
    int32_t ret = pointerDrawingManager.DrawCursor(mouseStyle);
    EXPECT_EQ(ret, RET_ERR);
    pointerDrawingManager.surfaceNode_ = nullptr;
    ret = pointerDrawingManager.DrawCursor(mouseStyle);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_DrawLoadingPointerStyle_001
 * @tc.desc: Test DrawLoadingPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawLoadingPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    MOUSE_ICON mouseStyle = EAST;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawLoadingPointerStyle(mouseStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawRunningPointerAnimate_001
 * @tc.desc: Test DrawRunningPointerAnimate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawRunningPointerAnimate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.surfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    pointerDrawingManager.surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    MOUSE_ICON mouseStyle = EAST;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawRunningPointerAnimate(mouseStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_GetLayer_001
 * @tc.desc: Test GetLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_GetLayer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.GetLayer());
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseIcon_001
 * @tc.desc: Test SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseIcon_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = -1;
    int32_t windowId = 1;
    CursorPixelMap curPixelMap;
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, curPixelMap);
    EXPECT_EQ(ret, RET_ERR);
    pid = 1;
    ret = pointerDrawingManager.SetMouseIcon(pid, windowId, curPixelMap);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseHotSpot_001
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseHotSpot_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = -1;
    int32_t windowId = 1;
    int32_t hotSpotX = 100;
    int32_t hotSpotY = 100;
    int32_t ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
    pid = 1;
    windowId = -1;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
    pid = 1;
    windowId = 1;
    hotSpotX = -1;
    hotSpotY = -1;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
    pid = 1;
    windowId = 1;
    hotSpotX = 100;
    hotSpotY = 100;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_DecodeImageToPixelMap_001
 * @tc.desc: Test DecodeImageToPixelMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DecodeImageToPixelMap_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    std::string iconPath = ("/system/etc/multimodalinput/mouse_icon/Loading_Left.svg");
    pointerDrawingManager.tempPointerColor_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DecodeImageToPixelMap(MOUSE_ICON::RUNNING));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerVisible_001
 * @tc.desc: Test UpdatePointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_UpdatePointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.mouseDisplayState_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdatePointerVisible());
    pointerDrawingManager.mouseDisplayState_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdatePointerVisible());
}

/**
 * @tc.name: InputWindowsManagerTest_IsPointerVisible_001
 * @tc.desc: Test IsPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_IsPointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    bool ret = pointerDrawingManager.IsPointerVisible();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_DeletePointerVisible_001
 * @tc.desc: Test DeletePointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DeletePointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    PointerDrawingManager::PidInfo info = {.pid = 1, .visible = true};
    pointerDrawingManager.pidInfos_.push_back(info);
    info = {.pid = 2, .visible = true};
    pointerDrawingManager.pidInfos_.push_back(info);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DeletePointerVisible(pid));
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerLocation_001
 * @tc.desc: Test SetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerLocation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t x = 100;
    int32_t y = 100;
    uint64_t displayId = 0;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetPointerLocation(x, y, displayId));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDefaultPointerStyle_001
 * @tc.desc: Test UpdateDefaultPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_UpdateDefaultPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = 1;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    int32_t ret = pointerDrawingManager.UpdateDefaultPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, RET_OK);
    windowId = -1;
    ret = pointerDrawingManager.UpdateDefaultPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateIconPath_001
 * @tc.desc: Test UpdateIconPath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_UpdateIconPath_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    MOUSE_ICON mouseStyle = EAST;
    std::string iconPath = "test";
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateIconPath(mouseStyle, iconPath));
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerStylePreference_001
 * @tc.desc: Test SetPointerStylePreference
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerStylePreference_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    int32_t ret = pointerDrawingManager.SetPointerStylePreference(pointerStyle);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_CheckPointerStyleParam_001
 * @tc.desc: Test CheckPointerStyleParam
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_CheckPointerStyleParam_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = EAST;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    int32_t windowId = -2;
    bool ret = pointerDrawingManager.CheckPointerStyleParam(windowId, pointerStyle);
    EXPECT_FALSE(ret);
    windowId = 1;
    ret = pointerDrawingManager.CheckPointerStyleParam(windowId, pointerStyle);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_CheckMouseIconPath_001
 * @tc.desc: Test CheckMouseIconPath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_CheckMouseIconPath_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.CheckMouseIconPath());
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPixelmap_001
 * @tc.desc: Test DrawPixelmap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPixelmap_001, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPixelmap_002, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPixelmap_003, TestSize.Level1)
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
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetCustomCursor_001, TestSize.Level1)
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
    CursorPixelMap curPixelMap;
    curPixelMap.pixelMap = (void *)pixelMap.get();
    int32_t ret = pointerDrawingManager.SetCustomCursor(curPixelMap, pid, windowId, focusX, focusY);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseIcon_002
 * @tc.desc: Test SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseIcon_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    int32_t pid = -1;
    int32_t windowId = 2;
    CursorPixelMap curPixelMap;
    curPixelMap.pixelMap = (void *)pixelMap.get();
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, curPixelMap);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseIcon_004
 * @tc.desc: Test SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseIcon_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    int32_t pid = 1;
    int32_t windowId = 2;
    CursorPixelMap curPixelMap;
    curPixelMap.pixelMap = (void *)pixelMap.release();
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, curPixelMap);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseIcon_005
 * @tc.desc: Test SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseIcon_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    int32_t pid = 2;
    int32_t windowId = 2;
    CursorPixelMap curPixelMap;
    curPixelMap.pixelMap = (void *)pixelMap.release();
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, curPixelMap);
    ASSERT_EQ(ret, RET_OK);
}


/**
 * @tc.name: InputWindowsManagerTest_SetMouseHotSpot_002
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseHotSpot_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = -1;
    int32_t windowId = 2;
    int32_t hotSpotX = 3;
    int32_t hotSpotY = 4;
    int32_t ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    pid = 1;
    windowId = -2;
    hotSpotX = 3;
    hotSpotY = 4;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    pid = 1;
    windowId = 2;
    hotSpotX = 3;
    hotSpotY = 4;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    pid = 2;
    windowId = 2;
    hotSpotX = -3;
    hotSpotY = -4;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    pid = 2;
    windowId = 2;
    hotSpotX = 3;
    hotSpotY = 4;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_OnDisplayInfo_001
 * @tc.desc: Test OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_OnDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displaysInfo;
    OLD::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.displaysInfo.push_back(displaysInfo);
    displayGroupInfo.focusWindowId = 0;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.surfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    pointerDrawingManager.surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnDisplayInfo(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_OnDisplayInfo_002
 * @tc.desc: Test OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_OnDisplayInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displaysInfo;
    OLD::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.displaysInfo.push_back(displaysInfo);
    displayGroupInfo.focusWindowId = 0;
    pointerDrawingManager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnDisplayInfo(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawManager_004
 * @tc.desc: Test DrawManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawManager_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hasDisplay_ = false;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_005
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointerStyle_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    pointerDrawingManager.hasDisplay_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
}

/**
 * @tc.name: PointerDrawingManagerTest_ConvertToColorSpace
 * @tc.desc: Test ConvertToColorSpace
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_ConvertToColorSpace, TestSize.Level1)
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
 * @tc.name: PointerDrawingManagerTest_PixelFormatToColorType
 * @tc.desc: Test PixelFormatToColorType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_PixelFormatToColorType, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Media::PixelFormat pixelFmt = Media::PixelFormat::RGB_565;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_RGB_565);
    pixelFmt = Media::PixelFormat::RGBA_8888;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_RGBA_8888);
    pixelFmt = Media::PixelFormat::BGRA_8888;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_BGRA_8888);
    pixelFmt = Media::PixelFormat::ALPHA_8;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_ALPHA_8);
    pixelFmt = Media::PixelFormat::RGBA_F16;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_RGBA_F16);
    pixelFmt = Media::PixelFormat::UNKNOWN;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::ARGB_8888;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::RGB_888;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::NV21;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::NV12;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = Media::PixelFormat::CMYK;
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
    pixelFmt = static_cast<Media::PixelFormat>(100);
    EXPECT_EQ(pointerDrawingManager.PixelFormatToColorType(pixelFmt), Rosen::Drawing::ColorType::COLORTYPE_UNKNOWN);
}

/**
 * @tc.name: PointerDrawingManagerTest__AlphaTypeToAlphaType
 * @tc.desc: Test AlphaTypeToAlphaType
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_AlphaTypeToAlphaType, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Media::AlphaType alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
    EXPECT_EQ(pointerDrawingManager.AlphaTypeToAlphaType(alphaType), Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN);
    alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    EXPECT_EQ(pointerDrawingManager.AlphaTypeToAlphaType(alphaType), Rosen::Drawing::AlphaType::ALPHATYPE_OPAQUE);
    alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    EXPECT_EQ(pointerDrawingManager.AlphaTypeToAlphaType(alphaType), Rosen::Drawing::AlphaType::ALPHATYPE_PREMUL);
    alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    EXPECT_EQ(pointerDrawingManager.AlphaTypeToAlphaType(alphaType), Rosen::Drawing::AlphaType::ALPHATYPE_UNPREMUL);
    alphaType = static_cast<Media::AlphaType>(5);
    EXPECT_EQ(pointerDrawingManager.AlphaTypeToAlphaType(alphaType), Rosen::Drawing::AlphaType::ALPHATYPE_UNKNOWN);
}

/**
 * @tc.name: PointerDrawingManagerTest_ExtractDrawingImage_001
 * @tc.desc: Test ExtractDrawingImage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_ExtractDrawingImage_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format {
        OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888, OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE};
    PointerDrawingManager pointerDrawingManager;
    bitmap.Build(64, 64, format);
    OHOS::Rosen::Drawing::Canvas canvas(256, 256);
    canvas.Bind(bitmap);
    canvas.Clear(OHOS::Rosen::Drawing::Color::COLOR_TRANSPARENT);
    MOUSE_ICON mouseStyle = MOUSE_ICON::RUNNING_LEFT;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawImage(canvas, mouseStyle));
}

/**
 * @tc.name: PointerDrawingManagerTest_ExtractDrawingImage_002
 * @tc.desc: Test ExtractDrawingImage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_ExtractDrawingImage_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format {
        OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888, OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE};
    PointerDrawingManager pointerDrawingManager;
    bitmap.Build(64, 64, format);
    OHOS::Rosen::Drawing::Canvas canvas(256, 256);
    canvas.Bind(bitmap);
    canvas.Clear(OHOS::Rosen::Drawing::Color::COLOR_TRANSPARENT);
    MOUSE_ICON mouseStyle = MOUSE_ICON::RUNNING;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawImage(canvas, mouseStyle));
}

/**
 * @tc.name: PointerDrawingManagerTest_ExtractDrawingImage_003
 * @tc.desc: Test ExtractDrawingImage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_ExtractDrawingImage_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format {
        OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888, OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE};
    PointerDrawingManager pointerDrawingManager;
    bitmap.Build(64, 64, format);
    OHOS::Rosen::Drawing::Canvas canvas(256, 256);
    canvas.Bind(bitmap);
    canvas.Clear(OHOS::Rosen::Drawing::Color::COLOR_TRANSPARENT);
    MOUSE_ICON mouseStyle = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawImage(canvas, mouseStyle));
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetPointerLocation(200, 200, 0));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointer_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerDrawingManager->DrawPointer(1, 100, 100, pointerStyle, DIRECTION180);
    EXPECT_EQ(pointerDrawingManager->lastDirection_, DIRECTION180);
    pointerDrawingManager->DrawPointer(1, 200, 200, pointerStyle, DIRECTION270);
    EXPECT_EQ(pointerDrawingManager->lastDirection_, DIRECTION270);
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_001
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = EAST;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
    pointerDrawingManager.lastPhysicalX_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawPointerStyle(pointerStyle));
}
/**
 * @tc.name: InputWindowsManagerTest_InitPointerCallback_001
 * @tc.desc: Test InitPointerCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_InitPointerCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager->InitPointerCallback());
}

/**
 * @tc.name: InputWindowsManagerTest_InitPointerCallback_002
 * @tc.desc: Test InitPointerCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_InitPointerCallback_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.SetSurfaceNode(nullptr);
    pointerDrawingManager.initEventhandlerFlag_.store(true);
    pointerDrawingManager.InitPointerCallback();
    ASSERT_EQ(pointerDrawingManager.GetSurfaceNode(), nullptr);
}

/**
 * @tc.name: InputWindowsManagerTest_InitPointerCallback_003
 * @tc.desc: Test InitPointerCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_InitPointerCallback_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::CURSOR_NODE;
    std::shared_ptr<Rosen::RSSurfaceNode> surfaceNode =
        Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(surfaceNode, nullptr);
    pointerDrawingManager.SetSurfaceNode(surfaceNode);

    pointerDrawingManager.initEventhandlerFlag_.store(true);
    pointerDrawingManager.InitPointerCallback();
    ASSERT_EQ(pointerDrawingManager.GetSurfaceNode(), nullptr);
}

/**
 * @tc.name: InputWindowsManagerTest_InitPointerObserver_001
 * @tc.desc: Test InitPointerObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_InitPointerObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager->InitPointerObserver());
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
/**
 * @tc.name: InputWindowsManagerTest_SetPixelMap
 * @tc.desc: Test SetPixelMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPixelMap, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager manager;
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = CreatePixelMap(MIDDLE_PIXEL_MAP_WIDTH, MIDDLE_PIXEL_MAP_HEIGHT);
    ASSERT_NO_FATAL_FAILURE(manager.SetPixelMap(pixelMap));
}
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

/**
 * @tc.name: PointerDrawingManagerTest_SwitchPointerStyle
 * @tc.desc: Test SwitchPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_SwitchPointerStyle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    pointerDrawMgr.lastMouseStyle_.id = 2;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.SwitchPointerStyle());
}

/**
 * @tc.name: PointerDrawingManagerTest_CreateMagicCursorChangeObserver
 * @tc.desc: Test CreateMagicCursorChangeObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_CreateMagicCursorChangeObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.CreateMagicCursorChangeObserver());
}

/**
 * @tc.name: PointerDrawingManagerTest_UpdateStyleOptions
 * @tc.desc: Test UpdateStyleOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_UpdateStyleOptions, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    pointerDrawMgr.pid_ = 100;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.UpdateStyleOptions());
}

/**
 * @tc.name: PointerDrawingManagerTest_InitPointerObserver
 * @tc.desc: Test InitPointerObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_InitPointerObserver, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    pointerDrawMgr.hasInitObserver_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.InitPointerObserver());

    pointerDrawMgr.hasInitObserver_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.InitPointerObserver());
}

/**
 * @tc.name: PointerDrawingManagerTest_AdjustMouseFocusByDirection90
 * @tc.desc: Test AdjustMouseFocusByDirection90
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_AdjustMouseFocusByDirection90, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    ICON_TYPE iconType = ANGLE_SW;
    int32_t physicalX = 500;
    int32_t physicalY = 500;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AdjustMouseFocusByDirection90(iconType, physicalX, physicalY));
    iconType = ANGLE_CENTER;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AdjustMouseFocusByDirection90(iconType, physicalX, physicalY));
    iconType = ANGLE_NW_RIGHT;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AdjustMouseFocusByDirection90(iconType, physicalX, physicalY));
    iconType = ANGLE_NW;
    pointerDrawMgr.userIcon_ = CreatePixelMap(MIDDLE_PIXEL_MAP_WIDTH, MIDDLE_PIXEL_MAP_HEIGHT);
    ASSERT_NE(pointerDrawMgr.userIcon_, nullptr);
    pointerDrawMgr.currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AdjustMouseFocusByDirection90(iconType, physicalX, physicalY));
    pointerDrawMgr.userIcon_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.AdjustMouseFocusByDirection90(iconType, physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerDevice_003
 * @tc.desc: Test UpdatePointerDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_UpdatePointerDevice_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    EXPECT_EQ(pointerDrawingManager->pidInfos_.size(), 100);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager->UpdatePointerDevice(true, false, true));
    pointerDrawingManager->UpdatePointerDevice(true, true, true);
    EXPECT_EQ(pointerDrawingManager->pidInfos_.size(), 100);
    pointerDrawingManager->surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager->UpdatePointerDevice(false, false, true));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager->surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager->surfaceNode_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager->UpdatePointerDevice(false, false, true));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawManager_001
 * @tc.desc: Test DrawManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawManager_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hasDisplay_ = false;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = false;
    pointerDrawingManager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.hasDisplay_ = false;
    pointerDrawingManager.hasPointerDevice_ = false;
    pointerDrawingManager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.hasDisplay_ = false;
    pointerDrawingManager.hasPointerDevice_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.hasDisplay_ = false;
    pointerDrawingManager.hasPointerDevice_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;
    pointerDrawingManager.lastPhysicalX_ = -1;
    pointerDrawingManager.lastPhysicalY_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.lastPhysicalX_ = -1;
    pointerDrawingManager.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
}

/**
 * @tc.name: InputWindowsManagerTest_DrawManager_002
 * @tc.desc: Test DrawManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawManager_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.lastPhysicalX_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
}

/**
 * @tc.name: InputWindowsManagerTest_DrawManager_003
 * @tc.desc: Test DrawManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawManager_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION90;
    pointerDrawingManager.lastPhysicalX_ = 2;
    pointerDrawingManager.lastPhysicalY_ = 2;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
}

/**
 * @tc.name: InputWindowsManagerTest_DeletePointerVisible_002
 * @tc.desc: Test DeletePointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DeletePointerVisible_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    pointerDrawingManager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DeletePointerVisible(pid));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DeletePointerVisible(pid));
}

/**
 * @tc.name: InputWindowsManagerTest_DeletePointerVisible_003
 * @tc.desc: Test DeletePointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DeletePointerVisible_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DeletePointerVisible(pid));
    PointerDrawingManager::PidInfo info = {.pid = 1, .visible = true};
    pointerDrawingManager.pidInfos_.push_back(info);
    info = {.pid = 2, .visible = true};
    pointerDrawingManager.pidInfos_.push_back(info);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DeletePointerVisible(pid));
    pid = 5;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DeletePointerVisible(pid));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDefaultPointerStyle_003
 * @tc.desc: Test UpdateDefaultPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_UpdateDefaultPointerStyle_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = 2;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    bool isUiExtension = true;
    int32_t ret = pointerDrawingManager.UpdateDefaultPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret, RET_OK);
    windowId = -1;
    ret = pointerDrawingManager.UpdateDefaultPointerStyle(pid, windowId, pointerStyle, isUiExtension);
}

/**
 * @tc.name: PointerDrawingManagerTest_DrawScreenCenterPointer_001
 * @tc.desc: Test DrawScreenCenterPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_DrawScreenCenterPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);

    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawScreenCenterPointer(pointerStyle));
}

/**
 * @tc.name: PointerDrawingManagerTest_DrawScreenCenterPointer_002
 * @tc.desc: Test DrawScreenCenterPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_DrawScreenCenterPointer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    pointerDrawingManager.hasDisplay_ = false;
    pointerDrawingManager.hasPointerDevice_ = true;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);

    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawScreenCenterPointer(pointerStyle));
}

/**
 * @tc.name: PointerDrawingManagerTest_UpdateBindDisplayId_001
 * @tc.desc: Test UpdateBindDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_UpdateBindDisplayId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.lastDisplayId_ = 0;
    uint64_t displayId = 0;
    pointerDrawingManager.UpdateBindDisplayId(displayId);
    EXPECT_EQ(pointerDrawingManager.lastDisplayId_, 0);
    EXPECT_EQ(pointerDrawingManager.screenId_, 0);

    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    pointerDrawingManager.UpdateBindDisplayId(displayId);
    displayId = 1;
    pointerDrawingManager.UpdateBindDisplayId(displayId);
    EXPECT_EQ(pointerDrawingManager.lastDisplayId_, 1);
    EXPECT_EQ(pointerDrawingManager.screenId_, 1);
}

/**
 * @tc.name: PointerDrawingManagerTest_DestroyPointerWindow_001
 * @tc.desc: Test DestroyPointerWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_DestroyPointerWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.delegateProxy_ = std::make_shared<DelegateInterface>(nullptr, nullptr);
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(pointerDrawingManager.delegateProxy_, nullptr);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DestroyPointerWindow());
    pointerDrawingManager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DestroyPointerWindow());
}

/**
 * @tc.name: PointerDrawingManagerTest_SetMouseHotSpot_004
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_SetMouseHotSpot_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    auto winmgrmock = std::make_shared<InputWindowsManagerMock>();
    int32_t pid = 1;
    int32_t windowId = 2;
    EXPECT_CALL(*winmgrmock, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_OK));
    int32_t hotSpotX = 1;
    int32_t hotSpotY = 2;
    // userIcon_ == nullptr
    int32_t ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    // hotSpotX < 0
    hotSpotX = -1;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    // hotSpotY < 0
    hotSpotX = 1;
    hotSpotY = -2;
    ret = pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    ASSERT_EQ(ret, RET_ERR);
    testing::Mock::AllowLeak(winmgrmock.get());
}

/**
 * @tc.name: InputWindowsManagerTest_IsPointerVisible_002
 * @tc.desc: Test IsPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_IsPointerVisible_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.pidInfos_.clear();
    pointerDrawingManager.pid_ = 0;
    PointerDrawingManager::PidInfo pidInfo;
    for (int32_t i = 1; i < 3; i++) {
        pidInfo.pid = 3 - i;
        pidInfo.visible = false;
        pointerDrawingManager.hapPidInfos_.push_back(pidInfo);
    }
    bool ret = pointerDrawingManager.IsPointerVisible();
    EXPECT_FALSE(ret);
    pointerDrawingManager.pid_ = 1;
    ret = pointerDrawingManager.IsPointerVisible();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerVisible_003
 * @tc.desc: Test SetPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerVisible_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 102;
    int32_t priority = 1;
    bool visible = false;
    bool isHap = true;
    PointerDrawingManager::PidInfo pidInfo;
    for (int32_t i = 1; i < 101; i++) {
        pidInfo.pid = 3 - i;
        pidInfo.visible = false;
        pointerDrawingManager.hapPidInfos_.push_back(pidInfo);
    }
    int32_t ret = pointerDrawingManager.SetPointerVisible(pid, visible, priority, isHap);
    ASSERT_EQ(ret, RET_OK);
    pid = 103;
    ret = pointerDrawingManager.SetPointerVisible(pid, visible, priority, isHap);
    ASSERT_EQ(ret, RET_OK);
    pid = 10;
    ret = pointerDrawingManager.SetPointerVisible(pid, visible, priority, isHap);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_DrawMovePointer_002
 * @tc.desc: Test the funcation DrawMovePointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawMovePointer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t physicalX = 1;
    int32_t physicalY = 2;
    uint64_t displayId = 3;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawMovePointer(displayId, physicalX, physicalY));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawMovePointer(displayId, physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerStyle_002
 * @tc.desc: Test SetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerStyle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    int32_t pid = 1;
    int32_t windowId = -2;
    int32_t ret = pointerDrawingManager.SetPointerStyle(pid, windowId, pointerStyle);
    ASSERT_EQ(ret, RET_ERR);
    windowId = -1;
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ret = pointerDrawingManager.SetPointerStyle(pid, windowId, pointerStyle);
    ASSERT_EQ(ret, RET_OK);
    windowId = 1;
    ret = pointerDrawingManager.SetPointerStyle(pid, windowId, pointerStyle);
    ASSERT_EQ(ret, RET_OK);
    IconStyle iconStyle;
    iconStyle.alignmentWay = 0;
    iconStyle.iconPath = "testpath";
    pointerDrawingManager.mouseIcons_.insert(std::make_pair(static_cast<MOUSE_ICON>(pointerStyle.id), iconStyle));
    ret = pointerDrawingManager.SetPointerStyle(pid, windowId, pointerStyle);
    ASSERT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_branchCoverage
 * @tc.desc: Test SetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_branchCoverage, TestSize.Level1)
{
    PointerDrawingManager pointerDrawingManager;
    MOUSE_ICON mouseStyle = EAST;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    pointerDrawingManager.UpdateIconPath(mouseStyle, iconPath);

    pointerDrawingManager.surfaceNode_ = nullptr;
    auto ret = pointerDrawingManager.SkipPointerLayer(false);
    ASSERT_EQ(ret, RET_OK);
    pointerDrawingManager.canvasWidth_ = 0;
    pointerDrawingManager.cursorWidth_ = 1;
    pointerDrawingManager.canvasHeight_ = 0;
    pointerDrawingManager.cursorHeight_ = 1;
    pointerDrawingManager.SetSurfaceNodeBounds();
    ret = pointerDrawingManager.DrawNewDpiPointer();
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusToSoftRenderOrigin_001
 * @tc.desc: Test AdjustMouseFocusToSoftRenderOrigin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusToSoftRenderOrigin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION0);
    pointerDrawingManager->AdjustMouseFocusToSoftRenderOrigin(
        DIRECTION0, MOUSE_ICON::TEXT_CURSOR, physicalX, physicalY);
    if (pointerDrawingManager->GetHardCursorEnabled()) {
        EXPECT_NE(physicalX, 200);
        EXPECT_NE(physicalY, 200);
    } else {
        EXPECT_EQ(physicalX, 75);
        EXPECT_EQ(physicalY, 75);
    }
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION90);
    pointerDrawingManager->AdjustMouseFocusToSoftRenderOrigin(
        DIRECTION90, MOUSE_ICON::TEXT_CURSOR, physicalX, physicalY);
    if (pointerDrawingManager->GetHardCursorEnabled()) {
        EXPECT_NE(physicalX, 200);
        EXPECT_NE(physicalY, 200);
    } else {
        EXPECT_EQ(physicalX, 75);
        EXPECT_EQ(physicalY, 125);
    }
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION270);
    pointerDrawingManager->AdjustMouseFocusToSoftRenderOrigin(
        DIRECTION270, MOUSE_ICON::TEXT_CURSOR, physicalX, physicalY);
    if (pointerDrawingManager->GetHardCursorEnabled()) {
        EXPECT_NE(physicalX, 200);
        EXPECT_NE(physicalY, 200);
    } else {
        EXPECT_EQ(physicalX, 125);
        EXPECT_EQ(physicalY, 75);
    }
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusToSoftRenderOrigin_002
 * @tc.desc: Test AdjustMouseFocusToSoftRenderOrigin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusToSoftRenderOrigin_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    pointerDrawingManager->UpdateIconPath(MOUSE_ICON::DEFAULT, CURSOR_ICON_PATH);
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION0);
    pointerDrawingManager->AdjustMouseFocusToSoftRenderOrigin(DIRECTION0, MOUSE_ICON::DEFAULT, physicalX, physicalY);
    if (pointerDrawingManager->GetHardCursorEnabled()) {
        EXPECT_NE(physicalX, 200);
        EXPECT_NE(physicalY, 200);
    } else {
        EXPECT_EQ(physicalX, 75);
        EXPECT_EQ(physicalY, 75);
    }
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION90);
    pointerDrawingManager->AdjustMouseFocusToSoftRenderOrigin(DIRECTION90, MOUSE_ICON::DEFAULT, physicalX, physicalY);
    if (pointerDrawingManager->GetHardCursorEnabled()) {
        EXPECT_NE(physicalX, 200);
        EXPECT_NE(physicalY, 200);
    } else {
        EXPECT_EQ(physicalX, 75);
        EXPECT_EQ(physicalY, 125);
    }
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION270);
    pointerDrawingManager->AdjustMouseFocusToSoftRenderOrigin(DIRECTION270, MOUSE_ICON::DEFAULT, physicalX, physicalY);
    if (pointerDrawingManager->GetHardCursorEnabled()) {
        EXPECT_NE(physicalX, 200);
        EXPECT_NE(physicalY, 200);
    } else {
        EXPECT_EQ(physicalX, 125);
        EXPECT_EQ(physicalY, 75);
    }
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusToSoftRenderOrigin_003
 * @tc.desc: Test AdjustMouseFocusToSoftRenderOrigin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusToSoftRenderOrigin_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    pointerDrawingManager->UpdateIconPath(MOUSE_ICON::DEFAULT, CUSTOM_CURSOR_ICON_PATH);
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION0);
    pointerDrawingManager->AdjustMouseFocusToSoftRenderOrigin(DIRECTION0, MOUSE_ICON::DEFAULT, physicalX, physicalY);
    if (pointerDrawingManager->GetHardCursorEnabled()) {
        EXPECT_NE(physicalX, 200);
        EXPECT_NE(physicalY, 200);
    } else {
        EXPECT_NE(physicalX, 75);
        EXPECT_NE(physicalY, 75);
    }
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION90);
    pointerDrawingManager->AdjustMouseFocusToSoftRenderOrigin(DIRECTION90, MOUSE_ICON::DEFAULT, physicalX, physicalY);
    if (pointerDrawingManager->GetHardCursorEnabled()) {
        EXPECT_NE(physicalX, 200);
        EXPECT_NE(physicalY, 200);
    } else {
        EXPECT_NE(physicalX, 75);
        EXPECT_NE(physicalY, 125);
    }
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION270);
    pointerDrawingManager->AdjustMouseFocusToSoftRenderOrigin(DIRECTION270, MOUSE_ICON::DEFAULT, physicalX, physicalY);
    if (pointerDrawingManager->GetHardCursorEnabled()) {
        EXPECT_NE(physicalX, 200);
        EXPECT_NE(physicalY, 200);
    } else {
        EXPECT_NE(physicalX, 125);
        EXPECT_NE(physicalY, 75);
    }
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusToSoftRenderOrigin_004
 * @tc.desc: Test AdjustMouseFocusToSoftRenderOrigin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusToSoftRenderOrigin_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    pointerDrawingManager->UpdateIconPath(MOUSE_ICON::DEFAULT, DEFAULT_ICON_PATH);
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION0);
    pointerDrawingManager->AdjustMouseFocusToSoftRenderOrigin(DIRECTION0, MOUSE_ICON::DEFAULT, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION90);
    pointerDrawingManager->AdjustMouseFocusToSoftRenderOrigin(DIRECTION90, MOUSE_ICON::DEFAULT, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION270);
    pointerDrawingManager->AdjustMouseFocusToSoftRenderOrigin(DIRECTION270, MOUSE_ICON::DEFAULT, physicalX, physicalY);
    EXPECT_NE(physicalX, 200);
    EXPECT_NE(physicalY, 200);
}

/**
 * @tc.name: PointerDrawingManagerTest_UpdateMouseStyle
 * @tc.desc: Test UpdateMouseStyle
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_UpdateMouseStyle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = AECH_DEVELOPER_DEFINED_STYLE;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateMouseStyle());
    pointerStyle.id = AECH_DEVELOPER_DEFINED;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateMouseStyle());
}

/**
 * @tc.name: PointerDrawingManagerTest_ConvertToColorSpace_001
 * @tc.desc: Test ConvertToColorSpace
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_ConvertToColorSpace_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Media::ColorSpace colorSpace = Media::ColorSpace::DISPLAY_P3;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.ConvertToColorSpace(colorSpace));
    colorSpace = Media::ColorSpace::LINEAR_SRGB;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.ConvertToColorSpace(colorSpace));
    colorSpace = Media::ColorSpace::ACES;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.ConvertToColorSpace(colorSpace));
}

/**
 * @tc.name: PointerDrawingManagerTest_RegisterDisplayStatusReceiver_001
 * @tc.desc: Test RegisterDisplayStatusReceiver
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, RegisterDisplayStatusReceiver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->initDisplayStatusReceiverFlag_ = true;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager->RegisterDisplayStatusReceiver());
}

/**
 * @tc.name: PointerDrawingManagerTest_RegisterDisplayStatusReceiver_002
 * @tc.desc: Test RegisterDisplayStatusReceiver
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, RegisterDisplayStatusReceiver_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->initDisplayStatusReceiverFlag_ = false;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager->RegisterDisplayStatusReceiver());
}

/**
 * @tc.name: PointerDrawingManagerTest_CalculateRenderDirection_001
 * @tc.desc: Test CalculateRenderDirection
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, CalculateRenderDirection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->displayInfo_.displayDirection = DIRECTION270;
    pointerDrawingManager->displayInfo_.direction = DIRECTION90;
    bool isHard = true;
    bool isWindowRotate = true;
    Direction ret = pointerDrawingManager->CalculateRenderDirection(isHard, isWindowRotate);
    ASSERT_EQ(ret, DIRECTION90);
    isHard = true;
    isWindowRotate = false;
    ret = pointerDrawingManager->CalculateRenderDirection(isHard, isWindowRotate);
    ASSERT_EQ(ret, DIRECTION90);
    isHard = false;
    isWindowRotate = true;
    ret = pointerDrawingManager->CalculateRenderDirection(isHard, isWindowRotate);
    ASSERT_EQ(ret, DIRECTION180);
    isHard = false;
    isWindowRotate = false;
    ret = pointerDrawingManager->CalculateRenderDirection(isHard, isWindowRotate);
    ASSERT_EQ(ret, DIRECTION0);
}

/**
 * @tc.name: PointerDrawingManagerTest_CalculateRenderDirection_002
 * @tc.desc: Test CalculateRenderDirection
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, CalculateRenderDirection_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->displayInfo_.displayDirection = DIRECTION270;
    pointerDrawingManager->displayInfo_.direction = DIRECTION90;
    bool isHard = true;
    bool isWindowRotate = true;
    Direction ret = pointerDrawingManager->CalculateRenderDirection(isHard, isWindowRotate);
    ASSERT_EQ(ret, DIRECTION90);
    isHard = true;
    isWindowRotate = false;
    ret = pointerDrawingManager->CalculateRenderDirection(isHard, isWindowRotate);
    ASSERT_EQ(ret, DIRECTION90);
    isHard = false;
    isWindowRotate = true;
    ret = pointerDrawingManager->CalculateRenderDirection(isHard, isWindowRotate);
    ASSERT_EQ(ret, DIRECTION180);
    isHard = false;
    isWindowRotate = false;
    ret = pointerDrawingManager->CalculateRenderDirection(isHard, isWindowRotate);
    ASSERT_EQ(ret, DIRECTION0);
}

/**
 * @tc.name: PointerDrawingManagerTest_UpdateMirrorScreens_001
 * @tc.desc: Test UpdateMirrorScreens
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, UpdateMirrorScreens_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    OLD::DisplayInfo displaysInfo;
    displaysInfo.rsId = 102;
    displaysInfo.direction = DIRECTION0;
    displaysInfo.displayDirection = DIRECTION0;
    displaysInfo.width = 400;
    displaysInfo.height = 300;
    pointerDrawingManager->displayInfo_.rsId = 100;
    pointerDrawingManager->displayInfo_.direction = DIRECTION0;
    pointerDrawingManager->displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager->displayInfo_.width = 600;
    pointerDrawingManager->displayInfo_.height = 400;
    auto spMirror = std::make_shared<ScreenPointer>(
        pointerDrawingManager->hardwareCursorPointerManager_, pointerDrawingManager->handler_, displaysInfo);
    auto spMain = std::make_shared<ScreenPointer>(pointerDrawingManager->hardwareCursorPointerManager_,
        pointerDrawingManager->handler_, pointerDrawingManager->displayInfo_);
    spMirror->mode_ = mode_t::SCREEN_MIRROR;
    spMirror->displayDirection_ = DIRECTION0;
    pointerDrawingManager->screenPointers_[displaysInfo.rsId] = spMirror;
    pointerDrawingManager->screenPointers_[101] = nullptr;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager->UpdateMirrorScreens(spMain, pointerDrawingManager->displayInfo_));
    pointerDrawingManager->displayInfo_.direction = DIRECTION90;
    pointerDrawingManager->displayInfo_.displayDirection = DIRECTION270;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager->UpdateMirrorScreens(spMain, pointerDrawingManager->displayInfo_));
}

/**
 * @tc.name: PointerDrawingManagerTest_SwitchPointerStyle_002
 * @tc.desc: Test SwitchPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_SwitchPointerStyle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    int32_t maxId = 49;
    std::vector<int32_t> vecStyleId;
    for (int32_t i = 0; i < maxId; i++) {
        vecStyleId.push_back(i);
    }
    vecStyleId.push_back(-100);
    vecStyleId.push_back(-101);
    vecStyleId.push_back(-1);
    for (size_t i = 0; i < vecStyleId.size(); i++) {
        pointerDrawMgr.lastMouseStyle_.id = vecStyleId[i];
        ASSERT_NO_FATAL_FAILURE(pointerDrawMgr.SwitchPointerStyle());
    }
}

/**
 * @tc.name: InputWindowsManagerTest_GetMainScreenDisplayInfo_001
 * @tc.desc: Test GetMainScreenDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_GetMainScreenDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displayInfo1;
    displayInfo1.id = 1;
    displayInfo1.x = 1;
    displayInfo1.y = 1;
    displayInfo1.width = 2;
    displayInfo1.height = 2;
    displayInfo1.dpi = 240;
    displayInfo1.name = "pp";
    displayInfo1.direction = DIRECTION0;
    displayInfo1.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_MAIN;

    OLD::DisplayInfo displayInfo2;
    displayInfo2.id = 2;
    displayInfo2.x = 1;
    displayInfo2.y = 1;
    displayInfo2.width = 2;
    displayInfo2.height = 2;
    displayInfo2.dpi = 240;
    displayInfo2.name = "pp";
    displayInfo2.uniq = "pp";
    displayInfo2.direction = DIRECTION0;
    displayInfo2.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_EXPAND;

    OLD::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.displaysInfo.push_back(displayInfo2);
    displayGroupInfo.displaysInfo.push_back(displayInfo1);
    OLD::DisplayInfo displayInfo = displayGroupInfo.displaysInfo[0];
    ASSERT_EQ(pointerDrawingManager.GetMainScreenDisplayInfo(displayGroupInfo, displayInfo), RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateMouseLayer
 * @tc.desc: Test UpdateMouseLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_UpdateMouseLayer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    int32_t physicalX = 1;
    int32_t physicalY = 2;
    pointerDrawingManager.surfaceNode_ = nullptr;
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    pointerDrawingManager.lastMouseStyle_.id = 2;
    ASSERT_EQ(pointerDrawingManager.UpdateMouseLayer(pointerStyle, physicalX, physicalY), RET_ERR);
}

/**
 * @tc.name: PointerDrawingManagerExTest_UpdateMirrorScreens_001
 * @tc.desc: Test the funcation UpdateMirrorScreens
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerExTest_UpdateMirrorScreens_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    hwcmgr_ptr_t hwcmgr = nullptr;
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    std::shared_ptr<ScreenPointer> screenpointer = std::make_shared<ScreenPointer>(hwcmgr, handler, di);
    OLD::DisplayInfo displaysInfo;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager->UpdateMirrorScreens(screenpointer, displaysInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_OnDisplayInfo_004
 * @tc.desc: Test OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_OnDisplayInfo_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displaysInfo;
    displaysInfo.rsId = 22;
    OLD::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.displaysInfo.push_back(displaysInfo);
    displayGroupInfo.focusWindowId = 0;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.surfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    pointerDrawingManager.surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    OLD::DisplayInfo displaysInfo_;
    displaysInfo_.rsId = 11;
    pointerDrawingManager.displayInfo_ = displaysInfo_;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnDisplayInfo(displayGroupInfo));

    OLD::DisplayGroupInfo displayGroupInfo2;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnDisplayInfo(displayGroupInfo2));

    OLD::DisplayInfo displaysInfo3;
    displaysInfo3.rsId = 33;
    OLD::DisplayGroupInfo displayGroupInfo3;
    displayGroupInfo3.displaysInfo.push_back(displaysInfo3);
    displayGroupInfo3.focusWindowId = 0;
    OLD::DisplayInfo displaysInfo33_;
    displaysInfo33_.rsId = 33;
    pointerDrawingManager.displayInfo_ = displaysInfo33_;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnDisplayInfo(displayGroupInfo3));
}

/**
 * @tc.name: InputWindowsManagerTest_OnDisplayInfo_005
 * @tc.desc: Test OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_OnDisplayInfo_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displaysInfo;
    displaysInfo.rsId = 22;
    OLD::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.displaysInfo.push_back(displaysInfo);
    displayGroupInfo.focusWindowId = 0;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.surfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    pointerDrawingManager.surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    OLD::DisplayInfo displaysInfo_;
    displaysInfo_.rsId = 11;
    pointerDrawingManager.displayInfo_ = displaysInfo_;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnDisplayInfo(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_OnDisplayInfo_006
 * @tc.desc: Test OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_OnDisplayInfo_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displaysInfo;
    displaysInfo.rsId = 11;
    OLD::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.displaysInfo.push_back(displaysInfo);
    displayGroupInfo.focusWindowId = 0;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.surfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    pointerDrawingManager.surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    OLD::DisplayInfo displaysInfo_;
    displaysInfo_.rsId = 11;
    pointerDrawingManager.displayInfo_ = displaysInfo_;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnDisplayInfo(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_OnDisplayInfo_007
 * @tc.desc: Test OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_OnDisplayInfo_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displaysInfo;
    displaysInfo.rsId = 11;
    displaysInfo.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_EXTEND;
    OLD::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.displaysInfo.push_back(displaysInfo);
    displayGroupInfo.focusWindowId = 0;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.surfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    pointerDrawingManager.surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    OLD::DisplayInfo displaysInfo_;
    displaysInfo_.rsId = 11;
    displaysInfo_.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_MAIN;
    pointerDrawingManager.displayInfo_ = displaysInfo_;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnDisplayInfo(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_OnDisplayInfo_008
 * @tc.desc: Test OnDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_OnDisplayInfo_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displaysInfo;
    displaysInfo.rsId = 11;
    displaysInfo.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_MAIN;
    OLD::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.displaysInfo.push_back(displaysInfo);
    displayGroupInfo.focusWindowId = 0;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.surfaceNode_->SetFrameGravity(Rosen::Gravity::RESIZE_ASPECT_FILL);
    pointerDrawingManager.surfaceNode_->SetPositionZ(Rosen::RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
    OLD::DisplayInfo displaysInfo_;
    displaysInfo_.rsId = 11;
    displaysInfo_.displaySourceMode = OHOS::MMI::DisplaySourceMode::SCREEN_MAIN;
    pointerDrawingManager.displayInfo_ = displaysInfo_;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnDisplayInfo(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_CreatePointerWindowForScreenPointer_003
 * @tc.desc: Test CreatePointerWindowForScreenPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_CreatePointerWindowForScreenPointer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OLD::DisplayInfo displayInfo_;
    std::unordered_map<uint32_t, std::shared_ptr<ScreenPointer>> screenPointers_;

    int32_t rsId = 1;
    int32_t physicalX = 0;
    int32_t physicalY = 0;
    auto sp = std::make_shared<ScreenPointer>(nullptr, nullptr, displayInfo_);
    auto pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->screenPointers_[rsId] = sp;
    OLD::DisplayInfo displaysInfo_;
    displaysInfo_.rsId = 1;
    pointerDrawingManager->displayInfo_ = displaysInfo_;
    g_isRsRestart.store(false);
    int32_t result = pointerDrawingManager->CreatePointerWindowForScreenPointer(rsId, physicalX, physicalY);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_CreatePointerWindowForScreenPointer_004
 * @tc.desc: Test CreatePointerWindowForScreenPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_CreatePointerWindowForScreenPointer_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OLD::DisplayInfo displayInfo_;
    std::unordered_map<uint32_t, std::shared_ptr<ScreenPointer>> screenPointers_;

    int32_t rsId = 1;
    int32_t physicalX = 0;
    int32_t physicalY = 0;
    auto sp = std::make_shared<ScreenPointer>(nullptr, nullptr, displayInfo_);
    auto pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->screenPointers_[rsId] = sp;
    OLD::DisplayInfo displaysInfo_;
    displaysInfo_.rsId = 2;
    pointerDrawingManager->displayInfo_ = displaysInfo_;
    g_isRsRestart.store(false);
    int32_t result = pointerDrawingManager->CreatePointerWindowForScreenPointer(rsId, physicalX, physicalY);
    EXPECT_NE(result, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_CreatePointerWindowForScreenPointer_005
 * @tc.desc: Test CreatePointerWindowForScreenPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_CreatePointerWindowForScreenPointer_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OLD::DisplayInfo displayInfo_;
    std::unordered_map<uint32_t, std::shared_ptr<ScreenPointer>> screenPointers_;

    int32_t rsId = 2;
    int32_t physicalX = 0;
    int32_t physicalY = 0;
    auto sp = std::make_shared<ScreenPointer>(nullptr, nullptr, displayInfo_);
    auto pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->screenPointers_[rsId] = sp;

    g_isRsRestart.store(false);
    int32_t result = pointerDrawingManager->CreatePointerWindowForScreenPointer(rsId, physicalX, physicalY);
    EXPECT_NE(result, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_DrawMovePointer_003
 * @tc.desc: Test the funcation DrawMovePointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawMovePointer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager manager;
    PointerStyle pointerStyle;

    int32_t displayId = 1;
    int32_t physicalX = 2;
    int32_t physicalY = 3;
    auto align = manager.MouseIcon2IconType(MOUSE_ICON(2));
    Direction direction = DIRECTION0;
    manager.surfaceNode_ = nullptr;
    int32_t ret = manager.DrawMovePointer(displayId, physicalX, physicalY, pointerStyle, direction);
    EXPECT_EQ(ret, RET_ERR);
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    manager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(manager.surfaceNode_ != nullptr);
    auto setlot = manager.SetCursorLocation(physicalX, physicalY, align);
    EXPECT_EQ(setlot, true);
    ret = manager.DrawMovePointer(displayId, physicalX, physicalY, pointerStyle, direction);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerSize_002
 * @tc.desc: Test SetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerSize_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawMgr;
    pointerDrawMgr.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawMgr.hardwareCursorPointerManager_->isEnableState_ = true;
    pointerDrawMgr.lastMouseStyle_.id = 2;
    ASSERT_EQ(pointerDrawMgr.SetPointerSize(0), RET_OK);
}

/**
 * @tc.name: PointerDrawingManagerTest_UpdateBindDisplayId_002
 * @tc.desc: Test UpdateBindDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_UpdateBindDisplayId_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.lastDisplayId_ = 0;
    pointerDrawingManager.surfaceNode_ = nullptr;
    int32_t displayId = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateBindDisplayId(displayId));
}

/**
 * @tc.name: InputWindowsManagerTest_LoadCursorSvgWithColor_001
 * @tc.desc: Test LoadCursorSvgWithColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_LoadCursorSvgWithColor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    auto type = MOUSE_ICON::DEFAULT;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager->LoadCursorSvgWithColor(type, MIN_POINTER_COLOR));
}

/**
 * @tc.name: InputWindowsManagerTest_AoutPointer_001
 * @tc.desc: Test AoutPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AoutPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto *pointerDrawingManager = static_cast<PointerDrawingManager *>(IPointerDrawingManager::GetInstance());
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager->SetPointerColor(MIN_POINTER_COLOR));
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager->SetPointerSize(1));
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager->UpdatePointerDevice(true, true, false));
    pointerDrawingManager->pidInfos_.clear();
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager->DeletePointerVisible(0));
    PointerDrawingManager::PidInfo pidInfo1{1, false};
    PointerDrawingManager::PidInfo pidInfo2{0, false};
    pointerDrawingManager->hapPidInfos_.push_back(pidInfo1);
    pointerDrawingManager->hapPidInfos_.push_back(pidInfo2);
    pointerDrawingManager->pid_ = 0;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager->GetPointerVisible(0));
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager->SetPointerVisible(0, true, 0, true));
    PointerStyle pointerStyle;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager->SetPointerStylePreference(pointerStyle));
}

/**
 * @tc.name: PointerDrawingManagerTest_GetCurrentCursorInfo_001
 * @tc.desc: Test GetCurrentCursorInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_GetCurrentCursorInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t style = 19;
    pointerDrawingManager.mouseDisplayState_ = true;
    pointerDrawingManager.lastMouseStyle_.id = style;
    bool visible = false;
    PointerStyle pointerStyle;
    auto ret = pointerDrawingManager.GetCurrentCursorInfo(visible, pointerStyle);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_TRUE(visible);
    ASSERT_EQ(pointerStyle.id, style);
}

/**
 * @tc.name: PointerDrawingManagerTest_GetCurrentCursorInfo_002
 * @tc.desc: Test GetCurrentCursorInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_GetCurrentCursorInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.mouseDisplayState_ = false;
    PointerStyle pointerStyle;
    bool visible;
    auto ret = pointerDrawingManager.GetCurrentCursorInfo(visible, pointerStyle);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_FALSE(visible);
}

/**
 * @tc.name: PointerDrawingManagerTest_GetCurrentCursorInfo_003
 * @tc.desc: Test GetCurrentCursorInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_GetCurrentCursorInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerDrawingManager::PidInfo pidInfo;
    pidInfo.visible = false;
    pointerDrawingManager.pidInfos_.push_back(pidInfo);
    PointerStyle pointerStyle;
    bool visible;
    auto ret = pointerDrawingManager.GetCurrentCursorInfo(visible, pointerStyle);
    ASSERT_EQ(ret, RET_OK);
    ASSERT_FALSE(visible);
}

/**
 * @tc.name: PointerDrawingManagerTest_GetUserDefinedCursorPixelMap_001
 * @tc.desc: Test GetUserDefinedCursorPixelMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_GetUserDefinedCursorPixelMap_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    void *pixelMapPtr = nullptr;
    auto ret = pointerDrawingManager.GetUserDefinedCursorPixelMap(pixelMapPtr);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PointerDrawingManagerTest_GetUserDefinedCursorPixelMap_002
 * @tc.desc: Test GetUserDefinedCursorPixelMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_GetUserDefinedCursorPixelMap_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = std::make_shared<OHOS::Media::PixelMap>();
    auto ret = pointerDrawingManager.GetUserDefinedCursorPixelMap(&pixelMap);
    ASSERT_EQ(ret, RET_ERR);
}
} // namespace MMI
} // namespace OHOS