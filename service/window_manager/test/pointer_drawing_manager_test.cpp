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
#include "knuckle_drawing_manager.h"
#include "libinput_mock.h"
#include "mmi_log.h"
#include "pixel_map.h"
#include "pointer_drawing_manager.h"
#include "pointer_event.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerDrawingManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t MOUSE_ICON_SIZE = 64;
} // namespace

class PointerDrawingManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void)
    {}
    void TearDown(void)
    {}

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
    int32_t displayId = 1;
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
 * @tc.name: InputWindowsManagerTest_FixCursorPosition_002
 * @tc.desc: Test FixCursorPosition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_FixCursorPosition_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager->displayInfo_.direction = DIRECTION0;
    pointerDrawingManager->displayInfo_.width = 500;
    pointerDrawingManager->displayInfo_.height = 1100;
    pointerDrawingManager->imageWidth_ = 48;
    pointerDrawingManager->imageHeight_ = 48;
    int32_t physicalX = -5;
    int32_t physicalY = -10;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager->FixCursorPosition(physicalX, physicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_SetCustomCursor_006
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetCustomCursor_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    int32_t pid = 1;
    int32_t windowId = -1;
    int32_t focusX = 2;
    int32_t focusY = 3;
    EXPECT_CALL(*WIN_MGR_MOCK, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_OK));
    int32_t ret = pointerDrawingManager.SetCustomCursor((void *)pixelMap.get(), pid, windowId, focusX, focusY);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseIcon_006
 * @tc.desc: Test SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseIcon_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    int32_t pid = 1;
    int32_t windowId = -2;
    EXPECT_CALL(*WIN_MGR_MOCK, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_OK));
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, (void *)pixelMap.get());
    ASSERT_EQ(ret, RET_ERR);
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
    int32_t pid = 1;
    int32_t windowId = -2;
    EXPECT_CALL(*WIN_MGR_MOCK, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_OK));
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
    EXPECT_CALL(*WIN_MGR_MOCK, GetPointerStyle).WillRepeatedly(testing::Return(RET_OK));
    ASSERT_EQ(ret, RET_ERR);
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
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
    pointerDrawingManager.hasDisplay_ = true;
    pointerDrawingManager.hasPointerDevice_ = true;
    pointerDrawingManager.surfaceNode_ = nullptr;
    EXPECT_CALL(*WIN_MGR_MOCK, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_ERR));
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    EXPECT_CALL(*WIN_MGR_MOCK, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_OK));
    pointerDrawingManager.lastPhysicalX_ = -1;
    pointerDrawingManager.lastPhysicalY_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    pointerDrawingManager.lastPhysicalX_ = -1;
    pointerDrawingManager.lastPhysicalY_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
    EXPECT_CALL(*WIN_MGR_MOCK, CheckWindowIdPermissionByPid).WillRepeatedly(testing::Return(RET_OK));
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawManager());
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    EXPECT_CALL(*WIN_MGR_MOCK, GetExtraData).WillRepeatedly(testing::Return(ExtraData{true}));
    int32_t pid = 1;
    bool visible = true;
    int32_t priority = 0;
    int32_t ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority);
    ASSERT_EQ(ret, RET_ERR);
    visible = false;
    priority = 0;
    ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority);
    ASSERT_EQ(ret, RET_OK);
    visible = true;
    priority = 1;
    ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority);
    ASSERT_EQ(ret, RET_OK);
    visible = false;
    priority = 1;
    ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority);
    ASSERT_EQ(ret, RET_OK);
    EXPECT_CALL(*WIN_MGR_MOCK, GetExtraData).WillRepeatedly(testing::Return(ExtraData{false}));
    visible = false;
    priority = 0;
    ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority);
    ASSERT_EQ(ret, RET_OK);
    visible = true;
    priority = 1;
    ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority);
    ASSERT_EQ(ret, RET_OK);
    visible = false;
    priority = 1;
    ret = pointerDrawingManager->SetPointerVisible(pid, visible, priority);
    ASSERT_EQ(ret, RET_OK);
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
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetPointerLocation(x, y));
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
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = -1;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    EXPECT_CALL(*WIN_MGR_MOCK, GetPointerStyle).WillRepeatedly(testing::Return(RET_ERR));
    int32_t ret = pointerDrawingManager.UpdateDefaultPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, RET_ERR);
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    int32_t pid = 1;
    int32_t windowId = 2;
    bool isUiExtension = true;
    PointerStyle pointerStyle;
    EXPECT_CALL(*WIN_MGR_MOCK, GetPointerStyle).WillRepeatedly(testing::Return(RET_ERR));
    int32_t ret = pointerDrawingManager->GetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret, RET_ERR);
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    pointerDrawingManager->userIconHotSpotX_ = 5;
    pointerDrawingManager->userIconHotSpotY_ = 5;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection0(ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 50);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection0(ANGLE_CENTER, physicalX, physicalY);
    EXPECT_EQ(physicalX, 75);
    EXPECT_EQ(physicalY, 75);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection0(ANGLE_NW_RIGHT, physicalX, physicalY);
    EXPECT_EQ(physicalX, 95);
    EXPECT_EQ(physicalY, 100);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager->currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerDrawingManager->AdjustMouseFocusByDirection0(ANGLE_NW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 95);
    EXPECT_EQ(physicalY, 95);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection0(ANGLE_E, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 100);
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    pointerDrawingManager->userIconHotSpotX_ = 5;
    pointerDrawingManager->userIconHotSpotY_ = 5;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection90(ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 150);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection90(ANGLE_CENTER, physicalX, physicalY);
    EXPECT_EQ(physicalX, 75);
    EXPECT_EQ(physicalY, 125);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection90(ANGLE_NW_RIGHT, physicalX, physicalY);
    EXPECT_EQ(physicalX, 90);
    EXPECT_EQ(physicalY, 105);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager->currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerDrawingManager->AdjustMouseFocusByDirection90(ANGLE_NW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 95);
    EXPECT_EQ(physicalY, 105);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection90(ANGLE_E, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 100);
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    pointerDrawingManager->userIconHotSpotX_ = 5;
    pointerDrawingManager->userIconHotSpotY_ = 5;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection180(ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 150);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection180(ANGLE_CENTER, physicalX, physicalY);
    EXPECT_EQ(physicalX, 125);
    EXPECT_EQ(physicalY, 125);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection180(ANGLE_NW_RIGHT, physicalX, physicalY);
    EXPECT_EQ(physicalX, 110);
    EXPECT_EQ(physicalY, 105);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager->currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerDrawingManager->AdjustMouseFocusByDirection180(ANGLE_NW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 105);
    EXPECT_EQ(physicalY, 105);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection180(ANGLE_E, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 100);
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    pointerDrawingManager->userIconHotSpotX_ = 5;
    pointerDrawingManager->userIconHotSpotY_ = 5;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection270(ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 50);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection270(ANGLE_CENTER, physicalX, physicalY);
    EXPECT_EQ(physicalX, 125);
    EXPECT_EQ(physicalY, 75);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection270(ANGLE_NW_RIGHT, physicalX, physicalY);
    EXPECT_EQ(physicalX, 110);
    EXPECT_EQ(physicalY, 95);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager->currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerDrawingManager->AdjustMouseFocusByDirection270(ANGLE_NW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 105);
    EXPECT_EQ(physicalY, 95);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->AdjustMouseFocusByDirection270(ANGLE_E, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 100);
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->imageWidth_ = 50;
    pointerDrawingManager->imageHeight_ = 50;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION0);
    pointerDrawingManager->AdjustMouseFocus(DIRECTION0, ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 50);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION90);
    pointerDrawingManager->AdjustMouseFocus(DIRECTION90, ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 150);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION180);
    pointerDrawingManager->AdjustMouseFocus(DIRECTION180, ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 150);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(DIRECTION270);
    pointerDrawingManager->AdjustMouseFocus(DIRECTION270, ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 50);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager->RotateDegree(static_cast<Direction>(4));
    pointerDrawingManager->AdjustMouseFocus(static_cast<Direction>(4), ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 100);
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->SetPointerColor(-1);
    int32_t color = pointerDrawingManager->GetPointerColor();
    EXPECT_EQ(color, 16777215);
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    for (int32_t i = 1; i < 102; i++) {
        pointerDrawingManager->SetPointerVisible(i, false, 0);
    }
    bool visible = pointerDrawingManager->GetPointerVisible(1);
    EXPECT_EQ(visible, true);
    pointerDrawingManager->SetPointerVisible(11, true, 0);
    visible = pointerDrawingManager->GetPointerVisible(11);
    EXPECT_EQ(visible, true);
}

/**
 * @tc.name: InputWindowsManagerTest_DrawLoadingPointerStyle_002
 * @tc.desc: Test the funcation DrawLoadingPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawLoadingPointerStyle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager manager;
    MOUSE_ICON mouseStyle = WEST;
    manager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(manager.DrawLoadingPointerStyle(mouseStyle));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    manager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(manager.surfaceNode_ != nullptr);
    ASSERT_NO_FATAL_FAILURE(manager.DrawLoadingPointerStyle(mouseStyle));
    mouseStyle = LOADING;
    ASSERT_NO_FATAL_FAILURE(manager.DrawLoadingPointerStyle(mouseStyle));
    mouseStyle = DEFAULT;
    ASSERT_NO_FATAL_FAILURE(manager.DrawLoadingPointerStyle(mouseStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_AttachToDisplay_001
 * @tc.desc: Test the funcation AttachToDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AttachToDisplay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager manager;
    manager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(manager.AttachToDisplay());
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    manager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(manager.surfaceNode_ != nullptr);
    manager.screenId_ = 0;
    ASSERT_NO_FATAL_FAILURE(manager.AttachToDisplay());
    manager.screenId_ = 1;
    ASSERT_NO_FATAL_FAILURE(manager.AttachToDisplay());
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->SetPointerSize(0);
    int32_t pointerSize = pointerDrawingManager->GetPointerSize();
    EXPECT_EQ(pointerSize, 1);
    pointerDrawingManager->SetPointerSize(8);
    pointerSize = pointerDrawingManager->GetPointerSize();
    EXPECT_EQ(pointerSize, 7);
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager->displayInfo_.direction = DIRECTION0;
    pointerDrawingManager->displayInfo_.width = 500;
    pointerDrawingManager->displayInfo_.height = 1100;
    pointerDrawingManager->imageWidth_ = 48;
    pointerDrawingManager->imageHeight_ = 48;
    int32_t physicalX = 500;
    int32_t physicalY = 1100;
    pointerDrawingManager->FixCursorPosition(physicalX, physicalY);
    EXPECT_EQ(physicalX, 497);
    EXPECT_EQ(physicalY, 1097);
    pointerDrawingManager->displayInfo_.direction = DIRECTION90;
    physicalX = 1100;
    physicalY = 500;
    pointerDrawingManager->FixCursorPosition(physicalX, physicalY);
    EXPECT_EQ(physicalX, 1097);
    EXPECT_EQ(physicalY, 497);
    pointerDrawingManager->displayInfo_.displayDirection = DIRECTION90;
    pointerDrawingManager->displayInfo_.direction = DIRECTION0;
    physicalX = 500;
    physicalY = 1100;
    pointerDrawingManager->FixCursorPosition(physicalX, physicalY);
    EXPECT_EQ(physicalX, 500);
    EXPECT_EQ(physicalY, 497);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateMouseStyle_001
 * @tc.desc: Test UpdateMouseStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_UpdateMouseStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.pid_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateMouseStyle());
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
    void* pixelMap = nullptr;
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, pixelMap);
    EXPECT_EQ(ret, RET_ERR);
    pid = 1;
    ret = pointerDrawingManager.SetMouseIcon(pid, windowId, pixelMap);
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
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DecodeImageToPixelMap(iconPath));
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
    PointerDrawingManager::PidInfo info = { .pid = 1, .visible = true };
    pointerDrawingManager.pidInfos_.push_back(info);
    info = { .pid = 2, .visible = true };
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
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetPointerLocation(x, y));
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
    int32_t ret = pointerDrawingManager.SetCustomCursor((void *)pixelMap.get(), pid, windowId, focusX, focusY);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetCustomCursor_002
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetCustomCursor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    int32_t pid = 1;
    int32_t windowId = -1;
    int32_t focusX = 2;
    int32_t focusY = 3;
    int32_t ret = pointerDrawingManager.SetCustomCursor((void *)pixelMap.get(), pid, windowId, focusX, focusY);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetCustomCursor_003
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetCustomCursor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    int32_t pid = 1;
    int32_t windowId = 2;
    int32_t focusX = 2;
    int32_t focusY = 3;
    int32_t ret = pointerDrawingManager.SetCustomCursor((void *)pixelMap.get(), pid, windowId, focusX, focusY);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetCustomCursor_004
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetCustomCursor_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    int32_t pid = 2;
    int32_t windowId = 2;
    int32_t focusX = -1;
    int32_t focusY = 3;
    int32_t ret = pointerDrawingManager.SetCustomCursor((void *)pixelMap.get(), pid, windowId, focusX, focusY);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetCustomCursor_005
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetCustomCursor_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    int32_t pid = 2;
    int32_t windowId = 2;
    int32_t focusX = 3;
    int32_t focusY = 4;
    int32_t ret = pointerDrawingManager.SetCustomCursor((void *)pixelMap.get(), pid, windowId, focusX, focusY);
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
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, (void *)pixelMap.get());
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseIcon_003
 * @tc.desc: Test SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetMouseIcon_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    const std::string iconPath = "/system/etc/multimodalinput/mouse_icon/North_South.svg";
    std::unique_ptr<OHOS::Media::PixelMap> pixelMap = SetMouseIconTest(iconPath);
    ASSERT_NE(pixelMap, nullptr);
    int32_t pid = 1;
    int32_t windowId = -2;
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, (void *)pixelMap.get());
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
    ASSERT_NE(pixelMap, nullptr);
    int32_t pid = 1;
    int32_t windowId = 2;
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, (void *)pixelMap.get());
    ASSERT_EQ(ret, RET_ERR);
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
    ASSERT_NE(pixelMap, nullptr);
    int32_t pid = 2;
    int32_t windowId = 2;
    int32_t ret = pointerDrawingManager.SetMouseIcon(pid, windowId, (void *)pixelMap.get());
    ASSERT_EQ(ret, RET_ERR);
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
    DisplayInfo displaysInfo;
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.displaysInfo.push_back(displaysInfo);
    displayGroupInfo.focusWindowId = 0;
    displayGroupInfo.width = 0;
    displayGroupInfo.height = 0;
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
    DisplayInfo displaysInfo;
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.displaysInfo.push_back(displaysInfo);
    displayGroupInfo.focusWindowId = 0;
    displayGroupInfo.width = 0;
    displayGroupInfo.height = 0;
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
 * @tc.name: PointerDrawingManagerTest_ExtractDrawingImage_001
 * @tc.desc: Test ExtractDrawingImage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, PointerDrawingManagerTest_ExtractDrawingImage_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::Rosen::Drawing::Bitmap bitmap;
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
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
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
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
    OHOS::Rosen::Drawing::BitmapFormat format { OHOS::Rosen::Drawing::COLORTYPE_RGBA_8888,
        OHOS::Rosen::Drawing::ALPHATYPE_OPAQUE };
    PointerDrawingManager pointerDrawingManager;
    bitmap.Build(64, 64, format);
    OHOS::Rosen::Drawing::Canvas canvas(256, 256);
    canvas.Bind(bitmap);
    canvas.Clear(OHOS::Rosen::Drawing::Color::COLOR_TRANSPARENT);
    MOUSE_ICON mouseStyle = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawImage(canvas, mouseStyle));
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetPointerLocation(200, 200));
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager->InitPointerCallback());
}

/**
 * @tc.name: InputWindowsManagerTest_SetTargetDevice_001
 * @tc.desc: Test SetTargetDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetTargetDevice_001, TestSize.Level1)
{
    #ifdef OHOS_BUILD_ENABLE_HARDWARE_CURSOR
    CALL_TEST_DEBUG;
    uint32_t devId = 0;
    hardwareCursorPointerManager_->devId_ = 0;
    hardwareCursorPointerManager_->SetTargetDevice(devId);
    ASSERT_FALSE(hardwareCursorPointerManager_->isEnableState_);
    devId = 10;
    hardwareCursorPointerManager_->SetTargetDevice(devId);
    ASSERT_FALSE(hardwareCursorPointerManager_->isEnableState_);
    #endif // OHOS_BUILD_ENABLE_HARDWARE_CURSOR
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager->InitPointerObserver());
}
} // namespace MMI
} // namespace OHOS