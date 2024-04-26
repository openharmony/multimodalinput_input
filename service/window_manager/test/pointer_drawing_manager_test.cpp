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

#include "pointer_drawing_manager.h"
#include "mmi_log.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class PointerDrawingManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void)
    {}
    void TearDown(void)
    {}
private:
};

/**
 * @tc.name: InputWindowsManagerTest_Init_001
 * @tc.desc: Test Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_Init_001, TestSize.Level1)
{
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
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    pointerDrawingManager->SetPointerColor(-1);
    int32_t color = pointerDrawingManager->GetPointerColor();
    EXPECT_EQ(color, 0);
    pointerDrawingManager->SetPointerColor(16777216);
    color = pointerDrawingManager->GetPointerColor();
    EXPECT_EQ(color, 16777215);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerVisible_001
 * @tc.desc: Test SetPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_SetPointerVisible_001, TestSize.Level1)
{
    std::shared_ptr<PointerDrawingManager> pointerDrawingManager =
        std::static_pointer_cast<PointerDrawingManager>(IPointerDrawingManager::GetInstance());
    for (int32_t i = 1; i < 102; i++) {
        pointerDrawingManager->SetPointerVisible(i, false);
    }
    bool visible = pointerDrawingManager->GetPointerVisible(1);
    EXPECT_EQ(visible, true);
    pointerDrawingManager->SetPointerVisible(11, true);
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
    EXPECT_EQ(physicalX, 497);
    EXPECT_EQ(physicalY, 1097);
}

/**
 * @tc.name: InputWindowsManagerTest_DrawPointer_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointer_001, TestSize.Level1)
{
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
 * @tc.name: InputWindowsManagerTest_UpdateMouseStyle_001
 * @tc.desc: Test UpdateMouseStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_UpdateMouseStyle_001, TestSize.Level1)
{
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.pid_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateMouseStyle());
}

/**
 * @tc.name: InputWindowsManagerTest_CreatePointerSwiftObserver_001
 * @tc.desc: Test CreatePointerSwiftObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_CreatePointerSwiftObserver_001, TestSize.Level1)
{
    PointerDrawingManager pointerDrawingManager;
    isMagicCursor item;
    item.isShow = true;
    item.name = "test";
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.CreatePointerSwiftObserver(item));
}

/**
 * @tc.name: InputWindowsManagerTest_DrawCursor_001
 * @tc.desc: Test DrawCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawCursor_001, TestSize.Level1)
{
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
 * @tc.name: InputWindowsManagerTest_DrawPointerStyle_001
 * @tc.desc: Test DrawPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_DrawPointerStyle_001, TestSize.Level1)
{
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
 * @tc.name: InputWindowsManagerTest_CheckMouseIconPath_001
 * @tc.desc: Test CheckMouseIconPath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_CheckMouseIconPath_001, TestSize.Level1)
{
    PointerDrawingManager pointerDrawingManager;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.CheckMouseIconPath());
}
} // namespace MMI
} // namespace OHOS
