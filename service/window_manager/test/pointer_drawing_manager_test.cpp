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
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.SetMouseDisplayState(true);
    bool mouseDisplayState = pointerDrawingManager.GetMouseDisplayState();
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
    PointerDrawingManager pointerDrawingManager;
    EXPECT_EQ(pointerDrawingManager.pidInfos_.size(), 0);
    pointerDrawingManager.UpdatePointerDevice(true, true, true);
    EXPECT_EQ(pointerDrawingManager.pidInfos_.size(), 1);
    pointerDrawingManager.UpdatePointerDevice(false, true, true);
    EXPECT_EQ(pointerDrawingManager.pidInfos_.size(), 0);
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustMouseFocusByDirection0_001
 * @tc.desc: Test AdjustMouseFocusByDirection0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerTest, InputWindowsManagerTest_AdjustMouseFocusByDirection0_001, TestSize.Level1)
{
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.imageWidth_ = 50;
    pointerDrawingManager.imageHeight_ = 50;
    pointerDrawingManager.userIconHotSpotX_ = 5;
    pointerDrawingManager.userIconHotSpotY_ = 5;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection0(ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 50);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection0(ANGLE_CENTER, physicalX, physicalY);
    EXPECT_EQ(physicalX, 75);
    EXPECT_EQ(physicalY, 75);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection0(ANGLE_NW_RIGHT, physicalX, physicalY);
    EXPECT_EQ(physicalX, 95);
    EXPECT_EQ(physicalY, 100);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager.currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerDrawingManager.AdjustMouseFocusByDirection0(ANGLE_NW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 95);
    EXPECT_EQ(physicalY, 95);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection0(ANGLE_E, physicalX, physicalY);
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
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.imageWidth_ = 50;
    pointerDrawingManager.imageHeight_ = 50;
    pointerDrawingManager.userIconHotSpotX_ = 5;
    pointerDrawingManager.userIconHotSpotY_ = 5;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection90(ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 150);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection90(ANGLE_CENTER, physicalX, physicalY);
    EXPECT_EQ(physicalX, 75);
    EXPECT_EQ(physicalY, 125);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection90(ANGLE_NW_RIGHT, physicalX, physicalY);
    EXPECT_EQ(physicalX, 95);
    EXPECT_EQ(physicalY, 100);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager.currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerDrawingManager.AdjustMouseFocusByDirection90(ANGLE_NW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 95);
    EXPECT_EQ(physicalY, 105);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection90(ANGLE_E, physicalX, physicalY);
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
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.imageWidth_ = 50;
    pointerDrawingManager.imageHeight_ = 50;
    pointerDrawingManager.userIconHotSpotX_ = 5;
    pointerDrawingManager.userIconHotSpotY_ = 5;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection180(ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 150);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection180(ANGLE_CENTER, physicalX, physicalY);
    EXPECT_EQ(physicalX, 125);
    EXPECT_EQ(physicalY, 125);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection180(ANGLE_NW_RIGHT, physicalX, physicalY);
    EXPECT_EQ(physicalX, 105);
    EXPECT_EQ(physicalY, 100);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager.currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerDrawingManager.AdjustMouseFocusByDirection180(ANGLE_NW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 105);
    EXPECT_EQ(physicalY, 105);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection180(ANGLE_E, physicalX, physicalY);
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
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.imageWidth_ = 50;
    pointerDrawingManager.imageHeight_ = 50;
    pointerDrawingManager.userIconHotSpotX_ = 5;
    pointerDrawingManager.userIconHotSpotY_ = 5;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection270(ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 50);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection270(ANGLE_CENTER, physicalX, physicalY);
    EXPECT_EQ(physicalX, 125);
    EXPECT_EQ(physicalY, 75);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection270(ANGLE_NW_RIGHT, physicalX, physicalY);
    EXPECT_EQ(physicalX, 105);
    EXPECT_EQ(physicalY, 100);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager.currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    pointerDrawingManager.AdjustMouseFocusByDirection270(ANGLE_NW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 105);
    EXPECT_EQ(physicalY, 95);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.AdjustMouseFocusByDirection270(ANGLE_E, physicalX, physicalY);
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
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.imageWidth_ = 50;
    pointerDrawingManager.imageHeight_ = 50;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager.RotateDegree(DIRECTION0);
    pointerDrawingManager.AdjustMouseFocus(DIRECTION0, ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 50);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.RotateDegree(DIRECTION90);
    pointerDrawingManager.AdjustMouseFocus(DIRECTION90, ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 150);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.RotateDegree(DIRECTION180);
    pointerDrawingManager.AdjustMouseFocus(DIRECTION180, ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 150);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.RotateDegree(DIRECTION270);
    pointerDrawingManager.AdjustMouseFocus(DIRECTION270, ANGLE_SW, physicalX, physicalY);
    EXPECT_EQ(physicalX, 100);
    EXPECT_EQ(physicalY, 50);
    physicalX = 100;
    physicalY = 100;
    pointerDrawingManager.RotateDegree(static_cast<Direction>(4));
    pointerDrawingManager.AdjustMouseFocus(static_cast<Direction>(4), ANGLE_SW, physicalX, physicalY);
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
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.SetPointerColor(-1);
    int32_t color = pointerDrawingManager.GetPointerColor();
    EXPECT_EQ(color, 0);
    pointerDrawingManager.SetPointerColor(16777216);
    color = pointerDrawingManager.GetPointerColor();
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
    PointerDrawingManager pointerDrawingManager;
    for (int32_t i = 1; i < 102; i++) {
        pointerDrawingManager.SetPointerVisible(i, false);
    }
    bool visible = pointerDrawingManager.GetPointerVisible(1);
    EXPECT_EQ(visible, true);
    pointerDrawingManager.SetPointerVisible(11, true);
    visible = pointerDrawingManager.GetPointerVisible(11);
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
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerDrawingManager.SetPointerStyle(1, -1, pointerStyle);
    PointerStyle pointerStyleTmp;
    pointerDrawingManager.GetPointerStyle(1, -1, pointerStyleTmp);
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
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.SetPointerSize(0);
    int32_t pointerSize = pointerDrawingManager.GetPointerSize();
    EXPECT_EQ(pointerSize, 1);
    pointerDrawingManager.SetPointerSize(8);
    pointerSize = pointerDrawingManager.GetPointerSize();
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
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    pointerDrawingManager.displayInfo_.width = 500;
    pointerDrawingManager.displayInfo_.height = 1100;
    pointerDrawingManager.imageWidth_ = 48;
    pointerDrawingManager.imageHeight_ = 48;
    int32_t physicalX = 500;
    int32_t physicalY = 1100;
    pointerDrawingManager.FixCursorPosition(physicalX, physicalY);
    EXPECT_EQ(physicalX, 497);
    EXPECT_EQ(physicalY, 1097);
    pointerDrawingManager.displayInfo_.direction = DIRECTION90;
    physicalX = 1100;
    physicalY = 500;
    pointerDrawingManager.FixCursorPosition(physicalX, physicalY);
    EXPECT_EQ(physicalX, 1097);
    EXPECT_EQ(physicalY, 497);
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION90;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    physicalX = 500;
    physicalY = 1100;
    pointerDrawingManager.FixCursorPosition(physicalX, physicalY);
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
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    pointerDrawingManager.DrawPointer(1, 100, 100, pointerStyle, DIRECTION180);
    EXPECT_EQ(pointerDrawingManager.lastDirection_, DIRECTION180);
    pointerDrawingManager.DrawPointer(1, 200, 200, pointerStyle, DIRECTION270);
    EXPECT_EQ(pointerDrawingManager.lastDirection_, DIRECTION270);
}
} // namespace MMI
} // namespace OHOS
