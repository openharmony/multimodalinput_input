/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "mmi_log.h"
#include "pointer_event.h"
#include "touch_drawing_manager.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "TouchDrawingManagerTest" };
} // namespace
class TouchDrawingManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void)
    {
        // 创建displayInfo_
        DisplayInfo info;
        info.id = 1;
        info.x =1;
        info.y = 1;
        info.width = 1;
        info.height = 1;
        int32_t displayDpi = 240;
        info.dpi = displayDpi;
        info.name = "xx";
        info.uniq = "xx";
        info.direction = DIRECTION0;
        TouchDrawingMgr->UpdateDisplayInfo(info);
    } // void SetUp(void)
};

/**
 * @tc.name: TouchDrawingManagerTest_TouchDrawHandler_001
 * @tc.desc: Test TouchDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_TouchDrawHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    int32_t displayX = 100;
    int32_t displayY = 100;
    item.SetDisplayX(displayX);
    item.SetDisplayY(displayY);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(TouchDrawingMgr->TouchDrawHandler(pointerEvent));
}

/**
 * @tc.name: TouchDrawingManagerTest_TouchDrawHandler_002
 * @tc.desc: Test TouchDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_TouchDrawHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);

    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    int32_t displayX = 200;
    int32_t displayY = 200;
    item.SetDisplayX(displayX);
    item.SetDisplayY(displayY);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetPointerId(0);
    pointerEvent->AddPointerItem(item);
    EXPECT_NO_FATAL_FAILURE(TouchDrawingMgr->TouchDrawHandler(pointerEvent));
}

/**
 * @tc.name: TouchDrawingManagerTest_IsValidAction_001
 * @tc.desc: Test is valid action
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_IsValidAction_001, TestSize.Level1)
{
    TouchDrawingManager manager;
    bool ret = manager.IsValidAction(PointerEvent::POINTER_ACTION_DOWN);
    EXPECT_TRUE(ret);
    ret = manager.IsValidAction(PointerEvent::POINTER_ACTION_PULL_DOWN);
    EXPECT_TRUE(ret);
    ret = manager.IsValidAction(PointerEvent::POINTER_ACTION_MOVE);
    EXPECT_TRUE(ret);
    ret = manager.IsValidAction(PointerEvent::POINTER_ACTION_PULL_MOVE);
    EXPECT_TRUE(ret);
    ret = manager.IsValidAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_TRUE(ret);
    ret = manager.IsValidAction(PointerEvent::POINTER_ACTION_PULL_UP);
    EXPECT_TRUE(ret);
    ret = manager.IsValidAction(100);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateDisplayInfo_001
 * @tc.desc: Test update display info
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t DENSITY_BASELINE = 160;
    int32_t INDEPENDENT_INNER_PIXELS = 20;
    int32_t INDEPENDENT_OUTER_PIXELS = 21;
    int32_t INDEPENDENT_WIDTH_PIXELS = 2;
    int32_t CALCULATE_MIDDLE = 2;
    TouchDrawingManager manager;
    DisplayInfo displayInfo;
    displayInfo.dpi = 160;
    manager.UpdateDisplayInfo(displayInfo);
    EXPECT_EQ(manager.bubble_.innerCircleRadius,
    displayInfo.dpi * INDEPENDENT_INNER_PIXELS / DENSITY_BASELINE / CALCULATE_MIDDLE);
    EXPECT_EQ(manager.bubble_.outerCircleRadius,
    displayInfo.dpi * INDEPENDENT_OUTER_PIXELS / DENSITY_BASELINE / CALCULATE_MIDDLE);
    EXPECT_EQ(manager.bubble_.outerCircleWidth,
    static_cast<float>(displayInfo.dpi * INDEPENDENT_WIDTH_PIXELS) / DENSITY_BASELINE);
    EXPECT_NO_FATAL_FAILURE(manager.UpdateDisplayInfo(displayInfo));
}

/**
 * @tc.name: TouchDrawingManagerTest_StartTouchDraw_001
 * @tc.desc: Test start touch draw
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_StartTouchDraw_001, TestSize.Level1)
{
    TouchDrawingManager manager;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    EXPECT_NO_FATAL_FAILURE(manager.StartTouchDraw(pointerEvent));
}

/**
 * @tc.name: TouchDrawingManagerTest_DrawGraphic_001
 * @tc.desc: Test draw graphic
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_DrawGraphic_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager manager;
    EXPECT_EQ(manager.DrawGraphic(nullptr), RET_ERR);
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    manager.canvasNode_ = nullptr;
    EXPECT_EQ(manager.DrawGraphic(pointerEvent), RET_ERR);
    pointerEvent->SetPointerId(PointerEvent::POINTER_ACTION_UP);
    EXPECT_EQ(manager.DrawGraphic(pointerEvent), RET_ERR);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    manager.displayInfo_.displayDirection = DIRECTION0;
    EXPECT_EQ(manager.DrawGraphic(pointerEvent), RET_ERR);
}
} // namespace MMI
} // namespace OHOS
