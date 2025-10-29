/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#ifndef USE_ROSEN_DRAWING
#define USE_ROSEN_DRAWING
#endif
#include "touch_drawing_manager.h"
#include "window_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TouchDrawingManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
constexpr int32_t ONE_SECOND = 1000;
} // namespace
class TouchDrawingManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void)
    {
        OLD::DisplayInfo info;
        info.id = 1;
        info.x = 1;
        info.y = 1;
        info.width = 1;
        info.height = 1;
        int32_t displayDpi = 240;
        info.dpi = displayDpi;
        info.name = "xx";
        info.uniq = "xx";
        info.direction = DIRECTION0;
        TOUCH_DRAWING_MGR->UpdateDisplayInfo(info);
    }

    void TearDown()
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(ONE_SECOND));
    }
};

/**
 * @tc.name: TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_001
 * @tc.desc: Test GetOriginalTouchScreenCoordinates
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t width = 100;
    int32_t height = 200;
    int32_t physicalX = 50;
    int32_t physicalY = 60;
    TOUCH_DRAWING_MGR->GetOriginalTouchScreenCoordinates(DIRECTION0, width, height, physicalX, physicalY);
    EXPECT_NE(physicalX, 100);
    EXPECT_NE(physicalY, 100);
}

/**
 * @tc.name: TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_002
 * @tc.desc: Test GetOriginalTouchScreenCoordinates
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t width = 100;
    int32_t height = 200;
    int32_t physicalX = 50;
    int32_t physicalY = 60;
    TOUCH_DRAWING_MGR->GetOriginalTouchScreenCoordinates(DIRECTION90, width, height, physicalX, physicalY);
    EXPECT_EQ(physicalX, 60);
    EXPECT_EQ(physicalY, 50);
}

/**
 * @tc.name: TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_003
 * @tc.desc: Test GetOriginalTouchScreenCoordinates
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t width = 100;
    int32_t height = 200;
    int32_t physicalX = 50;
    int32_t physicalY = 60;
    TOUCH_DRAWING_MGR->GetOriginalTouchScreenCoordinates(DIRECTION180, width, height, physicalX, physicalY);
    EXPECT_NE(physicalX, 100);
    EXPECT_NE(physicalY, 100);
}

/**
 * @tc.name: TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_004
 * @tc.desc: Test GetOriginalTouchScreenCoordinates
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_GetOriginalTouchScreenCoordinates_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t width = 100;
    int32_t height = 200;
    int32_t physicalX = 50;
    int32_t physicalY = 60;
    TOUCH_DRAWING_MGR->GetOriginalTouchScreenCoordinates(DIRECTION270, width, height, physicalX, physicalY);
    EXPECT_EQ(physicalX, 140);
    EXPECT_EQ(physicalY, 50);
}

/**
 * @tc.name: TouchDrawingManagerTest_RotationScreen_001
 * @tc.desc: Test TouchDrawingManager::RotationScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RotationScreen_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->LoadTouchDrawingHandler();
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->RotationScreen());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateLabels_001
 * @tc.desc: Test TouchDrawingManager::UpdateLabels
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateLabels_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->pointerMode_.isShow = true;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateLabels());
    EXPECT_NE(TOUCH_DRAWING_MGR->GetTouchDrawingHandler(), nullptr);
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateLabels_002
 * @tc.desc: Test TouchDrawingManager::UpdateLabels
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateLabels_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->pointerMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateLabels());
    EXPECT_EQ(TOUCH_DRAWING_MGR->GetTouchDrawingHandler(), nullptr);
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateBubbleData_001
 * @tc.desc: Test TouchDrawingManager::UpdateBubbleData
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateBubbleData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->bubbleMode_.isShow = true;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateBubbleData());
    EXPECT_NE(TOUCH_DRAWING_MGR->GetTouchDrawingHandler(), nullptr);
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateBubbleData_002
 * @tc.desc: Test TouchDrawingManager::UpdateBubbleData
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateBubbleData_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TOUCH_DRAWING_MGR->bubbleMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateBubbleData());
    EXPECT_EQ(TOUCH_DRAWING_MGR->GetTouchDrawingHandler(), nullptr);
}

/**
 * @tc.name: TouchDrawingManagerTest_LoadTouchDrawingHandler_001
 * @tc.desc: Test TouchDrawingManager::LoadTouchDrawingHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_LoadTouchDrawingHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->LoadTouchDrawingHandler());
    EXPECT_NE(TOUCH_DRAWING_MGR->GetTouchDrawingHandler(), nullptr);
}

/**
 * @tc.name: TouchDrawingManagerTest_TouchDrawHandler
 * @tc.desc: Test TouchDrawHandler
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_TouchDrawHandler, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(false);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetTargetDisplayId(10);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->TouchDrawHandler(pointerEvent));
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateDisplayInfo
 * @tc.desc: Test UpdateDisplayInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateDisplayInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(false);
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.width = 10;
    displayInfo.height = 20;
    displayInfo.validWidth = displayInfo.width;
    displayInfo.validHeight = displayInfo.height;
    displayInfo.direction = DIRECTION90;
    displayInfo.name = "Main Display";
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateDisplayInfo(displayInfo));
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateLabels
 * @tc.desc: Test UpdateLabels
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateLabels, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    TOUCH_DRAWING_MGR->pointerMode_.isShow = true;
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateLabels());

    TOUCH_DRAWING_MGR->pointerMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateLabels());
}

/**
 * @tc.name: TouchDrawingManagerTest_UpdateBubbleData
 * @tc.desc: Test UpdateBubbleData
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_UpdateBubbleData, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    TOUCH_DRAWING_MGR->bubbleMode_.isShow = true;
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateBubbleData());

    TOUCH_DRAWING_MGR->bubbleMode_.isShow = false;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->UpdateBubbleData());
}

/**
 * @tc.name: TouchDrawingManagerTest_IsWindowRotation
 * @tc.desc: Test IsWindowRotation
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_IsWindowRotation, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->IsWindowRotation());
}

/**
 * @tc.name: TouchDrawingManagerTest_SetDelegateProxy
 * @tc.desc: Test SetDelegateProxy
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_SetDelegateProxy, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    std::shared_ptr<DelegateInterface> proxy;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->SetDelegateProxy(proxy));
    EXPECT_EQ(TOUCH_DRAWING_MGR->delegateProxy_, proxy);
}

/**
 * @tc.name: TouchDrawingManagerTest_SetMultiWindowScreenId
 * @tc.desc: Test SetMultiWindowScreenId
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_SetMultiWindowScreenId, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    uint64_t screenId = 1000;
    uint64_t displayNodeScreenId = 0;
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetPressed(true);
    std::shared_ptr<DelegateInterface> proxy;
    EXPECT_NO_FATAL_FAILURE(TOUCH_DRAWING_MGR->SetMultiWindowScreenId(screenId, displayNodeScreenId));
}

/**
 * @tc.name: TouchDrawingManagerTest_ResetTouchWindow
 * @tc.desc: Test ResetTouchWindow
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_ResetTouchWindow, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.bubbleMode_.isShow = true;
    touchDrawingMgr.pointerMode_.isShow = true;
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.ResetTouchWindow());
    touchDrawingMgr.touchDrawingHandler_ = ComponentManager::LoadLibrary<ITouchDrawingHandler>(nullptr,
        "libmmi_touch_drawing_handler.z.so");
    EXPECT_NO_FATAL_FAILURE(touchDrawingMgr.ResetTouchWindow());
}

/**
 * @tc.name: TouchDrawingManagerTest_AddUpdateLabelsTimer_ShouldDoNothing_WhenTimerIsRunning
 * @tc.desc: Test AddUpdateLabelsTimer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_AddUpdateLabelsTimer_ShouldDoNothing_WhenTimerIsRunning,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.timerId_ = 1;
    touchDrawingMgr.AddUpdateLabelsTimer();
    EXPECT_EQ(touchDrawingMgr.timerId_, 1);
}

/**
 * @tc.name: TouchDrawingManagerTest_AddUpdateLabelsTimer_WhenTouchDrawingHandler
 * @tc.desc: Test AddUpdateLabelsTimer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_AddUpdateLabelsTimer_WhenTouchDrawingHandler,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.timerId_ = -1;
    touchDrawingMgr.LoadTouchDrawingHandler();
    touchDrawingMgr.AddUpdateLabelsTimer();
    EXPECT_NE(touchDrawingMgr.timerId_, -1);
}

/**
 * @tc.name: TouchDrawingManagerTest_RemoveUpdateLabelsTimer_ShouldRemoveTimer
 * @tc.desc: Test RemoveUpdateLabelsTimer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RemoveUpdateLabelsTimer_ShouldRemoveTimer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.timerId_ = 1;
    touchDrawingMgr.RemoveUpdateLabelsTimer();
    EXPECT_NE(touchDrawingMgr.timerId_, -2);
}

/**
 * @tc.name: TouchDrawingManagerTest_RemoveUpdateLabelsTimer_ShouldNotRemoveTimer
 * @tc.desc: Test RemoveUpdateLabelsTimer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(TouchDrawingManagerTest, TouchDrawingManagerTest_RemoveUpdateLabelsTimer_ShouldNotRemoveTimer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    TouchDrawingManager touchDrawingMgr;
    touchDrawingMgr.timerId_ = -1;
    touchDrawingMgr.RemoveUpdateLabelsTimer();
    EXPECT_EQ(touchDrawingMgr.timerId_, -1);
}
} // namespace MMI
} // namespace OHOS
