/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "input_windows_manager.h"
#include "input_windows_manager_mock.h"
#include "i_preference_manager.h"
#include "knuckle_drawing_manager.h"
#include "libinput_mock.h"
#include "mmi_log.h"
#include "parameters.h"
#include "pixel_map.h"
#include "pointer_drawing_manager.h"
#include "pointer_event.h"
#include "pointer_style.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerDrawingManagerSupTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;
constexpr int32_t MAX_POINTER_COLOR { 0x00ffffff };
constexpr int32_t AECH_DEVELOPER_DEFINED_STYLE { 47 };
constexpr int32_t AECH_DEVELOPER_DEFINED { 4 };
} // namespace

class PointerDrawingManagerSupTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {}
    void TearDown(void) {}
};

/**
 * @tc.name: PointerDrawingManagerSupTest_PostMoveRetryTask_001
 * @tc.desc: Test PostMoveRetryTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_PostMoveRetryTask_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::function<void()> task;
    PointerDrawingManager pointerDrawingManager;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager.PostMoveRetryTask(task));

    pointerDrawingManager.InitPointerCallback();
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager.PostMoveRetryTask(task));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_DrawDynamicHardwareCursor_001
 * @tc.desc: Test DrawDynamicHardwareCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_DrawDynamicHardwareCursor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    sptr<OHOS::Rosen::ScreenInfo> screenInfo = new OHOS::Rosen::ScreenInfo();
    auto screenpointer = std::make_shared<ScreenPointer>(hwcmgr, handler, screenInfo);
    ASSERT_NE(screenpointer, nullptr);
    RenderConfig cfg;
    PointerDrawingManager pointerDrawingManager;
    auto rlt = pointerDrawingManager.DrawDynamicHardwareCursor(screenpointer, cfg);
    EXPECT_EQ(rlt, RET_ERR);

    PointerRenderer renderer;
    ASSERT_TRUE(screenpointer->Init(renderer));
    screenpointer->bufferId_ = 5;
    cfg.style_ = TRANSPARENT_ICON;
    rlt = pointerDrawingManager.DrawDynamicHardwareCursor(screenpointer, cfg);
    EXPECT_EQ(rlt, RET_OK);
}

/**
 * @tc.name: PointerDrawingManagerSupTest_HardwareCursorDynamicRender_001
 * @tc.desc: Test HardwareCursorDynamicRender
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_HardwareCursorDynamicRender_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    sptr<OHOS::Rosen::ScreenInfo> screenInfo = new OHOS::Rosen::ScreenInfo();
    auto screenpointer = std::make_shared<ScreenPointer>(hwcmgr, handler, screenInfo);
    ASSERT_NE(screenpointer, nullptr);
    PointerDrawingManager pointerDrawingManager;

    pointerDrawingManager.screenPointers_[0] = screenpointer;

    MOUSE_ICON mouseStyle = MOUSE_ICON::LOADING;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager.HardwareCursorDynamicRender(mouseStyle));

    mouseStyle = MOUSE_ICON::RUNNING_RIGHT;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager.HardwareCursorDynamicRender(mouseStyle));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_DrawDynamicSoftCursor_001
 * @tc.desc: Test DrawDynamicSoftCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_DrawDynamicSoftCursor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "touch window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    auto sn = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NE(sn, nullptr);

    RenderConfig cfg;
    PointerDrawingManager pointerDrawingManager;
    auto rlt = pointerDrawingManager.DrawDynamicSoftCursor(sn, cfg);
    EXPECT_EQ(rlt, RET_OK);
}

/**
 * @tc.name: PointerDrawingManagerSupTest_SoftwareCursorDynamicRender_001
 * @tc.desc: Test SoftwareCursorDynamicRender
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SoftwareCursorDynamicRender_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    sptr<OHOS::Rosen::ScreenInfo> screenInfo = new OHOS::Rosen::ScreenInfo();
    auto screenpointer = std::make_shared<ScreenPointer>(hwcmgr, handler, screenInfo);
    ASSERT_NE(screenpointer, nullptr);
    PointerDrawingManager pointerDrawingManager;

    pointerDrawingManager.screenPointers_[0] = screenpointer;

    MOUSE_ICON mouseStyle = MOUSE_ICON::LOADING;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager.SoftwareCursorDynamicRender(mouseStyle));

    mouseStyle = MOUSE_ICON::RUNNING_RIGHT;
    EXPECT_NO_FATAL_FAILURE(pointerDrawingManager.SoftwareCursorDynamicRender(mouseStyle));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_RequestNextVSync_001
 * @tc.desc: Test RequestNextVSync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_RequestNextVSync_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    EXPECT_EQ(pointerDrawingManager.isRenderRunning_, false);
    auto rlt = pointerDrawingManager.RequestNextVSync();
    EXPECT_EQ(rlt, RET_ERR);
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
/**
 * @tc.name: PointerDrawingManagerSupTest_SetCursorLocation_002
 * @tc.desc: Test SetCursorLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SetCursorLocation_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    auto align = pointerDrawingManager.MouseIcon2IconType(MOUSE_ICON(2));
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager.lastMouseStyle_.id = 2;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetCursorLocation(physicalX, physicalY, align));
}
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

/**
 * @tc.name: PointerDrawingManagerSupTest_SetCursorLocation_003
 * @tc.desc: Test SetCursorLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SetCursorLocation_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    auto align = pointerDrawingManager.MouseIcon2IconType(MOUSE_ICON(2));
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetCursorLocation(physicalX, physicalY, align));
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    pointerDrawingManager.lastMouseStyle_.id = 2;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetCursorLocation(physicalX, physicalY, align));
    pointerDrawingManager.lastMouseStyle_.id = 42;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetCursorLocation(physicalX, physicalY, align));
    pointerDrawingManager.lastMouseStyle_.id = 43;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetCursorLocation(physicalX, physicalY, align));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_UpdateMouseStyle_001
 * @tc.desc: Test UpdateMouseStyle
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_UpdateMouseStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = AECH_DEVELOPER_DEFINED;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateMouseStyle());
    pointerStyle.id = AECH_DEVELOPER_DEFINED_STYLE;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateMouseStyle());

    pointerStyle.id = -2;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    pointerDrawingManager.pid_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateMouseStyle());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_UpdateStyleOptions_001
 * @tc.desc: Test UpdateStyleOptions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_UpdateStyleOptions_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerStyle.id = -2;
    pointerStyle.color = 0;
    pointerStyle.size = 2;
    pointerDrawingManager.pid_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateStyleOptions());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_InitVsync_001
 * @tc.desc: Test InitVsync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_InitVsync_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.InitVsync(MOUSE_ICON(MOUSE_ICON::DEVELOPER_DEFINED_ICON)));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_RetryGetSurfaceBuffer_001
 * @tc.desc: Test RetryGetSurfaceBuffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_RetryGetSurfaceBuffer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    auto layer = pointerDrawingManager.surfaceNode_->GetSurface();
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.RetryGetSurfaceBuffer(layer));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_PostTask_001
 * @tc.desc: Test PostTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_PostTask_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.PostTask([this]() {}));
    pointerDrawingManager.handler_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.PostTask([this]() {}));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_PostTask_002
 * @tc.desc: Test PostTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_PostTask_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    int32_t rsId = 10;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION90);
    pointerDrawingManager.runner_ = AppExecFwk::EventRunner::Create(false);
    pointerDrawingManager.handler_ = std::make_shared<AppExecFwk::EventHandler>(pointerDrawingManager.runner_);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.PostTask([this]() {}));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_PostSoftCursorTask_001
 * @tc.desc: Test PostSoftCursorTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_PostSoftCursorTask_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    pointerDrawingManager.softCursorHandler_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.PostSoftCursorTask([this]() {}));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_PostSoftCursorTask_002
 * @tc.desc: Test PostSoftCursorTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_PostSoftCursorTask_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    int32_t rsId = 10;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION90);
    pointerDrawingManager.softCursorRunner_ = AppExecFwk::EventRunner::Create(false);
    auto softCursorHander = std::make_shared<AppExecFwk::EventHandler>(pointerDrawingManager.softCursorRunner_);
    pointerDrawingManager.softCursorHandler_ = softCursorHander;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.PostSoftCursorTask([this]() {}));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_PostMoveRetryTask_002
 * @tc.desc: Test PostMoveRetryTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_PostMoveRetryTask_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    pointerDrawingManager.moveRetryHandler_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.PostMoveRetryTask([this]() {}));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_OnVsync_001
 * @tc.desc: Test OnVsync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_OnVsync_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    uint64_t timestamp = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnVsync(timestamp));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_OnVsync_002
 * @tc.desc: Test OnVsync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_OnVsync_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.currentMouseStyle_.id = MOUSE_ICON::RUNNING;
    uint64_t timestamp = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnVsync(timestamp));
    pointerDrawingManager.currentMouseStyle_.id = MOUSE_ICON::LOADING;
    pointerDrawingManager.mouseDisplayState_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnVsync(timestamp));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_OnVsync_003
 * @tc.desc: Test OnVsync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_OnVsync_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.currentMouseStyle_.id = MOUSE_ICON::RUNNING;
    uint64_t timestamp = 1;
    pointerDrawingManager.mouseDisplayState_ = true;
    pointerDrawingManager.currentMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnVsync(timestamp));
    pointerDrawingManager.currentMouseStyle_.id = MOUSE_ICON::LOADING;
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = 1;
    pointerDrawingManager.currentFrame_ = 0;
    pointerDrawingManager.frameCount_ = 0;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnVsync(timestamp));
    pointerDrawingManager.frameCount_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnVsync(timestamp));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_GetDisplayDirection_001
 * @tc.desc: Test GetDisplayDirection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_GetDisplayDirection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 10;
    displayInfo.width = 600;
    displayInfo.height = 600;
    displayInfo.direction = DIRECTION0;
    displayInfo.displayDirection = DIRECTION90;
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.GetDisplayDirection(&displayInfo));
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.GetDisplayDirection(&displayInfo));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_CreatePointerWindow_001
 * @tc.desc: Test CreatePointerWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_CreatePointerWindow_001, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t rsId = 10;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    pointerDrawingManager.surfaceNode_ = nullptr;
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = false;
    ASSERT_NO_FATAL_FAILURE(
        pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION90));
    ASSERT_NO_FATAL_FAILURE(
        pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION180));
    ASSERT_NO_FATAL_FAILURE(
        pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION270));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NO_FATAL_FAILURE(
        pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION90));
    ASSERT_NO_FATAL_FAILURE(
        pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION180));
    ASSERT_NO_FATAL_FAILURE(
        pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION270));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_CreatePointerWindow_002
 * @tc.desc: Test CreatePointerWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_CreatePointerWindow_002, TestSize.Level0)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t rsId = 10;
    int32_t physicalX = 100;
    int32_t physicalY = 100;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    OLD::DisplayInfo displaysInfo;
    displaysInfo.rsId = 102;
    displaysInfo.direction = DIRECTION0;
    displaysInfo.displayDirection = DIRECTION0;
    displaysInfo.width = 400;
    displaysInfo.height = 300;
    pointerDrawingManager.displayInfo_.rsId = 100;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.displayInfo_.width = 600;
    pointerDrawingManager.displayInfo_.height = 400;
    auto screenPointer = std::make_shared<ScreenPointer>(
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, displaysInfo);
    pointerDrawingManager.screenPointers_[rsId] = screenPointer;
    ASSERT_NO_FATAL_FAILURE(
        pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION90));
    ASSERT_NO_FATAL_FAILURE(
        pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION180));
    ASSERT_NO_FATAL_FAILURE(
        pointerDrawingManager.CreatePointerWindow(rsId, physicalX, physicalY, Direction::DIRECTION270));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_SetCustomCursor_001
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SetCustomCursor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = -1;
    int32_t windowId = 1;
    int32_t focusX = 2;
    int32_t focusY = 3;
    CursorPixelMap curPixelMap;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetCustomCursor(curPixelMap, pid, windowId, focusX, focusY));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_SetCustomCursor_002
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SetCustomCursor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = -1;
    int32_t focusX = 2;
    int32_t focusY = 3;
    CursorPixelMap curPixelMap;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetCustomCursor(curPixelMap, pid, windowId, focusX, focusY));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_SetCustomCursor_003
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SetCustomCursor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = 2;
    int32_t focusX = 2;
    int32_t focusY = 3;
    CursorPixelMap curPixelMap;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetCustomCursor(curPixelMap, pid, windowId, focusX, focusY));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_SetCustomCursor_004
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SetCustomCursor_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    int32_t windowId = 1;
    int32_t focusX = 2;
    int32_t focusY = 3;
    CursorPixelMap curPixelMap;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetCustomCursor(curPixelMap, pid, windowId, focusX, focusY));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_SetMouseHotSpot_001
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SetMouseHotSpot_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 2;
    int32_t windowId = 2;
    int32_t hotSpotX = 3;
    int32_t hotSpotY = 4;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    inputWindowsManager->globalStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_SetMouseHotSpot_002
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SetMouseHotSpot_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 2;
    int32_t windowId = 2;
    int32_t hotSpotX = 3;
    int32_t hotSpotY = 4;
    std::shared_ptr<InputWindowsManager> inputWindowsManager = std::make_shared<InputWindowsManager>();
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    inputWindowsManager->globalStyle_.id = MOUSE_ICON::DEFAULT;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_LoadCursorSvgWithColor_001
 * @tc.desc: Test LoadCursorSvgWithColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_LoadCursorSvgWithColor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    IconStyle iconStyle;
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    iconStyle.alignmentWay = 0;
    iconStyle.iconPath = "testpath";
    pointerDrawingManager.mouseIcons_.insert(std::make_pair(static_cast<MOUSE_ICON>(pointerStyle.id), iconStyle));
    pointerDrawingManager.tempPointerColor_ = -1;
    int32_t color = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.LoadCursorSvgWithColor(MOUSE_ICON::DEVELOPER_DEFINED_ICON, color));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_LoadCursorSvgWithColor_002
 * @tc.desc: Test LoadCursorSvgWithColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_LoadCursorSvgWithColor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    IconStyle iconStyle;
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    iconStyle.alignmentWay = 0;
    iconStyle.iconPath = "testpath";
    pointerDrawingManager.mouseIcons_.insert(std::make_pair(static_cast<MOUSE_ICON>(pointerStyle.id), iconStyle));
    pointerDrawingManager.tempPointerColor_ = 1;
    int32_t color = 0;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.LoadCursorSvgWithColor(MOUSE_ICON::DEVELOPER_DEFINED_ICON, color));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_LoadCursorSvgWithColor_003
 * @tc.desc: Test LoadCursorSvgWithColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_LoadCursorSvgWithColor_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    IconStyle iconStyle;
    pointerStyle.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    iconStyle.alignmentWay = 0;
    iconStyle.iconPath = "testpath";
    pointerDrawingManager.mouseIcons_.insert(std::make_pair(static_cast<MOUSE_ICON>(pointerStyle.id), iconStyle));
    pointerDrawingManager.tempPointerColor_ = -1;
    int32_t color = MAX_POINTER_COLOR;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.LoadCursorSvgWithColor(MOUSE_ICON::DEVELOPER_DEFINED_ICON, color));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_DecodeImageToPixelMap_001
 * @tc.desc: Test DecodeImageToPixelMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_DecodeImageToPixelMap_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerDrawingManager.InitPixelMaps();
    pointerDrawingManager.imageWidth_ = 2;
    pointerDrawingManager.imageHeight_ = 2;
    pointerDrawingManager.tempPointerColor_ = 2;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DecodeImageToPixelMap(MOUSE_ICON::LOADING));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_DecodeImageToPixelMap_002
 * @tc.desc: Test DecodeImageToPixelMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_DecodeImageToPixelMap_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    PointerStyle pointerStyle;
    pointerDrawingManager.InitPixelMaps();
    pointerDrawingManager.imageWidth_ = 2;
    pointerDrawingManager.imageHeight_ = 2;
    pointerDrawingManager.tempPointerColor_ = 2;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DecodeImageToPixelMap(MOUSE_ICON::RUNNING));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_UpdateDisplayInfo_001
 * @tc.desc: Test UpdateDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_UpdateDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t rsId = 10;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;

    OLD::DisplayInfo displaysInfo;
    displaysInfo.rsId = 102;
    displaysInfo.direction = DIRECTION0;
    displaysInfo.displayDirection = DIRECTION0;
    displaysInfo.width = 400;
    displaysInfo.height = 300;
    pointerDrawingManager.displayInfo_.rsId = 100;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.displayInfo_.width = 600;
    pointerDrawingManager.displayInfo_.height = 400;

    auto screenPointer = std::make_shared<ScreenPointer>(
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, displaysInfo);
    pointerDrawingManager.screenPointers_[rsId] = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateDisplayInfo(displaysInfo));
    pointerDrawingManager.screenPointers_[rsId] = screenPointer;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateDisplayInfo(displaysInfo));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_SetPointerSize_001
 * @tc.desc: Test SetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SetPointerSize_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t size = 10;
    pointerDrawingManager.lastMouseStyle_.id = MOUSE_ICON::CURSOR_CIRCLE;
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetPointerSize(size));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_SetPointerSize_002
 * @tc.desc: Test SetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SetPointerSize_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t size = 10;
    pointerDrawingManager.lastMouseStyle_.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SetPointerSize(size));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_AttachAllSurfaceNode_001
 * @tc.desc: Test AttachAllSurfaceNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_AttachAllSurfaceNode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t rsId = 10;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;

    OLD::DisplayInfo displaysInfo;
    displaysInfo.rsId = 102;
    displaysInfo.direction = DIRECTION0;
    displaysInfo.displayDirection = DIRECTION0;
    displaysInfo.width = 400;
    displaysInfo.height = 300;
    pointerDrawingManager.displayInfo_.rsId = 100;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.displayInfo_.width = 600;
    pointerDrawingManager.displayInfo_.height = 400;

    auto screenPointer = std::make_shared<ScreenPointer>(
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, displaysInfo);
    pointerDrawingManager.screenPointers_[rsId] = screenPointer;
    pointerDrawingManager.screenId_ = 100;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AttachAllSurfaceNode());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_AttachAllSurfaceNode_002
 * @tc.desc: Test AttachAllSurfaceNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_AttachAllSurfaceNode_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t rsId = 10;
    pointerDrawingManager.surfaceNode_ = nullptr;
    pointerDrawingManager.screenPointers_[rsId] = nullptr;
    pointerDrawingManager.screenId_ = 100;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AttachAllSurfaceNode());
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.AttachAllSurfaceNode());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_DetachAllSurfaceNode_001
 * @tc.desc: Test DetachAllSurfaceNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_DetachAllSurfaceNode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t rsId = 10;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;

    OLD::DisplayInfo displaysInfo;
    displaysInfo.rsId = 102;
    displaysInfo.direction = DIRECTION0;
    displaysInfo.displayDirection = DIRECTION0;
    displaysInfo.width = 400;
    displaysInfo.height = 300;
    pointerDrawingManager.displayInfo_.rsId = 100;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.displayInfo_.width = 600;
    pointerDrawingManager.displayInfo_.height = 400;

    auto screenPointer = std::make_shared<ScreenPointer>(
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, displaysInfo);
    pointerDrawingManager.screenPointers_[rsId] = screenPointer;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DetachAllSurfaceNode());
    pointerDrawingManager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DetachAllSurfaceNode());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_DetachAllSurfaceNode_002
 * @tc.desc: Test DetachAllSurfaceNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_DetachAllSurfaceNode_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t rsId = 0;
    pointerDrawingManager.surfaceNode_ = nullptr;
    pointerDrawingManager.screenPointers_[rsId] = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DetachAllSurfaceNode());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_DeletePointerVisible_001
 * @tc.desc: Test DeletePointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_DeletePointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    int32_t pid = 1;
    pointerDrawingManager.InitPointerCallback();
    pointerDrawingManager.surfaceNode_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DeletePointerVisible(pid));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DeletePointerVisible(pid));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_OnSessionLost_001
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_OnSessionLost_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.pidInfos_.clear();
    int32_t pid = 1;
    PointerDrawingManager::PidInfo pidInfo;
    for (int32_t i = 1; i < 3; i++) {
        pidInfo.pid = 3 - i;
        pidInfo.visible = false;
        pointerDrawingManager.hapPidInfos_.push_back(pidInfo);
    }
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnSessionLost(pid));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_OnSessionLost_002
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_OnSessionLost_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.pidInfos_.clear();
    int32_t pid = 10;
    PointerDrawingManager::PidInfo pidInfo;
    for (int32_t i = 1; i < 3; i++) {
        pidInfo.pid = 3 - i;
        pidInfo.visible = false;
        pointerDrawingManager.hapPidInfos_.push_back(pidInfo);
    }
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnSessionLost(pid));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_SubscribeScreenModeChange_001
 * @tc.desc: Test SubscribeScreenModeChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SubscribeScreenModeChange_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hardwareCursorPointerManager_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SubscribeScreenModeChange());
    pointerDrawingManager.hardwareCursorPointerManager_ = std::make_shared<HardwareCursorPointerManager>();
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SubscribeScreenModeChange());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_RegisterDisplayStatusReceiver_001
 * @tc.desc: Test RegisterDisplayStatusReceiver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_RegisterDisplayStatusReceiver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hardwareCursorPointerManager_ = nullptr;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.RegisterDisplayStatusReceiver());
    pointerDrawingManager.hardwareCursorPointerManager_ = std::make_shared<HardwareCursorPointerManager>();
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.RegisterDisplayStatusReceiver());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_RegisterDisplayStatusReceiver_002
 * @tc.desc: Test RegisterDisplayStatusReceiver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_RegisterDisplayStatusReceiver_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.hardwareCursorPointerManager_ = std::make_shared<HardwareCursorPointerManager>();
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    pointerDrawingManager.initDisplayStatusReceiverFlag_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.RegisterDisplayStatusReceiver());
    pointerDrawingManager.initDisplayStatusReceiverFlag_ = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.RegisterDisplayStatusReceiver());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_UpdateBindDisplayId_001
 * @tc.desc: Test UpdateBindDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_UpdateBindDisplayId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.lastDisplayId_ = 0;
    uint64_t rsId = 1;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    pointerDrawingManager.hardwareCursorPointerManager_ = std::make_shared<HardwareCursorPointerManager>();
    pointerDrawingManager.hardwareCursorPointerManager_->SetHdiServiceState(true);
    pointerDrawingManager.hardwareCursorPointerManager_->isEnableState_ = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.UpdateBindDisplayId(rsId));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_OnScreenModeChange_001
 * @tc.desc: Test OnScreenModeChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_OnScreenModeChange_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    std::vector<sptr<OHOS::Rosen::ScreenInfo>> screenInfos;
    OLD::DisplayInfo displaysInfo;
    displaysInfo.rsId = 102;
    displaysInfo.direction = DIRECTION0;
    displaysInfo.displayDirection = DIRECTION0;
    displaysInfo.width = 400;
    displaysInfo.height = 300;
    pointerDrawingManager.displayInfo_.rsId = 100;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.displayInfo_.width = 600;
    pointerDrawingManager.displayInfo_.height = 400;
    auto spMirror = std::make_shared<ScreenPointer>(
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, displaysInfo);
    spMirror->mode_ = mode_t::SCREEN_MIRROR;
    spMirror->displayDirection_ = DIRECTION0;
    pointerDrawingManager.screenPointers_[displaysInfo.rsId] = spMirror;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.OnScreenModeChange(screenInfos));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_CreateRenderConfig_001
 * @tc.desc: Test CreateRenderConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_CreateRenderConfig_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    RenderConfig cfg;
    OLD::DisplayInfo displayInfo;
    std::shared_ptr<ScreenPointer> screenpointer = std::make_shared<ScreenPointer>(nullptr, nullptr, displayInfo);
    MOUSE_ICON mouseStyle = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    bool isHard = true;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.CreateRenderConfig(cfg, screenpointer, mouseStyle, isHard));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_CreateRenderConfig_002
 * @tc.desc: Test CreateRenderConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_CreateRenderConfig_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    RenderConfig cfg;
    OLD::DisplayInfo displayInfo;
    std::shared_ptr<ScreenPointer> screenpointer = std::make_shared<ScreenPointer>(nullptr, nullptr, displayInfo);
    MOUSE_ICON mouseStyle = MOUSE_ICON::DEFAULT;
    bool isHard = false;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.CreateRenderConfig(cfg, screenpointer, mouseStyle, isHard));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_SoftwareCursorRender_001
 * @tc.desc: Test SoftwareCursorRender
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_SoftwareCursorRender_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displaysInfo;
    displaysInfo.rsId = 102;
    displaysInfo.direction = DIRECTION0;
    displaysInfo.displayDirection = DIRECTION0;
    displaysInfo.width = 400;
    displaysInfo.height = 300;
    pointerDrawingManager.displayInfo_.rsId = 100;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.displayInfo_.width = 600;
    pointerDrawingManager.displayInfo_.height = 400;
    auto spMirror = std::make_shared<ScreenPointer>(
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, displaysInfo);
    spMirror->mode_ = mode_t::SCREEN_MIRROR;
    spMirror->displayDirection_ = DIRECTION0;
    pointerDrawingManager.screenPointers_[displaysInfo.rsId] = spMirror;
    pointerDrawingManager.screenId_ = 100;
    MOUSE_ICON mouseStyle = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SoftwareCursorRender(mouseStyle));
    pointerDrawingManager.screenId_ = 102;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SoftwareCursorRender(mouseStyle));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_DrawSoftCursor_001
 * @tc.desc: Test DrawSoftCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_DrawSoftCursor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    RenderConfig cfg;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    auto surfaceNode = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawSoftCursor(surfaceNode, cfg));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_DrawHardCursor_001
 * @tc.desc: Test DrawHardCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_DrawHardCursor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    RenderConfig cfg;
    OLD::DisplayInfo displaysInfo;
    cfg.style_ = TRANSPARENT_ICON;
    displaysInfo.rsId = 102;
    displaysInfo.direction = DIRECTION0;
    displaysInfo.displayDirection = DIRECTION0;
    displaysInfo.width = 400;
    displaysInfo.height = 300;
    pointerDrawingManager.displayInfo_.rsId = 100;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.displayInfo_.width = 600;
    pointerDrawingManager.displayInfo_.height = 400;
    auto sp = std::make_shared<ScreenPointer>(
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, displaysInfo);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.DrawHardCursor(sp, cfg));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_GetMirrorScreenPointers_001
 * @tc.desc: Test GetMirrorScreenPointers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_GetMirrorScreenPointers_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displaysInfo;

    displaysInfo.rsId = 102;
    displaysInfo.direction = DIRECTION0;
    displaysInfo.displayDirection = DIRECTION0;
    displaysInfo.width = 400;
    displaysInfo.height = 300;
    pointerDrawingManager.displayInfo_.rsId = 100;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.displayInfo_.width = 600;
    pointerDrawingManager.displayInfo_.height = 400;

    auto spMirror = std::make_shared<ScreenPointer>(
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, displaysInfo);
    spMirror->mode_ = mode_t::SCREEN_MIRROR;
    spMirror->displayDirection_ = DIRECTION0;
    pointerDrawingManager.screenPointers_[displaysInfo.rsId] = spMirror;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.GetMirrorScreenPointers());
    spMirror->mode_ = mode_t::SCREEN_MAIN;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.GetMirrorScreenPointers());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_HardwareCursorMove_001
 * @tc.desc: Test HardwareCursorMove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_HardwareCursorMove_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displaysInfo;
    int32_t x = 1;
    int32_t y = 1;
    ICON_TYPE align = ANGLE_E;

    displaysInfo.rsId = 100;
    displaysInfo.direction = DIRECTION0;
    displaysInfo.displayDirection = DIRECTION0;
    displaysInfo.width = 400;
    displaysInfo.height = 300;
    pointerDrawingManager.displayInfo_.rsId = 101;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.displayInfo_.width = 600;
    pointerDrawingManager.displayInfo_.height = 400;

    auto spMirror = std::make_shared<ScreenPointer>(
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, displaysInfo);
    spMirror->mode_ = mode_t::SCREEN_MIRROR;
    spMirror->displayDirection_ = DIRECTION0;
    pointerDrawingManager.screenPointers_[displaysInfo.rsId] = spMirror;
    pointerDrawingManager.displayId_ = 100;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.HardwareCursorMove(x, y, align));
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SoftwareCursorMove(x, y, align));
    spMirror->mode_ = mode_t::SCREEN_EXTEND;
    pointerDrawingManager.displayId_ = 200;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.HardwareCursorMove(x, y, align));
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.SoftwareCursorMoveAsync(x, y, align));
}

/**
 * @tc.name: PointerDrawingManagerSupTest_CheckHwcReady_001
 * @tc.desc: Test CheckHwcReady
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_CheckHwcReady_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displaysInfo;

    displaysInfo.rsId = 100;
    displaysInfo.direction = DIRECTION0;
    displaysInfo.displayDirection = DIRECTION0;
    displaysInfo.width = 400;
    displaysInfo.height = 300;
    pointerDrawingManager.displayInfo_.rsId = 101;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.displayInfo_.width = 600;
    pointerDrawingManager.displayInfo_.height = 400;

    auto spMirror = std::make_shared<ScreenPointer>(
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, displaysInfo);
    spMirror->mode_ = mode_t::SCREEN_MIRROR;
    spMirror->displayDirection_ = DIRECTION0;
    pointerDrawingManager.screenPointers_[displaysInfo.rsId] = spMirror;
    pointerDrawingManager.displayId_ = 100;
    pointerDrawingManager.lastPhysicalX_ = 1;
    pointerDrawingManager.lastPhysicalY_ = 1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.CheckHwcReady());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_ResetMoveRetryTimer_001
 * @tc.desc: Test ResetMoveRetryTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_ResetMoveRetryTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.moveRetryTimerId_ = -1;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.ResetMoveRetryTimer());
    pointerDrawingManager.moveRetryTimerId_ = 2;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.ResetMoveRetryTimer());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_HideHardwareCursors_001
 * @tc.desc: Test HideHardwareCursors
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_HideHardwareCursors_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    OLD::DisplayInfo displaysInfo;

    displaysInfo.rsId = 100;
    displaysInfo.direction = DIRECTION0;
    displaysInfo.displayDirection = DIRECTION0;
    displaysInfo.width = 400;
    displaysInfo.height = 300;
    pointerDrawingManager.displayInfo_.rsId = 101;
    pointerDrawingManager.displayInfo_.direction = DIRECTION0;
    pointerDrawingManager.displayInfo_.displayDirection = DIRECTION0;
    pointerDrawingManager.displayInfo_.width = 600;
    pointerDrawingManager.displayInfo_.height = 400;

    auto spMirror = std::make_shared<ScreenPointer>(
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, displaysInfo);
    spMirror->mode_ = mode_t::SCREEN_MIRROR;
    spMirror->displayDirection_ = DIRECTION0;
    pointerDrawingManager.screenPointers_[displaysInfo.rsId] = spMirror;
    pointerDrawingManager.screenId_ = 100;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.HideHardwareCursors());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_GetUserIconCopy_001
 * @tc.desc: Test GetUserIconCopy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_GetUserIconCopy_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager.followSystem_ = true;
    pointerDrawingManager.cursorWidth_ = 300;
    pointerDrawingManager.cursorHeight_ = 300;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.GetUserIconCopy());
    pointerDrawingManager.cursorWidth_ = 200;
    pointerDrawingManager.cursorHeight_ = 200;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.GetUserIconCopy());
}

/**
 * @tc.name: PointerDrawingManagerSupTest_GetUserIconCopy_002
 * @tc.desc: Test GetUserIconCopy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_GetUserIconCopy_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    pointerDrawingManager.userIcon_ = std::make_unique<OHOS::Media::PixelMap>();
    pointerDrawingManager.followSystem_ = false;
    pointerDrawingManager.cursorWidth_ = 300;
    pointerDrawingManager.cursorHeight_ = 300;
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.GetUserIconCopy());
}
} // namespace MMI
} // namespace OHOS