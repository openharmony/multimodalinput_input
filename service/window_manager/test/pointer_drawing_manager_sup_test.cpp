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
    EXPECT_EQ(pointerDrawingManager.isRenderRuning_, false);
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
 * @tc.name: PointerDrawingManagerSupTest_CreatePointerSwitchObserver_002
 * @tc.desc: Test CreatePointerSwitchObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerSupTest, PointerDrawingManagerSupTest_CreatePointerSwitchObserver_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    isMagicCursor item;
    item.isShow = true;
    item.name = "test";
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_NO_FATAL_FAILURE(pointerDrawingManager.CreatePointerSwitchObserver(item));
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
    pointerDrawingManager.softCursorHander_ = nullptr;
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
    pointerDrawingManager.softCursorHander_ = softCursorHander;
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
    pointerDrawingManager.moveRetryHander_ = nullptr;
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
} // namespace MMI
} // namespace OHOS