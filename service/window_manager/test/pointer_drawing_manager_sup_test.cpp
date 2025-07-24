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
} // namespace MMI
} // namespace OHOS