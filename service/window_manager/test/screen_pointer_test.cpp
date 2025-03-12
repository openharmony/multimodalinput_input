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

#include "mmi_log.h"
#include "screen_pointer.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "ScreenPointerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace
class ScreenPointerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {};
};

/**
 * @tc.name: ScreenPointerTest_GetRenderDPI_001
 * @tc.desc: Test GetRenderDPI
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_GetRenderDPI_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = nullptr;
    handler_ptr_t handler = nullptr;
    DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->isCurrentOffScreenRendering_ = true;
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    float ret = screenpointer->GetRenderDPI();
    EXPECT_EQ(ret, 0);
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    ret = screenpointer->GetRenderDPI();
    screenpointer->isCurrentOffScreenRendering_ = false;
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    ret = screenpointer->GetRenderDPI();
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    ret = screenpointer->GetRenderDPI();
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: ScreenPointerTest_SetInvisible_001
 * @tc.desc: Test SetInvisible
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_SetInvisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    bool ret = screenpointer->SetInvisible();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ScreenPointerTest_MoveSoft_001
 * @tc.desc: Test MoveSoft
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_MoveSoft_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    const char* RS_SURFACE_NODE_NAME{"pointer window"};
    surfaceNodeConfig.SurfaceNodeName = RS_SURFACE_NODE_NAME;
    screenpointer->surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig,
        Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE);
    ASSERT_NE(screenpointer->surfaceNode_, nullptr);
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    ICON_TYPE align = ANGLE_W;
    int32_t x = 0;
    int32_t y = 0;
    bool ret = screenpointer->MoveSoft(x, y, align);
    EXPECT_TRUE(ret);
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    ret = screenpointer->MoveSoft(x, y, align);
    EXPECT_TRUE(ret);
    screenpointer->mode_ = mode_t::SCREEN_EXTEND;
    ret = screenpointer->MoveSoft(x, y, align);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ScreenPointerTest_Move_001
 * @tc.desc: Test Move
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Move_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    const char* RS_SURFACE_NODE_NAME{"pointer window"};
    surfaceNodeConfig.SurfaceNodeName = RS_SURFACE_NODE_NAME;
    screenpointer->surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig,
        Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE);
    ASSERT_NE(screenpointer->surfaceNode_, nullptr);
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    screenpointer->isCurrentOffScreenRendering_ = true;
    ICON_TYPE align = ANGLE_W;
    int32_t x = 0;
    int32_t y = 0;
    bool ret = screenpointer->Move(x, y, align);
    EXPECT_TRUE(ret);
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    screenpointer->isCurrentOffScreenRendering_ = true;
    ret = screenpointer->Move(x, y, align);
    EXPECT_TRUE(ret);
    screenpointer->mode_ = mode_t::SCREEN_EXTEND;
    screenpointer->isCurrentOffScreenRendering_ = false;
    ret = screenpointer->Move(x, y, align);
    EXPECT_TRUE(ret);
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    screenpointer->isCurrentOffScreenRendering_ = false;
    ret = screenpointer->Move(x, y, align);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ScreenPointerTest_Rotate_001
 * @tc.desc: Test Rotate
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Rotate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    int32_t x = 0;
    int32_t y = 0;
    rotation_t rotation = rotation_t(DIRECTION90);
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    screenpointer->rotation_ = rotation_t::ROTATION_0;
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    screenpointer->rotation_ = rotation_t::ROTATION_90;
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    screenpointer->rotation_ = rotation_t::ROTATION_180;
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    screenpointer->rotation_ = rotation_t::ROTATION_270;
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    screenpointer->rotation_ = rotation_t::ROTATION_0;
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    screenpointer->rotation_ = rotation_t::ROTATION_90;
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    screenpointer->rotation_ = rotation_t::ROTATION_180;
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    screenpointer->rotation_ = rotation_t::ROTATION_270;
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
}

/**
 * @tc.name: ScreenPointerTest_Rotate_002
 * @tc.desc: Test Rotate
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Rotate_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    int32_t x = 0;
    int32_t y = 0;
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    screenpointer->rotation_ = rotation_t::ROTATION_180;
    rotation_t rotation = rotation_t(DIRECTION90);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION180);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION270);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION0);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
}

/**
 * @tc.name: ScreenPointerTest_GetCurrentBuffer_001
 * @tc.desc: Test GetCurrentBuffer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_GetCurrentBuffer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->bufferId_ = 0;
    EXPECT_NO_FATAL_FAILURE(screenpointer->GetCurrentBuffer());
    sptr<OHOS::SurfaceBuffer> buffer = OHOS::SurfaceBuffer::Create();
    screenpointer->buffers_.push_back(buffer);
    EXPECT_NO_FATAL_FAILURE(screenpointer->GetCurrentBuffer());
}

/**
 * @tc.name: ScreenPointerTest_RequestBuffer_001
 * @tc.desc: Test RequestBuffer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_RequestBuffer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->bufferId_ = 1;
    EXPECT_NO_FATAL_FAILURE(screenpointer->RequestBuffer());
    sptr<OHOS::SurfaceBuffer> buffer = OHOS::SurfaceBuffer::Create();
    screenpointer->buffers_.push_back(buffer);
    EXPECT_NO_FATAL_FAILURE(screenpointer->RequestBuffer());
}

/**
 * @tc.name: ScreenPointerTest_UpdatePadding_001
 * @tc.desc: Test UpdatePadding
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_UpdatePadding_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    uint32_t mainWidth = 0;
    uint32_t mainHeight = 0;
    bool ret = screenpointer->UpdatePadding(mainWidth, mainHeight);
    EXPECT_FALSE(ret);
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    mainWidth = 0;
    mainHeight = 0;
    ret = screenpointer->UpdatePadding(mainWidth, mainHeight);
    EXPECT_FALSE(ret);
    mainWidth = 0;
    mainHeight = 5;
    ret = screenpointer->UpdatePadding(mainWidth, mainHeight);
    EXPECT_FALSE(ret);
    mainWidth = 5;
    mainHeight = 0;
    ret = screenpointer->UpdatePadding(mainWidth, mainHeight);
    EXPECT_FALSE(ret);
    mainWidth = 5;
    mainHeight = 5;
    screenpointer->rotation_ = rotation_t::ROTATION_90;
    ret = screenpointer->UpdatePadding(mainWidth, mainHeight);
    EXPECT_TRUE(ret);
    screenpointer->rotation_ = rotation_t::ROTATION_180;
    ret = screenpointer->UpdatePadding(mainWidth, mainHeight);
    EXPECT_TRUE(ret);
    screenpointer->rotation_ = rotation_t::ROTATION_270;
    ret = screenpointer->UpdatePadding(mainWidth, mainHeight);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ScreenPointerTest_OnDisplayInfo_001
 * @tc.desc: Test OnDisplayInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_OnDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    DisplayInfo di;
    di.id = 1;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->bufferId_ = 5;
    EXPECT_NO_FATAL_FAILURE(screenpointer->OnDisplayInfo(di));
    screenpointer->bufferId_ = 1;
    screenpointer->isCurrentOffScreenRendering_ = true;
    EXPECT_NO_FATAL_FAILURE(screenpointer->OnDisplayInfo(di));
    screenpointer->isCurrentOffScreenRendering_ = false;
    EXPECT_NO_FATAL_FAILURE(screenpointer->OnDisplayInfo(di));
}

/**
 * @tc.name: ScreenPointerTest_ScreenPointer_001
 * @tc.desc: Test ScreenPointer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_ScreenPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    DisplayInfo di;
    di.id = 1;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    screenpointer->rotation_ = rotation_t::ROTATION_90;
    ScreenPointer(hwcmgr, handler, di);
    screenpointer->rotation_ = rotation_t::ROTATION_180;
    ScreenPointer(hwcmgr, handler, di);
    screenpointer->rotation_ = rotation_t::ROTATION_270;
    ScreenPointer(hwcmgr, handler, di);
}
} // namespace MMI
} // namespace OHOS