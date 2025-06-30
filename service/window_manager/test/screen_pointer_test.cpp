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
    OLD::DisplayInfo di;
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
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    ASSERT_TRUE(screenpointer->Init(renderer));
    bool ret = screenpointer->SetInvisible();
    EXPECT_EQ(ret, hwcmgr->IsSupported());
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
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
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
 * @tc.name: ScreenPointerTest_MoveSoft_002
 * @tc.desc: Test MoveSoft
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_MoveSoft_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    di.id = 1;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    screenpointer->surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig,
        Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE);
    screenpointer->isCurrentOffScreenRendering_ = true;
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;

    int32_t x = -1;
    int32_t y = -1;
    ICON_TYPE align = ICON_TYPE::ANGLE_N;
    auto ret = screenpointer->MoveSoft(x, y, align);
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
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    ASSERT_TRUE(screenpointer->Init(renderer));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    screenpointer->surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig,
        Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE);
    ASSERT_NE(screenpointer->surfaceNode_, nullptr);
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    screenpointer->isCurrentOffScreenRendering_ = true;
    ICON_TYPE align = ANGLE_W;
    int32_t x = 0;
    int32_t y = 0;
    bool ret = screenpointer->Move(x, y, align);
    EXPECT_EQ(ret, hwcmgr->IsSupported());
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    screenpointer->isCurrentOffScreenRendering_ = true;
    ret = screenpointer->Move(x, y, align);
    EXPECT_EQ(ret, hwcmgr->IsSupported());
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    screenpointer->isWindowRotation_ = true;
    ret = screenpointer->Move(x, y, align);
    EXPECT_EQ(ret, hwcmgr->IsSupported());
    screenpointer->mode_ = mode_t::SCREEN_EXTEND;
    screenpointer->isCurrentOffScreenRendering_ = false;
    ret = screenpointer->Move(x, y, align);
    EXPECT_EQ(ret, hwcmgr->IsSupported());
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    screenpointer->isCurrentOffScreenRendering_ = false;
    ret = screenpointer->Move(x, y, align);
    EXPECT_EQ(ret, hwcmgr->IsSupported());
}

/**
 * @tc.name: ScreenPointerTest_Move_002
 * @tc.desc: Test Move
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Move_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    ASSERT_TRUE(screenpointer->Init(renderer));
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    screenpointer->surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig,
        Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE);
    ASSERT_NE(screenpointer->surfaceNode_, nullptr);
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    screenpointer->isWindowRotation_ = true;
    ICON_TYPE align = ANGLE_W;
    int32_t x = 0;
    int32_t y = 0;
    bool ret = screenpointer->Move(x, y, align);
    EXPECT_FALSE(ret);
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    screenpointer->isWindowRotation_ = true;
    ret = screenpointer->Move(x, y, align);
    EXPECT_FALSE(ret);
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
    OLD::DisplayInfo di;
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
    OLD::DisplayInfo di;
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
 * @tc.name: ScreenPointerTest_Rotate_003
 * @tc.desc: Test Rotate
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Rotate_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    int32_t x = 0;
    int32_t y = 0;
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    screenpointer->rotation_ = rotation_t::ROTATION_0;
    screenpointer->isWindowRotation_ = true;
    screenpointer->displayDirection_ = DIRECTION90;
    rotation_t rotation = rotation_t(DIRECTION90);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION180);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION270);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION0);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    screenpointer->displayDirection_ = DIRECTION270;
    rotation = rotation_t(DIRECTION90);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION180);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION270);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION0);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
}

/**
 * @tc.name: ScreenPointerTest_Rotate_004
 * @tc.desc: Test Rotate
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Rotate_004, TestSize.Level1)
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
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    screenpointer->rotation_ = rotation_t::ROTATION_0;
    screenpointer->isWindowRotation_ = true;
    screenpointer->displayDirection_ = DIRECTION90;
    rotation_t rotation = rotation_t(DIRECTION90);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION180);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION270);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION0);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    screenpointer->displayDirection_ = DIRECTION270;
    rotation = rotation_t(DIRECTION90);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION180);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION270);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
    rotation = rotation_t(DIRECTION0);
    EXPECT_NO_FATAL_FAILURE(screenpointer->Rotate(rotation, x, y));
}

/**
 * @tc.name: ScreenPointerTest_GetDefaultBuffer_001
 * @tc.desc: Test GetDefaultBuffer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_GetDefaultBufferr_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    ASSERT_TRUE(screenpointer->Init(renderer));
    ASSERT_NE(screenpointer->GetDefaultBuffer(), nullptr);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_GetTransparentBuffer_001
 * @tc.desc: Test GetTransparentBuffer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_GetTransparentBuffer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    ASSERT_TRUE(screenpointer->Init(renderer));
    ASSERT_NE(screenpointer->GetTransparentBuffer(), nullptr);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_GetCommonBuffer_001
 * @tc.desc: Test GetCommonBuffer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_GetCommonBuffer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    ASSERT_TRUE(screenpointer->Init(renderer));
    ASSERT_NE(screenpointer->GetCommonBuffer(), nullptr);
    delete screenpointer;
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
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    ASSERT_TRUE(screenpointer->Init(renderer));
    ASSERT_NE(screenpointer->GetCurrentBuffer(), nullptr);
    ASSERT_NE(screenpointer->GetTransparentBuffer(), nullptr);
    ASSERT_NE(screenpointer->GetCurrentBuffer(), nullptr);
    delete screenpointer;
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
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    ASSERT_TRUE(screenpointer->Init(renderer));
    screenpointer->bufferId_ = 5;
    bool isCommonBuffer;
    const RenderConfig cfg = {
        .style_ = TRANSPARENT_ICON,
    };
    ASSERT_NE(screenpointer->RequestBuffer(cfg, isCommonBuffer), nullptr);
    ASSERT_FALSE(isCommonBuffer);
    ASSERT_NE(screenpointer->GetCurrentBuffer(), nullptr);
    delete screenpointer;
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
    OLD::DisplayInfo di;
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
    OLD::DisplayInfo di;
    di.id = 1;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->bufferId_ = 5;
    EXPECT_NO_FATAL_FAILURE(screenpointer->OnDisplayInfo(di, false));
    screenpointer->bufferId_ = 1;
    screenpointer->isCurrentOffScreenRendering_ = true;
    EXPECT_NO_FATAL_FAILURE(screenpointer->OnDisplayInfo(di, false));
    screenpointer->isCurrentOffScreenRendering_ = false;
    EXPECT_NO_FATAL_FAILURE(screenpointer->OnDisplayInfo(di, false));

    screenpointer->screenId_ = 1;
    EXPECT_NO_FATAL_FAILURE(screenpointer->OnDisplayInfo(di, false));
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
    OLD::DisplayInfo di;
    di.id = 1;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    screenpointer->rotation_ = rotation_t::ROTATION_90;
    ScreenPointer(hwcmgr, handler, di);
    screenpointer->rotation_ = rotation_t::ROTATION_180;
    ScreenPointer(hwcmgr, handler, di);
    screenpointer->rotation_ = rotation_t::ROTATION_270;
    ScreenPointer(hwcmgr, handler, di);
}

/**
 * @tc.name: ScreenPointerTest_ScreenPointer_002
 * @tc.desc: Test ScreenPointer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_ScreenPointer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = nullptr;
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    di.width = 5;
    di.height = 6;
    di.direction = Direction::DIRECTION90;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);

    EXPECT_EQ(screenpointer->width_, di.height);
    EXPECT_EQ(screenpointer->height_, di.width);
}

/**
 * @tc.name: ScreenPointerTest_ScreenPointer_003
 * @tc.desc: Test ScreenPointer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_ScreenPointer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = nullptr;
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    di.width = 5;
    di.height = 6;
    di.direction = Direction::DIRECTION270;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);

    EXPECT_EQ(screenpointer->width_, di.height);
    EXPECT_EQ(screenpointer->height_, di.width);

    PointerRenderer render;
    ASSERT_TRUE(screenpointer->Init(render));
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_IsPositionOutScreen_001
 * @tc.desc: Test IsPositionOutScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_IsPositionOutScreen_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    di.id = 1;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    screenpointer->isCurrentOffScreenRendering_ = false;

    int32_t x = -1;
    int32_t y = -1;
    auto ret = screenpointer->IsPositionOutScreen(x, y);
    EXPECT_TRUE(ret);

    x = 1;
    ret = screenpointer->IsPositionOutScreen(x, y);
    EXPECT_TRUE(ret);

    y = 1;
    screenpointer->width_ = 0;
    ret = screenpointer->IsPositionOutScreen(x, y);
    EXPECT_TRUE(ret);

    screenpointer->width_ = 2;
    screenpointer->height_ = 0;
    ret = screenpointer->IsPositionOutScreen(x, y);
    EXPECT_TRUE(ret);

    screenpointer->height_ = 2;
    ret = screenpointer->IsPositionOutScreen(x, y);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: ScreenPointerTest_IsPositionOutScreen_002
 * @tc.desc: Test IsPositionOutScreen
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_IsPositionOutScreen_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    di.id = 1;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    screenpointer->isCurrentOffScreenRendering_ = true;
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;

    int32_t x = -1;
    int32_t y = -1;
    auto ret = screenpointer->IsPositionOutScreen(x, y);
    EXPECT_TRUE(ret);

    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    screenpointer->offRenderScale_ = 2.0;
    ret = screenpointer->IsPositionOutScreen(x, y);
    EXPECT_TRUE(ret);
}
} // namespace MMI
} // namespace OHOS