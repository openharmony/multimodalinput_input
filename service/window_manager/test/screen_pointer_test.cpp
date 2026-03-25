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
#include "product_name_definition.h"
#include "product_type_parser.h"

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
 * @tc.name: ScreenPointerTest_UpdateScreenInfo_001
 * @tc.desc: Test UpdateScreenInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_UpdateScreenInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    sptr<OHOS::Rosen::ScreenInfo> screenInfo = new OHOS::Rosen::ScreenInfo();
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, screenInfo);
    ASSERT_NE(screenpointer, nullptr);
    auto ret = screenpointer->InitSurface(true);
    EXPECT_EQ(ret, true);
    uint32_t width = screenpointer->GetScreenWidth();
    EXPECT_EQ(width, 0);
    uint32_t height = screenpointer->GetScreenHeight();
    EXPECT_EQ(height, 0);
    EXPECT_NO_FATAL_FAILURE(screenpointer->UpdateScreenInfo(screenInfo, true));
}

/**
 * @tc.name: ScreenPointerTest_UpdateScreenInfo_002
 * @tc.desc: Test UpdateScreenInfo with needDrawPointer=false
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_UpdateScreenInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    sptr<OHOS::Rosen::ScreenInfo> screenInfo = new OHOS::Rosen::ScreenInfo();
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, screenInfo);
    ASSERT_NE(screenpointer, nullptr);
    auto ret = screenpointer->InitSurface(true);
    EXPECT_EQ(ret, true);
    EXPECT_NO_FATAL_FAILURE(screenpointer->UpdateScreenInfo(screenInfo, false));
}

/**
 * @tc.name: ScreenPointerTest_InitSurface_002
 * @tc.desc: Test InitSurface with needDrawPointer=false then UpdateScreenInfo with needDrawPointer=true
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_InitSurface_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    sptr<OHOS::Rosen::ScreenInfo> screenInfo = new OHOS::Rosen::ScreenInfo();
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, screenInfo);
    ASSERT_NE(screenpointer, nullptr);
    auto ret = screenpointer->InitSurface(false);
    EXPECT_EQ(ret, true);
    EXPECT_NO_FATAL_FAILURE(screenpointer->UpdateScreenInfo(screenInfo, true));
}

/**
 * @tc.name: ScreenPointerTest_InitSurface_003
 * @tc.desc: Test InitSurface with needDrawPointer=false then UpdateScreenInfo with needDrawPointer=false
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_InitSurface_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    sptr<OHOS::Rosen::ScreenInfo> screenInfo = new OHOS::Rosen::ScreenInfo();
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, screenInfo);
    ASSERT_NE(screenpointer, nullptr);
    auto ret = screenpointer->InitSurface(false);
    EXPECT_EQ(ret, true);
    EXPECT_NO_FATAL_FAILURE(screenpointer->UpdateScreenInfo(screenInfo, false));
}

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
 * @tc.name: ScreenPointerTest_SetInvisible_002
 * @tc.desc: Test SetInvisible
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_SetInvisible_002, TestSize.Level1)
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
    screenpointer->SetVirtualExtend(true);
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
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    screenpointer->surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig,
        Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE);
    ASSERT_NE(screenpointer->surfaceNode_, nullptr);
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    int32_t x = 0;
    int32_t y = 0;
    bool ret = screenpointer->MoveSoft(x, y);
    EXPECT_TRUE(ret);
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    ret = screenpointer->MoveSoft(x, y);
    EXPECT_TRUE(ret);
    screenpointer->mode_ = mode_t::SCREEN_EXTEND;
    ret = screenpointer->MoveSoft(x, y);
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
    auto ret = screenpointer->MoveSoft(x, y);
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
    int32_t x = 0;
    int32_t y = 0;
    bool ret = screenpointer->Move(x, y);
    EXPECT_FALSE(ret);
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    screenpointer->isCurrentOffScreenRendering_ = true;
    ret = screenpointer->Move(x, y);
    EXPECT_FALSE(ret);
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    ret = screenpointer->Move(x, y);
    EXPECT_FALSE(ret);
    screenpointer->mode_ = mode_t::SCREEN_EXTEND;
    screenpointer->isCurrentOffScreenRendering_ = false;
    ret = screenpointer->Move(x, y);
    EXPECT_FALSE(ret);
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    screenpointer->isCurrentOffScreenRendering_ = false;
    ret = screenpointer->Move(x, y);
    EXPECT_FALSE(ret);
    delete screenpointer;
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
    int32_t x = 0;
    int32_t y = 0;
    bool ret = screenpointer->Move(x, y);
    EXPECT_FALSE(ret);
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    ret = screenpointer->Move(x, y);
    EXPECT_FALSE(ret);
    x = -1;
    y = -1;
    ret = screenpointer->Move(x, y);
    EXPECT_FALSE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_Move_003
 * @tc.desc: Test Move
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Move_003, TestSize.Level1)
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
    int32_t x = 0;
    int32_t y = 0;
    screenpointer->SetVirtualExtend(true);
    bool ret = screenpointer->Move(x, y);
    EXPECT_TRUE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_Move_004
 * @tc.desc: Test Move
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Move_004, TestSize.Level1)
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
    screenpointer->mode_ = mode_t::SCREEN_ALONE;
    int32_t x = 0;
    int32_t y = 0;
    bool ret = screenpointer->Move(x, y);
    EXPECT_FALSE(ret);
    screenpointer->mode_ = mode_t::SCREEN_UNIQUE;
    ret = screenpointer->Move(x, y);
    EXPECT_FALSE(ret);
    screenpointer->mode_ = static_cast<mode_t>(5);
    ret = screenpointer->Move(x, y);
    EXPECT_FALSE(ret);
    delete screenpointer;
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
    int32_t width = 1920;
    int32_t height = 1080;
    rotation_t rotation = rotation_t::ROTATION_0;
    screenpointer->Rotate(rotation, x, y, width, height);
    EXPECT_EQ(x, 0);
    EXPECT_EQ(y, 0);
    rotation = rotation_t::ROTATION_90;
    screenpointer->Rotate(rotation, x, y, width, height);
    EXPECT_EQ(x, 1080);
    EXPECT_EQ(y, 0);
    rotation = rotation_t::ROTATION_180;
    screenpointer->Rotate(rotation, x, y, width, height);
    EXPECT_EQ(x, 840);
    EXPECT_EQ(y, 1080);
    rotation = rotation_t::ROTATION_270;
    screenpointer->Rotate(rotation, x, y, width, height);
    EXPECT_EQ(x, 1080);
    EXPECT_EQ(y, 1080);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_CalculateHwcPositionForMain_001
 * @tc.desc: Test CalculateHwcPositionForMain
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_CalculateHwcPositionForMain_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->displayDirection_ = Direction::DIRECTION90;
    int32_t x = 10;
    int32_t y = 20;
    screenpointer->width_ = 1920;
    screenpointer->height_ = 1080;
    screenpointer->CalculateHwcPositionForMain(x, y);
    EXPECT_EQ(x, 20);
    EXPECT_EQ(y, 1070);
    screenpointer->displayDirection_ = Direction::DIRECTION270;
    screenpointer->CalculateHwcPositionForMain(x, y);
    EXPECT_EQ(x, 850);
    EXPECT_EQ(y, 20);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_CalculateHwcPositionForExtend_001
 * @tc.desc: Test CalculateHwcPositionForExtend
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_CalculateHwcPositionForExtend_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    int32_t x = 10;
    int32_t y = 20;
    screenpointer->offRenderScale_ = 0.5;
    screenpointer->isCurrentOffScreenRendering_ = true;
    screenpointer->CalculateHwcPositionForExtend(x, y);
    EXPECT_EQ(x, 5);
    EXPECT_EQ(y, 10);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_CalculateHwcPositionForMirror_001
 * @tc.desc: Test CalculateHwcPositionForMirror
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_CalculateHwcPositionForMirror_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->displayDirection_ = Direction::DIRECTION90;
    int32_t x = 40;
    int32_t y = 80;
    screenpointer->width_ = 1920;
    screenpointer->height_ = 1080;
    screenpointer->scale_ = 0.5;
    screenpointer->paddingLeft_ = 150;
    screenpointer->paddingTop_ = 0;
    screenpointer->CalculateHwcPositionForMirror(x, y);
    EXPECT_EQ(x, 190);
    EXPECT_EQ(y, 1060);
    screenpointer->displayDirection_ = Direction::DIRECTION270;
    screenpointer->CalculateHwcPositionForMirror(x, y);
    EXPECT_EQ(x, 1240);
    EXPECT_EQ(y, 95);
    delete screenpointer;
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
 * @tc.name: ScreenPointerTest_RequestBuffer_002
 * @tc.desc: Test RequestBuffer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_RequestBuffer_002, TestSize.Level1)
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
    RenderConfig defaultCursorCfg {
        .style_ = MOUSE_ICON::DEFAULT,
        .align_ = ICON_TYPE::ANGLE_NW,
        .path_ = "/system/etc/multimodalinput/mouse_icon/Default.svg",
        .color = 0,
        .size = 1,
        .direction = Direction::DIRECTION0,
        .dpi = screenpointer->GetDPI() * screenpointer->GetScale(),
        .isHard = true,
    };
    if (OHOS::system::GetParameter("const.build.product", SYS_GET_DEVICE_TYPE_PARAM) == DEVICE_TYPE_FOLD_PC) {
        defaultCursorCfg.size = 2;
    }
    bool isCommoBuffer;
    ASSERT_TRUE(screenpointer->IsDefaultCfg(defaultCursorCfg));
    ASSERT_NE(screenpointer->RequestBuffer(defaultCursorCfg, isCommoBuffer), nullptr);
    ASSERT_FALSE(isCommoBuffer);
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
    EXPECT_NO_FATAL_FAILURE(screenpointer->OnDisplayInfo(di));
    screenpointer->bufferId_ = 1;
    screenpointer->isCurrentOffScreenRendering_ = true;
    EXPECT_NO_FATAL_FAILURE(screenpointer->OnDisplayInfo(di));
    screenpointer->isCurrentOffScreenRendering_ = false;
    EXPECT_NO_FATAL_FAILURE(screenpointer->OnDisplayInfo(di));

    screenpointer->screenId_ = 1;
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

/**
 * @tc.name: ScreenPointerTest_InitSurface_004
 * @tc.desc: Test InitSurface with surfaceNode creation failure scenario
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_InitSurface_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    auto screenpointer = std::make_unique<ScreenPointer>(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    auto ret = screenpointer->InitSurface(true);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: ScreenPointerTest_InitDefaultBuffer_001
 * @tc.desc: Test InitDefaultBuffer with valid render config
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_InitDefaultBuffer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    OHOS::BufferRequestConfig bufferCfg = {
        .width = 512,
        .height = 512,
        .strideAlignment = 8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE,
        .timeout = 150,
    };
    auto ret = screenpointer->InitDefaultBuffer(bufferCfg, renderer);
    EXPECT_FALSE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_InitTransparentBuffer_001
 * @tc.desc: Test InitTransparentBuffer with valid buffer config
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_InitTransparentBuffer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    OHOS::BufferRequestConfig bufferCfg = {
        .width = 512,
        .height = 512,
        .strideAlignment = 8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE,
        .timeout = 150,
    };
    auto ret = screenpointer->InitTransparentBuffer(bufferCfg);
    EXPECT_TRUE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_InitCommonBuffer_001
 * @tc.desc: Test InitCommonBuffer with valid buffer config
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_InitCommonBuffer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    OHOS::BufferRequestConfig bufferCfg = {
        .width = 512,
        .height = 512,
        .strideAlignment = 8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE,
        .timeout = 150,
    };
    auto ret = screenpointer->InitCommonBuffer(bufferCfg);
    EXPECT_TRUE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_UpdateScreenInfo_003
 * @tc.desc: Test UpdateScreenInfo with nullptr screenInfo
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_UpdateScreenInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->InitSurface(true);
    sptr<OHOS::Rosen::ScreenInfo> screenInfo = nullptr;
    screenpointer->UpdateScreenInfo(screenInfo, true);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_OnDisplayInfo_002
 * @tc.desc: Test OnDisplayInfo with mismatched screenId
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_OnDisplayInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    di.id = 1;
    di.rsId = 100;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->screenId_ = 200;
    OLD::DisplayInfo di2;
    di2.id = 2;
    di2.rsId = 300;
    screenpointer->OnDisplayInfo(di2);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_OnDisplayInfo_003
 * @tc.desc: Test OnDisplayInfo with zero width for off screen rendering
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_OnDisplayInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    di.id = 1;
    di.width = 0;
    di.isCurrentOffScreenRendering = true;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->screenId_ = di.rsId;
    screenpointer->OnDisplayInfo(di);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_UpdatePadding_002
 * @tc.desc: Test UpdatePadding with external screen build and main screen mode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_UpdatePadding_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->mode_ = mode_t::SCREEN_MAIN;
    uint32_t mainWidth = 1920;
    uint32_t mainHeight = 1080;
    bool ret = screenpointer->UpdatePadding(mainWidth, mainHeight);
    EXPECT_FALSE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_Rotate_002
 * @tc.desc: Test Rotate with ROTATION_0
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
    int32_t x = 100;
    int32_t y = 200;
    int32_t width = 1920;
    int32_t height = 1080;
    rotation_t rotation = rotation_t::ROTATION_0;
    screenpointer->Rotate(rotation, x, y, width, height);
    EXPECT_EQ(x, 100);
    EXPECT_EQ(y, 200);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_CalculateHwcPositionForMain_002
 * @tc.desc: Test CalculateHwcPositionForMain with off screen rendering
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_CalculateHwcPositionForMain_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->isCurrentOffScreenRendering_ = true;
    screenpointer->offRenderScale_ = 2.0;
    int32_t x = 10;
    int32_t y = 20;
    screenpointer->CalculateHwcPositionForMain(x, y);
    EXPECT_EQ(x, 20);
    EXPECT_EQ(y, 40);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_CalculateHwcPositionForExtend_002
 * @tc.desc: Test CalculateHwcPositionForExtend without off screen rendering
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_CalculateHwcPositionForExtend_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->isCurrentOffScreenRendering_ = false;
    int32_t x = 10;
    int32_t y = 20;
    screenpointer->CalculateHwcPositionForExtend(x, y);
    EXPECT_EQ(x, 10);
    EXPECT_EQ(y, 20);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_Move_005
 * @tc.desc: Test Move with virtual extend mode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Move_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->SetVirtualExtend(true);
    int32_t x = 0;
    int32_t y = 0;
    bool ret = screenpointer->Move(x, y);
    EXPECT_TRUE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_Move_006
 * @tc.desc: Test Move with null hwcMgr
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Move_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = nullptr;
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    screenpointer->Init(renderer);
    int32_t x = 0;
    int32_t y = 0;
    bool ret = screenpointer->Move(x, y);
    EXPECT_FALSE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_MoveSoft_003
 * @tc.desc: Test MoveSoft with null surfaceNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_MoveSoft_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->surfaceNode_ = nullptr;
    int32_t x = 0;
    int32_t y = 0;
    bool ret = screenpointer->MoveSoft(x, y);
    EXPECT_FALSE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_SetInvisible_003
 * @tc.desc: Test SetInvisible with null hwcMgr
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_SetInvisible_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = nullptr;
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    screenpointer->Init(renderer);
    bool ret = screenpointer->SetInvisible();
    EXPECT_FALSE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_SetInvisible_004
 * @tc.desc: Test SetInvisible with invalid buffer dimensions
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_SetInvisible_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    screenpointer->Init(renderer);
    bool ret = screenpointer->SetInvisible();
    EXPECT_EQ(ret, hwcmgr->IsSupported());
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_GetRenderDPI_002
 * @tc.desc: Test GetRenderDPI with off screen rendering and mirror mode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_GetRenderDPI_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->isCurrentOffScreenRendering_ = true;
    screenpointer->mode_ = mode_t::SCREEN_MIRROR;
    float ret = screenpointer->GetRenderDPI();
    EXPECT_GE(ret, 0);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_GetRenderDPI_003
 * @tc.desc: Test GetRenderDPI without off screen rendering
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_GetRenderDPI_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->isCurrentOffScreenRendering_ = false;
    screenpointer->dpi_ = 2.0;
    screenpointer->scale_ = 1.0;
    float ret = screenpointer->GetRenderDPI();
    EXPECT_EQ(ret, 2.0);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_IsPositionOutScreen_003
 * @tc.desc: Test IsPositionOutScreen with boundary values
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_IsPositionOutScreen_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->width_ = 100;
    screenpointer->height_ = 100;
    int32_t x = 0;
    int32_t y = 0;
    auto ret = screenpointer->IsPositionOutScreen(x, y);
    EXPECT_FALSE(ret);
    x = 100;
    y = 100;
    ret = screenpointer->IsPositionOutScreen(x, y);
    EXPECT_FALSE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_RequestBuffer_003
 * @tc.desc: Test RequestBuffer
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_RequestBuffer_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
}

/**
 * @tc.name: ScreenPointerTest_IsDefaultCfg_001
 * @tc.desc: Test IsDefaultCfg with matching config
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_IsDefaultCfg_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    screenpointer->Init(renderer);
    RenderConfig cfg = screenpointer->defaultCursorCfg_;
    bool ret = screenpointer->IsDefaultCfg(cfg);
    EXPECT_TRUE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_IsDefaultCfg_002
 * @tc.desc: Test IsDefaultCfg with different direction
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_IsDefaultCfg_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    screenpointer->Init(renderer);
    RenderConfig cfg = screenpointer->defaultCursorCfg_;
    cfg.direction = Direction::DIRECTION90;
    bool ret = screenpointer->IsDefaultCfg(cfg);
    EXPECT_FALSE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_GetCommonBuffer_002
 * @tc.desc: Test GetCommonBuffer with incorrect buffer size
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_GetCommonBuffer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->commonBuffers_.clear();
    auto buffer = screenpointer->GetCommonBuffer();
    EXPECT_EQ(buffer, nullptr);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_Destructor_001
 * @tc.desc: Test ScreenPointer destructor with valid surfaceNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Destructor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->InitSurface(true);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_Destructor_002
 * @tc.desc: Test ScreenPointer destructor with null surfaceNode
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Destructor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->surfaceNode_ = nullptr;
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_Init_001
 * @tc.desc: Test Init with needDrawPointer=false
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_Init_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    auto ret = screenpointer->Init(renderer, false);
    EXPECT_TRUE(ret);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_GetCurrentBuffer_002
 * @tc.desc: Test GetCurrentBuffer after buffer switch
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_GetCurrentBuffer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    PointerRenderer renderer;
    screenpointer->Init(renderer);
    auto buffer1 = screenpointer->GetCurrentBuffer();
    screenpointer->GetCommonBuffer();
    auto buffer2 = screenpointer->GetCurrentBuffer();
    EXPECT_NE(buffer1, nullptr);
    delete screenpointer;
}

/**
 * @tc.name: ScreenPointerTest_CalculateHwcPositionForMirror_002
 * @tc.desc: Test CalculateHwcPositionForMirror with DIRECTION0
 * @tc.type: Function
 * @tc.require:
 */
HWTEST_F(ScreenPointerTest, ScreenPointerTest_CalculateHwcPositionForMirror_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    hwcmgr_ptr_t hwcmgr = std::make_shared<HardwareCursorPointerManager>();
    ASSERT_NE(hwcmgr, nullptr);
    handler_ptr_t handler = nullptr;
    OLD::DisplayInfo di;
    ScreenPointer* screenpointer = new ScreenPointer(hwcmgr, handler, di);
    ASSERT_NE(screenpointer, nullptr);
    screenpointer->displayDirection_ = Direction::DIRECTION0;
    screenpointer->sourceScreenRotation_ = rotation_t::ROTATION_0;
    int32_t x = 40;
    int32_t y = 80;
    screenpointer->width_ = 1920;
    screenpointer->height_ = 1080;
    screenpointer->scale_ = 1.0;
    screenpointer->paddingLeft_ = 0;
    screenpointer->paddingTop_ = 0;
    screenpointer->CalculateHwcPositionForMirror(x, y);
    EXPECT_EQ(x, 40);
    EXPECT_EQ(y, 80);
    delete screenpointer;
}
} // namespace MMI
} // namespace OHOS