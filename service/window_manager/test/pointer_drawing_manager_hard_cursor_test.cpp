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

#include <gtest/gtest.h>

#include "pointer_device_manager.h"
#include "pointer_drawing_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "PointerDrawingManagerHardCursorTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing;
using namespace testing::ext;

constexpr uint32_t SLEEP_TIME_IN_US = 200000; // 200ms
constexpr int32_t DEFAULT_VALUE { -1 };
} // namespace

class PointerDrawingManagerHardCursorTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {}
    void TearDown(void) {}
    static sptr<Rosen::ScreenInfo> CreateScreenInfo(Rosen::ScreenId rsId, uint32_t modeId, Rosen::ScreenSourceMode sourceMode)
    {
        sptr<Rosen::ScreenInfo> screenInfo = new Rosen::ScreenInfo();
        sptr<Rosen::SupportedScreenModes> mode = new Rosen::SupportedScreenModes();
        mode->width_ = 100;
        mode->height_ = 200;
        screenInfo->SetRsId(rsId);
        screenInfo->SetType(Rosen::ScreenType::REAL);
        screenInfo->SetModeId(modeId);
        screenInfo->modes_ = { { mode } };
        screenInfo->SetSourceMode(sourceMode);
        return screenInfo;
    }
 
    static std::shared_ptr<ScreenPointer> CreateScreenPointer(PointerRenderer pointerRenderer,
        std::shared_ptr<HardwareCursorPointerManager> hardwareCursorPointerManager,
        std::shared_ptr<AppExecFwk::EventHandler> handler,
        sptr<Rosen::ScreenInfo> screenInfo)
    {
        auto sp = std::make_shared<ScreenPointer>(hardwareCursorPointerManager, handler, screenInfo);
        sp->Init(pointerRenderer);
        return sp;
    }
};

/**
 * @tc.name: PointerDrawingManagerHardCursorTest_SetPointerLocation_001
 * @tc.desc: Test SetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerHardCursorTest, PointerDrawingManagerHardCursorTest_SetPointerLocation_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    ASSERT_NE(pointerDrawingManager.hardwareCursorPointerManager_, nullptr);
    EXPECT_CALL(*pointerDrawingManager.hardwareCursorPointerManager_, IsSupported).WillRepeatedly(Return(true));
    pointerDrawingManager.displayInfo_.validWidth = 500;
    pointerDrawingManager.displayInfo_.validHeight = 1000;
    int32_t x = 50;
    int32_t y = 60;
    uint64_t displayId = 0;
    Rosen::RSSurfaceNodeConfig surfaceNodeConfig;
    surfaceNodeConfig.SurfaceNodeName = "pointer window";
    Rosen::RSSurfaceNodeType surfaceNodeType = Rosen::RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    pointerDrawingManager.surfaceNode_ = Rosen::RSSurfaceNode::Create(surfaceNodeConfig, surfaceNodeType);
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    pointerDrawingManager.SetPointerLocation(x, y, displayId);
    EXPECT_EQ(pointerDrawingManager.lastPhysicalX_, x);
    EXPECT_EQ(pointerDrawingManager.lastPhysicalY_, y);
}

/**
 * @tc.name: PointerDrawingManagerHardCursorTest_OnVsync_001
 * @tc.desc: Test OnVsync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerHardCursorTest, PointerDrawingManagerHardCursorTest_OnVsync_001,
    TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    ASSERT_NE(pointerDrawingManager.hardwareCursorPointerManager_, nullptr);
    EXPECT_CALL(*pointerDrawingManager.hardwareCursorPointerManager_, IsSupported).WillRepeatedly(Return(true));
    EXPECT_CALL(*pointerDrawingManager.hardwareCursorPointerManager_, SetPosition)
        .WillOnce(Return(RET_ERR))
        .WillRepeatedly(Return(RET_OK));
    pointerDrawingManager.InitPointerCallback();
    sptr<Rosen::ScreenInfo> screenInfo = CreateScreenInfo(0, 0, Rosen::ScreenSourceMode::SCREEN_MAIN);
    auto sp = std::make_shared<ScreenPointer>(pointerDrawingManager.hardwareCursorPointerManager_,
        pointerDrawingManager.handler_, screenInfo);
    ASSERT_NE(sp, nullptr);
    sp->Init(pointerDrawingManager.pointerRenderer_);
    pointerDrawingManager.screenPointers_.insert({0, sp});
    pointerDrawingManager.lastPhysicalX_ = 10;
    pointerDrawingManager.lastPhysicalY_ = 20;
    pointerDrawingManager.SetSurfaceNode(sp->GetSurfaceNode());
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    pointerDrawingManager.currentMouseStyle_.id = 43;
    pointerDrawingManager.mouseDisplayState_ = true;
    pointerDrawingManager.mouseIconUpdate_ = true;
 
    pointerDrawingManager.OnVsync(100000);
    usleep(SLEEP_TIME_IN_US);  // wait for async OnVsync
    pointerDrawingManager.currentMouseStyle_.id = 0;
    pointerDrawingManager.ClearRunnerAndHandler();
    EXPECT_EQ(pointerDrawingManager.mouseIconUpdate_, false);
}

/**
 * @tc.name: PointerDrawingManagerHardCursorTest_UpdatePointerVisible_001
 * @tc.desc: Test UpdatePointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerHardCursorTest, PointerDrawingManagerHardCursorTest_UpdatePointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    ASSERT_NE(pointerDrawingManager.hardwareCursorPointerManager_, nullptr);
    EXPECT_CALL(*pointerDrawingManager.hardwareCursorPointerManager_, IsSupported).WillRepeatedly(Return(true));
    sptr<Rosen::ScreenInfo> screenInfo = CreateScreenInfo(0, 0, Rosen::ScreenSourceMode::SCREEN_MAIN);
    auto sp = std::make_shared<ScreenPointer>(pointerDrawingManager.hardwareCursorPointerManager_,
        pointerDrawingManager.handler_, screenInfo);
    ASSERT_NE(sp, nullptr);
    sp->Init(pointerDrawingManager.pointerRenderer_);
    pointerDrawingManager.screenPointers_.insert({0, sp});
    pointerDrawingManager.lastPhysicalX_ = 10;
    pointerDrawingManager.lastPhysicalY_ = 20;
    pointerDrawingManager.SetSurfaceNode(sp->GetSurfaceNode());
    ASSERT_TRUE(pointerDrawingManager.surfaceNode_ != nullptr);
    pointerDrawingManager.mouseDisplayState_ = true;
    pointerDrawingManager.UpdatePointerVisible();
    EXPECT_EQ(POINTER_DEV_MGR.isPointerVisible, true);
}

/**
 * @tc.name: PointerDrawingManagerHardCursorTest_HardwareCursorMove_001
 * @tc.desc: Test HardwareCursorMove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerHardCursorTest, PointerDrawingManagerHardCursorTest_HardwareCursorMove_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    ASSERT_NE(pointerDrawingManager.hardwareCursorPointerManager_, nullptr);
    EXPECT_CALL(*pointerDrawingManager.hardwareCursorPointerManager_, IsSupported).WillRepeatedly(Return(true));
    EXPECT_CALL(*pointerDrawingManager.hardwareCursorPointerManager_, SetPosition).WillRepeatedly(Return(RET_OK));
    sptr<Rosen::ScreenInfo> mainScreenInfo = CreateScreenInfo(0, 0, Rosen::ScreenSourceMode::SCREEN_MAIN);
    sptr<Rosen::ScreenInfo> mirrorScreenInfo = CreateScreenInfo(1, 1, Rosen::ScreenSourceMode::SCREEN_MIRROR);
    sptr<Rosen::ScreenInfo> extendScreenInfo = CreateScreenInfo(2, 2, Rosen::ScreenSourceMode::SCREEN_EXTEND);
    auto mainSp = CreateScreenPointer(pointerDrawingManager.pointerRenderer_,
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, mainScreenInfo);
    auto mirrorSp = CreateScreenPointer(pointerDrawingManager.pointerRenderer_,
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, mirrorScreenInfo);
    auto extendSp = CreateScreenPointer(pointerDrawingManager.pointerRenderer_,
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, extendScreenInfo);
    ASSERT_NE(mainSp, nullptr);
    ASSERT_NE(mirrorSp, nullptr);
    ASSERT_NE(extendSp, nullptr);
    pointerDrawingManager.screenPointers_.insert({0, mainSp});
    pointerDrawingManager.screenPointers_.insert({1, mirrorSp});
    pointerDrawingManager.screenPointers_.insert({2, extendSp});
    pointerDrawingManager.displayId_ = 0;
    int32_t ret = pointerDrawingManager.HardwareCursorMove(10, 20);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: PointerDrawingManagerHardCursorTest_HardwareCursorMove_002
 * @tc.desc: Test HardwareCursorMove
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerHardCursorTest, PointerDrawingManagerHardCursorTest_HardwareCursorMove_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerDrawingManager pointerDrawingManager;
    ASSERT_NE(pointerDrawingManager.hardwareCursorPointerManager_, nullptr);
    EXPECT_CALL(*pointerDrawingManager.hardwareCursorPointerManager_, IsSupported).WillRepeatedly(Return(true));
    EXPECT_CALL(*pointerDrawingManager.hardwareCursorPointerManager_, SetPosition).WillRepeatedly(Return(RET_ERR));
    sptr<Rosen::ScreenInfo> mainScreenInfo = CreateScreenInfo(0, 0, Rosen::ScreenSourceMode::SCREEN_MAIN);
    sptr<Rosen::ScreenInfo> mirrorScreenInfo = CreateScreenInfo(1, 1, Rosen::ScreenSourceMode::SCREEN_MIRROR);
    sptr<Rosen::ScreenInfo> extendScreenInfo = CreateScreenInfo(2, 2, Rosen::ScreenSourceMode::SCREEN_EXTEND);
    auto mainSp = CreateScreenPointer(pointerDrawingManager.pointerRenderer_,
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, mainScreenInfo);
    auto mirrorSp = CreateScreenPointer(pointerDrawingManager.pointerRenderer_,
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, mirrorScreenInfo);
    auto extendSp = CreateScreenPointer(pointerDrawingManager.pointerRenderer_,
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, extendScreenInfo);
    ASSERT_NE(mainSp, nullptr);
    ASSERT_NE(mirrorSp, nullptr);
    ASSERT_NE(extendSp, nullptr);
    pointerDrawingManager.screenPointers_.insert({0, mainSp});
    pointerDrawingManager.screenPointers_.insert({1, mirrorSp});
    pointerDrawingManager.screenPointers_.insert({2, extendSp});
    pointerDrawingManager.displayId_ = 0;
    int32_t ret = pointerDrawingManager.HardwareCursorMove(10, 20);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: PointerDrawingManagerHardCursorTest_CheckHwcReady_001
 * @tc.desc: Test CheckHwcReady
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PointerDrawingManagerHardCursorTest, PointerDrawingManagerHardCursorTest_CheckHwcReady_001, TestSize.Level1)
{
    PointerDrawingManager pointerDrawingManager;
    ASSERT_NE(pointerDrawingManager.hardwareCursorPointerManager_, nullptr);
    EXPECT_CALL(*pointerDrawingManager.hardwareCursorPointerManager_, IsSupported).WillRepeatedly(Return(true));
    EXPECT_CALL(*pointerDrawingManager.hardwareCursorPointerManager_, SetPosition).
        WillOnce(Return(RET_ERR)).
        WillOnce(Return(RET_OK));
    sptr<Rosen::ScreenInfo> ScreenInfo = CreateScreenInfo(0, 0, Rosen::ScreenSourceMode::SCREEN_MAIN);
    auto sp = CreateScreenPointer(pointerDrawingManager.pointerRenderer_,
        pointerDrawingManager.hardwareCursorPointerManager_, pointerDrawingManager.handler_, ScreenInfo);
    ASSERT_NE(sp, nullptr);
    pointerDrawingManager.screenPointers_.insert({0, sp});
    pointerDrawingManager.lastPhysicalX_ = 10;
    pointerDrawingManager.lastPhysicalY_ = 20;
    pointerDrawingManager.displayId_ = 0;
    int32_t ret = pointerDrawingManager.CheckHwcReady();
    EXPECT_EQ(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS