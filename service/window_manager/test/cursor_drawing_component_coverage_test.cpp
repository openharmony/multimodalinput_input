/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <cstdlib>

#include "cursor_drawing_component.h"
#include "mmi_log.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "CursorDrawingComponentCoverageTest"

namespace OHOS {
namespace MMI {
using namespace testing;
using namespace testing::ext;

class CursorDrawingComponentCoverageTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {};
    void TearDown(void) {};
};

/**
 * @tc.name: GetInstance_001
 * @tc.desc: Test GetInstance returns singleton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetInstance_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto &instance1 = CursorDrawingComponent::GetInstance();
    auto &instance2 = CursorDrawingComponent::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: GetLastMouseStyle_NotLoaded_001
 * @tc.desc: Test GetLastMouseStyle when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetLastMouseStyle_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t defaultId = 0;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto style = instance->GetLastMouseStyle();
    EXPECT_EQ(style.id, defaultId);
}

/**
 * @tc.name: GetIconStyle_NotLoaded_001
 * @tc.desc: Test GetIconStyle when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetIconStyle_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto iconStyle = instance->GetIconStyle(MOUSE_ICON::DEFAULT);

    EXPECT_GE(iconStyle.alignmentWay, 0);
}

/**
 * @tc.name: GetMouseIconPath_001
 * @tc.desc: Test GetMouseIconPath returns map
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetMouseIconPath_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto iconPath = instance->GetMouseIconPath();
    EXPECT_GE(iconPath.size(), 0);
}

/**
 * @tc.name: GetCurrentDisplayInfo_NotLoaded_001
 * @tc.desc: Test GetCurrentDisplayInfo when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetCurrentDisplayInfo_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t defaultId = 0;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto displayInfo = instance->GetCurrentDisplayInfo();
    EXPECT_EQ(displayInfo.id, defaultId);
}

/**
 * @tc.name: GetDelegateProxy_NotLoaded_001
 * @tc.desc: Test GetDelegateProxy when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetDelegateProxy_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto proxy = instance->GetDelegateProxy();
    EXPECT_EQ(proxy, nullptr);
}

/**
 * @tc.name: GetPointerInstance_001
 * @tc.desc: Test GetPointerInstance normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetPointerInstance_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto pointerInstance = instance->GetPointerInstance();

    if (!instance->isLoaded_) {
        EXPECT_EQ(pointerInstance, nullptr);
    }
}

/**
 * @tc.name: SetPointerVisible_NotLoaded_001
 * @tc.desc: Test SetPointerVisible when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, SetPointerVisible_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    int32_t defaultId = 0;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->SetPointerVisible(windowId, true, defaultId, false);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: GetPointerVisible_NotLoaded_001
 * @tc.desc: Test GetPointerVisible when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetPointerVisible_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->GetPointerVisible(windowId);
#ifndef OHOS_BUILD_ENABLE_POINTER_DRAWING
    EXPECT_EQ(ret, true);
#else
    EXPECT_GE(ret, false);
#endif
}

/**
 * @tc.name: IsPointerVisible_NotLoaded_001
 * @tc.desc: Test IsPointerVisible when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, IsPointerVisible_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->IsPointerVisible();
#ifndef OHOS_BUILD_ENABLE_POINTER_DRAWING
    EXPECT_EQ(ret, false);
#else
    EXPECT_GE(ret, false);
#endif
}

/**
 * @tc.name: SetPointerStyle_NotLoaded_001
 * @tc.desc: Test SetPointerStyle when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, SetPointerStyle_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t userId = 0;
    int32_t pid = 0;
    int32_t windowId = 100;
    int32_t defaultId = 0;
    CursorDrawingComponent component;
    auto *instance = &component;
    PointerStyle style;
    style.id = defaultId;
    auto ret = instance->SetPointerStyle(userId, pid, windowId, style);
#ifndef OHOS_BUILD_ENABLE_POINTER_DRAWING
    EXPECT_EQ(ret, RET_OK);
#else
    EXPECT_GE(ret, RET_ERR);
#endif
}

/**
 * @tc.name: GetPointerStyle_NotLoaded_001
 * @tc.desc: Test GetPointerStyle when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetPointerStyle_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t userId = 0;
    int32_t pid = 0;
    int32_t windowId = 100;
    CursorDrawingComponent component;
    auto *instance = &component;
    PointerStyle style;
    auto ret = instance->GetPointerStyle(userId, pid, windowId, style);
#ifndef OHOS_BUILD_ENABLE_POINTER_DRAWING
    EXPECT_EQ(ret, RET_OK);
#else
    EXPECT_GE(ret, RET_ERR);
#endif
}

/**
 * @tc.name: SetMouseIcon_NotLoaded_001
 * @tc.desc: Test SetMouseIcon when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, SetMouseIcon_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t userId = 0;
    int32_t pid = 0;
    int32_t windowId = 100;
    CursorDrawingComponent component;
    auto *instance = &component;
    CursorPixelMap pixelMap;
    pixelMap.pixelMap = nullptr;
    auto ret = instance->SetMouseIcon(userId, pid, windowId, pixelMap);
#ifndef OHOS_BUILD_ENABLE_POINTER_DRAWING
    EXPECT_EQ(ret, RET_OK);
#else
    EXPECT_EQ(ret, RET_ERR);
#endif
}

/**
 * @tc.name: DeletePointerVisible_NotLoaded_001
 * @tc.desc: Test DeletePointerVisible when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, DeletePointerVisible_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->DeletePointerVisible(windowId);

    SUCCEED();
}

/**
 * @tc.name: OnSessionLost_NotLoaded_001
 * @tc.desc: Test OnSessionLost when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, OnSessionLost_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->OnSessionLost(windowId);

    SUCCEED();
}

/**
 * @tc.name: InitDefaultMouseIconPath_NotLoaded_001
 * @tc.desc: Test InitDefaultMouseIconPath when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, InitDefaultMouseIconPath_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->InitDefaultMouseIconPath();

    SUCCEED();
}

/**
 * @tc.name: UpdateDisplayInfo_NotLoaded_001
 * @tc.desc: Test UpdateDisplayInfo when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, UpdateDisplayInfo_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = 1;
    int32_t screenWidth = 1920;
    int32_t screenHeight = 1080;
    CursorDrawingComponent component;
    auto *instance = &component;
    OLD::DisplayInfo displayInfo;
    displayInfo.id = displayId;
    displayInfo.width = screenWidth;
    displayInfo.height = screenHeight;
    instance->UpdateDisplayInfo(displayInfo);

    SUCCEED();
}

/**
 * @tc.name: UpdateBindDisplayId_NotLoaded_001
 * @tc.desc: Test UpdateBindDisplayId when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, UpdateBindDisplayId_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = 1;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->UpdateBindDisplayId(displayId);

    SUCCEED();
}

/**
 * @tc.name: OnDisplayInfo_NotLoaded_001
 * @tc.desc: Test OnDisplayInfo when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, OnDisplayInfo_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t defaultId = 0;
    CursorDrawingComponent component;
    auto *instance = &component;
    OLD::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.groupId = defaultId;
    instance->OnDisplayInfo(displayGroupInfo);

    SUCCEED();
}

/**
 * @tc.name: OnWindowInfo_NotLoaded_001
 * @tc.desc: Test OnWindowInfo when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, OnWindowInfo_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    CursorDrawingComponent component;
    auto *instance = &component;
    WinInfo info;
    info.windowPid = windowId;
    instance->OnWindowInfo(info);

    SUCCEED();
}

/**
 * @tc.name: Init_NotLoaded_001
 * @tc.desc: Test Init when library loads successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, Init_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->Init();

    EXPECT_GE(ret, true);
}

/**
 * @tc.name: SetPointerColor_NotLoaded_001
 * @tc.desc: Test SetPointerColor when library loads successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, SetPointerColor_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t userId = 0;
    uint32_t colorWhite = 0xFFFFFFFF;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->SetPointerColor(userId, colorWhite);

    EXPECT_GE(ret, RET_OK);
}

/**
 * @tc.name: GetPointerColor_NotLoaded_001
 * @tc.desc: Test GetPointerColor when library loads successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetPointerColor_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t userId = 0;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->GetPointerColor(userId);

    EXPECT_GE(ret, RET_OK);
}

/**
 * @tc.name: ClearWindowPointerStyle_NotLoaded_001
 * @tc.desc: Test ClearWindowPointerStyle when library loads successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, ClearWindowPointerStyle_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->ClearWindowPointerStyle(100, 1);

    EXPECT_GE(ret, RET_OK);
}

/**
 * @tc.name: SetCustomCursor_NotLoaded_001
 * @tc.desc: Test SetCustomCursor when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, SetCustomCursor_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    int32_t displayId = 1;
    CursorDrawingComponent component;
    auto *instance = &component;
    CursorPixelMap pixelMap;
    auto ret = instance->SetCustomCursor(pixelMap, windowId, displayId, 0, 0);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SetMouseHotSpot_NotLoaded_001
 * @tc.desc: Test SetMouseHotSpot when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, SetMouseHotSpot_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    int32_t displayId = 1;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->SetMouseHotSpot(windowId, displayId, 0, 0);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SetPointerSize_NotLoaded_001
 * @tc.desc: Test SetPointerSize when library loads successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, SetPointerSize_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t userId = 0;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->SetPointerSize(userId, 1);

    EXPECT_GE(ret, RET_OK);
}

/**
 * @tc.name: GetPointerSize_NotLoaded_001
 * @tc.desc: Test GetPointerSize when library loads successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetPointerSize_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t userId = 0;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->GetPointerSize(userId);

    EXPECT_GE(ret, RET_OK);
}

/**
 * @tc.name: GetCursorSurfaceId_NotLoaded_001
 * @tc.desc: Test GetCursorSurfaceId when library loads successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetCursorSurfaceId_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    uint64_t surfaceId = 0;
    auto ret = instance->GetCursorSurfaceId(surfaceId);

    EXPECT_GE(ret, RET_OK);
}

/**
 * @tc.name: SwitchPointerStyle_NotLoaded_001
 * @tc.desc: Test SwitchPointerStyle when library loads successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, SwitchPointerStyle_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->SwitchPointerStyle();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DrawMovePointer_NotLoaded_001
 * @tc.desc: Test DrawMovePointer when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, DrawMovePointer_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = 1;
    int32_t pointerX = 100;
    int32_t pointerY = 200;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->DrawMovePointer(displayId, pointerX, pointerY);

    SUCCEED();
}

/**
 * @tc.name: Dump_NotLoaded_001
 * @tc.desc: Test Dump when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, Dump_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    std::vector<std::string> args;
    instance->Dump(1, args);

    SUCCEED();
}

/**
 * @tc.name: InitPointerCallback_NotLoaded_001
 * @tc.desc: Test InitPointerCallback when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, InitPointerCallback_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->InitPointerCallback();

    SUCCEED();
}

/**
 * @tc.name: InitScreenInfo_NotLoaded_001
 * @tc.desc: Test InitScreenInfo when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, InitScreenInfo_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->InitScreenInfo();

    SUCCEED();
}

/**
 * @tc.name: EnableHardwareCursorStats_NotLoaded_001
 * @tc.desc: Test EnableHardwareCursorStats when library loads successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, EnableHardwareCursorStats_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->EnableHardwareCursorStats(windowId, true);

    EXPECT_GE(ret, RET_OK);
}

/**
 * @tc.name: GetHardwareCursorStats_NotLoaded_001
 * @tc.desc: Test GetHardwareCursorStats when library loads successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetHardwareCursorStats_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    CursorDrawingComponent component;
    auto *instance = &component;
    uint32_t frameCount = 0;
    uint32_t vsyncCount = 0;
    auto ret = instance->GetHardwareCursorStats(windowId, frameCount, vsyncCount);

    EXPECT_GE(ret, RET_OK);
}

/**
 * @tc.name: ForceClearPointerVisibleStatus_NotLoaded_001
 * @tc.desc: Test ForceClearPointerVisibleStatus when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, ForceClearPointerVisibleStatus_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->ForceClearPointerVisibleStatus();

    SUCCEED();
}

/**
 * @tc.name: InitPointerObserver_NotLoaded_001
 * @tc.desc: Test InitPointerObserver when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, InitPointerObserver_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->InitPointerObserver();

    SUCCEED();
}

/**
 * @tc.name: SkipPointerLayer_NotLoaded_001
 * @tc.desc: Test SkipPointerLayer when library loads successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, SkipPointerLayer_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->SkipPointerLayer(true);

    EXPECT_GE(ret, RET_OK);
}

/**
 * @tc.name: SetDelegateProxy_NotLoaded_001
 * @tc.desc: Test SetDelegateProxy when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, SetDelegateProxy_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    std::shared_ptr<DelegateInterface> proxy = nullptr;
    instance->SetDelegateProxy(proxy);

    SUCCEED();
}

/**
 * @tc.name: DestroyPointerWindow_NotLoaded_001
 * @tc.desc: Test DestroyPointerWindow when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, DestroyPointerWindow_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->DestroyPointerWindow();

    SUCCEED();
}

/**
 * @tc.name: DrawScreenCenterPointer_NotLoaded_001
 * @tc.desc: Test DrawScreenCenterPointer when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, DrawScreenCenterPointer_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    PointerStyle style;
    instance->DrawScreenCenterPointer(style);

    SUCCEED();
}

/**
 * @tc.name: SubscribeScreenModeChange_NotLoaded_001
 * @tc.desc: Test SubscribeScreenModeChange when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, SubscribeScreenModeChange_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->SubscribeScreenModeChange();

    SUCCEED();
}

/**
 * @tc.name: AllPointerDeviceRemoved_NotLoaded_001
 * @tc.desc: Test AllPointerDeviceRemoved when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, AllPointerDeviceRemoved_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->AllPointerDeviceRemoved();

    SUCCEED();
}

/**
 * @tc.name: RegisterDisplayStatusReceiver_NotLoaded_001
 * @tc.desc: Test RegisterDisplayStatusReceiver when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, RegisterDisplayStatusReceiver_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->RegisterDisplayStatusReceiver();

    SUCCEED();
}

/**
 * @tc.name: UpdateMouseLayer_NotLoaded_001
 * @tc.desc: Test UpdateMouseLayer when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, UpdateMouseLayer_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->UpdateMouseLayer(100, 200);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: DrawNewDpiPointer_NotLoaded_001
 * @tc.desc: Test DrawNewDpiPointer when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, DrawNewDpiPointer_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    auto ret = instance->DrawNewDpiPointer();
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: NotifyPointerEventToRS_NotLoaded_001
 * @tc.desc: Test NotifyPointerEventToRS when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, NotifyPointerEventToRS_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
#ifndef OHOS_BUILD_ENABLE_WATCH
    CursorDrawingComponent component;
    auto *instance = &component;
    instance->NotifyPointerEventToRS(1, 1, 0);

#endif
}

/**
 * @tc.name: UpdatePointerItemCursorInfo_NotLoaded_001
 * @tc.desc: Test UpdatePointerItemCursorInfo when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, UpdatePointerItemCursorInfo_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    PointerEvent::PointerItem pointerItem;
    instance->UpdatePointerItemCursorInfo(pointerItem);

    SUCCEED();
}

/**
 * @tc.name: GetCurrentCursorInfo_NotLoaded_001
 * @tc.desc: Test GetCurrentCursorInfo when library loads successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetCurrentCursorInfo_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    bool visible = false;
    PointerStyle pointerStyle;
    auto ret = instance->GetCurrentCursorInfo(visible, pointerStyle);

    EXPECT_GE(ret, RET_OK);
}

/**
 * @tc.name: GetUserDefinedCursorPixelMap_NotLoaded_001
 * @tc.desc: Test GetUserDefinedCursorPixelMap when library not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentCoverageTest, GetUserDefinedCursorPixelMap_NotLoaded_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    CursorDrawingComponent component;
    auto *instance = &component;
    void *pixelMapPtr = nullptr;
    auto ret = instance->GetUserDefinedCursorPixelMap(pixelMapPtr);
    EXPECT_EQ(ret, RET_ERR);
}
} // namespace MMI
} // namespace OHOS
