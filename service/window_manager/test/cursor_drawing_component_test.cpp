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

#include "cursor_drawing_adapter.h"
#include "cursor_drawing_component.h"

using namespace testing::ext;
namespace OHOS {
namespace MMI {

class CursorDrawingComponentTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {};
    void TearDown(void) {};
private:
    static CursorDrawingComponent* instance_;
};

CursorDrawingComponent* CursorDrawingComponentTest::instance_ = nullptr;

class CursorDrawingAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp(void) {};
    void TearDown(void) {};
};

/**
 * @tc.name: CursorDrawingAdapterTest_GetPointerInstance_001
 * @tc.desc: GetPointerInstance will return not nullptr when called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingAdapterTest, CursorDrawingAdapterTest_GetPointerInstance_001, TestSize.Level1)
{
    auto ret = GetPointerInstance();
    EXPECT_NE(ret, nullptr);
}

/**
 * @tc.name: CursorDrawingComponentTest_load_001
 * @tc.desc: Load and UnLoad will success when called twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_load_001, TestSize.Level1)
{
    CursorDrawingComponent cursorDrawingComponent;
    EXPECT_EQ(cursorDrawingComponent.isLoaded_, false);
    EXPECT_EQ(cursorDrawingComponent.soHandle_, nullptr);

    cursorDrawingComponent.Load();
    EXPECT_EQ(cursorDrawingComponent.isLoaded_, true);
    EXPECT_NE(cursorDrawingComponent.soHandle_, nullptr);

    cursorDrawingComponent.UnLoad();
    EXPECT_EQ(cursorDrawingComponent.isLoaded_, false);
    EXPECT_EQ(cursorDrawingComponent.soHandle_, nullptr);

    cursorDrawingComponent.~CursorDrawingComponent();
    EXPECT_EQ(cursorDrawingComponent.isLoaded_, false);
    EXPECT_EQ(cursorDrawingComponent.soHandle_, nullptr);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetInstance_001
 * @tc.desc: GetInstance will return not nullptr when called
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetInstance_001, TestSize.Level1)
{
    instance_ = &CursorDrawingComponent::GetInstance();
    ASSERT_NE(instance_, nullptr);
    ASSERT_EQ(instance_->isLoaded_, true);
    ASSERT_NE(instance_->soHandle_, nullptr);
    ASSERT_NE(instance_->pointerInstance_, nullptr);
    EXPECT_EQ(instance_->Init(), true);
}

/**
 * @tc.name: CursorDrawingComponentTest_DrawPointer_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_DrawPointer_001, TestSize.Level1)
{
    int32_t displayId = 1;
    int32_t physicalX = 1;
    int32_t physicalY = 1;
    PointerStyle pointerStyle;
    Direction direction = DIRECTION0;

    EXPECT_NO_FATAL_FAILURE(instance_->DrawPointer(displayId, physicalX, physicalY, pointerStyle, direction));
}

/**
 * @tc.name: CursorDrawingComponentTest_UpdateDisplayInfo_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UpdateDisplayInfo_001, TestSize.Level1)
{
    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.x =1;
    displayInfo.y = 1;
    displayInfo.width = 2;
    displayInfo.height = 2;
    displayInfo.dpi = 240;
    displayInfo.name = "pp";
    displayInfo.direction = DIRECTION0;
    displayInfo.displayMode = DisplayMode::FULL;
    EXPECT_NO_FATAL_FAILURE(instance_->UpdateDisplayInfo(displayInfo));
}

/**
 * @tc.name: CursorDrawingComponentTest_OnWindowInfo_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_OnWindowInfo_001, TestSize.Level1)
{
    WinInfo windowInfo;
    windowInfo.windowId = 1;
    windowInfo.windowPid = 1;
    EXPECT_NO_FATAL_FAILURE(instance_->OnWindowInfo(windowInfo));
}

/**
 * @tc.name: CursorDrawingComponentTest_OnDisplayInfo_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_OnDisplayInfo_001, TestSize.Level1)
{
    OLD::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 0;

    OLD::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.x =1;
    displayInfo.y = 1;
    displayInfo.width = 2;
    displayInfo.height = 2;
    displayInfo.dpi = 240;
    displayInfo.name = "pp";
    displayInfo.uniq = "pp";
    displayInfo.direction = DIRECTION0;
    displayInfo.displayMode = DisplayMode::FULL;
    displayGroupInfo.displaysInfo.push_back(displayInfo);

    WindowInfo info;
    info.id = 1;
    info.pid = 1;
    info.uid = 1;
    info.area = {1, 1, 1, 1};
    info.defaultHotAreas = { info.area };
    info.pointerHotAreas = { info.area };
    info.pointerChangeAreas = {16, 5, 16, 5, 16, 5, 16, 5};
    info.transform = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
    info.agentWindowId = 1;
    info.flags = 0;
    info.displayId = 0;
    info.zOrder = static_cast<float>(1);
    displayGroupInfo.windowsInfo.push_back(info);

    EXPECT_NO_FATAL_FAILURE(instance_->OnDisplayInfo(displayGroupInfo));

    auto ret = (instance_->GetCurrentDisplayInfo());
    EXPECT_EQ(ret.id, displayInfo.id);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_001, TestSize.Level1)
{
    int32_t pid = 1;
    bool visible = true;
    int32_t priority = 0;
    instance_->SetPointerVisible(pid, visible, priority, false);
    bool ret = instance_->GetPointerVisible(pid);
    EXPECT_EQ(ret, visible);
    ret = instance_->IsPointerVisible();
    EXPECT_EQ(ret, visible);
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerColor_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerColor_001, TestSize.Level1)
{
    int32_t color = 0;
    EXPECT_NO_FATAL_FAILURE(instance_->SetPointerColor(color));

    auto ret = instance_->GetPointerColor();
    EXPECT_EQ(ret, color);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerStyle_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerStyle_001, TestSize.Level1)
{
    int32_t pid = 1;
    int32_t windowId = 1;
    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    bool isUiExtension = false;
    int32_t ret = instance_->SetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret, RET_ERR);

    EXPECT_NO_FATAL_FAILURE(instance_->DrawPointerStyle(pointerStyle));

    ret = instance_->GetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret, RET_OK);

    auto style = instance_->GetLastMouseStyle();
    EXPECT_EQ(style.id, 0);

    ret = instance_->SwitchPointerStyle();
    EXPECT_EQ(ret, RET_OK);

    ret = instance_->ClearWindowPointerStyle(pid, windowId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerLocation_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerLocation_001, TestSize.Level1)
{
    int32_t x = 100;
    int32_t y = 100;
    int32_t displayId = 0;
    EXPECT_NO_FATAL_FAILURE(instance_->SetPointerLocation(x, y, displayId));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetMouseDisplayState_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetMouseDisplayState_001, TestSize.Level1)
{
    bool state = true;
    EXPECT_NO_FATAL_FAILURE(instance_->SetMouseDisplayState(state));
    bool ret = instance_->GetMouseDisplayState();
    EXPECT_EQ(ret, state);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetMouseHotSpot_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetMouseHotSpot_001, TestSize.Level1)
{
    int32_t pid = 1;
    int32_t windowId = 1;
    int32_t hotSpotX = 1;
    int32_t hotSpotY = 1;
    int32_t ret = instance_->SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetMouseIcon_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetMouseIcon_001, TestSize.Level1)
{
    int32_t pid = 1;
    int32_t windowId = 1;
    CursorPixelMap curPixelMap;
    int32_t ret = instance_->SetMouseIcon(pid, windowId, curPixelMap);
    EXPECT_EQ(ret, RET_ERR);

    EXPECT_NO_FATAL_FAILURE(instance_->GetMouseIconPath());
}

/**
 * @tc.name: CursorDrawingComponentTest_SetCustomCursor_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetCustomCursor_001, TestSize.Level1)
{
    CursorPixelMap curPixelMap;
    int32_t pid = 1;
    int32_t windowId = 1;
    int32_t focusX = 1;
    int32_t focusY = 1;
    int32_t ret = instance_->SetCustomCursor(curPixelMap, pid, windowId, focusX, focusY);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetCustomCursor_002
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetCustomCursor_002, TestSize.Level1)
{
    int32_t pid = 1;
    int32_t windowId = 1;
    CustomCursor cursor;
    CursorOptions options;
    int32_t ret = instance_->SetCustomCursor(pid, windowId, cursor, options);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_PointerSize_001
 * @tc.desc: Test SetPointerSize and GetPointerSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerSize_001, TestSize.Level1)
{
    int32_t size = 1;
    int32_t ret = instance_->SetPointerSize(size);
    EXPECT_EQ(ret, RET_OK);
    ret = instance_->GetPointerSize();
    EXPECT_EQ(ret, size);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetPointerImageSize_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetPointerImageSize_001, TestSize.Level1)
{
    int32_t width = 1;
    int32_t height = 1;
    EXPECT_NO_FATAL_FAILURE(instance_->GetPointerImageSize(width, height));
}

/**
 * @tc.name: CursorDrawingComponentTest_GetCursorSurfaceId_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetCursorSurfaceId_001, TestSize.Level1)
{
    uint64_t surfaceId = 1;
    int32_t ret = instance_->GetCursorSurfaceId(surfaceId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CursorDrawingComponentTest_DrawMovePointer_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_DrawMovePointer_001, TestSize.Level1)
{
    int32_t displayId = 1;
    int32_t physicalX = 1;
    int32_t physicalY = 1;
    EXPECT_NO_FATAL_FAILURE(instance_->DrawMovePointer(displayId, physicalX, physicalY));
}

/**
 * @tc.name: CursorDrawingComponentTest_Dump_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_Dump_001, TestSize.Level1)
{
    int32_t fd = 1;
    const std::vector<std::string> args;
    EXPECT_NO_FATAL_FAILURE(instance_->Dump(fd, args));
}

/**
 * @tc.name: CursorDrawingComponentTest_InitPointerCallback_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_InitPointerCallback_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->InitPointerCallback());
}

/**
 * @tc.name: CursorDrawingComponentTest_InitScreenInfo_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_InitScreenInfo_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->InitScreenInfo());
}

/**
 * @tc.name: CursorDrawingComponentTest_EnableHardwareCursorStats_001
 * @tc.desc: Test DrawPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_EnableHardwareCursorStats_001, TestSize.Level1)
{
    int32_t pid = 1;
    bool enable = true;
    int32_t ret = instance_->EnableHardwareCursorStats(pid, enable);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetHardwareCursorStats_001
 * @tc.desc: Test GetHardwareCursorStats
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetHardwareCursorStats_001, TestSize.Level1)
{
    int32_t pid = 1;
    uint32_t frameCount = 1;
    uint32_t vsyncCount = 1;
    int32_t ret = instance_->GetHardwareCursorStats(pid, frameCount, vsyncCount);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CursorDrawingComponentTest_ForceClearPointerVisiableStatus_001
 * @tc.desc: Test ForceClearPointerVisiableStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_ForceClearPointerVisiableStatus_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->ForceClearPointerVisiableStatus());
}

/**
 * @tc.name: CursorDrawingComponentTest_InitPointerObserver_001
 * @tc.desc: Test InitPointerObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_InitPointerObserver_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->InitPointerObserver());
}

/**
 * @tc.name: CursorDrawingComponentTest_OnSessionLost_001
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_OnSessionLost_001, TestSize.Level1)
{
    int32_t pid = 1;
    EXPECT_NO_FATAL_FAILURE(instance_->OnSessionLost(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_SkipPointerLayer_001
 * @tc.desc: Test SkipPointerLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SkipPointerLayer_001, TestSize.Level1)
{
    bool isSkip = true;
    int32_t ret = instance_->SkipPointerLayer(isSkip);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetDelegateProxy_001
 * @tc.desc: Test SetDelegateProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetDelegateProxy_001, TestSize.Level1)
{
    std::shared_ptr<DelegateInterface> proxy;
    EXPECT_NO_FATAL_FAILURE(instance_->SetDelegateProxy(proxy));

    auto ret = instance_->GetDelegateProxy();
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: CursorDrawingComponentTest_DestroyPointerWindow_001
 * @tc.desc: Test DestroyPointerWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_DestroyPointerWindow_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->DestroyPointerWindow());
}

/**
 * @tc.name: CursorDrawingComponentTest_DrawScreenCenterPointer_001
 * @tc.desc: Test DrawScreenCenterPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_DrawScreenCenterPointer_001, TestSize.Level1)
{
    PointerStyle pointerStyle;
    EXPECT_NO_FATAL_FAILURE(instance_->DrawScreenCenterPointer(pointerStyle));
}

/**
 * @tc.name: CursorDrawingComponentTest_SubscribeScreenModeChange_001
 * @tc.desc: Test SubscribeScreenModeChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SubscribeScreenModeChange_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->SubscribeScreenModeChange());
}

/**
 * @tc.name: CursorDrawingComponentTest_RegisterDisplayStatusReceiver_001
 * @tc.desc: Test RegisterDisplayStatusReceiver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_RegisterDisplayStatusReceiver_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->RegisterDisplayStatusReceiver());
}

/**
 * @tc.name: CursorDrawingComponentTest_UpdateMouseLayer_001
 * @tc.desc: Test UpdateMouseLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UpdateMouseLayer_001, TestSize.Level1)
{
    PointerStyle pointerStyle;
    int32_t displayId = 1;
    int32_t physicalX = 1;
    int32_t physicalY = 1;
    int32_t ret = instance_->UpdateMouseLayer(pointerStyle, displayId, physicalX, physicalY);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CursorDrawingComponentTest_DrawNewDpiPointer_001
 * @tc.desc: Test DrawNewDpiPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_DrawNewDpiPointer_001, TestSize.Level1)
{
    int32_t ret = instance_->DrawNewDpiPointer();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetHardCursorEnabled_001
 * @tc.desc: Test GetHardCursorEnabled
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetHardCursorEnabled_001, TestSize.Level1)
{
    bool ret = instance_->GetHardCursorEnabled();
    EXPECT_EQ(ret, false);
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
/**
 * @tc.name: CursorDrawingComponentTest_GetPointerSnapshot_001
 * @tc.desc: Test GetPointerSnapshot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetPointerSnapshot_001, TestSize.Level1)
{
    void *pixelMapPtr = nullptr;
    EXPECT_NO_FATAL_FAILURE(instance_->GetPointerSnapshot(pixelMapPtr));
}
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
} // namespace MMI
} // namespace OHOS
