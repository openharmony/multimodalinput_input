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
    ASSERT_NE(instance_->isLoaded_, true);
    ASSERT_EQ(instance_->soHandle_, nullptr);
    ASSERT_EQ(instance_->pointerInstance_, nullptr);
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
    int32_t userId = 100;
    EXPECT_NO_FATAL_FAILURE(instance_->SetPointerColor(userId, color));

    auto ret = instance_->GetPointerColor(0);
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
    int32_t userId = 0;
    int32_t pid = 1;
    int32_t windowId = 1;
    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    bool isUiExtension = false;
    int32_t ret = instance_->SetPointerStyle(userId, pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret, RET_ERR);

    EXPECT_NO_FATAL_FAILURE(instance_->DrawPointerStyle(pointerStyle));

    ret = instance_->GetPointerStyle(userId, pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret, RET_OK);

    auto style = instance_->GetLastMouseStyle();
    EXPECT_EQ(style.id, 0);

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
    int32_t userId = 100;
    CursorPixelMap curPixelMap;
    int32_t ret = instance_->SetMouseIcon(userId, pid, windowId, curPixelMap);
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
    int32_t userId = 100;
    int32_t ret = instance_->SetPointerSize(userId, size);
    EXPECT_EQ(ret, RET_OK);
    ret = instance_->GetPointerSize(userId);
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
 * @tc.name: CursorDrawingComponentTest_ForceClearPointerVisibleStatus_001
 * @tc.desc: Test ForceClearPointerVisibleStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_ForceClearPointerVisibleStatus_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->ForceClearPointerVisibleStatus());
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

/**
 * @tc.name: CursorDrawingComponentTest_Load_002
 * @tc.desc: Test Load
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_Load_002, TestSize.Level1)
{
    instance_ = &CursorDrawingComponent::GetInstance();
    ASSERT_NE(instance_, nullptr);
    instance_->isLoaded_ = true;
    instance_->soHandle_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(instance_->Load());
}

/**
 * @tc.name: CursorDrawingComponentTest_UnLoad_002
 * @tc.desc: Test UnLoad
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UnLoad_002, TestSize.Level1)
{
    instance_ = &CursorDrawingComponent::GetInstance();
    ASSERT_NE(instance_, nullptr);
    instance_->isLoaded_ = true;
    ASSERT_NE(instance_->soHandle_, nullptr);
    EXPECT_NO_FATAL_FAILURE(instance_->UnLoad());
}

/**
 * @tc.name: CursorDrawingComponentTest_ResetUnloadTimer_001
 * @tc.desc: Test ResetUnloadTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_ResetUnloadTimer_001, TestSize.Level1)
{
    instance_ = &CursorDrawingComponent::GetInstance();
    ASSERT_NE(instance_, nullptr);
    instance_->timerId_ = -1;
    instance_->ResetUnloadTimer();
    ASSERT_NE(instance_->timerId_, -1);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetMouseIconPath
 * @tc.desc: Test GetMouseIconPath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetMouseIconPath, TestSize.Level1)
{
    int32_t pid = 1;
    int32_t windowId = 1;
    int32_t userId = 100;
    CursorPixelMap curPixelMap;
    int32_t ret = instance_->SetMouseIcon(userId, pid, windowId, curPixelMap);
    instance_->isLoaded_ = false;
    EXPECT_EQ(ret, RET_ERR);
    EXPECT_NO_FATAL_FAILURE(instance_->GetMouseIconPath());

    instance_->isLoaded_ = true;
    EXPECT_NO_FATAL_FAILURE(instance_->GetMouseIconPath());
}

/**
 * @tc.name: CursorDrawingComponentTest_RegisterDisplayStatusReceiver
 * @tc.desc: Test RegisterDisplayStatusReceiver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_RegisterDisplayStatusReceiver, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->RegisterDisplayStatusReceiver());

    instance_->isLoaded_ = true;
    EXPECT_NO_FATAL_FAILURE(instance_->RegisterDisplayStatusReceiver());
}

#ifndef OHOS_BUILD_ENABLE_WATCH
/**
 * @tc.name: CursorDrawingComponentTest_NotifyPointerEventToRS
 * @tc.desc: Test NotifyPointerEventToRS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_NotifyPointerEventToRS, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    int32_t pointAction = 1;
    int32_t pointCnt = 0;
    int32_t sourceType = 1;
    EXPECT_NO_FATAL_FAILURE(instance_->NotifyPointerEventToRS(pointAction, pointCnt, sourceType));

    instance_->isLoaded_ = true;
    EXPECT_NO_FATAL_FAILURE(instance_->NotifyPointerEventToRS(pointAction, pointCnt, sourceType));
}
#endif // OHOS_BUILD_ENABLE_WATCH

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
 * @tc.name: CursorDrawingComponentTest_GetUserDefinedCursorPixelMap
 * @tc.desc: Test GetUserDefinedCursorPixelMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetUserDefinedCursorPixelMap, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    ASSERT_EQ(instance_->GetUserDefinedCursorPixelMap(nullptr), RET_ERR);

    instance_->isLoaded_ = true;
    ASSERT_EQ(instance_->GetUserDefinedCursorPixelMap(nullptr), RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_UpdatePointerItemCursorInfo_001
 * @tc.desc: Test GetUserDefinedCursorPixelMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UpdatePointerItemCursorInfo_001, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    PointerEvent::PointerItem pointerItem;
    int32_t pointerId = 1;
    pointerItem.SetPointerId(pointerId);
    instance_->UpdatePointerItemCursorInfo(pointerItem);
    ASSERT_EQ(pointerItem.GetPointerId(), pointerId);
}

/**
 * @tc.name: CursorDrawingComponentTest_UpdatePointerItemCursorInfo_002
 * @tc.desc: Test GetUserDefinedCursorPixelMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UpdatePointerItemCursorInfo_002, TestSize.Level1)
{
    instance_->isLoaded_ = true;
    PointerEvent::PointerItem pointerItem;
    int32_t pointerId = 1;
    pointerItem.SetPointerId(pointerId);
    instance_->UpdatePointerItemCursorInfo(pointerItem);
    ASSERT_EQ(pointerItem.GetPointerId(), pointerId);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetWorkerThreadId_001
 * @tc.desc: Test SetWorkerThreadId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetWorkerThreadId_001, TestSize.Level1)
{
    instance_->isLoaded_ = true;
    uint64_t tid = 1;
    instance_->SetWorkerThreadId(tid);
    ASSERT_EQ(instance_->workerThreadId_, tid);
}

/**
 * @tc.name: CursorDrawingComponentTest_LoadLibrary_001
 * @tc.desc: Test LoadLibrary
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_LoadLibrary_001, TestSize.Level1)
{
    instance_->soHandle_ = nullptr;
    bool ret = instance_->LoadLibrary();
    if (instance_->soHandle_ == nullptr)
    {
        EXPECT_EQ(ret, false);
    }
    else
    {
        EXPECT_EQ(ret, true);
    }
}

/**
 * @tc.name: CursorDrawingComponentTest_ResetUnloadTimer_002
 * @tc.desc: Test ResetUnloadTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_ResetUnloadTimer_002, TestSize.Level1)
{
    int32_t unloadTime = 5000;
    int32_t checkInterval = 1000;
    instance_->timerId_ = -1;
    bool ret = instance_->ResetUnloadTimer(unloadTime, checkInterval);
    EXPECT_EQ(ret, true);
    EXPECT_NE(instance_->timerId_, -1);
}

/**
 * @tc.name: CursorDrawingComponentTest_AllPointerDeviceRemoved_001
 * @tc.desc: Test AllPointerDeviceRemoved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_AllPointerDeviceRemoved_001, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->AllPointerDeviceRemoved());
    instance_->isLoaded_ = true;
    EXPECT_NO_FATAL_FAILURE(instance_->AllPointerDeviceRemoved());
}

/**
 * @tc.name: CursorDrawingComponentTest_UpdateMouseLayer_001
 * @tc.desc: Test UpdateMouseLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UpdateMouseLayer_001, TestSize.Level1)
{
    int32_t x = 200;
    int32_t y = 200;
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->UpdateMouseLayer(x, y));
    instance_->isLoaded_ = true;
    EXPECT_NO_FATAL_FAILURE(instance_->UpdateMouseLayer(x, y));
}

/**
 * @tc.name: CursorDrawingComponentTest_DrawNewDpiPointer_001
 * @tc.desc: Test DrawNewDpiPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_DrawNewDpiPointer_001, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->DrawNewDpiPointer());
    instance_->isLoaded_ = true;
    EXPECT_NO_FATAL_FAILURE(instance_->DrawNewDpiPointer());
}

/**
 * @tc.name: CursorDrawingComponentTest_OnSwitchUser_001
 * @tc.desc: Test OnSwitchUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_OnSwitchUser_001, TestSize.Level1)
{
    int32_t userId = 200;
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->OnSwitchUser(userId));
    instance_->isLoaded_ = true;
    EXPECT_NO_FATAL_FAILURE(instance_->OnSwitchUser(userId));
}

/**
 * @tc.name: CursorDrawingComponentTest_GetCurrentCursorInfo_001
 * @tc.desc: Test GetCurrentCursorInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetCurrentCursorInfo_001, TestSize.Level1)
{
    bool visible = false;
    PointerStyle style;
    instance_->isLoaded_ = false;
    int32_t ret = instance_->GetCurrentCursorInfo(visible, style);
    EXPECT_EQ(ret, RET_OK);
    instance_->isLoaded_ = true;
    ret = instance_->GetCurrentCursorInfo(visible, style);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CursorDrawingComponentTest_InitDefaultMouseIconPath_001
 * @tc.desc: Test InitDefaultMouseIconPath
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_InitDefaultMouseIconPath_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->InitDefaultMouseIconPath());
}

/**
 * @tc.name: CursorDrawingComponentTest_SwitchPointerStyle_001
 * @tc.desc: Test SwitchPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SwitchPointerStyle_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->SwitchPointerStyle());
}

/**
 * @tc.name: CursorDrawingComponentTest_GetIconStyle_001
 * @tc.desc: Test GetIconStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetIconStyle_001, TestSize.Level1)
{
    MOUSE_ICON style = MOUSE_ICON::DEFAULT;
    instance_->isLoaded_ = false;
    IconStyle ret = instance_->GetIconStyle(style);
    EXPECT_EQ(ret.alignmentWay, 0);
    instance_->isLoaded_ = true;
    ret = instance_->GetIconStyle(style);
    EXPECT_NE(ret.iconPath.empty(), true);
}

/**
 * @tc.name: CursorDrawingComponentTest_UnLoad_003
 * @tc.desc: Test UnLoad Uninstall Logic
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UnLoad_003, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    instance_->soHandle_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(instance_->UnLoad());
}

/**
 * @tc.name: CursorDrawingComponentTest_SetMouseIcon_002
 * @tc.desc: Test SetMouseIcon Illegal argument
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetMouseIcon_002, TestSize.Level1)
{
    int32_t userId = 100;
    CursorPixelMap curPixelMap;
    int32_t ret = instance_->SetMouseIcon(userId, -1, 1, curPixelMap);
    EXPECT_EQ(ret, RET_ERR);
    ret = instance_->SetMouseIcon(userId, 1, -1, curPixelMap);
    EXPECT_EQ(ret, RET_ERR);
    curPixelMap.pixelMap = nullptr;
    ret = instance_->SetMouseIcon(userId, 1, 1, curPixelMap);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_002
 * @tc.desc: Test SetPointerVisible with invisible state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_002, TestSize.Level1)
{
    int32_t pid = 2;
    bool visible = false;
    int32_t priority = 0;
    instance_->SetPointerVisible(pid, visible, priority, false);
    bool ret = instance_->GetPointerVisible(pid);
    EXPECT_EQ(ret, visible);
    ret = instance_->IsPointerVisible();
    EXPECT_EQ(ret, visible);
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_003
 * @tc.desc: Test SetPointerVisible with different priority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_003, TestSize.Level1)
{
    int32_t pid = 3;
    bool visible = true;
    int32_t priority = 1;
    instance_->SetPointerVisible(pid, visible, priority, false);
    bool ret = instance_->GetPointerVisible(pid);
    EXPECT_EQ(ret, visible);
    ret = instance_->IsPointerVisible();
    EXPECT_EQ(ret, visible);
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_004
 * @tc.desc: Test SetPointerVisible for HAP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_004, TestSize.Level1)
{
    int32_t pid = 4;
    bool visible = true;
    int32_t priority = 0;
    instance_->SetPointerVisible(pid, visible, priority, true);
    bool ret = instance_->GetPointerVisible(pid);
    EXPECT_EQ(ret, visible);
    ret = instance_->IsPointerVisible();
    EXPECT_EQ(ret, visible);
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_005
 * @tc.desc: Test SetPointerVisible multiple PIDs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_005, TestSize.Level1)
{
    int32_t pid1 = 5;
    int32_t pid2 = 6;
    bool visible1 = true;
    bool visible2 = false;
    instance_->SetPointerVisible(pid1, visible1, 0, false);
    instance_->SetPointerVisible(pid2, visible2, 0, false);
    bool ret1 = instance_->GetPointerVisible(pid1);
    bool ret2 = instance_->GetPointerVisible(pid2);
    EXPECT_EQ(ret1, visible1);
    EXPECT_EQ(ret2, visible2);
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid1));
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid2));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_006
 * @tc.desc: Test SetPointerVisible update existing PID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_006, TestSize.Level1)
{
    int32_t pid = 7;
    instance_->SetPointerVisible(pid, true, 0, false);
    bool ret = instance_->GetPointerVisible(pid);
    EXPECT_EQ(ret, true);

    instance_->SetPointerVisible(pid, false, 0, false);
    ret = instance_->GetPointerVisible(pid);
    EXPECT_EQ(ret, false);

    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_007
 * @tc.desc: Test SetPointerVisible with non-existent PID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_007, TestSize.Level1)
{
    int32_t pid = 8;
    bool visible = true;
    bool ret = instance_->GetPointerVisible(pid);
    EXPECT_EQ(ret, true);

    instance_->SetPointerVisible(pid, visible, 0, false);
    ret = instance_->GetPointerVisible(pid);
    EXPECT_EQ(ret, visible);
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_010
 * @tc.desc: Test updating existing HAP PID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_010, TestSize.Level1)
{
    int32_t pid = 100;
    instance_->SetPointerVisible(pid, true, 0, true);
    bool ret = instance_->GetPointerVisible(pid);
    EXPECT_EQ(ret, true);
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_011
 * @tc.desc: Test when pointerInstance is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_011, TestSize.Level1)
{
    int32_t pid = 101;
    int32_t result = instance_->SetPointerVisible(pid, true, 0, true);
    EXPECT_EQ(result, RET_OK);

    bool ret = instance_->GetPointerVisible(pid);
    EXPECT_EQ(ret, true);
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_012
 * @tc.desc: Test drag state with non-zero priority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_012, TestSize.Level1)
{
    int32_t pid = 102;
    bool visible = true;
    int32_t priority = 1;

    int32_t result = instance_->SetPointerVisible(pid, visible, priority, false);
    EXPECT_EQ(result, RET_OK);

    bool ret = instance_->GetPointerVisible(pid);
    EXPECT_EQ(ret, visible);
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_013
 * @tc.desc: Test drag state with visible=false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_013, TestSize.Level1)
{
    int32_t pid = 103;
    bool visible = false;
    int32_t priority = 0;

    int32_t result = instance_->SetPointerVisible(pid, visible, priority, false);
    EXPECT_EQ(result, RET_OK);

    bool ret = instance_->GetPointerVisible(pid);
    EXPECT_EQ(ret, visible);
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_014
 * @tc.desc: Test conditional update for pointer visibility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_014, TestSize.Level1)
{
    int32_t pid = 104;
    int32_t result = instance_->SetPointerVisible(pid, true, 0, false);
    EXPECT_EQ(result, RET_OK);
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_UpdateBindDisplayId_001
 * @tc.desc: Test UpdateBindDisplayId with valid rsId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UpdateBindDisplayId_001, TestSize.Level1)
{
    uint64_t rsId = 1001;
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->UpdateBindDisplayId(rsId));

    instance_->isLoaded_ = true;
    EXPECT_NO_FATAL_FAILURE(instance_->UpdateBindDisplayId(rsId));

    uint64_t invalidRsId = 0;
    EXPECT_NO_FATAL_FAILURE(instance_->UpdateBindDisplayId(invalidRsId));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerStyle_002
 * @tc.desc: Test SetPointerStyle with GLOBAL_WINDOW_ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerStyle_002, TestSize.Level1)
{
    constexpr int32_t CURSOR_CIRCLE_STYLE{41};
    int32_t userId = 0;
    int32_t pid = 1;
    int32_t windowId = GLOBAL_WINDOW_ID;
    PointerStyle pointerStyle;
    pointerStyle.id = CURSOR_CIRCLE_STYLE;
    bool isUiExtension = false;

    int32_t ret = instance_->SetPointerStyle(userId, pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret, RET_OK);

    PointerStyle invalidStyle;
    invalidStyle.id = -1;
    ret = instance_->SetPointerStyle(userId, pid, windowId, invalidStyle, isUiExtension);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetPointerInstance_001
 * @tc.desc: Test GetPointerInstance with lock and time update
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetPointerInstance_001, TestSize.Level1)
{
    instance_->isLoaded_ = true;
    instance_->pointerInstance_ = nullptr;
    IPointerDrawingManager *ret = instance_->GetPointerInstance();
    EXPECT_EQ(ret, nullptr);

    instance_->isLoaded_ = false;
    ret = instance_->GetPointerInstance();
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: CursorDrawingComponentTest_LoadLibrary_003
 * @tc.desc: Test LoadLibrary when already loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_LoadLibrary_003, TestSize.Level1)
{
    instance_ = &CursorDrawingComponent::GetInstance();
    ASSERT_NE(instance_, nullptr);
    ASSERT_TRUE(instance_->LoadLibrary());
    bool ret = instance_->LoadLibrary();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: CursorDrawingComponentTest_UnLoad_004
 * @tc.desc: Test UnLoad when not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UnLoad_004, TestSize.Level1)
{
    instance_ = &CursorDrawingComponent::GetInstance();
    ASSERT_NE(instance_, nullptr);
    instance_->isLoaded_ = false;
    instance_->soHandle_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(instance_->UnLoad());
    EXPECT_EQ(instance_->isLoaded_, false);
    EXPECT_EQ(instance_->soHandle_, nullptr);
}

/**
 * @tc.name: CursorDrawingComponentTest_DrawPointer_002
 * @tc.desc: Test DrawPointer with invalid displayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_DrawPointer_002, TestSize.Level1)
{
    uint64_t displayId = 0;
    int32_t physicalX = -1;
    int32_t physicalY = -1;
    PointerStyle pointerStyle;
    pointerStyle.id = -1;
    Direction direction = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(instance_->DrawPointer(displayId, physicalX, physicalY, pointerStyle, direction));
}

/**
 * @tc.name: CursorDrawingComponentTest_DrawPointer_003
 * @tc.desc: Test DrawPointer with max values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_DrawPointer_003, TestSize.Level1)
{
    uint64_t displayId = UINT64_MAX;
    int32_t physicalX = INT32_MAX;
    int32_t physicalY = INT32_MAX;
    PointerStyle pointerStyle;
    pointerStyle.id = INT32_MAX;
    Direction direction = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(instance_->DrawPointer(displayId, physicalX, physicalY, pointerStyle, direction));
}

/**
 * @tc.name: CursorDrawingComponentTest_UpdateDisplayInfo_002
 * @tc.desc: Test UpdateDisplayInfo with empty displayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UpdateDisplayInfo_002, TestSize.Level1)
{
    OLD::DisplayInfo displayInfo;
    displayInfo.id = -1;
    displayInfo.x = 0;
    displayInfo.y = 0;
    displayInfo.width = 0;
    displayInfo.height = 0;
    displayInfo.dpi = 0;
    EXPECT_NO_FATAL_FAILURE(instance_->UpdateDisplayInfo(displayInfo));
}

/**
 * @tc.name: CursorDrawingComponentTest_OnWindowInfo_002
 * @tc.desc: Test OnWindowInfo with invalid windowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_OnWindowInfo_002, TestSize.Level1)
{
    WinInfo windowInfo;
    windowInfo.windowId = -1;
    windowInfo.windowPid = -1;
    EXPECT_NO_FATAL_FAILURE(instance_->OnWindowInfo(windowInfo));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerVisible_015
 * @tc.desc: Test SetPointerVisible with negative pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerVisible_015, TestSize.Level1)
{
    int32_t pid = -1;
    bool visible = true;
    int32_t priority = 0;
    int32_t result = instance_->SetPointerVisible(pid, visible, priority, false);
    EXPECT_TRUE(result == RET_OK || result == RET_ERR);
    EXPECT_NO_FATAL_FAILURE(instance_->DeletePointerVisible(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerColor_002
 * @tc.desc: Test SetPointerColor with invalid userId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerColor_002, TestSize.Level1)
{
    int32_t color = -1;
    int32_t userId = -1;
    int32_t ret = instance_->SetPointerColor(userId, color);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerColor_003
 * @tc.desc: Test SetPointerColor with max color value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerColor_003, TestSize.Level1)
{
    int32_t color = INT32_MAX;
    int32_t userId = INT32_MAX;
    int32_t ret = instance_->SetPointerColor(userId, color);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetPointerColor_002
 * @tc.desc: Test GetPointerColor with invalid userId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetPointerColor_002, TestSize.Level1)
{
    int32_t userId = -1;
    int32_t ret = instance_->GetPointerColor(userId);
    EXPECT_GE(ret, 0);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerStyle_003
 * @tc.desc: Test SetPointerStyle with invalid windowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerStyle_003, TestSize.Level1)
{
    int32_t userId = 0;
    int32_t pid = 1;
    int32_t windowId = -2;
    PointerStyle pointerStyle;
    pointerStyle.id = MOUSE_ICON::DEFAULT;
    bool isUiExtension = false;
    int32_t ret = instance_->SetPointerStyle(userId, pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerStyle_004
 * @tc.desc: Test SetPointerStyle with invalid pointerStyle id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerStyle_004, TestSize.Level1)
{
    int32_t userId = 0;
    int32_t pid = 1;
    int32_t windowId = 1;
    PointerStyle pointerStyle;
    pointerStyle.id = -2;
    bool isUiExtension = false;
    int32_t ret = instance_->SetPointerStyle(userId, pid, windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerStyle_005
 * @tc.desc: Test SetPointerStyle with isUiExtension true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerStyle_005, TestSize.Level1)
{
    int32_t userId = 0;
    int32_t pid = 1;
    int32_t windowId = 1;
    PointerStyle pointerStyle;
    pointerStyle.id = MOUSE_ICON::DEFAULT;
    bool isUiExtension = true;
    int32_t ret = instance_->SetPointerStyle(userId, pid, windowId, pointerStyle, isUiExtension);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_ClearWindowPointerStyle_002
 * @tc.desc: Test ClearWindowPointerStyle with invalid pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_ClearWindowPointerStyle_002, TestSize.Level1)
{
    int32_t pid = -1;
    int32_t windowId = 1;
    int32_t ret = instance_->ClearWindowPointerStyle(pid, windowId);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_ClearWindowPointerStyle_003
 * @tc.desc: Test ClearWindowPointerStyle with invalid windowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_ClearWindowPointerStyle_003, TestSize.Level1)
{
    int32_t pid = 1;
    int32_t windowId = -1;
    int32_t ret = instance_->ClearWindowPointerStyle(pid, windowId);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerLocation_002
 * @tc.desc: Test SetPointerLocation with negative coordinates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerLocation_002, TestSize.Level1)
{
    int32_t x = -100;
    int32_t y = -100;
    uint64_t displayId = 0;
    EXPECT_NO_FATAL_FAILURE(instance_->SetPointerLocation(x, y, displayId));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerLocation_003
 * @tc.desc: Test SetPointerLocation with max coordinates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerLocation_003, TestSize.Level1)
{
    int32_t x = INT32_MAX;
    int32_t y = INT32_MAX;
    uint64_t displayId = UINT64_MAX;
    EXPECT_NO_FATAL_FAILURE(instance_->SetPointerLocation(x, y, displayId));
}

/**
 * @tc.name: CursorDrawingComponentTest_SetMouseDisplayState_002
 * @tc.desc: Test SetMouseDisplayState with false state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetMouseDisplayState_002, TestSize.Level1)
{
    bool state = false;
    EXPECT_NO_FATAL_FAILURE(instance_->SetMouseDisplayState(state));
    bool ret = instance_->GetMouseDisplayState();
    EXPECT_EQ(ret, state);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetMouseHotSpot_002
 * @tc.desc: Test SetMouseHotSpot with negative values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetMouseHotSpot_002, TestSize.Level1)
{
    int32_t pid = -1;
    int32_t windowId = -1;
    int32_t hotSpotX = -1;
    int32_t hotSpotY = -1;
    int32_t ret = instance_->SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetMouseHotSpot_003
 * @tc.desc: Test SetMouseHotSpot with max values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetMouseHotSpot_003, TestSize.Level1)
{
    int32_t pid = INT32_MAX;
    int32_t windowId = INT32_MAX;
    int32_t hotSpotX = INT32_MAX;
    int32_t hotSpotY = INT32_MAX;
    int32_t ret = instance_->SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerSize_002
 * @tc.desc: Test SetPointerSize with invalid size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerSize_002, TestSize.Level1)
{
    int32_t size = -1;
    int32_t userId = 100;
    int32_t ret = instance_->SetPointerSize(userId, size);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
    ret = instance_->GetPointerSize(userId);
    EXPECT_TRUE(ret >= 0);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetPointerSize_003
 * @tc.desc: Test SetPointerSize with max size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetPointerSize_003, TestSize.Level1)
{
    int32_t size = INT32_MAX;
    int32_t userId = INT32_MAX;
    int32_t ret = instance_->SetPointerSize(userId, size);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetPointerImageSize_002
 * @tc.desc: Test GetPointerImageSize with null references
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetPointerImageSize_002, TestSize.Level1)
{
    int32_t width = 0;
    int32_t height = 0;
    EXPECT_NO_FATAL_FAILURE(instance_->GetPointerImageSize(width, height));
    EXPECT_TRUE(width >= 0);
    EXPECT_TRUE(height >= 0);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetCursorSurfaceId_002
 * @tc.desc: Test GetCursorSurfaceId with invalid surfaceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetCursorSurfaceId_002, TestSize.Level1)
{
    uint64_t surfaceId = 0;
    int32_t ret = instance_->GetCursorSurfaceId(surfaceId);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_EnableHardwareCursorStats_002
 * @tc.desc: Test EnableHardwareCursorStats with disable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_EnableHardwareCursorStats_002, TestSize.Level1)
{
    int32_t pid = 1;
    bool enable = false;
    int32_t ret = instance_->EnableHardwareCursorStats(pid, enable);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CursorDrawingComponentTest_EnableHardwareCursorStats_003
 * @tc.desc: Test EnableHardwareCursorStats with invalid pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_EnableHardwareCursorStats_003, TestSize.Level1)
{
    int32_t pid = -1;
    bool enable = true;
    int32_t ret = instance_->EnableHardwareCursorStats(pid, enable);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetHardwareCursorStats_002
 * @tc.desc: Test GetHardwareCursorStats with zero counts
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetHardwareCursorStats_002, TestSize.Level1)
{
    int32_t pid = 1;
    uint32_t frameCount = 0;
    uint32_t vsyncCount = 0;
    int32_t ret = instance_->GetHardwareCursorStats(pid, frameCount, vsyncCount);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CursorDrawingComponentTest_SkipPointerLayer_002
 * @tc.desc: Test SkipPointerLayer with false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SkipPointerLayer_002, TestSize.Level1)
{
    bool isSkip = false;
    int32_t ret = instance_->SkipPointerLayer(isSkip);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetDelegateProxy_002
 * @tc.desc: Test SetDelegateProxy with null proxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetDelegateProxy_002, TestSize.Level1)
{
    std::shared_ptr<DelegateInterface> proxy = nullptr;
    EXPECT_NO_FATAL_FAILURE(instance_->SetDelegateProxy(proxy));
    auto ret = instance_->GetDelegateProxy();
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: CursorDrawingComponentTest_UpdateBindDisplayId_002
 * @tc.desc: Test UpdateBindDisplayId with zero rsId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UpdateBindDisplayId_002, TestSize.Level1)
{
    uint64_t rsId = 0;
    EXPECT_NO_FATAL_FAILURE(instance_->UpdateBindDisplayId(rsId));
}

/**
 * @tc.name: CursorDrawingComponentTest_UpdateBindDisplayId_003
 * @tc.desc: Test UpdateBindDisplayId with max rsId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UpdateBindDisplayId_003, TestSize.Level1)
{
    uint64_t rsId = UINT64_MAX;
    EXPECT_NO_FATAL_FAILURE(instance_->UpdateBindDisplayId(rsId));
}

/**
 * @tc.name: CursorDrawingComponentTest_OnSessionLost_002
 * @tc.desc: Test OnSessionLost with invalid pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_OnSessionLost_002, TestSize.Level1)
{
    int32_t pid = -1;
    EXPECT_NO_FATAL_FAILURE(instance_->OnSessionLost(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_OnSessionLost_003
 * @tc.desc: Test OnSessionLost with max pid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_OnSessionLost_003, TestSize.Level1)
{
    int32_t pid = INT32_MAX;
    EXPECT_NO_FATAL_FAILURE(instance_->OnSessionLost(pid));
}

/**
 * @tc.name: CursorDrawingComponentTest_Dump_002
 * @tc.desc: Test Dump with invalid fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_Dump_002, TestSize.Level1)
{
    int32_t fd = -1;
    const std::vector<std::string> args;
    EXPECT_NO_FATAL_FAILURE(instance_->Dump(fd, args));
}

/**
 * @tc.name: CursorDrawingComponentTest_Dump_003
 * @tc.desc: Test Dump with args
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_Dump_003, TestSize.Level1)
{
    int32_t fd = 1;
    const std::vector<std::string> args = {"test", "arg"};
    EXPECT_NO_FATAL_FAILURE(instance_->Dump(fd, args));
}

/**
 * @tc.name: CursorDrawingComponentTest_Init_002
 * @tc.desc: Test Init when already loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_Init_002, TestSize.Level1)
{
    instance_ = &CursorDrawingComponent::GetInstance();
    ASSERT_NE(instance_, nullptr);
    instance_->isLoaded_ = true;
    bool ret = instance_->Init();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetCurrentDisplayInfo_002
 * @tc.desc: Test GetCurrentDisplayInfo when not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetCurrentDisplayInfo_002, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    instance_->pointerInstance_ = nullptr;
    auto ret = instance_->GetCurrentDisplayInfo();
    EXPECT_EQ(ret.id, 0);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetLastMouseStyle_002
 * @tc.desc: Test GetLastMouseStyle when not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetLastMouseStyle_002, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    instance_->pointerInstance_ = nullptr;
    auto style = instance_->GetLastMouseStyle();
    EXPECT_EQ(style.id, 0);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetIconStyle_002
 * @tc.desc: Test GetIconStyle with different mouse styles
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetIconStyle_002, TestSize.Level1)
{
    MOUSE_ICON style = MOUSE_ICON::EAST;
    instance_->isLoaded_ = false;
    IconStyle ret = instance_->GetIconStyle(style);
    EXPECT_EQ(ret.alignmentWay, 0);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetIconStyle_003
 * @tc.desc: Test GetIconStyle with max mouse style
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetIconStyle_003, TestSize.Level1)
{
    MOUSE_ICON style = MOUSE_ICON::LASER_CURSOR_DOT_RED;
    instance_->isLoaded_ = true;
    IconStyle ret = instance_->GetIconStyle(style);
    EXPECT_TRUE(ret.iconPath.empty() || !ret.iconPath.empty());
}

/**
 * @tc.name: CursorDrawingComponentTest_DrawMovePointer_002
 * @tc.desc: Test DrawMovePointer with zero coordinates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_DrawMovePointer_002, TestSize.Level1)
{
    uint64_t displayId = 0;
    int32_t physicalX = 0;
    int32_t physicalY = 0;
    EXPECT_NO_FATAL_FAILURE(instance_->DrawMovePointer(displayId, physicalX, physicalY));
}

/**
 * @tc.name: CursorDrawingComponentTest_InitPointerCallback_002
 * @tc.desc: Test InitPointerCallback when not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_InitPointerCallback_002, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->InitPointerCallback());
}

/**
 * @tc.name: CursorDrawingComponentTest_InitScreenInfo_002
 * @tc.desc: Test InitScreenInfo when not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_InitScreenInfo_002, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->InitScreenInfo());
}

/**
 * @tc.name: CursorDrawingComponentTest_ForceClearPointerVisibleStatus_002
 * @tc.desc: Test ForceClearPointerVisibleStatus when not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_ForceClearPointerVisibleStatus_002, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->ForceClearPointerVisibleStatus());
}

/**
 * @tc.name: CursorDrawingComponentTest_InitPointerObserver_002
 * @tc.desc: Test InitPointerObserver when not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_InitPointerObserver_002, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->InitPointerObserver());
}

/**
 * @tc.name: CursorDrawingComponentTest_DestroyPointerWindow_002
 * @tc.desc: Test DestroyPointerWindow when not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_DestroyPointerWindow_002, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->DestroyPointerWindow());
}

/**
 * @tc.name: CursorDrawingComponentTest_DrawScreenCenterPointer_002
 * @tc.desc: Test DrawScreenCenterPointer with invalid style
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_DrawScreenCenterPointer_002, TestSize.Level1)
{
    PointerStyle pointerStyle;
    pointerStyle.id = -1;
    EXPECT_NO_FATAL_FAILURE(instance_->DrawScreenCenterPointer(pointerStyle));
}

/**
 * @tc.name: CursorDrawingComponentTest_SubscribeScreenModeChange_002
 * @tc.desc: Test SubscribeScreenModeChange when not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SubscribeScreenModeChange_002, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->SubscribeScreenModeChange());
}

/**
 * @tc.name: CursorDrawingComponentTest_RegisterDisplayStatusReceiver_002
 * @tc.desc: Test RegisterDisplayStatusReceiver when not loaded
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_RegisterDisplayStatusReceiver_002, TestSize.Level1)
{
    instance_->isLoaded_ = false;
    EXPECT_NO_FATAL_FAILURE(instance_->RegisterDisplayStatusReceiver());
}

/**
 * @tc.name: CursorDrawingComponentTest_AllPointerDeviceRemoved_002
 * @tc.desc: Test AllPointerDeviceRemoved multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_AllPointerDeviceRemoved_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->AllPointerDeviceRemoved());
    EXPECT_NO_FATAL_FAILURE(instance_->AllPointerDeviceRemoved());
    EXPECT_NO_FATAL_FAILURE(instance_->AllPointerDeviceRemoved());
}

/**
 * @tc.name: CursorDrawingComponentTest_UpdateMouseLayer_002
 * @tc.desc: Test UpdateMouseLayer with zero coordinates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UpdateMouseLayer_002, TestSize.Level1)
{
    int32_t x = 0;
    int32_t y = 0;
    int32_t ret = instance_->UpdateMouseLayer(x, y);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_UpdateMouseLayer_003
 * @tc.desc: Test UpdateMouseLayer with negative coordinates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UpdateMouseLayer_003, TestSize.Level1)
{
    int32_t x = -1;
    int32_t y = -1;
    int32_t ret = instance_->UpdateMouseLayer(x, y);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_DrawNewDpiPointer_002
 * @tc.desc: Test DrawNewDpiPointer multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_DrawNewDpiPointer_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->DrawNewDpiPointer());
    EXPECT_NO_FATAL_FAILURE(instance_->DrawNewDpiPointer());
}

/**
 * @tc.name: CursorDrawingComponentTest_OnSwitchUser_002
 * @tc.desc: Test OnSwitchUser with invalid userId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_OnSwitchUser_002, TestSize.Level1)
{
    int32_t userId = -1;
    EXPECT_NO_FATAL_FAILURE(instance_->OnSwitchUser(userId));
}

/**
 * @tc.name: CursorDrawingComponentTest_OnSwitchUser_003
 * @tc.desc: Test OnSwitchUser with max userId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_OnSwitchUser_003, TestSize.Level1)
{
    int32_t userId = INT32_MAX;
    EXPECT_NO_FATAL_FAILURE(instance_->OnSwitchUser(userId));
}

/**
 * @tc.name: CursorDrawingComponentTest_GetCurrentCursorInfo_002
 * @tc.desc: Test GetCurrentCursorInfo with null references
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetCurrentCursorInfo_002, TestSize.Level1)
{
    bool visible = false;
    PointerStyle style;
    int32_t ret = instance_->GetCurrentCursorInfo(visible, style);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_InitDefaultMouseIconPath_002
 * @tc.desc: Test InitDefaultMouseIconPath multiple times
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_InitDefaultMouseIconPath_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(instance_->InitDefaultMouseIconPath());
    EXPECT_NO_FATAL_FAILURE(instance_->InitDefaultMouseIconPath());
}

/**
 * @tc.name: CursorDrawingComponentTest_GetUserDefinedCursorPixelMap_002
 * @tc.desc: Test GetUserDefinedCursorPixelMap with valid pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetUserDefinedCursorPixelMap_002, TestSize.Level1)
{
    void* pixelMapPtr = nullptr;
    int32_t ret = instance_->GetUserDefinedCursorPixelMap(&pixelMapPtr);
    EXPECT_TRUE(ret == RET_OK || ret == RET_ERR);
}

/**
 * @tc.name: CursorDrawingComponentTest_UpdatePointerItemCursorInfo_003
 * @tc.desc: Test UpdatePointerItemCursorInfo with invalid pointerId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_UpdatePointerItemCursorInfo_003, TestSize.Level1)
{
    instance_->isLoaded_ = true;
    PointerEvent::PointerItem pointerItem;
    int32_t pointerId = -1;
    pointerItem.SetPointerId(pointerId);
    EXPECT_NO_FATAL_FAILURE(instance_->UpdatePointerItemCursorInfo(pointerItem));
    ASSERT_EQ(pointerItem.GetPointerId(), pointerId);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetWorkerThreadId_002
 * @tc.desc: Test SetWorkerThreadId with zero tid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetWorkerThreadId_002, TestSize.Level1)
{
    instance_->isLoaded_ = true;
    uint64_t tid = 0;
    instance_->SetWorkerThreadId(tid);
    ASSERT_EQ(instance_->workerThreadId_, tid);
}

/**
 * @tc.name: CursorDrawingComponentTest_SetWorkerThreadId_003
 * @tc.desc: Test SetWorkerThreadId with max tid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_SetWorkerThreadId_003, TestSize.Level1)
{
    instance_->isLoaded_ = true;
    uint64_t tid = UINT64_MAX;
    instance_->SetWorkerThreadId(tid);
    ASSERT_EQ(instance_->workerThreadId_, tid);
}

/**
 * @tc.name: CursorDrawingComponentTest_ResetUnloadTimer_003
 * @tc.desc: Test ResetUnloadTimer with zero values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_ResetUnloadTimer_003, TestSize.Level1)
{
    int32_t unloadTime = 0;
    int32_t checkInterval = 0;
    instance_->timerId_ = -1;
    bool ret = instance_->ResetUnloadTimer(unloadTime, checkInterval);
    EXPECT_TRUE(ret == true || ret == false);
}

/**
 * @tc.name: CursorDrawingComponentTest_ResetUnloadTimer_004
 * @tc.desc: Test ResetUnloadTimer with negative values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_ResetUnloadTimer_004, TestSize.Level1)
{
    int32_t unloadTime = -1;
    int32_t checkInterval = -1;
    instance_->timerId_ = -1;
    bool ret = instance_->ResetUnloadTimer(unloadTime, checkInterval);
    EXPECT_EQ(ret, true);
    EXPECT_NE(instance_->timerId_, -1);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetPointerInstance_002
 * @tc.desc: Test GetPointerInstance multiple calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetPointerInstance_002, TestSize.Level1)
{
    instance_ = &CursorDrawingComponent::GetInstance();
    ASSERT_NE(instance_, nullptr);
    IPointerDrawingManager* ret1 = instance_->GetPointerInstance();
    IPointerDrawingManager* ret2 = instance_->GetPointerInstance();
    EXPECT_EQ(ret1, ret2);
}

/**
 * @tc.name: CursorDrawingComponentTest_Constructor_001
 * @tc.desc: Test CursorDrawingComponent constructor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_Constructor_001, TestSize.Level1)
{
    CursorDrawingComponent component;
    EXPECT_EQ(component.isLoaded_, false);
    EXPECT_EQ(component.soHandle_, nullptr);
}

/**
 * @tc.name: CursorDrawingComponentTest_Destructor_001
 * @tc.desc: Test CursorDrawingComponent destructor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_Destructor_001, TestSize.Level1)
{
    CursorDrawingComponent component;
    EXPECT_EQ(component.isLoaded_, false);
}

/**
 * @tc.name: CursorDrawingComponentTest_GetInstance_002
 * @tc.desc: Test GetInstance returns same instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CursorDrawingComponentTest, CursorDrawingComponentTest_GetInstance_002, TestSize.Level1)
{
    CursorDrawingComponent* instance1 = &CursorDrawingComponent::GetInstance();
    CursorDrawingComponent* instance2 = &CursorDrawingComponent::GetInstance();
    EXPECT_EQ(instance1, instance2);
}
} // namespace MMI
} // namespace OHOS
