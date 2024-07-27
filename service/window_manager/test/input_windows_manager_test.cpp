/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "event_filter_handler.h"
#include "input_device_manager.h"
#include "input_event_handler.h"
#include "input_windows_manager.h"
#include "i_pointer_drawing_manager.h"
#include "fingersense_wrapper.h"
#include "mmi_log.h"
#include "pointer_drawing_manager.h"
#include "proto.h"
#include "scene_board_judgement.h"
#include "struct_multimodal.h"
#include "uds_server.h"
#include "window_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputWindowsManagerTest"

namespace OHOS {
namespace MMI {
using namespace testing::ext;
namespace {
InputWindowsManager *g_instance;
constexpr uint32_t DEFAULT_ICON_COLOR { 0xFF };
constexpr int32_t MIDDLE_PIXEL_MAP_WIDTH { 400 };
constexpr int32_t MIDDLE_PIXEL_MAP_HEIGHT { 400 };
constexpr int32_t MAX_PIXEL_MAP_WIDTH { 600 };
constexpr int32_t MAX_PIXEL_MAP_HEIGHT { 600 };
constexpr int32_t INT32_BYTE { 4 };
} // namespace

#ifdef WIN_MGR
#undef WIN_MGR
#endif
#define WIN_MGR g_instance

class InputWindowsManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void) {};
    static std::shared_ptr<Media::PixelMap> CreatePixelMap(int32_t width, int32_t height);
    void SetUp(void)
    {
        // 创建displayGroupInfo_
        DisplayGroupInfo displayGroupInfo;
        displayGroupInfo.width = 20;
        displayGroupInfo.height = 20;
        displayGroupInfo.focusWindowId = 1;
        uint32_t num = 1;
        for (uint32_t i = 0; i < num; i++) {
            WindowInfo info;
            info.id = 1;
            info.pid = 1;
            info.uid = 1;
            info.area = {1, 1, 1, 1};
            info.defaultHotAreas = { info.area };
            info.pointerHotAreas = { info.area };
            info.agentWindowId = 1;
            info.flags = 1;
            info.transform = {1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 1.0f};
            info.pointerChangeAreas = { 1, 2, 1, 2, 1, 2, 1, 2, 1 };
            displayGroupInfo.windowsInfo.push_back(info);
        }
        for (uint32_t i = 0; i < num; i++) {
            DisplayInfo info;
            info.id = 1;
            info.x =1;
            info.y = 1;
            info.width = 2;
            info.height = 2;
            info.dpi = 240;
            info.name = "pp";
            info.uniq = "pp";
            info.direction = DIRECTION0;
            displayGroupInfo.displaysInfo.push_back(info);
        }
        WIN_MGR->UpdateDisplayInfo(displayGroupInfo);
        preHoverScrollState_ = WIN_MGR->GetHoverScrollState();
    } // void SetUp(void)

    void TearDown(void)
    {
        WIN_MGR->SetHoverScrollState(preHoverScrollState_);
    }

private:
    bool preHoverScrollState_ { true };
};

void InputWindowsManagerTest::SetUpTestCase(void)
{
    g_instance = static_cast<InputWindowsManager *>(IInputWindowsManager::GetInstance().get());
}

void FingersenseWrapperTest(int32_t num) {}

std::shared_ptr<Media::PixelMap> InputWindowsManagerTest::CreatePixelMap(int32_t width, int32_t height)
{
    CALL_DEBUG_ENTER;
    if (width <= 0 || width > MAX_PIXEL_MAP_WIDTH || height <= 0 || height > MAX_PIXEL_MAP_HEIGHT) {
        return nullptr;
    }
    Media::InitializationOptions opts;
    opts.size.height = height;
    opts.size.width = width;
    opts.pixelFormat = Media::PixelFormat::BGRA_8888;
    opts.alphaType = Media::AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.scaleMode = Media::ScaleMode::FIT_TARGET_SIZE;

    int32_t colorLen = width * height;
    uint32_t *pixelColors = new (std::nothrow) uint32_t[colorLen];
    CHKPP(pixelColors);
    int32_t colorByteCount = colorLen * INT32_BYTE;
    errno_t ret = memset_s(pixelColors, colorByteCount, DEFAULT_ICON_COLOR, colorByteCount);
    if (ret != EOK) {
        delete[] pixelColors;
        return nullptr;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = Media::PixelMap::Create(pixelColors, colorLen, opts);
    if (pixelMap == nullptr) {
        delete[] pixelColors;
        return nullptr;
    }
    delete[] pixelColors;
    return pixelMap;
}

/**
 * @tc.name: InputWindowsManagerTest_GetClientFd_001
 * @tc.desc: Test GetClientFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetClientFd_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    WIN_MGR->GetDisplayGroupInfo();
    int32_t idNames = -1;
    ASSERT_EQ(WIN_MGR->GetClientFd(pointerEvent), idNames);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTarget_003
 * @tc.desc: Test UpdateTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTarget_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetDeviceId(1);
    keyEvent->SetTargetWindowId(1);
    keyEvent->SetAgentWindowId(1);
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->UpdateTarget(keyEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_HandleKeyEventWindowId_003
 * @tc.desc: Test HandleKeyEventWindowId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_HandleKeyEventWindowId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetDeviceId(1);
    keyEvent->SetTargetWindowId(1);
    keyEvent->SetAgentWindowId(1);
    WIN_MGR->HandleKeyEventWindowId(keyEvent);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateWindow_002
 * @tc.desc: Test UpdateWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateWindow_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo window;
    window.id = 11;
    window.pid = 1221;
    window.uid = 1;
    window.area = {1, 1, 1, 1};
    window.defaultHotAreas = { window.area };
    window.pointerHotAreas = { window.area };
    window.pointerChangeAreas = {1, 2, 1, 2};
    window.displayId = 0;
    window.agentWindowId = 1;
    window.flags = 1;
    window.action = WINDOW_UPDATE_ACTION::UNKNOWN;
    WIN_MGR->UpdateWindowInfo({0, 11, {window}});
    ASSERT_EQ(WIN_MGR->GetWindowPid(11), -1);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTargetPointer_005
 * @tc.desc: Test UpdateTargetPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTargetPointer_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_EQ(WIN_MGR->UpdateTargetPointer(pointerEvent), -1);
}

/**
 * @tc.name: InputWindowsManagerTest_IsNeedRefreshLayer_006
 * @tc.desc: Test IsNeedRefreshLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsNeedRefreshLayer_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        ASSERT_EQ(WIN_MGR->IsNeedRefreshLayer(-1), true);
        ASSERT_EQ(WIN_MGR->IsNeedRefreshLayer(0), true);
        ASSERT_EQ(WIN_MGR->IsNeedRefreshLayer(1), true);
    } else {
        ASSERT_EQ(WIN_MGR->IsNeedRefreshLayer(-1), false);
        ASSERT_EQ(WIN_MGR->IsNeedRefreshLayer(0), false);
        ASSERT_EQ(WIN_MGR->IsNeedRefreshLayer(1), false);
    }
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseCaptureMode_008
 * @tc.desc: Test SetMouseCaptureMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetMouseCaptureMode_008, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    bool isCaptureMode = false;
    ASSERT_EQ(WIN_MGR->SetMouseCaptureMode(-1, isCaptureMode), -1);
    ASSERT_EQ(WIN_MGR->SetMouseCaptureMode(1, isCaptureMode), 0);
    isCaptureMode = true;
    ASSERT_EQ(WIN_MGR->SetMouseCaptureMode(1, isCaptureMode), 0);
}

/**
 * @tc.name: InputWindowsManagerTest_SetDisplayBind_009
 * @tc.desc: Test SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetDisplayBind_009, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    std::string sysUid = "james";
    std::string devStatus = "add";
    WIN_MGR->DeviceStatusChanged(2, sysUid, devStatus);
    devStatus = "remove";
    WIN_MGR->DeviceStatusChanged(2, sysUid, devStatus);
    std::string msg = "There is in InputWindowsManagerTest_GetDisplayIdNames_009";
    ASSERT_EQ(WIN_MGR->SetDisplayBind(-1, 1, msg), -1);
}

/**
 * @tc.name: InputWindowsManagerTest_SetHoverScrollState_010
 * @tc.desc: Test SetHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetHoverScrollState_010, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_TRUE(WIN_MGR->SetHoverScrollState(false) == RET_OK);
    WIN_MGR->SetHoverScrollState(true);
}

/**
 * @tc.name: InputWindowsManagerTest_GetHoverScrollState_011
 * @tc.desc: Test GetHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetHoverScrollState_011, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WIN_MGR->SetHoverScrollState(true);
    ASSERT_TRUE(WIN_MGR->GetHoverScrollState());
}

/**
 * @tc.name: InputWindowsManagerTest_InitMouseDownInfo_001
 * @tc.desc: Test initializing mouse down information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_InitMouseDownInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WIN_MGR->InitMouseDownInfo();
    EXPECT_EQ(WIN_MGR->mouseDownInfo_.id, -1);
    EXPECT_EQ(WIN_MGR->mouseDownInfo_.pid, -1);
    EXPECT_TRUE(WIN_MGR->mouseDownInfo_.defaultHotAreas.empty());
    EXPECT_TRUE(WIN_MGR->mouseDownInfo_.pointerHotAreas.empty());
}

/**
 * @tc.name: InputWindowsManagerTest_InitMouseDownInfo_002
 * @tc.desc: Test initializing mouse down information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_InitMouseDownInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WIN_MGR->mouseDownInfo_.id = 1;
    WIN_MGR->mouseDownInfo_.pid = 123;
    WIN_MGR->mouseDownInfo_.defaultHotAreas.push_back({0, 0, 100, 100});
    WIN_MGR->InitMouseDownInfo();
    EXPECT_EQ(WIN_MGR->mouseDownInfo_.id, -1);
    EXPECT_EQ(WIN_MGR->mouseDownInfo_.pid, -1);
    EXPECT_TRUE(WIN_MGR->mouseDownInfo_.defaultHotAreas.empty());
    EXPECT_TRUE(WIN_MGR->mouseDownInfo_.pointerHotAreas.empty());
}

/**
 * @tc.name: InputWindowsManagerTest_GetWindowGroupInfoByDisplayId_001
 * @tc.desc: Test getting window group information by display ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetWindowGroupInfoByDisplayId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = -1;
    const std::vector<WindowInfo>& windowGroupInfo = WIN_MGR->GetWindowGroupInfoByDisplayId(displayId);
    EXPECT_EQ(windowGroupInfo.size(), 1);
}

/**
 * @tc.name: InputWindowsManagerTest_GetWindowGroupInfoByDisplayId_002
 * @tc.desc: Test getting window group information by display ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetWindowGroupInfoByDisplayId_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = 1;
    const std::vector<WindowInfo>& windowGroupInfo = WIN_MGR->GetWindowGroupInfoByDisplayId(displayId);
    EXPECT_FALSE(windowGroupInfo.empty());
}

/**
 * @tc.name: InputWindowsManagerTest_GetDisplayId_001
 * @tc.desc: Test getting the display ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetDisplayId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t expectedDisplayId = 1;
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->SetTargetDisplayId(expectedDisplayId);
    int32_t ret = WIN_MGR->GetDisplayId(inputEvent);
    EXPECT_EQ(ret, expectedDisplayId);
}

/**
 * @tc.name: InputWindowsManagerTest_GetPidAndUpdateTarget_001
 * @tc.desc: Test getting PID and updating the target
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetPidAndUpdateTarget_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    EXPECT_NE(keyEvent, nullptr);
    int32_t targetDisplayId = 0;
    keyEvent->SetTargetDisplayId(targetDisplayId);
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->GetPidAndUpdateTarget(keyEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_GetWindowPid_001
 * @tc.desc: Test getting the process ID of a window
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetWindowPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 100;
    std::vector<WindowInfo> windowsInfo;
    int32_t ret = WIN_MGR->GetWindowPid(windowId,  windowsInfo);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: InputWindowsManagerTest_CheckFocusWindowChange_001
 * @tc.desc: Test checking focus window changes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CheckFocusWindowChange_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 123;
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->CheckFocusWindowChange(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_CheckFocusWindowChange_002
 * @tc.desc: Test checking focus window changes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CheckFocusWindowChange_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    DisplayGroupInfo displayGroupInfo_;
    displayGroupInfo.focusWindowId = 123;
    displayGroupInfo_.focusWindowId = 456;
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->CheckFocusWindowChange(displayGroupInfo));
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->CheckFocusWindowChange(displayGroupInfo_));
}

/**
 * @tc.name: InputWindowsManagerTest_CheckZorderWindowChange_001
 * @tc.desc: Test checking Z-order window changes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CheckZorderWindowChange_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<WindowInfo> oldWindowsInfo = {{1}};
    std::vector<WindowInfo> newWindowsInfo = {{2}};
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->CheckZorderWindowChange(oldWindowsInfo, newWindowsInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDisplayIdAndName_001
 * @tc.desc: Test updating display ID and name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateDisplayIdAndName_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->UpdateDisplayIdAndName());
    assert(WIN_MGR->GetDisplayIdNames().size() == 2);
    assert(WIN_MGR->IsDisplayAdd(1, "A"));
    assert(WIN_MGR->IsDisplayAdd(2, "B"));
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->UpdateDisplayIdAndName());
    assert(WIN_MGR->GetDisplayIdNames().size() == 2);
    assert(WIN_MGR->IsDisplayAdd(1, "A"));
    assert(WIN_MGR->IsDisplayAdd(3, "C"));
    assert(!WIN_MGR->IsDisplayAdd(2, "B"));
}

/**
 * @tc.name: InputWindowsManagerTest_GetDisplayBindInfo_001
 * @tc.desc: Test getting display binding information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetDisplayBindInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t deviceId = 1;
    int32_t displayId = 2;
    DisplayBindInfos infos;
    std::string msg;
    int32_t ret = WIN_MGR->SetDisplayBind(deviceId, displayId, msg);
    EXPECT_EQ(ret, -1);
    ret = WIN_MGR->GetDisplayBindInfo(infos);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateCaptureMode_001
 * @tc.desc: Test updating capture mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateCaptureMode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 123;
    WIN_MGR->UpdateCaptureMode(displayGroupInfo);
    EXPECT_FALSE(WIN_MGR->captureModeInfo_.isCaptureMode);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDisplayInfoByIncrementalInfo_001
 * @tc.desc: Test updating display information by incremental info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateDisplayInfoByIncrementalInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 1;
    WindowInfo window;
    WIN_MGR->UpdateDisplayInfoByIncrementalInfo(window, displayGroupInfo);
    EXPECT_EQ(displayGroupInfo.windowsInfo.size(), 0);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateWindowsInfoPerDisplay_001
 * @tc.desc: Test updating window information for each display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateWindowsInfoPerDisplay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 2;
    WIN_MGR->UpdateWindowsInfoPerDisplay(displayGroupInfo);
    WindowInfo window1{1};
    WindowInfo window2{2};
    displayGroupInfo.windowsInfo.push_back(window1);
    displayGroupInfo.windowsInfo.push_back(window2);
    WIN_MGR->UpdateDisplayInfo(displayGroupInfo);
    ASSERT_EQ(displayGroupInfo.windowsInfo.size(), 2);
    ASSERT_EQ(displayGroupInfo.windowsInfo[0].zOrder, 0);
    ASSERT_EQ(displayGroupInfo.windowsInfo[1].zOrder, 0);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDisplayInfo_001
 * @tc.desc: Test updating display information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    WindowInfo windowInfo1;
    windowInfo1.zOrder = 1;
    windowInfo1.action = WINDOW_UPDATE_ACTION::ADD_END;
    WindowInfo windowInfo2;
    windowInfo2.zOrder = 2;
    windowInfo2.action = WINDOW_UPDATE_ACTION::ADD_END;
    displayGroupInfo.windowsInfo.push_back(windowInfo1);
    displayGroupInfo.windowsInfo.push_back(windowInfo2);
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->UpdateDisplayInfo(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_NeedUpdatePointDrawFlag_001
 * @tc.desc: Test whether the point draw flag needs to be updated
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_NeedUpdatePointDrawFlag_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<WindowInfo> windows1;
    EXPECT_FALSE(WIN_MGR->NeedUpdatePointDrawFlag(windows1));
    std::vector<WindowInfo> windows2;
    windows2.push_back(WindowInfo());
    windows2.back().action = OHOS::MMI::WINDOW_UPDATE_ACTION::ADD;
    EXPECT_FALSE(WIN_MGR->NeedUpdatePointDrawFlag(windows2));
    std::vector<WindowInfo> windows3;
    windows3.push_back(WindowInfo());
    windows3.back().action = OHOS::MMI::WINDOW_UPDATE_ACTION::ADD_END;
    EXPECT_TRUE(WIN_MGR->NeedUpdatePointDrawFlag(windows3));
}

/**
 * @tc.name: InputWindowsManagerTest_GetPointerStyleByArea_001
 * @tc.desc: Test getting pointer style by area
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetPointerStyleByArea_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowArea area;
    int32_t pid = 123;
    int32_t winId = 678;
    PointerStyle pointerStyle;
    pointerStyle.size = 1;
    pointerStyle.color = 2;
    pointerStyle.id = 3;
    area = WindowArea::TOP_LEFT_LIMIT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::SOUTH_EAST);
    area = WindowArea::TOP_RIGHT_LIMIT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::SOUTH_WEST);
    area = WindowArea::TOP_LIMIT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::SOUTH);
    area = WindowArea::LEFT_LIMIT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::EAST);
    area = WindowArea::RIGHT_LIMIT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::WEST);
    area = WindowArea::BOTTOM_LEFT_LIMIT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_WEST);
    area = WindowArea::BOTTOM_LIMIT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_WEST);
    area = WindowArea::BOTTOM_RIGHT_LIMIT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_WEST);
    area = WindowArea::FOCUS_ON_INNER;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_WEST);
}

/**
 * @tc.name: InputWindowsManagerTest_GetPointerStyleByArea_002
 * @tc.desc: Test getting pointer style by area
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetPointerStyleByArea_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowArea area;
    int32_t pid = 123;
    int32_t winId = 678;
    PointerStyle pointerStyle;
    pointerStyle.size = 1;
    pointerStyle.color = 2;
    pointerStyle.id = 3;
    area = WindowArea::ENTER;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::SOUTH);
    area = WindowArea::EXIT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::SOUTH);
    area = WindowArea::FOCUS_ON_TOP_LEFT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_WEST_SOUTH_EAST);
    area = WindowArea::FOCUS_ON_BOTTOM_RIGHT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_WEST_SOUTH_EAST);
    area = WindowArea::FOCUS_ON_TOP_RIGHT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_EAST_SOUTH_WEST);
    area = WindowArea::FOCUS_ON_BOTTOM_LEFT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_EAST_SOUTH_WEST);
    area = WindowArea::FOCUS_ON_TOP;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_SOUTH);
    area = WindowArea::FOCUS_ON_BOTTOM;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_SOUTH);
    area = WindowArea::FOCUS_ON_LEFT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::WEST_EAST);
    area = WindowArea::FOCUS_ON_RIGHT;
    WIN_MGR->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::WEST_EAST);
}

/**
 * @tc.name: InputWindowsManagerTest_SetWindowPointerStyle_001
 * @tc.desc: Test setting window pointer style
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetWindowPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowArea area;
    int32_t pid = 1;
    int32_t windowId = 2;
    IconStyle defaultIconStyle;
    area = WindowArea::ENTER;
    defaultIconStyle.iconPath = "default_icon_path";
    WIN_MGR->SetWindowPointerStyle(area, pid, windowId);
    assert(lastPointerStyle_.id == pointerStyle.id);
    assert(windowId != GLOBAL_WINDOW_ID && (pointerStyle.id == MOUSE_ICON::DEFAULT &&
        mouseIcons[MOUSE_ICON(pointerStyle.id)].iconPath != DEFAULT_ICON_PATH));
    assert(WIN_MGR->GetPointerStyle(pid, GLOBAL_WINDOW_ID, style) == RET_OK);
    assert(lastPointerStyle_.id == style.id);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateWindowPointerVisible_001
 * @tc.desc: Test updating window pointer visibility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateWindowPointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = 123;
    bool visible = true;
    IPointerDrawingManager::GetInstance()->GetPointerVisible(pid);
    IPointerDrawingManager::GetInstance()->SetPointerVisible(pid, visible, 0, false);
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->UpdateWindowPointerVisible(pid));
}

/**
 * @tc.name: InputWindowsManagerTest_DispatchPointer_001
 * @tc.desc: Test dispatching pointer events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_DispatchPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_ENTER_WINDOW;
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->DispatchPointer(pointerAction));
    pointerAction = PointerEvent::POINTER_ACTION_LEAVE_WINDOW;
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->DispatchPointer(pointerAction));
    pointerAction = PointerEvent::POINTER_ACTION_MOVE;
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->DispatchPointer(pointerAction));
}

/**
 * @tc.name: InputWindowsManagerTest_NotifyPointerToWindow_001
 * @tc.desc: Test notifying pointer events to window
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_NotifyPointerToWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    inputWindowsManager.lastPointerEvent_ = nullptr;
    inputWindowsManager.NotifyPointerToWindow();
    EXPECT_EQ(inputWindowsManager.lastWindowInfo_.id, -1);
}

/**
 * @tc.name: InputWindowsManagerTest_PrintWindowInfo_001
 * @tc.desc: Test printing window information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_PrintWindowInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo1;
    windowInfo1.id = 1;
    windowInfo1.pid = 100;
    windowInfo1.uid = 200;
    windowInfo1.area = {0, 0, 800, 600};
    windowInfo1.defaultHotAreas = {{10, 10, 100, 100}, {200, 200, 50, 50}};
    windowInfo1.pointerHotAreas = {{30, 30, 150, 150}, {400, 400, 70, 70}};
    windowInfo1.agentWindowId = 10;
    windowInfo1.flags = 1;
    windowInfo1.displayId = 3;
    windowInfo1.zOrder = 4.0f;
    windowInfo1.pointerChangeAreas = {10, 20, 30};
    windowInfo1.transform = {1.0f, 2.0f, 3.0f};
    WindowInfo windowInfo2;
    windowInfo2.id = 2;
    windowInfo2.pid = 101;
    windowInfo2.uid = 201;
    windowInfo2.area = {800, 600, 1024, 768};
    windowInfo2.defaultHotAreas = {{50, 50, 200, 200}, {600, 600, 100, 100}};
    windowInfo2.pointerHotAreas = {{70, 70, 250, 250}, {800, 800, 120, 120}};
    windowInfo2.agentWindowId = 20;
    windowInfo2.flags = 2;
    windowInfo2.displayId = 4;
    windowInfo2.zOrder = 5.0f;
    windowInfo2.pointerChangeAreas = {40, 50, 60};
    windowInfo2.transform = {4.0f, 5.0f, 6.0f};
    std::vector<WindowInfo> windowsInfo = {windowInfo1, windowInfo2};
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->PrintWindowInfo(windowsInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_PrintWindowGroupInfo_001
 * @tc.desc: Test printing window group information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_PrintWindowGroupInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowGroupInfo testData;
    testData.focusWindowId = 1;
    testData.displayId = 2;
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->PrintWindowGroupInfo(testData));
}

/**
 * @tc.name: InputWindowsManagerTest_PrintDisplayInfo_001
 * @tc.desc: Test printing display information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_PrintDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager manager;
    manager.displayGroupInfo_.width = 1920;
    manager.displayGroupInfo_.height = 1080;
    manager.displayGroupInfo_.focusWindowId = 1;
    manager.displayGroupInfo_.windowsInfo.push_back(WindowInfo());
    manager.displayGroupInfo_.displaysInfo.push_back(DisplayInfo());
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->PrintDisplayInfo());
}

/**
 * @tc.name: InputWindowsManagerTest_GetPhysicalDisplay_001
 * @tc.desc: Test getting physical display information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetPhysicalDisplay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t id = 1;
    const DisplayInfo* displayInfo = WIN_MGR->GetPhysicalDisplay(id);
    EXPECT_NE(displayInfo, nullptr);
    EXPECT_EQ(displayInfo->id, id);
}

/**
 * @tc.name: InputWindowsManagerTest_GetPhysicalDisplay_002
 * @tc.desc: Test getting physical display information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetPhysicalDisplay_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t id = -1;
    const DisplayInfo* displayInfo = WIN_MGR->GetPhysicalDisplay(id);
    EXPECT_EQ(displayInfo, nullptr);
}

/**
 * @tc.name: InputWindowsManagerTest_FindPhysicalDisplayInfo_001
 * @tc.desc: Test finding physical display information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_FindPhysicalDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager manager;
    ASSERT_EQ(manager.FindPhysicalDisplayInfo("test"), nullptr);
    DisplayInfo info1;
    info1.id = 123;
    manager.displayGroupInfo_.displaysInfo.push_back(info1);
    ASSERT_NE(manager.FindPhysicalDisplayInfo("test"), nullptr);
    DisplayInfo info2;
    info2.id = 456;
    manager.displayGroupInfo_.displaysInfo.push_back(info2);
    ASSERT_NE(manager.FindPhysicalDisplayInfo("test"), nullptr);
    ASSERT_NE(manager.FindPhysicalDisplayInfo("not_matching"), nullptr);
    ASSERT_NE(manager.FindPhysicalDisplayInfo("nonexistent"), nullptr);
}

/**
 * @tc.name: InputWindowsManagerTest_RotateScreen_001
 * @tc.desc: Test rotating the screen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_RotateScreen_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo info;
    PhysicalCoordinate coord;
    info.direction = DIRECTION0;
    coord.x = 10;
    coord.y = 20;
    WIN_MGR->RotateScreen(info, coord);
    EXPECT_EQ(coord.x, 10);
    EXPECT_EQ(coord.y, 20);
}

/**
 * @tc.name: InputWindowsManagerTest_RotateScreen_002
 * @tc.desc: Test rotating the screen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_RotateScreen_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo info;
    PhysicalCoordinate coord;
    info.direction = DIRECTION90;
    info.width = 800;
    info.height = 600;
    coord.x = 10;
    coord.y = 20;
    WIN_MGR->RotateScreen(info, coord);
    EXPECT_EQ(coord.x, 580);
    EXPECT_EQ(coord.y, 10);
}

/**
 * @tc.name: InputWindowsManagerTest_RotateScreen_003
 * @tc.desc: Test rotating the screen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_RotateScreen_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo info;
    PhysicalCoordinate coord;
    info.direction = DIRECTION180;
    info.width = 800;
    info.height = 600;
    coord.x = 10;
    coord.y = 20;
    WIN_MGR->RotateScreen(info, coord);
    EXPECT_EQ(coord.x, 790);
    EXPECT_EQ(coord.y, 580);
}

/**
 * @tc.name: InputWindowsManagerTest_RotateScreen_004
 * @tc.desc: Test rotating the screen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_RotateScreen_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo info;
    PhysicalCoordinate coord;
    info.direction = DIRECTION270;
    info.width = 800;
    info.height = 600;
    coord.x = 10;
    coord.y = 20;
    WIN_MGR->RotateScreen(info, coord);
    EXPECT_EQ(coord.x, 20);
    EXPECT_EQ(coord.y, 790);
}

/**
 * @tc.name: InputWindowsManagerTest_IsNeedRefreshLayer_001
 * @tc.desc: Test whether layer refresh is needed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsNeedRefreshLayer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(WIN_MGR->IsNeedRefreshLayer(1));
    WIN_MGR->GetWindowInfo(0, 0)->id = 2;
    EXPECT_FALSE(WIN_MGR->IsNeedRefreshLayer(GLOBAL_WINDOW_ID));
    WIN_MGR->GetWindowInfo(0, 0)->id = 3;
    EXPECT_FALSE(WIN_MGR->IsNeedRefreshLayer(1));
}

/**
 * @tc.name: InputWindowsManagerTest_OnSessionLost_001
 * @tc.desc: Test handling when session is lost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_OnSessionLost_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    SessionPtr session = std::shared_ptr<UDSSession>();
    WIN_MGR->OnSessionLost(session);
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->GetDisplayGroupInfo());
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePoinerStyle_001
 * @tc.desc: Test updating pointer style
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdatePoinerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = 1;
    int32_t windowId = 2;
    PointerStyle pointerStyle;
    int32_t ret = WIN_MGR->UpdatePoinerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, RET_OK);
    pid = -1;
    windowId = -2;
    ret = WIN_MGR->UpdatePoinerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, 401);
    pid = 1;
    windowId = -2;
    ret = WIN_MGR->UpdatePoinerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateSceneBoardPointerStyle_001
 * @tc.desc: Test updating scene board pointer style
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateSceneBoardPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = 1;
    int32_t windowId = 2;
    PointerStyle pointerStyle;
    pointerStyle.id = 3;
    int32_t ret = WIN_MGR->UpdateSceneBoardPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, RET_OK);
    pid = -1;
    windowId = -2;
    ret = WIN_MGR->UpdateSceneBoardPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerStyle_001
 * @tc.desc: Test setting pointer style
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = 1;
    int32_t windowId = GLOBAL_WINDOW_ID;
    PointerStyle pointerStyle;
    pointerStyle.id = 1;
    int32_t ret = WIN_MGR->SetPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(WIN_MGR->globalStyle_.id, pointerStyle.id);
    pid = 1;
    windowId = 2;
    ret = WIN_MGR->SetPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, WIN_MGR->UpdatePoinerStyle(pid, windowId, pointerStyle));
    pid = 1;
    windowId = 2;
    ret = WIN_MGR->SetPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, WIN_MGR->UpdateSceneBoardPointerStyle(pid, windowId, pointerStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_ClearWindowPointerStyle_001
 * @tc.desc: Test clearing window pointer style
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_ClearWindowPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = 123;
    int32_t windowId = 678;
    int32_t ret = WIN_MGR->ClearWindowPointerStyle(pid, windowId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_GetPointerStyle_001
 * @tc.desc: Test getting pointer style
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerStyle style;
    int32_t ret = WIN_MGR->GetPointerStyle(1, GLOBAL_WINDOW_ID, style);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(style.id, 1);
    ret = WIN_MGR->GetPointerStyle(3, 1, style);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(style.id, 1);
    ret = WIN_MGR->GetPointerStyle(1, 1, style);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(style.id, 1);
}

/**
 * @tc.name: InputWindowsManagerTest_IsInHotArea_001
 * @tc.desc: Test whether input is in the hot area
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsInHotArea_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WIN_MGR->InitPointerStyle();
    int32_t x = 10;
    int32_t y = 20;
    std::vector<Rect> rects = {{0, 0, 30, 40}};
    WindowInfo window;
    bool ret = WIN_MGR->IsInHotArea(x, y, rects, window);
    EXPECT_TRUE(ret);
    x = -10;
    y = 20;
    ret = WIN_MGR->IsInHotArea(x, y, rects, window);
    EXPECT_FALSE(ret);
    x = 10;
    y = -10;
    ret = WIN_MGR->IsInHotArea(x, y, rects, window);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_InWhichHotArea_001
 * @tc.desc: Test which hot area the input is in
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_InWhichHotArea_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t x = 50;
    int32_t y = 50;
    std::vector<Rect> rects = {{0, 0, 100, 100}, {100, 100, 200, 200}};
    PointerStyle pointerStyle;
    WIN_MGR->InWhichHotArea(x, y, rects, pointerStyle);
    ASSERT_EQ(pointerStyle.id, 6);
    x = 250;
    y = 250;
    WIN_MGR->InWhichHotArea(x, y, rects, pointerStyle);
    ASSERT_EQ(pointerStyle.id, 6);
}

/**
 * @tc.name: InputWindowsManagerTest_AdjustDisplayCoordinate_001
 * @tc.desc: Test adjusting display coordinates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_AdjustDisplayCoordinate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo displayInfo;
    displayInfo.width = 10;
    displayInfo.height = 20;
    displayInfo.direction = DIRECTION90;
    double physicalX = -5;
    double physicalY = 15;
    WIN_MGR->AdjustDisplayCoordinate(displayInfo, physicalX, physicalY);
    EXPECT_EQ(physicalX, 0);
    EXPECT_EQ(physicalY, 9);
    displayInfo.width = 10;
    displayInfo.height = 20;
    displayInfo.direction = DIRECTION270;
    physicalX = 15;
    physicalY = 25;
    WIN_MGR->AdjustDisplayCoordinate(displayInfo, physicalX, physicalY);
    EXPECT_EQ(physicalX, 15);
    EXPECT_EQ(physicalY, 9);
    displayInfo.width = 10;
    displayInfo.height = 20;
    displayInfo.direction = DIRECTION270;
    physicalX = -5;
    physicalY = -15;
    WIN_MGR->AdjustDisplayCoordinate(displayInfo, physicalX, physicalY);
    EXPECT_EQ(physicalX, 0);
    EXPECT_EQ(physicalY, 0);
}

/**
 * @tc.name: InputWindowsManagerTest_IsTransparentWin
 * @tc.desc: Test IsTransparentWin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsTransparentWin, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    void* pixelMap = nullptr;
    int32_t logicalX = 0;
    int32_t logicalY = 0;
    bool result = WIN_MGR->IsTransparentWin(pixelMap, logicalX, logicalY);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputWindowsManagerTest_CheckWindowIdPermissionByPid
 * @tc.desc: Test CheckWindowIdPermissionByPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CheckWindowIdPermissionByPid, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 12345;
    int32_t pid = 6789;
    int32_t result = WIN_MGR->CheckWindowIdPermissionByPid(windowId, pid);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_IsWindowVisible
 * @tc.desc: Test IsWindowVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsWindowVisible, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = -1;
    bool result = WIN_MGR->IsWindowVisible(pid);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: InputWindowsManagerTest_CoordinateCorrection_001
 * @tc.desc: Test CoordinateCorrection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CoordinateCorrection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t width = 100;
    int32_t height = 200;
    int32_t integerX = -1;
    int32_t integerY = 1;
    WIN_MGR->CoordinateCorrection(width, height, integerX, integerY);
    EXPECT_EQ(integerX, 0);
}

/**
 * @tc.name: InputWindowsManagerTest_CoordinateCorrection_002
 * @tc.desc: Test CoordinateCorrection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CoordinateCorrection_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t width = 100;
    int32_t height = 200;
    int32_t integerX = 150;
    int32_t integerY = 100;
    WIN_MGR->CoordinateCorrection(width, height, integerX, integerY);
    EXPECT_EQ(integerX, 99);
}

/**
 * @tc.name: InputWindowsManagerTest_CoordinateCorrection_003
 * @tc.desc: Test CoordinateCorrection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CoordinateCorrection_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t width = 100;
    int32_t height = 200;
    int32_t integerX = 1;
    int32_t integerY = -1;
    WIN_MGR->CoordinateCorrection(width, height, integerX, integerY);
    EXPECT_EQ(integerY, 0);
}

/**
 * @tc.name: InputWindowsManagerTest_CoordinateCorrection_004
 * @tc.desc: Test CoordinateCorrection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CoordinateCorrection_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t width = 100;
    int32_t height = 200;
    int32_t integerX = 100;
    int32_t integerY = 250;
    WIN_MGR->CoordinateCorrection(width, height, integerX, integerY);
    EXPECT_EQ(integerY, 199);
}

/**
 * @tc.name: InputWindowsManagerTest_HandleWindowInputType_001
 * @tc.desc: Test HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_HandleWindowInputType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::NORMAL;
    ASSERT_FALSE(WIN_MGR->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_HandleWindowInputType_002
 * @tc.desc: Test HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_HandleWindowInputType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::TRANSMIT_ALL;
    ASSERT_FALSE(WIN_MGR->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_HandleWindowInputType_003
 * @tc.desc: Test HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_HandleWindowInputType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::ANTI_MISTAKE_TOUCH;
    ASSERT_FALSE(WIN_MGR->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDisplayId_001
 * @tc.desc: Test updating display ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateDisplayId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = 1;
    bool ret = WIN_MGR->UpdateDisplayId(displayId);
    EXPECT_TRUE(ret);
    displayId = 0;
    ret = WIN_MGR->UpdateDisplayId(displayId);
    EXPECT_FALSE(ret);
    displayId = -1;
    ret = WIN_MGR->UpdateDisplayId(displayId);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_SelectWindowInfo_001
 * @tc.desc: Test selecting window information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SelectWindowInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetPressedKeys({1});
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetTargetWindowId(1);
    std::optional<WindowInfo> result = WIN_MGR->SelectWindowInfo(400, 300, pointerEvent);
    EXPECT_FALSE(result.has_value());
    int32_t ret1 = result->id;
    EXPECT_EQ(ret1, 0);
    int32_t ret2 = result->flags;
    EXPECT_EQ(ret2, 0);
    int32_t ret3 = result->pid;
    EXPECT_EQ(ret3, 0);
}

/**
 * @tc.name: InputWindowsManagerTest_SelectWindowInfo_002
 * @tc.desc: Test selecting window information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SelectWindowInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    pointerEvent->SetPressedKeys({1});
    pointerEvent->SetTargetDisplayId(0);
    pointerEvent->SetTargetWindowId(1);
    std::optional<WindowInfo> result = WIN_MGR->SelectWindowInfo(-123, -456, pointerEvent);
    EXPECT_FALSE(result.has_value());
    int32_t ret1 = result->id;
    EXPECT_EQ(ret1, 0);
    int32_t ret2 = result->flags;
    EXPECT_EQ(ret2, 0);
    int32_t ret3 = result->pid;
    EXPECT_EQ(ret3, 0);
}

/**
 * @tc.name: InputWindowsManagerTest_GetWindowInfo_001
 * @tc.desc: Test getting window information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetWindowInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo1 = {1, WindowInfo::FLAG_BIT_UNTOUCHABLE, {}};
    WindowInfo windowInfo2 = {2, 0, {}};
    WIN_MGR->displayGroupInfo_.windowsInfo = {windowInfo1, windowInfo2};
    auto result = WIN_MGR->GetWindowInfo(0, 0);
    EXPECT_FALSE(result.has_value());
    int32_t ret1 = result->id;
    EXPECT_EQ(ret1, 0);
}

/**
 * @tc.name: InputWindowsManagerTest_SelectPointerChangeArea_001
 * @tc.desc: Test selecting pointer change area
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SelectPointerChangeArea_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    PointerStyle pointerStyle;
    int32_t logicalX = 0;
    int32_t logicalY = 0;
    bool result = WIN_MGR->SelectPointerChangeArea(windowInfo, pointerStyle, logicalX, logicalY);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputWindowsManagerTest_SelectPointerChangeArea_002
 * @tc.desc: Test selecting pointer change area
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SelectPointerChangeArea_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    PointerStyle pointerStyle;
    int32_t logicalX = -1;
    int32_t logicalY = -2;
    bool result = WIN_MGR->SelectPointerChangeArea(windowInfo, pointerStyle, logicalX, logicalY);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerChangeAreas_001
 * @tc.desc: Test updating pointer change areas
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdatePointerChangeAreas_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    WIN_MGR->UpdatePointerChangeAreas(displayGroupInfo);
    EXPECT_TRUE(WIN_MGR->windowsHotAreas_.empty());
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerChangeAreas_002
 * @tc.desc: Test updating pointer change areas
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdatePointerChangeAreas_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    WIN_MGR->UpdatePointerChangeAreas();
    WIN_MGR->UpdatePointerChangeAreas(displayGroupInfo);
    EXPECT_EQ(WIN_MGR->windowsHotAreas_.size(), 1);
    EXPECT_EQ(WIN_MGR->windowsHotAreas_[1].size(), 8);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTopBottomArea_001
 * @tc.desc: Test updating top-bottom area
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTopBottomArea_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Rect windowArea = {0, 0, 100, 100};
    std::vector<int32_t> pointerChangeAreas = {10, 20, 30, 40, 50, 60, 70, 80};
    std::vector<Rect> windowHotAreas;
    WIN_MGR->UpdateTopBottomArea(windowArea, pointerChangeAreas, windowHotAreas);
    int32_t ret1 = windowHotAreas.size();
    EXPECT_EQ(ret1, 2);
    int32_t ret2 = windowHotAreas[0].x;
    EXPECT_EQ(ret2, 10);
    int32_t ret3 = windowHotAreas[0].y;
    EXPECT_EQ(ret3, -20);
    int32_t ret4 = windowHotAreas[0].width;
    EXPECT_EQ(ret4, 60);
    int32_t ret5 = windowHotAreas[0].height;
    EXPECT_EQ(ret5, 40);
    int32_t ret6 = windowHotAreas[1].x;
    EXPECT_EQ(ret6, 70);
    int32_t ret7 = windowHotAreas[1].y;
    EXPECT_EQ(ret7, 40);
    int32_t ret8 = windowHotAreas[1].width;
    EXPECT_EQ(ret8, -20);
    int32_t ret9 = windowHotAreas[1].height;
    EXPECT_EQ(ret9, 80);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTopBottomArea_002
 * @tc.desc: Test updating top-bottom area
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTopBottomArea_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Rect windowArea = {0, 0, 100, 100};
    std::vector<int32_t> pointerChangeAreas = {0, 0, 0, 0, 0, 0, 0, 0};
    std::vector<Rect> windowHotAreas;
    WIN_MGR->UpdateTopBottomArea(windowArea, pointerChangeAreas, windowHotAreas);
    int32_t ret1 = windowHotAreas.size();
    EXPECT_EQ(ret1, 2);
    int32_t ret2 = windowHotAreas[0].width;
    EXPECT_EQ(ret2, 0);
    int32_t ret3 = windowHotAreas[0].height;
    EXPECT_EQ(ret3, 0);
    int32_t ret4 = windowHotAreas[1].width;
    EXPECT_EQ(ret4, 0);
    int32_t ret5 = windowHotAreas[1].height;
    EXPECT_EQ(ret5, 0);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateLeftRightArea_001
 * @tc.desc: Test updating left-right area
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateLeftRightArea_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Rect windowArea = {0, 0, 100, 100};
    std::vector<int32_t> pointerChangeAreas = {10, 20, 30, 40, 50, 60, 70, 80};
    std::vector<Rect> windowHotAreas;
    WIN_MGR->UpdateLeftRightArea(windowArea, pointerChangeAreas, windowHotAreas);
    int32_t ret1 = windowHotAreas.size();
    EXPECT_EQ(ret1, 2);
    int32_t ret2 = windowHotAreas[0].x;
    EXPECT_EQ(ret2, -20);
    int32_t ret3 = windowHotAreas[0].y;
    EXPECT_EQ(ret3, 10);
    int32_t ret4 = windowHotAreas[0].width;
    EXPECT_EQ(ret4, 100);
    int32_t ret5 = windowHotAreas[0].height;
    EXPECT_EQ(ret5, 20);
    int32_t ret6 = windowHotAreas[1].x;
    EXPECT_EQ(ret6, 60);
    int32_t ret7 = windowHotAreas[1].y;
    EXPECT_EQ(ret7, 30);
    int32_t ret8 = windowHotAreas[1].width;
    EXPECT_EQ(ret8, 60);
    int32_t ret9 = windowHotAreas[1].height;
    EXPECT_EQ(ret9, 20);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateLeftRightArea_002
 * @tc.desc: Test updating left-right area
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateLeftRightArea_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Rect windowArea = {0, 0, 100, 100};
    std::vector<int32_t> pointerChangeAreas = {10, 0, 30, 40, 50, 60, 70, 80};
    std::vector<Rect> windowHotAreas;
    WIN_MGR->UpdateLeftRightArea(windowArea, pointerChangeAreas, windowHotAreas);
    int32_t ret1 = windowHotAreas.size();
    EXPECT_EQ(ret1, 2);
    int32_t ret2 = windowHotAreas[0].x;
    EXPECT_EQ(ret2, -20);
    int32_t ret3 = windowHotAreas[0].y;
    EXPECT_EQ(ret3, 10);
    int32_t ret4 = windowHotAreas[0].width;
    EXPECT_EQ(ret4, 100);
    int32_t ret5 = windowHotAreas[0].height;
    EXPECT_EQ(ret5, 20);
    int32_t ret6 = windowHotAreas[1].x;
    EXPECT_EQ(ret6, 60);
    int32_t ret7 = windowHotAreas[1].y;
    EXPECT_EQ(ret7, 30);
    int32_t ret8 = windowHotAreas[1].width;
    EXPECT_EQ(ret8, 60);
    int32_t ret9 = windowHotAreas[1].height;
    EXPECT_EQ(ret9, 20);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateInnerAngleArea_001
 * @tc.desc: Test updating inner angle area
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateInnerAngleArea_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    Rect windowArea;
    windowArea.x = 10;
    windowArea.y = 20;
    windowArea.width = 100;
    windowArea.height = 200;
    std::vector<int32_t> pointerChangeAreas(4, 10);
    std::vector<Rect> windowHotAreas;
    WIN_MGR->UpdateInnerAngleArea(windowArea, pointerChangeAreas, windowHotAreas);
    int32_t ret1 = windowHotAreas.size();
    EXPECT_EQ(ret1, 4);
    int32_t ret2 = windowHotAreas[0].x;
    EXPECT_EQ(ret2, -10);
    int32_t ret3 = windowHotAreas[0].y;
    EXPECT_EQ(ret3, 0);
    int32_t ret4 = windowHotAreas[0].width;
    EXPECT_EQ(ret4, 30);
    int32_t ret5 = windowHotAreas[0].height;
    EXPECT_EQ(ret5, 30);
    int32_t ret6 = windowHotAreas[1].x;
    EXPECT_EQ(ret6, 100);
    int32_t ret7 = windowHotAreas[1].y;
    EXPECT_EQ(ret7, 0);
    int32_t ret8 = windowHotAreas[1].width;
    EXPECT_EQ(ret8, 30);
    int32_t ret9 = windowHotAreas[1].height;
    EXPECT_EQ(ret9, 30);
    int32_t ret10 = windowHotAreas[2].x;
    EXPECT_EQ(ret10, -10);
    int32_t ret11 = windowHotAreas[2].y;
    EXPECT_NE(ret11, 110);
    int32_t ret12 = windowHotAreas[2].width;
    EXPECT_NE(ret12, 21);
    int32_t ret13 = windowHotAreas[2].height;
    EXPECT_EQ(ret13, 32);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerEvent_001
 * @tc.desc: Test updating pointer event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdatePointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t logicalX = 10;
    int32_t logicalY = 20;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo touchWindow;
    touchWindow.id = 2;
    WIN_MGR->UpdatePointerEvent(logicalX, logicalY, pointerEvent, touchWindow);
    EXPECT_EQ(inputWindowsManager.lastLogicX_, RET_ERR);
    EXPECT_EQ(inputWindowsManager.lastLogicY_, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerEvent_002
 * @tc.desc: Test updating pointer event
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdatePointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t logicalX = 10;
    int32_t logicalY = 20;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo touchWindow;
    touchWindow.id = 0;
    WIN_MGR->UpdatePointerEvent(logicalX, logicalY, pointerEvent, touchWindow);
    EXPECT_EQ(inputWindowsManager.lastLogicX_, RET_ERR);
    EXPECT_EQ(inputWindowsManager.lastLogicY_, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SetHoverScrollState_001
 * @tc.desc: Test setting hover scroll state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetHoverScrollState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t result = WIN_MGR->SetHoverScrollState(true);
    EXPECT_EQ(result, 0);
    result = WIN_MGR->SetHoverScrollState(false);
    EXPECT_EQ(result, 0);
}

/**
 * @tc.name: InputWindowsManagerTest_GetHoverScrollState_001
 * @tc.desc: Test getting hover scroll state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetHoverScrollState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool result = WIN_MGR->GetHoverScrollState();
    EXPECT_TRUE(result);
    result = WIN_MGR->GetHoverScrollState();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateMouseTarget_001
 * @tc.desc: Test updating mouse target
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateMouseTarget_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t result =WIN_MGR->UpdateMouseTarget(pointerEvent);
    WIN_MGR->SetMouseFlag(true);
    WIN_MGR->SetMouseFlag(false);
    auto ret = WIN_MGR->GetMouseFlag();
    EXPECT_FALSE(ret);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_SkipNavigationWindow_001
 * @tc.desc: Test updating window information for each display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SkipNavigationWindow_001, TestSize.Level1)
{
    WIN_MGR->SetAntiMisTakeStatus(false);
    ASSERT_FALSE(WIN_MGR->SkipNavigationWindow(WindowInputType::ANTI_MISTAKE_TOUCH, PointerEvent::TOOL_TYPE_PEN));
}

/**
 * @tc.name: InputWindowsManagerTest_SkipNavigationWindow_002
 * @tc.desc: Test updating window information for each display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SkipNavigationWindow_002, TestSize.Level1)
{
    WIN_MGR->SetAntiMisTakeStatus(false);
    ASSERT_FALSE(WIN_MGR->SkipNavigationWindow(WindowInputType::NORMAL, PointerEvent::TOOL_TYPE_RUBBER));
}

/**
 * @tc.name: InputWindowsManagerTest_SkipNavigationWindow_003
 * @tc.desc: Test updating window information for each display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SkipNavigationWindow_003, TestSize.Level1)
{
    WIN_MGR->SetAntiMisTakeStatus(false);
    ASSERT_FALSE(WIN_MGR->SkipNavigationWindow(WindowInputType::NORMAL, PointerEvent::TOOL_TYPE_PEN));
}

/**
 * @tc.name: InputWindowsManagerTest_SkipNavigationWindow_004
 * @tc.desc: Test updating window information for each display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SkipNavigationWindow_004, TestSize.Level1)
{
    WIN_MGR->SetAntiMisTakeStatus(false);
    ASSERT_FALSE(WIN_MGR->SkipNavigationWindow(WindowInputType::ANTI_MISTAKE_TOUCH, PointerEvent::TOOL_TYPE_RUBBER));
}

/**
 * @tc.name: InputWindowsManagerTest_SkipNavigationWindow_005
 * @tc.desc: Test updating window information for each display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SkipNavigationWindow_005, TestSize.Level1)
{
    WIN_MGR->SetAntiMisTake(true);
    WIN_MGR->SetAntiMisTakeStatus(false);
    ASSERT_FALSE(WIN_MGR->SkipNavigationWindow(WindowInputType::ANTI_MISTAKE_TOUCH, PointerEvent::TOOL_TYPE_PEN));
}

/**
 * @tc.name: InputWindowsManagerTest_JudgMouseIsDownOrUp_001
 * @tc.desc: This test verifies the functionality of judging whether the mouse button is down or up
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_JudgMouseIsDownOrUp_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WIN_MGR->JudgMouseIsDownOrUp(false);
    EXPECT_FALSE(WIN_MGR->GetMouseFlag());
    WIN_MGR->JudgMouseIsDownOrUp(true);
    EXPECT_FALSE(WIN_MGR->GetMouseFlag());
}

/**
 * @tc.name: InputWindowsManagerTest_SetMouseCaptureMode_001
 * @tc.desc: This test verifies the functionality of setting the mouse capture mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetMouseCaptureMode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = -1;
    bool isCaptureMode = true;
    int32_t result = WIN_MGR->SetMouseCaptureMode(windowId, isCaptureMode);
    EXPECT_EQ(result, RET_ERR);
    windowId = 1;
    isCaptureMode = false;
    result = WIN_MGR->SetMouseCaptureMode(windowId, isCaptureMode);
    EXPECT_EQ(result, RET_OK);
    windowId = 1;
    isCaptureMode = true;
    result = WIN_MGR->SetMouseCaptureMode(windowId, isCaptureMode);
    EXPECT_EQ(result, RET_OK);
    EXPECT_TRUE(WIN_MGR->GetMouseIsCaptureMode());
}

/**
 * @tc.name: InputWindowsManagerTest_IsNeedDrawPointer_001
 * @tc.desc: This test verifies the functionality of determining whether to draw the pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsNeedDrawPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerEvent::PointerItem pointerItem;
    pointerItem.SetToolType(PointerEvent::TOOL_TYPE_PEN);
    pointerItem.SetDeviceId(1);
    bool result = WIN_MGR->IsNeedDrawPointer(pointerItem);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputWindowsManagerTest_SkipAnnotationWindow_001
 * @tc.desc: This test verifies the functionality of determining whether to draw the pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SkipAnnotationWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint32_t flag = WindowInfo::FLAG_BIT_HANDWRITING;
    int32_t toolType = PointerEvent::TOOL_TYPE_FINGER;
    bool result = WIN_MGR->SkipAnnotationWindow(flag, toolType);
    EXPECT_TRUE(result);
    flag = WindowInfo::FLAG_BIT_HANDWRITING;
    toolType = PointerEvent::TOOL_TYPE_PEN;
    result = WIN_MGR->SkipAnnotationWindow(flag, toolType);
    EXPECT_FALSE(result);
    flag = 0;
    toolType = PointerEvent::TOOL_TYPE_FINGER;
    result = WIN_MGR->SkipAnnotationWindow(flag, toolType);
    EXPECT_FALSE(result);
    flag = 0;
    toolType = PointerEvent::TOOL_TYPE_PEN;
    result = WIN_MGR->SkipAnnotationWindow(flag, toolType);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTouchScreenTarget_001
 * @tc.desc: This test verifies the functionality of updating the touch screen target
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTouchScreenTarget_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto result = WIN_MGR->UpdateTouchScreenTarget(nullptr);
    EXPECT_NE(result, RET_ERR);
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetTargetDisplayId(-1);
    result = WIN_MGR->UpdateTouchScreenTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetTargetDisplayId(1);
    pointerEvent->SetPointerId(1);
    result = WIN_MGR->UpdateTouchScreenTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_PullEnterLeaveEvent_001
 * @tc.desc: This test verifies the functionality of pulling enter and leave events
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_PullEnterLeaveEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t logicalX = 100;
    int32_t logicalY = 200;
    auto pointerEvent = PointerEvent::Create();
    WindowInfo touchWindow;
    WIN_MGR->PullEnterLeaveEvent(logicalX, logicalY, pointerEvent, &touchWindow);
    logicalX = -123;
    logicalY = -456;
    WIN_MGR->PullEnterLeaveEvent(logicalX, logicalY, pointerEvent, &touchWindow);
}

/**
 * @tc.name: InputWindowsManagerTest_DispatchTouch_001
 * @tc.desc: This test verifies the functionality of touch event dispatching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_DispatchTouch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_PULL_IN_WINDOW;
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->DispatchTouch(pointerAction));
    pointerAction = PointerEvent::POINTER_ACTION_DOWN;
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->DispatchTouch(pointerAction));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTouchPadTarget_001
 * @tc.desc: This test verifies the functionality of updating the touchpad target
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTouchPadTarget_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    int32_t result = WIN_MGR->UpdateTouchPadTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    result = WIN_MGR->UpdateTouchPadTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    result = WIN_MGR->UpdateTouchPadTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    result = WIN_MGR->UpdateTouchPadTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    result = WIN_MGR->UpdateTouchPadTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetPointerAction(9999);
    result = WIN_MGR->UpdateTouchPadTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTargetPointer_001
 * @tc.desc: This test verifies the functionality of updating the target pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTargetPointer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    pointerEvent->SetPointerAction(1);
    int32_t result = WIN_MGR->UpdateTargetPointer(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(1);
    result = WIN_MGR->UpdateTargetPointer(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(1);
    result = WIN_MGR->UpdateTargetPointer(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->SetPointerAction(1);
    result = WIN_MGR->UpdateTargetPointer(pointerEvent);
    EXPECT_EQ(result, RET_OK);
    pointerEvent->SetSourceType(999);
    pointerEvent->SetPointerAction(1);
    result = WIN_MGR->UpdateTargetPointer(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_IsInsideDisplay_001
 * @tc.desc: This test verifies the functionality of determining whether it is inside the display area
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsInsideDisplay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo displayInfo;
    displayInfo.width = 1920;
    displayInfo.height = 1080;
    int32_t physicalX = 500;
    int32_t physicalY = 10;
    bool result = WIN_MGR->IsInsideDisplay(displayInfo, physicalX, physicalY);
    EXPECT_TRUE(result);
    physicalX = -10;
    physicalY = 500;
    result = WIN_MGR->IsInsideDisplay(displayInfo, physicalX, physicalY);
    EXPECT_FALSE(result);
    physicalX = 500;
    physicalY = -10;
    result = WIN_MGR->IsInsideDisplay(displayInfo, physicalX, physicalY);
    EXPECT_FALSE(result);
    physicalX = -500;
    physicalY = -10;
    result = WIN_MGR->IsInsideDisplay(displayInfo, physicalX, physicalY);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputWindowsManagerTest_FindPhysicalDisplay_001
 * @tc.desc: This test verifies the functionality of finding physical displays
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_FindPhysicalDisplay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo displayInfo = {10, 20};
    int32_t physicalX, physicalY, displayId;
    WIN_MGR->FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId);
    EXPECT_EQ(physicalX, RET_OK);
    EXPECT_EQ(physicalY, RET_OK);
    EXPECT_EQ(displayId, RET_OK);
    displayInfo.x = INT32_MAX;
    displayInfo.y = INT32_MAX;
    WIN_MGR->FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId);
    EXPECT_EQ(physicalX, RET_OK);
    EXPECT_EQ(physicalY, RET_OK);
    EXPECT_EQ(displayId, RET_OK);
    displayInfo.x = 50;
    displayInfo.y = 60;
    WIN_MGR->FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId);
    EXPECT_EQ(physicalX, RET_OK);
    EXPECT_EQ(physicalY, RET_OK);
    EXPECT_EQ(displayId, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_GetWidthAndHeight_001
 * @tc.desc: Test the method for retrieving width and height
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetWidthAndHeight_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo displayInfo;
    displayInfo.displayDirection = DIRECTION0;
    displayInfo.direction = DIRECTION0;
    int32_t width = 1920;
    int32_t height = 1080;
    WIN_MGR->GetWidthAndHeight(&displayInfo, width, height);
    EXPECT_EQ(width, RET_OK);
    EXPECT_EQ(height, RET_OK);
    displayInfo.direction = DIRECTION90;
    WIN_MGR->GetWidthAndHeight(&displayInfo, width, height);
    EXPECT_EQ(width, RET_OK);
    EXPECT_EQ(height, RET_OK);
    displayInfo.displayDirection = DIRECTION180;
    displayInfo.direction = DIRECTION0;
    WIN_MGR->GetWidthAndHeight(&displayInfo, width, height);
    EXPECT_EQ(width, RET_OK);
    EXPECT_EQ(height, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_ReverseRotateScreen_001
 * @tc.desc: Test the method for reversing screen rotation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_ReverseRotateScreen_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo info;
    Coordinate2D cursorPos;
    info.direction = DIRECTION0;
    info.width = 1920;
    info.height = 1080;
    WIN_MGR->ReverseRotateScreen(info, 100.0, 200.0, cursorPos);
    EXPECT_EQ(cursorPos.x, 100);
    EXPECT_EQ(cursorPos.y, 200);
    info.direction = DIRECTION90;
    WIN_MGR->ReverseRotateScreen(info, 100.0, 200.0, cursorPos);;
    EXPECT_EQ(cursorPos.x, 200);
    EXPECT_EQ(cursorPos.y, 1820);
    info.direction = DIRECTION180;
    WIN_MGR->ReverseRotateScreen(info, 100.0, 200.0, cursorPos);
    EXPECT_EQ(cursorPos.x, 1820);
    EXPECT_EQ(cursorPos.y, 880);
    info.direction = DIRECTION270;
    WIN_MGR->ReverseRotateScreen(info, 100.0, 200.0, cursorPos);
    EXPECT_EQ(cursorPos.x, 880);
    EXPECT_EQ(cursorPos.y, 100);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateAndAdjustMouseLocation_001
 * @tc.desc: Test the method for updating and adjusting mouse location
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateAndAdjustMouseLocation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = 2;
    double x = 100.5;
    double y = 200.5;
    bool isRealData = true;
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    WIN_MGR->UpdateAndAdjustMouseLocation(displayId, x, y, isRealData);
    auto ret = WIN_MGR->GetDisplayId(inputEvent);
    EXPECT_NE(displayId, ret);
    displayId = -1;
    x = 100.5;
    y = 200.5;
    isRealData = true;
    WIN_MGR->UpdateAndAdjustMouseLocation(displayId, x, y, isRealData);
    ret = WIN_MGR->GetDisplayId(inputEvent);
    EXPECT_NE(displayId, ret);
    displayId = 0;
    x = -100.5;
    y = -200.5;
    isRealData = true;
    WIN_MGR->UpdateAndAdjustMouseLocation(displayId, x, y, isRealData);
    ret = WIN_MGR->GetDisplayId(inputEvent);
    EXPECT_NE(displayId, ret);
    displayId = 0;
    x = 100.5;
    y = 200.5;
    isRealData = false;
    WIN_MGR->UpdateAndAdjustMouseLocation(displayId, x, y, isRealData);
    ret = WIN_MGR->GetDisplayId(inputEvent);
    EXPECT_NE(displayId, ret);
}

/**
 * @tc.name: InputWindowsManagerTest_GetMouseInfo_001
 * @tc.desc: Test the GetMouseInfo method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetMouseInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    MouseLocation mouseLocation;
    displayGroupInfo.displaysInfo.clear();
    MouseLocation result = WIN_MGR->GetMouseInfo();
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.width = 1920;
    displayInfo.height = 1080;
    displayGroupInfo.displaysInfo.push_back(displayInfo);
    mouseLocation.displayId = 0;
    result = WIN_MGR->GetMouseInfo();
    displayGroupInfo.displaysInfo.push_back(displayInfo);
    mouseLocation.displayId = -1;
    MouseLocation expectedResult;
    expectedResult.displayId = 1;
    expectedResult.physicalX = 960;
    expectedResult.physicalY = 540;
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->GetMouseInfo());
}

/**
 * @tc.name: InputWindowsManagerTest_GetCursorPos_001
 * @tc.desc: Test the functionality of getting the cursor position
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetCursorPos_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager manager;
    manager.cursorPos_.displayId = -1;
    manager.displayGroupInfo_.displaysInfo.push_back({0, 800, 600});
    CursorPosition result = WIN_MGR->GetCursorPos();
    EXPECT_EQ(result.displayId, 1);
    EXPECT_EQ(result.cursorPos.x, 1);
    EXPECT_EQ(result.cursorPos.y, 1);
    manager.cursorPos_.displayId = 1;
    manager.displayGroupInfo_.displaysInfo.push_back({1, 800, 600});
    result = WIN_MGR->GetCursorPos();
    EXPECT_EQ(result.displayId, 1);
    EXPECT_EQ(result.cursorPos.x, 1);
    EXPECT_EQ(result.cursorPos.y, 1);
}

/**
 * @tc.name: InputWindowsManagerTest_ResetCursorPos_001
 * @tc.desc: Test the functionality of resetting cursor position
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_ResetCursorPos_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager manager;
    manager.displayGroupInfo_.displaysInfo.push_back({1, 800, 600});
    CursorPosition result = WIN_MGR->ResetCursorPos();
    EXPECT_EQ(result.displayId, 1);
    EXPECT_EQ(result.cursorPos.x, 1);
    EXPECT_EQ(result.cursorPos.y, 1);
    manager.displayGroupInfo_.displaysInfo.clear();
    result = WIN_MGR->ResetCursorPos();
    EXPECT_EQ(result.displayId, 1);
    EXPECT_EQ(result.cursorPos.x, 1);
    EXPECT_EQ(result.cursorPos.y, 1);
}

/**
 * @tc.name: InputWindowsManagerTest_AppendExtraData_001
 * @tc.desc: Test the functionality of appending extra data in the input window manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_AppendExtraData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager manager;
    ExtraData extraData;
    extraData.appended = true;
    extraData.buffer = std::vector<uint8_t>{1, 2, 3};
    extraData.pointerId = 12345;
    int32_t result = WIN_MGR->AppendExtraData(extraData);
    ASSERT_EQ(result, RET_OK);
    ASSERT_NE(manager.GetExtraData().appended, extraData.appended);
    ASSERT_NE(manager.GetExtraData().buffer, extraData.buffer);
    ASSERT_NE(manager.GetExtraData().pointerId, extraData.pointerId);
}

/**
 * @tc.name: InputWindowsManagerTest_ClearExtraData_001
 * @tc.desc: Test the functionality of clearing extra data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_ClearExtraData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager manager;
    manager.extraData_.appended = true;
    manager.extraData_.buffer.push_back(1);
    manager.extraData_.sourceType = 0;
    manager.extraData_.pointerId = 1;
    WIN_MGR->ClearExtraData();
    EXPECT_TRUE(manager.extraData_.appended);
    EXPECT_FALSE(manager.extraData_.buffer.empty());
    EXPECT_NE(-1, manager.extraData_.sourceType);
    EXPECT_NE(-1, manager.extraData_.pointerId);
}

/**
 * @tc.name: InputWindowsManagerTest_GetExtraData_001
 * @tc.desc: Test the functionality of getting extra data in the input window manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetExtraData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->GetExtraData());
}

/**
 * @tc.name: InputWindowsManagerTest_IsWindowVisible_001
 * @tc.desc: Test the window visibility functionality of the input window manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsWindowVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t invalidPid = -1;
    bool result = WIN_MGR->IsWindowVisible(invalidPid);
    EXPECT_TRUE(result);
    int32_t visiblePid = 0;
    result = WIN_MGR->IsWindowVisible(visiblePid);
    EXPECT_FALSE(result);
    int32_t invisiblePid = 1;
    result = WIN_MGR->IsWindowVisible(invisiblePid);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerAction_001
 * @tc.desc: Test the update function of pointer action in Input Windows Manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdatePointerAction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    WIN_MGR->UpdatePointerAction(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_PULL_MOVE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    WIN_MGR->UpdatePointerAction(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_PULL_UP);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    WIN_MGR->UpdatePointerAction(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_PULL_UP);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ENTER_WINDOW);
    WIN_MGR->UpdatePointerAction(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_PULL_IN_WINDOW);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
    WIN_MGR->UpdatePointerAction(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW);
    pointerEvent->SetPointerAction(100);
    WIN_MGR->UpdatePointerAction(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerAction(), 100);
}

/**
 * @tc.name: InputWindowsManagerTest_Dump_001
 * @tc.desc: Test the dump function of the input window manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_Dump_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t fd = 1;
    std::vector<std::string> args;
    ASSERT_NO_FATAL_FAILURE(WIN_MGR->Dump(fd, args));
}

/**
 * @tc.name: InputWindowsManagerTest_TransformWindowXY_001
 * @tc.desc: Test the TransformWindowXY function of the input window manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_TransformWindowXY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo window;
    double logicX = 10.0;
    double logicY = 20.0;
    std::pair<double, double> result =WIN_MGR->TransformWindowXY(window, logicX, logicY);
    double ret = result.first;
    EXPECT_EQ(ret, logicX);
    double ret1 = result.second;
    EXPECT_EQ(ret1, logicY);
}

/**
 * @tc.name: InputWindowsManagerTest_IsValidZorderWindow_001
 * @tc.desc: Test the validity of the input window manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsValidZorderWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo window;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE);
    bool result = WIN_MGR->IsValidZorderWindow(window, pointerEvent);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: InputWindowsManagerTest_HandleWindowInputType_004
 * @tc.desc: Test the functionality of handling window input types in the Input Windows Manage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_HandleWindowInputType_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::TRANSMIT_EXCEPT_MOVE;
    ASSERT_FALSE(WIN_MGR->HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_GetWindowAndDisplayInfo_001
 * @tc.desc: Test the function of getting window and display information
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetWindowAndDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 1;
    int32_t displayId = 1;
    auto result = WIN_MGR->GetWindowAndDisplayInfo(windowId, displayId);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->id, windowId);
    windowId = -1;
    displayId = 1;
    result = WIN_MGR->GetWindowAndDisplayInfo(windowId, displayId);
    ASSERT_FALSE(result.has_value());
    windowId = 1;
    displayId = -1;
    result = WIN_MGR->GetWindowAndDisplayInfo(windowId, displayId);
    ASSERT_TRUE(result.has_value());
}

/**
 * @tc.name: InputWindowsManagerTest_GetTargetWindowIds_001
 * @tc.desc: Test the functionality of getting target window IDs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetTargetWindowIds_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> windowIds;
    int32_t pointerItemId = 1;
    int32_t windowId = 100;
    int32_t sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    WIN_MGR->AddTargetWindowIds(pointerItemId, sourceType, windowId);
    WIN_MGR->GetTargetWindowIds(pointerItemId, sourceType, windowIds);
    ASSERT_TRUE(!windowIds.empty());
    WIN_MGR->ClearTargetWindowId(pointerItemId);
}

/**
 * @tc.name: InputWindowsManagerTest_AddTargetWindowIds_001
 * @tc.desc: Test the functionality of adding target window IDs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_AddTargetWindowIds_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager manager;
    int32_t pointerItemId = 1;
    int32_t windowId = 100;
    int32_t sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    WIN_MGR->AddTargetWindowIds(pointerItemId, sourceType, windowId);
    ASSERT_FALSE(manager.targetTouchWinIds_.find(pointerItemId) != manager.targetTouchWinIds_.end());
    ASSERT_EQ(manager.targetTouchWinIds_[pointerItemId].size(), 0);
}

/**
 * @tc.name: InputWindowsManagerTest_AddTargetWindowIds_002
 * @tc.desc: Test the functionality of adding target window IDs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_AddTargetWindowIds_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager manager;
    int32_t pointerItemId = 2;
    int32_t windowId1 = 200;
    int32_t windowId2 = 201;
    int32_t sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    manager.targetTouchWinIds_[pointerItemId] = {windowId1};
    WIN_MGR->AddTargetWindowIds(pointerItemId, sourceType, windowId2);
    ASSERT_TRUE(manager.targetTouchWinIds_.find(pointerItemId) != manager.targetTouchWinIds_.end());
    ASSERT_EQ(manager.targetTouchWinIds_[pointerItemId].size(), 1);
    ASSERT_EQ(manager.targetTouchWinIds_[pointerItemId][0], windowId1);
    ASSERT_NE(manager.targetTouchWinIds_[pointerItemId][1], windowId2);
}

/**
 * @tc.name: InputWindowsManagerTest_CheckWindowIdPermissionByPid_002
 * @tc.desc: Test the functionality of checking window ID permission by process ID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CheckWindowIdPermissionByPid_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = -123;
    int32_t pid = -456;
    int32_t result = WIN_MGR->CheckWindowIdPermissionByPid(windowId, pid);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_IsTransparentWin_001
 * @tc.desc: Test the functionality of transparent windows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsTransparentWin_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    void* pixelMap = nullptr;
    int32_t logicalX = 0;
    int32_t logicalY = 0;
    auto result = WIN_MGR->IsTransparentWin(pixelMap, logicalX, logicalY);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: InputWindowsManagerTest_SetCurrentUser_001
 * @tc.desc: Test the functionality of setting the current user
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetCurrentUser_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t userId = 123;
    auto ret = WIN_MGR->SetCurrentUser(userId);
    EXPECT_EQ(ret, RET_OK);
    userId = -456;
    ret = WIN_MGR->SetCurrentUser(userId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerAction_01
 * @tc.desc: Test UpdatePointerAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdatePointerAction_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = pointerEvent->GetPointerAction();
    action = PointerEvent::POINTER_ACTION_MOVE;
    WIN_MGR->UpdatePointerAction(pointerEvent);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_MOVE));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerAction_02
 * @tc.desc: Test UpdatePointerAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdatePointerAction_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = pointerEvent->GetPointerAction();
    action = PointerEvent::POINTER_ACTION_UP;
    WIN_MGR->UpdatePointerAction(pointerEvent);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_UP));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerAction_03
 * @tc.desc: Test UpdatePointerAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdatePointerAction_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = pointerEvent->GetPointerAction();
    action = PointerEvent::POINTER_ACTION_ENTER_WINDOW;
    WIN_MGR->UpdatePointerAction(pointerEvent);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_IN_WINDOW));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerAction_04
 * @tc.desc: Test UpdatePointerAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdatePointerAction_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = pointerEvent->GetPointerAction();
    action = PointerEvent::POINTER_ACTION_LEAVE_WINDOW;
    WIN_MGR->UpdatePointerAction(pointerEvent);
    ASSERT_NO_FATAL_FAILURE(pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDisplayId_002
 * @tc.desc: Test UpdateDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateDisplayId_002, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetTargetDisplayId(1);
    auto id = pointerEvent->GetTargetDisplayId();
    ASSERT_TRUE(WIN_MGR->UpdateDisplayId(id));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDisplayId_003
 * @tc.desc: Test UpdateDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateDisplayId_003, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetTargetDisplayId(10);
    auto id = pointerEvent->GetTargetDisplayId();
    ASSERT_FALSE(WIN_MGR->UpdateDisplayId(id));
}

/**
 * @tc.name: InputWindowsManagerTest_Init_001
 * @tc.desc: Test Init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_Init_001, TestSize.Level1)
{
    UDSServer udsServer;
    WIN_MGR->Init(udsServer);
    EXPECT_TRUE(true);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateCaptureMode_002
 * @tc.desc: Test UpdateCaptureMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateCaptureMode_002, TestSize.Level1)
{
    DisplayGroupInfo displayGroupInfo;
    DisplayInfo info;
    info.id = 1;
    info.x =1;
    info.y = 1;
    info.width = 2;
    info.height = 2;
    info.dpi = 240;
    info.name = "pp";
    info.uniq = "pp";
    info.direction = DIRECTION0;
    displayGroupInfo.displaysInfo.push_back(info);
    WIN_MGR->UpdateCaptureMode(displayGroupInfo);
    ASSERT_FALSE(WIN_MGR->captureModeInfo_.isCaptureMode);
}

/**
 * @tc.name: InputWindowsManagerTest_IsWindowVisible_002
 * @tc.desc: Test IsWindowVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsWindowVisible_002, TestSize.Level1)
{
    int32_t pid = 1000;
    auto ret = WIN_MGR->IsWindowVisible(pid);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_IsWindowVisible_003
 * @tc.desc: Test IsWindowVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsWindowVisible_003, TestSize.Level1)
{
    int32_t pid = -1;
    auto ret = WIN_MGR->IsWindowVisible(pid);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_GetWindowGroupInfoByDisplayId
 * @tc.desc: Test GetWindowGroupInfoByDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetWindowGroupInfoByDisplayId, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    WindowGroupInfo windowGroupInfo;
    int32_t displayId = 1;
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(displayId, windowGroupInfo));
    EXPECT_TRUE(inputWindowsManager.GetWindowGroupInfoByDisplayId(displayId).empty());

    WindowInfo windowInfo;
    displayId = 2;
    windowInfo.id = 1;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(displayId, windowGroupInfo));
    EXPECT_TRUE(!inputWindowsManager.GetWindowGroupInfoByDisplayId(displayId).empty());
}

/**
 * @tc.name: InputWindowsManagerTest_GetClientFd
 * @tc.desc: Test GetClientFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetClientFd, TestSize.Level1)
{
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    WindowInfoEX windowInfoEX;
    windowInfoEX.flag = false;
    pointerEvent->SetPointerId(0);
    inputWindowsManager.touchItemDownInfos_.insert(std::make_pair(pointerEvent->GetPointerId(), windowInfoEX));
    EXPECT_EQ(inputWindowsManager.GetClientFd(pointerEvent), INVALID_FD);
    pointerEvent->SetPointerId(1);
    pointerEvent->SetTargetDisplayId(10);
    pointerEvent->SetTargetWindowId(15);
    WindowGroupInfo windowGroupInfo;
    WindowInfo windowInfo;
    windowInfo.id = 0;
    windowInfo.pid = 5;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    windowInfo.id = 15;
    windowInfo.pid = 6;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(pointerEvent->GetTargetDisplayId(), windowGroupInfo));
    UDSServer udsServer;
    udsServer.idxPidMap_.insert(std::make_pair(6, 15));
    inputWindowsManager.udsServer_ = &udsServer;
    EXPECT_NE(inputWindowsManager.udsServer_, nullptr);
    EXPECT_EQ(inputWindowsManager.GetClientFd(pointerEvent), 15);
    pointerEvent->SetTargetWindowId(20);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
    EXPECT_EQ(inputWindowsManager.GetClientFd(pointerEvent), INVALID_FD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_CANCEL);
    inputWindowsManager.touchItemDownInfos_.clear();
    windowInfoEX.flag = true;
    windowInfoEX.window.agentWindowId = 1;
    pointerEvent->SetPointerId(0);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    inputWindowsManager.touchItemDownInfos_.insert(std::make_pair(pointerEvent->GetPointerId(), windowInfoEX));
    EXPECT_EQ(inputWindowsManager.GetClientFd(pointerEvent), INVALID_FD);
    pointerEvent->SetPointerId(7);
    EXPECT_EQ(inputWindowsManager.GetClientFd(pointerEvent), INVALID_FD);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    inputWindowsManager.mouseDownInfo_.pid = 1;
    inputWindowsManager.mouseDownInfo_.agentWindowId = 6;
    EXPECT_EQ(inputWindowsManager.GetClientFd(pointerEvent), INVALID_FD);
    inputWindowsManager.mouseDownInfo_.pid = -1;
    EXPECT_EQ(inputWindowsManager.GetClientFd(pointerEvent), INVALID_FD);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    EXPECT_EQ(inputWindowsManager.GetClientFd(pointerEvent), INVALID_FD);
}

/**
 * @tc.name: InputWindowsManagerTest_GetClientFd_002
 * @tc.desc: Test GetClientFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetClientFd_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    UDSServer udsServer;
    int32_t udsPid = 20;
    int32_t udsFd = 15;
    udsServer.idxPidMap_.insert(std::make_pair(udsPid, udsFd));
    inputWindowsManager.udsServer_ = &udsServer;
    int32_t windowId = 15;
    EXPECT_NE(inputWindowsManager.udsServer_, nullptr);
    WindowGroupInfo widGroupInfo;
    WindowInfo windowInfo;
    pointerEvent->SetTargetDisplayId(15);
    windowInfo.id = 5;
    windowInfo.pid = 10;
    widGroupInfo.windowsInfo.push_back(windowInfo);
    windowInfo.id = 15;
    windowInfo.pid = 20;
    widGroupInfo.windowsInfo.push_back(windowInfo);
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(pointerEvent->GetTargetDisplayId(), widGroupInfo));
    EXPECT_EQ(inputWindowsManager.GetClientFd(pointerEvent, windowId), udsFd);
    windowId = 7;
    EXPECT_EQ(inputWindowsManager.GetClientFd(pointerEvent, windowId), INVALID_FD);
}

/**
 * @tc.name: InputWindowsManagerTest_CheckFocusWindowChange
 * @tc.desc: Test CheckFocusWindowChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CheckFocusWindowChange, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.focusWindowId = 1;
    inputWindowsManager.displayGroupInfo_.focusWindowId = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.CheckFocusWindowChange(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_CheckZorderWindowChange
 * @tc.desc: Test CheckZorderWindowChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CheckZorderWindowChange, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    std::vector<WindowInfo> oldWindowsInfo;
    std::vector<WindowInfo> newWindowsInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.CheckZorderWindowChange(oldWindowsInfo, newWindowsInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateCaptureMode
 * @tc.desc: Test UpdateCaptureMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateCaptureMode, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    DisplayGroupInfo displayGroupInfo;
    WindowInfo windowInfo;
    inputWindowsManager.captureModeInfo_.isCaptureMode = true;
    inputWindowsManager.displayGroupInfo_.focusWindowId = 25;
    displayGroupInfo.focusWindowId = 25;
    windowInfo.id = 10;
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    windowInfo.id = 11;
    displayGroupInfo.windowsInfo.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateCaptureMode(displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDisplayInfoByIncrementalInfo
 * @tc.desc: Test UpdateDisplayInfoByIncrementalInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateDisplayInfoByIncrementalInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    WindowInfo window;
    DisplayGroupInfo displayGroupInfo;
    WindowInfo windowInfo;
    window.action = WINDOW_UPDATE_ACTION::ADD_END;
    window.id = 5;
    windowInfo.id = 10;
    displayGroupInfo.windowsInfo.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateDisplayInfoByIncrementalInfo(window, displayGroupInfo));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateDisplayInfoByIncrementalInfo(window, displayGroupInfo));
    window.id = 5;
    window.action = WINDOW_UPDATE_ACTION::DEL;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateDisplayInfoByIncrementalInfo(window, displayGroupInfo));
    window.action = WINDOW_UPDATE_ACTION::CHANGE;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateDisplayInfoByIncrementalInfo(window, displayGroupInfo));
    window.id = 10;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateDisplayInfoByIncrementalInfo(window, displayGroupInfo));
    window.action = WINDOW_UPDATE_ACTION::UNKNOWN;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateDisplayInfoByIncrementalInfo(window, displayGroupInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDisplayMode
 * @tc.desc: Test UpdateDisplayMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateDisplayMode, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    DisplayInfo displayInfo;
    displayInfo.displayMode = DisplayMode::FULL;
    inputWindowsManager.displayMode_ = DisplayMode::FULL;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateDisplayMode());
    inputWindowsManager.displayMode_ = DisplayMode::MAIN;
    FINGERSENSE_WRAPPER->sendFingerSenseDisplayMode_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateDisplayMode());
    inputWindowsManager.displayMode_ = DisplayMode::MAIN;
    FINGERSENSE_WRAPPER->sendFingerSenseDisplayMode_ = FingersenseWrapperTest;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateDisplayMode());
}

/**
 * @tc.name: InputWindowsManagerTest_GetPhysicalDisplay
 * @tc.desc: Test GetPhysicalDisplay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetPhysicalDisplay, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t id = 1;
    DisplayInfo displayInfo;
    displayInfo.id = 0;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    displayInfo.id = 1;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_NE(inputWindowsManager.GetPhysicalDisplay(id), nullptr);
}

/**
 * @tc.name: InputWindowsManagerTest_FindPhysicalDisplayInfo
 * @tc.desc: Test FindPhysicalDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_FindPhysicalDisplayInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    DisplayInfo displayInfo;
    std::string uniq = "uniq_test";
    displayInfo.uniq = "uniq_test";
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_NE(inputWindowsManager.FindPhysicalDisplayInfo(uniq), nullptr);
}

/**
 * @tc.name: InputWindowsManagerTest_OnSessionLost
 * @tc.desc: Test OnSessionLost
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_OnSessionLost, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t pointerStylePid = 10;
    int32_t uidRoot = 0;
    std::string programName = "uds_sesion_test";
    int32_t moduleType = 3;
    int32_t pid = 9;
    int32_t fd = -1;
    SessionPtr sess = std::make_shared<UDSSession>(programName, moduleType, fd, uidRoot, pid);
    int32_t windowId = 1;
    PointerStyle pointerStyle;
    pointerStyle.size = 1;
    pointerStyle.color = 2;
    pointerStyle.id = 3;
    std::map<int32_t, PointerStyle> pointerStyleMap;
    pointerStyleMap.insert(std::make_pair(windowId, pointerStyle));
    inputWindowsManager.pointerStyle_.insert(std::make_pair(pointerStylePid, pointerStyleMap));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.OnSessionLost(sess));

    pid = 10;
    SessionPtr session = std::make_shared<UDSSession>(programName, moduleType, fd, uidRoot, pid);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.OnSessionLost(session));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePoinerStyle
 * @tc.desc: Test UpdatePoinerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdatePoinerStyle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t pid = 1;
    int32_t windowId = 1;
    PointerStyle pointerStyle;
    pointerStyle.size = 1;
    pointerStyle.color = 2;
    pointerStyle.id = 3;
    std::map<int32_t, PointerStyle> pointerStyleMap;
    pointerStyleMap.insert(std::make_pair(windowId, pointerStyle));
    inputWindowsManager.pointerStyle_.insert(std::make_pair(pid, pointerStyleMap));
    windowId = 2;
    WindowInfo windowInfo;
    windowInfo.id = 3;
    windowInfo.pid = 6;
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    windowInfo.id = 2;
    windowInfo.pid = 1;
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdatePoinerStyle(pid, windowId, pointerStyle));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateSceneBoardPointerStyle
 * @tc.desc: Test UpdateSceneBoardPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateSceneBoardPointerStyle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t pid = 1000;
    int32_t windowId = 987654321;
    bool isUiExtension = true;
    PointerStyle style;
    style.id = 0;
    std::map<int32_t, PointerStyle> pointerStyleMap;
    pointerStyleMap.insert(std::make_pair(windowId, style));
    inputWindowsManager.uiExtensionPointerStyle_.insert(std::make_pair(pid, pointerStyleMap));
    pid = 1001;
    EXPECT_EQ(inputWindowsManager.UpdateSceneBoardPointerStyle(pid, windowId, style, isUiExtension), RET_OK);
    pid = 1000;
    windowId = 123456789;
    EXPECT_EQ(inputWindowsManager.UpdateSceneBoardPointerStyle(pid, windowId, style, isUiExtension), RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_SetGlobalDefaultPointerStyle
 * @tc.desc: Test SetGlobalDefaultPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetGlobalDefaultPointerStyle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t defaultPointerStyle = 0;
    int32_t cursorCircleStyle = 41;
    int32_t pid = 100;
    int32_t windowId = 1000;
    PointerStyle pointerStyle;
    pointerStyle.id = defaultPointerStyle;
    std::map<int32_t, PointerStyle> pointerStyleMap;
    pointerStyleMap.insert(std::make_pair(windowId, pointerStyle));
    inputWindowsManager.pointerStyle_.insert(std::make_pair(pid, pointerStyleMap));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SetGlobalDefaultPointerStyle());

    pointerStyle.id = cursorCircleStyle;
    inputWindowsManager.pointerStyle_[pid][windowId] = pointerStyle;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SetGlobalDefaultPointerStyle());
}

/**
 * @tc.name: InputWindowsManagerTest_SetPointerStyle
 * @tc.desc: Test SetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetPointerStyle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    bool isUiExtension = false;
    int32_t pid = 100;
    int32_t windowId = 1000;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    std::map<int32_t, PointerStyle> pointerStyleMap;
    pointerStyleMap.insert(std::make_pair(windowId, pointerStyle));
    inputWindowsManager.uiExtensionPointerStyle_.insert(std::make_pair(pid, pointerStyleMap));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SetPointerStyle(pid, windowId, pointerStyle, isUiExtension));
}

/**
 * @tc.name: InputWindowsManagerTest_ClearWindowPointerStyle
 * @tc.desc: Test ClearWindowPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_ClearWindowPointerStyle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t pid = 100;
    int32_t windowId = 1000;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    std::map<int32_t, PointerStyle> pointerStyleMap;
    pointerStyleMap.insert(std::make_pair(windowId, pointerStyle));
    inputWindowsManager.pointerStyle_.insert(std::make_pair(pid, pointerStyleMap));
    windowId = 1001;
    EXPECT_EQ(inputWindowsManager.ClearWindowPointerStyle(pid, windowId), RET_OK);
    windowId = 1000;
    EXPECT_EQ(inputWindowsManager.ClearWindowPointerStyle(pid, windowId), RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_GetPointerStyle
 * @tc.desc: Test GetPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetPointerStyle, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    bool isUiExtension = true;
    int32_t pid = 100;
    int32_t windowId = 1000;
    PointerStyle pointerStyle;
    pointerStyle.id = 0;
    std::map<int32_t, PointerStyle> pointerStyleMap;
    pointerStyleMap.insert(std::make_pair(windowId, pointerStyle));
    inputWindowsManager.uiExtensionPointerStyle_.insert(std::make_pair(pid, pointerStyleMap));
    pid = 101;
    EXPECT_EQ(inputWindowsManager.GetPointerStyle(pid, windowId, pointerStyle, isUiExtension), RET_OK);
    pid = 100;
    windowId = 100;
    EXPECT_EQ(inputWindowsManager.GetPointerStyle(pid, windowId, pointerStyle, isUiExtension), RET_OK);
    windowId = 1000;
    EXPECT_EQ(inputWindowsManager.GetPointerStyle(pid, windowId, pointerStyle, isUiExtension), RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDisplayId
 * @tc.desc: Test UpdateDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateDisplayId, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t displayId = -1;
    DisplayInfo displayInfo;
    displayInfo.id = 10;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_TRUE(inputWindowsManager.UpdateDisplayId(displayId));
    EXPECT_TRUE(inputWindowsManager.UpdateDisplayId(displayId));
    displayId = 15;
    EXPECT_FALSE(inputWindowsManager.UpdateDisplayId(displayId));
}

/**
 * @tc.name: InputWindowsManagerTest_SelectWindowInfo
 * @tc.desc: Test SelectWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SelectWindowInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t desplayId = 10;
    int32_t logicalX = 200;
    int32_t logicalY = 200;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(10);
    WindowInfo windowInfo;
    windowInfo.id = 10;
    WindowGroupInfo windowGroupInfo;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(desplayId, windowGroupInfo));
    inputWindowsManager.firstBtnDownWindowId_ = 10;
    inputWindowsManager.extraData_.appended = false;
    inputWindowsManager.extraData_.sourceType = PointerEvent::SOURCE_TYPE_UNKNOWN;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ROTATE_BEGIN);
    pointerEvent->SetButtonPressed(1);
    pointerEvent->SetButtonPressed(2);
    EXPECT_NE(inputWindowsManager.SelectWindowInfo(logicalX, logicalY, pointerEvent), std::nullopt);
}

/**
 * @tc.name: InputWindowsManagerTest_GetWindowInfo
 * @tc.desc: Test GetWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetWindowInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t logicalX = 200;
    int32_t logicalY = 200;
    WindowInfo windowInfo;
    windowInfo.flags = 1;
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    EXPECT_EQ(inputWindowsManager.GetWindowInfo(logicalX, logicalY), std::nullopt);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateLeftRightArea
 * @tc.desc: Test UpdateLeftRightArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateLeftRightArea, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    Rect windowArea;
    std::vector<int32_t> pointerChangeAreas {5, 0, 5, 0, 5, 0, 5, 0};
    std::vector<Rect> windowHotAreas;
    windowArea.x = 200;
    windowArea.y = 200;
    windowArea.height = 400;
    windowArea.width = 400;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateLeftRightArea(windowArea, pointerChangeAreas, windowHotAreas));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateInnerAngleArea
 * @tc.desc: Test UpdateInnerAngleArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateInnerAngleArea, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    Rect windowArea;
    std::vector<int32_t> pointerChangeAreas {0, 16, 0, 16, 0, 16, 0, 16};
    std::vector<Rect> windowHotAreas;
    windowArea.x = 200;
    windowArea.y = 200;
    windowArea.height = 400;
    windowArea.width = 400;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateInnerAngleArea(windowArea, pointerChangeAreas, windowHotAreas));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdatePointerEvent
 * @tc.desc: Test UpdatePointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdatePointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t logicalX = 200;
    int32_t logicalY = 200;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo touchWindow;
    touchWindow.id = 1;
    inputWindowsManager.lastWindowInfo_.id = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdatePointerEvent(logicalX, logicalY, pointerEvent, touchWindow));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateMouseTarget
 * @tc.desc: Test UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateMouseTarget, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(-1);
    EXPECT_EQ(inputWindowsManager.UpdateMouseTarget(pointerEvent), RET_ERR);

    DisplayInfo displayInfo;
    displayInfo.id = 1;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    pointerEvent->SetPointerId(5);
    PointerEvent::PointerItem item;
    item.SetPointerId(10);
    pointerEvent->AddPointerItem(item);
    EXPECT_EQ(inputWindowsManager.UpdateMouseTarget(pointerEvent), RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_JudgMouseIsDownOrUp
 * @tc.desc: Test JudgMouseIsDownOrUp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_JudgMouseIsDownOrUp, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    bool dragState = false;
    inputWindowsManager.lastPointerEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager.lastPointerEvent_, nullptr);
    inputWindowsManager.lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    inputWindowsManager.pointerActionFlag_ = PointerEvent::POINTER_ACTION_BUTTON_UP;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.JudgMouseIsDownOrUp(dragState));

    dragState = true;
    inputWindowsManager.lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    inputWindowsManager.pointerActionFlag_ = PointerEvent::POINTER_ACTION_BUTTON_DOWN;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.JudgMouseIsDownOrUp(dragState));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateJoystickTarget
 * @tc.desc: Test UpdateJoystickTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateJoystickTarget, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    inputWindowsManager.displayGroupInfo_.focusWindowId = 150;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(-1);
    WindowInfo windowInfo;
    windowInfo.id = 150;
    windowInfo.agentWindowId = 200;
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateJoystickTarget(pointerEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateAndAdjustMouseLocation
 * @tc.desc: Test UpdateAndAdjustMouseLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateAndAdjustMouseLocation, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t displayId = 1;
    double x = 200;
    double y = 200;
    bool isRealData = true;
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.width = 500;
    displayInfo.height = 500;
    displayInfo.displayDirection = DIRECTION0;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateAndAdjustMouseLocation(displayId, x, y, isRealData));
    isRealData = false;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateAndAdjustMouseLocation(displayId, x, y, isRealData));
}

/**
 * @tc.name: InputWindowsManagerTest_GetMouseInfo
 * @tc.desc: Test GetMouseInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetMouseInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    inputWindowsManager.mouseLocation_.displayId = -1;
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.width = 600;
    displayInfo.height = 600;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_EQ(inputWindowsManager.GetMouseInfo().displayId, displayInfo.id);
}

/**
 * @tc.name: InputWindowsManagerTest_GetCursorPos
 * @tc.desc: Test GetCursorPos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetCursorPos, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    inputWindowsManager.cursorPos_.displayId = -1;
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.width = 300;
    displayInfo.height = 300;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_EQ(inputWindowsManager.GetCursorPos().displayId, displayInfo.id);
}

/**
 * @tc.name: InputWindowsManagerTest_ResetCursorPos
 * @tc.desc: Test ResetCursorPos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_ResetCursorPos, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.width = 300;
    displayInfo.height = 300;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_EQ(inputWindowsManager.ResetCursorPos().displayId, displayInfo.id);
}

/**
 * @tc.name: InputWindowsManagerTest_GetTargetWindowIds
 * @tc.desc: Test GetTargetWindowIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetTargetWindowIds, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t pointerItemId = 1;
    int32_t sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    std::vector<int32_t> windowIds { 1, 2, 3 };
    inputWindowsManager.targetTouchWinIds_.insert(std::make_pair(pointerItemId, windowIds));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.GetTargetWindowIds(pointerItemId, sourceType, windowIds));
}

/**
 * @tc.name: InputWindowsManagerTest_CheckWindowIdPermissionByPid_001
 * @tc.desc: Test CheckWindowIdPermissionByPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CheckWindowIdPermissionByPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t windowId = 300;
    int32_t pid = 500;
    WindowInfo windowInfo;
    windowInfo.id = 300;
    windowInfo.pid = 500;
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    EXPECT_EQ(inputWindowsManager.CheckWindowIdPermissionByPid(windowId, pid), RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_FindPhysicalDisplay_002
 * @tc.desc: This test verifies the functionality of finding physical displays
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_FindPhysicalDisplay_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    DisplayInfo displayInfo;
    DisplayInfo displaysInfo;
    int32_t logicalX = 300;
    int32_t logicalY = 400;
    int32_t physicalX = 100;
    int32_t physicalY =200;
    int32_t displayId = -1;
    displayInfo.x = INT32_MAX;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId));
    displayInfo.x = 200;
    inputWindowsManager.FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId);
    EXPECT_EQ(logicalX, physicalX + displayInfo.x);
    displayInfo.y = INT32_MAX ;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId));
    displayInfo.y = 200;
    inputWindowsManager.FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId);
    EXPECT_EQ(logicalY, physicalY + displayInfo.y);
    displaysInfo.x = 100;
    displaysInfo.width = INT32_MAX;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displaysInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId));
}

/**
 * @tc.name: InputWindowsManagerTest_FindPhysicalDisplay_003
 * @tc.desc: This test verifies the functionality of finding physical displays
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_FindPhysicalDisplay_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    DisplayInfo displayInfo;
    DisplayInfo displaysInfo;
    int32_t logicalX = 300;
    int32_t logicalY = 400;
    int32_t physicalX = 100;
    int32_t physicalY =200;
    int32_t displayMaxX = 300;
    int32_t displayMaxY = 400;
    int32_t displayId = -1;
    displayInfo.x = 200;
    inputWindowsManager.FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId);
    EXPECT_EQ(logicalX, physicalX + displayInfo.x);
    displayInfo.y = 200;
    inputWindowsManager.FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId);
    EXPECT_EQ(logicalY, physicalY + displayInfo.y);
    displaysInfo.x = 200;
    displaysInfo.width = 100;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displaysInfo);
    inputWindowsManager.FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId);
    EXPECT_EQ(displayMaxX, displaysInfo.x + displaysInfo.width);
    displaysInfo.y = 100;
    displaysInfo.height = INT32_MAX;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displaysInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId));
    displaysInfo.y = 200;
    displaysInfo.height = 200;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displaysInfo);
    inputWindowsManager.FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId);
    EXPECT_EQ(displayMaxY, displaysInfo.y + displaysInfo.height);
}

/**
 * @tc.name: InputWindowsManagerTest_IsInHotArea
 * @tc.desc: Test IsInHotArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsInHotArea, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t x = 200;
    int32_t y = 300;
    std::vector<Rect> rects;
    WindowInfo window;
    Rect rect;
    rect.x = 100;
    rect.width = INT32_MAX;
    rects.push_back(rect);
    EXPECT_FALSE(inputWindowsManager.IsInHotArea(x, y, rects, window));
    rects.clear();
    rects = { {150, 100, 300, INT32_MAX} };
    EXPECT_FALSE(inputWindowsManager.IsInHotArea(x, y, rects, window));
    rects.clear();
    rects = { {150, 250, 300, 500} };
    EXPECT_TRUE(inputWindowsManager.IsInHotArea(x, y, rects, window));
    x = 100;
    y = 200;
    EXPECT_FALSE(inputWindowsManager.IsInHotArea(x, y, rects, window));
}

/**
 * @tc.name: InputWindowsManagerTest_InWhichHotArea
 * @tc.desc: Test InWhichHotArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_InWhichHotArea, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t x = 500;
    int32_t y = 800;
    std::vector<Rect> rects;
    PointerStyle pointerStyle;
    rects = { { 100, 0, INT32_MAX, 0 } };
    EXPECT_FALSE(inputWindowsManager.InWhichHotArea(x, y, rects, pointerStyle));
    rects.clear();
    rects = { { 150, 100, 300, INT32_MAX } };
    EXPECT_FALSE(inputWindowsManager.InWhichHotArea(x, y, rects, pointerStyle));
    rects.clear();
    rects = { { 150, 250, 300, 500 } };
    EXPECT_FALSE(inputWindowsManager.InWhichHotArea(x, y, rects, pointerStyle));
    x = 200;
    y = 300;
    EXPECT_TRUE(inputWindowsManager.InWhichHotArea(x, y, rects, pointerStyle));
    int32_t cycleNum = 7;
    for (int32_t i = 0; i < cycleNum; ++i) {
        rects.insert(rects.begin(), { 1000, 1000, 1500, 1500 });
        EXPECT_TRUE(inputWindowsManager.InWhichHotArea(x, y, rects, pointerStyle));
    }
}

/**
 * @tc.name: InputWindowsManagerTest_DispatchPointer
 * @tc.desc: Test DispatchPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_DispatchPointer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_ENTER_WINDOW;
    UDSServer udsServer;
    inputWindowsManager.udsServer_ = &udsServer;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.DispatchPointer(pointerAction));
    IPointerDrawingManager::GetInstance()->SetMouseDisplayState(true);
    inputWindowsManager.lastPointerEvent_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.DispatchPointer(pointerAction));
    inputWindowsManager.lastPointerEvent_ = PointerEvent::Create();
    EXPECT_NE(inputWindowsManager.lastPointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    inputWindowsManager.lastPointerEvent_->AddPointerItem(item);
    inputWindowsManager.lastPointerEvent_->SetPointerId(1);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.DispatchPointer(pointerAction));
    inputWindowsManager.lastPointerEvent_->SetPointerId(0);
    inputWindowsManager.lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    WindowInfo windowInfo;
    windowInfo.flags = WindowInfo::FLAG_BIT_HANDWRITING;
    windowInfo.pointerHotAreas.push_back({  100, 0, INT32_MAX, 0 });
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager.lastLogicX_ = 200;
    inputWindowsManager.lastLogicY_ = 200;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.DispatchPointer(pointerAction));
}

/**
 * @tc.name: InputWindowsManagerTest_DispatchPointer_002
 * @tc.desc: Test DispatchPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_DispatchPointer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_ENTER_WINDOW;
    UDSServer udsServer;
    inputWindowsManager.udsServer_ = &udsServer;
    inputWindowsManager.lastPointerEvent_ = PointerEvent::Create();
    EXPECT_NE(inputWindowsManager.lastPointerEvent_, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayX(100);
    item.SetDisplayY(100);
    inputWindowsManager.lastPointerEvent_->AddPointerItem(item);
    inputWindowsManager.lastPointerEvent_->SetPointerId(0);
    inputWindowsManager.firstBtnDownWindowId_ = 1;
    inputWindowsManager.lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    inputWindowsManager.lastPointerEvent_->SetTargetDisplayId(-1);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager.lastWindowInfo_.id = 2;
    inputWindowsManager.lastWindowInfo_.agentWindowId = 2;
    inputWindowsManager.lastWindowInfo_.area.x = 100;
    inputWindowsManager.lastWindowInfo_.area.y = 100;
    inputWindowsManager.lastPointerEvent_->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    inputWindowsManager.lastPointerEvent_->SetDeviceId(5);
    inputWindowsManager.extraData_.appended = true;
    inputWindowsManager.extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    InputHandler->eventFilterHandler_ = std::make_shared<EventFilterHandler>();
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.DispatchPointer(pointerAction));
    inputWindowsManager.lastWindowInfo_.id = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.DispatchPointer(pointerAction));
    inputWindowsManager.extraData_.appended = false;
    pointerAction = PointerEvent::POINTER_ACTION_LEAVE_WINDOW;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.DispatchPointer(pointerAction));
}

/**
 * @tc.name: InputWindowsManagerTest_NotifyPointerToWindow
 * @tc.desc: Test NotifyPointerToWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_NotifyPointerToWindow, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    UDSServer udsServer;
    inputWindowsManager.lastPointerEvent_ = PointerEvent::Create();
    ASSERT_NE(inputWindowsManager.lastPointerEvent_, nullptr);
    inputWindowsManager.lastLogicX_ = 200;
    inputWindowsManager.lastLogicY_ = 300;
    WindowInfo windowInfo;
    windowInfo.flags = WindowInfo::FLAG_BIT_HANDWRITING;
    windowInfo.pointerHotAreas.push_back({ 100, 100, INT32_MAX, 100 });
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.NotifyPointerToWindow());
    windowInfo.id = 10;
    windowInfo.pointerHotAreas.clear();
    windowInfo.pointerHotAreas.push_back({ 150, 250, 300, 500 });
    inputWindowsManager.displayGroupInfo_.windowsInfo.insert(
        inputWindowsManager.displayGroupInfo_.windowsInfo.begin(), windowInfo);
    inputWindowsManager.lastWindowInfo_.id = 10;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.NotifyPointerToWindow());
    inputWindowsManager.lastWindowInfo_.id = 20;
    inputWindowsManager.lastWindowInfo_.pid = 50;
    int32_t udsFd = 100;
    udsServer.idxPidMap_.insert(std::make_pair(inputWindowsManager.lastWindowInfo_.pid, udsFd));
    inputWindowsManager.udsServer_ = &udsServer;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.NotifyPointerToWindow());
    inputWindowsManager.udsServer_ = nullptr;
    inputWindowsManager.lastWindowInfo_.id = 30;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.NotifyPointerToWindow());
    windowInfo.id = 50;
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    inputWindowsManager.lastWindowInfo_.id = 50;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.NotifyPointerToWindow());
}

/**
 * @tc.name: InputWindowsManagerTest_GetMouseInfo_002
 * @tc.desc: Test the function GetMouseInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetMouseInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    inputWindowsManager.mouseLocation_.displayId = -1;
    DisplayInfo displaysInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.GetMouseInfo());
    displaysInfo.id = 2;
    displaysInfo.width = 20;
    displaysInfo.height = 30;
    displaysInfo.name = "name1";
    displaysInfo.uniq = "uniq1";
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displaysInfo);
    MouseLocation result = inputWindowsManager.GetMouseInfo();
    EXPECT_EQ(result.displayId, 2);
    EXPECT_EQ(result.physicalX, 10);
    EXPECT_EQ(result.physicalY, 15);
}

/**
 * @tc.name: InputWindowsManagerTest_GetCursorPos_002
 * @tc.desc: Test the function GetCursorPos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetCursorPos_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    inputWindowsManager.cursorPos_.displayId = -1;
    DisplayInfo displaysInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.GetCursorPos());
    displaysInfo.id = 2;
    displaysInfo.width = 30;
    displaysInfo.height = 40;
    displaysInfo.name = "name2";
    displaysInfo.uniq = "uniq2";
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displaysInfo);
    CursorPosition result = inputWindowsManager.GetCursorPos();
    EXPECT_EQ(result.displayId, 2);
    EXPECT_EQ(result.cursorPos.x, 15);
    EXPECT_EQ(result.cursorPos.y, 20);
}

/**
 * @tc.name: InputWindowsManagerTest_ResetCursorPos_002
 * @tc.desc: Test the function ResetCursorPos
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_ResetCursorPos_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    DisplayInfo displaysInfo;
    CursorPosition result = inputWindowsManager.ResetCursorPos();
    EXPECT_EQ(result.displayId, -1);
    displaysInfo.id = 3;
    displaysInfo.width = 40;
    displaysInfo.height = 50;
    displaysInfo.name = "name3";
    displaysInfo.uniq = "uniq3";
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displaysInfo);
    result = inputWindowsManager.ResetCursorPos();
    EXPECT_EQ(result.displayId, 3);
    EXPECT_EQ(result.cursorPos.x, 20);
    EXPECT_EQ(result.cursorPos.y, 25);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDisplayIdAndName_002
 * @tc.desc: Test updating display ID and name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateDisplayIdAndName_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    DisplayInfo displaysInfo;
    displaysInfo.id = 1;
    displaysInfo.uniq = "abc";
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displaysInfo);
    inputWindowsManager.bindInfo_.AddDisplay(2, "cde");
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateDisplayIdAndName());
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDisplayIdAndName_003
 * @tc.desc: Test updating display ID and name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateDisplayIdAndName_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    DisplayInfo displaysInfo;
    displaysInfo.id = 1;
    displaysInfo.uniq = "abc";
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displaysInfo);
    inputWindowsManager.bindInfo_.AddDisplay(1, "abc");
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateDisplayIdAndName());
}

/**
 * @tc.name: InputWindowsManagerTest_SendPointerEvent
 * @tc.desc: Test SendPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SendPointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t pointerAction = PointerEvent::POINTER_ACTION_ENTER_WINDOW;
    UDSServer udsServer;
    WindowInfo windowInfo;
    inputWindowsManager.udsServer_ = &udsServer;
    windowInfo.pointerHotAreas.push_back({ 100, 100, INT32_MAX, 100 });
    inputWindowsManager.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SendPointerEvent(pointerAction));
    windowInfo.pointerHotAreas.clear();
    windowInfo.pointerHotAreas.push_back({ 150, 250, 300, 500 });
    windowInfo.area.x = 50;
    windowInfo.area.y = 50;
    windowInfo.id = 10;
    windowInfo.pid = 30;
    windowInfo.agentWindowId = 10;
    inputWindowsManager.displayGroupInfo_.windowsInfo.insert(
        inputWindowsManager.displayGroupInfo_.windowsInfo.begin(), windowInfo);
    inputWindowsManager.mouseLocation_.displayId = 1;
    inputWindowsManager.mouseLocation_.physicalX = 200;
    inputWindowsManager.mouseLocation_.physicalY = 300;
    inputWindowsManager.lastLogicX_ = 150;
    inputWindowsManager.lastLogicY_ = 150;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SendPointerEvent(pointerAction));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateMouseTarget001
 * @tc.desc: Test UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateMouseTarget001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 300;
    displayInfo.y = 500;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDisplayX(INT32_MAX);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(0);
    EXPECT_EQ(inputWindowsManager.UpdateMouseTarget(pointerEvent), RET_ERR);

    pointerEvent->SetPointerId(1);
    EXPECT_EQ(inputWindowsManager.UpdateMouseTarget(pointerEvent), RET_ERR);

    item.SetDisplayX(150);
    item.SetDisplayY(INT32_MAX);
    pointerEvent->UpdatePointerItem(pointerEvent->GetPointerId(), item);
    EXPECT_EQ(inputWindowsManager.UpdateMouseTarget(pointerEvent), RET_ERR);
    item.SetDisplayX(150);
    item.SetDisplayY(300);
    pointerEvent->UpdatePointerItem(pointerEvent->GetPointerId(), item);

    inputWindowsManager.firstBtnDownWindowId_ = 5;
    WindowGroupInfo windowGroupInfo;
    WindowInfo windowInfo;
    windowInfo.id = 10;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(pointerEvent->GetTargetDisplayId(), windowGroupInfo));
    inputWindowsManager.mouseDownInfo_.id = -1;
    EXPECT_EQ(inputWindowsManager.UpdateMouseTarget(pointerEvent), RET_ERR);

    inputWindowsManager.firstBtnDownWindowId_ = 10;
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_AXIS_UPDATE);
    inputWindowsManager.SetHoverScrollState(false);
    EXPECT_EQ(inputWindowsManager.UpdateMouseTarget(pointerEvent), RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateMouseTarget_002
 * @tc.desc: Test UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateMouseTarget_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_DOWN);
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 300;
    displayInfo.y = 500;
    displayInfo.width = 100;
    displayInfo.height = 100;
    displayInfo.displayDirection = DIRECTION0;
    displayInfo.direction = DIRECTION180;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDisplayX(150);
    item.SetDisplayY(300);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_EQ(inputWindowsManager.UpdateMouseTarget(pointerEvent), RET_ERR);
    inputWindowsManager.firstBtnDownWindowId_ = 10;
    WindowGroupInfo windowGroupInfo;
    WindowInfo windowInfo;
    windowInfo.id = 10;
    windowInfo.pid = 50;
    windowInfo.agentWindowId = 60;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(pointerEvent->GetTargetDisplayId(), windowGroupInfo));
    inputWindowsManager.mouseDownInfo_.id = -1;
    inputWindowsManager.SetHoverScrollState(true);
    std::map<int32_t, PointerStyle> styleMap;
    PointerStyle pointerStyle;
    IPointerDrawingManager::GetInstance()->SetMouseDisplayState(false);
    styleMap.insert(std::make_pair(windowInfo.id, pointerStyle));
    inputWindowsManager.uiExtensionPointerStyle_.insert(std::make_pair(windowInfo.pid, styleMap));
    UDSServer udsServer;
    inputWindowsManager.udsServer_ = &udsServer;
    inputWindowsManager.SetUiExtensionInfo(true, 50, 10);
    inputWindowsManager.isDragBorder_ = true;
    inputWindowsManager.dragFlag_ = false;
    inputWindowsManager.captureModeInfo_.isCaptureMode = true;
    inputWindowsManager.captureModeInfo_.windowId = 1;
    inputWindowsManager.extraData_.appended = true;
    inputWindowsManager.extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    EXPECT_EQ(inputWindowsManager.UpdateMouseTarget(pointerEvent), ERR_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateMouseTarget_003
 * @tc.desc: Test UpdateMouseTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateMouseTarget_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 300;
    displayInfo.y = 500;
    displayInfo.width = 100;
    displayInfo.height = 100;
    displayInfo.displayDirection = DIRECTION180;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDisplayX(150);
    item.SetDisplayY(300);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(1);
    EXPECT_EQ(inputWindowsManager.UpdateMouseTarget(pointerEvent), RET_ERR);
    inputWindowsManager.firstBtnDownWindowId_ = 10;
    WindowGroupInfo windowGroupInfo;
    WindowInfo windowInfo;
    windowInfo.id = 10;
    windowInfo.pid = 50;
    windowInfo.agentWindowId = 60;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(pointerEvent->GetTargetDisplayId(), windowGroupInfo));
    inputWindowsManager.mouseDownInfo_.id = -1;
    inputWindowsManager.SetHoverScrollState(true);
    std::map<int32_t, PointerStyle> styleMap;
    PointerStyle pointerStyle;
    IPointerDrawingManager::GetInstance()->SetMouseDisplayState(true);
    styleMap.insert(std::make_pair(windowInfo.id, pointerStyle));
    inputWindowsManager.uiExtensionPointerStyle_.insert(std::make_pair(windowInfo.pid, styleMap));
    UDSServer udsServer;
    inputWindowsManager.udsServer_ = &udsServer;
    inputWindowsManager.SetUiExtensionInfo(false, 50, 10);
    inputWindowsManager.isDragBorder_ = false;
    inputWindowsManager.dragFlag_ = true;
    inputWindowsManager.captureModeInfo_.isCaptureMode = false;
    inputWindowsManager.captureModeInfo_.windowId = 10;
    inputWindowsManager.extraData_.appended = false;
    EXPECT_EQ(inputWindowsManager.UpdateMouseTarget(pointerEvent), ERR_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTouchScreenTarget
 * @tc.desc: Test UpdateTouchScreenTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTouchScreenTarget, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetTargetDisplayId(1);
    pointerEvent->SetPointerId(0);
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.width = 300;
    displayInfo.height = 300;
    displayInfo.displayDirection = DIRECTION0;
    displayInfo.x = INT32_MAX;
    displayInfo.y = 300;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetDisplayX(100);
    item.SetDisplayY(100);
    item.SetDisplayXPos(100);
    item.SetDisplayYPos(100);
    item.SetTargetWindowId(-1);
    pointerEvent->AddPointerItem(item);
    EXPECT_EQ(inputWindowsManager.UpdateTouchScreenTarget(pointerEvent), RET_ERR);

    pointerEvent->SetPointerId(1);
    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_SIMULATE;
    EXPECT_EQ(inputWindowsManager.UpdateTouchScreenTarget(pointerEvent), RET_ERR);

    pointerEvent->bitwise_ = InputEvent::EVENT_FLAG_NONE;
    inputWindowsManager.displayGroupInfo_.displaysInfo[0].x = 300;
    inputWindowsManager.displayGroupInfo_.displaysInfo[0].y = INT32_MAX;
    EXPECT_EQ(inputWindowsManager.UpdateTouchScreenTarget(pointerEvent), RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_GetPidAndUpdateTarget_002
 * @tc.desc: Test getting PID and updating the target
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetPidAndUpdateTarget_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetTargetDisplayId(10);
    inputWindowsManager.displayGroupInfo_.focusWindowId = 52;
    WindowGroupInfo windowGroupInfo;
    WindowInfo windowInfo;
    windowInfo.id = 2;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    windowInfo.id = 52;
    windowInfo.pid = 100;
    windowInfo.agentWindowId = 65;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(keyEvent->GetTargetDisplayId(), windowGroupInfo));
    ASSERT_NO_FATAL_FAILURE(inputWindowsManager.GetPidAndUpdateTarget(keyEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateAndAdjustMouseLocation_002
 * @tc.desc: Test UpdateAndAdjustMouseLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateAndAdjustMouseLocation_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t displayId = 1;
    double x = 350;
    double y = 350;
    bool isRealData = true;
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 600;
    displayInfo.y = 600;
    displayInfo.width = 300;
    displayInfo.height = 300;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    displayInfo.id = 2;
    displayInfo.x = 500;
    displayInfo.y = 500;
    displayInfo.width = 600;
    displayInfo.height = 600;
    displayInfo.displayDirection = DIRECTION0;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateAndAdjustMouseLocation(displayId, x, y, isRealData));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateAndAdjustMouseLocation_003
 * @tc.desc: Test UpdateAndAdjustMouseLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateAndAdjustMouseLocation_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t displayId = 1;
    double x = 200;
    double y = 200;
    bool isRealData = false;
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.x = 600;
    displayInfo.y = 600;
    displayInfo.width = 400;
    displayInfo.height = 400;
    displayInfo.displayDirection = DIRECTION90;
    inputWindowsManager.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateAndAdjustMouseLocation(displayId, x, y, isRealData));
    inputWindowsManager.displayGroupInfo_.displaysInfo[0].displayDirection = DIRECTION0;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.UpdateAndAdjustMouseLocation(displayId, x, y, isRealData));
}

/**
 * @tc.name: InputWindowsManagerTest_SetWindowPointerStyle_002
 * @tc.desc: Test SetWindowPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetWindowPointerStyle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t pid = 10;
    int32_t windowId = 50;
    WindowArea area = WindowArea::FOCUS_ON_BOTTOM_RIGHT;
    inputWindowsManager.lastPointerStyle_.id = MOUSE_ICON::NORTH_WEST_SOUTH_EAST;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SetWindowPointerStyle(area, pid, windowId));

    windowId = -1;
    inputWindowsManager.lastPointerStyle_.id = MOUSE_ICON::EAST;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SetWindowPointerStyle(area, pid, windowId));
}

/**
 * @tc.name: InputWindowsManagerTest_SkipNavigationWindow_006
 * @tc.desc: Test updating window information for each display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SkipNavigationWindow_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    inputWindowsMgr.isOpenAntiMisTakeObserver_ = false;
    inputWindowsMgr.antiMistake_.isOpen = true;
    ASSERT_TRUE(inputWindowsMgr.SkipNavigationWindow(WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE,
        PointerEvent::TOOL_TYPE_PEN));

    inputWindowsMgr.isOpenAntiMisTakeObserver_ = true;
    inputWindowsMgr.antiMistake_.isOpen = false;
    ASSERT_FALSE(inputWindowsMgr.SkipNavigationWindow(WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE,
        PointerEvent::TOOL_TYPE_PEN));
}

/**
 * @tc.name: InputWindowsManagerTest_HandleWindowInputType_005
 * @tc.desc: Test HandleWindowInputType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_HandleWindowInputType_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    item.SetToolType(PointerEvent::TOOL_TYPE_MOUSE);
    pointerEvent->SetPointerId(1);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    WindowInfo window;
    window.windowInputType = WindowInputType::NORMAL;
    EXPECT_FALSE(inputWindowsMgr.HandleWindowInputType(window, pointerEvent));
    window.windowInputType = WindowInputType::TRANSMIT_ALL;
    EXPECT_TRUE(inputWindowsMgr.HandleWindowInputType(window, pointerEvent));
    window.windowInputType = WindowInputType::TRANSMIT_EXCEPT_MOVE;
    EXPECT_TRUE(inputWindowsMgr.HandleWindowInputType(window, pointerEvent));
    window.windowInputType = WindowInputType::ANTI_MISTAKE_TOUCH;
    EXPECT_FALSE(inputWindowsMgr.HandleWindowInputType(window, pointerEvent));
    window.windowInputType = WindowInputType::TRANSMIT_AXIS_MOVE;
    EXPECT_FALSE(inputWindowsMgr.HandleWindowInputType(window, pointerEvent));
    window.windowInputType = WindowInputType::TRANSMIT_MOUSE_MOVE;
    EXPECT_FALSE(inputWindowsMgr.HandleWindowInputType(window, pointerEvent));
    window.windowInputType = WindowInputType::TRANSMIT_LEFT_RIGHT;
    EXPECT_FALSE(inputWindowsMgr.HandleWindowInputType(window, pointerEvent));
    window.windowInputType = WindowInputType::TRANSMIT_BUTTOM;
    EXPECT_FALSE(inputWindowsMgr.HandleWindowInputType(window, pointerEvent));
    window.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    EXPECT_FALSE(inputWindowsMgr.HandleWindowInputType(window, pointerEvent));
    window.windowInputType = WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE;
    EXPECT_FALSE(inputWindowsMgr.HandleWindowInputType(window, pointerEvent));
    window.windowInputType = static_cast<WindowInputType>(100);
    EXPECT_FALSE(inputWindowsMgr.HandleWindowInputType(window, pointerEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_AddTargetWindowIds_003
 * @tc.desc: Test AddTargetWindowIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_AddTargetWindowIds_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    int32_t pointerItemId = 1;
    int32_t sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    int32_t windowId = 50;
    std::vector<int32_t> winIds;
    inputWindowsMgr.targetMouseWinIds_.insert(std::make_pair(pointerItemId, winIds));
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.AddTargetWindowIds(pointerItemId, sourceType, windowId));

    pointerItemId = 2;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.AddTargetWindowIds(pointerItemId, sourceType, windowId));

    sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    inputWindowsMgr.targetTouchWinIds_.insert(std::make_pair(pointerItemId, winIds));
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.AddTargetWindowIds(pointerItemId, sourceType, windowId));
}

/**
 * @tc.name: InputWindowsManagerTest_ReverseXY
 * @tc.desc: Test ReverseXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_ReverseXY, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    int32_t x = 100;
    int32_t y = 100;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.ReverseXY(x, y));

    DisplayInfo displayInfo;
    displayInfo.direction = DIRECTION0;
    displayInfo.width = 200;
    displayInfo.height = 300;
    inputWindowsMgr.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.ReverseXY(x, y));
}

/**
 * @tc.name: InputWindowsManagerTest_IsTransparentWin_002
 * @tc.desc: Test IsTransparentWin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsTransparentWin_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    std::shared_ptr<Media::PixelMap> pixelMap = CreatePixelMap(MIDDLE_PIXEL_MAP_WIDTH, MIDDLE_PIXEL_MAP_HEIGHT);
    ASSERT_NE(pixelMap, nullptr);
    int32_t logicalX = 100;
    int32_t logicalY = 100;
    EXPECT_FALSE(inputWindowsMgr.IsTransparentWin((void *)pixelMap.get(), logicalX, logicalY));
}

/**
 * @tc.name: InputWindowsManagerTest_PrintChangedWindowBySync
 * @tc.desc: Test PrintChangedWindowBySync
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_PrintChangedWindowBySync, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsMgr;
    DisplayGroupInfo newDisplayInfo;
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.PrintChangedWindowBySync(newDisplayInfo));
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 50;
    windowInfo.zOrder = 60;
    inputWindowsMgr.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    windowInfo.id = 2;
    newDisplayInfo.windowsInfo.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(inputWindowsMgr.PrintChangedWindowBySync(newDisplayInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_GetClientFd_003
 * @tc.desc: Test the funcation GetClientFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetClientFd_003, TestSize.Level1)
{
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    WindowInfoEX windowInfoEX;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 5;
    std::vector<WindowInfo> windows;
    windows.push_back(windowInfo);
    windowInfoEX.window = windows [0];
    windowInfoEX.flag = false;
    pointerEvent->pointerId_ = 1;
    inputWindowsManager.touchItemDownInfos_.insert(std::make_pair(1, windowInfoEX));
    int32_t ret = inputWindowsManager.GetClientFd(pointerEvent);
    EXPECT_EQ(ret, -1);
    windowInfoEX.flag = true;
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->targetDisplayId_ = 5;
    inputWindowsManager.touchItemDownInfos_.insert(std::make_pair(10, windowInfoEX));
    ret = inputWindowsManager.GetClientFd(pointerEvent);
    EXPECT_EQ(ret, -1);
}

/**
 * @tc.name: InputWindowsManagerTest_GetPidAndUpdateTarget_003
 * @tc.desc: Test the funcation GetPidAndUpdateTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetPidAndUpdateTarget_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    inputWindowsManager.displayGroupInfo_.focusWindowId = 10;
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->targetDisplayId_ = 10;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.GetPidAndUpdateTarget(keyEvent));
    inputEvent->targetDisplayId_ = 18;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.GetPidAndUpdateTarget(keyEvent));
    WindowGroupInfo windowGroupInfo;
    WindowInfo windowInfo;
    windowInfo.id = 10;
    windowInfo.pid = 11;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    windowInfo.id = 10;
    windowInfo.pid = 11;
    windowInfo.agentWindowId = 12;
    windowGroupInfo.windowsInfo.push_back(windowInfo);
    inputWindowsManager.windowsPerDisplay_.insert(std::make_pair(10, windowGroupInfo));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.GetPidAndUpdateTarget(keyEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_IsNeedRefreshLayer_002
 * @tc.desc: Test the funcation IsNeedRefreshLayer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsNeedRefreshLayer_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t windowId = 1;
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->targetDisplayId_ = -11;
    bool ret = inputWindowsManager.IsNeedRefreshLayer(windowId);
    EXPECT_FALSE(ret);
    inputEvent->targetDisplayId_ = 11;
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_SelectWindowInfo_003
 * @tc.desc: Test the funcation SelectWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SelectWindowInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t logicalX = 200;
    int32_t logicalY = 200;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    inputWindowsManager.firstBtnDownWindowId_ = -1;
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_BUTTON_DOWN;
    PointerEvent::PointerItem pointerItem;
    pointerItem.targetWindowId_ = 0;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SelectWindowInfo(logicalX, logicalY, pointerEvent));
    pointerItem.targetWindowId_ = 2;
    WindowInfo windowInfo;
    windowInfo.flags = WindowInfo::FLAG_BIT_UNTOUCHABLE;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SelectWindowInfo(logicalX, logicalY, pointerEvent));
    windowInfo.flags = WindowInfo::FLAG_BIT_HANDWRITING;
    pointerEvent->HasFlag(InputEvent::EVENT_FLAG_SIMULATE);
    inputWindowsManager.extraData_.appended = true;
    inputWindowsManager.extraData_.sourceType = PointerEvent::SOURCE_TYPE_MOUSE;
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_UP;
    windowInfo.pointerHotAreas.push_back({ 150, 250, 300, 500 });
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SelectWindowInfo(logicalX, logicalY, pointerEvent));
    inputWindowsManager.extraData_.appended = false;
    inputWindowsManager.extraData_.sourceType = PointerEvent::SOURCE_TYPE_TOUCHSCREEN;
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_IN_WINDOW;
    pointerItem.targetWindowId_ = -2;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SelectWindowInfo(logicalX, logicalY, pointerEvent));
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_UP;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SelectWindowInfo(logicalX, logicalY, pointerEvent));
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_AXIS_BEGIN;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SelectWindowInfo(logicalX, logicalY, pointerEvent));
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_AXIS_UPDATE;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SelectWindowInfo(logicalX, logicalY, pointerEvent));
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SelectWindowInfo(logicalX, logicalY, pointerEvent));
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_AXIS_END;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SelectWindowInfo(logicalX, logicalY, pointerEvent));
    pointerItem.targetWindowId_ = 10;
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->targetDisplayId_ = 11;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SelectWindowInfo(logicalX, logicalY, pointerEvent));
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_BUTTON_DOWN;
    inputWindowsManager.firstBtnDownWindowId_ = 1;
    inputEvent->targetDisplayId_ = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.SelectWindowInfo(logicalX, logicalY, pointerEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateCrownTarget_001
 * @tc.desc: Test the funcation UpdateCrownTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateCrownTarget_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    std::shared_ptr<InputEvent> inputEvent = InputEvent::Create();
    EXPECT_NE(inputEvent, nullptr);
    inputEvent->targetDisplayId_ = -1;
    inputWindowsManager.displayGroupInfo_.focusWindowId = -1;
    int32_t ret = inputWindowsManager.UpdateCrownTarget(pointerEvent);
    EXPECT_NE(ret, RET_OK);
    inputEvent->targetDisplayId_ = 5;
    ret = inputWindowsManager.UpdateCrownTarget(pointerEvent);
    EXPECT_NE(ret, RET_OK);
    inputWindowsManager.displayGroupInfo_.focusWindowId = 5;
    ret = inputWindowsManager.UpdateCrownTarget(pointerEvent);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_PrintChangedWindowByEvent_001
 * @tc.desc: Test the funcation PrintChangedWindowByEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_PrintChangedWindowByEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWindowsManager;
    int32_t eventType = 1;
    WindowInfo newWindowInfo;
    newWindowInfo.id = 6;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 5;
    windowInfo.uid = 1;
    inputWindowsManager.lastMatchedWindow_.insert(std::make_pair(1, windowInfo));
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.PrintChangedWindowByEvent(eventType, newWindowInfo));
    eventType = 10;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.PrintChangedWindowByEvent(eventType, newWindowInfo));
    newWindowInfo.id = 1;
    EXPECT_NO_FATAL_FAILURE(inputWindowsManager.PrintChangedWindowByEvent(eventType, newWindowInfo));
}

/**
 * @tc.name: InputWindowsManagerTest_TransformDisplayXY_001
 * @tc.desc: Test the TransformDisplayXY function of the input window manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_TransformDisplayXY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo info;
    double logicX = 10.0;
    double logicY = 20.0;
    std::pair<double, double> result =WIN_MGR->TransformDisplayXY(info, logicX, logicY);
    double ret = result.first;
    EXPECT_EQ(ret, logicX);
    double ret1 = result.second;
    EXPECT_EQ(ret1, logicY);
}

/**
 * @tc.name: InputWindowsManagerTest_TransformDisplayXY_002
 * @tc.desc: Test the TransformDisplayXY function of the input window manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_TransformDisplayXY_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo info;
    std::vector<float> transform = { 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0};
    info.transform = transform;
    double logicX = 10.0;
    double logicY = 20.0;
    std::pair<double, double> result =WIN_MGR->TransformDisplayXY(info, logicX, logicY);
    double ret = result.first;
    EXPECT_EQ(ret, logicX);
    double ret1 = result.second;
    EXPECT_EQ(ret1, logicY);
}

/**
 * @tc.name: InputWindowsManagerTest_TransformDisplayXY_003
 * @tc.desc: Test the TransformDisplayXY function of the input window manager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_TransformDisplayXY_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo info;
    std::vector<float> transform = { 0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 315.0, 690.0, 1.0};
    info.transform = transform;
    double logicX = 10.0;
    double logicY = 20.0;
    std::pair<double, double> result =WIN_MGR->TransformDisplayXY(info, logicX, logicY);
    double ret = result.first;
    EXPECT_EQ(ret, 320);
    double ret1 = result.second;
    EXPECT_EQ(ret1, 700);
}

/**
 * @tc.name: InputWindowsManagerTest_IsValidNavigationWindow_001
 * @tc.desc: Test IsValidNavigationWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsValidNavigationWindow_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    double x = 10.0;
    double y = 20.0;
    Rect rect = {0, 0, 30, 40};
    windowInfo.defaultHotAreas.push_back(rect);
    EXPECT_TRUE(WIN_MGR->IsValidNavigationWindow(windowInfo, x, y));
}

/**
 * @tc.name: InputWindowsManagerTest_IsValidNavigationWindow_002
 * @tc.desc: Test IsValidNavigationWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsValidNavigationWindow_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.windowInputType = WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE;
    double x = 10.0;
    double y = 20.0;
    Rect rect = {0, 0, 30, 40};
    windowInfo.defaultHotAreas.push_back(rect);
    EXPECT_TRUE(WIN_MGR->IsValidNavigationWindow(windowInfo, x, y));
}

/**
 * @tc.name: InputWindowsManagerTest_IsValidNavigationWindow_003
 * @tc.desc: Test IsValidNavigationWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsValidNavigationWindow_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.windowInputType = WindowInputType::NORMAL;
    double x = 10.0;
    double y = 20.0;
    Rect rect = {0, 0, 30, 40};
    windowInfo.defaultHotAreas.push_back(rect);
    EXPECT_FALSE(WIN_MGR->IsValidNavigationWindow(windowInfo, x, y));
}

/**
 * @tc.name: InputWindowsManagerTest_IsValidNavigationWindow_004
 * @tc.desc: Test IsValidNavigationWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsValidNavigationWindow_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.windowInputType = WindowInputType::MIX_LEFT_RIGHT_ANTI_AXIS_MOVE;
    double x = -10.0;
    double y = 20.0;
    Rect rect = {0, 0, 30, 40};
    windowInfo.defaultHotAreas.push_back(rect);
    EXPECT_FALSE(WIN_MGR->IsValidNavigationWindow(windowInfo, x, y));
}

/**
 * @tc.name: InputWindowsManagerTest_IsValidNavigationWindow_005
 * @tc.desc: Test IsValidNavigationWindow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsValidNavigationWindow_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.windowInputType = WindowInputType::TRANSMIT_ALL;
    double x = 10.0;
    double y = -20.0;
    Rect rect = {0, 0, 30, 40};
    windowInfo.defaultHotAreas.push_back(rect);
    EXPECT_FALSE(WIN_MGR->IsValidNavigationWindow(windowInfo, x, y));
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTransformDisplayXY_001
 * @tc.desc: Test UpdateTransformDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTransformDisplayXY_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayXPos(10);
    item.SetDisplayYPos(20);
    pointerEvent->UpdatePointerItem(0, item);
    std::vector<WindowInfo> windowsInfo;
    DisplayInfo info;
    WIN_MGR->UpdateTransformDisplayXY(pointerEvent, windowsInfo, info);
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOG_DISPATCHE("Can't find pointer item, pointer:%{public}d", pointerId);
        return;
    }
    int32_t physicalX = pointerItem.GetDisplayX();
    int32_t physicalY = pointerItem.GetDisplayX();
    EXPECT_EQ(physicalX, 10);
    EXPECT_EQ(physicalY, 20);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTransformDisplayXY_002
 * @tc.desc: Test UpdateTransformDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTransformDisplayXY_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayXPos(10);
    item.SetDisplayYPos(20);
    pointerEvent->UpdatePointerItem(0, item);
    std::vector<WindowInfo> windowsInfo;
    WindowInfo windowInfo;
    DisplayInfo info;
    std::vector<float> transform = { 0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 315.0, 690.0, 1.0};
    info.transform = transform;
    windowInfo.windowInputType = WindowInputType::MIX_BUTTOM_ANTI_AXIS_MOVE;
    Rect rect = {0, 0, 30, 40};
    windowInfo.defaultHotAreas.push_back(rect);
    windowsInfo.push_back(windowInfo);
    WIN_MGR->UpdateTransformDisplayXY(pointerEvent, windowsInfo, info);
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOG_DISPATCHE("Can't find pointer item, pointer:%{public}d", pointerId);
        return;
    }
    int32_t physicalX = pointerItem.GetDisplayX();
    int32_t physicalY = pointerItem.GetDisplayX();
    EXPECT_EQ(physicalX, 10);
    EXPECT_EQ(physicalY, 20);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTransformDisplayXY_003
 * @tc.desc: Test UpdateTransformDisplayXY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTransformDisplayXY_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    EXPECT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(0);
    item.SetDisplayXPos(10);
    item.SetDisplayYPos(20);
    pointerEvent->UpdatePointerItem(0, item);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    std::vector<WindowInfo> windowsInfo;
    WindowInfo windowInfo;
    DisplayInfo info;
    std::vector<float> transform = { 0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 315.0, 690.0, 1.0};
    info.transform = transform;
    windowInfo.windowInputType = WindowInputType::TRANSMIT_ALL;
    Rect rect = {0, 0, 30, 40};
    windowInfo.defaultHotAreas.push_back(rect);
    windowsInfo.push_back(windowInfo);
    WIN_MGR->UpdateTransformDisplayXY(pointerEvent, windowsInfo, info);
    int32_t pointerId = pointerEvent->GetPointerId();
    PointerEvent::PointerItem pointerItem;
    if (!pointerEvent->GetPointerItem(pointerId, pointerItem)) {
        MMI_HILOG_DISPATCHE("Can't find pointer item, pointer:%{public}d", pointerId);
        return;
    }
    int32_t physicalX = pointerItem.GetDisplayX();
    int32_t physicalY = pointerItem.GetDisplayX();
    EXPECT_EQ(physicalX, 320);
    EXPECT_EQ(physicalY, 700);
}

/**
 * @tc.name: InputWindowsManagerTest_GetUIExtentionWindowInfo
 * @tc.desc: Test the funcation GetUIExtentionWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetUIExtentionWindowInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWinMgr;
    WindowInfo windowInfo;
    windowInfo.id = 5;
    std::vector<WindowInfo> uiExtentionWindowInfo;
    int32_t windowId = 10;
    WindowInfo *touchWindow;
    bool isUiExtentionWindow = false;
    uiExtentionWindowInfo.push_back(windowInfo);
    windowInfo.id = 10;
    uiExtentionWindowInfo.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(inputWinMgr.GetUIExtentionWindowInfo(uiExtentionWindowInfo, windowId,
        &touchWindow, isUiExtentionWindow));
}

/**
 * @tc.name: InputWindowsManagerTest_CheckUIExtentionWindowDefaultHotArea
 * @tc.desc: Test the funcation CheckUIExtentionWindowDefaultHotArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CheckUIExtentionWindowDefaultHotArea, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWinMgr;
    int32_t logicalX = 150;
    int32_t logicalY = 150;
    std::vector<WindowInfo> windowInfos;
    int32_t winId = 10;
    WindowInfo windowInfo;
    Rect rect;
    rect.x = INT32_MAX;
    rect.width = 100;
    windowInfo.defaultHotAreas.push_back(rect);
    windowInfos.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(inputWinMgr.CheckUIExtentionWindowDefaultHotArea(logicalX, logicalY, windowInfos, winId));
}

/**
 * @tc.name: InputWindowsManagerTest_CheckUIExtentionWindowDefaultHotArea_001
 * @tc.desc: Test the funcation CheckUIExtentionWindowDefaultHotArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CheckUIExtentionWindowDefaultHotArea_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWinMgr;
    int32_t logicalX = 150;
    int32_t logicalY = 150;
    std::vector<WindowInfo> windowInfos;
    int32_t winId = 10;
    WindowInfo windowInfo;
    Rect rect;
    rect.x = 100;
    rect.y = 100;
    rect.width = 200;
    rect.height = 200;
    windowInfo.defaultHotAreas.push_back(rect);
    windowInfos.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(inputWinMgr.CheckUIExtentionWindowDefaultHotArea(logicalX, logicalY, windowInfos, winId));
}

/**
 * @tc.name: InputWindowsManagerTest_IsKeyPressed
 * @tc.desc: Test the funcation IsKeyPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsKeyPressed, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWinMgr;
    KeyEvent::KeyItem item;
    int32_t pressedKey = 2024;
    std::vector<KeyEvent::KeyItem> keyItems;
    item.SetKeyCode(2018);
    item.SetPressed(false);
    keyItems.push_back(item);
    EXPECT_FALSE(inputWinMgr.IsKeyPressed(pressedKey, keyItems));
}

/**
 * @tc.name: InputWindowsManagerTest_IsKeyPressed_001
 * @tc.desc: Test the funcation IsKeyPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsKeyPressed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWinMgr;
    KeyEvent::KeyItem item;
    int32_t pressedKey = 2024;
    std::vector<KeyEvent::KeyItem> keyItems;
    item.SetKeyCode(2024);
    item.SetPressed(true);
    keyItems.push_back(item);
    EXPECT_TRUE(inputWinMgr.IsKeyPressed(pressedKey, keyItems));
}

/**
 * @tc.name: InputWindowsManagerTest_IsOnTheWhitelist
 * @tc.desc: Test the funcation IsOnTheWhitelist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsOnTheWhitelist, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputWinMgr;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    KeyEvent::KeyItem item;
    SwitchFocusKey switchFocusKey;
    switchFocusKey.keyCode = 2024;
    switchFocusKey.pressedKey = -1;
    inputWinMgr.vecWhiteList_.push_back(switchFocusKey);
    keyEvent->SetKeyCode(2024);
    item.SetPressed(true);
    item.SetKeyCode(2024);
    keyEvent->AddKeyItem(item);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    EXPECT_TRUE(inputWinMgr.IsOnTheWhitelist(keyEvent));

    inputWinMgr.vecWhiteList_[0].pressedKey = 2024;
    keyEvent->AddKeyItem(item);
    EXPECT_TRUE(inputWinMgr.IsOnTheWhitelist(keyEvent));

    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_UP);
    EXPECT_FALSE(inputWinMgr.IsOnTheWhitelist(keyEvent));

    keyEvent->SetKeyCode(2018);
    EXPECT_FALSE(inputWinMgr.IsOnTheWhitelist(keyEvent));
}

/**
 * @tc.name: InputWindowsManagerTest_IsOnTheWhitelist_001
 * @tc.desc: Test IsOnTheWhitelist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsOnTheWhitelist_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WIN_MGR->vecWhiteList_ = {{1}, {2}, {3}};
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(4);
    bool ret = WIN_MGR->IsOnTheWhitelist(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_IsOnTheWhitelist_002
 * @tc.desc: Test IsOnTheWhitelist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsOnTheWhitelist_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputManager;
    SwitchFocusKey whitelistItem;
    whitelistItem.keyCode = 1;
    whitelistItem.pressedKey = -1;
    inputManager.vecWhiteList_.push_back(whitelistItem);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(1);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    KeyEvent::KeyItem item;
    item.SetKeyCode(KeyEvent::KEYCODE_HOME);
    keyEvent->AddKeyItem(item);
    bool ret = inputManager.IsOnTheWhitelist(keyEvent);
    ASSERT_TRUE(ret);
    whitelistItem.pressedKey = 2;
    ret = inputManager.IsOnTheWhitelist(keyEvent);
    ASSERT_TRUE(ret);
    whitelistItem.pressedKey = -1;
    item.SetDeviceId(100);
    item.SetKeyCode(KeyEvent::KEYCODE_PAGE_DOWN);
    item.SetDownTime(100);
    keyEvent->AddKeyItem(item);
    ret = inputManager.IsOnTheWhitelist(keyEvent);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_IsOnTheWhitelist_003
 * @tc.desc: Test IsOnTheWhitelist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsOnTheWhitelist_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager inputManager;
    SwitchFocusKey whitelistItem;
    whitelistItem.keyCode = 1;
    whitelistItem.pressedKey = 1;
    inputManager.vecWhiteList_.push_back(whitelistItem);
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(1);
    keyEvent->SetKeyAction(KeyEvent::KEY_ACTION_DOWN);
    KeyEvent::KeyItem item;
    item.SetDeviceId(100);
    item.SetDownTime(100);
    keyEvent->AddKeyItem(item);
    item.pressed_ = true;
    bool ret = WIN_MGR->IsOnTheWhitelist(keyEvent);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_IsKeyPressed_002
 * @tc.desc: Test IsKeyPressed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_IsKeyPressed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    KeyEvent::KeyItem item;
    item.SetKeyCode(1);
    std::vector<KeyEvent::KeyItem> keyItems;
    keyItems.push_back(item);
    bool ret = WIN_MGR->IsKeyPressed(1, keyItems);
    ASSERT_FALSE(ret);
    ret = WIN_MGR->IsKeyPressed(2, keyItems);
    ASSERT_FALSE(ret);
    item.pressed_ = true;
    keyItems.push_back(item);
    ret = WIN_MGR->IsKeyPressed(1, keyItems);
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: InputWindowsManagerTest_CheckUIExtentionWindowPointerHotArea_001
 * @tc.desc: Test CheckUIExtentionWindowPointerHotArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CheckUIExtentionWindowPointerHotArea_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.windowType = 2105;
    windowInfo.area.x = 10;
    windowInfo.area.y = 80;
    windowInfo.area.height = 90;
    std::vector<WindowInfo> windows;
    windows.push_back(windowInfo);
    int32_t windowId = 1;
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->CheckUIExtentionWindowPointerHotArea(15, 20, windows, windowId));
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->CheckUIExtentionWindowPointerHotArea(100, 200, windows, windowId));
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->CheckUIExtentionWindowPointerHotArea(100, 200, {}, windowId));
}

/**
 * @tc.name: InputWindowsManagerTest_GetUIExtentionWindowInfo_001
 * @tc.desc: Test GetUIExtentionWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetUIExtentionWindowInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager manager;
    std::vector<WindowInfo> windows = {{1}, {2}, {3}};
    WindowInfo *touchWindow = nullptr;
    bool isUiExtentionWindow = false;
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->GetUIExtentionWindowInfo(windows, 2, &touchWindow, isUiExtentionWindow));
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->GetUIExtentionWindowInfo(windows, 4, &touchWindow, isUiExtentionWindow));
    std::vector<WindowInfo> emptyWindows;
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->GetUIExtentionWindowInfo(emptyWindows, 1, &touchWindow, isUiExtentionWindow));
}

/**
 * @tc.name: InputWindowsManagerTest_CheckUIExtentionWindowDefaultHotArea_002
 * @tc.desc: Test CheckUIExtentionWindowDefaultHotArea
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_CheckUIExtentionWindowDefaultHotArea_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputWindowsManager manager;
    int32_t windowId;
    WindowInfo windowInfo;
    windowInfo.windowType = 2105;
    windowInfo.area.x = 10;
    windowInfo.area.y = 100;
    windowInfo.area.height = 200;
    std::vector<WindowInfo> windows;
    windows.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->CheckUIExtentionWindowDefaultHotArea(15, 25, windows, windowId));
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->CheckUIExtentionWindowDefaultHotArea(300, 300, windows, windowId));
    EXPECT_NO_FATAL_FAILURE(WIN_MGR->CheckUIExtentionWindowDefaultHotArea(15, 25, {}, windowId));
}
} // namespace MMI
} // namespace OHOS
