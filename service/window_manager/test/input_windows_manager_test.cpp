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

#include "input_windows_manager.h"
#include "i_pointer_drawing_manager.h"
#include "fingersense_wrapper.h"
#include "mmi_log.h"
#include "proto.h"
#include "scene_board_judgement.h"
#include "struct_multimodal.h"
#include "uds_server.h"
#include "window_info.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputWindowsManagerTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputWindowsManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
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
        WinMgr->UpdateDisplayInfo(displayGroupInfo);
        preHoverScrollState_ = WinMgr->GetHoverScrollState();
    } // void SetUp(void)

    void TearDown(void)
    {
        WinMgr->SetHoverScrollState(preHoverScrollState_);
    }

private:
    bool preHoverScrollState_ { true };
};

void FingersenseWrapperTest(int32_t num) {}

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
    WinMgr->Init(udsServer);
    WinMgr->GetDisplayGroupInfo();
    int32_t idNames = -1;
    ASSERT_EQ(WinMgr->GetClientFd(pointerEvent), idNames);
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
    WinMgr->Init(udsServer);
    auto keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetDeviceId(1);
    keyEvent->SetTargetWindowId(1);
    keyEvent->SetAgentWindowId(1);
    ASSERT_EQ(WinMgr->UpdateTarget(keyEvent), -1);
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
    WinMgr->UpdateWindowInfo({0, 11, {window}});
    ASSERT_EQ(WinMgr->GetWindowPid(11), -1);
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
    WinMgr->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_EQ(WinMgr->UpdateTargetPointer(pointerEvent), -1);
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
    WinMgr->Init(udsServer);
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        ASSERT_EQ(WinMgr->IsNeedRefreshLayer(-1), true);
        ASSERT_EQ(WinMgr->IsNeedRefreshLayer(0), true);
        ASSERT_EQ(WinMgr->IsNeedRefreshLayer(1), true);
    } else {
        ASSERT_EQ(WinMgr->IsNeedRefreshLayer(-1), false);
        ASSERT_EQ(WinMgr->IsNeedRefreshLayer(0), false);
        ASSERT_EQ(WinMgr->IsNeedRefreshLayer(1), false);
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
    WinMgr->Init(udsServer);
    bool isCaptureMode = false;
    ASSERT_EQ(WinMgr->SetMouseCaptureMode(-1, isCaptureMode), -1);
    ASSERT_EQ(WinMgr->SetMouseCaptureMode(1, isCaptureMode), 0);
    isCaptureMode = true;
    ASSERT_EQ(WinMgr->SetMouseCaptureMode(1, isCaptureMode), 0);
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
    WinMgr->Init(udsServer);
    std::string sysUid = "james";
    std::string devStatus = "add";
    WinMgr->DeviceStatusChanged(2, sysUid, devStatus);
    devStatus = "remove";
    WinMgr->DeviceStatusChanged(2, sysUid, devStatus);
    std::string msg = "There is in InputWindowsManagerTest_GetDisplayIdNames_009";
    ASSERT_EQ(WinMgr->SetDisplayBind(-1, 1, msg), -1);
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
    ASSERT_TRUE(WinMgr->SetHoverScrollState(false) == RET_OK);
    WinMgr->SetHoverScrollState(true);
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
    WinMgr->SetHoverScrollState(true);
    ASSERT_TRUE(WinMgr->GetHoverScrollState());
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
    WinMgr->InitMouseDownInfo();
    EXPECT_EQ(WinMgr->mouseDownInfo_.id, -1);
    EXPECT_EQ(WinMgr->mouseDownInfo_.pid, -1);
    EXPECT_TRUE(WinMgr->mouseDownInfo_.defaultHotAreas.empty());
    EXPECT_TRUE(WinMgr->mouseDownInfo_.pointerHotAreas.empty());
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
    WinMgr->mouseDownInfo_.id = 1;
    WinMgr->mouseDownInfo_.pid = 123;
    WinMgr->mouseDownInfo_.defaultHotAreas.push_back({0, 0, 100, 100});
    WinMgr->InitMouseDownInfo();
    EXPECT_EQ(WinMgr->mouseDownInfo_.id, -1);
    EXPECT_EQ(WinMgr->mouseDownInfo_.pid, -1);
    EXPECT_TRUE(WinMgr->mouseDownInfo_.defaultHotAreas.empty());
    EXPECT_TRUE(WinMgr->mouseDownInfo_.pointerHotAreas.empty());
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
    const std::vector<WindowInfo>& windowGroupInfo = WinMgr->GetWindowGroupInfoByDisplayId(displayId);
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
    const std::vector<WindowInfo>& windowGroupInfo = WinMgr->GetWindowGroupInfoByDisplayId(displayId);
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
    int32_t ret = WinMgr->GetDisplayId(inputEvent);
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
    int32_t ret = WinMgr->GetPidAndUpdateTarget(keyEvent);
    EXPECT_EQ(ret, 1);
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
    int32_t ret = WinMgr->GetWindowPid(windowId,  windowsInfo);
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
    ASSERT_NO_FATAL_FAILURE(WinMgr->CheckFocusWindowChange(displayGroupInfo));
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
    ASSERT_NO_FATAL_FAILURE(WinMgr->CheckFocusWindowChange(displayGroupInfo));
    ASSERT_NO_FATAL_FAILURE(WinMgr->CheckFocusWindowChange(displayGroupInfo_));
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
    ASSERT_NO_FATAL_FAILURE(WinMgr->CheckZorderWindowChange(oldWindowsInfo, newWindowsInfo));
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
    ASSERT_NO_FATAL_FAILURE(WinMgr->UpdateDisplayIdAndName());
    assert(WinMgr->GetDisplayIdNames().size() == 2);
    assert(WinMgr->IsDisplayAdd(1, "A"));
    assert(WinMgr->IsDisplayAdd(2, "B"));
    ASSERT_NO_FATAL_FAILURE(WinMgr->UpdateDisplayIdAndName());
    assert(WinMgr->GetDisplayIdNames().size() == 2);
    assert(WinMgr->IsDisplayAdd(1, "A"));
    assert(WinMgr->IsDisplayAdd(3, "C"));
    assert(!WinMgr->IsDisplayAdd(2, "B"));
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
    int32_t ret = WinMgr->SetDisplayBind(deviceId, displayId, msg);
    EXPECT_EQ(ret, -1);
    ret = WinMgr->GetDisplayBindInfo(infos);
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
    WinMgr->UpdateCaptureMode(displayGroupInfo);
    EXPECT_FALSE(WinMgr->captureModeInfo_.isCaptureMode);
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
    WinMgr->UpdateDisplayInfoByIncrementalInfo(window, displayGroupInfo);
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
    WinMgr->UpdateWindowsInfoPerDisplay(displayGroupInfo);
    WindowInfo window1{1};
    WindowInfo window2{2};
    displayGroupInfo.windowsInfo.push_back(window1);
    displayGroupInfo.windowsInfo.push_back(window2);
    WinMgr->UpdateDisplayInfo(displayGroupInfo);
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
    ASSERT_NO_FATAL_FAILURE(WinMgr->UpdateDisplayInfo(displayGroupInfo));
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
    EXPECT_FALSE(WinMgr->NeedUpdatePointDrawFlag(windows1));
    std::vector<WindowInfo> windows2;
    windows2.push_back(WindowInfo());
    windows2.back().action = OHOS::MMI::WINDOW_UPDATE_ACTION::ADD;
    EXPECT_FALSE(WinMgr->NeedUpdatePointDrawFlag(windows2));
    std::vector<WindowInfo> windows3;
    windows3.push_back(WindowInfo());
    windows3.back().action = OHOS::MMI::WINDOW_UPDATE_ACTION::ADD_END;
    EXPECT_TRUE(WinMgr->NeedUpdatePointDrawFlag(windows3));
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
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::SOUTH_EAST);
    area = WindowArea::TOP_RIGHT_LIMIT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::SOUTH_WEST);
    area = WindowArea::TOP_LIMIT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::SOUTH);
    area = WindowArea::LEFT_LIMIT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::EAST);
    area = WindowArea::RIGHT_LIMIT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::WEST);
    area = WindowArea::BOTTOM_LEFT_LIMIT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_WEST);
    area = WindowArea::BOTTOM_LIMIT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_WEST);
    area = WindowArea::BOTTOM_RIGHT_LIMIT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_WEST);
    area = WindowArea::FOCUS_ON_INNER;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
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
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::SOUTH);
    area = WindowArea::EXIT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::SOUTH);
    area = WindowArea::FOCUS_ON_TOP_LEFT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_WEST_SOUTH_EAST);
    area = WindowArea::FOCUS_ON_BOTTOM_RIGHT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_WEST_SOUTH_EAST);
    area = WindowArea::FOCUS_ON_TOP_RIGHT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_EAST_SOUTH_WEST);
    area = WindowArea::FOCUS_ON_BOTTOM_LEFT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_EAST_SOUTH_WEST);
    area = WindowArea::FOCUS_ON_TOP;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_SOUTH);
    area = WindowArea::FOCUS_ON_BOTTOM;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::NORTH_SOUTH);
    area = WindowArea::FOCUS_ON_LEFT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
    EXPECT_EQ(pointerStyle.id, MOUSE_ICON::WEST_EAST);
    area = WindowArea::FOCUS_ON_RIGHT;
    WinMgr->GetPointerStyleByArea(area, pid, winId, pointerStyle);
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
    WinMgr->SetWindowPointerStyle(area, pid, windowId);
    assert(lastPointerStyle_.id == pointerStyle.id);
    assert(windowId != GLOBAL_WINDOW_ID && (pointerStyle.id == MOUSE_ICON::DEFAULT &&
        mouseIcons[MOUSE_ICON(pointerStyle.id)].iconPath != defaultIconPath));
    assert(WinMgr->GetPointerStyle(pid, GLOBAL_WINDOW_ID, style) == RET_OK);
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
    IPointerDrawingManager::GetInstance()->SetPointerVisible(pid, visible, 0);
    ASSERT_NO_FATAL_FAILURE(WinMgr->UpdateWindowPointerVisible(pid));
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
    ASSERT_NO_FATAL_FAILURE(WinMgr->DispatchPointer(pointerAction));
    pointerAction = PointerEvent::POINTER_ACTION_LEAVE_WINDOW;
    ASSERT_NO_FATAL_FAILURE(WinMgr->DispatchPointer(pointerAction));
    pointerAction = PointerEvent::POINTER_ACTION_MOVE;
    ASSERT_NO_FATAL_FAILURE(WinMgr->DispatchPointer(pointerAction));
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
    ASSERT_NO_FATAL_FAILURE(WinMgr->PrintWindowInfo(windowsInfo));
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
    ASSERT_NO_FATAL_FAILURE(WinMgr->PrintWindowGroupInfo(testData));
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
    ASSERT_NO_FATAL_FAILURE(WinMgr->PrintDisplayInfo());
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
    const DisplayInfo* displayInfo = WinMgr->GetPhysicalDisplay(id);
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
    const DisplayInfo* displayInfo = WinMgr->GetPhysicalDisplay(id);
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
    WinMgr->RotateScreen(info, coord);
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
    WinMgr->RotateScreen(info, coord);
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
    WinMgr->RotateScreen(info, coord);
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
    WinMgr->RotateScreen(info, coord);
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
    EXPECT_FALSE(WinMgr->IsNeedRefreshLayer(1));
    WinMgr->GetWindowInfo(0, 0)->id = 2;
    EXPECT_FALSE(WinMgr->IsNeedRefreshLayer(GLOBAL_WINDOW_ID));
    WinMgr->GetWindowInfo(0, 0)->id = 3;
    EXPECT_FALSE(WinMgr->IsNeedRefreshLayer(1));
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
    WinMgr->OnSessionLost(session);
    DisplayGroupInfo actualInfo = WinMgr->GetDisplayGroupInfo();
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
    int32_t ret = WinMgr->UpdatePoinerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, 401);
    pid = -1;
    windowId = -2;
    ret = WinMgr->UpdatePoinerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, 401);
    pid = 1;
    windowId = -2;
    ret = WinMgr->UpdatePoinerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, 401);
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
    int32_t ret = WinMgr->UpdateSceneBoardPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, RET_OK);
    pid = -1;
    windowId = -2;
    ret = WinMgr->UpdateSceneBoardPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputWindowsManagerTest_SetGlobalDefaultPointerStyle_001
 * @tc.desc: Test setting global default pointer style
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetGlobalDefaultPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WinMgr->SetGlobalDefaultPointerStyle();
    for (auto &iter : WinMgr->pointerStyle_) {
        for (auto &item : iter.second) {
            EXPECT_NE(item.second.id, WinMgr->globalStyle_.id);
        }
    }
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
    int32_t ret = WinMgr->SetPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(WinMgr->globalStyle_.id, pointerStyle.id);
    pid = 1;
    windowId = 2;
    ret = WinMgr->SetPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, WinMgr->UpdatePoinerStyle(pid, windowId, pointerStyle));
    pid = 1;
    windowId = 2;
    ret = WinMgr->SetPointerStyle(pid, windowId, pointerStyle);
    EXPECT_EQ(ret, WinMgr->UpdateSceneBoardPointerStyle(pid, windowId, pointerStyle));
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
    int32_t ret = WinMgr->ClearWindowPointerStyle(pid, windowId);
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
    int32_t ret = WinMgr->GetPointerStyle(1, GLOBAL_WINDOW_ID, style);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(style.id, 1);
    ret = WinMgr->GetPointerStyle(3, 1, style);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_EQ(style.id, 1);
    ret = WinMgr->GetPointerStyle(1, 1, style);
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
    WinMgr->InitPointerStyle();
    int32_t x = 10;
    int32_t y = 20;
    std::vector<Rect> rects = {{0, 0, 30, 40}};
    WindowInfo window;
    bool ret = WinMgr->IsInHotArea(x, y, rects, window);
    EXPECT_TRUE(ret);
    x = -10;
    y = 20;
    ret = WinMgr->IsInHotArea(x, y, rects, window);
    EXPECT_FALSE(ret);
    x = 10;
    y = -10;
    ret = WinMgr->IsInHotArea(x, y, rects, window);
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
    WinMgr->InWhichHotArea(x, y, rects, pointerStyle);
    ASSERT_EQ(pointerStyle.id, 6);
    x = 250;
    y = 250;
    WinMgr->InWhichHotArea(x, y, rects, pointerStyle);
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
    WinMgr->AdjustDisplayCoordinate(displayInfo, physicalX, physicalY);
    EXPECT_EQ(physicalX, 0);
    EXPECT_EQ(physicalY, 9);
    displayInfo.width = 10;
    displayInfo.height = 20;
    displayInfo.direction = DIRECTION270;
    physicalX = 15;
    physicalY = 25;
    WinMgr->AdjustDisplayCoordinate(displayInfo, physicalX, physicalY);
    EXPECT_EQ(physicalX, 15);
    EXPECT_EQ(physicalY, 9);
    displayInfo.width = 10;
    displayInfo.height = 20;
    displayInfo.direction = DIRECTION270;
    physicalX = -5;
    physicalY = -15;
    WinMgr->AdjustDisplayCoordinate(displayInfo, physicalX, physicalY);
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
    bool result = WinMgr->IsTransparentWin(pixelMap, logicalX, logicalY);
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
    int32_t result = WinMgr->CheckWindowIdPermissionByPid(windowId, pid);
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
    bool result = WinMgr->IsWindowVisible(pid);
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
    WinMgr->CoordinateCorrection(width, height, integerX, integerY);
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
    WinMgr->CoordinateCorrection(width, height, integerX, integerY);
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
    WinMgr->CoordinateCorrection(width, height, integerX, integerY);
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
    WinMgr->CoordinateCorrection(width, height, integerX, integerY);
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
    WinMgr->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::NORMAL;
    ASSERT_FALSE(WinMgr->HandleWindowInputType(window, pointerEvent));
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
    WinMgr->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::TRANSMIT_ALL;
    ASSERT_TRUE(WinMgr->HandleWindowInputType(window, pointerEvent));
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
    WinMgr->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::ANTI_MISTAKE_TOUCH;
    ASSERT_TRUE(WinMgr->HandleWindowInputType(window, pointerEvent));
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
    bool ret = WinMgr->UpdateDisplayId(displayId);
    EXPECT_TRUE(ret);
    displayId = 0;
    ret = WinMgr->UpdateDisplayId(displayId);
    EXPECT_FALSE(ret);
    displayId = -1;
    ret = WinMgr->UpdateDisplayId(displayId);
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
    std::optional<WindowInfo> result = WinMgr->SelectWindowInfo(400, 300, pointerEvent);
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
    std::optional<WindowInfo> result = WinMgr->SelectWindowInfo(-123, -456, pointerEvent);
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
    WinMgr->displayGroupInfo_.windowsInfo = {windowInfo1, windowInfo2};
    auto result = WinMgr->GetWindowInfo(0, 0);
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
    bool result = WinMgr->SelectPointerChangeArea(windowInfo, pointerStyle, logicalX, logicalY);
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
    bool result = WinMgr->SelectPointerChangeArea(windowInfo, pointerStyle, logicalX, logicalY);
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
    WinMgr->UpdatePointerChangeAreas(displayGroupInfo);
    EXPECT_TRUE(WinMgr->windowsHotAreas_.empty());
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
    WinMgr->UpdatePointerChangeAreas();
    WinMgr->UpdatePointerChangeAreas(displayGroupInfo);
    EXPECT_EQ(WinMgr->windowsHotAreas_.size(), 1);
    EXPECT_EQ(WinMgr->windowsHotAreas_[1].size(), 8);
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
    WinMgr->UpdateTopBottomArea(windowArea, pointerChangeAreas, windowHotAreas);
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
    WinMgr->UpdateTopBottomArea(windowArea, pointerChangeAreas, windowHotAreas);
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
    WinMgr->UpdateLeftRightArea(windowArea, pointerChangeAreas, windowHotAreas);
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
    WinMgr->UpdateLeftRightArea(windowArea, pointerChangeAreas, windowHotAreas);
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
    WinMgr->UpdateInnerAngleArea(windowArea, pointerChangeAreas, windowHotAreas);
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
    EXPECT_EQ(ret12, 32);
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
    WinMgr->UpdatePointerEvent(logicalX, logicalY, pointerEvent, touchWindow);
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
    WinMgr->UpdatePointerEvent(logicalX, logicalY, pointerEvent, touchWindow);
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
    int32_t result = WinMgr->SetHoverScrollState(true);
    EXPECT_EQ(result, 0);
    result = WinMgr->SetHoverScrollState(false);
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
    bool result = WinMgr->GetHoverScrollState();
    EXPECT_TRUE(result);
    result = WinMgr->GetHoverScrollState();
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
    int32_t result =WinMgr->UpdateMouseTarget(pointerEvent);
    WinMgr->SetMouseFlag(true);
    WinMgr->SetMouseFlag(false);
    auto ret = WinMgr->GetMouseFlag();
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
    ASSERT_FALSE(WinMgr->SkipNavigationWindow(WindowInputType::ANTI_MISTAKE_TOUCH, PointerEvent::TOOL_TYPE_PEN));
}

/**
 * @tc.name: InputWindowsManagerTest_SkipNavigationWindow_002
 * @tc.desc: Test updating window information for each display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SkipNavigationWindow_002, TestSize.Level1)
{
    ASSERT_FALSE(WinMgr->SkipNavigationWindow(WindowInputType::NORMAL, PointerEvent::TOOL_TYPE_RUBBER));
}

/**
 * @tc.name: InputWindowsManagerTest_SkipNavigationWindow_003
 * @tc.desc: Test updating window information for each display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SkipNavigationWindow_003, TestSize.Level1)
{
    ASSERT_FALSE(WinMgr->SkipNavigationWindow(WindowInputType::NORMAL, PointerEvent::TOOL_TYPE_PEN));
}

/**
 * @tc.name: InputWindowsManagerTest_SkipNavigationWindow_004
 * @tc.desc: Test updating window information for each display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SkipNavigationWindow_004, TestSize.Level1)
{
    ASSERT_FALSE(WinMgr->SkipNavigationWindow(WindowInputType::ANTI_MISTAKE_TOUCH, PointerEvent::TOOL_TYPE_RUBBER));
}

/**
 * @tc.name: InputWindowsManagerTest_SkipNavigationWindow_005
 * @tc.desc: Test updating window information for each display
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SkipNavigationWindow_005, TestSize.Level1)
{
    WinMgr->SetAntiMisTake(true);
    ASSERT_TRUE(WinMgr->SkipNavigationWindow(WindowInputType::ANTI_MISTAKE_TOUCH, PointerEvent::TOOL_TYPE_PEN));
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
    WinMgr->JudgMouseIsDownOrUp(false);
    EXPECT_FALSE(WinMgr->GetMouseFlag());
    WinMgr->JudgMouseIsDownOrUp(true);
    EXPECT_FALSE(WinMgr->GetMouseFlag());
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
    int32_t result = WinMgr->SetMouseCaptureMode(windowId, isCaptureMode);
    EXPECT_EQ(result, RET_ERR);
    windowId = 1;
    isCaptureMode = false;
    result = WinMgr->SetMouseCaptureMode(windowId, isCaptureMode);
    EXPECT_EQ(result, RET_OK);
    windowId = 1;
    isCaptureMode = true;
    result = WinMgr->SetMouseCaptureMode(windowId, isCaptureMode);
    EXPECT_EQ(result, RET_OK);
    EXPECT_TRUE(WinMgr->GetMouseIsCaptureMode());
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
    bool result = WinMgr->IsNeedDrawPointer(pointerItem);
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
    bool result = WinMgr->SkipAnnotationWindow(flag, toolType);
    EXPECT_TRUE(result);
    flag = WindowInfo::FLAG_BIT_HANDWRITING;
    toolType = PointerEvent::TOOL_TYPE_PEN;
    result = WinMgr->SkipAnnotationWindow(flag, toolType);
    EXPECT_FALSE(result);
    flag = 0;
    toolType = PointerEvent::TOOL_TYPE_FINGER;
    result = WinMgr->SkipAnnotationWindow(flag, toolType);
    EXPECT_FALSE(result);
    flag = 0;
    toolType = PointerEvent::TOOL_TYPE_PEN;
    result = WinMgr->SkipAnnotationWindow(flag, toolType);
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
    auto result = WinMgr->UpdateTouchScreenTarget(nullptr);
    EXPECT_NE(result, RET_ERR);
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetTargetDisplayId(-1);
    result = WinMgr->UpdateTouchScreenTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetTargetDisplayId(1);
    pointerEvent->SetPointerId(1);
    result = WinMgr->UpdateTouchScreenTarget(pointerEvent);
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
    WinMgr->PullEnterLeaveEvent(logicalX, logicalY, pointerEvent, &touchWindow);
    logicalX = -123;
    logicalY = -456;
    WinMgr->PullEnterLeaveEvent(logicalX, logicalY, pointerEvent, &touchWindow);
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
    WinMgr->DispatchTouch(pointerAction);
    pointerAction = PointerEvent::POINTER_ACTION_DOWN;
    WinMgr->DispatchTouch(pointerAction);
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
    int32_t result = WinMgr->UpdateTouchPadTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    result = WinMgr->UpdateTouchPadTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    result = WinMgr->UpdateTouchPadTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    result = WinMgr->UpdateTouchPadTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    result = WinMgr->UpdateTouchPadTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetPointerAction(9999);
    result = WinMgr->UpdateTouchPadTarget(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: InputWindowsManagerTest_DrawTouchGraphic_001
 * @tc.desc: This test verifies the functionality of drawing touch graphics
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_DrawTouchGraphic_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    WinMgr->DrawTouchGraphic(pointerEvent);
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
    int32_t result = WinMgr->UpdateTargetPointer(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_MOUSE);
    pointerEvent->SetPointerAction(1);
    result = WinMgr->UpdateTargetPointer(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHPAD);
    pointerEvent->SetPointerAction(1);
    result = WinMgr->UpdateTargetPointer(pointerEvent);
    EXPECT_EQ(result, RET_ERR);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_JOYSTICK);
    pointerEvent->SetPointerAction(1);
    result = WinMgr->UpdateTargetPointer(pointerEvent);
    EXPECT_EQ(result, RET_OK);
    pointerEvent->SetSourceType(999);
    pointerEvent->SetPointerAction(1);
    result = WinMgr->UpdateTargetPointer(pointerEvent);
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
    bool result = WinMgr->IsInsideDisplay(displayInfo, physicalX, physicalY);
    EXPECT_TRUE(result);
    physicalX = -10;
    physicalY = 500;
    result = WinMgr->IsInsideDisplay(displayInfo, physicalX, physicalY);
    EXPECT_FALSE(result);
    physicalX = 500;
    physicalY = -10;
    result = WinMgr->IsInsideDisplay(displayInfo, physicalX, physicalY);
    EXPECT_FALSE(result);
    physicalX = -500;
    physicalY = -10;
    result = WinMgr->IsInsideDisplay(displayInfo, physicalX, physicalY);
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
    WinMgr->FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId);
    EXPECT_EQ(physicalX, RET_OK);
    EXPECT_EQ(physicalY, RET_OK);
    EXPECT_EQ(displayId, RET_OK);
    displayInfo.x = INT32_MAX;
    displayInfo.y = INT32_MAX;
    WinMgr->FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId);
    EXPECT_EQ(physicalX, RET_OK);
    EXPECT_EQ(physicalY, RET_OK);
    EXPECT_EQ(displayId, RET_OK);
    displayInfo.x = 50;
    displayInfo.y = 60;
    WinMgr->FindPhysicalDisplay(displayInfo, physicalX, physicalY, displayId);
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
    WinMgr->GetWidthAndHeight(&displayInfo, width, height);
    EXPECT_EQ(width, RET_OK);
    EXPECT_EQ(height, RET_OK);
    displayInfo.direction = DIRECTION90;
    WinMgr->GetWidthAndHeight(&displayInfo, width, height);
    EXPECT_EQ(width, RET_OK);
    EXPECT_EQ(height, RET_OK);
    displayInfo.displayDirection = DIRECTION180;
    displayInfo.direction = DIRECTION0;
    WinMgr->GetWidthAndHeight(&displayInfo, width, height);
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
    WinMgr->ReverseRotateScreen(info, 100.0, 200.0, cursorPos);
    EXPECT_EQ(cursorPos.x, 100);
    EXPECT_EQ(cursorPos.y, 200);
    info.direction = DIRECTION90;
    WinMgr->ReverseRotateScreen(info, 100.0, 200.0, cursorPos);;
    EXPECT_EQ(cursorPos.x, 200);
    EXPECT_EQ(cursorPos.y, 1820);
    info.direction = DIRECTION180;
    WinMgr->ReverseRotateScreen(info, 100.0, 200.0, cursorPos);
    EXPECT_EQ(cursorPos.x, 1820);
    EXPECT_EQ(cursorPos.y, 880);
    info.direction = DIRECTION270;
    WinMgr->ReverseRotateScreen(info, 100.0, 200.0, cursorPos);
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
    WinMgr->UpdateAndAdjustMouseLocation(displayId, x, y, isRealData);
    auto ret = WinMgr->GetDisplayId(inputEvent);
    EXPECT_NE(displayId, ret);
    displayId = -1;
    x = 100.5;
    y = 200.5;
    isRealData = true;
    WinMgr->UpdateAndAdjustMouseLocation(displayId, x, y, isRealData);
    ret = WinMgr->GetDisplayId(inputEvent);
    EXPECT_NE(displayId, ret);
    displayId = 0;
    x = -100.5;
    y = -200.5;
    isRealData = true;
    WinMgr->UpdateAndAdjustMouseLocation(displayId, x, y, isRealData);
    ret = WinMgr->GetDisplayId(inputEvent);
    EXPECT_NE(displayId, ret);
    displayId = 0;
    x = 100.5;
    y = 200.5;
    isRealData = false;
    WinMgr->UpdateAndAdjustMouseLocation(displayId, x, y, isRealData);
    ret = WinMgr->GetDisplayId(inputEvent);
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
    MouseLocation result = WinMgr->GetMouseInfo();
    DisplayInfo displayInfo;
    displayInfo.id = 1;
    displayInfo.width = 1920;
    displayInfo.height = 1080;
    displayGroupInfo.displaysInfo.push_back(displayInfo);
    mouseLocation.displayId = 0;
    result = WinMgr->GetMouseInfo();
    displayGroupInfo.displaysInfo.push_back(displayInfo);
    mouseLocation.displayId = -1;
    MouseLocation expectedResult;
    expectedResult.displayId = 1;
    expectedResult.physicalX = 960;
    expectedResult.physicalY = 540;
    result = WinMgr->GetMouseInfo();
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
    CursorPosition result = WinMgr->GetCursorPos();
    EXPECT_EQ(result.displayId, 1);
    EXPECT_EQ(result.cursorPos.x, 1);
    EXPECT_EQ(result.cursorPos.y, 1);
    manager.cursorPos_.displayId = 1;
    manager.displayGroupInfo_.displaysInfo.push_back({1, 800, 600});
    result = WinMgr->GetCursorPos();
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
    CursorPosition result = WinMgr->ResetCursorPos();
    EXPECT_EQ(result.displayId, 1);
    EXPECT_EQ(result.cursorPos.x, 1);
    EXPECT_EQ(result.cursorPos.y, 1);
    manager.displayGroupInfo_.displaysInfo.clear();
    result = WinMgr->ResetCursorPos();
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
    int32_t result = WinMgr->AppendExtraData(extraData);
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
    WinMgr->ClearExtraData();
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
    ExtraData actualData = WinMgr->GetExtraData();
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
    bool result = WinMgr->IsWindowVisible(invalidPid);
    EXPECT_TRUE(result);
    int32_t visiblePid = 0;
    result = WinMgr->IsWindowVisible(visiblePid);
    EXPECT_FALSE(result);
    int32_t invisiblePid = 1;
    result = WinMgr->IsWindowVisible(invisiblePid);
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
    WinMgr->UpdatePointerAction(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_PULL_MOVE);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_BUTTON_UP);
    WinMgr->UpdatePointerAction(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_PULL_UP);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    WinMgr->UpdatePointerAction(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_PULL_UP);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_ENTER_WINDOW);
    WinMgr->UpdatePointerAction(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_PULL_IN_WINDOW);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_LEAVE_WINDOW);
    WinMgr->UpdatePointerAction(pointerEvent);
    EXPECT_EQ(pointerEvent->GetPointerAction(), PointerEvent::POINTER_ACTION_PULL_OUT_WINDOW);
    pointerEvent->SetPointerAction(100);
    WinMgr->UpdatePointerAction(pointerEvent);
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
    WinMgr->Dump(fd, args);
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
    std::pair<double, double> result =WinMgr->TransformWindowXY(window, logicX, logicY);
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
    bool result = WinMgr->IsValidZorderWindow(window, pointerEvent);
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
    WinMgr->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    WindowInfo window;
    window.windowInputType = WindowInputType::TRANSMIT_EXCEPT_MOVE;
    ASSERT_FALSE(WinMgr->HandleWindowInputType(window, pointerEvent));
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
    auto result = WinMgr->GetWindowAndDisplayInfo(windowId, displayId);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->id, windowId);
    windowId = -1;
    displayId = 1;
    result = WinMgr->GetWindowAndDisplayInfo(windowId, displayId);
    ASSERT_FALSE(result.has_value());
    windowId = 1;
    displayId = -1;
    result = WinMgr->GetWindowAndDisplayInfo(windowId, displayId);
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
    WinMgr->GetTargetWindowIds(pointerItemId, windowIds);
    ASSERT_TRUE(windowIds.empty());
    pointerItemId = -1;
    WinMgr->GetTargetWindowIds(pointerItemId, windowIds);
    ASSERT_TRUE(windowIds.empty());
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
    WinMgr->AddTargetWindowIds(pointerItemId, windowId);
    ASSERT_FALSE(manager.targetWindowIds_.find(pointerItemId) != manager.targetWindowIds_.end());
    ASSERT_EQ(manager.targetWindowIds_[pointerItemId].size(), 0);
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
    manager.targetWindowIds_[pointerItemId] = {windowId1};
    WinMgr->AddTargetWindowIds(pointerItemId, windowId2);
    ASSERT_TRUE(manager.targetWindowIds_.find(pointerItemId) != manager.targetWindowIds_.end());
    ASSERT_EQ(manager.targetWindowIds_[pointerItemId].size(), 1);
    ASSERT_EQ(manager.targetWindowIds_[pointerItemId][0], windowId1);
    ASSERT_NE(manager.targetWindowIds_[pointerItemId][1], windowId2);
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
    int32_t result = WinMgr->CheckWindowIdPermissionByPid(windowId, pid);
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
    auto result = WinMgr->IsTransparentWin(pixelMap, logicalX, logicalY);
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
    auto ret = WinMgr->SetCurrentUser(userId);
    EXPECT_EQ(ret, RET_OK);
    userId = -456;
    ret = WinMgr->SetCurrentUser(userId);
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
    WinMgr->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = pointerEvent->GetPointerAction();
    action = PointerEvent::POINTER_ACTION_MOVE;
    WinMgr->UpdatePointerAction(pointerEvent);
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
    WinMgr->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = pointerEvent->GetPointerAction();
    action = PointerEvent::POINTER_ACTION_UP;
    WinMgr->UpdatePointerAction(pointerEvent);
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
    WinMgr->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = pointerEvent->GetPointerAction();
    action = PointerEvent::POINTER_ACTION_ENTER_WINDOW;
    WinMgr->UpdatePointerAction(pointerEvent);
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
    WinMgr->Init(udsServer);
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    int32_t action = pointerEvent->GetPointerAction();
    action = PointerEvent::POINTER_ACTION_LEAVE_WINDOW;
    WinMgr->UpdatePointerAction(pointerEvent);
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
    ASSERT_TRUE(WinMgr->UpdateDisplayId(id));
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
    ASSERT_FALSE(WinMgr->UpdateDisplayId(id));
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
    WinMgr->Init(udsServer);
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
    WinMgr->UpdateCaptureMode(displayGroupInfo);
    ASSERT_FALSE(WinMgr->captureModeInfo_.isCaptureMode);
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
    auto ret = WinMgr->IsWindowVisible(pid);
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
    auto ret = WinMgr->IsWindowVisible(pid);
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
} // namespace MMI
} // namespace OHOS
