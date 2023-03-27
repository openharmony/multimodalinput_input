/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "gtest/gtest.h"

#include <fstream>

#include "input_windows_manager.h"
#include "mmi_log.h"
#include "uds_server.h"

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
    } // void SetUp(void)
};


/**
 * @tc.name: InputWindowsManagerTest_GetClientFd_001
 * @tc.desc: Test GetClientFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetClientFd_001, TestSize.Level1)
{
    auto pointerEvent = PointerEvent::Create();
    UDSServer udsServer;
    WinMgr->Init(udsServer);
    WinMgr->GetDisplayGroupInfo();
    int32_t idNames = -1;
    ASSERT_EQ(WinMgr->GetClientFd(pointerEvent), idNames);
}

/**
 * @tc.name: InputWindowsManagerTest_GetPidAndUpdateTarget_002
 * @tc.desc: Test GetPidAndUpdateTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetPidAndUpdateTarget_002, TestSize.Level1)
{
    UDSServer udsServer;
    WinMgr->Init(udsServer);
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    inputEvent->SetDeviceId(1);
    inputEvent->SetTargetWindowId(1);
    inputEvent->SetAgentWindowId(1);
    ASSERT_EQ(WinMgr->GetPidAndUpdateTarget(inputEvent), 1);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTarget_003
 * @tc.desc: Test UpdateTarget
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTarget_003, TestSize.Level1)
{
    UDSServer udsServer;
    WinMgr->Init(udsServer);
    auto inputEvent = InputEvent::Create();
    ASSERT_NE(inputEvent, nullptr);
    inputEvent->SetDeviceId(1);
    inputEvent->SetTargetWindowId(1);
    inputEvent->SetAgentWindowId(1);
    ASSERT_EQ(WinMgr->UpdateTarget(inputEvent), -1);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateDisplayId_004
 * @tc.desc: Test UpdateDisplayId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateDisplayId_004, TestSize.Level1)
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

    UDSServer udsServer;
    WinMgr->Init(udsServer);
    WinMgr->UpdateDisplayInfo(displayGroupInfo);
    int32_t displayId= 1;
    double x = 0;
    double y = 0;
    WinMgr->UpdateAndAdjustMouseLocation(displayId, x, y);
    ASSERT_EQ(WinMgr->UpdateDisplayId(displayId), true);
    displayId= -1;
    WinMgr->UpdateAndAdjustMouseLocation(displayId, x, y);
    ASSERT_EQ(WinMgr->UpdateDisplayId(displayId), true);
}

/**
 * @tc.name: InputWindowsManagerTest_UpdateTargetPointer_005
 * @tc.desc: Test UpdateTargetPointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_UpdateTargetPointer_005, TestSize.Level1)
{
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
    UDSServer udsServer;
    WinMgr->Init(udsServer);
    ASSERT_EQ(WinMgr->IsNeedRefreshLayer(-1), false);
    ASSERT_EQ(WinMgr->IsNeedRefreshLayer(0), false);
    ASSERT_EQ(WinMgr->IsNeedRefreshLayer(1), false);
}

/**
 * @tc.name: InputWindowsManagerTest_GetWindowPid_007
 * @tc.desc: Test GetWindowPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_GetWindowPid_002, TestSize.Level1)
{
    UDSServer udsServer;
    WinMgr->Init(udsServer);
    ASSERT_EQ(WinMgr->GetWindowPid(1), 1);
    ASSERT_EQ(WinMgr->GetWindowPid(2), -1);
}


/**
 * @tc.name: InputWindowsManagerTest_SetMouseCaptureMode_008
 * @tc.desc: Test SetMouseCaptureMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputWindowsManagerTest, InputWindowsManagerTest_SetMouseCaptureMode_008, TestSize.Level1)
{
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
} // namespace MMI
} // namespace OHOS
