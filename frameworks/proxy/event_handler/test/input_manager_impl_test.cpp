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

#include <gtest/gtest.h>

#include "input_manager_impl.h"
#include "multimodal_event_handler.h"
#include "multimodal_input_connect_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputManagerImplTest"

namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class InputManagerImplTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: InputManagerImplTest_IsValiadWindowAreas
 * @tc.desc: Test IsValiadWindowAreas
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsValiadWindowAreas, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.action = WINDOW_UPDATE_ACTION::UNKNOWN;
    Rect rect;
    rect.x = 100;
    windowInfo.defaultHotAreas.push_back(rect);
    windowInfo.pointerHotAreas.push_back(rect);
    windowInfo.pointerChangeAreas.push_back(100);
    windowInfo.transform.push_back(100.5);
    std::vector<WindowInfo> windows;
    windows.push_back(windowInfo);
    EXPECT_FALSE(InputMgrImpl.IsValiadWindowAreas(windows));

    windows[0].pointerChangeAreas.clear();
    EXPECT_FALSE(InputMgrImpl.IsValiadWindowAreas(windows));
}

/**
 * @tc.name: InputManagerImplTest_PrintWindowInfo
 * @tc.desc: Test PrintWindowInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_PrintWindowInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    WindowInfo windowInfo;
    windowInfo.action = WINDOW_UPDATE_ACTION::UNKNOWN;
    Rect rect {
        .x = 100,
        .y = 100,
        .width = 300,
        .height = 300,
    };
    windowInfo.id = 10;
    windowInfo.pid = 1000;
    windowInfo.uid = 100;
    windowInfo.area.x = 100;
    windowInfo.area.y = 100;
    windowInfo.area.height = 200;
    windowInfo.area.width = 200;
    windowInfo.agentWindowId = 50;
    windowInfo.flags = 0;
    windowInfo.displayId = 30;
    windowInfo.zOrder = 60;
    windowInfo.defaultHotAreas.push_back(rect);
    windowInfo.pointerHotAreas.push_back(rect);
    windowInfo.pointerChangeAreas.push_back(100);
    windowInfo.transform.push_back(100.5);
    std::vector<WindowInfo> windows;
    windows.push_back(windowInfo);
    EXPECT_NO_FATAL_FAILURE(InputMgrImpl.PrintWindowInfo(windows));
}

/**
 * @tc.name: InputManagerImplTest_RecoverPointerEvent
 * @tc.desc: Test RecoverPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_RecoverPointerEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputMgrImpl.lastPointerEvent_ = PointerEvent::Create();
    ASSERT_NE(InputMgrImpl.lastPointerEvent_, nullptr);
    std::initializer_list<int32_t> pointerActionPullEvents { PointerEvent::POINTER_ACTION_MOVE,
        PointerEvent::POINTER_ACTION_UP };
    InputMgrImpl.lastPointerEvent_->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    EXPECT_FALSE(InputMgrImpl.RecoverPointerEvent(pointerActionPullEvents, PointerEvent::POINTER_ACTION_UP));

    PointerEvent::PointerItem item;
    item.SetPointerId(1);
    InputMgrImpl.lastPointerEvent_->SetPointerId(1);
    InputMgrImpl.lastPointerEvent_->AddPointerItem(item);
    EXPECT_TRUE(InputMgrImpl.RecoverPointerEvent(pointerActionPullEvents, PointerEvent::POINTER_ACTION_UP));

    InputMgrImpl.lastPointerEvent_->SetPointerId(2);
    EXPECT_FALSE(InputMgrImpl.RecoverPointerEvent(pointerActionPullEvents, PointerEvent::POINTER_ACTION_UP));
}

/**
 * @tc.name: InputManagerImplTest_OnDisconnected_01
 * @tc.desc: Test OnDisconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnDisconnected_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_UP;

    EXPECT_NO_FATAL_FAILURE(InputMgrImpl.OnDisconnected());
}

/**
 * @tc.name: InputManagerImplTest_OnDisconnected_02
 * @tc.desc: Test OnDisconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnDisconnected_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->pointerAction_ = PointerEvent::POINTER_ACTION_PULL_UP;

    EXPECT_NO_FATAL_FAILURE(InputMgrImpl.OnDisconnected());
}

/**
 * @tc.name: InputManagerImplTest_OnKeyEvent_01
 * @tc.desc: Test OnKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnKeyEvent_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);

    MMIClientPtr client = MMIEventHdl.GetMMIClient();
    EXPECT_NO_FATAL_FAILURE(InputMgrImpl.OnKeyEvent(keyEvent));
}

/**
 * @tc.name: InputManagerImplTest_IsValiadWindowAreas_01
 * @tc.desc: Test IsValiadWindowAreas
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsValiadWindowAreas_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<WindowInfo> windows;
    WindowInfo window;
    window.action = WINDOW_UPDATE_ACTION::DEL;

    bool ret = InputMgrImpl.IsValiadWindowAreas(windows);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InputManagerImplTest_IsValiadWindowAreas_02
 * @tc.desc: Test IsValiadWindowAreas
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsValiadWindowAreas_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<WindowInfo> windows;
    WindowInfo window;
    window.action = WINDOW_UPDATE_ACTION::CHANGE;

    bool ret = InputMgrImpl.IsValiadWindowAreas(windows);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InputManagerImplTest_SetCustomCursor_01
 * @tc.desc: Test SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetCustomCursor_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 2;
    int32_t focusX = 3;
    int32_t focusY = 4;
    void* pixelMap = nullptr;
    int32_t winPid = InputMgrImpl.GetWindowPid(windowId);
    EXPECT_FALSE(winPid == -1);
    int32_t ret = InputMgrImpl.SetCustomCursor(windowId, focusX, focusY, pixelMap);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: InputManagerImplTest_SetMouseHotSpot_01
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetMouseHotSpot_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 2;
    int32_t hotSpotX = 3;
    int32_t hotSpotY = 4;

    int32_t winPid = InputMgrImpl.GetWindowPid(windowId);
    EXPECT_TRUE(winPid != -1);
    int32_t ret = InputMgrImpl.SetMouseHotSpot(windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputManagerImplTest_SetMouseHotSpot_02
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetMouseHotSpot_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = -5;
    int32_t hotSpotX = 2;
    int32_t hotSpotY = 3;

    int32_t winPid = InputMgrImpl.GetWindowPid(windowId);
    EXPECT_FALSE(winPid != -1);
    int32_t ret = InputMgrImpl.SetMouseHotSpot(windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputManagerImplTest_ReAddInputEventFilter_01
 * @tc.desc: Test ReAddInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_ReAddInputEventFilter_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_FALSE(InputMgrImpl.eventFilterServices_.size() > 4);
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.ReAddInputEventFilter());
}

/**
 * @tc.name: InputManagerImplTest_IsPointerVisible_01
 * @tc.desc: Test IsPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsPointerVisible_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool visible = true;
    bool ret = InputMgrImpl.IsPointerVisible();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InputManagerImplTest_IsPointerVisible_02
 * @tc.desc: Test IsPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsPointerVisible_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool visible = false;
    bool ret = InputMgrImpl.IsPointerVisible();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InputManagerImplTest_SetPointerColor_01
 * @tc.desc: Test SetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetPointerColor_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t color = 6;
    int32_t ret = InputMgrImpl.SetPointerColor(color);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputManagerImplTest_SetPointerColor_02
 * @tc.desc: Test SetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetPointerColor_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t color = -10;
    int32_t ret = InputMgrImpl.SetPointerColor(color);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputManagerImplTest_SetPointerSpeed_01
 * @tc.desc: Test SetPointerSpeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetPointerSpeed_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t speed = 10;
    int32_t ret2 = InputMgrImpl.SetPointerSpeed(speed);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: InputManagerImplTest_EnableCombineKey_01
 * @tc.desc: Test EnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_EnableCombineKey_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool enable = true;
    int32_t ret2 = InputMgrImpl.EnableCombineKey(enable);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: InputManagerImplTest_EnableCombineKey_02
 * @tc.desc: Test EnableCombineKey
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_EnableCombineKey_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool enable = false;
    int32_t ret2 = InputMgrImpl.EnableCombineKey(enable);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: InputManagerImplTest_OnConnected_01
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnConnected_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    EXPECT_TRUE(InputMgrImpl.displayGroupInfo_.windowsInfo.empty());
    EXPECT_TRUE(InputMgrImpl.displayGroupInfo_.displaysInfo.empty());
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.OnConnected());
}

/**
 * @tc.name: InputManagerImplTest_OnConnected_02
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnConnected_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputMgrImpl.displayGroupInfo_.width = 50;
    InputMgrImpl.displayGroupInfo_.height = 60;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 2;
    InputMgrImpl.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    EXPECT_FALSE(InputMgrImpl.displayGroupInfo_.windowsInfo.empty());

    DisplayInfo displayInfo;
    displayInfo.width = 10;
    displayInfo.height = 20;
    InputMgrImpl.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_FALSE(InputMgrImpl.displayGroupInfo_.displaysInfo.empty());

    EXPECT_TRUE(InputMgrImpl.anrObservers_.empty());
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.OnConnected());
}

/**
 * @tc.name: InputManagerImplTest_OnConnected_03
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnConnected_03, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayInfo displayInfo;
    displayInfo.width = 10;
    displayInfo.height = 20;
    InputMgrImpl.displayGroupInfo_.displaysInfo.push_back(displayInfo);
    EXPECT_FALSE(InputMgrImpl.displayGroupInfo_.displaysInfo.empty());
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.OnConnected());
}

/**
 * @tc.name: InputManagerImplTest_OnConnected_04
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnConnected_04, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputMgrImpl.displayGroupInfo_.width = 50;
    InputMgrImpl.displayGroupInfo_.height = 60;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 2;
    InputMgrImpl.displayGroupInfo_.windowsInfo.push_back(windowInfo);
    EXPECT_FALSE(InputMgrImpl.displayGroupInfo_.windowsInfo.empty());
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.OnConnected());
}

/**
 * @tc.name: InputManagerImplTest_SetPixelMapData_01
 * @tc.desc: Test SetPixelMapData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetPixelMapData_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t infoId = -1;
    void* pixelMap = nullptr;
    int32_t ret = InputMgrImpl.SetPixelMapData(infoId, pixelMap);
    EXPECT_EQ(ret, RET_ERR);

    infoId = 2;
    int32_t ret2 = InputMgrImpl.SetPixelMapData(infoId, pixelMap);
    EXPECT_EQ(ret2, RET_ERR);
}

/**
 * @tc.name: InputManagerImplTest_SendEnhanceConfig_01
 * @tc.desc: Test SendEnhanceConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SendEnhanceConfig_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MmiMessageId idMsg = MmiMessageId::SCINFO_CONFIG;
    NetPacket pkt(idMsg);
    EXPECT_EQ(InputMgrImpl.PackEnhanceConfig(pkt), RET_ERR);
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.SendEnhanceConfig());
}

/**
 * @tc.name: InputManagerImplTest_SendEnhanceConfig_02
 * @tc.desc: Test SendEnhanceConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SendEnhanceConfig_02, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MmiMessageId idMsg = MmiMessageId::INVALID;
    NetPacket pkt(idMsg);
    EXPECT_EQ(InputMgrImpl.PackEnhanceConfig(pkt), RET_ERR);
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.SendEnhanceConfig());
}

/**
 * @tc.name: InputManagerImplTest_GetPointerColor_01
 * @tc.desc: Test GetPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_GetPointerColor_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t color = 5;
    int32_t ret = InputMgrImpl.GetPointerColor(color);
    EXPECT_EQ(ret, RET_OK);

    color = -1;
    int32_t ret2 = InputMgrImpl.GetPointerColor(color);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: InputManagerImplTest_GetMouseScrollRows_01
 * @tc.desc: Test GetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_GetMouseScrollRows_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t rows = 8;
    int32_t ret = InputMgrImpl.GetMouseScrollRows(rows);
    EXPECT_EQ(ret, RET_OK);

    rows = -5;
    int32_t ret2 = InputMgrImpl.GetMouseScrollRows(rows);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: InputManagerImplTest_SetMouseScrollRows_01
 * @tc.desc: Test SetMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetMouseScrollRows_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t rows = 3;
    int32_t ret = InputMgrImpl.SetMouseScrollRows(rows);
    EXPECT_EQ(ret, RET_OK);

    rows = -2;
    int32_t ret2 = InputMgrImpl.SetMouseScrollRows(rows);
    EXPECT_EQ(ret2, RET_OK);
}

/**
 * @tc.name: InputManagerImplTest_LeaveCaptureMode_01
 * @tc.desc: Test LeaveCaptureMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_LeaveCaptureMode_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 3;
    int32_t ret = InputMgrImpl.LeaveCaptureMode(windowId);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputManagerImplTest_EnableInputDevice_01
 * @tc.desc: Test EnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_EnableInputDevice_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool enable = false;
    int32_t ret = InputMgrImpl.EnableInputDevice(enable);
    EXPECT_EQ(ret, RET_OK);

    enable = true;
    int32_t ret2 = InputMgrImpl.EnableInputDevice(enable);
    EXPECT_EQ(ret2, RET_OK);
}
} // namespace MMI
} // namespace OHOS
