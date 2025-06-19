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

#include "input_scene_board_judgement.h"
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

struct InputEventFilterMock : public IInputEventFilter {
public:
    InputEventFilterMock() = default;
    virtual ~InputEventFilterMock() = default;
    bool OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const
    {
        return true;
    }
    bool OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const
    {
        return true;
    }
};

class InputManagerImplTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

class TestInputEventConsumer : public IInputEventConsumer {
public:
    TestInputEventConsumer() = default;
    ~TestInputEventConsumer() = default;
    void OnInputEvent(std::shared_ptr<KeyEvent> keyEvent) const override
    {
        MMI_HILOGI("OnInputEvent KeyEvent enter");
    }
    void OnInputEvent(std::shared_ptr<PointerEvent> pointerEvent) const override
    {
        MMI_HILOGI("OnInputEvent PointerEvent enter");
    }
    void OnInputEvent(std::shared_ptr<AxisEvent> axisEvent) const override
    {}
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_PrintWindowInfo, TestSize.Level2)
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_RecoverPointerEvent, TestSize.Level2)
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsValiadWindowAreas_01, TestSize.Level3)
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetCustomCursor_01, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 2;
    int32_t focusX = 3;
    int32_t focusY = 4;
    void* pixelMap = nullptr;
    int32_t winPid = InputMgrImpl.GetWindowPid(windowId);
    EXPECT_TRUE(winPid == -1);
    int32_t ret = InputMgrImpl.SetCustomCursor(windowId, focusX, focusY, pixelMap);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: InputManagerImplTest_SetMouseHotSpot_01
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetMouseHotSpot_01, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    int32_t windowId = 2;
    int32_t hotSpotX = 3;
    int32_t hotSpotY = 4;

    int32_t winPid = InputMgrImpl.GetWindowPid(windowId);
    EXPECT_TRUE(winPid == -1);
    int32_t ret = InputMgrImpl.SetMouseHotSpot(windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputManagerImplTest_SetMouseHotSpot_02
 * @tc.desc: Test SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetMouseHotSpot_02, TestSize.Level2)
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_ReAddInputEventFilter_01, TestSize.Level3)
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsPointerVisible_01, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    bool ret = InputMgrImpl.IsPointerVisible();
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: InputManagerImplTest_IsPointerVisible_02
 * @tc.desc: Test IsPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsPointerVisible_02, TestSize.Level3)
{
    CALL_TEST_DEBUG;
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_EnableCombineKey_02, TestSize.Level2)
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnConnected_01, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo {};
    InputMgrImpl.displayGroupInfoArray_.push_back(displayGroupInfo);
    EXPECT_TRUE(InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].windowsInfo.empty());
    EXPECT_TRUE(InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].displaysInfo.empty());
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.OnConnected());
}

/**
 * @tc.name: InputManagerImplTest_OnConnected_02
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnConnected_02, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo {};
    InputMgrImpl.displayGroupInfoArray_.push_back(displayGroupInfo);
    InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].width = 50;
    InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].height = 60;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 2;
    InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].windowsInfo.push_back(windowInfo);
    EXPECT_FALSE(InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].windowsInfo.empty());

    DisplayInfo displayInfo;
    displayInfo.width = 10;
    displayInfo.height = 20;
    InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].displaysInfo.push_back(displayInfo);
    EXPECT_FALSE(InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].displaysInfo.empty());

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
    DisplayGroupInfo displayGroupInfo {};
    InputMgrImpl.displayGroupInfoArray_.push_back(displayGroupInfo);
    InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].displaysInfo.push_back(displayInfo);
    EXPECT_FALSE(InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].displaysInfo.empty());
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.OnConnected());
}

/**
 * @tc.name: InputManagerImplTest_OnConnected_04
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnConnected_04, TestSize.Level2)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo {};
    InputMgrImpl.displayGroupInfoArray_.push_back(displayGroupInfo);
    InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].width = 50;
    InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].height = 60;
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 2;
    InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].windowsInfo.push_back(windowInfo);
    EXPECT_FALSE(InputMgrImpl.displayGroupInfoArray_[DEFAULT_GROUP_ID].windowsInfo.empty());
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.OnConnected());
}

/**
 * @tc.name: InputManagerImplTest_SetPixelMapData_01
 * @tc.desc: Test SetPixelMapData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetPixelMapData_01, TestSize.Level2)
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SendEnhanceConfig_01, TestSize.Level2)
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_GetPointerColor_01, TestSize.Level3)
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

/**
 * @tc.name: InputManagerImplTest_ConvertToCapiKeyAction_001
 * @tc.desc: Test the funcation ConvertToCapiKeyAction
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_ConvertToCapiKeyAction_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyAction = KeyEvent::KEY_ACTION_DOWN;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.ConvertToCapiKeyAction(keyAction));
    keyAction = KeyEvent::KEY_ACTION_UP;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.ConvertToCapiKeyAction(keyAction));
    keyAction = KeyEvent::KEY_ACTION_CANCEL;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.ConvertToCapiKeyAction(keyAction));
    keyAction = 10;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.ConvertToCapiKeyAction(keyAction));
}

/**
 * @tc.name: InputManagerImplTest_GetTouchpadThreeFingersTapSwitch_001
 * @tc.desc: Test the funcation GetTouchpadThreeFingersTapSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_GetTouchpadThreeFingersTapSwitch_001, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    bool switchFlag = true;
    int32_t ret = InputMgrImpl.GetTouchpadThreeFingersTapSwitch(switchFlag);
    EXPECT_EQ(ret, RET_OK);
    switchFlag = true;
    ret = InputMgrImpl.GetTouchpadThreeFingersTapSwitch(switchFlag);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputManagerImplTest_SetTouchpadThreeFingersTapSwitch_001
 * @tc.desc: Test the funcation SetTouchpadThreeFingersTapSwitch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetTouchpadThreeFingersTapSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool switchFlag = true;
    int32_t ret = InputMgrImpl.SetTouchpadThreeFingersTapSwitch(switchFlag);
    EXPECT_EQ(ret, RET_OK);
    switchFlag = true;
    ret = InputMgrImpl.SetTouchpadThreeFingersTapSwitch(switchFlag);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: InputManagerImplTest_SetCurrentUser_001
 * @tc.desc: Test the funcation SetCurrentUser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetCurrentUser_001, TestSize.Level3)
{
    CALL_TEST_DEBUG;
    int32_t userId = 1;
    int32_t ret = InputMgrImpl.SetCurrentUser(userId);
    EXPECT_EQ(ret, RET_ERR);
    userId = 0;
    ret = InputMgrImpl.SetCurrentUser(userId);
    EXPECT_EQ(ret, RET_ERR);
    userId = -1;
    ret = InputMgrImpl.SetCurrentUser(userId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputManagerImplTest_Authorize_001
 * @tc.desc: Test the funcation Authorize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_Authorize_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    bool isAuthorize = true;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.Authorize(isAuthorize));
    isAuthorize = false;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.Authorize(isAuthorize));
}

/**
 * @tc.name: InputManagerImplTest_SubscribeLongPressEvent
 * @tc.desc: Test SubscribeLongPressEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SubscribeLongPressEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    LongPressRequest longPR;
    longPR.fingerCount = 3;
    longPR.duration = 2;
    int32_t ret = InputMgrImpl.SubscribeLongPressEvent(longPR, nullptr);
    ASSERT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InputManagerImplTest_UnsubscribeLongPressEvent
 * @tc.desc: Test UnsubscribeLongPressEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_UnsubscribeLongPressEvent, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t subscriberId = 0;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.UnsubscribeLongPressEvent(subscriberId));
}

/**
 * @tc.name  : PrintForemostThreeWindowInfo_WhenMoreThanThreeWindowsExist
 * @tc.desc  : Test PrintForemostThreeWindowInfo method when there are more than three windows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, PrintForemostThreeWindowInfo_WhenMoreThanThreeWindowsExist, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<WindowInfo> windowsInfo;
    for (int i = 0; i < 5; i++) {
        WindowInfo windowInfo;
        windowInfo.action = WINDOW_UPDATE_ACTION::UNKNOWN;
        windowsInfo.push_back(windowInfo);
    }
    InputMgrImpl.PrintForemostThreeWindowInfo(windowsInfo);
}

/**
 * @tc.name  : ConvertToCapiKeyAction_ShouldReturnInvalidValue_WhenKeyActionIsInvalid
 * @tc.desc  : Test ConvertToCapiKeyAction function when keyAction is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(InputManagerImplTest, ConvertToCapiKeyAction_ShouldReturnInvalidValue_WhenKeyActionIsInvalid, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t keyAction = -1;
    int32_t expected = -1;
    int32_t result = InputMgrImpl.ConvertToCapiKeyAction(keyAction);
    EXPECT_EQ(result, expected);
}
/**
 * @tc.name  : OnWindowStateError_WhenWindowStateCallbackIsNull
 * @tc.desc  : OnWindowState Error Should Not Call Window State Callback When Window State Callback Is Null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, OnWindowStateError_WhenWindowStateCallbackIsNull, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t pid = 123;
    int32_t windowId = 456;
    InputMgrImpl.OnWindowStateError(pid, windowId);
}

/**
 * @tc.name  : SetCurrentUser_Test_001
 * @tc.desc  : Test SetCurrentUser function when userId is less than 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, SetCurrentUser_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t userId = -1;
    int32_t ret = InputMgrImpl.SetCurrentUser(userId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name  : SetPixelMapData_InvalidInput_Test
 * @tc.desc  : Test SetPixelMapData function with invalid input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, SetPixelMapData_InvalidInput_Test, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t infoId = -1;
    int32_t ret = InputMgrImpl.SetPixelMapData(infoId, nullptr);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name  : CancelInjection_Success
 * @tc.desc  : Test CancelInjection function when CancelInjection is successful.
 * @tc.type: FUNC
 * @tc.require:
  */
HWTEST_F(InputManagerImplTest, CancelInjection_Success, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t result = InputMgrImpl.CancelInjection();
    EXPECT_EQ(result, RET_OK);
}

/**
 * @tc.name  : GetKeyState_ReturnsOk_WhenInputValid
 * @tc.desc  : Test GetKeyState function when input is valid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, GetKeyState_ReturnsOk_WhenInputValid, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<int32_t> pressedKeys = {1, 2, 3};
    std::map<int32_t, int32_t> specialKeysState = {{1, 1}, {2, 2}, {3, 3}};
    int32_t result = InputMgrImpl.GetKeyState(pressedKeys, specialKeysState);
    EXPECT_EQ(result, RET_OK);
}


/**
 * @tc.name  : ReAddInputEventFilter_Test_001
 * @tc.desc  : Test when eventFilterServices_ size is greater than MAX_FILTER_NUM, ReAddInputEventFilter should return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, ReAddInputEventFilter_Test_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputMgrImpl.eventFilterServices_.insert(std::make_pair(1, std::make_tuple(nullptr, 1, 1)));
    InputMgrImpl.eventFilterServices_.insert(std::make_pair(2, std::make_tuple(nullptr, 2, 2)));
    InputMgrImpl.eventFilterServices_.insert(std::make_pair(3, std::make_tuple(nullptr, 3, 3)));
    InputMgrImpl.eventFilterServices_.insert(std::make_pair(4, std::make_tuple(nullptr, 4, 4)));
    InputMgrImpl.eventFilterServices_.insert(std::make_pair(5, std::make_tuple(nullptr, 5, 5)));
    InputMgrImpl.ReAddInputEventFilter();
    ASSERT_EQ(InputMgrImpl.eventFilterServices_.size(), 5);
}


/**
 * @tc.name  : SetPointerStyle_InvalidParam_Test
 * @tc.desc  : Test SetPointerStyle function with invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, SetPointerStyle_InvalidParam_Test, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    PointerStyle pointerStyle;
    pointerStyle.id = -1;
    int32_t windowId = 1;
    bool isUiExtension = false;
    int32_t ret = InputMgrImpl.SetPointerStyle(windowId, pointerStyle, isUiExtension);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name  : SetMouseHotSpot_Test001
 * @tc.desc  : Test SetMouseHotSpot function when windowId is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, SetMouseHotSpot_Test001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t windowId = -1;
    int32_t hotSpotX = 100;
    int32_t hotSpotY = 200;
    int32_t ret = InputMgrImpl.SetMouseHotSpot(windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name  : AddInputEventFilter_Test001
 * @tc.desc  : Test AddInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, AddInputEventFilter_Test001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto filter = std::make_shared<InputEventFilterMock>();
    int32_t priority = 0;
    uint32_t deviceTags = 0;

    InputMgrImpl.eventFilterServices_.clear();
    EventFilterService::filterIdSeed_ = 0;
    int32_t filterId = EventFilterService::filterIdSeed_;
    sptr<IEventFilter> service = new (std::nothrow) EventFilterService(filter);
    ASSERT_NE(service, nullptr);

    InputMgrImpl.eventFilterServices_.emplace(filterId, std::make_tuple(service, priority, deviceTags));
    int32_t ret = InputMgrImpl.AddInputEventFilter(filter, priority, deviceTags);
    EXPECT_EQ(ret, filterId);
}

/**
 * @tc.name  : RemoveInputEventFilter_Test001
 * @tc.desc  : Test RemoveInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, RemoveInputEventFilter_Test001, TestSize.Level1)
{
    CALL_TEST_DEBUG;

    InputMgrImpl.eventFilterServices_.clear();
    auto filter = std::make_shared<InputEventFilterMock>();
    sptr<IEventFilter> service = new (std::nothrow) EventFilterService(filter);
    ASSERT_NE(service, nullptr);

    int32_t priority = 0;
    uint32_t deviceTags = 0;
    int32_t filterId = 5;
    InputMgrImpl.eventFilterServices_.emplace(filterId, std::make_tuple(service, priority, deviceTags));
    filterId = 0;

    int32_t ret = InputMgrImpl.RemoveInputEventFilter(filterId);
    EXPECT_EQ(ret, RET_OK);
}
#ifdef OHOS_BUILD_ENABLE_ONE_HAND_MODE
/**
 * @tc.name: InputManagerImplTest_UpdateDisplayXYInOneHandMode_001
 * @tc.desc: Test UpdateDisplayXYInOneHandMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_UpdateDisplayXYInOneHandMode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetFixedMode(PointerEvent::FixedMode::NORMAL);
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.UpdateDisplayXYInOneHandMode(pointerEvent));
}

/**
 * @tc.name: InputManagerImplTest_UpdateDisplayXYInOneHandMode_002
 * @tc.desc: Test UpdateDisplayXYInOneHandMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_UpdateDisplayXYInOneHandMode_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetFixedMode(PointerEvent::FixedMode::AUTO);
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.UpdateDisplayXYInOneHandMode(pointerEvent));
}
/**
 * @tc.name: InputManagerImplTest_UpdateDisplayXYInOneHandMode_001
 * @tc.desc: Test UpdateDisplayXYInOneHandMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_UpdateDisplayXYInOneHandMode_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetFixedMode(PointerEvent::FixedMode::AUTO);
    int32_t pointerId = 3;
    pointerEvent->SetPointerId(pointerId);
    PointerEvent::PointerItem pointerItem;
    pointerItem.pointerId_ = pointerId;
    pointerEvent->pointers_.push_back(pointerItem);
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.UpdateDisplayXYInOneHandMode(pointerEvent));
}
/**
 * @tc.name: InputManagerImplTest_UpdateDisplayXYInOneHandMode_001
 * @tc.desc: Test UpdateDisplayXYInOneHandMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_UpdateDisplayXYInOneHandMode_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    auto pointerEvent = PointerEvent::Create();
    pointerEvent->SetFixedMode(PointerEvent::FixedMode::AUTO);
    int32_t pointerId = 3;
    pointerEvent->SetPointerId(pointerId);
    PointerEvent::PointerItem pointerItem;
    pointerItem.pointerId_ = 4;
    pointerEvent->pointers_.push_back(pointerItem);
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.UpdateDisplayXYInOneHandMode(pointerEvent));
}
#endif // OHOS_BUILD_ENABLE_ONE_HAND_MODE

#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
/**
 * @tc.name: InputManagerImplTest_SetEnhanceConfig_001
 * @tc.desc: Test SetEnhanceConfig
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetEnhanceConfig_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    uint8_t *cfg = nullptr;
    uint32_t cfgLen = 0;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.SetEnhanceConfig(cfg, cfgLen));

    uint8_t data = 1;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.SetEnhanceConfig(&data, cfgLen));
}
#endif

/**
 * @tc.name: InputManagerImplTest_SetInputDeviceConsumer
 * @tc.desc: Test SetInputDeviceConsumer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetInputDeviceConsumer, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::vector<std::string> deviceNames;
    deviceNames.push_back("test1");
    deviceNames.push_back("test2");
    std::shared_ptr<IInputEventConsumer> consumer = nullptr;
    auto ret = InputMgrImpl.SetInputDeviceConsumer(deviceNames, consumer);
    ASSERT_NE(ret, RET_OK);
}

/**
 * @tc.name  : SubscribeInputActive_Test001
 * @tc.desc  : Test SubscribeInputActive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, SubscribeInputActive_Test001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    std::shared_ptr<TestInputEventConsumer> inputEventConsumer = std::make_shared<TestInputEventConsumer>();
    EXPECT_NE(inputEventConsumer, nullptr);
    int64_t interval = -1; // ms
    int32_t subscriberId = InputMgrImpl.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), interval);
    EXPECT_LT(subscriberId, 0);

    interval = 0; // ms
    subscriberId = InputMgrImpl.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), interval);
    EXPECT_GE(subscriberId, 0);
    InputMgrImpl.UnsubscribeInputActive(subscriberId);
    interval = 1; // ms
    subscriberId = InputMgrImpl.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), interval);
    EXPECT_GE(subscriberId, 0);
    InputMgrImpl.UnsubscribeInputActive(subscriberId);

    interval = 499; // ms
    subscriberId = InputMgrImpl.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), interval);
    EXPECT_GE(subscriberId, 0);
    InputMgrImpl.UnsubscribeInputActive(subscriberId);

    interval = 500; // ms
    subscriberId = InputMgrImpl.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), interval);
    EXPECT_GE(subscriberId, 0);
    InputMgrImpl.UnsubscribeInputActive(subscriberId);

    interval = 2000; // ms
    subscriberId = InputMgrImpl.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), interval);
    EXPECT_GE(subscriberId, 0);
    InputMgrImpl.UnsubscribeInputActive(subscriberId);

    interval = 2001; // ms
    subscriberId = InputMgrImpl.SubscribeInputActive(
        std::static_pointer_cast<IInputEventConsumer>(inputEventConsumer), interval);
    EXPECT_GE(subscriberId, 0);
    InputMgrImpl.UnsubscribeInputActive(subscriberId);
}

} // namespace MMI
} // namespace OHOS
