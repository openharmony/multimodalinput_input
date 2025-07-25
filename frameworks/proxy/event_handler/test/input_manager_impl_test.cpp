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
#include <gmock/gmock.h>

#include "input_scene_board_judgement.h"
#include "input_manager_impl.h"
#include "multimodal_event_handler.h"
#include "error_multimodal.h"

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
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.OnWindowStateError(pid, windowId));
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
 * @tc.name: InputManagerImplTest_IsPointerVisible_01
 * @tc.desc: Test IsPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsPointerVisible_01, TestSize.Level1)
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_IsPointerVisible_02, TestSize.Level1)
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
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.SetPointerColor(color));
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
    EXPECT_NE(ret, -10);
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
    DisplayGroupInfo displayGroupInfo {};
    InputMgrImpl.userScreenInfo_.displayGroups.push_back(displayGroupInfo);
    EXPECT_TRUE(InputMgrImpl.userScreenInfo_.displayGroups[DEFAULT_GROUP_ID].windowsInfo.empty());
    EXPECT_TRUE(InputMgrImpl.userScreenInfo_.displayGroups[DEFAULT_GROUP_ID].displaysInfo.empty());
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
    DisplayGroupInfo displayGroupInfo {};
    InputMgrImpl.userScreenInfo_.displayGroups.push_back(displayGroupInfo);
    DisplayInfo displayInfo;
    displayInfo.width = 50;
    displayInfo.height = 60;
    InputMgrImpl.userScreenInfo_.displayGroups[DEFAULT_GROUP_ID].displaysInfo.push_back(displayInfo);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 2;
    InputMgrImpl.userScreenInfo_.displayGroups[DEFAULT_GROUP_ID].windowsInfo.push_back(windowInfo);
    EXPECT_FALSE(InputMgrImpl.userScreenInfo_.displayGroups[DEFAULT_GROUP_ID].windowsInfo.empty());

    displayInfo.width = 10;
    displayInfo.height = 20;
    InputMgrImpl.userScreenInfo_.displayGroups[DEFAULT_GROUP_ID].displaysInfo.push_back(displayInfo);
    EXPECT_FALSE(InputMgrImpl.userScreenInfo_.displayGroups[DEFAULT_GROUP_ID].displaysInfo.empty());

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
    InputMgrImpl.userScreenInfo_.displayGroups.push_back(displayGroupInfo);
    InputMgrImpl.userScreenInfo_.displayGroups[DEFAULT_GROUP_ID].displaysInfo.push_back(displayInfo);
    EXPECT_FALSE(InputMgrImpl.userScreenInfo_.displayGroups[DEFAULT_GROUP_ID].displaysInfo.empty());
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
    DisplayGroupInfo displayGroupInfo {};
    InputMgrImpl.userScreenInfo_.displayGroups.push_back(displayGroupInfo);
    DisplayInfo displayInfo;
    displayInfo.width = 50;
    displayInfo.height = 60;
    InputMgrImpl.userScreenInfo_.displayGroups[DEFAULT_GROUP_ID].displaysInfo.push_back(displayInfo);
    WindowInfo windowInfo;
    windowInfo.id = 1;
    windowInfo.pid = 2;
    InputMgrImpl.userScreenInfo_.displayGroups[DEFAULT_GROUP_ID].windowsInfo.push_back(windowInfo);
    EXPECT_FALSE(InputMgrImpl.userScreenInfo_.displayGroups[DEFAULT_GROUP_ID].windowsInfo.empty());
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.OnConnected());
}

/**
 * @tc.name: InputManagerImplTest_OnConnected_05
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnConnected_05, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputMgrImpl.anrObservers_.push_back(nullptr);
    EXPECT_FALSE(InputMgrImpl.anrObservers_.empty());
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.OnConnected());
}
 
/**
 * @tc.name: InputManagerImplTest_OnConnected_06
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnConnected_06, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    class IAnrObserverTest : public IAnrObserver {
    public:
        IAnrObserverTest() : IAnrObserver()
        {}
        virtual ~IAnrObserverTest()
        {}
        void OnAnr(int32_t pid, int32_t eventId) const override
        {
            MMI_HILOGD("Set anr success");
        };
    };
    std::shared_ptr<IAnrObserverTest> observer = std::make_shared<IAnrObserverTest>();
    InputMgrImpl.anrObservers_.push_back(observer);
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.OnConnected());
}
 
/**
 * @tc.name: InputManagerImplTest_OnConnected_07
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnConnected_07, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputMgrImpl.currentUserId_.store(42);
    EXPECT_TRUE(InputMgrImpl.currentUserId_ != -1);
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.OnConnected());
}
 
/**
 * @tc.name: InputManagerImplTest_OnConnected_08
 * @tc.desc: Test OnConnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_OnConnected_08, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    InputMgrImpl.currentUserId_.store(-1);
    EXPECT_TRUE(InputMgrImpl.currentUserId_ == -1);
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_GetTouchpadThreeFingersTapSwitch_001, TestSize.Level1)
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
HWTEST_F(InputManagerImplTest, InputManagerImplTest_SetCurrentUser_001, TestSize.Level1)
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

/**
 * @tc.name: InputManagerImplTest_GetPointerLocation001
 * @tc.desc: Test AboutPoint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_GetPointerLocation001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    int32_t displayId = 0;
    double displayX = 0.0;
    double displayY = 0.0;
    EXPECT_EQ(InputMgrImpl.GetPointerLocation(displayId, displayX, displayY), ERROR_APP_NOT_FOCUSED);
}

/**
 * @tc.name: InputManagerImplTest_TestUpdateDisplayInfo_001
 * @tc.desc: Test UpdateDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestUpdateDisplayInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::MMI::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.width = 1920;
    displayInfo.height = 1080;
    displayInfo.name = "Main Display";
    OHOS::MMI::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.id = 1;
    displayGroupInfo.name = "Main Display Group";
    displayGroupInfo.type = OHOS::MMI::GroupType::GROUP_DEFAULT;
    displayGroupInfo.focusWindowId = 1;
    displayGroupInfo.mainDisplayId = displayInfo.id;
    displayGroupInfo.displaysInfo.push_back(displayInfo);
    OHOS::MMI::UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 100;
    userScreenInfo.displayGroups.push_back(displayGroupInfo);
    int32_t result = InputMgrImpl.UpdateDisplayInfo(userScreenInfo);
    EXPECT_EQ(result, RET_OK);
}
 
class MockNetPacket : public NetPacket {
public:
    explicit MockNetPacket(MmiMessageId msgId) : NetPacket(msgId) {}
    MOCK_METHOD(bool, Write, (const char* data, size_t size), (override));
};
 
/**
 * @tc.name: InputManagerImplTest_TestPackDisplayData_WriteFailure
 * @tc.desc: Test PackDisplayData_WriteFailure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestPackDisplayData_WriteFailure, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    DisplayGroupInfo group;
    group.id = 1;
    group.name = "MainGroup";
    group.type = GroupType::GROUP_DEFAULT;
    group.mainDisplayId = 2;
    group.focusWindowId = 123;
    group.windowsInfo.push_back(WindowInfo());
    group.displaysInfo.push_back(DisplayInfo());
    DisplayInfo display;
    display.width = 1920;
    display.height = 1080;
    group.displaysInfo.push_back(display);
    WindowInfo window;
    window.groupId = 0;
    window.id = 123;
    group.windowsInfo.push_back(window);
    userScreenInfo.displayGroups.push_back(group);
    userScreenInfo.screens.push_back(ScreenInfo());
    MockNetPacket mock_pkt(MmiMessageId::DISPLAY_INFO);
    EXPECT_CALL(mock_pkt, Write(testing::_, testing::_)).WillRepeatedly(testing::Return(false));
    int32_t result = InputMgrImpl.PackDisplayData(mock_pkt, userScreenInfo);
    EXPECT_EQ(result, RET_OK);
}
 
/**
 * @tc.name: InputManagerImplTest_TestPackWindowInfoReturnsError
 * @tc.desc: Test TestPackWindowInfoReturnsError
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestPackWindowInfoReturnsError, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.id = 101;
    displayGroupInfo.type = GroupType::GROUP_DEFAULT;
    displayGroupInfo.focusWindowId = 123;
    displayGroupInfo.mainDisplayId = 0;
    WindowInfo windowInfo;
    displayGroupInfo.windowsInfo.push_back(windowInfo);
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    userScreenInfo.displayGroups.push_back(displayGroupInfo);
    MockNetPacket mockPacket(MmiMessageId::DISPLAY_INFO);
    int writeCallCount = 0;
    EXPECT_CALL(mockPacket, Write(testing::_, testing::_))
        .WillRepeatedly(testing::Invoke([&writeCallCount](const char*, size_t) {
            bool success = (writeCallCount < 6);
            writeCallCount++;
            return success;
        }));
    int32_t result = InputMgrImpl.PackDisplayData(mockPacket, userScreenInfo);
    EXPECT_NE(result, RET_ERR);
}
 
/**
 * @tc.name: InputManagerImplTest_PrintDisplayInfo_004
 * @tc.desc: Test TestPrintDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_PrintDisplayInfo_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    DisplayGroupInfo group;
    int32_t mainDisplayId = 0;
    group.mainDisplayId = mainDisplayId;
    DisplayInfo displayInfo;
    displayInfo.id = mainDisplayId;
    displayInfo.name = "Display 0";
    displayInfo.width = 1920;
    displayInfo.height = 1080;
    group.displaysInfo.push_back(displayInfo);
    WindowInfo windowInfo;
    windowInfo.id = 123;
    windowInfo.displayId = mainDisplayId;
    group.windowsInfo.push_back(windowInfo);
    userScreenInfo.displayGroups.push_back(group);
    EXPECT_NO_FATAL_FAILURE(InputMgrImpl.PrintDisplayInfo(userScreenInfo));
    DisplayGroupInfo newGroup;
    newGroup.mainDisplayId = 1;
    DisplayInfo newDisplayInfo;
    newDisplayInfo.id = 1;
    newDisplayInfo.name = "Display 1";
    newDisplayInfo.width = 1440;
    newDisplayInfo.height = 900;
    newGroup.displaysInfo.push_back(newDisplayInfo);
    WindowInfo newWindowInfo;
    newWindowInfo.id = 1;
    newWindowInfo.displayId = 1;
    newGroup.windowsInfo.push_back(newWindowInfo);
    userScreenInfo.displayGroups.push_back(newGroup);
    int32_t result = InputMgrImpl.UpdateDisplayInfo(userScreenInfo);
    EXPECT_EQ(result, RET_OK);
}
 
/**
 * @tc.name: InputManagerImplTest_TestPackDisplayData_WriteFailure
 * @tc.desc: Test PackDisplayData_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestPackDisplayData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    DisplayGroupInfo group;
    group.id = 1;
    group.name = "MainGroup";
    group.type = GroupType::GROUP_DEFAULT;
    group.mainDisplayId = 2;
    group.focusWindowId = 123;
    group.windowsInfo.push_back(WindowInfo());
    group.displaysInfo.push_back(DisplayInfo());
    DisplayInfo display;
    display.width = 1920;
    display.height = 1080;
    group.displaysInfo.push_back(display);
    WindowInfo window;
    window.groupId = 1;
    window.id = 123;
    group.windowsInfo.push_back(window);
    userScreenInfo.displayGroups.push_back(group);
    userScreenInfo.screens.push_back(ScreenInfo());
    NetPacket pkt(MmiMessageId::INVALID);
    EXPECT_FALSE(pkt.ChkRWError());
    int32_t r3;
    pkt >> r3;
    EXPECT_TRUE(pkt.ChkRWError());
    auto result = InputMgrImpl.PackDisplayData(pkt, userScreenInfo);
    EXPECT_EQ(result, RET_ERR);
}
 
/**
 * @tc.name: InputManagerImplTest_TestPackScreensInfo
 * @tc.desc: Test PackScreensInfo_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestPackScreensInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket pkt(MmiMessageId::INVALID);
    EXPECT_FALSE(pkt.ChkRWError());
    int32_t r3;
    pkt >> r3;
    EXPECT_TRUE(pkt.ChkRWError());
    std::vector<ScreenInfo> screens;
    auto result = InputMgrImpl.PackScreensInfo(pkt, screens);
    EXPECT_EQ(result, RET_ERR);
}
 
/**
 * @tc.name: InputManagerImplTest_TestPackDisplayGroupsInfo
 * @tc.desc: Test PackDisplayGroupsInfo_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestPackDisplayGroupsInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket pkt(MmiMessageId::INVALID);
    EXPECT_FALSE(pkt.ChkRWError());
    int32_t r3;
    pkt >> r3;
    EXPECT_TRUE(pkt.ChkRWError());
    std::vector<DisplayGroupInfo> group;
    auto result = InputMgrImpl.PackDisplayGroupsInfo(pkt, group);
    EXPECT_EQ(result, RET_ERR);
}
 
/**
 * @tc.name: InputManagerImplTest_TestPackDisplaysInfo
 * @tc.desc: Test PackDisplaysInfo_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestPackDisplaysInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    NetPacket pkt(MmiMessageId::INVALID);
    EXPECT_FALSE(pkt.ChkRWError());
    int32_t r3;
    pkt >> r3;
    EXPECT_TRUE(pkt.ChkRWError());
    std::vector<DisplayInfo> displayInfo;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.PackDisplaysInfo(pkt, displayInfo));
}
 
/**
 * @tc.name: InputManagerImplTest_TestUpdateDisplayInfo_002
 * @tc.desc: Test UpdateDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestUpdateDisplayInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::MMI::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.width = 1920;
    displayInfo.height = 1080;
    displayInfo.name = "Main Display";
    OHOS::MMI::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.id = 1;
    displayGroupInfo.name = "Main Display Group";
    displayGroupInfo.type = OHOS::MMI::GroupType::GROUP_DEFAULT;
    displayGroupInfo.focusWindowId = 1;
    displayGroupInfo.mainDisplayId = displayInfo.id;
    displayGroupInfo.displaysInfo.push_back(displayInfo);
    OHOS::MMI::UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 100;
    userScreenInfo.displayGroups.push_back(displayGroupInfo);
    userScreenInfo.displayGroups.resize(110);
    int32_t result = InputMgrImpl.UpdateDisplayInfo(userScreenInfo);
    EXPECT_EQ(result, RET_ERR);
    userScreenInfo.screens.resize(1100);
    result = InputMgrImpl.UpdateDisplayInfo(userScreenInfo);
    EXPECT_EQ(result, RET_ERR);
}
 
/**
 * @tc.name: InputManagerImplTest_TestPackDisplayData_002
 * @tc.desc: Test PackDisplayData_002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestPackDisplayData_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    std::vector<DisplayGroupInfo> group;
    userScreenInfo.userId = 0;
  
    NetPacket pkt(MmiMessageId::INVALID);
    EXPECT_FALSE(pkt.ChkRWError());
    int32_t r3;
    pkt >> r3;
    EXPECT_TRUE(pkt.ChkRWError());
    auto result = InputMgrImpl.PackDisplayGroupsInfo(pkt, group);
    EXPECT_EQ(result, RET_ERR);
    result = InputMgrImpl.PackDisplayData(pkt, userScreenInfo);
    EXPECT_EQ(result, RET_ERR);
}
 
/**
 * @tc.name: InputManagerImplTest_TestPackDisplayData_003
 * @tc.desc: Test PackDisplayData_003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestPackDisplayData_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    NetPacket pkt(MmiMessageId::INVALID);
    EXPECT_FALSE(pkt.ChkRWError());
    int32_t r3;
    pkt >> r3;
    EXPECT_TRUE(pkt.ChkRWError());
    auto result = InputMgrImpl.PackDisplayData(pkt, userScreenInfo);
    EXPECT_EQ(result, RET_ERR);
}

/**
 * @tc.name: InputManagerImplTest_TestUpdateDisplayInfo_003
 * @tc.desc: Test UpdateDisplayInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestUpdateDisplayInfo_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::MMI::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.width = 1920;
    displayInfo.height = 1080;
    displayInfo.name = "Main Display";
    OHOS::MMI::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.id = 1;
    displayGroupInfo.name = "Main Display Group";
    displayGroupInfo.type = OHOS::MMI::GroupType::GROUP_DEFAULT;
    displayGroupInfo.focusWindowId = 1;
    displayGroupInfo.mainDisplayId = displayInfo.id;
    displayGroupInfo.displaysInfo.push_back(displayInfo);
    OHOS::MMI::UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 100;
    userScreenInfo.displayGroups.push_back(displayGroupInfo);
    userScreenInfo.displayGroups.resize(1110);
    int32_t result = InputMgrImpl.UpdateDisplayInfo(userScreenInfo);
    EXPECT_EQ(result, RET_ERR);
    userScreenInfo.screens.resize(1100);
    result = InputMgrImpl.UpdateDisplayInfo(userScreenInfo);
    EXPECT_EQ(result, RET_ERR);
}
 
 
/**
 * @tc.name: InputManagerImplTest_TestPackDisplayData_004
 * @tc.desc: Test PackDisplayData_004
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestPackDisplayData_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    NetPacket pkt(MmiMessageId::INVALID);
    auto screelet = InputMgrImpl.PackScreensInfo(pkt, userScreenInfo.screens);
    EXPECT_EQ(screelet, RET_OK);
    auto groplet = InputMgrImpl.PackDisplayGroupsInfo(pkt, userScreenInfo.displayGroups);
    EXPECT_EQ(groplet, RET_OK);
    auto result = InputMgrImpl.PackDisplayData(pkt, userScreenInfo);
    EXPECT_EQ(result, RET_OK);
}
 
/**
 * @tc.name: InputManagerImplTest_TestPrintScreens
 * @tc.desc: Test PrintScreens
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestPrintScreens, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.PrintScreens(userScreenInfo.screens));
}
 
/**
 * @tc.name: InputManagerImplTest_TestPrintDisplayGroups
 * @tc.desc: Test PrintDisplayGroups
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestPrintDisplayGroups, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    UserScreenInfo userScreenInfo;
    userScreenInfo.userId = 0;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.PrintDisplayGroups(userScreenInfo.displayGroups));
}
 
/**
 * @tc.name: InputManagerImplTest_TestPrintDisplaysInfo
 * @tc.desc: Test PrintDisplaysInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InputManagerImplTest, InputManagerImplTest_TestPrintDisplaysInfo, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    OHOS::MMI::DisplayInfo displayInfo;
    displayInfo.id = 0;
    displayInfo.width = 1920;
    displayInfo.height = 1080;
    displayInfo.name = "Main Display";
    OHOS::MMI::DisplayGroupInfo displayGroupInfo;
    displayGroupInfo.id = 1;
    displayGroupInfo.name = "Main Display Group";
    displayGroupInfo.type = OHOS::MMI::GroupType::GROUP_DEFAULT;
    displayGroupInfo.focusWindowId = 1;
    displayGroupInfo.mainDisplayId = displayInfo.id;
    displayGroupInfo.displaysInfo.push_back(displayInfo);
    DisplayGroupInfo userScreenInfo;
    ASSERT_NO_FATAL_FAILURE(InputMgrImpl.PrintDisplaysInfo(displayGroupInfo.displaysInfo));
}
} // namespace MMI
} // namespace OHOS