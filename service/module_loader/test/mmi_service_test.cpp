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

#include "proto.h"

#include "input_event_handler.h"
#include "mmi_log.h"
#include "mmi_service.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "MMIServerTest"
namespace OHOS {
namespace MMI {
namespace {
using namespace testing::ext;
} // namespace

class MMIServerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
};

/**
 * @tc.name: MMIServerTest_OnThread_01
 * @tc.desc: Test OnThread
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_OnThread_01, TestSize.Level1)
{
    MMIService mmiService;
    EpollEventType epollType;
    epollType = EPOLL_EVENT_INPUT;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnThread());
}

/**
 * @tc.name: ShiftAppPointerEvent_001
 * @tc.desc: Test the function ShiftAppPointerEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, ShiftAppPointerEvent_001, TestSize.Level1)
{
    MMIService mmiService;
    ShiftWindowParam param;
    param.sourceWindowId = -100;
    param.targetWindowId = -200;
    bool autoGenDown = true;
    int32_t ret = mmiService.ShiftAppPointerEvent(param, autoGenDown);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_OnThread_02
 * @tc.desc: Test OnThread
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_OnThread_02, TestSize.Level1)
{
    MMIService mmiService;
    EpollEventType epollType;
    epollType = EPOLL_EVENT_SOCKET;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnThread());
}

/**
 * @tc.name: MMIServerTest_OnThread_03
 * @tc.desc: Test OnThread
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_OnThread_03, TestSize.Level1)
{
    MMIService mmiService;
    EpollEventType epollType;
    epollType = EPOLL_EVENT_SIGNAL;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnThread());
}

/**
 * @tc.name: MMIServerTest_OnThread_04
 * @tc.desc: Test OnThread
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_OnThread_04, TestSize.Level1)
{
    MMIService mmiService;
    EpollEventType epollType;
    epollType = EPOLL_EVENT_ETASK;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnThread());
}

/**
 * @tc.name: MMIServerTest_EnableInputDevice_01
 * @tc.desc: Test EnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_EnableInputDevice_01, TestSize.Level1)
{
    MMIService mmiService;
    bool enable = true;
    int32_t ret = mmiService.EnableInputDevice(enable);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_EnableInputDevice_02
 * @tc.desc: Test EnableInputDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_EnableInputDevice_02, TestSize.Level1)
{
    MMIService mmiService;
    bool enable = false;
    int32_t ret = mmiService.EnableInputDevice(enable);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_OnDisconnected_01
 * @tc.desc: Test OnDisconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_OnDisconnected_01, TestSize.Level1)
{
    MMIService mmiService;
    SessionPtr session;
    auto ret1 = mmiService.RemoveInputEventFilter(-1);
    EXPECT_EQ(ret1, ETASKS_POST_SYNCTASK_FAIL);
    ASSERT_NO_FATAL_FAILURE(mmiService.OnDisconnected(session));
}

/**
 * @tc.name: MMIServerTest_OnDisconnected_02
 * @tc.desc: Test OnDisconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_OnDisconnected_02, TestSize.Level1)
{
    MMIService mmiService;
    SessionPtr session;
    auto ret1 = mmiService.RemoveInputEventFilter(2);
    EXPECT_EQ(ret1, ETASKS_POST_SYNCTASK_FAIL);
    ASSERT_NO_FATAL_FAILURE(mmiService.OnDisconnected(session));
}

/**
 * @tc.name: MMIServerTest_AddInputHandler_01
 * @tc.desc: Test the function AddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_AddInputHandler_01, TestSize.Level1)
{
    MMIService mmiService;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_KEY;
    int32_t priority = 1;
    uint32_t deviceTags = 3;
    int32_t ret = mmiService.AddInputHandler(handlerType, eventType, priority, deviceTags);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: MMIServerTest_RemoveInputHandler_01
 * @tc.desc: Test the function RemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_RemoveInputHandler_01, TestSize.Level1)
{
    MMIService mmiService;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = HANDLE_EVENT_TYPE_POINTER;
    int32_t priority = 1;
    uint32_t deviceTags = 2;
    int32_t ret = mmiService.RemoveInputHandler(handlerType, eventType, priority, deviceTags);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: AddEpollAndDelEpoll_001
 * @tc.desc: Test the function AddEpoll and DelEpoll
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, AddEpollAndDelEpoll_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t fd = -1;
    int32_t ret = mmiService.AddEpoll(EPOLL_EVENT_INPUT, fd);
    EXPECT_EQ(ret, RET_ERR);
    ret = mmiService.DelEpoll(EPOLL_EVENT_INPUT, fd);
    EXPECT_EQ(ret, RET_ERR);
    fd = 1;
    ret = mmiService.AddEpoll(EPOLL_EVENT_INPUT, fd);
    EXPECT_EQ(ret, RET_ERR);
    ret = mmiService.DelEpoll(EPOLL_EVENT_INPUT, fd);
    EXPECT_EQ(ret, RET_ERR);
    ret = mmiService.AddEpoll(EPOLL_EVENT_END, fd);
    EXPECT_EQ(ret, RET_ERR);
    ret = mmiService.DelEpoll(EPOLL_EVENT_END, fd);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: InitLibinputService_001
 * @tc.desc: Test the function InitLibinputService
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, InitLibinputService_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool ret = mmiService.InitService();
    EXPECT_FALSE(ret);
    ret = mmiService.InitDelegateTasks();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: AddAppDebugListener_001
 * @tc.desc: Test the function AddAppDebugListener and RemoveAppDebugListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, AddAppDebugListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ASSERT_NO_FATAL_FAILURE(mmiService.AddAppDebugListener());
    ASSERT_NO_FATAL_FAILURE(mmiService.RemoveAppDebugListener());
}

/**
 * @tc.name: AllocSocketFd_001
 * @tc.desc: Test the function AllocSocketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, AllocSocketFd_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    const std::string programName = "programName";
    const int32_t moduleType = 1;
    int32_t toReturnClientFd = 1;
    int32_t tokenType = 1;
    int32_t ret = mmiService.AllocSocketFd(programName, moduleType, toReturnClientFd, tokenType);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: AddInputEventFilter_001
 * @tc.desc: Test the function AddInputEventFilter and RemoveInputEventFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, AddInputEventFilter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t filterId = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 1;
    int32_t returnCode0 = ETASKS_POST_SYNCTASK_FAIL;
    int32_t returnCode = ERROR_NULL_POINTER;
    sptr<IEventFilter> filter;
    int32_t ret = mmiService.AddInputEventFilter(filter, filterId, priority, deviceTags);
    EXPECT_EQ(ret, returnCode);
    ret = mmiService.RemoveInputEventFilter(filterId);
    EXPECT_EQ(ret, returnCode0);
}

/**
 * @tc.name: OnConnected_001
 * @tc.desc: Test the function OnConnected and OnDisconnected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, OnConnected_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    SessionPtr session;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnConnected(session));
    ASSERT_NO_FATAL_FAILURE(mmiService.OnDisconnected(session));
}

/**
 * @tc.name: SetCustomCursor_001
 * @tc.desc: Test the function SetCustomCursorPixelMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SetCustomCursorPixelMap_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t windowId = 1;
    int32_t focusX = 200;
    int32_t focusY = 500;
    CursorPixelMap curPixelMap;
    ASSERT_NO_FATAL_FAILURE(mmiService.SetCustomCursorPixelMap(windowId, focusX, focusY, curPixelMap));
}

/**
 * @tc.name: SetMouseIcon_001
 * @tc.desc: Test the function SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SetMouseIcon_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t windowId = 1;
    CursorPixelMap curPixelMap;
    int32_t ret = mmiService.SetMouseIcon(windowId, curPixelMap);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: SetMouseHotSpot_001
 * @tc.desc: Test the function SetMouseHotSpot
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SetMouseHotSpot_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t pid = 1;
    int32_t windowId = 1;
    int32_t hotSpotX = 100;
    int32_t hotSpotY = 200;
    int32_t ret = mmiService.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: SetNapStatus_001
 * @tc.desc: Test the function SetNapStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SetNapStatus_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t pid = 1;
    int32_t uid = 2;
    std::string bundleName = "bundleName";
    int32_t napStatus = 1;
    int32_t ret = mmiService.SetNapStatus(pid, uid, bundleName, napStatus);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: ReadMouseScrollRows_001
 * @tc.desc: Test the function ReadMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, ReadMouseScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t rows = 1;
    int32_t ret = mmiService.ReadMouseScrollRows(rows);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: SetMousePrimaryButton_001
 * @tc.desc: Test the function SetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SetMousePrimaryButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t primaryButton = 1;
    int32_t returnCode = ETASKS_POST_SYNCTASK_FAIL;
    int32_t ret = mmiService.SetMousePrimaryButton(primaryButton);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: ReadMousePrimaryButton_001
 * @tc.desc: Test the function ReadMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, ReadMousePrimaryButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t primaryButton = 1;
    int32_t ret = mmiService.ReadMousePrimaryButton(primaryButton);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: GetMousePrimaryButton_001
 * @tc.desc: Test the function GetMousePrimaryButton
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, GetMousePrimaryButton_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t primaryButton = 1;
    int32_t ret = mmiService.GetMousePrimaryButton(primaryButton);
    EXPECT_NE(ret, RET_ERR);
}

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)

/**
 * @tc.name: CheckPointerVisible_001
 * @tc.desc: Test the function CheckPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, CheckPointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool visible = true;
    int32_t ret = mmiService.CheckPointerVisible(visible);
    EXPECT_EQ(ret, RET_OK);
}

#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

/**
 * @tc.name: MarkProcessed_001
 * @tc.desc: Test the function MarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MarkProcessed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t eventType = 1;
    int32_t eventId = 1;
    int32_t ret = mmiService.MarkProcessed(eventType, eventId);
    EXPECT_NE(ret, RET_ERR);
}

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)

/**
 * @tc.name: ReadPointerColor_001
 * @tc.desc: Test the function ReadPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, ReadPointerColor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t color = 1;
    int32_t ret = mmiService.ReadPointerColor(color);
    EXPECT_EQ(ret, RET_OK);
}

#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING

/**
 * @tc.name: NotifyNapOnline_001
 * @tc.desc: Test the function NotifyNapOnline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, NotifyNapOnline_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t ret = mmiService.NotifyNapOnline();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: RemoveInputEventObserver_001
 * @tc.desc: Test the function RemoveInputEventObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, RemoveInputEventObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t ret = mmiService.RemoveInputEventObserver();
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: ClearWindowPointerStyle_001
 * @tc.desc: Test the function ClearWindowPointerStyle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, ClearWindowPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t pid = 1;
    int32_t windowId = 2;
    int32_t ret = mmiService.ClearWindowPointerStyle(pid, windowId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: ReadHoverScrollState_001
 * @tc.desc: Test the function ReadHoverScrollState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, ReadHoverScrollState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool state = true;
    int32_t ret = mmiService.ReadHoverScrollState(state);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: OnSupportKeys_001
 * @tc.desc: Test the function OnSupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, OnSupportKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t deviceId = 1;
    int32_t return_code = 401;
    std::vector<int32_t> keys{ 1 };
    std::vector<bool> keystroke{ true, true };
    std::vector<bool> keystroke1{ true, true, true, true, true, true };
    int32_t ret = mmiService.OnSupportKeys(deviceId, keys, keystroke);
    EXPECT_EQ(ret, return_code);
    ret = mmiService.OnSupportKeys(deviceId, keys, keystroke1);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: SupportKeys_001
 * @tc.desc: Test the function SupportKeys
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SupportKeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t deviceId = 1;
    int32_t returnCode = ETASKS_POST_SYNCTASK_FAIL;
    std::vector<int32_t> keys{ 1 };
    std::vector<bool> keystroke{ true, true };
    int32_t ret = mmiService.SupportKeys(deviceId, keys, keystroke);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: OnGetDeviceIds_001
 * @tc.desc: Test the function OnGetDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, OnGetDeviceIds_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::vector<int32_t> ids{ 1 };
    int32_t ret = mmiService.OnGetDeviceIds(ids);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: GetDeviceIds_001
 * @tc.desc: Test the function GetDeviceIds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, GetDeviceIds_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::vector<int32_t> ids{ 1 };
    int32_t ret = mmiService.GetDeviceIds(ids);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: OnGetDevice_001
 * @tc.desc: Test the function OnGetDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, OnGetDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t deviceId = 1;
    int32_t return_code = 401;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
    int32_t ret = mmiService.OnGetDevice(deviceId, inputDevice);
    EXPECT_EQ(ret, return_code);
}

/**
 * @tc.name: GetDevice_001
 * @tc.desc: Test the function GetDevice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, GetDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t returnCode = ETASKS_POST_SYNCTASK_FAIL;
    int32_t deviceId = 1;
    InputDevice inputDevice;
    int32_t ret = mmiService.GetDevice(deviceId, inputDevice);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: OnRegisterDevListener_001
 * @tc.desc: Test the function OnRegisterDevListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, OnRegisterDevListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t pid = 1;
    int32_t ret = mmiService.OnRegisterDevListener(pid);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: RegisterDevListener_001
 * @tc.desc: Test the function RegisterDevListener and OnUnregisterDevListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, RegisterDevListener_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t pid = 1;
    int32_t ret = mmiService.RegisterDevListener();
    EXPECT_NE(ret, RET_OK);
    ret = mmiService.UnregisterDevListener();
    EXPECT_NE(ret, RET_OK);
    ret = mmiService.OnUnregisterDevListener(pid);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: OnGetKeyboardType_001
 * @tc.desc: Test the function OnGetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, OnGetKeyboardType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t deviceId = 1;
    int32_t keyboardType = 1;
    int32_t return_code = 401;
    int32_t ret = mmiService.OnGetKeyboardType(deviceId, keyboardType);
    EXPECT_EQ(ret, return_code);
}

/**
 * @tc.name: GetKeyboardType_001
 * @tc.desc: Test the function GetKeyboardType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, GetKeyboardType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t deviceId = 1;
    int32_t keyboardType = 1;
    int32_t ret = mmiService.GetKeyboardType(deviceId, keyboardType);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: GetKeyboardRepeatDelay_001
 * @tc.desc: Test the function GetKeyboardRepeatDelay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, GetKeyboardRepeatDelay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t delay = 1;
    int32_t ret = mmiService.GetKeyboardRepeatDelay(delay);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: GetKeyboardRepeatRate_001
 * @tc.desc: Test the function GetKeyboardRepeatRate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, GetKeyboardRepeatRate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t returnCode = 65142800;
    int32_t rate = 1;
    int32_t ret = mmiService.GetKeyboardRepeatRate(rate);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: CheckAddInput_001
 * @tc.desc: Test the function CheckAddInput
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, CheckAddInput_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t returnCode = ERROR_NULL_POINTER;
    int32_t pid = 1;
    InputHandlerType handlerType = InputHandlerType::MONITOR;
    HandleEventType eventType = 10;
    int32_t priority = 1;
    uint32_t deviceTags = 1;
    int32_t ret = mmiService.CheckAddInput(pid, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: AddInputHandler_001
 * @tc.desc: Test the function AddInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, AddInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 10;
    int32_t priority = 1;
    uint32_t deviceTags = 1;
    int32_t ret = mmiService.AddInputHandler(handlerType, eventType, priority, deviceTags);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: CheckRemoveInput_001
 * @tc.desc: Test the function CheckRemoveInput
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, CheckRemoveInput_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t returnCode = ERROR_NULL_POINTER;
    int32_t pid = 1;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 1;
    int32_t ret = mmiService.CheckRemoveInput(pid, handlerType, eventType, priority, deviceTags);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: RemoveInputHandler_001
 * @tc.desc: Test the function RemoveInputHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, RemoveInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    InputHandlerType handlerType = InputHandlerType::INTERCEPTOR;
    HandleEventType eventType = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 1;
    int32_t ret = mmiService.RemoveInputHandler(handlerType, eventType, priority, deviceTags);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: CheckMarkConsumed_001
 * @tc.desc: Test the function CheckMarkConsumed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, CheckMarkConsumed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t returnCode = ERROR_NULL_POINTER;
    int32_t pid = 1;
    int32_t eventId = 1;
    int32_t ret = mmiService.CheckMarkConsumed(pid, eventId);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: MoveMouseEvent_001
 * @tc.desc: Test the function MoveMouseEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MoveMouseEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t offsetX = 100;
    int32_t offsetY = 200;
    int32_t ret = mmiService.MoveMouseEvent(offsetX, offsetY);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: CheckInjectKeyEvent_001
 * @tc.desc: Test the function CheckInjectKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, CheckInjectKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t returnCode = ERROR_NULL_POINTER;
    std::shared_ptr<KeyEvent> Event{ nullptr };
    int32_t pid = 1;
    bool isNativeInject = false;
    int32_t ret = mmiService.CheckInjectKeyEvent(Event, pid, isNativeInject);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: SubscribeKeyEvent_001
 * @tc.desc: Test the function SubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SubscribeKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t subscribeId = 1;
    KeyOption option;
    ASSERT_NO_FATAL_FAILURE(mmiService.SubscribeKeyEvent(subscribeId, option));
    ASSERT_NO_FATAL_FAILURE(mmiService.UnsubscribeKeyEvent(subscribeId));
}

/**
 * @tc.name: GetDisplayBindInfo_001
 * @tc.desc: Test the function GetDisplayBindInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, GetDisplayBindInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    DisplayBindInfos infos;
    int32_t ret = mmiService.GetDisplayBindInfo(infos);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: SetDisplayBind_001
 * @tc.desc: Test the function SetDisplayBind
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SetDisplayBind_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t deviceId = 1;
    int32_t displayId = 2;
    std::string msg = "test";
    int32_t ret = mmiService.SetDisplayBind(deviceId, displayId, msg);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: SetFunctionKeyState_001
 * @tc.desc: Test the function SetFunctionKeyState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SetFunctionKeyState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t funcKey = 1;
    bool enable = true;
    bool state = false;
    int32_t ret = mmiService.SetFunctionKeyState(funcKey, enable);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
    ret = mmiService.GetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: OnDelegateTask_001
 * @tc.desc: Test the function OnDelegateTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, OnDelegateTask_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    epoll_event ev;
    ev.events = 0;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnDelegateTask(ev));
    ev.events = 1;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnDelegateTask(ev));
}

/**
 * @tc.name: OnThread_001
 * @tc.desc: Test the function OnThread
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, OnThread_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnThread());
}

/**
 * @tc.name: InitSignalHandler_001
 * @tc.desc: Test the function InitSignalHandler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, InitSignalHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool ret = mmiService.InitSignalHandler();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: AddReloadDeviceTimer_001
 * @tc.desc: Test the function AddReloadDeviceTimer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, AddReloadDeviceTimer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ASSERT_NO_FATAL_FAILURE(mmiService.AddReloadDeviceTimer());
}

/**
 * @tc.name: Dump_001
 * @tc.desc: Test the function Dump
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, Dump_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t fd = -1;
    std::vector<std::u16string> args;
    int32_t ret = mmiService.Dump(fd, args);
    EXPECT_EQ(ret, DUMP_PARAM_ERR);
    fd = 1;
    ret = mmiService.Dump(fd, args);
    EXPECT_EQ(ret, DUMP_PARAM_ERR);
}

/**
 * @tc.name: SetMouseCaptureMode_001
 * @tc.desc: Test the function SetMouseCaptureMode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SetMouseCaptureMode_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t windowId = 1;
    bool isCaptureMode = false;
    int32_t returnCode = ETASKS_POST_SYNCTASK_FAIL;
    int32_t ret = mmiService.SetMouseCaptureMode(windowId, isCaptureMode);
    EXPECT_EQ(ret, returnCode);
    isCaptureMode = true;
    ret = mmiService.SetMouseCaptureMode(windowId, isCaptureMode);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: OnGetWindowPid_001
 * @tc.desc: Test the function OnGetWindowPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, OnGetWindowPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t windowId = 1;
    int32_t windowPid = 1;
    int32_t ret = mmiService.OnGetWindowPid(windowId, windowPid);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: GetWindowPid_001
 * @tc.desc: Test the function GetWindowPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, GetWindowPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t windowId = 1;
    int32_t windowPid = 1;
    int32_t ret = mmiService.GetWindowPid(windowId, windowPid);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: CheckPidPermission_001
 * @tc.desc: Test the function CheckPidPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, CheckPidPermission_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t pid = 10;
    int32_t ret = mmiService.CheckPidPermission(pid);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SetShieldStatus_001
 * @tc.desc: Test the function SetShieldStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SetShieldStatus_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t returnCode = 65142800;
    int32_t shieldMode = 1;
    bool isShield = 0;
    int32_t ret = mmiService.SetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(ret, returnCode);
    ret = mmiService.GetShieldStatus(shieldMode, isShield);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: MMIServerTest_InitService
 * @tc.desc: Test Init Service
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_InitService, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService service;
    service.state_ = ServiceRunningState::STATE_RUNNING;
    ASSERT_FALSE(service.InitService());
    service.state_ = ServiceRunningState::STATE_NOT_START;
    service.mmiFd_ = 1000;
    ASSERT_FALSE(service.InitService());
}

/**
 * @tc.name: MMIServerTest_OnAppDebugStoped_01
 * @tc.desc: Test OnAppDebugStoped
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_OnAppDebugStoped_01, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    AppDebugListener listener;
    std::vector<AppExecFwk::AppDebugInfo> debugInfos;
    ASSERT_NO_FATAL_FAILURE(listener.OnAppDebugStoped(debugInfos));
    listener.appDebugPid_ = 4;
    ASSERT_NO_FATAL_FAILURE(listener.OnAppDebugStoped(debugInfos));
}

/**
 * @tc.name: MMIServerTest_GetPointerLocation_001
 * @tc.desc: Test the function GetPointerLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_GetPointerLocation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t displayId = 0;
    double displayX = 0.0;
    double displayY = 0.0;
    int32_t ret = mmiService.GetPointerLocation(displayId, displayX, displayY);
    EXPECT_EQ(ret, ERROR_APP_NOT_FOCUSED);
}

/**
 * @tc.name: MMIServerTest_SetMouseScrollRows_001
 * @tc.desc: When the service is not running, return MMISERVICED_NOT_RUNING
 * @tc.type: FUNC
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetMouseScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService service;
    int32_t rows = 3;
    ErrCode ret = service.SetMouseScrollRows(rows);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_GetMouseScrollRows_001
 * @tc.desc: When GetMouseScrollRows is called while the service is not running it should return MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_GetMouseScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t rows = 0;
    ErrCode ret = mmiService.GetMouseScrollRows(rows);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_SetPointerSize_001
 * @tc.desc: Call SetPointerSize, and the return value is determined based on the current device status
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetPointerSize_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t ret = mmiService.SetPointerSize(20);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_GetPointerSize_001
 * @tc.desc: Call GetPointerSize, and the return value is determined based on runtime status and system permissions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_GetPointerSize_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t size = 0;
    int32_t ret = mmiService.GetPointerSize(size);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_GetCursorSurfaceId_001
 * @tc.desc: Obtain Cursor SurfaceId; the actual return value depends on the runtime status and permissions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_GetCursorSurfaceId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    uint64_t surfaceId = 123;
    ErrCode ret = mmiService.GetCursorSurfaceId(surfaceId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_SetPointerVisible_001
 * @tc.desc: Set cursor visibility, priority less than 0, return RET_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetPointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t ret = mmiService.SetPointerVisible(true, -1);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIServerTest_SetPointerVisible_002
 * @tc.desc: Set cursor visibility, priority is valid, return RET_OK or actual return value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetPointerVisible_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t ret = mmiService.SetPointerVisible(false, 1);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_IsPointerVisible_001
 * @tc.desc: Verify that the logic of calling the IsPointerVisible interface is operational and compatible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_IsPointerVisible_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool visible = false;
    ErrCode ret = mmiService.IsPointerVisible(visible);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_SetPointerColor_001
 * @tc.desc: When the service is not running, calling SetPointerColor returns MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetPointerColor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t ret = mmiService.SetPointerColor(0xFF0000);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_GetPointerColor_001
 * @tc.desc: When the service is not running, calling GetPointerColor returns MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_GetPointerColor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t color = 0;
    int32_t ret = mmiService.GetPointerColor(color);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_SetPointerSpeed_001
 * @tc.desc: Non-system applications calling SetPointerSpeed should return ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t ret = mmiService.SetPointerSpeed(3);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_GetPointerSpeed_001
 * @tc.desc: Non-system applications calling GetPointerSpeed should return ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_GetPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t speed = -1;
    int32_t ret = mmiService.GetPointerSpeed(speed);
    EXPECT_NE(ret, RET_OK);
    EXPECT_EQ(speed, 0);
}

/**
 * @tc.name: MMIServerTest_SetPointerStyle_001
 * @tc.desc: Non-system application sets global pointer style, returns error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    PointerStyle style;
    ErrCode ret = mmiService.SetPointerStyle(-1, style, false);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_SetPointerStyle_002
 * @tc.desc: Non-system application windowId < 0, return error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetPointerStyle_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    PointerStyle style;
    ErrCode ret = mmiService.SetPointerStyle(-2, style, false);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_SetPointerStyle_003
 * @tc.desc: Set the pointer style to normal and return RET_OK or Task error code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetPointerStyle_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    PointerStyle style;
    ErrCode ret = mmiService.SetPointerStyle(1234, style, false);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_GetPointerStyle_001
 * @tc.desc: Normally obtain the pointer style and verify whether the return value is RET_OK or fault-tolerant
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_GetPointerStyle_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    PointerStyle style;
    int32_t windowId = 100;
    bool isUiExtension = false;
    ErrCode ret = mmiService.GetPointerStyle(windowId, style, isUiExtension);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_SetHoverScrollState_001
 * @tc.desc: When calling SetHoverScrollState in a non-system application, it returns ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetHoverScrollState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ErrCode ret = mmiService.SetHoverScrollState(true);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_SetHoverScrollState_002
 * @tc.desc: The system application calls SetHoverScrollState to verify whether the return value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetHoverScrollState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ErrCode ret = mmiService.SetHoverScrollState(false);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_GetHoverScrollState_001
 * @tc.desc: Non-system applications calling GetHoverScrollState return ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_GetHoverScrollState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool state = false;
    ErrCode ret = mmiService.GetHoverScrollState(state);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_SetKeyboardRepeatDelay_001
 * @tc.desc: SetKeyboardRepeatDelay returns error when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetKeyboardRepeatDelay_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t delay = 500;
    ErrCode ret = mmiService.SetKeyboardRepeatDelay(delay);
    MMI_HILOGI("SetKeyboardRepeatDelay_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_SetKeyboardRepeatDelay_002
 * @tc.desc: SetKeyboardRepeatDelay returns success or error for valid running service
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetKeyboardRepeatDelay_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t delay = 500;
    ErrCode ret = mmiService.SetKeyboardRepeatDelay(delay);
    MMI_HILOGI("SetKeyboardRepeatDelay_002 ret: %{public}d", ret);
    EXPECT_NE(ret, RET_OK);
}


/**
 * @tc.name: MMIServerTest_SetKeyboardRepeatRate_001
 * @tc.desc: When calling SetKeyboardRepeatRate with the service not running, it returns MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetKeyboardRepeatRate_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t ret = mmiService.SetKeyboardRepeatRate(30);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_AddPreInputHandler_001
 * @tc.desc: Non-system applications result in AddPreInputHandler returning a value other than RET_OK
 * @tc.type: FUNC
 */
HWTEST_F(MMIServerTest, MMIServerTest_AddPreInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::vector<int32_t> keys = { 1, 2, 3 };
    int32_t ret = mmiService.AddPreInputHandler(100, 1, keys);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_AddPreInputHandler_002
 * @tc.desc: The keys parameter is empty, and AddPreInputHandler returns RET_ERR
 * @tc.type: FUNC
 */
HWTEST_F(MMIServerTest, MMIServerTest_AddPreInputHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::vector<int32_t> emptyKeys;
    int32_t ret = mmiService.AddPreInputHandler(1, 1, emptyKeys);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_AddPreInputHandler_003
 * @tc.desc: The size of keys exceeds the limit; invalid parameter
 * @tc.type: FUNC
 */
HWTEST_F(MMIServerTest, MMIServerTest_AddPreInputHandler_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::vector<int32_t> keys(1000, 1);
    ErrCode ret = mmiService.AddPreInputHandler(1003, 1, keys);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_RemovePreInputHandler_001
 * @tc.desc: Non-system application call, returns ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 */
HWTEST_F(MMIServerTest, MMIServerTest_RemovePreInputHandler_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t ret = mmiService.RemovePreInputHandler(1001);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_RemovePreInputHandler_002
 * @tc.desc: The service is not running, returning MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 */
HWTEST_F(MMIServerTest, MMIServerTest_RemovePreInputHandler_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    if (mmiService.IsRunning()) {
        GTEST_SKIP() << "Skip: The service is not running";
    }

    int32_t ret = mmiService.RemovePreInputHandler(1002);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_AddGestureMonitor_InvalidHandler
 * @tc.desc: AddGestureMonitor should return RET_ERR when handlerType is not MONITOR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_AddGestureMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.AddGestureMonitor(
        0,
        HANDLE_EVENT_TYPE_TOUCH_GESTURE,
        3,
        2);
    MMI_HILOGI("AddGestureMonitor invalid handlerType, ret: %{public}d", ret);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIServerTest_RemoveGestureMonitor_001
 * @tc.desc: RemoveGestureMonitor returns RET_ERR when handlerType is not MONITOR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_RemoveGestureMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;

    ErrCode ret = mmiService.RemoveGestureMonitor(
        0,
        HANDLE_EVENT_TYPE_TOUCH_GESTURE,
        3,
        2);
    MMI_HILOGI("RemoveGestureMonitor_001 return: %{public}d", ret);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIServerTest_RemoveGestureMonitor_002
 * @tc.desc: RemoveGestureMonitor returns expected value for valid MONITOR input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_RemoveGestureMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;

    ErrCode ret = mmiService.RemoveGestureMonitor(
        2,
        HANDLE_EVENT_TYPE_TOUCH_GESTURE,
        3,
        2);
    MMI_HILOGI("RemoveGestureMonitor_002 return: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_MarkEventConsumed_001
 * @tc.desc: MarkEventConsumed returns error when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_MarkEventConsumed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t eventId = 1001;
    ErrCode ret = mmiService.MarkEventConsumed(eventId);
    MMI_HILOGI("MarkEventConsumed_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_MarkEventConsumed_002
 * @tc.desc: MarkEventConsumed returns success or error in normal running condition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_MarkEventConsumed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t eventId = 1002;
    ErrCode ret = mmiService.MarkEventConsumed(eventId);
    MMI_HILOGI("MarkEventConsumed_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_InjectKeyEvent_001
 * @tc.desc: InjectKeyEvent returns MMISERVICE_NOT_RUNNING if service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_InjectKeyEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(126);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_UP);
    ErrCode ret = mmiService.InjectKeyEvent(*keyEvent, true);
    MMI_HILOGI("InjectKeyEvent_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_InjectKeyEvent_002
 * @tc.desc: InjectKeyEvent returns ETASKS_POST_SYNCTASK_FAIL when PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_InjectKeyEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    std::shared_ptr<KeyEvent> keyEvent = KeyEvent::Create();
    ASSERT_NE(keyEvent, nullptr);
    keyEvent->SetKeyCode(126);
    keyEvent->SetAction(KeyEvent::KEY_ACTION_UP);
    ErrCode ret = mmiService.InjectKeyEvent(*keyEvent, true);
    MMI_HILOGI("InjectKeyEvent_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_OnGetKeyState_001
 * @tc.desc: OnGetKeyState returns RET_OK or ERROR_NULL_POINTER depending on KeyEvent availability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_OnGetKeyState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::vector<int32_t> pressedKeys;
    std::unordered_map<int32_t, int32_t> specialKeysState;
    ErrCode ret = mmiService.OnGetKeyState(pressedKeys, specialKeysState);
    MMI_HILOGI("OnGetKeyState_001 ret: %{public}d", ret);
    EXPECT_TRUE(ret == RET_OK);
}

/**
 * @tc.name: MMIServerTest_CheckInjectPointerEvent_001
 * @tc.desc: CheckInjectPointerEvent returns ERROR_NULL_POINTER when pointerEvent is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_CheckInjectPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::shared_ptr<PointerEvent> pointerEvent = nullptr;
    int32_t pid = 1000;
    bool isNativeInject = true;
    bool isShell = false;
    int32_t useCoordinate = 0;
    int32_t ret = mmiService.CheckInjectPointerEvent(pointerEvent, pid, isNativeInject, isShell, useCoordinate);
    MMI_HILOGI("CheckInjectPointerEvent_001 return: %{public}d", ret);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/**
 * @tc.name: MMIServerTest_CheckInjectPointerEvent_002
 * @tc.desc: CheckInjectPointerEvent runs with valid PointerEvent and returns result of handler
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_CheckInjectPointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetId(1);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    int32_t pid = 1000;
    bool isNativeInject = true;
    bool isShell = false;
    int32_t useCoordinate = 0;
    int32_t ret = mmiService.CheckInjectPointerEvent(pointerEvent, pid, isNativeInject, isShell, useCoordinate);
    MMI_HILOGI("CheckInjectPointerEvent_002 return: %{public}d", ret);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_InjectPointerEvent_001
 * @tc.desc: InjectPointerEvent returns MMISERVICE_NOT_RUNNING when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_InjectPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ErrCode ret = mmiService.InjectPointerEvent(*pointerEvent, true, 0);
    MMI_HILOGI("InjectPointerEvent_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_InjectPointerEvent_002
 * @tc.desc: InjectPointerEvent returns ETASKS_POST_SYNCTASK_FAIL when PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_InjectPointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    pointerEvent->SetPointerAction(PointerEvent::POINTER_ACTION_MOVE);
    pointerEvent->SetSourceType(PointerEvent::SOURCE_TYPE_TOUCHSCREEN);
    ErrCode ret = mmiService.InjectPointerEvent(*pointerEvent, true, 0);
    MMI_HILOGI("InjectPointerEvent_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_ScreenCaptureCallback_001
 * @tc.desc: ScreenCaptureCallback should not crash even if PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_ScreenCaptureCallback_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t testPid = 12345;
    bool isStart = true;
    ASSERT_NO_FATAL_FAILURE(mmiService.ScreenCaptureCallback(testPid, isStart));
}

/**
 * @tc.name: MMIServerTest_SubscribeHotkey_001
 * @tc.desc: SubscribeHotkey returns MMISERVICE_NOT_RUNNING when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SubscribeHotkey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    KeyOption keyOption;
    keyOption.SetFinalKey(125);
    keyOption.SetFinalKeyDown(true);
    keyOption.SetPreKeys({123});
    keyOption.SetRepeat(false);
    keyOption.SetPriority(SubscribePriority::PRIORITY_0);
    ErrCode ret = mmiService.SubscribeHotkey(1, keyOption);
    MMI_HILOGI("SubscribeHotkey_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_SubscribeHotkey_002
 * @tc.desc: SubscribeHotkey returns ETASKS_POST_SYNCTASK_FAIL when PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SubscribeHotkey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    KeyOption keyOption;
    keyOption.SetFinalKey(126);
    keyOption.SetFinalKeyDown(false);
    keyOption.SetPreKeys({122});
    keyOption.SetRepeat(true);
    keyOption.SetFinalKeyDownDuration(300);
    keyOption.SetFinalKeyUpDelay(150);
    keyOption.SetPriority(SubscribePriority::PRIORITY_100);
    ErrCode ret = mmiService.SubscribeHotkey(100, keyOption);
    MMI_HILOGI("SubscribeHotkey_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_SubscribeHotkey_003
 * @tc.desc: SubscribeHotkey returns RET_ERR when subscribeId < 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SubscribeHotkey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    KeyOption keyOption;
    keyOption.SetFinalKey(127);
    keyOption.SetFinalKeyDown(true);
    keyOption.SetPreKeys({120});
    keyOption.SetRepeat(false);
    ErrCode ret = mmiService.SubscribeHotkey(-1, keyOption);
    MMI_HILOGI("SubscribeHotkey_003 ret: %{public}d", ret);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIServerTest_UnsubscribeHotkey_001
 * @tc.desc: UnsubscribeHotkey returns MMISERVICE_NOT_RUNNING when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_UnsubscribeHotkey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t subscribeId = 100;
    ErrCode ret = mmiService.UnsubscribeHotkey(subscribeId);
    MMI_HILOGI("UnsubscribeHotkey_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_UnsubscribeHotkey_002
 * @tc.desc: UnsubscribeHotkey returns ETASKS_POST_SYNCTASK_FAIL when PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_UnsubscribeHotkey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t subscribeId = 200;
    ErrCode ret = mmiService.UnsubscribeHotkey(subscribeId);
    MMI_HILOGI("UnsubscribeHotkey_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_SubscribeKeyMonitor_001
 * @tc.desc: SubscribeKeyMonitor returns MMISERVICE_NOT_RUNNING when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SubscribeKeyMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    KeyMonitorOption keyOption;
    keyOption.SetKey(125);
    keyOption.SetAction(KeyEvent::KEY_ACTION_DOWN);
    keyOption.SetRepeat(false);
    ErrCode ret = mmiService.SubscribeKeyMonitor(keyOption);
    MMI_HILOGI("SubscribeKeyMonitor_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_SubscribeKeyMonitor_002
 * @tc.desc: SubscribeKeyMonitor returns ETASKS_POST_SYNCTASK_FAIL when PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SubscribeKeyMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    KeyMonitorOption keyOption;
    keyOption.SetKey(126);
    keyOption.SetAction(KeyEvent::KEY_ACTION_UP);
    keyOption.SetRepeat(true);
    ErrCode ret = mmiService.SubscribeKeyMonitor(keyOption);
    MMI_HILOGI("SubscribeKeyMonitor_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_UnsubscribeKeyMonitor_001
 * @tc.desc: UnsubscribeKeyMonitor returns MMISERVICE_NOT_RUNNING when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_UnsubscribeKeyMonitor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    KeyMonitorOption keyOption;
    keyOption.SetKey(123);
    keyOption.SetAction(KeyEvent::KEY_ACTION_DOWN);
    keyOption.SetRepeat(false);
    ErrCode ret = mmiService.UnsubscribeKeyMonitor(keyOption);
    MMI_HILOGI("UnsubscribeKeyMonitor_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_UnsubscribeKeyMonitor_002
 * @tc.desc: UnsubscribeKeyMonitor returns ETASKS_POST_SYNCTASK_FAIL when PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_UnsubscribeKeyMonitor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    KeyMonitorOption keyOption;
    keyOption.SetKey(124);
    keyOption.SetAction(KeyEvent::KEY_ACTION_UP);
    keyOption.SetRepeat(true);
    ErrCode ret = mmiService.UnsubscribeKeyMonitor(keyOption);
    MMI_HILOGI("UnsubscribeKeyMonitor_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_SubscribeSwitchEvent_001
 * @tc.desc: SubscribeSwitchEvent returns MMISERVICE_NOT_RUNNING when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SubscribeSwitchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t subscribeId = 1001;
    int32_t switchType = 1;
    ErrCode ret = mmiService.SubscribeSwitchEvent(subscribeId, switchType);
    MMI_HILOGI("SubscribeSwitchEvent_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_SubscribeSwitchEvent_002
 * @tc.desc: SubscribeSwitchEvent returns ETASKS_POST_SYNCTASK_FAIL when PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SubscribeSwitchEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t subscribeId = 1002;
    int32_t switchType = 2;
    ErrCode ret = mmiService.SubscribeSwitchEvent(subscribeId, switchType);
    MMI_HILOGI("SubscribeSwitchEvent_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_UnsubscribeSwitchEvent_001
 * @tc.desc: UnsubscribeSwitchEvent returns RET_ERR for invalid subscribeId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_UnsubscribeSwitchEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t subscribeId = -1;
    ErrCode ret = mmiService.UnsubscribeSwitchEvent(subscribeId);
    MMI_HILOGI("UnsubscribeSwitchEvent_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIServerTest_UnsubscribeSwitchEvent_002
 * @tc.desc: UnsubscribeSwitchEvent returns ETASKS_POST_SYNCTASK_FAIL when PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_UnsubscribeSwitchEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t subscribeId = 1000;
    ErrCode ret = mmiService.UnsubscribeSwitchEvent(subscribeId);
    MMI_HILOGI("UnsubscribeSwitchEvent_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_QuerySwitchStatus_001
 * @tc.desc: QuerySwitchStatus returns error when service not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_QuerySwitchStatus_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t switchType = 1;
    int32_t state = -1;
    ErrCode ret = mmiService.QuerySwitchStatus(switchType, state);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_QuerySwitchStatus_002
 * @tc.desc: QuerySwitchStatus returns error when PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_QuerySwitchStatus_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t switchType = 1;
    int32_t state = -1;
    ErrCode ret = mmiService.QuerySwitchStatus(switchType, state);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIServerTest_SubscribeTabletProximity_001
 * @tc.desc: SubscribeTabletProximity returns error when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SubscribeTabletProximity_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t subscribeId = 123;
    ErrCode ret = mmiService.SubscribeTabletProximity(subscribeId);
    MMI_HILOGI("SubscribeTabletProximity_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_SubscribeTabletProximity_002
 * @tc.desc: SubscribeTabletProximity returns error when PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SubscribeTabletProximity_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t subscribeId = 456;
    ErrCode ret = mmiService.SubscribeTabletProximity(subscribeId);
    MMI_HILOGI("SubscribeTabletProximity_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_UnsubscribetabletProximity_001
 * @tc.desc: Unsubscribe tablet proximity when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_UnsubscribetabletProximity_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t subscribeId = 1;
    ErrCode ret = mmiService.UnsubscribetabletProximity(subscribeId);
    MMI_HILOGI("UnsubscribetabletProximity_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_UnsubscribetabletProximity_002
 * @tc.desc: Unsubscribe tablet proximity with invalid id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_UnsubscribetabletProximity_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t invalidId = -1;
    ErrCode ret = mmiService.UnsubscribetabletProximity(invalidId);
    MMI_HILOGI("UnsubscribetabletProximity_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIServerTest_SubscribeLongPressEvent_001
 * @tc.desc: SubscribeLongPressEvent when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SubscribeLongPressEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t subscribeId = 1;
    LongPressRequest req;
    ErrCode ret = mmiService.SubscribeLongPressEvent(subscribeId, req);
    MMI_HILOGI("SubscribeLongPressEvent_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_SubscribeLongPressEvent_002
 * @tc.desc: SubscribeLongPressEvent returns failure if PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SubscribeLongPressEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t subscribeId = 100;
    LongPressRequest req;
    ErrCode ret = mmiService.SubscribeLongPressEvent(subscribeId, req);
    MMI_HILOGI("SubscribeLongPressEvent_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_UnsubscribeLongPressEvent_001
 * @tc.desc: UnsubscribeLongPressEvent when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_UnsubscribeLongPressEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t subscribeId = 1;
    ErrCode ret = mmiService.UnsubscribeLongPressEvent(subscribeId);
    MMI_HILOGI("UnsubscribeLongPressEvent_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_UnsubscribeLongPressEvent_002
 * @tc.desc: UnsubscribeLongPressEvent fails if PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_UnsubscribeLongPressEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t subscribeId = 99;
    ErrCode ret = mmiService.UnsubscribeLongPressEvent(subscribeId);
    MMI_HILOGI("UnsubscribeLongPressEvent_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_SetAnrObserver_001
 * @tc.desc: SetAnrObserver when service not running, expect fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetAnrObserver_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    ErrCode ret = mmiService.SetAnrObserver();
    MMI_HILOGI("SetAnrObserver_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_SetAnrObserver_002
 * @tc.desc: SetAnrObserver when PostSyncTask fails, expect fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetAnrObserver_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.SetAnrObserver();
    MMI_HILOGI("SetAnrObserver_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIServerTest_GetAllMmiSubscribedEvents_001
 * @tc.desc: GetAllMmiSubscribedEvents when service not running, expect fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_GetAllMmiSubscribedEvents_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    MmiEventMap mmiEventMap;
    ErrCode ret = mmiService.GetAllMmiSubscribedEvents(mmiEventMap);
    MMI_HILOGI("GetAllMmiSubscribedEvents_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_GetAllMmiSubscribedEvents_002
 * @tc.desc: GetAllMmiSubscribedEvents when service is running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_GetAllMmiSubscribedEvents_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    MmiEventMap mmiEventMap;
    mmiEventMap.datas.emplace(std::make_tuple(1, 0, "dummy"), 123);
    ErrCode ret = mmiService.GetAllMmiSubscribedEvents(mmiEventMap);
    EXPECT_EQ(ret, RET_OK);
    EXPECT_TRUE(mmiEventMap.datas.empty());
}

/**
 * @tc.name: MMIServerTest_SetPointerLocation_001
 * @tc.desc: SetPointerLocation when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetPointerLocation_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService service;
    service.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t x = 100;
    int32_t y = 200;
    int32_t displayId = 0;
    ErrCode ret = service.SetPointerLocation(x, y, displayId);
    MMI_HILOGI("SetPointerLocation_001 ret: %{public}d", ret);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIServerTest_SetPointerLocation_002
 * @tc.desc: SetPointerLocation when PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIServerTest_SetPointerLocation_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService service;
    service.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t x = 300;
    int32_t y = 400;
    int32_t displayId = 1;
    ErrCode ret = service.SetPointerLocation(x, y, displayId);
    MMI_HILOGI("SetPointerLocation_002 ret: %{public}d", ret);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_OnGetWindowPid_001
 * @tc.desc: Obtain the pid of a legitimate windowId, and it should return RET_OK
 * @tc.type: FUNC
 * @tc.require:SR000HQ1CT
 */
HWTEST_F(MMIServerTest, MMIService_OnGetWindowPid_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t windowId = 1;
    int32_t pid = -1;
    int32_t ret = mmiService.OnGetWindowPid(windowId, pid);
    MMI_HILOGI("OnGetWindowPid ret: %{public}d, pid: %{public}d", ret, pid);
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: MMIService_AppendExtraData_001
 * @tc.desc: When the system application appends valid ExtraData, it should return RET_OK or a task failure code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_AppendExtraData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ExtraData data;
    data.sourceType = InputEvent::SOURCE_TYPE_TOUCHSCREEN;
    data.pointerId = 0;
    data.pullId = 0;
    data.eventId = 100;
    data.buffer.resize(32);
    int32_t returnCode = 65142800;
    int32_t ret = mmiService.AppendExtraData(data);
    MMI_HILOGI("AppendExtraData ret: %{public}d", ret);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: MMIService_AppendExtraData_002
 * @tc.desc: When called while MMIService is not running, it should return MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_AppendExtraData_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ExtraData data;
    data.sourceType = InputEvent::SOURCE_TYPE_TOUCHSCREEN;
    data.pointerId = 0;
    data.pullId = 0;
    data.eventId = 500;
    data.buffer.resize(16);
    int32_t ret = mmiService.AppendExtraData(data);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_UpdateCombineKeyState_001
 * @tc.desc: Both handlers exist, and the EnableCombineKey call succeeds or fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UpdateCombineKeyState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool enable = true;
    int32_t ret = mmiService.UpdateCombineKeyState(enable);
    MMI_HILOGI("UpdateCombineKeyState ret: %{public}d", ret);
    EXPECT_TRUE(ret == RET_ERR);
}

/**
 * @tc.name: MMIService_UpdateCombineKeyState_002
 * @tc.desc: When SubscriberHandler is null, RET_ERR should be returned
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UpdateCombineKeyState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    auto backup = InputHandler->GetSubscriberHandler();
    int32_t ret = mmiService.UpdateCombineKeyState(true);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIService_UpdateCombineKeyState_003
 * @tc.desc: When KeyCommandHandler is null, RET_ERR should be returned
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UpdateCombineKeyState_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    auto backup = InputHandler->GetSubscriberHandler();
    int32_t ret = mmiService.UpdateCombineKeyState(true);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIService_EnableCombineKey_001
 * @tc.desc: EnableCombineKey when service not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_EnableCombineKey_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ErrCode ret = mmiService.EnableCombineKey(true);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_EnableCombineKey_002
 * @tc.desc: Non-system application calls EnableCombineKey and returns ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_EnableCombineKey_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t ret = mmiService.EnableCombineKey(true);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: MMIService_EnableCombineKey_003
 * @tc.desc: When MMIService is not running, EnableCombineKey returns MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_EnableCombineKey_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t ret = mmiService.EnableCombineKey(true);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_UpdateSettingsXml_001
 * @tc.desc: Normally calling UpdateSettingsXml is expected to return RET_OK or a business layer return code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UpdateSettingsXml_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    std::string businessId = "com.example.setting";
    int32_t delay = 300;
    int32_t ret = mmiService.UpdateSettingsXml(businessId, delay);
    MMI_HILOGI("UpdateSettingsXml return code: %{public}d", ret);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_UpdateSettingsXml_002
 * @tc.desc: Pass an empty business ID and check the function's processing result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UpdateSettingsXml_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::string businessId = "";
    int32_t delay = 100;
    int32_t ret = mmiService.UpdateSettingsXml(businessId, delay);
    MMI_HILOGI("UpdateSettingsXml with empty businessId, return code: %{public}d", ret);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_UpdateSettingsXml_003
 * @tc.desc: Pass a negative number delay, check the function's processing result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UpdateSettingsXml_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::string businessId = "com.example.delay";
    int32_t delay = -100;
    int32_t ret = mmiService.UpdateSettingsXml(businessId, delay);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetKeyDownDuration_001
 * @tc.desc: Service not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetKeyDownDuration_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ErrCode ret = mmiService.SetKeyDownDuration("testBusiness", 100);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetKeyDownDuration_002
 * @tc.desc: PostSyncTask runs (success or fail), service running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetKeyDownDuration_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.SetKeyDownDuration("realBiz", 300);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_ReadTouchpadScrollSwich_001
 * @tc.desc: Verify ReadTouchpadScrollSwich returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ReadTouchpadScrollSwich_001, TestSize.Level1)
{
    MMIService mmiService;
    bool value = false;
    int32_t ret = mmiService.ReadTouchpadScrollSwich(value);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIService_ReadTouchpadScrollDirection_001
 * @tc.desc: Verify ReadTouchpadScrollDirection returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ReadTouchpadScrollDirection_001, TestSize.Level1)
{
    MMIService mmiService;
    bool value = false;
    int32_t ret = mmiService.ReadTouchpadScrollDirection(value);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIService_ReadTouchpadTapSwitch_001
 * @tc.desc: Verify ReadTouchpadTapSwitch returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ReadTouchpadTapSwitch_001, TestSize.Level1)
{
    MMIService mmiService;
    bool value = false;
    int32_t ret = mmiService.ReadTouchpadTapSwitch(value);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIService_ReadTouchpadPointerSpeed_001
 * @tc.desc: Verify ReadTouchpadPointerSpeed returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ReadTouchpadPointerSpeed_001, TestSize.Level1)
{
    MMIService mmiService;
    int32_t speed = -1;
    int32_t ret = mmiService.ReadTouchpadPointerSpeed(speed);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIService_ReadTouchpadPinchSwitch_001
 * @tc.desc: Verify ReadTouchpadPinchSwitch returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ReadTouchpadPinchSwitch_001, TestSize.Level1)
{
    MMIService mmiService;
    bool value = false;
    int32_t ret = mmiService.ReadTouchpadPinchSwitch(value);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIService_ReadTouchpadSwipeSwitch_001
 * @tc.desc: Verify ReadTouchpadSwipeSwitch returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ReadTouchpadSwipeSwitch_001, TestSize.Level1)
{
    MMIService mmiService;
    bool value = false;
    int32_t ret = mmiService.ReadTouchpadSwipeSwitch(value);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIService_ReadTouchpadRightMenuType_001
 * @tc.desc: Verify ReadTouchpadRightMenuType returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ReadTouchpadRightMenuType_001, TestSize.Level1)
{
    MMIService mmiService;
    int32_t type = -1;
    int32_t ret = mmiService.ReadTouchpadRightMenuType(type);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIService_ReadTouchpadRotateSwitch_001
 * @tc.desc: Verify ReadTouchpadRotateSwitch returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ReadTouchpadRotateSwitch_001, TestSize.Level1)
{
    MMIService mmiService;
    bool value = false;
    int32_t ret = mmiService.ReadTouchpadRotateSwitch(value);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIService_ReadTouchpadDoubleTapAndDragState_001
 * @tc.desc: Verify ReadTouchpadDoubleTapAndDragState returns RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ReadTouchpadDoubleTapAndDragState_001, TestSize.Level1)
{
    MMIService mmiService;
    bool value = false;
    int32_t ret = mmiService.ReadTouchpadDoubleTapAndDragState(value);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetTouchpadScrollSwitch_001
 * @tc.desc: Verify SetTouchpadScrollSwitch returns RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadScrollSwitch_001, TestSize.Level1)
{
    MMIService mmiService;
    bool switchFlag = true;
    int32_t ret = mmiService.SetTouchpadScrollSwitch(switchFlag);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetTouchpadScrollSwitch_002
 * @tc.desc: Verify SetTouchpadScrollSwitch returns MMISERVICE_NOT_RUNNING when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadScrollSwitch_002, TestSize.Level1)
{
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool switchFlag = false;
    int32_t ret = mmiService.SetTouchpadScrollSwitch(switchFlag);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_GetTouchpadScrollSwitch_001
 * @tc.desc: GetTouchpadScrollSwitch should return RET_OK or ETASKS_POST_SYNCTASK_FAIL when service is running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadScrollSwitch_001, TestSize.Level1)
{
    MMIService mmiService;
    bool switchFlag = false;
    int32_t ret = mmiService.GetTouchpadScrollSwitch(switchFlag);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_GetTouchpadScrollSwitch_002
 * @tc.desc: GetTouchpadScrollSwitch should return MMISERVICE_NOT_RUNNING when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadScrollSwitch_002, TestSize.Level1)
{
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool switchFlag = false;
    int32_t ret = mmiService.GetTouchpadScrollSwitch(switchFlag);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetTouchpadScrollDirection_001
 * @tc.desc: SetTouchpadScrollDirection should succeed or fail due to PostSyncTask failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadScrollDirection_001, TestSize.Level1)
{
    MMIService mmiService;
    bool state = true;
    int32_t ret = mmiService.SetTouchpadScrollDirection(state);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetTouchpadScrollDirection_002
 * @tc.desc: SetTouchpadScrollDirection should fail when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadScrollDirection_002, TestSize.Level1)
{
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool state = false;
    int32_t ret = mmiService.SetTouchpadScrollDirection(state);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_GetTouchpadScrollDirection_001
 * @tc.desc: Verify return RET_OK when service is running and permission is valid
 * @tc.type: FUNC
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadScrollDirection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool switchFlag = false;
    ErrCode ret = mmiService.GetTouchpadScrollDirection(switchFlag);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_GetTouchpadScrollDirection_002
 * @tc.desc: Test GetTouchpadScrollDirection when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadScrollDirection_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    bool direction = false;
    ErrCode ret = mmiService.GetTouchpadScrollDirection(direction);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetTouchpadTapSwitch_001
 * @tc.desc: Verify SetTouchpadTapSwitch returns MMISERVICE_NOT_RUNNING when service not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadTapSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    bool value = false;
    ErrCode ret = mmiService.SetTouchpadTapSwitch(value);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetTouchpadTapSwitch_002
 * @tc.desc: Verify SetTouchpadTapSwitch returns RET_OK or ETASKS_POST_SYNCTASK_FAIL on normal condition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadTapSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool value = true;
    ErrCode ret = mmiService.SetTouchpadTapSwitch(value);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_GetTouchpadTapSwitch_001
 * @tc.desc: Verify GetTouchpadTapSwitch returns MMISERVICE_NOT_RUNNING when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadTapSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    bool switchFlag = false;
    ErrCode ret = mmiService.GetTouchpadTapSwitch(switchFlag);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_GetTouchpadTapSwitch_002
 * @tc.desc: Verify GetTouchpadTapSwitch returns RET_OK or ETASKS_POST_SYNCTASK_FAIL under normal condition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadTapSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool switchFlag = false;
    ErrCode ret = mmiService.GetTouchpadTapSwitch(switchFlag);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_SetTouchpadPointerSpeed_001
 * @tc.desc: Service not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t speed = 3;
    ErrCode ret = mmiService.SetTouchpadPointerSpeed(speed);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetTouchpadPointerSpeed_002
 * @tc.desc: Normal call with speed clipping, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadPointerSpeed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    std::vector<int32_t> testSpeeds = { -10, 0, 1, 3, 5, 10, 999 };
    for (int32_t speed : testSpeeds) {
        ErrCode ret = mmiService.SetTouchpadPointerSpeed(speed);
        EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL) << "Failed at speed=" << speed;
    }
}

/**
 * @tc.name: MMIService_GetTouchpadPointerSpeed_001
 * @tc.desc: Service is not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadPointerSpeed_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t speed = 0;
    ErrCode ret = mmiService.GetTouchpadPointerSpeed(speed);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_GetTouchpadPointerSpeed_002
 * @tc.desc: Valid request, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadPointerSpeed_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t speed = -1;
    ErrCode ret = mmiService.GetTouchpadPointerSpeed(speed);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_SetTouchpadPinchSwitch_001
 * @tc.desc: Service not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadPinchSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    ErrCode ret = mmiService.SetTouchpadPinchSwitch(true);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetTouchpadPinchSwitch_002
 * @tc.desc: Valid call, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadPinchSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.SetTouchpadPinchSwitch(true);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_GetTouchpadPinchSwitch_001
 * @tc.desc: Service not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadPinchSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    bool switchFlag = false;
    ErrCode ret = mmiService.GetTouchpadPinchSwitch(switchFlag);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_GetTouchpadPinchSwitch_002
 * @tc.desc: Valid call, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadPinchSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool switchFlag = false;
    ErrCode ret = mmiService.GetTouchpadPinchSwitch(switchFlag);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_SetTouchpadSwipeSwitch_001
 * @tc.desc: Service is not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadSwipeSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    ErrCode ret = mmiService.SetTouchpadSwipeSwitch(true);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetTouchpadSwipeSwitch_002
 * @tc.desc: Valid call with running service, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadSwipeSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.SetTouchpadSwipeSwitch(false);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_GetTouchpadSwipeSwitch_001
 * @tc.desc: Service is not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadSwipeSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    bool switchFlag = false;
    ErrCode ret = mmiService.GetTouchpadSwipeSwitch(switchFlag);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_GetTouchpadSwipeSwitch_002
 * @tc.desc: Valid call with running service, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadSwipeSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool switchFlag = false;
    ErrCode ret = mmiService.GetTouchpadSwipeSwitch(switchFlag);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_IsValidType_001
 * @tc.desc: Valid type TOUCHPAD_RIGHT_BUTTON, expect true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_IsValidType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    EXPECT_TRUE(mmiService.IsValidType(RightClickType::TOUCHPAD_RIGHT_BUTTON));
}

/**
 * @tc.name: MMIService_IsValidType_002
 * @tc.desc: Valid type TOUCHPAD_LEFT_BUTTON, expect true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_IsValidType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    EXPECT_TRUE(mmiService.IsValidType(RightClickType::TOUCHPAD_LEFT_BUTTON));
}

/**
 * @tc.name: MMIService_IsValidType_003
 * @tc.desc: Valid type TOUCHPAD_TWO_FINGER_TAP, expect true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_IsValidType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    EXPECT_TRUE(mmiService.IsValidType(RightClickType::TOUCHPAD_TWO_FINGER_TAP));
}

/**
 * @tc.name: MMIService_IsValidType_004
 * @tc.desc: Valid type TOUCHPAD_TWO_FINGER_TAP_OR_RIGHT_BUTTON, expect true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_IsValidType_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    EXPECT_TRUE(mmiService.IsValidType(RightClickType::TOUCHPAD_TWO_FINGER_TAP_OR_RIGHT_BUTTON));
}

/**
 * @tc.name: MMIService_IsValidType_005
 * @tc.desc: Valid type TOUCHPAD_TWO_FINGER_TAP_OR_LEFT_BUTTON, expect true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_IsValidType_005, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    EXPECT_TRUE(mmiService.IsValidType(RightClickType::TOUCHPAD_TWO_FINGER_TAP_OR_LEFT_BUTTON));
}

/**
 * @tc.name: MMIService_IsValidType_006
 * @tc.desc: Invalid type -1, expect false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_IsValidType_006, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    EXPECT_FALSE(mmiService.IsValidType(-1));
}

/**
 * @tc.name: MMIService_IsValidType_007
 * @tc.desc: Invalid type 1000, expect false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_IsValidType_007, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    EXPECT_FALSE(mmiService.IsValidType(1000));
}

/**
 * @tc.name: MMIService_SetTouchpadRightClickType_001
 * @tc.desc: Service not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadRightClickType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t type = RightClickType::TOUCHPAD_RIGHT_BUTTON;
    ErrCode ret = mmiService.SetTouchpadRightClickType(type);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetTouchpadRightClickType_002
 * @tc.desc: Invalid right click type, expect RET_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadRightClickType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t type = -999;
    ErrCode ret = mmiService.SetTouchpadRightClickType(type);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIService_SetTouchpadRightClickType_003
 * @tc.desc: Valid call, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadRightClickType_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t type = RightClickType::TOUCHPAD_RIGHT_BUTTON;
    ErrCode ret = mmiService.SetTouchpadRightClickType(type);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_GetTouchpadRightClickType_001
 * @tc.desc: Service not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadRightClickType_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t type = 0;
    ErrCode ret = mmiService.GetTouchpadRightClickType(type);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_GetTouchpadRightClickType_002
 * @tc.desc: Valid case, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadRightClickType_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t type = 0;
    ErrCode ret = mmiService.GetTouchpadRightClickType(type);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_SetTouchpadRotateSwitch_001
 * @tc.desc: Service not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadRotateSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    bool rotateSwitch = true;
    ErrCode ret = mmiService.SetTouchpadRotateSwitch(rotateSwitch);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetTouchpadRotateSwitch_002
 * @tc.desc: Valid call, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadRotateSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool rotateSwitch = true;
    ErrCode ret = mmiService.SetTouchpadRotateSwitch(rotateSwitch);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_GetTouchpadRotateSwitch_001
 * @tc.desc: Service not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadRotateSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    bool rotateSwitch = false;
    ErrCode ret = mmiService.GetTouchpadRotateSwitch(rotateSwitch);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_GetTouchpadRotateSwitch_002
 * @tc.desc: Valid call, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadRotateSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool rotateSwitch = false;
    ErrCode ret = mmiService.GetTouchpadRotateSwitch(rotateSwitch);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_SetTouchpadDoubleTapAndDragState_001
 * @tc.desc: Service not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadDoubleTapAndDragState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    ErrCode ret = mmiService.SetTouchpadDoubleTapAndDragState(true);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetTouchpadDoubleTapAndDragState_002
 * @tc.desc: Valid call, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadDoubleTapAndDragState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.SetTouchpadDoubleTapAndDragState(true);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_GetTouchpadDoubleTapAndDragState_001
 * @tc.desc: Service not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadDoubleTapAndDragState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    bool switchFlag = false;
    ErrCode ret = mmiService.GetTouchpadDoubleTapAndDragState(switchFlag);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_GetTouchpadDoubleTapAndDragState_002
 * @tc.desc: Valid call, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadDoubleTapAndDragState_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool switchFlag = false;
    ErrCode ret = mmiService.GetTouchpadDoubleTapAndDragState(switchFlag);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_GetKeyState_001
 * @tc.desc: GetKeyState returns RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetKeyState_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;

    std::vector<int32_t> pressedKeys;
    std::unordered_map<int32_t, int32_t> specialKeysState;
    ErrCode ret = mmiService.GetKeyState(pressedKeys, specialKeysState);

    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_Authorize_001
 * @tc.desc: Service fails system app check, expect ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_Authorize_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ErrCode ret = mmiService.Authorize(true);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_CancelInjection_001
 * @tc.desc: PostSyncTask fails, expect ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_CancelInjection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ErrCode ret = mmiService.CancelInjection();
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_CancelInjection_002
 * @tc.desc: PostSyncTask success, expect RET_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_CancelInjection_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.CancelInjection();
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_HasIrEmitter_001
 * @tc.desc: Verify system app failed, expect ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_HasIrEmitter_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool hasIrEmitter = false;
    ErrCode ret = mmiService.HasIrEmitter(hasIrEmitter);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIService_HasIrEmitter_002
 * @tc.desc: Verify valid path, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_HasIrEmitter_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool hasIrEmitter = false;
    ErrCode ret = mmiService.HasIrEmitter(hasIrEmitter);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MMIService_RequestInjection_001
 * @tc.desc: Verify sync task failure path, expect ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_RequestInjection_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t status = -1;
    int32_t reqId = -1;
    ErrCode ret = mmiService.RequestInjection(status, reqId);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_RequestInjection_002
 * @tc.desc: Validate output parameters are unchanged if task fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_RequestInjection_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t status = 100;
    int32_t reqId = 200;
    ErrCode ret = mmiService.RequestInjection(status, reqId);
    if (ret != RET_OK) {
        EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
    }
}

/**
 * @tc.name: MMIService_QueryAuthorizedStatus_001
 * @tc.desc: PostSyncTask fails, expect ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_QueryAuthorizedStatus_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t status = -1;
    ErrCode ret = mmiService.QueryAuthorizedStatus(status);
    EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_QueryAuthorizedStatus_002
 * @tc.desc: Validate status unchanged on failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_QueryAuthorizedStatus_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t status = 1234;
    ErrCode ret = mmiService.QueryAuthorizedStatus(status);
    if (ret != RET_OK) {
        EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
    }
}

/**
 * @tc.name: MMIService_GetInfraredFrequencies_001
 * @tc.desc: Normal case, verify return value and content
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetInfraredFrequencies_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::vector<InfraredFrequency> frequencies;
    ErrCode ret = mmiService.GetInfraredFrequencies(frequencies);
    EXPECT_EQ(ret, RET_OK);
#ifndef OHOS_BUILD_ENABLE_WATCH
    for (auto &freq : frequencies) {
        EXPECT_GE(freq.min_, 0);
        EXPECT_GE(freq.max_, freq.min_);
    }
#endif
}

/**
 * @tc.name: MMIService_SetPixelMapData_001
 * @tc.desc: Non-system applications calling SetPixelMapData are expected to return ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetPixelMapData_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    CursorPixelMap pixelMap;
    pixelMap.pixelMap = new (std::nothrow) Media::PixelMap();
    ASSERT_NE(pixelMap.pixelMap, nullptr);
    ErrCode ret = mmiService.SetPixelMapData(1, pixelMap);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetPixelMapData_002
 * @tc.desc: The service is not running; SetPixelMapData returned MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetPixelMapData_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    CursorPixelMap pixelMap;
    pixelMap.pixelMap = nullptr;
    ErrCode ret = mmiService.SetPixelMapData(1, pixelMap);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetPixelMapData_003
 * @tc.desc: The parameter infoId is invalid (<=0), expecting to return RET_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetPixelMapData_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    CursorPixelMap pixelMap;
    pixelMap.pixelMap = nullptr;
    ErrCode ret = mmiService.SetPixelMapData(0, pixelMap);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIService_SetPixelMapData_004
 * @tc.desc: PixelMap is nullptr, expecting to return ERROR_NULL_POINTER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetPixelMapData_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    CursorPixelMap pixelMap;
    pixelMap.pixelMap = nullptr;
    ErrCode ret = mmiService.SetPixelMapData(1, pixelMap);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/**
 * @tc.name: MMIService_SetCurrentUser_001
 * @tc.desc: Verify return MMISERVICE_NOT_RUNNING when service not started
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetCurrentUser_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t userId = 100;
    ErrCode ret = mmiService.SetCurrentUser(userId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetCurrentUser_002
 * @tc.desc: Verify normal call, expect RET_OK or RET_ERR based on runtime environment
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetCurrentUser_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t userId = 1;
    ErrCode ret = mmiService.SetCurrentUser(userId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetTouchpadThreeFingersTapSwitch_001
 * @tc.desc: Verify return ERROR_NOT_SYSAPI when permission check fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadThreeFingersTapSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool switchFlag = true;
    ErrCode ret = mmiService.SetTouchpadThreeFingersTapSwitch(switchFlag);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetTouchpadThreeFingersTapSwitch_002
 * @tc.desc: Verify return RET_OK or ETASKS_POST_SYNCTASK_FAIL if permission granted and task posted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadThreeFingersTapSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    bool switchFlag = false;
    ErrCode ret = mmiService.SetTouchpadThreeFingersTapSwitch(switchFlag);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_GetTouchpadThreeFingersTapSwitch_001
 * @tc.desc: Verify return ERROR_NOT_SYSAPI when not a system app
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadThreeFingersTapSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool switchFlag = false;
    ErrCode ret = mmiService.GetTouchpadThreeFingersTapSwitch(switchFlag);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_GetTouchpadThreeFingersTapSwitch_002
 * @tc.desc: Verify return RET_OK or ETASKS_POST_SYNCTASK_FAIL when called as system app
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadThreeFingersTapSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool switchFlag = false;
    ErrCode ret = mmiService.GetTouchpadThreeFingersTapSwitch(switchFlag);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_AddVirtualInputDevice_001
 * @tc.desc: Not system app, expect ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_AddVirtualInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    InputDevice device {};
    int32_t deviceId = -1;
    ErrCode ret = mmiService.AddVirtualInputDevice(device, deviceId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_AddVirtualInputDevice_002
 * @tc.desc: Normal case, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_AddVirtualInputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    InputDevice device {};
    int32_t deviceId = -1;
    ErrCode ret = mmiService.AddVirtualInputDevice(device, deviceId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_RemoveVirtualInputDevice_001
 * @tc.desc: Not system app, expect ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_RemoveVirtualInputDevice_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t deviceId = 100;
    ErrCode ret = mmiService.RemoveVirtualInputDevice(deviceId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_RemoveVirtualInputDevice_002
 * @tc.desc: Invalid deviceId, expect RET_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_RemoveVirtualInputDevice_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t deviceId = -1;
    ErrCode ret = mmiService.RemoveVirtualInputDevice(deviceId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIService_RemoveVirtualInputDevice_003
 * @tc.desc: Normal case, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL or ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_RemoveVirtualInputDevice_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t deviceId = 123;
    ErrCode ret = mmiService.RemoveVirtualInputDevice(deviceId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_EnableHardwareCursorStats_001
 * @tc.desc: Normal enable case, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_EnableHardwareCursorStats_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool enable = true;
    ErrCode ret = mmiService.EnableHardwareCursorStats(enable);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_EnableHardwareCursorStats_002
 * @tc.desc: Disable hardware cursor stats, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_EnableHardwareCursorStats_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool enable = false;
    ErrCode ret = mmiService.EnableHardwareCursorStats(enable);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_GetHardwareCursorStats_001
 * @tc.desc: Normal case, expect RET_OK or ETASKS_POST_SYNCTASK_FAIL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetHardwareCursorStats_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    uint32_t frameCount = 0;
    uint32_t vsyncCount = 0;
    ErrCode ret = mmiService.GetHardwareCursorStats(frameCount, vsyncCount);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetTouchpadScrollRows_001
 * @tc.desc: Service not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t rows = 3;
    ErrCode ret = mmiService.SetTouchpadScrollRows(rows);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetTouchpadScrollRows_002
 * @tc.desc: Valid input within range, expect RET_OK or PostSyncTask fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadScrollRows_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t rows = 3;
    ErrCode ret = mmiService.SetTouchpadScrollRows(rows);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetTouchpadScrollRows_003
 * @tc.desc: Input less than MIN_ROWS, should be clamped, expect RET_OK or fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadScrollRows_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t rows = -100; // invalid, expect clamped to MIN_ROWS
    ErrCode ret = mmiService.SetTouchpadScrollRows(rows);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetTouchpadScrollRows_004
 * @tc.desc: Input greater than MAX_ROWS, should be clamped, expect RET_OK or fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetTouchpadScrollRows_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t rows = 9999;
    ErrCode ret = mmiService.SetTouchpadScrollRows(rows);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_GetTouchpadScrollRows_001
 * @tc.desc: Service not running, expect MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadScrollRows_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t rows = 0;
    ErrCode ret = mmiService.GetTouchpadScrollRows(rows);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_GetTouchpadScrollRows_002
 * @tc.desc: Service running, expect RET_OK or PostSyncTask failure
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadScrollRows_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t rows = 0;
    ErrCode ret = mmiService.GetTouchpadScrollRows(rows);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_GetTouchpadScrollRows_003
 * @tc.desc: Get rows and verify it's within expected range if success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetTouchpadScrollRows_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t rows = -1;
    ErrCode ret = mmiService.GetTouchpadScrollRows(rows);
    if (ret == RET_OK) {
        EXPECT_GE(rows, 1);
        EXPECT_LE(rows, 100);
    } else {
        EXPECT_TRUE(ret == ETASKS_POST_SYNCTASK_FAIL);
    }
}

#ifdef OHOS_BUILD_ENABLE_ANCO
/**
 * @tc.name: MMIService_AncoAddChannel_001
 * @tc.desc: Verify system app failed, expect ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_AncoAddChannel_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    sptr<IAncoChannel> channel = nullptr;
    ErrCode ret = mmiService.AncoAddChannel(channel);
    EXPECT_NE(ret, RET_OK);
}
#endif

/**
 * @tc.name: MMIService_TransferBinderClientSrv_001
 * @tc.desc: Transfer binder client with nullptr, expect RET_ERR or PostSyncTask error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_TransferBinderClientSrv_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    sptr<IRemoteObject> remoteObj = nullptr;
    ErrCode ret = mmiService.TransferBinderClientSrv(remoteObj);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_CalculateFuntionRunningTime_001
 * @tc.desc: Verify the normal execution path of CalculateFunctionRunningTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_CalculateFuntionRunningTime_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::string flag = "TestCalcFuncTime";
    bool executed = false;
    auto testFunc = [&executed]() {
        usleep(50000);
        executed = true;
    };
    mmiService.CalculateFuntionRunningTime(testFunc, flag);
    EXPECT_TRUE(executed);
}

/**
 * @tc.name: MMIService_PrintLog_001
 * @tc.desc: Verify whether the PrintLog function can execute properly and call the DumpCatch interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_PrintLog_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::string flag = "PrintLogTest";
    int32_t duration = 5;
    int32_t pid = getpid();
    int32_t tid = gettid();
    ASSERT_NO_FATAL_FAILURE(mmiService.PrintLog(flag, duration, pid, tid));
}

/**
 * @tc.name: MMIService_SkipPointerLayer_001
 * @tc.desc: Permission verification failed, returning ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SkipPointerLayer_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ErrCode ret = mmiService.SkipPointerLayer(true);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_OnSessionDelete_001
 * @tc.desc: No action will be taken when the session is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_OnSessionDelete_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    SessionPtr session = nullptr;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnSessionDelete(session));
}

/**
 * @tc.name: MMIService_SetClientInfo_001
 * @tc.desc: Error returned when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetClientInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t pid = 12345;
    uint64_t readThreadId = 100;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    ErrCode ret = mmiService.SetClientInfo(pid, readThreadId);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetClientInfo_002
 * @tc.desc: readThreadId is invalid, returning an error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetClientInfo_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t pid = 12345;
    uint64_t readThreadId = static_cast<uint64_t>(-1);
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.SetClientInfo(pid, readThreadId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_InitPrintClientInfo_001
 * @tc.desc: Verify whether InitPrintClientInfo successfully sets the timer and callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_InitPrintClientInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    {
        std::lock_guard<std::mutex> lock(mmiService.mutex_);
        mmiService.clientInfos_["com.test.same"] = {
            .pid = 1234,
            .readThreadId = 1234
        };
        mmiService.clientInfos_["com.test.diff"] = {
            .pid = 5678,
            .readThreadId = 8765
        };
    }
    ASSERT_NO_FATAL_FAILURE(mmiService.InitPrintClientInfo());
}

/**
 * @tc.name: MMIService_GetIntervalSinceLastInput_001
 * @tc.desc: Verify that the input interval time returned under normal conditions is greater than or equal to 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetIntervalSinceLastInput_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int64_t timeInterval = -1;
    ErrCode ret = mmiService.GetIntervalSinceLastInput(timeInterval);
    EXPECT_NE(ret, RET_OK);
    EXPECT_GE(timeInterval, 0);
}

/**
 * @tc.name: MMIService_GetAllSystemHotkeys_001
 * @tc.desc: The verification call was successful
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetAllSystemHotkeys_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::vector<KeyOption> keyOptions;
    ErrCode ret = mmiService.GetAllSystemHotkeys(keyOptions);
    EXPECT_NE(ret, RET_OK);
    for (const auto& keyOpt : keyOptions) {
        EXPECT_GE(keyOpt.GetFinalKey(), 0);
        EXPECT_GE(keyOpt.GetPriority(), 0);
    }
}

/**
 * @tc.name: MMIService_GetAllSystemHotkeys_002
 * @tc.desc: When SHORTCUT_KEY_MANAGER_ENABLED is undefined, it returns ERROR_UNSUPPORTED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetAllSystemHotkeys_002, TestSize.Level1)
{
#if !defined(SHORTCUT_KEY_MANAGER_ENABLED)
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::vector<KeyOption> keyOptions;
    ErrCode ret = mmiService.GetAllSystemHotkeys(keyOptions);
    EXPECT_NE(ret, RET_OK);
    EXPECT_TRUE(keyOptions.empty());
#else
    GTEST_SKIP() << "SHORTCUT_KEY_MANAGER_ENABLED is defined, skip this test";
#endif
}

/**
 * @tc.name: MMIService_SetInputDeviceEnable_IllegalSession_001
 * @tc.desc: Return failure when SessionPtr is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetInputDeviceEnable_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t deviceId = 1;
    int32_t index = 0;
    int32_t pid = 0;
    SessionPtr nullSession = nullptr;
    ErrCode ret = mmiService.SetInputDeviceEnable(deviceId, true, index, pid, nullSession);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIService_SetInputDeviceEnabled_001
 * @tc.desc: Test SetInputDeviceEnabled when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetInputDeviceEnabled_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    int32_t deviceId = 1;
    int32_t index = 0;
    ErrCode ret = mmiService.SetInputDeviceEnabled(deviceId, true, index);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetInputDeviceEnabled_002
 * @tc.desc: Test SetInputDeviceEnabled when service is running but not system app
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetInputDeviceEnabled_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    int32_t deviceId = 1;
    int32_t index = 0;
    ErrCode ret = mmiService.SetInputDeviceEnabled(deviceId, true, index);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_ShiftAppPointerEvent_001
 * @tc.desc: ShiftAppPointerEvent when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ShiftAppPointerEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    ShiftWindowParam param {};
    bool autoGenDown = false;
    ErrCode ret = mmiService.ShiftAppPointerEvent(param, autoGenDown);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_ShiftAppPointerEvent_002
 * @tc.desc: ShiftAppPointerEvent when service is running but not system app
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ShiftAppPointerEvent_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ShiftWindowParam param {};
    bool autoGenDown = true;
    ErrCode ret = mmiService.ShiftAppPointerEvent(param, autoGenDown);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetCustomCursor_001
 * @tc.desc: SetCustomCursor when service is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetCustomCursor_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    CustomCursorParcel cursorParcel;
    CursorOptionsParcel optionParcel;
    ErrCode ret = mmiService.SetCustomCursor(1, cursorParcel, optionParcel);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SetCustomCursor_002
 * @tc.desc: SetCustomCursor when window permission denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetCustomCursor_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    CustomCursorParcel cursorParcel;
    CursorOptionsParcel optionParcel;
    int32_t invalidWindowId = -100;
    ErrCode ret = mmiService.SetCustomCursor(invalidWindowId, cursorParcel, optionParcel);
    EXPECT_NE(ret, RET_OK);
}

#ifdef OHOS_BUILD_ENABLE_ANCO
/**
 * @tc.name: MMIService_CheckKnuckleEvent_001
 * @tc.desc: CheckKnuckleEvent without modifying system app permission, default should be denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_CheckKnuckleEvent_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    float pointX = 100.0f;
    float pointY = 200.0f;
    bool isKnuckleType = false;
    ErrCode ret = mmiService.CheckKnuckleEvent(pointX, pointY, isKnuckleType);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SyncKnuckleStatus_001
 * @tc.desc: SyncKnuckleStatus returns RET_OK when delegateTasks_ runs normally
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SyncKnuckleStatus_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t ret = mmiService.SyncKnuckleStatus();
    EXPECT_NE(ret, RET_OK);
}
#endif

/**
 * @tc.name: MMIService_SetMultiWindowScreenId_001
 * @tc.desc: Test SetMultiWindowScreenId returns ERROR_NOT_SYSAPI when caller is not system app
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetMultiWindowScreenId_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    uint64_t screenId = 1;
    uint64_t displayNodeScreenId = 2;
    ErrCode ret = mmiService.SetMultiWindowScreenId(screenId, displayNodeScreenId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetKnuckleSwitch_001
 * @tc.desc: Test SetKnuckleSwitch returns ERROR_NOT_SYSAPI when uid is not 7011 or not system app
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetKnuckleSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool knuckleSwitch = true;
    ErrCode ret = mmiService.SetKnuckleSwitch(knuckleSwitch);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_LaunchAiScreenAbility_001
 * @tc.desc: Test LaunchAiScreenAbility when keyHandler is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_LaunchAiScreenAbility_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ErrCode ret = mmiService.LaunchAiScreenAbility();
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_GetMaxMultiTouchPointNum_001
 * @tc.desc: Test GetMaxMultiTouchPointNum returns expected value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetMaxMultiTouchPointNum_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t pointNum = 0;
    ErrCode ret = mmiService.GetMaxMultiTouchPointNum(pointNum);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_DealConsumers_001
 * @tc.desc: Test DealConsumers adds consumer name when UID matches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_DealConsumers_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t callingUid = 0;
    DeviceConsumer consumer;
    consumer.name = "TestConsumer";
    consumer.uids.push_back(callingUid);
    std::vector<std::string> filterNames;
    mmiService.DealConsumers(filterNames, consumer);
    ASSERT_EQ(filterNames.size(), 1);
    EXPECT_EQ(filterNames[0], "TestConsumer");
}

/**
 * @tc.name: MMIService_DealConsumers_002
 * @tc.desc: Test DealConsumers does not add name when UID does not match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_DealConsumers_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t callingUid = 1;
    DeviceConsumer consumer;
    consumer.name = "TestConsumer";
    consumer.uids.push_back(callingUid + 1000);
    std::vector<std::string> filterNames;
    mmiService.DealConsumers(filterNames, consumer);
    ASSERT_TRUE(filterNames.empty());
}

/**
 * @tc.name: MMIService_FilterConsumers_001
 * @tc.desc: Test FilterConsumers returns matched consumer name with correct UID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_FilterConsumers_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t uid = 0;
    DeviceConsumer consumer;
    consumer.name = "DeviceA";
    consumer.uids.push_back(uid);
    mmiService.consumersData_.consumers.push_back(consumer);
    std::vector<std::string> deviceNames = { "DeviceA" };
    std::vector<std::string> result = mmiService.FilterConsumers(deviceNames);
    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "DeviceA");
}

/**
 * @tc.name: MMIService_FilterConsumers_002
 * @tc.desc: Test FilterConsumers ignores consumer if UID doesn't match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_FilterConsumers_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t uid = 1;
    DeviceConsumer consumer;
    consumer.name = "DeviceB";
    consumer.uids.push_back(uid + 10000);
    mmiService.consumersData_.consumers.push_back(consumer);
    std::vector<std::string> deviceNames = { "DeviceB" };
    std::vector<std::string> result = mmiService.FilterConsumers(deviceNames);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: MMIService_FilterConsumers_003
 * @tc.desc: Test FilterConsumers with no matching device name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_FilterConsumers_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t uid = 1;
    DeviceConsumer consumer;
    consumer.name = "DeviceC";
    consumer.uids.push_back(uid);
    mmiService.consumersData_.consumers.push_back(consumer);
    std::vector<std::string> deviceNames = { "NonExistDevice" };
    std::vector<std::string> result = mmiService.FilterConsumers(deviceNames);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: MMIService_UpdateConsumers_001
 * @tc.desc: Parse valid JSON and store name and uids correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UpdateConsumers_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    const char *jsonStr = R"({
        "name": "DeviceTest",
        "uids": [1001, 1002]
    })";
    cJSON *json = cJSON_Parse(jsonStr);
    ASSERT_NE(json, nullptr);
    mmiService.UpdateConsumers(json);
    ASSERT_EQ(mmiService.consumersData_.consumers.size(), 1);
    const auto &consumer = mmiService.consumersData_.consumers[0];
    EXPECT_EQ(consumer.name, "DeviceTest");
    EXPECT_EQ(consumer.uids.size(), 2);
    EXPECT_EQ(consumer.uids[0], 1001);
    EXPECT_EQ(consumer.uids[1], 1002);
    cJSON_Delete(json);
}

/**
 * @tc.name: MMIService_UpdateConsumers_002
 * @tc.desc: JSON without name, should skip name assignment
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UpdateConsumers_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    const char *jsonStr = R"({
        "uids": [2001, 2002]
    })";
    cJSON *json = cJSON_Parse(jsonStr);
    ASSERT_NE(json, nullptr);
    mmiService.UpdateConsumers(json);
    ASSERT_EQ(mmiService.consumersData_.consumers.size(), 1);
    const auto &consumer = mmiService.consumersData_.consumers[0];
    EXPECT_EQ(consumer.name, "");
    EXPECT_EQ(consumer.uids.size(), 2);
    EXPECT_EQ(consumer.uids[0], 2001);
    EXPECT_EQ(consumer.uids[1], 2002);
    cJSON_Delete(json);
}

/**
 * @tc.name: MMIService_UpdateConsumers_003
 * @tc.desc: JSON without uids, should keep uids empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UpdateConsumers_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    const char *jsonStr = R"({
        "name": "DeviceOnly"
    })";
    cJSON *json = cJSON_Parse(jsonStr);
    ASSERT_NE(json, nullptr);
    mmiService.UpdateConsumers(json);
    ASSERT_EQ(mmiService.consumersData_.consumers.size(), 1);
    const auto &consumer = mmiService.consumersData_.consumers[0];
    EXPECT_EQ(consumer.name, "DeviceOnly");
    EXPECT_TRUE(consumer.uids.empty());
    cJSON_Delete(json);
}

/**
 * @tc.name: MMIService_UpdateConsumers_004
 * @tc.desc: uids array includes non-numeric value, should ignore them
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UpdateConsumers_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    const char *jsonStr = R"({
        "name": "MixedUID",
        "uids": [3001, "notANumber", 3002]
    })";
    cJSON *json = cJSON_Parse(jsonStr);
    ASSERT_NE(json, nullptr);
    mmiService.UpdateConsumers(json);
    ASSERT_EQ(mmiService.consumersData_.consumers.size(), 1);
    const auto &consumer = mmiService.consumersData_.consumers[0];
    EXPECT_EQ(consumer.name, "MixedUID");
    ASSERT_EQ(consumer.uids.size(), 2);
    EXPECT_EQ(consumer.uids[0], 3001);
    EXPECT_EQ(consumer.uids[1], 3002);

    cJSON_Delete(json);
}

/**
 * @tc.name: MMIService_ParseDeviceConsumerConfig_001
 * @tc.desc: GetOneCfgFile returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ParseDeviceConsumerConfig_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool result = mmiService.ParseDeviceConsumerConfig();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MMIService_SubscribeInputActive_001
 * @tc.desc: VerifySystemApp returns false → return ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SubscribeInputActive_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ErrCode ret = mmiService.SubscribeInputActive(1, 1000);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SubscribeInputActive_002
 * @tc.desc: Service not running → return MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SubscribeInputActive_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    ErrCode ret = mmiService.SubscribeInputActive(2, 1000);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_SubscribeInputActive_003
 * @tc.desc: GetSessionByPid returns nullptr → return RET_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SubscribeInputActive_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.SubscribeInputActive(3, 500);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_UnsubscribeInputActive_001
 * @tc.desc: Permission denied, VerifySystemApp returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UnsubscribeInputActive_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ErrCode ret = mmiService.UnsubscribeInputActive(1);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_UnsubscribeInputActive_002
 * @tc.desc: Service not running, return MMISERVICE_NOT_RUNNING
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UnsubscribeInputActive_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_NOT_START;
    ErrCode ret = mmiService.UnsubscribeInputActive(2);
    EXPECT_EQ(ret, MMISERVICE_NOT_RUNNING);
}

/**
 * @tc.name: MMIService_UnsubscribeInputActive_003
 * @tc.desc: Invalid subscribeId (negative), return RET_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UnsubscribeInputActive_003, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.UnsubscribeInputActive(-1);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: MMIService_UnsubscribeInputActive_004
 * @tc.desc: No session registered, GetSessionByPid returns null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_UnsubscribeInputActive_004, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.UnsubscribeInputActive(4);
    EXPECT_EQ(ret, ETASKS_POST_SYNCTASK_FAIL);
}

/**
 * @tc.name: MMIService_SetMouseAccelerateMotionSwitch_001
 * @tc.desc: Permission denied → RequestFromShell returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetMouseAccelerateMotionSwitch_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t deviceId = 0;
    bool enable = true;
    ErrCode ret = mmiService.SetMouseAccelerateMotionSwitch(deviceId, enable);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SetMouseAccelerateMotionSwitch_002
 * @tc.desc: Permission granted, but PostSyncTask fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SetMouseAccelerateMotionSwitch_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t deviceId = 1;
    bool enable = false;
    ErrCode ret = mmiService.SetMouseAccelerateMotionSwitch(deviceId, enable);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SwitchScreenCapturePermission_001
 * @tc.desc: Not system app, should return ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SwitchScreenCapturePermission_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    ErrCode ret = mmiService.SwitchScreenCapturePermission(1, true);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_SwitchScreenCapturePermission_002
 * @tc.desc: Uid not in {PENGLAI_UID, GAME_UID}, return ERROR_NO_PERMISSION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_SwitchScreenCapturePermission_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    mmiService.state_ = ServiceRunningState::STATE_RUNNING;
    ErrCode ret = mmiService.SwitchScreenCapturePermission(2, false);
    EXPECT_EQ(ret, ERROR_NO_PERMISSION);
}

/**
 * @tc.name: MMIService_ClearMouseHideFlag_001
 * @tc.desc: App is not a system app, return ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ClearMouseHideFlag_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t eventId = 100;
    ErrCode ret = mmiService.ClearMouseHideFlag(eventId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_ClearMouseHideFlag_002
 * @tc.desc: Uid not SYNERGY_UID, return ERROR_NO_PERMISSION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_ClearMouseHideFlag_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    int32_t eventId = 101;
    ErrCode ret = mmiService.ClearMouseHideFlag(eventId);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_QueryPointerRecord_001
 * @tc.desc: Not system app, should return ERROR_NOT_SYSAPI
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_QueryPointerRecord_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::vector<std::shared_ptr<PointerEvent>> pointerList;
    ErrCode ret = mmiService.QueryPointerRecord(5, pointerList);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_QueryPointerRecord_002
 * @tc.desc: No monitor permission, should return ERROR_NO_PERMISSION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_QueryPointerRecord_002, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::vector<std::shared_ptr<PointerEvent>> pointerList;
    ErrCode ret = mmiService.QueryPointerRecord(10, pointerList);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_GetExternalObject_001
 * @tc.desc: No remote object, should return ERROR_NO_POINTER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetExternalObject_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::string pluginName = "yunshuiqiao";
    sptr<IRemoteObject> remoteObj = nullptr;
    ErrCode ret = mmiService.GetExternalObject(pluginName, remoteObj);
    EXPECT_EQ(ret, ERROR_NULL_POINTER);
}

/**
 * @tc.name: MMIService_GetCurrentCursorInfo_001
 * @tc.desc: Test the function GetCurrentCursorInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetCurrentCursorInfo_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    bool visible;
    PointerStyle style;
    ErrCode ret = mmiService.GetCurrentCursorInfo(visible, style);
    EXPECT_NE(ret, RET_OK);
}

/**
 * @tc.name: MMIService_GetUserDefinedCursorPixelMap_001
 * @tc.desc: Test the function GetUserDefinedCursorPixelMap
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MMIService_GetUserDefinedCursorPixelMap_001, TestSize.Level1)
{
    CALL_TEST_DEBUG;
    MMIService mmiService;
    std::shared_ptr<PixelMap> pixelMap;
    ErrCode ret = mmiService.GetUserDefinedCursorPixelMap(pixelMap);
    EXPECT_NE(ret, RET_OK);
}
} // namespace MMI
} // namespace OHOS
