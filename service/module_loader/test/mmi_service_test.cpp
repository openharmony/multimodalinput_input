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
#include "udp_wrap.h"

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
    MMIService mmiService;
    int32_t filterId = 1;
    int32_t priority = 1;
    uint32_t deviceTags = 1;
    int32_t returnCode0 = 65142804;
    int32_t returnCode = 65142786;
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
    MMIService mmiService;
    SessionPtr session;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnConnected(session));
    ASSERT_NO_FATAL_FAILURE(mmiService.OnDisconnected(session));
}

/**
 * @tc.name: SetCustomCursor_001
 * @tc.desc: Test the function SetCustomCursor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SetCustomCursor_001, TestSize.Level1)
{
    MMIService mmiService;
    int32_t pid = 1;
    int32_t windowId = 1;
    int32_t focusX = 200;
    int32_t focusY = 500;
    void* pixelMap = nullptr;
    int32_t ret = mmiService.SetCustomCursor(pid, windowId, focusX, focusY, pixelMap);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SetMouseIcon_001
 * @tc.desc: Test the function SetMouseIcon
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SetMouseIcon_001, TestSize.Level1)
{
    MMIService mmiService;
    int32_t windowId = 1;
    void* pixelMap = nullptr;
    int32_t ret = mmiService.SetMouseIcon(windowId, pixelMap);
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
    MMIService mmiService;
    int32_t pid = 1;
    int32_t windowId = 1;
    int32_t hotSpotX = 100;
    int32_t hotSpotY = 200;
    int32_t ret = mmiService.SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: SetNapStatus_001
 * @tc.desc: Test the function SetNapStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SetNapStatus_001, TestSize.Level1)
{
    MMIService mmiService;
    int32_t pid = 1;
    int32_t uid = 2;
    std::string bundleName = "bundleName";
    int32_t napStatus = 1;
    int32_t ret = mmiService.SetNapStatus(pid, uid, bundleName, napStatus);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: ReadMouseScrollRows_001
 * @tc.desc: Test the function ReadMouseScrollRows
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, ReadMouseScrollRows_001, TestSize.Level1)
{
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
    MMIService mmiService;
    int32_t primaryButton = 1;
    int32_t returnCode = 65142804;
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
    MMIService mmiService;
    int32_t primaryButton = 1;
    int32_t ret = mmiService.GetMousePrimaryButton(primaryButton);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: CheckPointerVisible_001
 * @tc.desc: Test the function CheckPointerVisible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, CheckPointerVisible_001, TestSize.Level1)
{
    MMIService mmiService;
    bool visible = true;
    int32_t ret = mmiService.CheckPointerVisible(visible);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: MarkProcessed_001
 * @tc.desc: Test the function MarkProcessed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, MarkProcessed_001, TestSize.Level1)
{
    MMIService mmiService;
    int32_t eventType = 1;
    int32_t eventId = 1;
    int32_t ret = mmiService.MarkProcessed(eventType, eventId);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: ReadPointerColor_001
 * @tc.desc: Test the function ReadPointerColor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, ReadPointerColor_001, TestSize.Level1)
{
    MMIService mmiService;
    int32_t color = 1;
    int32_t ret = mmiService.ReadPointerColor(color);
    EXPECT_EQ(ret, RET_OK);
}

/**
 * @tc.name: NotifyNapOnline_001
 * @tc.desc: Test the function NotifyNapOnline
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, NotifyNapOnline_001, TestSize.Level1)
{
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
    MMIService mmiService;
    int32_t deviceId = 1;
    int32_t returnCode = 65142804;
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
    MMIService mmiService;
    int32_t returnCode = 65142804;
    int32_t deviceId = 1;
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();
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
    MMIService mmiService;
    int32_t pid = 1;
    int32_t ret = mmiService.RegisterDevListener();
    EXPECT_EQ(ret, RET_ERR);
    ret = mmiService.UnregisterDevListener();
    EXPECT_EQ(ret, RET_ERR);
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
    MMIService mmiService;
    int32_t returnCode = 65142804;
    int32_t deviceId = 1;
    int32_t keyboardType = 1;
    int32_t ret = mmiService.GetKeyboardType(deviceId, keyboardType);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: GetKeyboardRepeatDelay_001
 * @tc.desc: Test the function GetKeyboardRepeatDelay
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, GetKeyboardRepeatDelay_001, TestSize.Level1)
{
    MMIService mmiService;
    int32_t returnCode = 65142804;
    int32_t delay = 1;
    int32_t ret = mmiService.GetKeyboardRepeatDelay(delay);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: GetKeyboardRepeatRate_001
 * @tc.desc: Test the function GetKeyboardRepeatRate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, GetKeyboardRepeatRate_001, TestSize.Level1)
{
    MMIService mmiService;
    int32_t returnCode = 65142804;
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
    MMIService mmiService;
    int32_t returnCode = 65142786;
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
    MMIService mmiService;
    int32_t returnCode = 65142786;
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
    MMIService mmiService;
    int32_t returnCode = 65142786;
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
    MMIService mmiService;
    int32_t returnCode = 65142786;
    std::shared_ptr<KeyEvent> Event{ nullptr };
    int32_t pid = 1;
    bool isNativeInject = false;
    int32_t ret = mmiService.CheckInjectKeyEvent(Event, pid, isNativeInject);
    EXPECT_EQ(ret, returnCode);
}

/**
 * @tc.name: CheckInjectKeyEvent_001
 * @tc.desc: Test the function AdaptScreenResolution
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, AdaptScreenResolution_001, TestSize.Level1)
{
    MMIService mmiService;
    auto pointerEvent = PointerEvent::Create();
    ASSERT_NE(pointerEvent, nullptr);
    PointerEvent::PointerItem item;
    item.SetPointerId(10000);
    item.SetDisplayX(360);
    item.SetDisplayY(500);
    pointerEvent->AddPointerItem(item);
    pointerEvent->SetPointerId(10000);
    int32_t ret = mmiService.AdaptScreenResolution(pointerEvent);
    EXPECT_NE(ret, RET_ERR);
    ret = mmiService.AdaptScreenResolution(pointerEvent);
    EXPECT_NE(ret, RET_ERR);
}

/**
 * @tc.name: OnAddSystemAbility_001
 * @tc.desc: Test the function OnAddSystemAbility
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, OnAddSystemAbility_001, TestSize.Level1)
{
    MMIService mmiService;
    int32_t systemAbilityId = 1;
    std::string deviceId = "device_id";
    systemAbilityId = RES_SCHED_SYS_ABILITY_ID;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnAddSystemAbility(systemAbilityId, deviceId));
    systemAbilityId = COMMON_EVENT_SERVICE_ID;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnAddSystemAbility(systemAbilityId, deviceId));
    systemAbilityId = APP_MGR_SERVICE_ID;
    ASSERT_NO_FATAL_FAILURE(mmiService.OnAddSystemAbility(systemAbilityId, deviceId));
}

/**
 * @tc.name: SubscribeKeyEvent_001
 * @tc.desc: Test the function SubscribeKeyEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, SubscribeKeyEvent_001, TestSize.Level1)
{
    MMIService mmiService;
    int32_t subscribeId = 1;
    std::shared_ptr<KeyOption> option = std::make_shared<KeyOption>();
    int32_t ret = mmiService.SubscribeKeyEvent(subscribeId, option);
    EXPECT_EQ(ret, RET_ERR);
    ret = mmiService.UnsubscribeKeyEvent(subscribeId);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: GetDisplayBindInfo_001
 * @tc.desc: Test the function GetDisplayBindInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, GetDisplayBindInfo_001, TestSize.Level1)
{
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
    MMIService mmiService;
    int32_t funcKey = 1;
    bool enable = true;
    bool state = false;
    int32_t ret = mmiService.SetFunctionKeyState(funcKey, enable);
    EXPECT_EQ(ret, RET_ERR);
    ret = mmiService.GetFunctionKeyState(funcKey, state);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: OnDelegateTask_001
 * @tc.desc: Test the function OnDelegateTask
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, OnDelegateTask_001, TestSize.Level1)
{
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
    MMIService mmiService;
    int32_t windowId = 1;
    bool isCaptureMode = false;
    int32_t ret = mmiService.SetMouseCaptureMode(windowId, isCaptureMode);
    EXPECT_EQ(ret, RET_ERR);
    isCaptureMode = true;
    ret = mmiService.SetMouseCaptureMode(windowId, isCaptureMode);
    EXPECT_EQ(ret, RET_ERR);
}

/**
 * @tc.name: OnGetWindowPid_001
 * @tc.desc: Test the function OnGetWindowPid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(MMIServerTest, OnGetWindowPid_001, TestSize.Level1)
{
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
    MMIService mmiService;
    int32_t windowId = 1;
    int32_t ret = mmiService.GetWindowPid(windowId);
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
    MMIService mmiService;
    int32_t returnCode = 65142804;
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
    MMIService service;
    service.state_ = ServiceRunningState::STATE_RUNNING;
    ASSERT_FALSE(service.InitService());
    service.state_ = ServiceRunningState::STATE_NOT_START;
    service.mmiFd_ = 1000;
    ASSERT_FALSE(service.InitService());
}
} // namespace MMI
} // namespace OHOS