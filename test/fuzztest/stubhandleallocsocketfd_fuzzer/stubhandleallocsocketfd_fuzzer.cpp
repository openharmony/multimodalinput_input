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

#include "stubhandleallocsocketfd_fuzzer.h"

#include "mmi_service.h"
#include "multimodal_input_connect_stub.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "StubHandleAllocSocketFdFuzzTest"

class UDSSession;
using SessionPtr = std::shared_ptr<UDSSession>;

namespace OHOS {
namespace MMI {
const std::u16string FORMMGR_INTERFACE_TOKEN { u"ohos.multimodalinput.IConnectManager" };
EpollEventType event_type = EPOLL_EVENT_SIGNAL;
InputHandlerType handlerType = NONE;
HandleEventType eventType = HANDLE_EVENT_TYPE_NONE;
int32_t tmpfd = 1;
uint32_t tmp32 = 1;
int32_t type = 1;
int64_t number = 1;
int32_t infoId = 1;
int32_t userId = 1;
int32_t deviceId = 1;
uint32_t frameCount = 1;
uint32_t vsyncCount = 1;
int64_t infraredFrequency = 1;
std::vector<int32_t> vec = {1, 2, 3};
std::vector<bool> vec_bool = {1};
std::vector<std::u16string> args = {u"hello", u"worid"};
std::vector<int64_t> pattern = {1, 2, 3};
std::map<int32_t, int32_t> mp = {{1, 2}, {2, 2}, {3, 2}};
std::vector<InfraredFrequency> requencys = {{1, 2}, {2, 2}};
int tmpdate = 1;
void* pixelMap = &tmpdate;
bool isAuthorize = true;
bool isNativeInject = true;
bool switchFlag = true;
bool enable = true;
bool rotateSwitch = true;
bool state = true;
std::string msg = "hello";
std::string businessId = "hello";
std::string flag = "hello";
std::shared_ptr<InputDevice> inputDevice;
std::shared_ptr<InputDevice> device;
std::shared_ptr<PointerEvent> pointerEvent;
std::shared_ptr<KeyOption> p_option;
std::shared_ptr<KeyEvent> keyEvent;

bool StubHandleAllocSocketFdFuzzTest(const uint8_t *data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    MMIService::GetInstance()->AddEpoll(event_type, tmpfd);
    MMIService::GetInstance()->DelEpoll(event_type, tmpfd);
    MMIService::GetInstance()->InitLibinputService();
    MMIService::GetInstance()->InitDelegateTasks();
    MMIService::GetInstance()->AddAppDebugListener();
    MMIService::GetInstance()->SetMouseScrollRows(tmpfd);
    MMIService::GetInstance()->SetMouseIcon(tmpfd, pixelMap);
    MMIService::GetInstance()->ReadMouseScrollRows(tmpfd);
    MMIService::GetInstance()->MarkProcessed(tmpfd, tmpfd);
    MMIService::GetInstance()->ReadPointerColor(tmpfd);
    MMIService::GetInstance()->OnSupportKeys(tmpfd, vec, vec_bool);
    MMIService::GetInstance()->OnGetDeviceIds(vec);
    MMIService::GetInstance()->OnGetDevice(tmpfd, inputDevice);
    MMIService::GetInstance()->OnGetKeyboardType(tmpfd, tmpfd);
    MMIService::GetInstance()->SetKeyboardRepeatDelay(tmpfd);
    MMIService::GetInstance()->CheckRemoveInput(tmpfd, handlerType, eventType, tmpfd, tmp32);
    MMIService::GetInstance()->RemoveInputHandler(handlerType, eventType, tmpfd, tmp32);
    MMIService::GetInstance()->MarkEventConsumed(tmpfd);
    MMIService::GetInstance()->MoveMouseEvent(tmpfd, tmpfd);
    MMIService::GetInstance()->InjectKeyEvent(keyEvent, isNativeInject);
    MMIService::GetInstance()->CheckInjectKeyEvent(keyEvent, tmpfd, isNativeInject);
    MMIService::GetInstance()->OnGetKeyState(vec, mp);
    MMIService::GetInstance()->InjectPointerEvent(pointerEvent, isNativeInject);
    MMIService::GetInstance()->OnAddSystemAbility(tmpfd, "deviceId");
    MMIService::GetInstance()->SubscribeKeyEvent(tmpfd, p_option);
    MMIService::GetInstance()->UnsubscribeKeyEvent(tmpfd);
    MMIService::GetInstance()->SubscribeSwitchEvent(tmpfd, tmpfd);
    MMIService::GetInstance()->SetDisplayBind(tmpfd, tmpfd, msg);
    MMIService::GetInstance()->SetFunctionKeyState(tmpfd, enable);
    MMIService::GetInstance()->SetPointerLocation(tmpfd, tmpfd);
    MMIService::GetInstance()->AddReloadDeviceTimer();
    MMIService::GetInstance()->Dump(tmpfd, args);
    MMIService::GetInstance()->OnGetWindowPid(tmpfd, tmpfd);
    MMIService::GetInstance()->GetWindowPid(tmpfd);
    MMIService::GetInstance()->SetKeyDownDuration(businessId, tmpfd);
    MMIService::GetInstance()->ReadTouchpadScrollSwich(switchFlag);
    MMIService::GetInstance()->ReadTouchpadScrollDirection(switchFlag);
    MMIService::GetInstance()->ReadTouchpadTapSwitch(switchFlag);
    MMIService::GetInstance()->ReadTouchpadPointerSpeed(tmpfd);
    MMIService::GetInstance()->ReadTouchpadPinchSwitch(switchFlag);
    MMIService::GetInstance()->ReadTouchpadSwipeSwitch(switchFlag);
    MMIService::GetInstance()->ReadTouchpadRightMenuType(tmpfd);
    MMIService::GetInstance()->ReadTouchpadRotateSwitch(rotateSwitch);
    MMIService::GetInstance()->SetTouchpadScrollSwitch(switchFlag);
    MMIService::GetInstance()->GetTouchpadScrollSwitch(switchFlag);
    MMIService::GetInstance()->SetTouchpadScrollDirection(state);
    MMIService::GetInstance()->GetTouchpadScrollDirection(state);
    MMIService::GetInstance()->SetTouchpadTapSwitch(switchFlag);
    MMIService::GetInstance()->GetTouchpadTapSwitch(switchFlag);
    MMIService::GetInstance()->SetTouchpadPointerSpeed(tmpfd);
    MMIService::GetInstance()->GetTouchpadPointerSpeed(tmpfd);
    MMIService::GetInstance()->SetTouchpadPinchSwitch(switchFlag);
    MMIService::GetInstance()->GetTouchpadPinchSwitch(switchFlag);
    MMIService::GetInstance()->SetTouchpadSwipeSwitch(switchFlag);
    MMIService::GetInstance()->GetTouchpadSwipeSwitch(switchFlag);
    MMIService::GetInstance()->SetTouchpadRightClickType(type);
    MMIService::GetInstance()->SetTouchpadRotateSwitch(rotateSwitch);
    MMIService::GetInstance()->GetTouchpadRotateSwitch(rotateSwitch);
    MMIService::GetInstance()->GetKeyState(vec, mp);
    MMIService::GetInstance()->Authorize(isAuthorize);
    MMIService::GetInstance()->OnAuthorize(isAuthorize);
    MMIService::GetInstance()->CancelInjection();
    MMIService::GetInstance()->OnCancelInjection();
    MMIService::GetInstance()->GetInfraredFrequencies(requencys);
    MMIService::GetInstance()->TransmitInfrared(number, pattern);
    MMIService::GetInstance()->OnGetInfraredFrequencies(requencys);
    MMIService::GetInstance()->OnTransmitInfrared(infraredFrequency, pattern);
    MMIService::GetInstance()->SetPixelMapData(infoId, pixelMap);
    MMIService::GetInstance()->SetCurrentUser(userId);
    MMIService::GetInstance()->AddVirtualInputDevice(device, deviceId);
    MMIService::GetInstance()->RemoveVirtualInputDevice(tmpfd);
    MMIService::GetInstance()->EnableHardwareCursorStats(enable);
    MMIService::GetInstance()->GetHardwareCursorStats(frameCount, vsyncCount);
    MMIService::GetInstance()->GetPointerSnapshot(pixelMap);
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(MultimodalinputConnectInterfaceCode::ALLOC_SOCKET_FD), datas, reply, option);
    return true;
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    OHOS::MMI::StubHandleAllocSocketFdFuzzTest(data, size);
    return 0;
}
