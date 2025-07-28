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

#include <fuzzer/FuzzedDataProvider.h>
#include "stubhandleallocsocketfd_fuzzer.h"

#include "mmi_service.h"
#include "multimodal_input_connect_stub.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "StubHandleAllocSocketFdFuzzTest"

class UDSSession;
using SessionPtr = std::shared_ptr<UDSSession>;

namespace OHOS {
namespace MMI {
namespace {
constexpr uint32_t MAX_BUNDLE_NAME_LENGTH = 127;
} // namespace
const std::u16string FORMMGR_INTERFACE_TOKEN { u"ohos.multimodalinput.IConnectManager" };

void AddEpollFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    EpollEventType type = static_cast<EpollEventType>(fdp.ConsumeIntegralInRange<uint32_t>(0, EPOLL_EVENT_END));
    int32_t fd = fdp.ConsumeIntegral<int32_t>();
    bool readOnly = fdp.ConsumeBool();
    MMIService::GetInstance()->AddEpoll(type, fd, readOnly);
}

void DelEpollFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    EpollEventType type = static_cast<EpollEventType>(fdp.ConsumeIntegralInRange<uint32_t>(0, EPOLL_EVENT_END));
    int32_t fd = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->DelEpoll(type, fd);
}

void SetMouseScrollRowsFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t rows = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->SetMouseScrollRows(rows);
}

void SetMouseIconFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    CursorPixelMap cursorPixelMap;

    MMIService::GetInstance()->SetMouseIcon(windowId, cursorPixelMap);
}

void ReadMouseScrollRowsFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t rows = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->ReadMouseScrollRows(rows);
}

void MarkProcessedFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t eventType = fdp.ConsumeIntegral<int32_t>();
    int32_t eventId = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->MarkProcessed(eventType, eventId);
}

void OnSupportKeysFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    std::vector<int32_t> keys = {
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>()
    };
    std::vector<bool> keystroke = {
        fdp.ConsumeBool(),
        fdp.ConsumeBool()
    };

    MMIService::GetInstance()->OnSupportKeys(deviceId, keys, keystroke);
}

void OnGetDeviceIdsFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::vector<int32_t> ids = {
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>()
    };

    MMIService::GetInstance()->OnGetDeviceIds(ids);
}

void OnGetDeviceFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    std::shared_ptr<InputDevice> inputDevice = std::make_shared<InputDevice>();

    MMIService::GetInstance()->OnGetDevice(deviceId, inputDevice);
}

void OnGetKeyboardTypeFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    int32_t keyboardType = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->OnGetKeyboardType(deviceId, keyboardType);
}

void SetKeyboardRepeatDelayFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t delay = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->SetKeyboardRepeatDelay(delay);
}

void CheckRemoveInputFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    InputHandlerType handlerType =
        static_cast<InputHandlerType>(fdp.ConsumeIntegralInRange<uint32_t>(0, MONITOR));
    HandleEventType eventType = fdp.ConsumeIntegral<int32_t>();
    int32_t priority = fdp.ConsumeIntegral<int32_t>();
    uint32_t deviceTags = fdp.ConsumeIntegral<uint32_t>();

    MMIService::GetInstance()->CheckRemoveInput(pid, handlerType, eventType, priority, deviceTags);
}

void RemoveInputHandlerFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t handlerType = fdp.ConsumeIntegral<int32_t>();
    uint32_t eventType = fdp.ConsumeIntegral<uint32_t>();
    int32_t priority = fdp.ConsumeIntegral<int32_t>();
    uint32_t deviceTags = fdp.ConsumeIntegral<uint32_t>();

    MMIService::GetInstance()->RemoveInputHandler(handlerType, eventType, priority, deviceTags);
}

void MarkEventConsumedFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t eventId = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->MarkEventConsumed(eventId);
}

void MoveMouseEventFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t offsetX = fdp.ConsumeIntegral<int32_t>();
    int32_t offsetY = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->MoveMouseEvent(offsetX, offsetY);
}

void InjectPointerEventFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    pointerEvent->pointerAction_ = fdp.ConsumeIntegral<int32_t>();
    pointerEvent->originPointerAction_ = fdp.ConsumeIntegral<int32_t>();
    pointerEvent->buttonId_ = fdp.ConsumeIntegral<int32_t>();
    pointerEvent->fingerCount_  = fdp.ConsumeIntegral<int32_t>();
    pointerEvent->pullId_  = fdp.ConsumeIntegral<int32_t>();
    bool isNativeInject = fdp.ConsumeBool();
    int32_t useCoordinate = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->InjectPointerEvent(*pointerEvent.get(), isNativeInject, useCoordinate);
}

void OnAddSystemAbilityFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t systemAbilityId = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId = fdp.ConsumeBytesAsString(10); // test value

    MMIService::GetInstance()->OnAddSystemAbility(systemAbilityId, deviceId);
}

void SubscribeKeyEventFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    KeyOption keyOption;
    keyOption.finalKey_ = fdp.ConsumeIntegral<int32_t>();
    keyOption.isFinalKeyDown_ = fdp.ConsumeIntegral<int32_t>();
    keyOption.finalKeyDownDuration_ = fdp.ConsumeBool();
    keyOption.finalKeyUpDelay_ = fdp.ConsumeIntegral<int32_t>();
    keyOption.isRepeat_ = fdp.ConsumeBool();
    keyOption.priority_ = SubscribePriority::PRIORITY_0;

    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->SubscribeKeyEvent(subscribeId, keyOption);
}

void UnsubscribeKeyEventFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->UnsubscribeKeyEvent(subscribeId);
}

void SubscribeSwitchEventFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    int32_t switchType = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->SubscribeSwitchEvent(subscribeId, switchType);
}

void SetDisplayBindFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    int32_t displayId = fdp.ConsumeIntegral<int32_t>();
    std::string msg = fdp.ConsumeBytesAsString(10); // test value

    MMIService::GetInstance()->SetDisplayBind(deviceId, displayId, msg);
}

void SetFunctionKeyStateFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t funcKey = fdp.ConsumeIntegral<int32_t>();
    bool enable = fdp.ConsumeBool();

    MMIService::GetInstance()->SetFunctionKeyState(funcKey, enable);
}

void SetPointerLocationFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t x = fdp.ConsumeIntegral<int32_t>();
    int32_t y = fdp.ConsumeIntegral<int32_t>();
    int32_t displayId = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->SetPointerLocation(x, y, displayId);
}

void DumpFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    std::vector<std::u16string> args = {
        u"datatest1",
        u"datatest2",
        u"datatest3",
        u"datatest4"
    };
    int32_t fd = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->Dump(fd, args);
}

void OnGetWindowPidFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    int32_t ywindowPid = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->OnGetWindowPid(windowId, ywindowPid);
}

void GetWindowPidFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    int32_t ywindowPid = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->GetWindowPid(windowId, ywindowPid);
}

void SetKeyDownDurationFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    std::string businessId = fdp.ConsumeBytesAsString(10); // test value
    int32_t delay = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->SetKeyDownDuration(businessId, delay);
}

void ReadTouchpadScrollSwichFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->ReadTouchpadScrollSwich(switchFlag);
}

void ReadTouchpadScrollDirectionFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->ReadTouchpadScrollDirection(switchFlag);
}

void ReadTouchpadTapSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->ReadTouchpadTapSwitch(switchFlag);
}

void ReadTouchpadPointerSpeedFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t speed = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->ReadTouchpadPointerSpeed(speed);
}

void ReadTouchpadPinchSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->ReadTouchpadPinchSwitch(switchFlag);
}

void ReadTouchpadSwipeSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->ReadTouchpadSwipeSwitch(switchFlag);
}

void ReadTouchpadRightMenuTypeFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t type = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->ReadTouchpadRightMenuType(type);
}

void ReadTouchpadRotateSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool rotateSwitch = fdp.ConsumeBool();

    MMIService::GetInstance()->ReadTouchpadRotateSwitch(rotateSwitch);
}

void SetTouchpadScrollSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->SetTouchpadScrollSwitch(switchFlag);
}

void GetTouchpadScrollSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->GetTouchpadScrollSwitch(switchFlag);
}

void SetTouchpadScrollDirectionFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool state = fdp.ConsumeBool();

    MMIService::GetInstance()->SetTouchpadScrollDirection(state);
}

void GetTouchpadScrollDirectionFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->GetTouchpadScrollDirection(switchFlag);
}

void SetTouchpadTapSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->SetTouchpadTapSwitch(switchFlag);
}

void GetTouchpadTapSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->GetTouchpadTapSwitch(switchFlag);
}

void SetTouchpadPointerSpeedFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t speed = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->SetTouchpadPointerSpeed(speed);
}

void GetTouchpadPointerSpeedFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t speed = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->GetTouchpadPointerSpeed(speed);
}

void SetTouchpadPinchSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->SetTouchpadPinchSwitch(switchFlag);
}

void GetTouchpadPinchSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->GetTouchpadPinchSwitch(switchFlag);
}

void SetTouchpadSwipeSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->SetTouchpadSwipeSwitch(switchFlag);
}

void GetTouchpadSwipeSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool switchFlag = fdp.ConsumeBool();

    MMIService::GetInstance()->GetTouchpadSwipeSwitch(switchFlag);
}

void SetTouchpadRightClickTypeFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t type = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->SetTouchpadRightClickType(type);
}

void SetTouchpadRotateSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool rotateSwitch = fdp.ConsumeBool();

    MMIService::GetInstance()->SetTouchpadRotateSwitch(rotateSwitch);
}

void GetTouchpadRotateSwitchFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool rotateSwitch = fdp.ConsumeBool();

    MMIService::GetInstance()->GetTouchpadRotateSwitch(rotateSwitch);
}

void GetKeyStateFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    std::vector<int32_t> pressedKey = {
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>()
    };

    std::unordered_map<int32_t, int32_t> specialkeysState = {
        {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()},
        {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()},
        {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()},
        {fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeIntegral<int32_t>()},
    };

    MMIService::GetInstance()->GetKeyState(pressedKey, specialkeysState);
}

void AuthorizeFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool isAuthorize = fdp.ConsumeBool();

    MMIService::GetInstance()->Authorize(isAuthorize);
}

void OnAuthorizeFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool isAuthorize = fdp.ConsumeBool();

    MMIService::GetInstance()->OnAuthorize(isAuthorize);
}

void TransmitInfraredFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int64_t number = fdp.ConsumeIntegral<int64_t>();
    std::vector<int64_t> pattern = {
        fdp.ConsumeIntegral<int64_t>(),
        fdp.ConsumeIntegral<int64_t>(),
        fdp.ConsumeIntegral<int64_t>(),
        fdp.ConsumeIntegral<int64_t>()
    };

    MMIService::GetInstance()->TransmitInfrared(number, pattern);
}

void SetPixelMapDataFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t infoId = fdp.ConsumeIntegral<int32_t>();
    CursorPixelMap cursorPixelMap;

    MMIService::GetInstance()->SetPixelMapData(infoId, cursorPixelMap);
}

void SetCurrentUserFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t userId = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->SetCurrentUser(userId);
}

void AddVirtualInputDeviceFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    InputDevice device;
    device.id_ = fdp.ConsumeIntegral<int32_t>();
    device.type_ = fdp.ConsumeIntegral<int32_t>();
    device.bus_ = fdp.ConsumeIntegral<int32_t>();
    device.version_ = fdp.ConsumeIntegral<int32_t>();
    device.product_ = fdp.ConsumeIntegral<int32_t>();
    device.vendor_ = fdp.ConsumeIntegral<int32_t>();
    device.phys_ = fdp.ConsumeRandomLengthString(MAX_BUNDLE_NAME_LENGTH);
    device.uniq_ = fdp.ConsumeRandomLengthString(MAX_BUNDLE_NAME_LENGTH);
    MMIService::GetInstance()->AddVirtualInputDevice(device, deviceId);
}

void RemoveVirtualInputDeviceFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->RemoveVirtualInputDevice(deviceId);
}

void EnableHardwareCursorStatsFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    bool enable = fdp.ConsumeBool();

    MMIService::GetInstance()->EnableHardwareCursorStats(enable);
}

void GetHardwareCursorStatsFuzzTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    uint32_t frameCount = fdp.ConsumeIntegral<uint32_t>();
    uint32_t vsyncCount = fdp.ConsumeIntegral<uint32_t>();

    MMIService::GetInstance()->GetHardwareCursorStats(frameCount, vsyncCount);
}

void MmiServiceFuzzFirstGroup(const uint8_t *data, size_t size)
{
    AddEpollFuzzTest(data, size);
    DelEpollFuzzTest(data, size);
    SetMouseScrollRowsFuzzTest(data, size);
    SetMouseIconFuzzTest(data, size);
    ReadMouseScrollRowsFuzzTest(data, size);
    MarkProcessedFuzzTest(data, size);
    OnSupportKeysFuzzTest(data, size);
    OnGetDeviceIdsFuzzTest(data, size);
    OnGetDeviceFuzzTest(data, size);
    OnGetKeyboardTypeFuzzTest(data, size);
    SetKeyboardRepeatDelayFuzzTest(data, size);
    CheckRemoveInputFuzzTest(data, size);
    RemoveInputHandlerFuzzTest(data, size);
    MarkEventConsumedFuzzTest(data, size);
    MoveMouseEventFuzzTest(data, size);
    InjectPointerEventFuzzTest(data, size);
    OnAddSystemAbilityFuzzTest(data, size);
    SubscribeKeyEventFuzzTest(data, size);
    UnsubscribeKeyEventFuzzTest(data, size);
    SubscribeSwitchEventFuzzTest(data, size);
    SetDisplayBindFuzzTest(data, size);
    SetFunctionKeyStateFuzzTest(data, size);
    SetPointerLocationFuzzTest(data, size);
    DumpFuzzTest(data, size);
    OnGetWindowPidFuzzTest(data, size);
    GetWindowPidFuzzTest(data, size);
    SetKeyDownDurationFuzzTest(data, size);
    ReadTouchpadScrollSwichFuzzTest(data, size);
    ReadTouchpadScrollDirectionFuzzTest(data, size);
    ReadTouchpadTapSwitchFuzzTest(data, size);
}

void MmiServiceFuzzSecondGroup(const uint8_t *data, size_t size)
{
    ReadTouchpadPointerSpeedFuzzTest(data, size);
    ReadTouchpadPinchSwitchFuzzTest(data, size);
    ReadTouchpadSwipeSwitchFuzzTest(data, size);
    ReadTouchpadRightMenuTypeFuzzTest(data, size);
    ReadTouchpadRotateSwitchFuzzTest(data, size);
    SetTouchpadScrollSwitchFuzzTest(data, size);
    GetTouchpadScrollSwitchFuzzTest(data, size);
    SetTouchpadScrollDirectionFuzzTest(data, size);
    GetTouchpadScrollDirectionFuzzTest(data, size);
    SetTouchpadTapSwitchFuzzTest(data, size);
    GetTouchpadTapSwitchFuzzTest(data, size);
    SetTouchpadPointerSpeedFuzzTest(data, size);
    GetTouchpadPointerSpeedFuzzTest(data, size);
    SetTouchpadPinchSwitchFuzzTest(data, size);
    GetTouchpadPinchSwitchFuzzTest(data, size);
    SetTouchpadSwipeSwitchFuzzTest(data, size);
    GetTouchpadSwipeSwitchFuzzTest(data, size);
    SetTouchpadRightClickTypeFuzzTest(data, size);
    SetTouchpadRotateSwitchFuzzTest(data, size);
    GetTouchpadRotateSwitchFuzzTest(data, size);
    GetKeyStateFuzzTest(data, size);
    AuthorizeFuzzTest(data, size);
    OnAuthorizeFuzzTest(data, size);
    TransmitInfraredFuzzTest(data, size);
    SetPixelMapDataFuzzTest(data, size);
    SetCurrentUserFuzzTest(data, size);
    AddVirtualInputDeviceFuzzTest(data, size);
    RemoveVirtualInputDeviceFuzzTest(data, size);
    EnableHardwareCursorStatsFuzzTest(data, size);
    GetHardwareCursorStatsFuzzTest(data, size);
}

bool StubHandleAllocSocketFdFuzzTest(const uint8_t *data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN) ||
        !datas.WriteBuffer(data, size) || !datas.RewindRead(0)) {
        return false;
    }
    MessageParcel reply;
    MessageOption option;
    
    MMIService::GetInstance()->InitLibinputService();
    MMIService::GetInstance()->InitDelegateTasks();
    MMIService::GetInstance()->AddAppDebugListener();
    MMIService::GetInstance()->AddReloadDeviceTimer();
    MMIService::GetInstance()->CancelInjection();
    MMIService::GetInstance()->OnCancelInjection();
    MmiServiceFuzzFirstGroup(data, size);
    MmiServiceFuzzSecondGroup(data, size);

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MMIService::GetInstance()->GetPointerSnapshot(*pixelMapPtr);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_ALLOC_SOCKET_FD), datas, reply, option);
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
