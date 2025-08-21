/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "stubmmiservice_fuzzer.h"

#include "mmi_service.h"
#include "multimodal_input_connect_stub.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "StubMmiServiceFuzzTest"

class UDSSession;
using SessionPtr = std::shared_ptr<UDSSession>;

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t MAX_BUNDLE_NAME_LEN = 128;
constexpr size_t MAX_PREINPUT_KEYS = 8;
constexpr int32_t MAX_GESTURE_FINGERS = 10;
} // namespace
const std::u16string FORMMGR_INTERFACE_TOKEN { u"ohos.multimodalinput.IConnectManager" };

void SetCustomCursorPixelMapFuzz(FuzzedDataProvider &fdp)
{
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    int32_t focusX   = fdp.ConsumeIntegral<int32_t>();
    int32_t focusY   = fdp.ConsumeIntegral<int32_t>();
    CursorPixelMap cur;
    MMIService::GetInstance()->SetCustomCursorPixelMap(windowId, focusX, focusY, cur);
}

void SetMouseHotSpotFuzz(FuzzedDataProvider &fdp)
{
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    int32_t hotX = fdp.ConsumeIntegral<int32_t>();
    int32_t hotY = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetMouseHotSpot(pid, windowId, hotX, hotY);
}

void SetNapStatusFuzz(FuzzedDataProvider &fdp)
{
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    std::string bundle = fdp.ConsumeRandomLengthString(fdp.ConsumeIntegralInRange<size_t>(0, MAX_BUNDLE_NAME_LEN));
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetNapStatus(pid, uid, bundle, status);
}

void GetMouseScrollRowsFuzz(FuzzedDataProvider &fdp)
{
    int32_t rows = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetMouseScrollRows(rows);
}

void SetPointerSizeFuzz(FuzzedDataProvider &fdp)
{
    int32_t sizeArg = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetPointerSize(sizeArg);
}

void GetPointerSizeFuzz(FuzzedDataProvider &fdp)
{
    int32_t size = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetPointerSize(size);
}

void GetCursorSurfaceIdFuzz(FuzzedDataProvider &fdp)
{
    uint64_t surfaceId = fdp.ConsumeIntegral<uint64_t>();
    MMIService::GetInstance()->GetCursorSurfaceId(surfaceId);
}

void SetMousePrimaryButtonFuzz(FuzzedDataProvider &fdp)
{
    int32_t primaryButton = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetMousePrimaryButton(primaryButton);
}

void GetMousePrimaryButtonFuzz(FuzzedDataProvider &fdp)
{
    int32_t primaryButton = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetMousePrimaryButton(primaryButton);
}

void SetPointerVisibleFuzz(FuzzedDataProvider &fdp)
{
    bool visible = fdp.ConsumeBool();
    int32_t priority = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetPointerVisible(visible, priority);
}

void IsPointerVisibleFuzz(FuzzedDataProvider &fdp)
{
    bool visible = fdp.ConsumeBool();
    MMIService::GetInstance()->IsPointerVisible(visible);
}

void SetPointerColorFuzz(FuzzedDataProvider &fdp)
{
    int32_t color = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetPointerColor(color);
}

void GetPointerColorFuzz(FuzzedDataProvider &fdp)
{
    int32_t color = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetPointerColor(color);
}

void SetPointerSpeedFuzz(FuzzedDataProvider &fdp)
{
    int32_t speed = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetPointerSpeed(speed);
}

void GetPointerSpeedFuzz(FuzzedDataProvider &fdp)
{
    int32_t speed = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetPointerSpeed(speed);
}

void NotifyNapOnlineFuzz(FuzzedDataProvider &fdp)
{
    bool callTwice = fdp.ConsumeBool();
    MMIService::GetInstance()->NotifyNapOnline();
    if (callTwice) {
        MMIService::GetInstance()->NotifyNapOnline();
    }
}

void RemoveInputEventObserverFuzz(FuzzedDataProvider &fdp)
{
    bool callTwice = fdp.ConsumeBool();
    MMIService::GetInstance()->RemoveInputEventObserver();
    if (callTwice) {
        MMIService::GetInstance()->RemoveInputEventObserver();
    }
}

void SetPointerStyleFuzz(FuzzedDataProvider &fdp)
{
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    PointerStyle ps;
    ps.size = fdp.ConsumeIntegral<int32_t>();
    ps.color = fdp.ConsumeIntegral<int32_t>();
    ps.id = fdp.ConsumeIntegral<int32_t>();
    ps.options = fdp.ConsumeIntegral<int32_t>();
    bool isUiExtension = fdp.ConsumeBool();
    MMIService::GetInstance()->SetPointerStyle(windowId, ps, isUiExtension);
}

void ClearWindowPointerStyleFuzz(FuzzedDataProvider &fdp)
{
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->ClearWindowPointerStyle(pid, windowId);
}

void GetPointerStyleFuzz(FuzzedDataProvider &fdp)
{
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    PointerStyle ps;
    bool isUiExtension = fdp.ConsumeBool();
    MMIService::GetInstance()->GetPointerStyle(windowId, ps, isUiExtension);
}

void SetHoverScrollStateFuzz(FuzzedDataProvider &fdp)
{
    bool state = fdp.ConsumeBool();
    MMIService::GetInstance()->SetHoverScrollState(state);
}

void GetHoverScrollStateFuzz(FuzzedDataProvider &fdp)
{
    bool state = fdp.ConsumeBool();
    MMIService::GetInstance()->GetHoverScrollState(state);
}

void OnSupportKeysFuzz(FuzzedDataProvider &fdp)
{
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

void OnGetDeviceIdsFuzz(FuzzedDataProvider &fdp)
{
    std::vector<int32_t> ids = {
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>(),
        fdp.ConsumeIntegral<int32_t>()
    };

    MMIService::GetInstance()->OnGetDeviceIds(ids);
}

void GetDeviceFuzzTest(FuzzedDataProvider &fdp)
{
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    InputDevice inputDevice;
    MMIService::GetInstance()->GetDevice(deviceId, inputDevice);
}

void OnRegisterDevListenerFuzz(FuzzedDataProvider &fdp)
{
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->OnRegisterDevListener(pid);
}

void RegisterDevListenerFuzz(FuzzedDataProvider &fdp)
{
    bool callTwice = fdp.ConsumeBool();
    MMIService::GetInstance()->RegisterDevListener();
    if (callTwice) {
        MMIService::GetInstance()->RegisterDevListener();
    }
}

void OnUnregisterDevListenerFuzz(FuzzedDataProvider &fdp)
{
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->OnUnregisterDevListener(pid);
}

void UnregisterDevListenerFuzz(FuzzedDataProvider &fdp)
{
    bool callTwice = fdp.ConsumeBool();
    MMIService::GetInstance()->UnregisterDevListener();
    if (callTwice) {
        MMIService::GetInstance()->UnregisterDevListener();
    }
}

void GetKeyboardTypeFuzz(FuzzedDataProvider &fdp)
{
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    int32_t keyboardType = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetKeyboardType(deviceId, keyboardType);
}

void SetKeyboardRepeatRateFuzz(FuzzedDataProvider &fdp)
{
    int32_t rate = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetKeyboardRepeatRate(rate);
}

void GetKeyboardRepeatDelayFuzz(FuzzedDataProvider &fdp)
{
    int32_t delay = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetKeyboardRepeatDelay(delay);
}

void GetKeyboardRepeatRateFuzz(FuzzedDataProvider &fdp)
{
    int32_t rate = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetKeyboardRepeatRate(rate);
}

void CheckInputHandlerVaildFuzz(FuzzedDataProvider &fdp)
{
    int32_t ht = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->CheckInputHandlerVaild(static_cast<InputHandlerType>(ht));
}

void AddInputHandlerFuzz(FuzzedDataProvider &fdp)
{
    int32_t handlerType = fdp.ConsumeIntegral<int32_t>();
    uint32_t eventType = fdp.ConsumeIntegral<uint32_t>();
    int32_t priority = fdp.ConsumeIntegral<int32_t>();
    uint32_t deviceTags = fdp.ConsumeIntegral<uint32_t>();
    MMIService::GetInstance()->AddInputHandler(handlerType, eventType, priority, deviceTags);
}

void AddPreInputHandlerFuzz(FuzzedDataProvider &fdp)
{
    int32_t handlerId = fdp.ConsumeIntegral<int32_t>();
    uint32_t eventType = fdp.ConsumeIntegral<uint32_t>();
    size_t n = fdp.ConsumeIntegralInRange<size_t>(0, MAX_PREINPUT_KEYS);
    std::vector<int32_t> keys;
    keys.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        keys.push_back(fdp.ConsumeIntegral<int32_t>());
    }
    MMIService::GetInstance()->AddPreInputHandler(handlerId, eventType, keys);
}

void RemovePreInputHandlerFuzz(FuzzedDataProvider &fdp)
{
    int32_t handlerId = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->RemovePreInputHandler(handlerId);
}

void ObserverAddInputHandlerFuzz(FuzzedDataProvider &fdp)
{
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->ObserverAddInputHandler(pid);
}

void AddGestureMonitorFuzz(FuzzedDataProvider &fdp)
{
    int32_t handlerType = fdp.ConsumeIntegral<int32_t>();
    uint32_t eventType = fdp.ConsumeIntegral<uint32_t>();
    uint32_t gestureType = fdp.ConsumeIntegral<uint32_t>();
    int32_t fingers = fdp.ConsumeIntegralInRange<int32_t>(0, MAX_GESTURE_FINGERS);

    MMIService::GetInstance()->AddGestureMonitor(handlerType, eventType, gestureType, fingers);
}

void RemoveGestureMonitorFuzz(FuzzedDataProvider &fdp)
{
    int32_t handlerType = fdp.ConsumeIntegral<int32_t>();
    uint32_t eventType = fdp.ConsumeIntegral<uint32_t>();
    uint32_t gestureType = fdp.ConsumeIntegral<uint32_t>();
    int32_t fingers = fdp.ConsumeIntegralInRange<int32_t>(0, MAX_GESTURE_FINGERS);

    MMIService::GetInstance()->RemoveGestureMonitor(handlerType, eventType, gestureType, fingers);
}

void CheckMarkConsumedFuzz(FuzzedDataProvider &fdp)
{
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    int32_t eventId = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->CheckMarkConsumed(pid, eventId);
}

void InjectKeyEventFuzz(FuzzedDataProvider &fdp)
{
    auto keyEvent = KeyEvent::Create();
    if (!keyEvent) {
        return;
    }
    keyEvent->SetKeyCode(fdp.ConsumeIntegral<int32_t>());
    keyEvent->SetKeyAction(fdp.ConsumeIntegral<int32_t>());
    bool isNativeInject = fdp.ConsumeBool();

    MMIService::GetInstance()->InjectKeyEvent(*keyEvent, isNativeInject);
}

void CheckInjectKeyEventFuzz(FuzzedDataProvider &fdp)
{
    auto keyEvent = KeyEvent::Create();
    if (!keyEvent) {
        return;
    }
    keyEvent->SetKeyCode(fdp.ConsumeIntegral<int32_t>());
    keyEvent->SetKeyAction(fdp.ConsumeIntegral<int32_t>());
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    bool isNativeInject = fdp.ConsumeBool();

    MMIService::GetInstance()->CheckInjectKeyEvent(keyEvent, pid, isNativeInject);
}

void OnGetKeyStateFuzz(FuzzedDataProvider &fdp)
{
    std::vector<int32_t> pressedKeys;
    std::unordered_map<int32_t, int32_t> specialKeysState;

    MMIService::GetInstance()->OnGetKeyState(pressedKeys, specialKeysState);
}

void CheckInjectPointerEventFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<PointerEvent> pointerEvent = PointerEvent::Create();
    if (!pointerEvent) {
        return;
    }

    pointerEvent->pointerAction_ = fdp.ConsumeIntegral<int32_t>();
    pointerEvent->originPointerAction_ = fdp.ConsumeIntegral<int32_t>();
    pointerEvent->buttonId_ = fdp.ConsumeIntegral<int32_t>();
    pointerEvent->fingerCount_ = fdp.ConsumeIntegral<int32_t>();
    pointerEvent->pullId_ = fdp.ConsumeIntegral<int32_t>();

    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    bool isNativeInject = fdp.ConsumeBool();
    bool isShell = fdp.ConsumeBool();
    int32_t useCoordinate = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->CheckInjectPointerEvent(pointerEvent, pid, isNativeInject, isShell, useCoordinate);
}

void ScreenCaptureCallbackFuzz(FuzzedDataProvider &fdp)
{
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    bool isStart = fdp.ConsumeBool();
    MMIService::ScreenCaptureCallback(pid, isStart);
}

void SubscribeHotkeyFuzz(FuzzedDataProvider &fdp)
{
    KeyOption keyOption;
    keyOption.finalKey_ = fdp.ConsumeIntegral<int32_t>();
    keyOption.isFinalKeyDown_ = fdp.ConsumeBool();
    keyOption.finalKeyDownDuration_ = fdp.ConsumeIntegral<int32_t>();
    keyOption.finalKeyUpDelay_ = fdp.ConsumeIntegral<int32_t>();
    keyOption.isRepeat_ = fdp.ConsumeBool();
    keyOption.priority_ = SubscribePriority::PRIORITY_0;

    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SubscribeHotkey(subscribeId, keyOption);
}

void UnsubscribeHotkeyFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->UnsubscribeHotkey(subscribeId);
}

void UnsubscribeSwitchEventFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->UnsubscribeSwitchEvent(subscribeId);
}

void QuerySwitchStatusFuzz(FuzzedDataProvider &fdp)
{
    int32_t switchType = fdp.ConsumeIntegral<int32_t>();
    int32_t state = 0;
    MMIService::GetInstance()->QuerySwitchStatus(switchType, state);
}

void SubscribeTabletProximityFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SubscribeTabletProximity(subscribeId);
}

void UnsubscribeTabletProximityFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->UnsubscribetabletProximity(subscribeId);
}

void SubscribeLongPressEventFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();

    LongPressRequest req;
    req.fingerCount = fdp.ConsumeIntegral<int32_t>();
    req.duration = fdp.ConsumeIntegral<int32_t>();

    MMIService::GetInstance()->SubscribeLongPressEvent(subscribeId, req);
}

void UnsubscribeLongPressEventFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->UnsubscribeLongPressEvent(subscribeId);
}

void SetAnrObserverFuzz(FuzzedDataProvider &fdp)
{
    bool callTwice = fdp.ConsumeBool();
    MMIService::GetInstance()->SetAnrObserver();
    if (callTwice) {
        MMIService::GetInstance()->SetAnrObserver();
    }
}

void GetDisplayBindInfoFuzz(FuzzedDataProvider &fdp)
{
    std::vector<DisplayBindInfo> infos;
    MMIService::GetInstance()->GetDisplayBindInfo(infos);
}

void GetAllMmiSubscribedEventsFuzz(FuzzedDataProvider &fdp)
{
    MmiEventMap eventMap;
    bool callTwice = fdp.ConsumeBool();
    MMIService::GetInstance()->GetAllMmiSubscribedEvents(eventMap);
    if (callTwice) {
        MMIService::GetInstance()->GetAllMmiSubscribedEvents(eventMap);
    }
}

void GetFunctionKeyStateFuzz(FuzzedDataProvider &fdp)
{
    int32_t funcKey = fdp.ConsumeIntegral<int32_t>();
    bool state = fdp.ConsumeBool();
    MMIService::GetInstance()->GetFunctionKeyState(funcKey, state);
}

void GetPointerLocationFuzz(FuzzedDataProvider &fdp)
{
    int32_t displayId = fdp.ConsumeIntegral<int32_t>();
    double displayX = fdp.ConsumeFloatingPoint<double>();
    double displayY = fdp.ConsumeFloatingPoint<double>();

    (void)MMIService::GetInstance()->GetPointerLocation(displayId, displayX, displayY);
}

void MmiServiceFuzzFirstGroup(FuzzedDataProvider &provider)
{
    SetCustomCursorPixelMapFuzz(provider);
    SetMouseHotSpotFuzz(provider);
    SetNapStatusFuzz(provider);
    GetMouseScrollRowsFuzz(provider);
    SetPointerSizeFuzz(provider);
    GetPointerSizeFuzz(provider);
    GetCursorSurfaceIdFuzz(provider);
    SetMousePrimaryButtonFuzz(provider);
    GetMousePrimaryButtonFuzz(provider);
    SetPointerVisibleFuzz(provider);
    IsPointerVisibleFuzz(provider);
    SetPointerColorFuzz(provider);
    GetPointerColorFuzz(provider);
    SetPointerSpeedFuzz(provider);
    GetPointerSpeedFuzz(provider);
    NotifyNapOnlineFuzz(provider);
    RemoveInputEventObserverFuzz(provider);
    SetPointerStyleFuzz(provider);
    ClearWindowPointerStyleFuzz(provider);
    GetPointerStyleFuzz(provider);
    SetHoverScrollStateFuzz(provider);
    GetHoverScrollStateFuzz(provider);
}

void MmiServiceFuzzSecondGroup(FuzzedDataProvider &provider)
{
    OnSupportKeysFuzz(provider);
    OnGetDeviceIdsFuzz(provider);
    GetDeviceFuzzTest(provider);
    OnRegisterDevListenerFuzz(provider);
    RegisterDevListenerFuzz(provider);
    OnUnregisterDevListenerFuzz(provider);
    UnregisterDevListenerFuzz(provider);
    GetKeyboardTypeFuzz(provider);
    SetKeyboardRepeatRateFuzz(provider);
    GetKeyboardRepeatDelayFuzz(provider);
    GetKeyboardRepeatRateFuzz(provider);
    CheckInputHandlerVaildFuzz(provider);
    AddInputHandlerFuzz(provider);
    AddPreInputHandlerFuzz(provider);
    RemovePreInputHandlerFuzz(provider);
    ObserverAddInputHandlerFuzz(provider);
    AddGestureMonitorFuzz(provider);
    RemoveGestureMonitorFuzz(provider);
    CheckMarkConsumedFuzz(provider);
    InjectKeyEventFuzz(provider);
    CheckInjectKeyEventFuzz(provider);
    OnGetKeyStateFuzz(provider);
    CheckInjectPointerEventFuzz(provider);
    ScreenCaptureCallbackFuzz(provider);
    SubscribeHotkeyFuzz(provider);
    UnsubscribeHotkeyFuzz(provider);
    UnsubscribeSwitchEventFuzz(provider);
    QuerySwitchStatusFuzz(provider);
    SubscribeTabletProximityFuzz(provider);
    UnsubscribeTabletProximityFuzz(provider);
    SubscribeLongPressEventFuzz(provider);
    UnsubscribeLongPressEventFuzz(provider);
    SetAnrObserverFuzz(provider);
    GetDisplayBindInfoFuzz(provider);
    GetAllMmiSubscribedEventsFuzz(provider);
    GetFunctionKeyStateFuzz(provider);
    GetPointerLocationFuzz(provider);
}

bool StubMmiServiceFuzzTest(FuzzedDataProvider &provider)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(std::u16string(FORMMGR_INTERFACE_TOKEN))) {
        return false;
    }

    const size_t n = provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes());
    auto blob = provider.ConsumeBytes<uint8_t>(n);
    if (!blob.empty() && !datas.WriteBuffer(blob.data(), blob.size())) {
        return false;
    }
    if (!datas.RewindRead(0)) {
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
    MmiServiceFuzzFirstGroup(provider);
    MmiServiceFuzzSecondGroup(provider);

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MMIService::GetInstance()->GetPointerSnapshot(pixelMap);
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    MMIService::GetInstance()->state_ = ServiceRunningState::STATE_RUNNING;
    MMIService::GetInstance()->OnRemoteRequest(
        static_cast<uint32_t>(IMultimodalInputConnectIpcCode::COMMAND_ALLOC_SOCKET_FD), datas, reply, option);
    return true;
}
} // MMI
} // OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (!data || size == 0) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::MMI::StubMmiServiceFuzzTest(provider);
    return 0;
}
