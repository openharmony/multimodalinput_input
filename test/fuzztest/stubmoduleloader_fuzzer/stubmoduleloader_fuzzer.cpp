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
#include "stubmoduleloader_fuzzer.h"

#include "mmi_service.h"
#include "multimodal_input_connect_stub.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "StubModuleLoaderFuzzTest"

class UDSSession;
using SessionPtr = std::shared_ptr<UDSSession>;

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t MAX_BUNDLE_NAME_LEN = 128;
constexpr size_t MAX_NAME_COUNT = 8;
} // namespace
const std::u16string FORMMGR_INTERFACE_TOKEN { u"ohos.multimodalinput.IConnectManager" };

void SetMouseCaptureModeFuzz(FuzzedDataProvider &fdp)
{
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    bool isCaptureMode = fdp.ConsumeBool();
    MMIService::GetInstance()->SetMouseCaptureMode(windowId, isCaptureMode);
}

void EnableInputDeviceFuzz(FuzzedDataProvider &fdp)
{
    bool enable = fdp.ConsumeBool();
    MMIService::GetInstance()->EnableInputDevice(enable);
}

void EnableCombineKeyFuzz(FuzzedDataProvider &fdp)
{
    bool enable = fdp.ConsumeBool();
    MMIService::GetInstance()->EnableCombineKey(enable);
}

void CheckPidPermissionFuzz(FuzzedDataProvider &fdp)
{
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->CheckPidPermission(pid);
}

#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_COMBINATION_KEY)
void UpdateSettingsXmlFuzz(FuzzedDataProvider &fdp)
{
    size_t strLen = fdp.ConsumeIntegralInRange<size_t>(0, MAX_BUNDLE_NAME_LEN);
    std::string businessId = fdp.ConsumeRandomLengthString(strLen);
    int32_t delay = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->UpdateSettingsXml(businessId, delay);
}
#endif

void ReadTouchpadDoubleTapAndDragStateFuzz(FuzzedDataProvider &fdp)
{
    bool switchFlag = fdp.ConsumeBool();
    MMIService::GetInstance()->ReadTouchpadDoubleTapAndDragState(switchFlag);
}

void GetTouchpadRightClickTypeFuzz(FuzzedDataProvider &fdp)
{
    int32_t type = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetTouchpadRightClickType(type);
}

void SetTouchpadDoubleTapAndDragStateFuzz(FuzzedDataProvider &fdp)
{
    bool switchFlag = fdp.ConsumeBool();
    MMIService::GetInstance()->SetTouchpadDoubleTapAndDragState(switchFlag);
}

void GetTouchpadDoubleTapAndDragStateFuzz(FuzzedDataProvider &fdp)
{
    bool switchFlag = fdp.ConsumeBool();
    MMIService::GetInstance()->GetTouchpadDoubleTapAndDragState(switchFlag);
}

void SetShieldStatusFuzz(FuzzedDataProvider &fdp)
{
    int32_t shieldMode = fdp.ConsumeIntegral<int32_t>();
    bool isShield = fdp.ConsumeBool();
    MMIService::GetInstance()->SetShieldStatus(shieldMode, isShield);
}

void GetShieldStatusFuzz(FuzzedDataProvider &fdp)
{
    int32_t shieldMode = fdp.ConsumeIntegral<int32_t>();
    bool isShield = fdp.ConsumeBool();
    MMIService::GetInstance()->GetShieldStatus(shieldMode, isShield);
}

void HasIrEmitterFuzz(FuzzedDataProvider &fdp)
{
    bool hasIrEmitter = fdp.ConsumeBool();
    MMIService::GetInstance()->HasIrEmitter(hasIrEmitter);
}

void RequestInjectionFuzz(FuzzedDataProvider &fdp)
{
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    int32_t reqId = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->RequestInjection(status, reqId);
}

void QueryAuthorizedStatusFuzz(FuzzedDataProvider &fdp)
{
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->QueryAuthorizedStatus(status);
}

void SetTouchpadThreeFingersTapSwitchFuzz(FuzzedDataProvider &fdp)
{
    bool switchFlag = fdp.ConsumeBool();
    MMIService::GetInstance()->SetTouchpadThreeFingersTapSwitch(switchFlag);
}

void GetTouchpadThreeFingersTapSwitchFuzz(FuzzedDataProvider &fdp)
{
    bool switchFlag = fdp.ConsumeBool();
    MMIService::GetInstance()->GetTouchpadThreeFingersTapSwitch(switchFlag);
}

void SetTouchpadScrollRowsFuzz(FuzzedDataProvider &fdp)
{
    int32_t rows = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetTouchpadScrollRows(rows);
}

void GetTouchpadScrollRowsFuzz(FuzzedDataProvider &fdp)
{
    int32_t rows = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetTouchpadScrollRows(rows);
}

void SkipPointerLayerFuzz(FuzzedDataProvider &fdp)
{
    bool isSkip = fdp.ConsumeBool();
    MMIService::GetInstance()->SkipPointerLayer(isSkip);
}

void SetClientInfoFuzz(FuzzedDataProvider &fdp)
{
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    uint64_t readThreadId = fdp.ConsumeIntegral<uint64_t>();
    MMIService::GetInstance()->SetClientInfo(pid, readThreadId);
}

void GetIntervalSinceLastInputFuzz(FuzzedDataProvider &fdp)
{
    int64_t timeInterval = fdp.ConsumeIntegral<int64_t>();
    MMIService::GetInstance()->GetIntervalSinceLastInput(timeInterval);
}

void GetAllSystemHotkeysFuzz(FuzzedDataProvider &fdp)
{
    std::vector<KeyOption> keyOptions;
    MMIService::GetInstance()->GetAllSystemHotkeys(keyOptions);
}

void SetInputDeviceEnabledFuzz(FuzzedDataProvider &fdp)
{
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    bool enable = fdp.ConsumeBool();
    int32_t index = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->SetInputDeviceEnabled(deviceId, enable, index);
}

void SetCustomCursorParcelFuzz(FuzzedDataProvider &fdp)
{
    int32_t windowId = fdp.ConsumeIntegral<int32_t>();
    CustomCursorParcel cur;
    cur.pixelMap = nullptr;
    cur.focusX = fdp.ConsumeIntegral<int32_t>();
    cur.focusY = fdp.ConsumeIntegral<int32_t>();
    CursorOptionsParcel opt;
    opt.followSystem = fdp.ConsumeBool();
    MMIService::GetInstance()->SetCustomCursor(windowId, cur, opt);
}

void SetMultiWindowScreenIdFuzz(FuzzedDataProvider &fdp)
{
    uint64_t screenId = fdp.ConsumeIntegral<uint64_t>();
    uint64_t displayNodeScreenId = fdp.ConsumeIntegral<uint64_t>();
    MMIService::GetInstance()->SetMultiWindowScreenId(screenId, displayNodeScreenId);
}

void SetKnuckleSwitchFuzz(FuzzedDataProvider &fdp)
{
    bool knuckleSwitch = fdp.ConsumeBool();
    MMIService::GetInstance()->SetKnuckleSwitch(knuckleSwitch);
}

void LaunchAiScreenAbilityFuzz(FuzzedDataProvider &fdp)
{
    bool callTwice = fdp.ConsumeBool();
    MMIService::GetInstance()->LaunchAiScreenAbility();
    if (callTwice) {
        MMIService::GetInstance()->LaunchAiScreenAbility();
    }
}

void GetMaxMultiTouchPointNumFuzz(FuzzedDataProvider &fdp)
{
    int32_t pointNum = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->GetMaxMultiTouchPointNum(pointNum);
}

void SetInputDeviceConsumerFuzz(FuzzedDataProvider &fdp)
{
    size_t n = fdp.ConsumeIntegralInRange<size_t>(0, MAX_NAME_COUNT);
    std::vector<std::string> names;
    names.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        size_t len = fdp.ConsumeIntegralInRange<size_t>(0, MAX_BUNDLE_NAME_LEN);
        names.emplace_back(fdp.ConsumeRandomLengthString(len));
    }
    MMIService::GetInstance()->SetInputDeviceConsumer(names);
}

void ClearInputDeviceConsumerFuzz(FuzzedDataProvider &fdp)
{
    size_t n = fdp.ConsumeIntegralInRange<size_t>(0, MAX_NAME_COUNT);
    std::vector<std::string> names;
    names.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        size_t len = fdp.ConsumeIntegralInRange<size_t>(0, MAX_BUNDLE_NAME_LEN);
        names.emplace_back(fdp.ConsumeRandomLengthString(len));
    }
    MMIService::GetInstance()->ClearInputDeviceConsumer(names);
}

void SubscribeInputActiveFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    int64_t interval = fdp.ConsumeIntegral<int64_t>();
    MMIService::GetInstance()->SubscribeInputActive(subscribeId, interval);
}

void UnsubscribeInputActiveFuzz(FuzzedDataProvider &fdp)
{
    int32_t subscribeId = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->UnsubscribeInputActive(subscribeId);
}

void SetMouseAccelerateMotionSwitchFuzz(FuzzedDataProvider &fdp)
{
    int32_t deviceId = fdp.ConsumeIntegral<int32_t>();
    bool enable = fdp.ConsumeBool();
    MMIService::GetInstance()->SetMouseAccelerateMotionSwitch(deviceId, enable);
}

void SwitchScreenCapturePermissionFuzz(FuzzedDataProvider &fdp)
{
    uint32_t permissionType = fdp.ConsumeIntegral<uint32_t>();
    bool enable = fdp.ConsumeBool();
    MMIService::GetInstance()->SwitchScreenCapturePermission(permissionType, enable);
}

void ClearMouseHideFlagFuzz(FuzzedDataProvider &fdp)
{
    int32_t eventId = fdp.ConsumeIntegral<int32_t>();
    MMIService::GetInstance()->ClearMouseHideFlag(eventId);
}

void QueryPointerRecordFuzz(FuzzedDataProvider &fdp)
{
    int32_t count = fdp.ConsumeIntegral<int32_t>();
    std::vector<std::shared_ptr<PointerEvent>> list;
    MMIService::GetInstance()->QueryPointerRecord(count, list);
}

void MmiServiceFuzzFirstGroup(FuzzedDataProvider &provider)
{
    SetMouseCaptureModeFuzz(provider);
    EnableInputDeviceFuzz(provider);
    EnableCombineKeyFuzz(provider);
    CheckPidPermissionFuzz(provider);
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_COMBINATION_KEY)
    UpdateSettingsXmlFuzz(provider);
#endif
    ReadTouchpadDoubleTapAndDragStateFuzz(provider);
    GetTouchpadRightClickTypeFuzz(provider);
    SetTouchpadDoubleTapAndDragStateFuzz(provider);
    GetTouchpadDoubleTapAndDragStateFuzz(provider);
    SetShieldStatusFuzz(provider);
    GetShieldStatusFuzz(provider);
    HasIrEmitterFuzz(provider);
    RequestInjectionFuzz(provider);
    QueryAuthorizedStatusFuzz(provider);
    SetTouchpadThreeFingersTapSwitchFuzz(provider);
    GetTouchpadThreeFingersTapSwitchFuzz(provider);
    SetTouchpadScrollRowsFuzz(provider);
    GetTouchpadScrollRowsFuzz(provider);
}

void MmiServiceFuzzSecondGroup(FuzzedDataProvider &provider)
{
    SkipPointerLayerFuzz(provider);
    SetClientInfoFuzz(provider);
    GetIntervalSinceLastInputFuzz(provider);
    GetAllSystemHotkeysFuzz(provider);
    SetInputDeviceEnabledFuzz(provider);
    SetCustomCursorParcelFuzz(provider);
    SetMultiWindowScreenIdFuzz(provider);
    SetKnuckleSwitchFuzz(provider);
    LaunchAiScreenAbilityFuzz(provider);
    GetMaxMultiTouchPointNumFuzz(provider);
    SetInputDeviceConsumerFuzz(provider);
    ClearInputDeviceConsumerFuzz(provider);
    SubscribeInputActiveFuzz(provider);
    UnsubscribeInputActiveFuzz(provider);
    SetMouseAccelerateMotionSwitchFuzz(provider);
    SwitchScreenCapturePermissionFuzz(provider);
    ClearMouseHideFlagFuzz(provider);
    QueryPointerRecordFuzz(provider);
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
