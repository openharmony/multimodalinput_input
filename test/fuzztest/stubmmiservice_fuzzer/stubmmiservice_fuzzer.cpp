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
