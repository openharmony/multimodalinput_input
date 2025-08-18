/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cursor_drawing_component.h"

#include <dlfcn.h>
#include <securec.h>

#include "mmi_log.h"
#include "pointer_device_manager.h"
#include "timer_manager.h"

#define MMI_LOG_TAG "CursorDrawingComponent"
#define CHK_IS_LOADV(isLoaded, pointerInstance)                                                      \
    if ((!isLoaded) || ((pointerInstance) == nullptr)) {                                             \
        MMI_HILOGE("libcursor_drawing_adapter.z.so is not loaded or instance does not exist");       \
        return;                                                                                      \
    }

#define CHK_IS_LOADF(isLoaded, pointerInstance)                                                      \
    if ((!isLoaded) || ((pointerInstance) == nullptr)) {                                             \
        MMI_HILOGE("libcursor_drawing_adapter.z.so is not loaded or instance does not exist");       \
        return false;                                                                                \
    }

#define CHK_IS_LOADR(isLoaded, pointerInstance)                                                      \
    if ((!isLoaded_) || ((pointerInstance_) == nullptr)) {                                           \
        MMI_HILOGE("libcursor_drawing_adapter.z.so is not loaded or instance does not exist");       \
        return RET_ERR;                                                                              \
    }

namespace OHOS::MMI {
namespace {
static constexpr const char *MULTIMODAL_PATH_NAME = "libcursor_drawing_adapter.z.so";
constexpr int32_t UNLOAD_TIME_MS = 2 * 60 * 1000; // 2 minutes
constexpr int32_t CHECK_INTERVAL_MS = 20 * 1000;  // check every 20 seconds
constexpr int32_t CHECK_COUNT = -1;
}

CursorDrawingComponent& CursorDrawingComponent::GetInstance()
{
    static CursorDrawingComponent instance;
    instance.Load();
    instance.lastCallTime_ = std::chrono::steady_clock::now();
    return instance;
}

CursorDrawingComponent::CursorDrawingComponent()
{
    MMI_HILOGI("create succeeded");
}

CursorDrawingComponent::~CursorDrawingComponent()
{
    UnLoad();
    MMI_HILOGI("destroy succeeded");
}


void CursorDrawingComponent::Load()
{
    {
        std::lock_guard<std::mutex> lockGuard(loadSoMutex_);
        if (isLoaded_ && (soHandle_ != nullptr)) {
            return;
        }

        if (!LoadLibrary()) {
            return;
        }
    }

    if (timerId_ > 0) {
        TimerMgr->RemoveTimer(timerId_);
    }
    timerId_ = TimerMgr->AddLongTimer(CHECK_INTERVAL_MS, CHECK_COUNT, [this] {
        auto idleTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - lastCallTime_).count();
        if ((idleTime >= UNLOAD_TIME_MS) && !POINTER_DEV_MGR.isInit) {
            CursorDrawingComponent::GetInstance().UnLoad();
        }
    }, "libcursor_drawing_adapter-Unload");
    if (timerId_ < 0) {
        MMI_HILOGE("Add timer for unloading libcursor_drawing_adapter library fail");
        UnLoad();
        return;
    }
    MMI_HILOGI("Load %{public}s is succeeded", MULTIMODAL_PATH_NAME);
}

bool CursorDrawingComponent::LoadLibrary()
{
    soHandle_ = dlopen(MULTIMODAL_PATH_NAME, RTLD_LAZY);
    if (soHandle_ == nullptr) {
        const char *errorMsg = dlerror();
        MMI_HILOGE("dlopen %{public}s failed, err msg:%{public}s", MULTIMODAL_PATH_NAME,
            (errorMsg != nullptr) ? errorMsg : "");
        return false;
    }

    getPointerInstance_ = reinterpret_cast<GetPointerInstanceFunc>(dlsym(soHandle_, "GetPointerInstance"));
    if (getPointerInstance_ == nullptr) {
        const char *errorMsg = dlerror();
        MMI_HILOGE("dlsym GetInstanceFunc failed, err msg:%{public}s", (errorMsg != nullptr) ? errorMsg : "");
        if (dlclose(soHandle_) != 0) {
            errorMsg = dlerror();
            MMI_HILOGE("dlclose %{public}s failed, err msg:%{public}s", MULTIMODAL_PATH_NAME,
                (errorMsg != nullptr) ? errorMsg : "");
        }
        soHandle_ = nullptr;
        return false;
    }

    pointerInstance_ = reinterpret_cast<IPointerDrawingManager*>(getPointerInstance_());
    if (pointerInstance_ == nullptr) {
        MMI_HILOGE("pointerInstance_ is nullptr");
        if (dlclose(soHandle_) != 0) {
            const char *errorMsg = dlerror();
            MMI_HILOGE("dlclose %{public}s failed, err msg:%{public}s", MULTIMODAL_PATH_NAME,
                (errorMsg != nullptr) ? errorMsg : "");
        }
        soHandle_ = nullptr;
        getPointerInstance_ = nullptr;
        return false;
    }
    isLoaded_ = true;
    return true;
}

void CursorDrawingComponent::UnLoad()
{
    std::lock_guard<std::mutex> lockGuard(loadSoMutex_);
    if (!isLoaded_ || (soHandle_ == nullptr)) {
        MMI_HILOGI("%{public}s has been UnLoaded", MULTIMODAL_PATH_NAME);
        return;
    }

    if (dlclose(soHandle_) != 0) {
        const char *errorMsg = dlerror();
        MMI_HILOGE("dlclose %{public}s failed, err msg:%{public}s", MULTIMODAL_PATH_NAME,
            (errorMsg != nullptr) ? errorMsg : "");
        return;
    }
    if (dlclose(soHandle_) != 0) {
        const char *errorMsg = dlerror();
        MMI_HILOGW("%{public}s has been unloaded, err msg:%{public}s", MULTIMODAL_PATH_NAME,
            (errorMsg != nullptr) ? errorMsg : "");
    }
    isLoaded_ = false;
    soHandle_ = nullptr;
    getPointerInstance_ = nullptr;
    pointerInstance_ = nullptr;
    MMI_HILOGI("UnLoad %{public}s is succeeded", MULTIMODAL_PATH_NAME);
}

void CursorDrawingComponent::DrawPointer(uint64_t displayId, int32_t physicalX, int32_t physicalY,
    const PointerStyle pointerStyle, Direction direction)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->DrawPointer(displayId, physicalX, physicalY, pointerStyle, direction);
}

void CursorDrawingComponent::UpdateDisplayInfo(const OLD::DisplayInfo &displayInfo)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->UpdateDisplayInfo(displayInfo);
}

void CursorDrawingComponent::OnDisplayInfo(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->OnDisplayInfo(displayGroupInfo);
}

void CursorDrawingComponent::OnWindowInfo(const WinInfo &info)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->OnWindowInfo(info);
}

bool CursorDrawingComponent::Init()
{
    CHK_IS_LOADF(isLoaded_, pointerInstance_)
    return pointerInstance_->Init();
}

void CursorDrawingComponent::DeletePointerVisible(int32_t pid)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->DeletePointerVisible(pid);
}

int32_t CursorDrawingComponent::SetPointerVisible(int32_t pid, bool visible, int32_t priority, bool isHap)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->SetPointerVisible(pid, visible, priority, isHap);
}

bool CursorDrawingComponent::GetPointerVisible(int32_t pid)
{
    CHK_IS_LOADF(isLoaded_, pointerInstance_)
    return pointerInstance_->GetPointerVisible(pid);
}

int32_t CursorDrawingComponent::SetPointerColor(int32_t color)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->SetPointerColor(color);
}

int32_t CursorDrawingComponent::GetPointerColor()
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->GetPointerColor();
}

int32_t CursorDrawingComponent::SetPointerStyle(
    int32_t pid, int32_t windowId, PointerStyle pointerStyle, bool isUiExtension)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->SetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
}

int32_t CursorDrawingComponent::ClearWindowPointerStyle(int32_t pid, int32_t windowId)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->ClearWindowPointerStyle(pid, windowId);
}

int32_t CursorDrawingComponent::GetPointerStyle(
    int32_t pid, int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->GetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
}

void CursorDrawingComponent::DrawPointerStyle(const PointerStyle &pointerStyle)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->DrawPointerStyle(pointerStyle);
}

bool CursorDrawingComponent::IsPointerVisible()
{
    CHK_IS_LOADF(isLoaded_, pointerInstance_)
    return pointerInstance_->IsPointerVisible();
}

void CursorDrawingComponent::SetPointerLocation(int32_t x, int32_t y, uint64_t displayId)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->SetPointerLocation(x, y, displayId);
}

void CursorDrawingComponent::SetMouseDisplayState(bool state)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->SetMouseDisplayState(state);
}

bool CursorDrawingComponent::GetMouseDisplayState()
{
    CHK_IS_LOADF(isLoaded_, pointerInstance_)
    return pointerInstance_->GetMouseDisplayState();
}

int32_t CursorDrawingComponent::SetCustomCursor(
    CursorPixelMap curPixelMap, int32_t pid, int32_t windowId, int32_t focusX, int32_t focusY)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->SetCustomCursor(curPixelMap, pid, windowId, focusX, focusY);
}

int32_t CursorDrawingComponent::SetCustomCursor(
    int32_t pid, int32_t windowId, CustomCursor cursor, CursorOptions options)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->SetCustomCursor(pid, windowId, cursor, options);
}

int32_t CursorDrawingComponent::SetMouseIcon(int32_t pid, int32_t windowId, CursorPixelMap curPixelMap)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->SetMouseIcon(pid, windowId, curPixelMap);
}

int32_t CursorDrawingComponent::SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->SetMouseHotSpot(pid, windowId, hotSpotX, hotSpotY);
}

int32_t CursorDrawingComponent::SetPointerSize(int32_t size)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->SetPointerSize(size);
}

int32_t CursorDrawingComponent::GetPointerSize()
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->GetPointerSize();
}

void CursorDrawingComponent::GetPointerImageSize(int32_t &width, int32_t &height)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->GetPointerImageSize(width, height);
}

int32_t CursorDrawingComponent::GetCursorSurfaceId(uint64_t &surfaceId)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->GetCursorSurfaceId(surfaceId);
}

PointerStyle CursorDrawingComponent::GetLastMouseStyle()
{
    if (!isLoaded_ || (pointerInstance_ == nullptr)) {
        MMI_HILOGE("%{public}s is closed", MULTIMODAL_PATH_NAME);
        return PointerStyle();
    }
    return pointerInstance_->GetLastMouseStyle();
}

IconStyle CursorDrawingComponent::GetIconStyle(const MOUSE_ICON mouseStyle)
{
    if (!isLoaded_ || (pointerInstance_ == nullptr)) {
        MMI_HILOGE("%{public}s is closed", MULTIMODAL_PATH_NAME);
        return IconStyle();
    }
    return pointerInstance_->GetIconStyle(mouseStyle);
}

const std::map<MOUSE_ICON, IconStyle>& CursorDrawingComponent::GetMouseIconPath()
{
    if (!isLoaded_ || (pointerInstance_ == nullptr)) {
        MMI_HILOGE("%{public}s is closed", MULTIMODAL_PATH_NAME);
        static std::map<MOUSE_ICON, IconStyle> emptMap;
        return emptMap;
    }
    return pointerInstance_->GetMouseIconPath();
}

int32_t CursorDrawingComponent::SwitchPointerStyle()
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->SwitchPointerStyle();
}

void CursorDrawingComponent::DrawMovePointer(uint64_t displayId, int32_t physicalX, int32_t physicalY)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->DrawMovePointer(displayId, physicalX, physicalY);
}

void CursorDrawingComponent::Dump(int32_t fd, const std::vector<std::string> &args)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->Dump(fd, args);
}

void CursorDrawingComponent::InitPointerCallback()
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->InitPointerCallback();
}

void CursorDrawingComponent::InitScreenInfo()
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->InitScreenInfo();
}

int32_t CursorDrawingComponent::EnableHardwareCursorStats(int32_t pid, bool enable)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->EnableHardwareCursorStats(pid, enable);
}

int32_t CursorDrawingComponent::GetHardwareCursorStats(int32_t pid, uint32_t &frameCount, uint32_t &vsyncCount)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->GetHardwareCursorStats(pid, frameCount, vsyncCount);
}

OLD::DisplayInfo CursorDrawingComponent::GetCurrentDisplayInfo()
{
    if (!isLoaded_ || (pointerInstance_ == nullptr)) {
        MMI_HILOGE("%{public}s is closed", MULTIMODAL_PATH_NAME);
        return OLD::DisplayInfo();
    }
    return pointerInstance_->GetCurrentDisplayInfo();
}

void CursorDrawingComponent::ForceClearPointerVisiableStatus()
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    return pointerInstance_->ForceClearPointerVisiableStatus();
}

void CursorDrawingComponent::InitPointerObserver()
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->InitPointerObserver();
}

void CursorDrawingComponent::OnSessionLost(int32_t pid)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->OnSessionLost(pid);
}

int32_t CursorDrawingComponent::SkipPointerLayer(bool isSkip)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->SkipPointerLayer(isSkip);
}

void CursorDrawingComponent::SetDelegateProxy(std::shared_ptr<DelegateInterface> proxy)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->SetDelegateProxy(proxy);
}

std::shared_ptr<DelegateInterface> CursorDrawingComponent::GetDelegateProxy()
{
    if (!isLoaded_ || (pointerInstance_ == nullptr)) {
        MMI_HILOGE("%{public}s is closed", MULTIMODAL_PATH_NAME);
        return nullptr;
    }
    return pointerInstance_->GetDelegateProxy();
}

void CursorDrawingComponent::DestroyPointerWindow()
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->DestroyPointerWindow();
}

void CursorDrawingComponent::DrawScreenCenterPointer(const PointerStyle &pointerStyle)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->DrawScreenCenterPointer(pointerStyle);
}

void CursorDrawingComponent::SubscribeScreenModeChange()
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->SubscribeScreenModeChange();
}

void CursorDrawingComponent::RegisterDisplayStatusReceiver()
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->RegisterDisplayStatusReceiver();
}

int32_t CursorDrawingComponent::UpdateMouseLayer(
    const PointerStyle &pointerStyle, uint64_t displayId, int32_t physicalX, int32_t physicalY)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->UpdateMouseLayer(pointerStyle, physicalX, physicalY);
}

int32_t CursorDrawingComponent::DrawNewDpiPointer()
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->DrawNewDpiPointer();
}

bool CursorDrawingComponent::GetHardCursorEnabled()
{
    CHK_IS_LOADF(isLoaded_, pointerInstance_)
    return pointerInstance_->GetHardCursorEnabled();
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
int32_t CursorDrawingComponent::GetPointerSnapshot(void *pixelMapPtr)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->GetPointerSnapshot(pixelMapPtr);
}
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

#ifndef OHOS_BUILD_ENABLE_WATCH
void CursorDrawingComponent::NotifyPointerEventToRS(int32_t pointAction, int32_t pointCnt)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->NotifyPointerEventToRS(pointAction, pointCnt);
}
#endif // OHOS_BUILD_ENABLE_WATCH
} // namespace OHOS
