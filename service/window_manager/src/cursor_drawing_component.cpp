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

#include "ffrt.h"
#include "input_device_manager.h"
#include "i_input_windows_manager.h"
#include "i_preference_manager.h"
#include "mmi_log.h"
#include "pointer_device_manager.h"
#include "timer_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "CursorDrawingComponent"
#define CHK_IS_LOADV(isLoaded, pointerInstance)                     \
    Load();                                                         \
    if (!(isLoaded)) {                                              \
        MMI_HILOGE("libcursor_drawing_adapter.z.so is not loaded"); \
        return;                                                     \
    }                                                               \
    if ((pointerInstance) == nullptr) {                             \
        MMI_HILOGE("pointer instance does not exist");              \
        return;                                                     \
    }

#define CHK_IS_LOADF(isLoaded, pointerInstance)                     \
    Load();                                                         \
    if (!(isLoaded)) {                                              \
        MMI_HILOGE("libcursor_drawing_adapter.z.so is not loaded"); \
        return false;                                               \
    }                                                               \
    if ((pointerInstance) == nullptr) {                             \
        MMI_HILOGE("pointer instance does not exist");              \
        return false;                                               \
    }

#define CHK_IS_LOADR(isLoaded, pointerInstance)                     \
    Load();                                                         \
    if (!(isLoaded)) {                                              \
        MMI_HILOGE("libcursor_drawing_adapter.z.so is not loaded"); \
        return RET_ERR;                                             \
    }                                                               \
    if ((pointerInstance) == nullptr) {                             \
        MMI_HILOGE("pointer instance does not exist");              \
        return RET_ERR;                                             \
    }

namespace OHOS::MMI {
namespace {
static constexpr const char *MULTIMODAL_PATH_NAME = "libcursor_drawing_adapter.z.so";
constexpr int32_t UNLOAD_TIME_MS = 2 * 60 * 1000; // 2 minutes
constexpr int32_t CHECK_INTERVAL_MS = 20 * 1000;  // check every 20 seconds
constexpr int32_t CHECK_COUNT = -1;
constexpr int32_t DEFAULT_VALUE { -1 };
constexpr int32_t VISIBLE_LIST_MAX_SIZE { 100 };
constexpr int32_t CURSOR_CIRCLE_STYLE { 41 };
constexpr int32_t AECH_DEVELOPER_DEFINED_STYLE { 47 };
constexpr int32_t DEFAULT_POINTER_SIZE { 1 };
constexpr int32_t DEFAULT_POINTER_STYLE { 0 };
const char *POINTER_COLOR = "pointerColor";
const char *POINTER_SIZE = "pointerSize";
const std::string MOUSE_FILE_NAME { "mouse_settings.xml" };
const std::string IMAGE_POINTER_DEFAULT_PATH = "/system/etc/multimodalinput/mouse_icon/";
const std::string DefaultIconPath = IMAGE_POINTER_DEFAULT_PATH + "Default.svg";
}

CursorDrawingComponent& CursorDrawingComponent::GetInstance()
{
    static CursorDrawingComponent instance;
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
        lastCallTime_ = std::chrono::steady_clock::now();
        if (isLoaded_ && (soHandle_ != nullptr)) {
            return;
        }

        if (!LoadLibrary()) {
            return;
        }
    }

    if (!ResetUnloadTimer()) {
        MMI_HILOGE("reset timer for unloading libcursor_drawing_adapter library fail");
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
    POINTER_DEV_MGR.isInitDefaultMouseIconPath = true;
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    pointerInstance_->SetLastMouseStyle(CursorDrawingInformation::GetInstance().GetLastMouseStyle());
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
    return true;
}

bool CursorDrawingComponent::ResetUnloadTimer(int32_t unloadTime, int32_t checkInterval)
{
    if (timerId_ > 0) {
        TimerMgr->RemoveTimer(timerId_);
    }
    if (unloadTime == -1) {
        unloadTime = UNLOAD_TIME_MS;
    }
    if (checkInterval == -1) {
        checkInterval = CHECK_INTERVAL_MS;
    }
    timerId_ = TimerMgr->AddLongTimer(checkInterval, CHECK_COUNT, [this, unloadTime] {
        auto idleTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - lastCallTime_).count();
        if ((idleTime >= unloadTime) && !POINTER_DEV_MGR.isInit && !POINTER_DEV_MGR.isPointerVisible) {
            ffrt::submit([this] {
                this->UnLoad();
            });
        }
    }, "libcursor_drawing_adapter-ResetUnloadTimer");
    if (timerId_ < 0) {
        MMI_HILOGE("Failed to add timer.");
        return false;
    }
    return true;
}

void CursorDrawingComponent::UnLoad()
{
    std::lock_guard<std::mutex> lockGuard(loadSoMutex_);
    if (!isLoaded_ || (soHandle_ == nullptr)) {
        MMI_HILOGI("%{public}s has been UnLoaded", MULTIMODAL_PATH_NAME);
        return;
    }
    pointerInstance_->ClearResources();
    if (dlclose(soHandle_) != 0) {
        const char *errorMsg = dlerror();
        MMI_HILOGE("dlclose %{public}s failed, err msg:%{public}s", MULTIMODAL_PATH_NAME,
            (errorMsg != nullptr) ? errorMsg : "");
        return;
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

void CursorDrawingComponent::UpdateBindDisplayId(uint64_t rsId)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->UpdateBindDisplayId(rsId);
}

void CursorDrawingComponent::OnDisplayInfo(const OLD::DisplayGroupInfo &displayGroupInfo)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->OnDisplayInfo(displayGroupInfo);
}

void CursorDrawingComponent::OnWindowInfo(const WinInfo &info)
{
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    int32_t pid = CursorDrawingInformation::GetInstance().GetCurPid();
    if (pid != info.windowPid) {
        CursorDrawingInformation::GetInstance().SetCurPid(info.windowPid);
    }
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
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
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    CursorDrawingInformation::GetInstance().DeletePointerVisible(pid);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
}

int32_t CursorDrawingComponent::SetPointerVisible(int32_t pid, bool visible, int32_t priority, bool isHap)
{
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    return CursorDrawingInformation::GetInstance().SetPointerVisible(pid, visible, priority, isHap);
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
}

bool CursorDrawingComponent::GetPointerVisible(int32_t pid)
{
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    return CursorDrawingInformation::GetInstance().GetPointerVisible(pid);
#else
    return true;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
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
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    return CursorDrawingInformation::GetInstance().SetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
}

int32_t CursorDrawingComponent::ClearWindowPointerStyle(int32_t pid, int32_t windowId)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->ClearWindowPointerStyle(pid, windowId);
}

int32_t CursorDrawingComponent::GetPointerStyle(
    int32_t pid, int32_t windowId, PointerStyle &pointerStyle, bool isUiExtension)
{
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    return CursorDrawingInformation::GetInstance().GetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
}

void CursorDrawingComponent::DrawPointerStyle(const PointerStyle &pointerStyle)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->DrawPointerStyle(pointerStyle);
}

bool CursorDrawingComponent::IsPointerVisible()
{
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    return CursorDrawingInformation::GetInstance().IsPointerVisible();
#else
    return false;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
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
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    return CursorDrawingInformation::GetInstance().SetMouseIcon(pid, windowId, curPixelMap);
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
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
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    return CursorDrawingInformation::GetInstance().GetMouseIconPath();
#else
    static std::map<MOUSE_ICON, IconStyle> emptyMap;
    return emptyMap;
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
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

void CursorDrawingComponent::ForceClearPointerVisibleStatus()
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    return pointerInstance_->ForceClearPointerVisibleStatus();
}

void CursorDrawingComponent::InitPointerObserver()
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->InitPointerObserver();
}

void CursorDrawingComponent::OnSessionLost(int32_t pid)
{
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    CursorDrawingInformation::GetInstance().OnSessionLost(pid);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
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
    uint64_t workerThreadId = workerThreadId_.load();
    pointerInstance_->SubscribeScreenModeChange(workerThreadId);
}

void CursorDrawingComponent::AllPointerDeviceRemoved()
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->AllPointerDeviceRemoved();
}

void CursorDrawingComponent::RegisterDisplayStatusReceiver()
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->RegisterDisplayStatusReceiver();
}

int32_t CursorDrawingComponent::UpdateMouseLayer(int32_t physicalX, int32_t physicalY)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->UpdateMouseLayer(physicalX, physicalY);
}

int32_t CursorDrawingComponent::DrawNewDpiPointer()
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->DrawNewDpiPointer();
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
int32_t CursorDrawingComponent::GetPointerSnapshot(void *pixelMapPtr)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->GetPointerSnapshot(pixelMapPtr);
}
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR

#ifndef OHOS_BUILD_ENABLE_WATCH
void CursorDrawingComponent::NotifyPointerEventToRS(int32_t pointAction, int32_t pointCnt, int32_t sourceType)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->NotifyPointerEventToRS(pointAction, pointCnt, sourceType);
}
#endif // OHOS_BUILD_ENABLE_WATCH

void CursorDrawingComponent::InitDefaultMouseIconPath()
{
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    CursorDrawingInformation::GetInstance().InitDefaultMouseIconPath();
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
}

int32_t CursorDrawingComponent::GetCurrentCursorInfo(bool& visible, PointerStyle& pointerStyle)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->GetCurrentCursorInfo(visible, pointerStyle);
}

int32_t CursorDrawingComponent::GetUserDefinedCursorPixelMap(void *pixelMapPtr)
{
    CHK_IS_LOADR(isLoaded_, pointerInstance_)
    return pointerInstance_->GetUserDefinedCursorPixelMap(pixelMapPtr);
}

void CursorDrawingComponent::UpdatePointerItemCursorInfo(PointerEvent::PointerItem& pointerItem)
{
    CHK_IS_LOADV(isLoaded_, pointerInstance_)
    pointerInstance_->UpdatePointerItemCursorInfo(pointerItem);
}

IPointerDrawingManager* CursorDrawingComponent::GetPointerInstance()
{
    std::lock_guard<std::mutex> lockGuard(loadSoMutex_);
    lastCallTime_ = std::chrono::steady_clock::now();
    return pointerInstance_;
}

#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
CursorDrawingInformation& CursorDrawingInformation::GetInstance()
{
    static CursorDrawingInformation instance;
    return instance;
}

CursorDrawingInformation::CursorDrawingInformation()
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    MMI_HILOGI("The magic cursor InitStyle");
    hasMagicCursor_.name = "isMagicCursor";
    MAGIC_CURSOR->InitStyle();
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    InitStyle();
    InitDefaultMouseIconPath();
    MMI_HILOGI("create success");
}

CursorDrawingInformation::~CursorDrawingInformation()
{
    MMI_HILOGI("destroy succeeded");
}

std::map<MOUSE_ICON, IconStyle>& CursorDrawingInformation::GetMouseIcons()
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        MMI_HILOGD("Magiccurosr get magic mouse map");
        return MAGIC_CURSOR->magicMouseIcons_;
    } else {
        MMI_HILOGD("Magiccurosr get mouse icon, HasMagicCursor is false");
        return mouseIcons_;
    }
#else
    return mouseIcons_;
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
}

void CursorDrawingInformation::UpdateIconPath(const MOUSE_ICON mouseStyle, const std::string& iconPath)
{
    std::map<MOUSE_ICON, IconStyle> &mouseIcons = GetMouseIcons();
    auto iter = mouseIcons.find(mouseStyle);
    if (iter == mouseIcons.end()) {
        MMI_HILOGE("Cannot find the mouseStyle:%{public}d", static_cast<int32_t>(mouseStyle));
        return;
    }
    iter->second.iconPath = iconPath;
}

int32_t CursorDrawingInformation::UpdateDefaultPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
    bool isUiExtension)
{
    if (windowId != GLOBAL_WINDOW_ID) {
        MMI_HILOGD("No need to change the default icon style");
        return RET_OK;
    }
    PointerStyle style;
    WIN_MGR->GetPointerStyle(pid, GLOBAL_WINDOW_ID, style, isUiExtension);
    if (pointerStyle.id != style.id) {
        auto iconPath = GetMouseIconPath();
        auto it = iconPath.find(MOUSE_ICON(MOUSE_ICON::DEFAULT));
        if (it == iconPath.end()) {
            MMI_HILOGE("Cannot find the default style");
            return RET_ERR;
        }
        std::string newIconPath;
        if (pointerStyle.id == MOUSE_ICON::DEFAULT) {
            newIconPath = DefaultIconPath;
        } else {
            newIconPath = iconPath.at(MOUSE_ICON(pointerStyle.id)).iconPath;
        }
        MMI_HILOGD("Default path has changed from %{private}s to %{private}s",
            it->second.iconPath.c_str(), newIconPath.c_str());
        it->second.iconPath = newIconPath;
        UpdateIconPath(MOUSE_ICON(MOUSE_ICON::DEFAULT), newIconPath);
    }
    lastMouseStyle_ = style;
    auto pointerInstance = CursorDrawingComponent::GetInstance().GetPointerInstance();
    if (pointerInstance != nullptr) {
        pointerInstance->SetLastMouseStyle(style);
    }
    return RET_OK;
}

bool CursorDrawingInformation::HasMagicCursor()
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (!MAGIC_CURSOR->isExistDefaultStyle) {
        MMI_HILOGE("MagicCursor default icon file is not exist");
        return false;
    }
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    return hasMagicCursor_.isShow;
}

void CursorDrawingInformation::InitDefaultMouseIconPath()
{
    PointerStyle curPointerStyle;
    GetPointerStyle(pid_, GLOBAL_WINDOW_ID, curPointerStyle);
    if (curPointerStyle.id == CURSOR_CIRCLE_STYLE || curPointerStyle.id == AECH_DEVELOPER_DEFINED_STYLE) {
        auto iconPath = GetMouseIconPath();
        auto it = iconPath.find(MOUSE_ICON(MOUSE_ICON::DEFAULT));
        if (it == iconPath.end()) {
            MMI_HILOGE("Cannot find the default style");
            return;
        }
        auto itNew = iconPath.find(MOUSE_ICON(curPointerStyle.id));
        if (itNew == iconPath.end()) {
            MMI_HILOGE("Cannot find the target style: %{public}d", curPointerStyle.id);
            return;
        }
        std::string newIconPath = iconPath.at(MOUSE_ICON(curPointerStyle.id)).iconPath;
        MMI_HILOGD("default path has changed from %{private}s to %{private}s, target style is %{public}d",
            it->second.iconPath.c_str(), newIconPath.c_str(), curPointerStyle.id);
        it->second.iconPath = newIconPath;
        UpdateIconPath(MOUSE_ICON(MOUSE_ICON::DEFAULT), newIconPath);
    }
}

void CursorDrawingInformation::CheckMouseIconPath()
{
    for (auto iter = mouseIcons_.begin(); iter != mouseIcons_.end();) {
        if ((ReadCursorStyleFile(iter->second.iconPath)) != RET_OK) {
            iter = mouseIcons_.erase(iter);
            continue;
        }
        ++iter;
    }
}

void CursorDrawingInformation::InitStyle()
{
    mouseIcons_ = {
        {DEFAULT, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Default.svg"}},
        {EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "East.svg"}},
        {WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "West.svg"}},
        {SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "South.svg"}},
        {NORTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North.svg"}},
        {WEST_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "West_East.svg"}},
        {NORTH_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_South.svg"}},
        {NORTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_East.svg"}},
        {NORTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_West.svg"}},
        {SOUTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "South_East.svg"}},
        {SOUTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "South_West.svg"}},
        {NORTH_EAST_SOUTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_East_South_West.svg"}},
        {NORTH_WEST_SOUTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "North_West_South_East.svg"}},
        {CROSS, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Cross.svg"}},
        {CURSOR_COPY, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Copy.svg"}},
        {CURSOR_FORBID, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Forbid.svg"}},
        {COLOR_SUCKER, {ANGLE_SW, IMAGE_POINTER_DEFAULT_PATH + "Colorsucker.svg"}},
        {HAND_GRABBING, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Hand_Grabbing.svg"}},
        {HAND_OPEN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Hand_Open.svg"}},
        {HAND_POINTING, {ANGLE_NW_RIGHT, IMAGE_POINTER_DEFAULT_PATH + "Hand_Pointing.svg"}},
        {HELP, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Help.svg"}},
        {CURSOR_MOVE, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Move.svg"}},
        {RESIZE_LEFT_RIGHT, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Resize_Left_Right.svg"}},
        {RESIZE_UP_DOWN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Resize_Up_Down.svg"}},
        {SCREENSHOT_CHOOSE, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Screenshot_Cross.svg"}},
        {SCREENSHOT_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Screenshot_Cursor.svg"}},
        {TEXT_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Text_Cursor.svg"}},
        {ZOOM_IN, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Zoom_In.svg"}},
        {ZOOM_OUT, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Zoom_Out.svg"}},
        {MIDDLE_BTN_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_East.svg"}},
        {MIDDLE_BTN_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_West.svg"}},
        {MIDDLE_BTN_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_South.svg"}},
        {MIDDLE_BTN_NORTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North.svg"}},
        {MIDDLE_BTN_NORTH_SOUTH, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North_South.svg"}},
        {MIDDLE_BTN_EAST_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_East_West.svg"}},
        {MIDDLE_BTN_NORTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North_East.svg"}},
        {MIDDLE_BTN_NORTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_North_West.svg"}},
        {MIDDLE_BTN_SOUTH_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_South_East.svg"}},
        {MIDDLE_BTN_SOUTH_WEST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "MID_Btn_South_West.svg"}},
        {MIDDLE_BTN_NORTH_SOUTH_WEST_EAST, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH +
            "MID_Btn_North_South_West_East.svg"}},
        {HORIZONTAL_TEXT_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Horizontal_Text_Cursor.svg"}},
        {CURSOR_CROSS, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Cursor_Cross.svg"}},
        {CURSOR_CIRCLE, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Cursor_Circle.png"}},
        {LOADING, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Loading.svg"}},
        {RUNNING, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Loading_Left.svg"}},
        {RUNNING_LEFT, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Loading_Left.svg"}},
        {RUNNING_RIGHT, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Loading_Right.svg"}},
        {AECH_DEVELOPER_DEFINED_ICON, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Custom_Cursor_Circle.svg"}},
        {DEVELOPER_DEFINED_ICON, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Default.svg"}},
        {TRANSPARENT_ICON, {ANGLE_NW, IMAGE_POINTER_DEFAULT_PATH + "Default.svg"}},
        {SCREENRECORDER_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "ScreenRecorder_Cursor.svg"}},
        {LASER_CURSOR, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Laser_Cursor.svg"}},
        {LASER_CURSOR_DOT, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Laser_Cursor_Dot.svg"}},
        {LASER_CURSOR_DOT_RED, {ANGLE_CENTER, IMAGE_POINTER_DEFAULT_PATH + "Laser_Cursor_Dot_Red.svg"}},
    };
    CheckMouseIconPath();
}

ICON_TYPE CursorDrawingInformation::MouseIcon2IconType(MOUSE_ICON m)
{
    return ICON_TYPE(mouseIcons_[m].alignmentWay);
}

void CursorDrawingInformation::OnSessionLost(int32_t pid)
{
    for (auto it = hapPidInfos_.begin(); it != hapPidInfos_.end(); ++it) {
        if (it->pid == pid) {
            hapPidInfos_.erase(it);
            break;
        }
    }
}

bool CursorDrawingInformation::IsPointerVisible()
{
    if (!pidInfos_.empty()) {
        auto info = pidInfos_.back();
        if (!info.visible) {
            MMI_HILOGI("High priority visible property:%{public}zu.%{public}d-visible:%{public}s",
                pidInfos_.size(), info.pid, info.visible?"true":"false");
            return info.visible;
        }
    }
    if (!hapPidInfos_.empty()) {
        for (auto& item : hapPidInfos_) {
            if (item.pid == pid_) {
                MMI_HILOGI("Visible pid:%{public}d-visible:%{public}s", item.pid, item.visible ? "true" : "false");
                return item.visible;
            }
        }
        if (!(INPUT_DEV_MGR->HasPointerDevice() || WIN_MGR->IsMouseSimulate() ||
        INPUT_DEV_MGR->HasVirtualPointerDevice()) || pid_ == 0) {
            auto info = hapPidInfos_.back();
            MMI_HILOGI("Only hap visible pid:%{public}d-visible:%{public}s", info.pid, info.visible ? "true" : "false");
            return info.visible;
        }
    }
    if (pidInfos_.empty()) {
        MMI_HILOGI("Visible property is true");
        return true;
    }
    auto info = pidInfos_.back();
    MMI_HILOGI("Visible property:%{public}zu.%{public}d-visible:%{public}s",
        pidInfos_.size(), info.pid, info.visible ? "true" : "false");
    return info.visible;
}

void CursorDrawingInformation::DeletePointerVisible(int32_t pid)
{
    if (!pidInfos_.empty()) {
        auto it = pidInfos_.begin();
        for (; it != pidInfos_.end(); ++it) {
            if (it->pid == pid) {
                pidInfos_.erase(it);
                break;
            }
        }
    }
    auto pointerInstance = CursorDrawingComponent::GetInstance().GetPointerInstance();
    if (pointerInstance == nullptr) {
        return;
    }
    pointerInstance->DeleteSurfaceNode();
    if (!pidInfos_.empty()) {
        if (IsPointerVisible()) {
            pointerInstance->InitLayer(MOUSE_ICON(pointerInstance->GetLastMouseStyle().id));
        }
        pointerInstance->UpdatePointerVisible();
    }
}

bool CursorDrawingInformation::GetPointerVisible(int32_t pid)
{
    bool ret = true;
    int32_t count = 0;
    for (auto it = pidInfos_.begin(); it != pidInfos_.end(); ++it) {
        if (it->pid == pid) {
            count++;
            ret = it->visible;
            break;
        }
    }
    if (count == 0 && !hapPidInfos_.empty()) {
        for (auto& item : hapPidInfos_) {
            if (item.pid == pid_) {
                MMI_HILOGI("Visible pid:%{public}d-visible:%{public}s", item.pid, item.visible ? "true" : "false");
                count++;
                ret = item.visible;
                break;
            }
        }
    }
    return ret;
}

int32_t CursorDrawingInformation::SetPointerVisible(int32_t pid, bool visible, int32_t priority, bool isHap)
{
    MMI_HILOGI("The pid:%{public}d,visible:%{public}s,priority:%{public}d,isHap:%{public}s", pid,
        visible ? "true" : "false", priority, isHap ? "true" : "false");
    if (isHap) {
        for (auto it = hapPidInfos_.begin(); it != hapPidInfos_.end(); ++it) {
            if (it->pid == pid) {
                hapPidInfos_.erase(it);
                break;
            }
        }
        PidInfo info = { .pid = pid, .visible = visible };
        hapPidInfos_.push_back(info);
        if (hapPidInfos_.size() > VISIBLE_LIST_MAX_SIZE) {
            hapPidInfos_.pop_front();
        }
        auto pointerInstance = CursorDrawingComponent::GetInstance().GetPointerInstance();
        if (pointerInstance != nullptr) {
            pointerInstance->UpdatePointerVisible();
        }
        return RET_OK;
    }
    if (WIN_MGR->GetExtraData().appended && visible && priority == 0) {
        MMI_HILOGE("current is drag state, can not set pointer visible");
        return RET_ERR;
    }
    for (auto it = pidInfos_.begin(); it != pidInfos_.end(); ++it) {
        if (it->pid == pid) {
            pidInfos_.erase(it);
            break;
        }
    }
    PidInfo info = { .pid = pid, .visible = visible };
    pidInfos_.push_back(info);
    if (pidInfos_.size() > VISIBLE_LIST_MAX_SIZE) {
        pidInfos_.pop_front();
    }
    if (!WIN_MGR->HasMouseHideFlag() ||
        INPUT_DEV_MGR->HasPointerDevice() ||
        INPUT_DEV_MGR->HasVirtualPointerDevice()) {
        auto pointerInstance = CursorDrawingComponent::GetInstance().GetPointerInstance();
        if (pointerInstance != nullptr) {
            pointerInstance->UpdatePointerVisible();
        }
    }
    return RET_OK;
}

int32_t CursorDrawingInformation::SetPointerStylePreference(PointerStyle pointerStyle)
{
    std::string name = "pointerStyle";
    int32_t ret = PREFERENCES_MGR->SetIntValue(name, MOUSE_FILE_NAME, pointerStyle.id);
    if (ret != RET_OK) {
        MMI_HILOGE("Set pointer style failed, code:%{public}d", ret);
    }
    MMI_HILOGD("Set pointer style successfully, style:%{public}d", pointerStyle.id);
    return RET_OK;
}

bool CursorDrawingInformation::IsPointerStyleParamValid(int32_t windowId, PointerStyle pointerStyle)
{
    if (windowId < -1) {
        return false;
    }
    return !((pointerStyle.id < MOUSE_ICON::DEFAULT && pointerStyle.id != MOUSE_ICON::DEVELOPER_DEFINED_ICON) ||
        pointerStyle.id > MOUSE_ICON::LASER_CURSOR_DOT_RED);
}

int32_t CursorDrawingInformation::SetPointerStyle(int32_t pid, int32_t windowId, PointerStyle pointerStyle,
    bool isUiExtension)
{
    if (!IsPointerStyleParamValid(windowId, pointerStyle)) {
        MMI_HILOGE("PointerStyle param is invalid");
        return RET_ERR;
    }
    if (windowId == GLOBAL_WINDOW_ID) {
        int32_t ret = SetPointerStylePreference(pointerStyle);
        if (ret != RET_OK) {
            MMI_HILOGE("Set style preference is failed, ret:%{public}d", ret);
            return RET_ERR;
        }
    }
    auto& iconPath = GetMouseIconPath();
    if (iconPath.find(MOUSE_ICON(pointerStyle.id)) == iconPath.end()) {
        MMI_HILOGE("The param pointerStyle is invalid");
        return RET_ERR;
    }
    if (UpdateDefaultPointerStyle(pid, windowId, pointerStyle) != RET_OK) {
        MMI_HILOGE("Update default pointer iconPath failed");
        return RET_ERR;
    }
    if (WIN_MGR->SetPointerStyle(pid, windowId, pointerStyle, isUiExtension) != RET_OK) {
        MMI_HILOGE("Set pointer style failed");
        return RET_ERR;
    }
    if (!INPUT_DEV_MGR->HasPointerDevice() && !INPUT_DEV_MGR->HasVirtualPointerDevice()) {
        MMI_HILOGD("The pointer device is not exist");
        return RET_OK;
    }
    if (!WIN_MGR->IsNeedRefreshLayer(windowId)) {
        MMI_HILOGD("Not need refresh layer, window type:%{public}d, pointer style:%{public}d",
            windowId, pointerStyle.id);
        return RET_OK;
    }
    if (windowId != GLOBAL_WINDOW_ID && (pointerStyle.id == MOUSE_ICON::DEFAULT &&
        iconPath.at(MOUSE_ICON(pointerStyle.id)).iconPath != DefaultIconPath)) {
        PointerStyle style;
        WIN_MGR->GetPointerStyle(pid, GLOBAL_WINDOW_ID, style);
        pointerStyle = style;
    }
    auto pointerInstance = CursorDrawingComponent::GetInstance().GetPointerInstance();
    if (pointerInstance != nullptr) {
        pointerInstance->SetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    }
    return RET_OK;
}

int32_t CursorDrawingInformation::GetPointerStyle(int32_t pid, int32_t windowId, PointerStyle &pointerStyle,
    bool isUiExtension)
{
    if (windowId == GLOBAL_WINDOW_ID) {
        std::string name = POINTER_COLOR;
        pointerStyle.color = PREFERENCES_MGR->GetIntValue(name, DEFAULT_VALUE);
        name = POINTER_SIZE;
        pointerStyle.size = PREFERENCES_MGR->GetIntValue(name, DEFAULT_POINTER_SIZE);
        name = "pointerStyle";
        int32_t style = PREFERENCES_MGR->GetIntValue(name, DEFAULT_POINTER_STYLE);
        MMI_HILOGD("Get pointer style successfully, pointerStyle:%{public}d", style);
        if (style == CURSOR_CIRCLE_STYLE || style == AECH_DEVELOPER_DEFINED_STYLE) {
            pointerStyle.id = style;
            return RET_OK;
        }
    }
    WIN_MGR->GetPointerStyle(pid, windowId, pointerStyle, isUiExtension);
    MMI_HILOGD("Window id:%{public}d get pointer style:%{public}d success", windowId, pointerStyle.id);
    return RET_OK;
}

int32_t CursorDrawingInformation::SetMouseIcon(int32_t pid, int32_t windowId, CursorPixelMap curPixelMap)
{
    if (pid == DEFAULT_VALUE) {
        MMI_HILOGE("pid is invalid return -1");
        return RET_ERR;
    }
    CHKPR(curPixelMap.pixelMap, RET_ERR);
    if (windowId < 0) {
        MMI_HILOGE("Get invalid windowId, %{public}d", windowId);
        return RET_ERR;
    }
    if (WIN_MGR->CheckWindowIdPermissionByPid(windowId, pid) != RET_OK) {
        MMI_HILOGE("windowId not in right pid");
        return RET_ERR;
    }
    OHOS::Media::PixelMap* pixelMapPtr = static_cast<OHOS::Media::PixelMap*>(curPixelMap.pixelMap);
    {
        std::lock_guard<std::mutex> guard(userIconMtx_);
        userIcon_.reset(pixelMapPtr);
        curPixelMap.pixelMap = nullptr;
    }

    mouseIconUpdate_ = true;
    PointerStyle style;
    style.id = MOUSE_ICON::DEVELOPER_DEFINED_ICON;
    int32_t ret = SetPointerStyle(pid, windowId, style);
    if (ret == RET_ERR) {
        MMI_HILOGE("SetPointerStyle return RET_ERR here");
    }
    return ret;
}

const std::map<MOUSE_ICON, IconStyle>& CursorDrawingInformation::GetMouseIconPath()
{
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    if (HasMagicCursor()) {
        MMI_HILOGD("Magiccurosr get magic mouse map");
        return MAGIC_CURSOR->magicMouseIcons_;
    } else {
        MMI_HILOGD("Magiccurosr get mouse icon, HasMagicCursor is false");
        return mouseIcons_;
    }
#else
    return mouseIcons_;
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
}

const std::list<PidInfo>& CursorDrawingInformation::GetPidInfos() const
{
    return pidInfos_;
}

void CursorDrawingInformation::ClearPidInfos()
{
    pidInfos_.clear();
}

std::shared_ptr<OHOS::Media::PixelMap> CursorDrawingInformation::GetUserIconPixelMap()
{
    std::lock_guard<std::mutex> guard(userIconMtx_);
    return userIcon_;
}

void CursorDrawingInformation::SetUserIconPixelMap(const OHOS::Media::PixelMap *newPixelMap)
{
    if (newPixelMap != nullptr) {
        std::lock_guard<std::mutex> guard(userIconMtx_);
        userIcon_ = std::make_shared<OHOS::Media::PixelMap>(*newPixelMap);
    }
}

bool CursorDrawingInformation::GetMouseIconUpdate()
{
    return mouseIconUpdate_;
}

void CursorDrawingInformation::SetMouseIconUpdate(const bool mouseIconUpdate)
{
    mouseIconUpdate_ = mouseIconUpdate;
}

std::map<MOUSE_ICON, IconStyle> CursorDrawingInformation::GetMouseIconsMap()
{
    return mouseIcons_;
}

int32_t CursorDrawingInformation::GetCurPid()
{
    return pid_;
}

void CursorDrawingInformation::SetCurPid(int32_t pid)
{
    pid_ = pid;
}

void CursorDrawingInformation::SetMouseIcons(std::map<MOUSE_ICON, IconStyle> mouseIcons)
{
    mouseIcons_ = mouseIcons;
}

isMagicCursor CursorDrawingInformation::GetHasMagicCursor()
{
    return hasMagicCursor_;
}

PointerStyle CursorDrawingInformation::GetLastMouseStyle()
{
    return lastMouseStyle_;
}
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING
} // namespace OHOS
