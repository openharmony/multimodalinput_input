/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
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

#include "knuckle_handler_component.h"
#include <string>
#include "dlfcn.h"
#include "mmi_log.h"

#include "i_input_windows_manager.h"
#include "dfx_hisysevent.h"
#include "bundle_name_parser.h"
#include "input_event_handler.h"
#include "ability_launcher.h"

#undef MMI_HILOG_TAG
#define MMI_HILOG_TAG "KnuckleHandlerComponent"

namespace {
static const std::string KNUCKLE_LIB = "libmmi_knuckle.z.so";
}

namespace OHOS {
namespace MMI {

KnuckleHandlerComponent &KnuckleHandlerComponent::GetInstance()
{
    static KnuckleHandlerComponent instance;
    return instance;
}

bool KnuckleHandlerComponent::Init()
{
    return Load() != nullptr ? true : false;
}

void KnuckleHandlerComponent::SetCurrentToolType(struct TouchType touchType, int32_t &toolType)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return;
    }
    impl->SetCurrentToolType(touchType, toolType);
}

void KnuckleHandlerComponent::NotifyTouchUp(struct TouchType *rawTouch)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return;
    }
    impl->NotifyTouchUp(rawTouch);
}

void KnuckleHandlerComponent::EnableFingersense(void)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return;
    }
    impl->EnableFingersense();
}

void KnuckleHandlerComponent::DisableFingersense(void)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return;
    }
    impl->DisableFingersense();
}

void KnuckleHandlerComponent::UpdateDisplayMode(int32_t displayMode)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return;
    }
    impl->UpdateDisplayMode(displayMode);
}

void KnuckleHandlerComponent::SaveTouchInfo(float pointX, float pointY, int32_t toolType)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return;
    }
    impl->SaveTouchInfo(pointX, pointY, toolType);
}

int32_t KnuckleHandlerComponent::CheckKnuckleEvent(float pointX, float pointY, bool &isKnuckleType)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return RET_ERR;
    }
    return impl->CheckKnuckleEvent(pointX, pointY, isKnuckleType);
}

void KnuckleHandlerComponent::SetMultiWindowScreenId(uint64_t screenId, uint64_t displayModeScreenId)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return;
    }
    impl->SetMultiWindowScreenId(screenId, displayModeScreenId);
}

void KnuckleHandlerComponent::HandleKnuckleEvent(std::shared_ptr<PointerEvent> touchEvent)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return;
    }
    impl->HandleKnuckleEvent(touchEvent);
}

void KnuckleHandlerComponent::RegisterSwitchObserver()
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return;
    }
    impl->RegisterSwitchObserver();
}

int32_t KnuckleHandlerComponent::RegisterKnuckleSwitchByUserId(int32_t userId)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return RET_ERR;
    }
    return impl->RegisterKnuckleSwitchByUserId(userId);
}

int32_t KnuckleHandlerComponent::SetKnucklePermissions(int32_t permissions, bool enable)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return RET_ERR;
    }
    return impl->SetKnucklePermissions(permissions, enable);
}

bool KnuckleHandlerComponent::SkipKnuckleDetect()
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return RET_ERR;
    }
    return impl->SkipKnuckleDetect();
}

int32_t KnuckleHandlerComponent::SetKnuckleSwitch(bool knuckleSwitch)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return RET_ERR;
    }
    return impl->SetKnuckleSwitch(knuckleSwitch);
}

void KnuckleHandlerComponent::Dump(int32_t fd)
{
    IKnuckleHandler *impl = Load();
    if (impl == nullptr) {
        MMI_HILOGE("impl is null");
        return;
    }
    impl->Dump(fd);
}

IKnuckleHandler *KnuckleHandlerComponent::Load()
{
    if (impl_ != nullptr) {
        return impl_;
    }

    if (!LoadKnuckleSharedLibrary()) {
        MMI_HILOGE("load knuckle shared library fail");
        return nullptr;
    }

    auto knuckleCtx = std::make_shared<KnuckleContextImpl>();
    if (knuckleCtx == nullptr) {
        MMI_HILOGE("Create KnuckleContextImpl fail");
        Unload();
        return nullptr;
    }

    impl_ = create_(knuckleCtx);
    if (impl_ == nullptr) {
        MMI_HILOGE("create KnuckleHandler fail");
        Unload();
        return nullptr;
    }
    MMI_HILOGD("success to Load KnuckleHandler");
    return impl_;
}

bool KnuckleHandlerComponent::LoadKnuckleSharedLibrary()
{
    if (handle_ == nullptr) {
        handle_ = ::dlopen(KNUCKLE_LIB.c_str(), RTLD_LAZY);
        if (handle_ == nullptr) {
            MMI_HILOGE("%{public}s dlopen fail", KNUCKLE_LIB.c_str());
            return false;
        }
    }

    create_ = reinterpret_cast<GetKnuckleHandlerFunc>(::dlsym(handle_, "GetKnuckleHandler"));
    if (create_ == nullptr) {
        MMI_HILOGE("dlsym GetKnuckleHandler fail");
        ::dlclose(handle_);
        return false;
    }

    destroy_ = reinterpret_cast<DestroyKnuckleHandlerFunc>(::dlsym(handle_, "DestroyKnuckleHandler"));
    if (destroy_ == nullptr) {
        MMI_HILOGE("dlsym DestroyKnuckleHandler fail");
        create_ = nullptr;
        ::dlclose(handle_);
        return false;
    }
    MMI_HILOGI("success to load knuckle shared library");
    return true;
}

void KnuckleHandlerComponent::Unload()
{
    create_ = nullptr;
    if (destroy_ != nullptr && impl_ != nullptr) {
        destroy_(impl_);
    }
    destroy_ = nullptr;
    impl_ = nullptr;

    if (handle_ != nullptr) {
        ::dlclose(handle_);
        handle_ = nullptr;
    }
    MMI_HILOGI("success to Unload KnuckleHandler");
}

const OLD::DisplayInfo *KnuckleContextImpl::GetPhysicalDisplay(int32_t id)
{
    return WIN_MGR->GetPhysicalDisplay(id);
}

std::optional<WindowInfo> KnuckleContextImpl::GetWindowAndDisplayInfo(int32_t windowId, int32_t displayId)
{
    return WIN_MGR->GetWindowAndDisplayInfo(windowId, displayId);
}

void KnuckleContextImpl::ReportKnuckleClickEvent()
{
    DfxHisysevent::ReportKnuckleClickEvent();
}

void KnuckleContextImpl::ReportFailIfOneSuccTwoFail(const std::shared_ptr<PointerEvent> touchEvent)
{
    DfxHisysevent::ReportFailIfOneSuccTwoFail(touchEvent);
}

void KnuckleContextImpl::ReportFailIfKnockTooFast()
{
    DfxHisysevent::ReportFailIfKnockTooFast();
}

void KnuckleContextImpl::ReportSingleKnuckleDoubleClickEvent(int32_t intervalTime, int32_t distanceInterval)
{
    DfxHisysevent::ReportSingleKnuckleDoubleClickEvent(intervalTime, distanceInterval);
}

void KnuckleContextImpl::ReportScreenRecorderGesture(int32_t intervalTime)
{
    DfxHisysevent::ReportScreenRecorderGesture(intervalTime);
}

void KnuckleContextImpl::ReportFailIfInvalidTime(const std::shared_ptr<PointerEvent> touchEvent, int32_t intervalTime)
{
    DfxHisysevent::ReportFailIfInvalidTime(touchEvent, intervalTime);
}

void KnuckleContextImpl::ReportFailIfInvalidDistance(const std::shared_ptr<PointerEvent> touchEvent, float distance)
{
    DfxHisysevent::ReportFailIfInvalidDistance(touchEvent, distance);
}

void KnuckleContextImpl::ReportScreenCaptureGesture()
{
    DfxHisysevent::ReportScreenCaptureGesture();
}

void KnuckleContextImpl::ReportKnuckleGestureFaildTimes()
{
    DfxHisysevent::ReportKnuckleGestureFaildTimes();
}

void KnuckleContextImpl::ReportKnuckleGestureTrackLength(int32_t knuckleGestureTrackLength)
{
    DfxHisysevent::ReportKnuckleGestureTrackLength(knuckleGestureTrackLength);
}

void KnuckleContextImpl::ReportKnuckleGestureTrackTime(const std::vector<int64_t> &gestureTimeStamps)
{
    DfxHisysevent::ReportKnuckleGestureTrackTime(gestureTimeStamps);
}

void KnuckleContextImpl::ReportKnuckleGestureFromSuccessToFailTime(int32_t intervalTime)
{
    DfxHisysevent::ReportKnuckleGestureFromSuccessToFailTime(intervalTime);
}

void KnuckleContextImpl::ReportSmartShotSuccTimes()
{
    DfxHisysevent::ReportSmartShotSuccTimes();
}

void KnuckleContextImpl::ReportKnuckleDrawSSuccessTimes()
{
    DfxHisysevent::ReportKnuckleDrawSSuccessTimes();
}

void KnuckleContextImpl::ReportKnuckleGestureFromFailToSuccessTime(int32_t intervalTime)
{
    DfxHisysevent::ReportKnuckleGestureFromFailToSuccessTime(intervalTime);
}

std::string KnuckleContextImpl::GetBundleName(const std::string &key)
{
    return BUNDLE_NAME_PARSER.GetBundleName(key);
}

void KnuckleContextImpl::LaunchAbility(const Ability &ability, int64_t delay)
{
    LAUNCHER_ABILITY->LaunchAbility(ability, delay);
}

int32_t KnuckleContextImpl::SyncKnuckleStatus(bool isKnuckleEnable)
{
#ifdef OHOS_BUILD_ENABLE_ANCO
    return WIN_MGR->SyncKnuckleStatus(isKnuckleEnable);
#else
    return RET_OK;
#endif // OHOS_BUILD_ENABLE_ANCO
}

bool KnuckleContextImpl::UpdateDisplayId(int32_t &displayId)
{
    return WIN_MGR->UpdateDisplayId(displayId);
}
} // namespace MMI
} // namespace OHOS