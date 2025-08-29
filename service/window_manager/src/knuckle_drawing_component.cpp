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

#include "knuckle_drawing_component.h"

#include <string>
#include "dlfcn.h"

#include "define_multimodal.h"
#include "mmi_log.h"
#include "timer_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KnuckleDrawingComponent"

namespace {
static const std::string KNUCKLE_DRAWING_LIB_PATH = "libmmi-knuckle.z.so";
constexpr int32_t UNLOAD_TIME_MS = 2 * 60 * 1000; // 2 minutes
constexpr int32_t CHECK_INTERVAL_MS = 20 * 1000; // check every 20 seconds
constexpr int32_t CHECK_COUNT = -1;
} // namespace

namespace OHOS {
namespace MMI {
KnuckleDrawingComponent &KnuckleDrawingComponent::GetInstance()
{
    static KnuckleDrawingComponent instance;
    return instance;
}

void KnuckleDrawingComponent::Draw(const OLD::DisplayInfo& displayInfo,
    const std::shared_ptr<PointerEvent> &touchEvent)
{
    lastCallTime_ = std::chrono::steady_clock::now();
    IKnuckleDrawing *impl = Load();
    CHKPRV(impl, "load knuckle lib fail");
    impl->Draw(displayInfo, touchEvent);
}

void KnuckleDrawingComponent::SetMultiWindowScreenId(uint64_t screenId, uint64_t displayNodeScreenId)
{
    lastCallTime_ = std::chrono::steady_clock::now();
    IKnuckleDrawing *impl = Load();
    CHKPRV(impl, "load knuckle lib fail");
    impl->SetMultiWindowScreenId(screenId, displayNodeScreenId);
    windowScreenId_ = screenId;
    displayNodeScreenId_ = displayNodeScreenId;
}

KnuckleDrawingComponent::~KnuckleDrawingComponent()
{
    Unload();
}

IKnuckleDrawing *KnuckleDrawingComponent::Load()
{
    if (impl_ != nullptr) {
        return impl_;
    }

    if (!LoadKnuckleSharedLibrary()) {
        MMI_HILOGE("load knuckle shared library fail");
        return nullptr;
    }

    impl_ = create_();
    if (impl_ == nullptr) {
        MMI_HILOGE("create KnuckleDrawing fail");
        Unload();
        return nullptr;
    }
    impl_->RegisterAddTimer([this]
        (int32_t intervalMs, int32_t repeatCount, std::function<void()> callback, const std::string &name) -> int32_t {
        return TimerMgr->AddTimer(intervalMs, repeatCount, callback, name);
    });
    if (timerId_ > 0) {
        TimerMgr->RemoveTimer(timerId_);
    }
    timerId_ = TimerMgr->AddLongTimer(CHECK_INTERVAL_MS, CHECK_COUNT, [this] {
        auto idleTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - lastCallTime_).count();
        if (idleTime >= UNLOAD_TIME_MS) {
            KnuckleDrawingComponent::GetInstance().Unload();
        }
    }, "KnuckleDrawingComponent-Unload");
    if (timerId_ < 0) {
        MMI_HILOGE("Add timer for unloading knuckle library fail");
        Unload();
        return nullptr;
    }
    impl_ ->SetMultiWindowScreenId(windowScreenId_, displayNodeScreenId_);
    MMI_HILOGD("success to Load KnuckleDrawing");
    return impl_;
}

bool KnuckleDrawingComponent::LoadKnuckleSharedLibrary()
{
    if (handle_ == nullptr) {
        handle_ = ::dlopen(KNUCKLE_DRAWING_LIB_PATH.c_str(), RTLD_LAZY);
        if (handle_ == nullptr) {
            MMI_HILOGE("%{public}s dlopen fail", KNUCKLE_DRAWING_LIB_PATH.c_str());
            return false;
        }
    }

    create_ = reinterpret_cast<GetKnuckleDrawingFunc>(::dlsym(handle_, "GetKnuckleDrawing"));
    if (create_ == nullptr) {
        MMI_HILOGE("dlsym GetKnuckleDrawing fail");
        ::dlclose(handle_);
        return false;
    }

    destroy_ = reinterpret_cast<DestroyKnuckleDrawingFunc>(::dlsym(handle_, "DestroyKnuckleDrawing"));
    if (destroy_ == nullptr) {
        MMI_HILOGE("dlsym DestroyKnuckleDrawing fail");
        create_ = nullptr;
        ::dlclose(handle_);
        return false;
    }
    MMI_HILOGD("success to load knuckle shared library");
    return true;
}

void KnuckleDrawingComponent::Unload()
{
    TimerMgr->RemoveTimer(timerId_);
    timerId_ = -1;

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
    MMI_HILOGD("success to Unload KnuckleDrawing");
}
} // namespace MMI
} // namespace OHOS
