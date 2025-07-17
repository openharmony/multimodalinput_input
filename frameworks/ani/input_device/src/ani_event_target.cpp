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

#include "ani_event_target.h"
#include "ani_util.h"
#include "bytrace_adapter.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniEventTarget"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t INPUT_PARAMETER_MIDDLE { 2 };

std::mutex mutex_;
const std::string ADD_EVENT = "add";
const std::string REMOVE_EVENT = "remove";
const std::string CHANGED_TYPE = "change";
constexpr int32_t ANI_SCOPE_SIZE = 16;

struct DeviceItem {
    int32_t deviceId;
    void *item;
};

} // namespace

AniEventTarget::AniEventTarget()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(mutex_);
    auto ret = devListener_.insert({ CHANGED_TYPE, std::vector<std::unique_ptr<AniUtil::CallbackInfo>>() });
    CK(ret.second, VAL_NOT_EXP);
    GetMainEventHandler();
}

AniEventTarget::~AniEventTarget()
{
    CALL_DEBUG_ENTER;
    handler_ = nullptr;
}

void AniEventTarget::GetMainEventHandler()
{
    CALL_DEBUG_ENTER;
    auto runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
    handler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
}

bool AniEventTarget::EmitCallbackWork(ani_env *env, const std::shared_ptr<AniUtil::ReportData> &reportData,
    const std::string &type)
{
    CALL_DEBUG_ENTER;
    AniLocalScopeGuard aniLocalScopeGuard(env, ANI_SCOPE_SIZE);
    if (!aniLocalScopeGuard.IsStatusOK()) {
        MMI_HILOGE("%{public}s: CreateLocalScope failed", __func__);
        return false;
    }
    std::vector<ani_ref> args;
    const char *nsName = "@ohos.multimodalInput.inputDevice.inputDevice";
    const char *className = "DeviceListenerImpl";
    auto obj = AniUtil::CreateAniObject(env, nsName, className);
    if (obj == nullptr) {
        MMI_HILOGE("%{public}s: CreateAniObject DeviceListenerObj failed", __func__);
        return false;
    }
    ani_string stringValue = AniUtil::StdStringToANIString(env, type);
    if (ANI_OK != env->Object_SetPropertyByName_Ref(obj, "type", stringValue)) {
        MMI_HILOGE("%{public}s: Object_SetPropertyByName_Ref failed",  __func__);
        return false;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Double(obj, "deviceId", reportData->deviceId)) {
        MMI_HILOGE("%{public}s: SetPropertyByName deviceId:%{public}d failed", __func__, reportData->deviceId);
        return false;
    }

    MMI_HILOGE("%{public}s: type:%{public}s, deviceId:%{public}d", __func__, type.c_str(), reportData->deviceId);
    args.push_back(obj);

    auto fnObj = reinterpret_cast<ani_fn_object>(reportData->ref);
    if (AniUtil::IsInstanceOf(env, "std.core.Function1", fnObj) == 0) {
        MMI_HILOGE("%{public}s: fnObj is not instance Of function", __func__);
        return false;
    }

    ani_ref result;
    if (ANI_OK != env->FunctionalObject_Call(fnObj, 1, args.data(), &result)) {
        MMI_HILOGE("%{public}s: FunctionalObject_Call failed", __func__);
        return false;
    }
    MMI_HILOGD("FunctionalObject_Call success");
    return true;
}

void AniEventTarget::EmitAddedDeviceEvent(const std::shared_ptr<AniUtil::ReportData> &reportData)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto addEvent = devListener_.find(CHANGED_TYPE);
    if (addEvent == devListener_.end()) {
        MMI_HILOGE("%{public}s: Find change event failed", __func__);
        return;
    }
    for (const auto &item : addEvent->second) {
        CHKPC(item->env_);
        if (item->callback_ != reportData->ref) {
            continue;
        }

        if (!EmitCallbackWork(item->env_, reportData, ADD_EVENT)) {
            continue;
        }

        BytraceAdapter::StartDevListener(ADD_EVENT, reportData->deviceId);
        MMI_HILOGI("Report device change task, event type:%{public}s, deviceid:%{public}d",
            ADD_EVENT.c_str(), reportData->deviceId);
        BytraceAdapter::StopDevListener();
    }
}

void AniEventTarget::EmitRemoveDeviceEvent(const std::shared_ptr<AniUtil::ReportData> &reportData)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto removeEvent = devListener_.find(CHANGED_TYPE);
    if (removeEvent == devListener_.end()) {
        MMI_HILOGE("%{public}s: Find change event failed", __func__);
        return;
    }
    for (const auto &item : removeEvent->second) {
        CHKPC(item->env_);
        if (item->callback_ != reportData->ref) {
            continue;
        }

        if (!EmitCallbackWork(item->env_, reportData, REMOVE_EVENT)) {
            continue;
        }

        BytraceAdapter::StartDevListener(REMOVE_EVENT, reportData->deviceId);
        MMI_HILOGI("Report device change task, event type:%{public}s, deviceid:%{public}d",
            REMOVE_EVENT.c_str(), reportData->deviceId);
        BytraceAdapter::StopDevListener();
    }
}

void AniEventTarget::PostMainThreadTask(const std::function<void()> task)
{
    if (!handler_) {
        auto runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        if (!runner) {
            MMI_HILOGE("get main event runner failed!");
            return;
        }
        handler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    bool ret = handler_->PostTask(task, "", 0, OHOS::AppExecFwk::EventQueue::Priority::HIGH, {});
    MMI_HILOGI("%{public}s: PostTask %{public}s", __func__, (ret? "success" : "failed"));
}

void AniEventTarget::OnDeviceAdded(int32_t deviceId, const std::string &type)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto changeEvent = devListener_.find(CHANGED_TYPE);
    if (changeEvent == devListener_.end()) {
        MMI_HILOGE("%{public}s: Find %{public}s failed", __func__, CHANGED_TYPE.c_str());
        return;
    }

    for (auto &item : changeEvent->second) {
        CHKPC(item);
        CHKPC(item->env_);
        auto reportData = std::make_shared<AniUtil::ReportData>();
        if (reportData == nullptr) {
            MMI_HILOGE("%{public}s: Memory allocation failed", __func__);
            return;
        }
        reportData->deviceId = deviceId;
        reportData->ref = item->callback_;
        auto task = [reportData, this] () { EmitAddedDeviceEvent(reportData); };
        PostMainThreadTask(task);
    }
}

void AniEventTarget::OnDeviceRemoved(int32_t deviceId, const std::string &type)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto changeEvent = devListener_.find(CHANGED_TYPE);
    if (changeEvent == devListener_.end()) {
        MMI_HILOGE("%{public}s: Find %{public}s failed", __func__, CHANGED_TYPE.c_str());
        return;
    }
    for (auto &item : changeEvent->second) {
        CHKPC(item);
        CHKPC(item->env_);
        std::shared_ptr<AniUtil::ReportData> reportData = std::make_shared<AniUtil::ReportData>();
        if (reportData == nullptr) {
            MMI_HILOGE("%{public}s: Memory allocation failed", __func__);
            return;
        }
        reportData->deviceId = deviceId;
        reportData->ref = item->callback_;
        auto task = [reportData, this] () { EmitRemoveDeviceEvent(reportData); };
        PostMainThreadTask(task);
    }
}

void AniEventTarget::AddListener(ani_env *env, const std::string &type, ani_object handle)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    auto it = devListener_.find(type);
    if (it == devListener_.end()) {
        MMI_HILOGE("%{public}s: Find %{public}s failed", __func__, type.c_str());
        return;
    }

    auto monitor = std::make_unique<AniUtil::CallbackInfo>();
    monitor->env_ = env;
    if (!monitor->SetCallback(handle)) {
        return;
    }

    for (const auto &iter : it->second) {
        CHKPC(iter);
        if (AniUtil::IsSameHandle(env, monitor->callback_, iter->env_, iter->callback_)) {
            MMI_HILOGW("The handle already exists");
            return;
        }
    }

    it->second.push_back(std::move(monitor));
    if (!isListeningProcess_) {
        isListeningProcess_ = true;
        InputManager::GetInstance()->RegisterDevListener("change", shared_from_this());
    }
}

void AniEventTarget::ResetEnv()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    devListener_.clear();
    InputManager::GetInstance()->UnregisterDevListener("change", shared_from_this());
}
} // namespace MMI
} // namespace OHOS
