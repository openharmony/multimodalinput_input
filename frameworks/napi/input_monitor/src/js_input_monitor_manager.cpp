/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "js_input_monitor_manager.h"
#include <uv.h>
#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "JsInputMonitorManager" };
}

JsInputMonitorManager::~JsInputMonitorManager()
{
    for (const auto &item : monitors_) {
        item->Stop();
    }
    monitors_.clear();
    RemoveAllEnv();
}

JsInputMonitorManager& JsInputMonitorManager::GetInstance()
{
    static JsInputMonitorManager instance;
    return instance;
}

void JsInputMonitorManager::AddMonitor(napi_env jsEnv, napi_value receiver)
{
    MMI_LOGD("Enter");
    std::lock_guard<std::mutex> guard(mutex_);
    for (auto& item : monitors_) {
        if (item->IsMatch(jsEnv, receiver) != RET_ERR) {
            return;
        }
    }
    std::shared_ptr<JsInputMonitor> monitor = std::make_shared<JsInputMonitor>(jsEnv, receiver, nextId_++);
    monitors_.push_back(monitor);
    if (!monitor->Start()) {
        monitors_.pop_back();
    }
    MMI_LOGD("Leave");
}

void JsInputMonitorManager::RemoveMonitor(napi_env jsEnv, napi_value receiver)
{
    MMI_LOGD("Enter");
    std::shared_ptr<JsInputMonitor> monitor;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        for (auto it = monitors_.begin(); it != monitors_.end(); ++it) {
            if ((*it)->IsMatch(jsEnv, receiver) == RET_OK) {
                monitor = *it;
                monitors_.erase(it);
                MMI_LOGD("Found monitor");
                break;
            }
        }
    }
    if (monitor != nullptr) {
        monitor->Stop();
    }
    MMI_LOGD("Leave");    
}

void JsInputMonitorManager::RemoveMonitor(napi_env jsEnv)
{
    MMI_LOGD("Enter");
    std::list<std::shared_ptr<JsInputMonitor>> monitors;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        for (auto it = monitors_.begin(); it != monitors_.end();) {
            if ((*it)->IsMatch(jsEnv) == RET_OK) {
                monitors.push_back(*it);
                monitors_.erase(it++);
                continue;
            }
            ++it;
        }
    }
    for (const auto &item : monitors) {
        item->Stop();
    }
    MMI_LOGD("Leave");
}

std::shared_ptr<JsInputMonitor> JsInputMonitorManager::GetMonitor(int32_t id) {
    MMI_LOGD("Enter");
    std::lock_guard<std::mutex> guard(mutex_);
    for (auto &item : monitors_) {
        if (item->GetId() == id) {
            MMI_LOGD("Leave");
            return item;
        }
    } 
    MMI_LOGD("No monitor found");
    return nullptr;
}

bool JsInputMonitorManager::AddEnv(napi_env env, napi_callback_info cbInfo)
{
    MMI_LOGD("Enter");
    if (IsExisting(env)) {
        MMI_LOGD("Env is already exists");
        return true;
    }
    napi_value thisVar = nullptr;
    void *data = nullptr;
    int32_t *id = new int32_t;
    *id = 0;
    napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, &data);
    auto status = napi_wrap(env, thisVar, static_cast<void*>(id),
                            [](napi_env env, void *data, void *hint) {
                                MMI_LOGD("napi_wrap enter");
                                int32_t *id = (int32_t *)data;
                                delete id;
                                id = nullptr;
                                JSIMM.RemoveMonitor(env);
                                JSIMM.RemoveEnv(env);
                                MMI_LOGD("napi_wrap leave");
                                }, nullptr, nullptr);
    if (status != napi_ok) {
        MMI_LOGE("napi_wrap failed");
        delete id;
        return false;
    }
    napi_ref ref = nullptr;
    status = napi_create_reference(env, thisVar, 1, &ref);
    if (status != napi_ok) {
        MMI_LOGE("napi_create_reference failed");
        delete id;
        return false;
    }
    envManager_.insert(std::pair<napi_env, napi_ref>(env, ref));
    MMI_LOGD("Leave");
    return true;
}

void JsInputMonitorManager::RemoveEnv(napi_env env)
{
    MMI_LOGD("Enter");
    auto it = envManager_.find(env);
    if (it == envManager_.end()) {
        MMI_LOGD("No env found");
        return;
    }
    RemoveEnv(it);
    MMI_LOGD("Leave");
}

void JsInputMonitorManager::RemoveEnv(std::map<napi_env, napi_ref>::iterator it)
{
    MMI_LOGD("Enter");
    uint32_t refCount;
    auto status = napi_reference_unref(it->first, it->second, &refCount);
    if (status != napi_ok) {
        MMI_LOGE("napi_reference_unref failed");
        return;
    }
    envManager_.erase(it);
    MMI_LOGD("Leave");
}

void JsInputMonitorManager::RemoveAllEnv()
{
    MMI_LOGD("Enter");
    for (auto it = envManager_.begin(); it != envManager_.end();) {
        RemoveEnv(it++);
    }
    MMI_LOGD("Leave");
}

bool JsInputMonitorManager::IsExisting(napi_env env)
{
    MMI_LOGD("Enter");
    auto it = envManager_.find(env);
    if (it == envManager_.end()) {
        MMI_LOGD("No env found");
        return false;
    }
    MMI_LOGD("Leave");
    return true;
}
} // namespace MMI
} // namespace OHOS
