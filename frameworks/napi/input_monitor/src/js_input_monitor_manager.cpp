/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
} // namespace

JsInputMonitorManager& JsInputMonitorManager::GetInstance()
{
    static JsInputMonitorManager instance;
    return instance;
}

void JsInputMonitorManager::AddMonitor(napi_env jsEnv, napi_value callback)
{
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    for (const auto& item : monitors_) {
        if ((item != nullptr) && (item->IsMatch(jsEnv, callback) != RET_ERR)) {
            MMI_LOGD("add js monitor failed");
            return;
        }
    }
    auto monitor = std::make_shared<JsInputMonitor>(jsEnv, callback, nextId_++);
    CHKPV(monitor);
    if (!monitor->Start()) {
        MMI_LOGD("js monitor startup failed");
        return;
    }
    monitors_.push_back(monitor);
}

void JsInputMonitorManager::RemoveMonitor(napi_env jsEnv, napi_value callback)
{
    CALL_LOG_ENTER;
    std::shared_ptr<JsInputMonitor> monitor = nullptr;
    do {
        std::lock_guard<std::mutex> guard(mutex_);
        for (auto it = monitors_.begin(); it != monitors_.end();) {
            if ((*it) == nullptr) {
                it = monitors_.erase(it);
                continue;
            }
            if ((*it)->IsMatch(jsEnv, callback) == RET_OK) {
                monitor = *it;
                monitors_.erase(it);
                MMI_LOGD("Found monitor");
                break;
            }
            ++it;
        }
    } while (0);
    
    if (monitor != nullptr) {
        monitor->Stop();
    }
}

void JsInputMonitorManager::RemoveMonitor(napi_env jsEnv)
{
    CALL_LOG_ENTER;
    std::list<std::shared_ptr<JsInputMonitor>> monitors;
    do {
        std::lock_guard<std::mutex> guard(mutex_);
        for (auto it = monitors_.begin(); it != monitors_.end();) {
            if ((*it) == nullptr) {
                it = monitors_.erase(it);
                continue;
            }
            if ((*it)->IsMatch(jsEnv) == RET_OK) {
                monitors.push_back(*it);
                monitors_.erase(it++);
                continue;
            }
            ++it;
        }
    } while (0);

    for (const auto &item : monitors) {
        if (item != nullptr) {
            item->Stop();
        }
    }
}

std::shared_ptr<JsInputMonitor> JsInputMonitorManager::GetMonitor(int32_t id) {
    CALL_LOG_ENTER;
    std::lock_guard<std::mutex> guard(mutex_);
    for (const auto &item : monitors_) {
        if ((item != nullptr) && (item->GetId() == id)) {
            return item;
        }
    } 
    MMI_LOGD("No monitor found");
    return nullptr;
}

bool JsInputMonitorManager::AddEnv(napi_env env, napi_callback_info cbInfo)
{
    CALL_LOG_ENTER;
    if (IsExisting(env)) {
        MMI_LOGD("Env is already exists");
        return true;
    }
    napi_value thisVar = nullptr;
    void *data = nullptr;
    int32_t *id = new (std::nothrow) int32_t;
    CHKPF(id);
    *id = 0;
    napi_get_cb_info(env, cbInfo, nullptr, nullptr, &thisVar, &data);
    auto status = napi_wrap(env, thisVar, static_cast<void*>(id),
                            [](napi_env env, void *data, void *hint) {
                                MMI_LOGD("napi_wrap enter");
                                int32_t *id = static_cast<int32_t *>(data);
                                delete id;
                                id = nullptr;
                                JsInputMonMgr.RemoveMonitor(env);
                                JsInputMonMgr.RemoveEnv(env);
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
    auto iter = envManager_.insert(std::pair<napi_env, napi_ref>(env, ref));
    if (!iter.second) {
        MMI_LOGE("Insert value failed");
        return false;
    }
    return true;
}

void JsInputMonitorManager::RemoveEnv(napi_env env)
{
    CALL_LOG_ENTER;
    auto it = envManager_.find(env);
    if (it == envManager_.end()) {
        MMI_LOGD("No env found");
        return;
    }
    RemoveEnv(it);
}

void JsInputMonitorManager::RemoveEnv(std::map<napi_env, napi_ref>::iterator it)
{
    CALL_LOG_ENTER;
    uint32_t refCount;
    auto status = napi_reference_unref(it->first, it->second, &refCount);
    if (status != napi_ok) {
        MMI_LOGE("napi_reference_unref failed");
        return;
    }
    envManager_.erase(it);
}

void JsInputMonitorManager::RemoveAllEnv()
{
    CALL_LOG_ENTER;
    for (auto it = envManager_.begin(); it != envManager_.end();) {
        RemoveEnv(it++);
    }
}

bool JsInputMonitorManager::IsExisting(napi_env env)
{
    CALL_LOG_ENTER;
    auto it = envManager_.find(env);
    if (it == envManager_.end()) {
        MMI_LOGD("No env found");
        return false;
    }

    return true;
}
} // namespace MMI
} // namespace OHOS
