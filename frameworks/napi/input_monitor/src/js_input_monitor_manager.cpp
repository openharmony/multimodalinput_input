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
    for (const auto &it : monitors_) {
        it->Stop();
    }
    monitors_.clear();
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
    for (auto& monitor : monitors_) {
        if (monitor->IsMatch(jsEnv, receiver) != RET_ERR) {
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
                MMI_LOGD("leave");
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
    MMI_LOGD("enter");
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
    for (auto &monitor : monitors) {
        monitor->Stop();
    }
    MMI_LOGD("Leave");
}

std::shared_ptr<JsInputMonitor> JsInputMonitorManager::GetMonitor(int32_t id) {
    MMI_LOGD("enter");
    std::lock_guard<std::mutex> guard(mutex_);
    for (auto &monitor : monitors_) {
        if (monitor->GetId() == id) {
            MMI_LOGD("Leave");
            return monitor;
        }
    } 
    MMI_LOGD("no monitor found");
    return nullptr;
}
} // namespace MMI
} // namespace OHOS
