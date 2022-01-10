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
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
        LOG_CORE, MMI_LOG_DOMAIN, "JsInputMonitorManager"
    };
}

JsInputMonitorManager::~JsInputMonitorManager()
{
    for (auto &it : monitors_) {
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
    MMI_LOGD("enter");
    for (auto& monitor : monitors_) {
        if (monitor->IsMatch(jsEnv, receiver) != RET_ERR) {
            return;
        }
    }
    std::unique_ptr<JsInputMonitor> monitor = std::make_unique<JsInputMonitor>(jsEnv, receiver);
    monitor->Start();
    monitors_.push_back(std::move(monitor));
    MMI_LOGD("leave");
}

void JsInputMonitorManager::RemoveMonitor(napi_env jsEnv, napi_value receiver)
{
    MMI_LOGD("enter");
    for (auto it = monitors_.begin(); it != monitors_.end(); ++it) {
        if ((*it)->IsMatch(jsEnv, receiver) == RET_OK) {
            (*it)->Stop();
            monitors_.erase(it);
            return;
        }
    }
    MMI_LOGD("leave");
}

void JsInputMonitorManager::RemoveMonitor(napi_env jsEnv)
{
    MMI_LOGD("enter");
    for (auto it = monitors_.begin(); it != monitors_.end();) {
        if ((*it)->IsMatch(jsEnv) == RET_OK) {
            (*it)->Stop();
            monitors_.erase(it++);
            return;
        }
        ++it;
    }
    MMI_LOGD("leave");
}
}
}