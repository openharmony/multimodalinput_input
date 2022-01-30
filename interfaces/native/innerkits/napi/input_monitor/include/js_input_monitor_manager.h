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

#ifndef JS_INPUT_MONITOR_MANAGER_H
#define JS_INPUT_MONITOR_MANAGER_H

#include <list>
#include <mutex>
#include <inttypes.h>
#include "js_input_monitor.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace MMI {

class JsInputMonitorManager {
public:
    static JsInputMonitorManager& GetInstance();

    ~JsInputMonitorManager();

    void AddMonitor(napi_env jsEnv, napi_value receiver);

    void RemoveMonitor(napi_env jsEnv, napi_value receiver);

    void RemoveMonitor(napi_env jsEnv);

    std::shared_ptr<JsInputMonitor> GetMonitor(int32_t id);

    void ResetEnv();

private:
    JsInputMonitorManager() = default;

    JsInputMonitorManager(const JsInputMonitorManager&) = delete;

    JsInputMonitorManager(JsInputMonitorManager&&) = delete;

    JsInputMonitorManager& operator=(const JsInputMonitorManager&) = delete;

private:
    int32_t nextId_ {0};
    std::mutex mutex_;
    std::list<std::shared_ptr<JsInputMonitor>> monitors_;
};
}
}
#define JSIMM JsInputMonitorManager::GetInstance()
#endif
