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

#ifndef JS_INPUT_MONITOR_MANAGER_H
#define JS_INPUT_MONITOR_MANAGER_H

#include <cinttypes>
#include <list>
#include <map>
#include <mutex>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "nocopyable.h"

#include "js_input_monitor.h"

namespace OHOS {
namespace MMI {
class JsInputMonitorManager {
public:
    static JsInputMonitorManager& GetInstance();
    DISALLOW_COPY_AND_MOVE(JsInputMonitorManager);
    ~JsInputMonitorManager() = default;

    void AddMonitor(napi_env jsEnv, const std::string &typeName, napi_value callback);

    void RemoveMonitor(napi_env jsEnv, const std::string &typeName, napi_value callback);

    void RemoveMonitor(napi_env jsEnv, const std::string &typeName);

    void RemoveMonitor(napi_env jsEnv);

    const std::shared_ptr<JsInputMonitor> GetMonitor(int32_t id);

    bool AddEnv(napi_env env, napi_callback_info cbInfo);

    void RemoveEnv(napi_env env);

    void ThrowError(napi_env env, int32_t code);
private:
    JsInputMonitorManager() = default;

    bool IsExisting(napi_env env);

    void RemoveEnv(std::map<napi_env, napi_ref>::iterator it);

    void RemoveAllEnv();

private:
    std::list<std::shared_ptr<JsInputMonitor>> monitors_;
    std::map<napi_env, napi_ref> envManager_;
    int32_t nextId_ { 0 };
    std::mutex mutex_;
};

#define JsInputMonMgr JsInputMonitorManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // JS_INPUT_MONITOR_MANAGER_H
