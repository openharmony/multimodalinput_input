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
#ifndef JS_REGISTER_HANDLE_H
#define JS_REGISTER_HANDLE_H
#include "js_register_module.h"

namespace OHOS {
namespace MMI {
int32_t AddEvent(const napi_env& env, StandEventPtr &eventHandle, const EventInfo &event);
int32_t DelEvent(const napi_env& env, StandEventPtr &eventHandle, const EventInfo &event);
void UnitSent(napi_env env, int32_t winId, uint32_t eventType, const MultimodalEvent& event);

class JSRegisterHandle {
public:
    explicit JSRegisterHandle(const napi_env& env);
    ~JSRegisterHandle() = default;

    int32_t Register(const StandEventPtr eventHandle, int32_t winId, uint32_t type);
    int32_t Unregister(int32_t winId, uint32_t type);
    int32_t UnregisterAll();
    StandEventPtr GetEventHandle(int32_t winId, uint32_t type);
    bool CheckRegistered(int32_t winId, uint32_t type);
    bool CheckUnregistered(int32_t winId, uint32_t type);
private:
    napi_env env_ = nullptr;
};
}
}
#endif // JS_REGISTER_HANDLE_H