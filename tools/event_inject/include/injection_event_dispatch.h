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

#ifndef INJECTION_EVENT_DISPATCH_H
#define INJECTION_EVENT_DISPATCH_H

#include "manage_inject_device.h"
#include "injection_tools_help_func.h"

namespace OHOS {
namespace MMI {
using InjectFunction = std::function<int32_t()>;

struct InjectFunctionMap {
    std::string id;
    InjectFunction fun;
};

class InjectionEventDispatch {
public:
    InjectionEventDispatch() = default;
    ~InjectionEventDispatch() = default;
    DISALLOW_COPY_AND_MOVE(InjectionEventDispatch);

    void Init();
    void InitManageFunction();
    void Run();
    int32_t OnSendEvent();
    int32_t OnJson();
    int32_t OnHelp();
    int32_t ExecuteFunction(std::string funId);
    std::string GetFunId() const;
    bool VerifyArgvs(const int32_t &argc, const std::vector<std::string> &argv);
    bool RegisterInjectEvent(InjectFunctionMap &msg)
    {
        auto it = injectFuns_.find(msg.id);
        if (it != injectFuns_.end()) {
            return false;
        }
        injectFuns_[msg.id] = msg.fun;
        return true;
    }

    InjectFunction* GetFun(std::string id)
    {
        auto it = injectFuns_.find(id);
        if (it == injectFuns_.end()) {
            return nullptr;
        }
        return &it->second;
    }
private:
    std::string funId_ { "" };
    int32_t argvNum_ { 0 };
    ManageInjectDevice manageInjectDevice_;
    std::vector<std::string> injectArgvs_;
    std::map<std::string, InjectFunction> injectFuns_;
    bool CheckType(const std::string &inputType);
    bool CheckCode(const std::string &inputCode);
    bool CheckValue(const std::string &inputValue);
    bool CheckEventValue(const std::string &inputType, const std::string &inputCode,
    const std::string &inputValue);
};
} // namespace MMI
} // namespace OHOS
#endif // INJECTION_EVENT_DISPATCH_H