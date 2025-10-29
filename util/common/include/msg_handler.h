/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef MSG_HANDLER_H
#define MSG_HANDLER_H

#include <functional>
#include <map>
#include <string>

#include "proto.h"

namespace OHOS {
namespace MMI {
template<typename K, typename V>
class MsgHandler {
public:
    void Clear()
    {
        callbacks_.clear();
    }
    bool ChkKey(K id)
    {
        return (GetMsgCallback(id) != nullptr);
    }

    std::string GetDebugInfo() const
    {
        std::string str;
        for (auto &it : callbacks_) {
            str += std::to_string(it.first);
            str += ',';
        }
        if (str.size() > 0) {
            str.resize(str.size() - 1);
        }
        return str;
    }

protected:
    struct MsgCallback {
        K id;
        V fun;
    };

protected:
    virtual ~MsgHandler() = default;
    V *GetMsgCallback(K id)
    {
        auto it = callbacks_.find(id);
        if (it == callbacks_.end()) {
            return nullptr;
        }
        return &it->second;
    }
    bool RegistrationEvent(MsgCallback& msg)
    {
        auto it = callbacks_.find(msg.id);
        if (it != callbacks_.end()) {
            return false;
        }
        callbacks_[msg.id] = msg.fun;
        return true;
    }

protected:
    std::map<K, V> callbacks_;
};
} // namespace MMI
} // namespace OHOS
#endif // MSG_HANDLER_H
