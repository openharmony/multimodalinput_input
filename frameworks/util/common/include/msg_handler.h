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
#ifndef MSG_HANDLER_H
#define MSG_HANDLER_H

#include <map>
#include <functional>
#include "proto.h"

namespace OHOS {
namespace MMI {
template<typename T>
class MsgHandler {
public:
    void Clear()
    {
        mapFuns_.clear();
    }

protected:
    struct MsgCallback {
        MmiMessageId id;
        T fun;
    };

protected:
    virtual ~MsgHandler() {};
    T *GetFun(MmiMessageId id)
    {
        auto it = mapFuns_.find(id);
        if (it == mapFuns_.end())
            return nullptr;
        return &it->second;
    }
    bool RegistrationEvent(MsgCallback& msg)
    {
        auto it = mapFuns_.find(msg.id);
        if (it != mapFuns_.end())
            return false;
        mapFuns_[msg.id] = msg.fun;
        return true;
    }

protected:
    std::map<MmiMessageId, T> mapFuns_;
};
}
}
#endif // MSG_HANDLER_H