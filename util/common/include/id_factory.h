/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
 
#ifndef ID_FACTORY_H
#define ID_FACTORY_H

#include <set>

#include "nocopyable.h"

namespace OHOS {
namespace MMI {
template<typename T>
class IdFactory {
public:
    IdFactory() : IdFactory(1) {}
    explicit IdFactory(T seed) : seed_(seed) {}
    virtual ~IdFactory() = default;
    DISALLOW_COPY_AND_MOVE(IdFactory);

    T GenerateId()
    {
        if (ids_.empty()) {
            if (seed_ == maxLimit_) {
                return 0;
            }
            return seed_++;
        }
        T id = *ids_.begin();
        ids_.erase(ids_.begin());
        return id;
    }
    void RecoveryId(T id)
    {
        if (id > seed_) {
            return;
        }
        ids_.insert(id);
    }

private:
    T seed_ { 0 };
    const T maxLimit_ = std::numeric_limits<T>::max();
    std::set<T> ids_;
};
} // namespace MMI
} // namespace OHOS
#endif // ID_FACTORY_H
