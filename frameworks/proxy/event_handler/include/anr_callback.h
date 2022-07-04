/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ANR_CALLBACK_H
#define ANR_CALLBACK_H

#include <functional>

#include "nocopyable.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
class AnrCallback : public DelayedSingleton<AnrCallback> {
public:
    AnrCallback() = default;
    DISALLOW_COPY_AND_MOVE(AnrCallback);
    ~AnrCallback() = default;
    void SetAnrCallback(std::function<void(int32_t)> callback);
    void OnAnrNoticed(int32_t pid);
private:
    std::function<void(int32_t)> callback_;
};
} // namespace MMI 
} // namespace OHOS
#define AnrCall OHOS::MMI::AnrCallback::GetInstance()
#endif
