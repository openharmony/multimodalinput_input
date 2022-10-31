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
#ifndef INPUT_DEVICE_COOPERATE_UTIL_H
#define INPUT_DEVICE_COOPERATE_UTIL_H

#include <string>

#include "cJSON.h"

namespace OHOS {
namespace MMI {
struct JsonParser {
    JsonParser() = default;
    ~JsonParser()
    {
        if (json_ != nullptr) {
            cJSON_Delete(json_);
            json_ = nullptr;
        }
    }
    operator cJSON *()
    {
        return json_;
    }
    cJSON *json_ { nullptr };
};
std::string GetLocalDeviceId();
} // namespace MMI
} // namespace OHOS
#endif // INPUT_DEVICE_COOPERATE_UTIL_H
