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

#ifndef CONFIG_KEY_VALUE_TRANSFORM_H
#define CONFIG_KEY_VALUE_TRANSFORM_H

#include <map>
#include <string>

#include "key_event_value_transformation.h"
#include "libinput.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
class ConfigKeyValueTransform : public DelayedSingleton<ConfigKeyValueTransform> {
public:
    ConfigKeyValueTransform() = default;
    ~ConfigKeyValueTransform() = default;
    void GetConfigKeyValue(const std::string &fileName);
    void ParseDeviceConfigFile(struct libinput_event *event);
    void RemoveKeyValue(struct libinput_event *event);
    std::string GetProFilePath(const std::string &fileName) const;
    std::string GetKeyEventFileName(struct libinput_event* event);
    KeyEventValueTransformation TransferDefaultKeyValue(int32_t inputKey);
    KeyEventValueTransformation TransferDeviceKeyValue(struct libinput_event* event, int32_t inputKey);
private:
    std::map<std::string, std::multimap<int32_t, KeyEventValueTransformation>> configKeyValue_;
};

#define KeyValueTransform ConfigKeyValueTransform::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // CONFIG_KEY_VALUE_TRANSFORM_H