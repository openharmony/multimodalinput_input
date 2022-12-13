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

#ifndef KEY_MAP_MANAGER_H
#define KEY_MAP_MANAGER_H

#include <map>
#include <string>

#include "key_event_value_transformation.h"
#include "libinput.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
class KeyMapManager final {
    DECLARE_DELAYED_SINGLETON(KeyMapManager);
public:
    DISALLOW_COPY_AND_MOVE(KeyMapManager);
    void GetConfigKeyValue(const std::string &fileName, int32_t deviceId);
    void ParseDeviceConfigFile(struct libinput_device *device);
    void RemoveKeyValue(struct libinput_device *device);
    std::string GetProFilePath(const std::string &fileName) const;
    std::string GetKeyEventFileName(struct libinput_device *device);
    int32_t GetDefaultKeyId();
    int32_t TransferDefaultKeyValue(int32_t inputKey);
    int32_t TransferDeviceKeyValue(struct libinput_device *device, int32_t inputKey);
    std::vector<int32_t> InputTransferKeyValue(int32_t deviceId, int32_t keyCode);
private:
    std::map<int32_t, std::map<int32_t, int32_t>> configKeyValue_;
    int32_t defaultKeyId_ { -1 };
};

#define KeyMapMgr ::OHOS::DelayedSingleton<KeyMapManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // KEY_MAP_MANAGER_H