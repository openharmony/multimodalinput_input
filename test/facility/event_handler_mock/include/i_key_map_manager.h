/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MMI_I_KEY_MAP_MANAGER_MOCK_H
#define MMI_I_KEY_MAP_MANAGER_MOCK_H

#include <cstdint>
#include <memory>
#include <vector>

#include "key_event.h"

namespace OHOS {
namespace MMI {
class IKeyMapManager {
public:
    virtual void GetConfigKeyValue(const std::string&, int32_t) = 0;
    virtual void ParseDeviceConfigFile(struct libinput_device*) = 0;
    virtual void RemoveKeyValue(struct libinput_device*) = 0;
    virtual std::string GetProFilePath(const std::string&) const = 0;
    virtual std::string GetKeyEventFileName(struct libinput_device*) = 0;
    virtual int32_t GetDefaultKeyId() = 0;
    virtual int32_t TransferDefaultKeyValue(int32_t) = 0;
    virtual int32_t TransferDeviceKeyValue(struct libinput_device*, int32_t) = 0;
    virtual std::vector<int32_t> InputTransferKeyValue(int32_t, int32_t) = 0;
    virtual uint32_t KeyCodeToUnicode(int32_t, std::shared_ptr<KeyEvent>) = 0;
    virtual int32_t KeyItemsTransKeyIntention(const std::vector<KeyEvent::KeyItem>&) = 0;
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_I_KEY_MAP_MANAGER_MOCK_H
