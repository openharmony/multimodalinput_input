/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MMI_KEY_MAP_MANAGER_MOCK_H
#define MMI_KEY_MAP_MANAGER_MOCK_H

#include <vector>
#include <gmock/gmock.h>

#include "key_event_value_transformation.h"
#include "libinput.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class IKeyMapManager {
public:
    IKeyMapManager() = default;
    virtual ~IKeyMapManager() = default;

    virtual void GetConfigKeyValue(const std::string&, int32_t) = 0;
    virtual void ParseDeviceConfigFile(struct libinput_device*) = 0;
    virtual void RemoveKeyValue(struct libinput_device*) = 0;
    virtual std::string GetProFilePath(const std::string&) const = 0;
    virtual std::string GetKeyEventFileName(struct libinput_device*) = 0;
    virtual int32_t GetDefaultKeyId() = 0;
    virtual int32_t TransferDefaultKeyValue(int32_t) = 0;
    virtual int32_t TransferDeviceKeyValue(struct libinput_device*, int32_t) = 0;
    virtual std::vector<int32_t> InputTransferKeyValue(int32_t, int32_t) = 0;
};

class KeyMapManager final : public IKeyMapManager {
public:
    static std::shared_ptr<KeyMapManager> GetInstance();
    static void ReleaseInstance();

    KeyMapManager() = default;
    ~KeyMapManager() = default;
    DISALLOW_COPY_AND_MOVE(KeyMapManager);

    MOCK_METHOD(void, GetConfigKeyValue, (const std::string&, int32_t));
    MOCK_METHOD(void, ParseDeviceConfigFile, (struct libinput_device*));
    MOCK_METHOD(void, RemoveKeyValue, (struct libinput_device*));
    MOCK_METHOD(std::string, GetProFilePath, (const std::string&), (const));
    MOCK_METHOD(std::string, GetKeyEventFileName, (struct libinput_device*));
    MOCK_METHOD(int32_t, GetDefaultKeyId, ());
    MOCK_METHOD(int32_t, TransferDefaultKeyValue, (int32_t));
    MOCK_METHOD(int32_t, TransferDeviceKeyValue, (struct libinput_device*, int32_t));
    MOCK_METHOD(std::vector<int32_t>, InputTransferKeyValue, (int32_t, int32_t));

private:
    static std::shared_ptr<KeyMapManager> instance_;
};

#define KeyMapMgr KeyMapManager::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MMI_KEY_MAP_MANAGER_MOCK_H