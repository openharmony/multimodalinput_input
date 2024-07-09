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

#include "key_map_manager.h"

#include <array>

#include "define_multimodal.h"
#include "input_device_manager.h"
#include "mmi_log.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyMapManager"

namespace OHOS {
namespace MMI {
KeyMapManager::KeyMapManager() {}
KeyMapManager::~KeyMapManager() {}

void KeyMapManager::GetConfigKeyValue(const std::string &fileName, int32_t deviceId)
{
    CALL_DEBUG_ENTER;
    std::string filePath = GetProFilePath(fileName);
    ReadProFile(filePath, deviceId, configKeyValue_);
    MMI_HILOGD("Number of loaded config files:%{public}zu", configKeyValue_.size());
}

void KeyMapManager::ParseDeviceConfigFile(struct libinput_device *device)
{
    CHKPV(device);
    std::string fileName = GetKeyEventFileName(device);
    if (fileName.empty()) {
        MMI_HILOGE("Get fileName is empty");
        return;
    }
    int32_t deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
    GetConfigKeyValue(fileName, deviceId);
}

void KeyMapManager::RemoveKeyValue(struct libinput_device *device)
{
    CHKPV(device);
    int32_t deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
    auto iter = configKeyValue_.find(deviceId);
    if (iter == configKeyValue_.end()) {
        MMI_HILOGD("Device config file does not exist");
        return;
    }
    configKeyValue_.erase(iter);
    MMI_HILOGD("Number of files that remain after deletion:%{public}zu", configKeyValue_.size());
}

int32_t KeyMapManager::GetDefaultKeyId()
{
    return defaultKeyId_;
}

std::string KeyMapManager::GetProFilePath(const std::string &fileName) const
{
    return "/vendor/etc/keymap/" + fileName + ".pro";
}

std::string KeyMapManager::GetKeyEventFileName(struct libinput_device *device)
{
    CHKPS(device);
    uint32_t vendor = libinput_device_get_id_vendor(device);
    uint32_t product = libinput_device_get_id_product(device);
    uint32_t version = libinput_device_get_id_version(device);
    const char *name = libinput_device_get_name(device);
    CHKPS(name);
    std::string fileName = std::to_string(vendor) + "_" + std::to_string(product) + "_" +
        std::to_string(version) + "_" + name;
    RemoveSpace(fileName);
    return fileName;
}

int32_t KeyMapManager::TransferDefaultKeyValue(int32_t inputKey)
{
    CALL_DEBUG_ENTER;
    if (auto itr = configKeyValue_.find(defaultKeyId_); itr != configKeyValue_.end()) {
        if (auto defaultKey = itr->second.find(inputKey); defaultKey != itr->second.end()) {
            return defaultKey->second;
        }
    }
    MMI_HILOGD("Return key values in the TransferKeyValue");
    return TransferKeyValue(inputKey).sysKeyValue;
}

int32_t KeyMapManager::TransferDeviceKeyValue(struct libinput_device *device,
    int32_t inputKey)
{
    CALL_DEBUG_ENTER;
    if (device == nullptr) {
        return TransferDefaultKeyValue(inputKey);
    }
    int32_t deviceId = INPUT_DEV_MGR->FindInputDeviceId(device);
    if (auto itr = configKeyValue_.find(deviceId); itr != configKeyValue_.end()) {
        if (auto devKey = itr->second.find(inputKey); devKey != itr->second.end()) {
            return devKey->second;
        }
    }
    return TransferDefaultKeyValue(inputKey);
}

std::vector<int32_t> KeyMapManager::InputTransferKeyValue(int32_t deviceId, int32_t keyCode)
{
    std::vector<int32_t> sysKey;
    if (auto iter = configKeyValue_.find(deviceId); iter != configKeyValue_.end()) {
        for (const auto &it : iter->second) {
            if (it.second == keyCode) {
                sysKey.push_back(it.first);
            }
        }
        return sysKey;
    } else if (auto itr = configKeyValue_.find(defaultKeyId_); itr != configKeyValue_.end()) {
        for (const auto &it : itr->second) {
            if (it.second == keyCode) {
                sysKey.push_back(it.first);
            }
        }
        return sysKey;
    } else {
        sysKey.push_back(InputTransformationKeyValue(keyCode));
        return sysKey;
    }
    return sysKey;
}
} // namespace MMI
} // namespace OHOS
