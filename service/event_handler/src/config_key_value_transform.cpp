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

#include "config_key_value_transform.h"

#include <array>

#include "define_multimodal.h"
#include "mmi_log.h"
#include "util.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "ConfigKeyValueTransform" };
constexpr int32_t KEY_ELEMENT_COUNT = 4;
} // namespace

void ConfigKeyValueTransform::GetConfigKeyValue(const std::string &fileName)
{
    CALL_LOG_ENTER;
    auto configKey = ReadProFile(GetProFilePath(fileName));
    if (configKey.empty()) {
        MMI_HILOGE("Read config file failure");
        return;
    }
    KeyEventValueTransformation trans;
    std::multimap<int32_t, KeyEventValueTransformation> tmpConfigKey;
    for (size_t i = 0; i < configKey.size(); ++i) {
        std::istringstream stream(configKey[i]);
        std::array<std::string, KEY_ELEMENT_COUNT> keyElement;
        stream >> keyElement[0] >> keyElement[1] >> keyElement[2] >> keyElement[3];
        trans.keyEvent = keyElement[0];
        trans.nativeKeyValue = stoi(keyElement[1]);
        trans.sysKeyValue = stoi(keyElement[2]);
        tmpConfigKey.insert(std::pair<int32_t, KeyEventValueTransformation>(trans.nativeKeyValue, trans));
    }
    auto iter = configKeyValue_.insert(std::make_pair(fileName, tmpConfigKey));
    if (!iter.second) {
        MMI_HILOGE("The file name is duplicated");
        return;
    }
}

void ConfigKeyValueTransform::ParseDeviceConfigFile(struct libinput_event *event)
{
    CHKPV(event);
    std::string fileName = GetKeyEventFileName(event);
    if (fileName.empty()) {
        MMI_HILOGE("Get fileName is empty");
        return;
    }
    GetConfigKeyValue(fileName);
}

void ConfigKeyValueTransform::RemoveKeyValue(struct libinput_event *event)
{
    CHKPV(event);
    std::string fileName = GetKeyEventFileName(event);
    if (fileName.empty()) {
        MMI_HILOGE("Get fileName is empty");
        return;
    }
    auto iter = configKeyValue_.find(fileName);
    if (iter == configKeyValue_.end()) {
        MMI_HILOGE("Device config file does not exist");
        return;
    }
    configKeyValue_.erase(iter);
}

std::string ConfigKeyValueTransform::GetProFilePath(const std::string &fileName) const
{
    return "/vendor/etc/KeyValueTransform/" + fileName + ".pro";
}

std::string ConfigKeyValueTransform::GetKeyEventFileName(struct libinput_event* event)
{
    CHKPS(event);
    auto device = libinput_event_get_device(event);
    CHKPS(device);
    uint32_t vendor = libinput_device_get_id_vendor(device);
    uint32_t product = libinput_device_get_id_product(device);
    uint32_t version = libinput_device_get_id_version(device);
    const char *name = libinput_device_get_name(device);
    CHKPS(name);
    std::string fileName = std::to_string(vendor) + std::to_string(product) +
        std::to_string(version) + name;
    RemoveSpace(fileName);
    return fileName;
}

KeyEventValueTransformation ConfigKeyValueTransform::TransferDefaultKeyValue(int32_t inputKey)
{
    CALL_LOG_ENTER;
    auto itr = configKeyValue_.find("default_key");
    if (itr != configKeyValue_.end()) {
        auto defaultKey = itr->second.find(inputKey);
        if (defaultKey != itr->second.end()) {
            return defaultKey->second;
        }
    }
    MMI_HILOGW("Return key values in the TransferKeyValue");
    return TransferKeyValue(inputKey);
}

KeyEventValueTransformation ConfigKeyValueTransform::TransferDeviceKeyValue(struct libinput_event* event,
    int32_t inputKey)
{
    CALL_LOG_ENTER;
    if (event == nullptr) {
        return TransferDefaultKeyValue(inputKey);
    }
    std::string fileName = KeyValueTransform->GetKeyEventFileName(event);
    auto devName = configKeyValue_.find(fileName);
    if (devName != configKeyValue_.end()) {
        auto devKey = devName->second.find(inputKey);
        if (devKey != devName->second.end()) {
            return devKey->second;
        }
    }
    return TransferDefaultKeyValue(inputKey);
}
} // namespace MMI
} // namespace OHOS