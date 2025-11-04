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

#include "joystick_layout_map.h"

#include <fstream>
#include <unistd.h>

#include "define_multimodal.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_DISPATCH
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JoystickLayoutMap"

namespace OHOS {
namespace MMI {
namespace {
constexpr char EMPTY_NAME[] { "" };
constexpr char CONFIG_FILE_EXTENSION[] { ".json" };
constexpr std::uintmax_t MAX_SIZE_OF_CONFIG { 4096 };
} // namespace

std::vector<std::filesystem::path> JoystickLayoutMap::configBasePaths_ {
    "/system/etc/multimodalinput/joystick/layout"
};
const std::unordered_map<JoystickLayoutMap::AxisMode, std::string> JoystickLayoutMap::axisModeNames_ {
    { AxisMode::AXIS_MODE_NORMAL, "NORMAL" },
    { AxisMode::AXIS_MODE_INVERT, "INVERT" },
    { AxisMode::AXIS_MODE_SPLIT, "SPLIT" },
};

void JoystickLayoutMap::AddConfigBasePath(const std::string &basePath)
{
    std::filesystem::path tBasePath { basePath };
    std::error_code ec {};

    if (!std::filesystem::exists(tBasePath, ec)) {
        return;
    }
    for (const auto &item : configBasePaths_) {
        if (std::filesystem::equivalent(tBasePath, item, ec)) {
            return;
        }
    }
    configBasePaths_.push_back(std::move(tBasePath));
}

std::shared_ptr<JoystickLayoutMap> JoystickLayoutMap::Load(struct libinput_device *device)
{
    CHKPP(device);
    const char *name = libinput_device_get_name(device);
    const char *devName = (name != nullptr ? name : EMPTY_NAME);

    auto cfgName = FormatConfigName(device);
    if (cfgName.empty()) {
        MMI_HILOGW("Empty config name");
        return nullptr;
    }
    MMI_HILOGD("[%{public}s] Loading joystick layout from '%{private}s'", devName, cfgName.c_str());
    auto layout = Load(cfgName);
    if (layout != nullptr) {
        MMI_HILOGI("[%{public}s] Joystick layout loaded from '%{private}s'", devName, layout->GetFilePath().c_str());
        return layout;
    }
    return nullptr;
}

std::string JoystickLayoutMap::MapAxisModeName(AxisMode mode)
{
    if (auto iter = axisModeNames_.find(mode); iter != axisModeNames_.cend()) {
        return iter->second;
    }
    return std::string();
}

JoystickLayoutMap::JoystickLayoutMap(const std::string &filePath)
    : filePath_(filePath) {}

std::string JoystickLayoutMap::GetFilePath() const
{
    return filePath_;
}

std::optional<JoystickLayoutMap::Key> JoystickLayoutMap::MapKey(int32_t rawCode) const
{
    if (auto iter = keys_.find(rawCode); iter != keys_.cend()) {
        return iter->second;
    }
    return std::nullopt;
}

std::optional<JoystickLayoutMap::AxisInfo> JoystickLayoutMap::MapAxis(int32_t rawAxis) const
{
    if (auto iter = axes_.find(rawAxis); iter != axes_.cend()) {
        return iter->second;
    }
    return std::nullopt;
}

std::string JoystickLayoutMap::FormatConfigName(struct libinput_device *device)
{
    constexpr int32_t ID_WIDTH { 4 };
    uint32_t vendor = libinput_device_get_id_vendor(device);
    uint32_t product = libinput_device_get_id_product(device);
    if ((vendor != 0U) && (product != 0U)) {
        uint32_t version = libinput_device_get_id_version(device);
        if (version != 0U) {
            std::ostringstream oss1;
            oss1 << "Vendor_" << std::setfill('0') << std::setw(ID_WIDTH) << std::hex << vendor
                << "_Product_" << std::setfill('0') << std::setw(ID_WIDTH) << std::hex << product
                << "_Version_" << std::setfill('0') << std::setw(ID_WIDTH) << std::hex << version;
            auto filePath = FormatConfigPath(std::move(oss1).str());
            if (!filePath.empty()) {
                return filePath;
            }
        }

        std::ostringstream oss2;
        oss2 << "Vendor_" << std::setfill('0') << std::setw(ID_WIDTH) << std::hex << vendor
            << "_Product_" << std::setfill('0') << std::setw(ID_WIDTH) << std::hex << product;
        auto filePath = FormatConfigPath(std::move(oss2).str());
        if (!filePath.empty()) {
            return filePath;
        }
    }

    const char *name = libinput_device_get_name(device);
    if ((name == nullptr) || (name[0] == '\0')) {
        return std::string();
    }
    std::string devName { name };
    for (auto &ch : devName) {
        if (!std::isalnum(ch) && (ch != '_') && (ch != '-')) {
            ch = '_';
        }
    }
    return FormatConfigPath(devName);
}

std::string JoystickLayoutMap::FormatConfigPath(const std::string &name)
{
    for (const auto &basePath : configBasePaths_) {
        std::filesystem::path tBasePath { basePath };
        tBasePath /= name;
        tBasePath.replace_extension(CONFIG_FILE_EXTENSION);

        std::error_code ec {};
        if (std::filesystem::exists(tBasePath, ec)) {
            return tBasePath.string();
        }
    }
    return std::string();
}

std::shared_ptr<JoystickLayoutMap> JoystickLayoutMap::Load(const std::string &filePath)
{
    auto realPath = std::unique_ptr<char, std::function<void(char *)>>(
        ::realpath(filePath.c_str(), nullptr),
        [](auto arr) {
            if (arr != nullptr) {
                ::free(arr);
            }
        });
    if (realPath == nullptr) {
        MMI_HILOGE("Path '%{private}s' is not real:%{public}s", filePath.c_str(), ::strerror(errno));
        return nullptr;
    }
    std::error_code ec {};
    auto fsize = std::filesystem::file_size(realPath.get(), ec);
    if (ec || (fsize > MAX_SIZE_OF_CONFIG)) {
        MMI_HILOGE("File is too large: %{private}s", realPath.get());
        return nullptr;
    }
    std::ifstream ifs(realPath.get());
    if (!ifs.is_open()) {
        MMI_HILOGE("Can not open '%{private}s'", realPath.get());
        return nullptr;
    }
    MMI_HILOGD("Load joystick layout from '%{private}s'", realPath.get());
    std::string config { std::istream_iterator<char>(ifs), std::istream_iterator<char>() };
    auto jsonDoc = std::unique_ptr<cJSON, std::function<void(cJSON *)>>(
        cJSON_Parse(config.c_str()),
        [](cJSON *doc) {
            if (doc != nullptr) {
                cJSON_Delete(doc);
            }
        });
    auto keyLayout = std::make_shared<JoystickLayoutMap>(realPath.get());
    keyLayout->OnLoading();
    keyLayout->LoadKeys(jsonDoc.get());
    keyLayout->LoadAxes(jsonDoc.get());
    keyLayout->OnLoaded();
    return keyLayout;
}

void JoystickLayoutMap::OnLoading()
{
    mapper_ = PropertyNameMapper::Load(PropertyNameMapper::UnloadOption::UNLOAD_MANUALLY);
}

void JoystickLayoutMap::OnLoaded()
{
    mapper_.reset();
    PropertyNameMapper::Unload(PropertyNameMapper::UnloadOption::UNLOAD_AUTOMATICALLY_WITH_DELAY);
}

void JoystickLayoutMap::LoadKeys(cJSON *jsonDoc)
{
    auto jsonKeys = cJSON_GetObjectItemCaseSensitive(jsonDoc, "KEYS");
    if (!cJSON_IsArray(jsonKeys)) {
        MMI_HILOGE("The jsonKeys is not array");
        return;
    }
    int32_t nKeys = cJSON_GetArraySize(jsonKeys);
    for (int32_t index = 0; index < nKeys; ++index) {
        auto jsonKey = cJSON_GetArrayItem(jsonKeys, index);
        CHKPC(jsonKey);
        LoadKeyItem(jsonKey, index);
    }
}

void JoystickLayoutMap::LoadKeyItem(cJSON *jsonItem, int32_t index)
{
    Key key {};

    auto jsonRawCode = cJSON_GetObjectItemCaseSensitive(jsonItem, "RAWCODE");
    if (!cJSON_IsNumber(jsonRawCode)) {
        MMI_HILOGE("KEYS[%{public}d].RAWCODE is not number", index);
        return;
    }
    auto rawCode = static_cast<int32_t>(cJSON_GetNumberValue(jsonRawCode));

    auto jsonKeyCode = cJSON_GetObjectItemCaseSensitive(jsonItem, "KEYCODE");
    if (!cJSON_IsString(jsonKeyCode)) {
        MMI_HILOGE("KEYS[%{public}d].KEYCODE is not string", index);
        return;
    }
    const char *sKeyCode = cJSON_GetStringValue(jsonKeyCode);
    if (sKeyCode == nullptr) {
        MMI_HILOGE("KEYS[%{public}d].KEYCODE is not string", index);
        return;
    }
    key.keyCode_ = MapKeyName(sKeyCode);
    if (key.keyCode_ == KeyEvent::KEYCODE_UNKNOWN) {
        MMI_HILOGE("KEYS[%{public}d].KEYCODE is unknown, got '%{private}s'", index, sKeyCode);
        return;
    }

    keys_.insert_or_assign(rawCode, key);
}

void JoystickLayoutMap::LoadAxes(cJSON *jsonDoc)
{
    auto jsonAxes = cJSON_GetObjectItemCaseSensitive(jsonDoc, "AXES");
    if (!cJSON_IsArray(jsonAxes)) {
        MMI_HILOGE("The jsonAxes is not array");
        return;
    }
    int32_t nAxes = cJSON_GetArraySize(jsonAxes);
    for (int32_t index = 0; index < nAxes; ++index) {
        auto jsonItem = cJSON_GetArrayItem(jsonAxes, index);
        if (jsonItem != nullptr) {
            LoadAxisItem(jsonItem, index);
        }
    }
}

void JoystickLayoutMap::LoadAxisItem(cJSON *jsonItem, int32_t index)
{
    AxisInfo axisInfo {};

    auto jsonRawCode = cJSON_GetObjectItemCaseSensitive(jsonItem, "RAWCODE");
    if (!cJSON_IsNumber(jsonRawCode)) {
        MMI_HILOGE("AXES[%{public}d].RAWCODE is not number", index);
        return;
    }
    auto rawCode = static_cast<int32_t>(cJSON_GetNumberValue(jsonRawCode));

    axisInfo.axis_ = ReadAxis(jsonItem, index, "AXIS");
    if (axisInfo.axis_ == PointerEvent::AXIS_TYPE_UNKNOWN) {
        MMI_HILOGE("AXES[%{public}d].AXIS is unknown", index);
        return;
    }
    if (!ReadAxisMode(jsonItem, index, axisInfo.mode_)) {
        return;
    }
    if (axisInfo.mode_ == AxisMode::AXIS_MODE_SPLIT) {
        auto jsonSplitValue = cJSON_GetObjectItemCaseSensitive(jsonItem, "SPLIT_VALUE");
        if (!cJSON_IsNumber(jsonSplitValue)) {
            MMI_HILOGE("AXES[%{public}d].SPLIT_VALUE is not number", index);
            return;
        }
        axisInfo.splitValue_ = static_cast<int32_t>(cJSON_GetNumberValue(jsonSplitValue));

        axisInfo.highAxis_ = ReadAxis(jsonItem, index, "HIGH_AXIS");
        if (axisInfo.highAxis_ == PointerEvent::AXIS_TYPE_UNKNOWN) {
            MMI_HILOGE("AXES[%{public}d].HIGH_AXIS is unknown", index);
            return;
        }
    }

    auto jsonFlatValue = cJSON_GetObjectItemCaseSensitive(jsonItem, "FLAT");
    if (jsonFlatValue != nullptr) {
        if (!cJSON_IsNumber(jsonFlatValue)) {
            MMI_HILOGE("AXES[%{public}d].FLAT is not number", index);
            return;
        }
        axisInfo.flatOverride_ = static_cast<int32_t>(cJSON_GetNumberValue(jsonFlatValue));
    }

    axes_.insert_or_assign(rawCode, axisInfo);
}

PointerEvent::AxisType JoystickLayoutMap::ReadAxis(cJSON *jsonItem, int32_t index, const char *name) const
{
    auto jsonAxis = cJSON_GetObjectItemCaseSensitive(jsonItem, name);
    if (!cJSON_IsString(jsonAxis)) {
        MMI_HILOGE("AXES[%{public}d].%{public}s is not string", index, name);
        return PointerEvent::AXIS_TYPE_UNKNOWN;
    }
    auto sAxis = cJSON_GetStringValue(jsonAxis);
    if (sAxis == nullptr) {
        MMI_HILOGE("AXES[%{public}d].%{public}s is NULL", index, name);
        return PointerEvent::AXIS_TYPE_UNKNOWN;
    }
    return MapAxisName(sAxis);
}

bool JoystickLayoutMap::ReadAxisMode(cJSON *jsonItem, int32_t index, AxisMode &mode) const
{
    auto jsonMode = cJSON_GetObjectItemCaseSensitive(jsonItem, "MODE");
    if (jsonMode == nullptr) {
        return true;
    }
    if (!cJSON_IsString(jsonMode)) {
        MMI_HILOGE("AXES[%{public}d].MODE is not string", index);
        return false;
    }
    const char *sMode = cJSON_GetStringValue(jsonMode);
    if (sMode == nullptr) {
        MMI_HILOGE("AXES[%{public}d].MODE is NULL", index);
        return false;
    }
    if (std::strcmp(sMode, "INVERT") == 0) {
        mode = AxisMode::AXIS_MODE_INVERT;
        return true;
    }
    if (std::strcmp(sMode, "SPLIT") == 0) {
        mode = AxisMode::AXIS_MODE_SPLIT;
        return true;
    }
    MMI_HILOGE("AXES[%{public}d].MODE is invalid: '%{public}s'", index, sMode);
    return false;
}
} // namespace MMI
} // namespace OHOS
