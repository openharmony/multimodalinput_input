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

#ifndef JOYSTICK_LAYOUT_MAP_H
#define JOYSTICK_LAYOUT_MAP_H

#include <filesystem>
#include <map>
#include <memory>

#include "libinput.h"
#include "nocopyable.h"

#include "cJSON.h"
#include "key_event.h"
#include "pointer_event.h"
#include "property_name_mapper.h"

namespace OHOS {
namespace MMI {
class JoystickLayoutMap final {
public:
    struct Key {
        int32_t keyCode_ { KeyEvent::KEYCODE_UNKNOWN };
        uint32_t flags_ { 0U };
    };

    enum class AxisMode {
        AXIS_MODE_NORMAL = 0,
        AXIS_MODE_INVERT,
        AXIS_MODE_SPLIT,
    };

    struct AxisInfo {
        AxisMode mode_ { AxisMode::AXIS_MODE_NORMAL };
        PointerEvent::AxisType axis_ { PointerEvent::AXIS_TYPE_UNKNOWN };
        PointerEvent::AxisType highAxis_ { PointerEvent::AXIS_TYPE_UNKNOWN };
        int32_t splitValue_ {};
        int32_t flatOverride_ {};
    };

    static void AddConfigBasePath(const std::string &basePath);
    static std::shared_ptr<JoystickLayoutMap> Load(struct libinput_device *device);
    static std::string MapAxisModeName(AxisMode mode);

    JoystickLayoutMap(const std::string &filePath);
    ~JoystickLayoutMap() = default;
    DISALLOW_COPY_AND_MOVE(JoystickLayoutMap);

    std::string GetFilePath() const;
    std::optional<Key> MapKey(int32_t rawCode) const;
    std::optional<AxisInfo> MapAxis(int32_t rawAxis) const;

private:
    static std::string FormatConfigName(struct libinput_device *device);
    static std::string FormatConfigPath(const std::string &name);
    static std::shared_ptr<JoystickLayoutMap> Load(const std::string &filePath);

    void OnLoading();
    void OnLoaded();
    int32_t MapKeyName(const std::string &name) const;
    PointerEvent::AxisType MapAxisName(const std::string &name) const;
    void LoadKeys(cJSON *jsonDoc);
    void LoadKeyItem(cJSON *jsonItem, int32_t index);
    void LoadAxes(cJSON *jsonDoc);
    void LoadAxisItem(cJSON *jsonItem, int32_t index);
    PointerEvent::AxisType ReadAxis(cJSON *jsonItem, int32_t index, const char *name) const;
    bool ReadAxisMode(cJSON *jsonItem, int32_t index, AxisMode &mode) const;

    static std::vector<std::filesystem::path> configBasePaths_;
    static const std::unordered_map<AxisMode, std::string> axisModeNames_;
    const std::string filePath_;
    std::shared_ptr<PropertyNameMapper> mapper_;
    std::unordered_map<int32_t, Key> keys_;
    std::unordered_map<int32_t, AxisInfo> axes_;
};

inline int32_t JoystickLayoutMap::MapKeyName(const std::string &name) const
{
    return ((mapper_ != nullptr) ? mapper_->MapKey(name) : KeyEvent::KEYCODE_UNKNOWN);
}

inline PointerEvent::AxisType JoystickLayoutMap::MapAxisName(const std::string &name) const
{
    return ((mapper_ != nullptr) ? mapper_->MapAxis(name) : PointerEvent::AXIS_TYPE_UNKNOWN);
}
} // namespace MMI
} // namespace OHOS
#endif // JOYSTICK_LAYOUT_MAP_H
