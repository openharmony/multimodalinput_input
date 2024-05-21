/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef INPUT_DISPLAY_BIND_HELPER_H
#define INPUT_DISPLAY_BIND_HELPER_H

#include <cstdint>
#include <memory>
#include <set>
#include <string>

#include "window_info.h"

namespace OHOS {
namespace MMI {
class BindInfos;
class InputDisplayBindHelper {
public:
    InputDisplayBindHelper(const std::string bindCfgFile);
    std::string GetBindDisplayNameByInputDevice(int32_t inputDeviceId) const;
    void AddInputDevice(int32_t id, const std::string &name);
    void RemoveInputDevice(int32_t id);
    bool IsDisplayAdd(int32_t id, const std::string &name);
    std::set<std::pair<int32_t, std::string>> GetDisplayIdNames() const;
    void AddDisplay(int32_t id, const std::string &name);
    void AddLocalDisplay(int32_t id, const std::string &name);
    void RemoveDisplay(int32_t id);
    void Load();
    std::string Dumps() const;
    void Store();
    int32_t GetDisplayBindInfo(DisplayBindInfos &infos);
    int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg);

    std::string GetInputDeviceById(int32_t id);
    std::string GetInputNodeNameByCfg(int32_t id);
    std::string GetContent(const std::string &fileName);
    std::string GetInputNode(const std::string &inputNodeName);

private:
    const std::string fileName_;
    std::shared_ptr<BindInfos> infos_;
    std::shared_ptr<BindInfos> configFileInfos_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_DISPLAY_BIND_HELPER_H
