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

#include <list>
#include <set>

#include "window_info.h"

namespace OHOS {
namespace MMI {
class BindInfo {
public:
    int32_t GetInputDeviceId() const;
    std::string GetInputDeviceName() const;
    int32_t GetDisplayId() const;
    std::string GetDisplayName() const;
    bool IsUnbind() const;
    bool InputDeviceNotBind() const;
    bool DisplayNotBind() const;
    bool AddInputDevice(int32_t deviceId, const std::string &deviceName);
    void RemoveInputDevice();
    bool AddDisplay(int32_t id, const std::string &name);
    void RemoveDisplay();
    std::string GetDesc() const;
    friend bool operator < (const BindInfo &l, const BindInfo &r);
    friend std::ostream &operator << (std::ostream &os, const BindInfo &r);
    friend std::istream &operator >> (std::istream &is, BindInfo &r);

private:
    int32_t inputDeviceId_ { -1 };
    std::string inputDeviceName_;
    int32_t displayId_ { -1 };
    std::string displayName_;
};
class BindInfos {
public:
    bool Add(const BindInfo &info);
    void UnbindInputDevice(int32_t deviceId);
    void UnbindDisplay(int32_t displayId);
    BindInfo GetUnbindInputDevice(const std::string &displayName);
    BindInfo GetUnbindDisplay(const std::string &inputDeviceName);
    std::string GetDisplayNameByInputDevice(const std::string &name) const;
    int32_t GetBindDisplayIdByInputDevice(int32_t inputDeviceId) const;
    std::string GetBindDisplayNameByInputDevice(int32_t inputDeviceId) const;
    std::string GetInputDeviceByDisplayName(const std::string &name) const;
    std::string GetDesc() const;
    const std::list<BindInfo> &GetInfos() const;
    friend std::ostream &operator << (std::ostream &os, const BindInfos &r);
    friend std::istream &operator >> (std::istream &is, BindInfos &r);

private:
    BindInfo GetUnbindInputDevice();
    BindInfo GetUnbindDisplay();
    std::list<BindInfo> infos_;
};
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
