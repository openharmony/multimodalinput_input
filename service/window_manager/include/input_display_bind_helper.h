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
#include <vector>

#include "old_display_info.h"
#include "window_info.h"

namespace OHOS {
namespace MMI {
class BindInfo {
public:
    int32_t GetInputDeviceId() const;
    std::string GetInputNodeName() const;
    std::string GetInputDeviceName() const;
    int32_t GetDisplayId() const;
    uint64_t GetRsId() const;
    std::string GetDisplayName() const;
    bool IsUnbind() const;
    bool InputDeviceNotBind() const;
    bool DisplayNotBind() const;
    bool IsBindToDisplay() const;
    void SetBindToDisplayFlag(bool bindToDisplay);
    bool AddInputDevice(int32_t deviceId, const std::string &nodeName, const std::string &deviceName);
    void RemoveInputDevice();
    bool AddDisplay(uint64_t rsId, int32_t displayId, const std::string &name);
    void RemoveDisplay();
    std::string GetDesc() const;
    friend bool operator < (const BindInfo &l, const BindInfo &r);
    friend std::ostream &operator << (std::ostream &os, const BindInfo &r);
    friend std::istream &operator >> (std::istream &is, BindInfo &r);

private:
    int32_t inputDeviceId_ { -1 };
    std::string inputNodeName_;
    std::string inputDeviceName_;
    int32_t displayId_ { -1 };
    uint64_t rsId_ { ~uint64_t(0) };
    std::string displayName_;
    // Runtime-only marker: true when this binding was established via the bindToDisplay API.
    // Not serialized (BindToDisplay does not persist), so config-loaded bindings stay false.
    bool bindToDisplay_ { false };
};
class BindInfos {
public:
    bool Add(const BindInfo &info);
    void UnbindInputDevice(int32_t deviceId);
    void UnbindDisplay(int32_t displayId);
    void UnbindDisplayByRsId(uint64_t rsId);
    void BindDisplayByCfgNodes(uint64_t rsId, int32_t displayId, const std::string &displayName,
        const std::set<std::string> &cfgNodeNames);
    BindInfo GetUnbindInputDevice(const std::string &displayName);
    BindInfo GetUnbindDisplay(const std::string &inputDeviceName);
    std::string GetDisplayNameByInputDevice(const std::string &name) const;
    int32_t GetBindDisplayIdByInputDevice(int32_t inputDeviceId) const;
    int32_t GetBindToDisplayIdByInputDevice(int32_t inputDeviceId) const;
    std::string GetBindDisplayNameByInputDevice(int32_t inputDeviceId) const;
    std::string GetInputDeviceByDisplayName(const std::string &name) const;
    std::string GetDesc() const;
    const std::list<BindInfo> &GetInfos() const;
    friend std::ostream &operator << (std::ostream &os, const BindInfos &r);
    friend std::istream &operator >> (std::istream &is, BindInfos &r);

private:
    BindInfo GetUnbindInputDevice();
    std::list<BindInfo> infos_;
};
class InputDisplayBindHelper {
public:
    InputDisplayBindHelper(const std::string bindCfgFile);
    std::string GetBindDisplayNameByInputDevice(int32_t inputDeviceId) const;
    void AddInputDevice(int32_t id, const std::string &name, const std::string &sysUid,
        const std::vector<OLD::DisplayInfo> &displays = {});
    void RemoveInputDevice(int32_t id);
    bool IsDisplayAdd(uint64_t id, const std::string &name);
    std::set<std::pair<uint64_t, std::string>> GetDisplayIdNames() const;
    void AddDisplay(uint64_t rsId, int32_t displayId, const std::string &name);
    void RemoveDisplay(int32_t id);
    void RemoveDisplayByRsId(uint64_t rsId);
    void Load();
    std::string Dumps() const;
    void Store();
    int32_t GetDisplayBindInfo(DisplayBindInfos &infos);
    int32_t SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg);
    int32_t BindToDisplay(int32_t deviceId, int32_t displayId, uint64_t rsId, const std::string &displayName,
        std::string &msg);

    int32_t GetBindDisplayIdByInputDevice(int32_t inputDeviceId) const;
    int32_t GetBindToDisplayIdByInputDevice(int32_t inputDeviceId) const;
    std::string GetInputDeviceById(int32_t id);
    std::string GetInputNodeNameByCfg(int32_t id);
    void GetInputNodeNamesByCfg(int32_t id, std::vector<std::string> &nodeNames);
    std::string GetContent(const std::string &fileName);
    std::string GetInputNode(const std::string &inputNodeName);
    bool GetRsIdByInputNodeNameCfg(const std::string &nodeName, int32_t &cfgRsId) const;

private:
    std::string GetInputDeviceNameCfgPath() const;
    const std::string fileName_;
    std::shared_ptr<BindInfos> infos_;
    std::shared_ptr<BindInfos> configFileInfos_;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_DISPLAY_BIND_HELPER_H
