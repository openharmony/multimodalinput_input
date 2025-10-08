/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
 
#include "input_display_bind_helper.h"

#include <fstream>

#include "parameters.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_WINDOW
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InputDisplayBindHelper"

namespace OHOS {
namespace MMI {
namespace {
const std::string FOLD_SCREEN_FLAG = system::GetParameter("const.window.foldscreen.type", "");
const char* INPUT_DEVICE_NAME_CONFIG { "/sys_prod/etc/input/input_device_name.cfg" };
const std::string DIRECTORY { "/sys/devices/virtual/input" };
const char* SEPARATOR { "/" };
const char* SUFFIX { "0000:0000" };
const std::string INPUT { "input" };
const std::string EVENT { "event" };
const char* NAME { "name" };
}

namespace fs = std::filesystem;

int32_t BindInfo::GetInputDeviceId() const
{
    return inputDeviceId_;
}

std::string BindInfo::GetInputNodeName() const
{
    return inputNodeName_;
}

std::string BindInfo::GetInputDeviceName() const
{
    return inputDeviceName_;
}

int32_t BindInfo::GetDisplayId() const
{
    return displayId_;
}

std::string BindInfo::GetDisplayName() const
{
    return displayName_;
}

bool BindInfo::IsUnbind() const
{
    return ((inputDeviceId_ == -1) || (displayId_ == -1));
}

bool BindInfo::InputDeviceNotBind() const
{
    return (inputDeviceId_ == -1);
}

bool BindInfo::DisplayNotBind() const
{
    return (displayId_ == -1);
}

bool BindInfo::AddInputDevice(int32_t deviceId, const std::string &nodeName, const std::string &deviceName)
{
    if ((inputDeviceId_ != -1) || !inputNodeName_.empty() || !inputDeviceName_.empty()) {
        return false;
    }
    inputDeviceId_ = deviceId;
    inputNodeName_ = nodeName;
    inputDeviceName_ = deviceName;
    return true;
}

void BindInfo::RemoveInputDevice()
{
    inputDeviceId_ = -1;
    inputDeviceName_.clear();
}

bool BindInfo::AddDisplay(int32_t id, const std::string &name)
{
    if ((displayId_ != -1) || !displayName_.empty()) {
        return false;
    }
    displayId_ = id;
    displayName_ = name;
    return true;
}

void BindInfo::RemoveDisplay()
{
    displayId_ = -1;
    displayName_.clear();
}

std::string BindInfo::GetDesc() const
{
    std::ostringstream oss;
    oss << "InputDevice(id:" << inputDeviceId_ << ",name:" << inputDeviceName_ << "),Display(id:" << displayId_ <<
        ",name:" << displayName_ << ")";
    return oss.str();
}

bool operator < (const BindInfo &l, const BindInfo &r)
{
    if (l.inputDeviceId_ != r.inputDeviceId_) {
        return (l.inputDeviceId_ < r.inputDeviceId_);
    }
    return (l.displayId_ < r.displayId_);
}

std::ostream &operator << (std::ostream &os, const BindInfo &r)
{
    os << r.inputDeviceName_ << "<=>" << r.displayName_ << std::endl;
    return os;
}

std::istream &operator >> (std::istream &is, BindInfo &r)
{
    std::string line;
    std::getline(is, line);
    const std::string delim = "<=>";
    std::string::size_type pos = line.find(delim);
    if (pos == std::string::npos) {
        return is;
    }
    r.inputDeviceName_ = line.substr(0, pos);
    r.displayName_ = line.substr(pos + delim.length());
    r.inputDeviceId_ = 0;
    r.displayId_ = 0;
    return is;
}

std::string BindInfos::GetDesc() const
{
    int32_t index = 0;
    std::ostringstream oss;
    for (const auto &info : infos_) {
        oss << "index:" << index << "," << info.GetDesc() << std::endl;
    }
    return oss.str();
}

const std::list<BindInfo> &BindInfos::GetInfos() const
{
    return infos_;
}

int32_t BindInfos::GetBindDisplayIdByInputDevice(int32_t inputDeviceId) const
{
    for (const auto &item : infos_) {
        if (item.GetInputDeviceId() == inputDeviceId) {
            if (!item.IsUnbind()) {
                return item.GetDisplayId();
            }
        }
    }
    return -1;
}

std::string BindInfos::GetBindDisplayNameByInputDevice(int32_t inputDeviceId) const
{
    for (const auto &item : infos_) {
        if (item.GetInputDeviceId() == inputDeviceId) {
            if (!item.IsUnbind()) {
                return item.GetDisplayName();
            }
        }
    }
    return "";
}

std::string BindInfos::GetDisplayNameByInputDevice(const std::string &name) const
{
    for (const auto &item : infos_) {
        if (item.GetInputDeviceName() == name) {
            return item.GetDisplayName();
        }
    }
    return "";
}

std::string BindInfos::GetInputDeviceByDisplayName(const std::string &name) const
{
    for (const auto &item : infos_) {
        if (item.GetDisplayName() == name) {
            return item.GetInputDeviceName();
        }
    }
    return "";
}

bool BindInfos::Add(const BindInfo &info)
{
    auto it = infos_.begin();
    for (; it != infos_.end(); ++it) {
        if (info < *it) {
            break;
        }
    }
    auto it2 = infos_.emplace(it, std::move(info));
    if (it2 == infos_.end()) {
        MMI_HILOGE("Duplicate %{public}s", info.GetDesc().c_str());
    }
    return true;
}

void BindInfos::UnbindInputDevice(int32_t deviceId)
{
    auto it = infos_.begin();
    for (; it != infos_.end(); ++it) {
        if (it->GetInputDeviceId() == deviceId) {
            it->RemoveInputDevice();
            infos_.erase(it);
            return;
        }
    }
}

void BindInfos::UnbindDisplay(int32_t displayId)
{
    auto it = infos_.begin();
    for (; it != infos_.end(); ++it) {
        if (it->GetDisplayId() == displayId) {
            it->RemoveDisplay();
            infos_.erase(it);
            return;
        }
    }
}

BindInfo BindInfos::GetUnbindInputDevice(const std::string &displayName)
{
    auto it = infos_.begin();
    while (it != infos_.end()) {
        if (it->InputDeviceNotBind()) {
            if (it->GetDisplayName() == displayName) {
                auto info = std::move(*it);
                infos_.erase(it);
                return info;
            }
        }
        ++it;
    }
    return BindInfo();
}

BindInfo BindInfos::GetUnbindDisplay()
{
    auto it = infos_.begin();
    while (it != infos_.end()) {
        if (it->DisplayNotBind()) {
            auto info = std::move(*it);
            infos_.erase(it);
            return info;
        }
        ++it;
    }
    return BindInfo();
}

BindInfo BindInfos::GetUnbindDisplay(const std::string &inputDeviceName)
{
    auto it = infos_.begin();
    while (it != infos_.end()) {
        if (it->DisplayNotBind()) {
            if (it->GetInputDeviceName() == inputDeviceName) {
                auto info = std::move(*it);
                infos_.erase(it);
                return info;
            }
        }
        ++it;
    }
    return GetUnbindDisplay();
}

std::ostream &operator << (std::ostream &os, const BindInfos &r)
{
    const auto &infos = r.GetInfos();
    for (const auto &info : infos) {
        if (!info.IsUnbind()) {
            os << info;
        }
    }
    return os;
}

std::istream &operator >> (std::istream &is, BindInfos &r)
{
    while (!is.eof()) {
        BindInfo info;
        is >> info;
        if (info.IsUnbind()) {
            break;
        }
        r.Add(info);
    }
    return is;
}

InputDisplayBindHelper::InputDisplayBindHelper(const std::string bindCfgFile)
    : fileName_(bindCfgFile), infos_(std::make_shared<BindInfos>()), configFileInfos_(std::make_shared<BindInfos>())
{}

std::string InputDisplayBindHelper::GetBindDisplayNameByInputDevice(int32_t inputDeviceId) const
{
    CALL_DEBUG_ENTER;
    CHKPO(infos_);
    return infos_->GetBindDisplayNameByInputDevice(inputDeviceId);
}

void InputDisplayBindHelper::AddInputDevice(int32_t id, const std::string &nodeName, const std::string &sysUid)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Param: id:%{public}d, nodeName:%{public}s, name:%{public}s", id, nodeName.c_str(), sysUid.c_str());
    CHKPV(configFileInfos_);
    auto displayName = configFileInfos_->GetDisplayNameByInputDevice(sysUid);
    BindInfo info = infos_->GetUnbindInputDevice(displayName);
    info.AddInputDevice(id, nodeName, sysUid);
    infos_->Add(info);
    Store();
}

void InputDisplayBindHelper::RemoveInputDevice(int32_t id)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Param: id:%{public}d", id);
    CHKPV(infos_);
    infos_->UnbindInputDevice(id);
}

bool InputDisplayBindHelper::IsDisplayAdd(int32_t id, const std::string &name)
{
    CHKPF(infos_);
    const auto &infos = infos_->GetInfos();
    for (const auto &info : infos) {
        if ((info.GetDisplayName() == name) && (info.GetDisplayId() == id)) {
            return true;
        }
    }
    return false;
}

std::set<std::pair<uint64_t, std::string>> InputDisplayBindHelper::GetDisplayIdNames() const
{
    CALL_DEBUG_ENTER;
    std::set<std::pair<uint64_t, std::string>> idNames;
    CHKFR(infos_, idNames, "infos_ is null");
    const auto &infos = infos_->GetInfos();
    for (const auto &info : infos) {
        if (info.GetDisplayId() != -1) {
            idNames.insert(std::make_pair(info.GetDisplayId(), info.GetDisplayName()));
        }
    }
    return idNames;
}

void InputDisplayBindHelper::AddDisplay(int32_t id, const std::string &name)
{
    CALL_DEBUG_ENTER;
    auto inputDeviceName = configFileInfos_->GetInputDeviceByDisplayName(name);
    
    std::string deviceName = GetInputDeviceById(id);
    if (!deviceName.empty()) {
        inputDeviceName = deviceName;
    }
    BindInfo info = infos_->GetUnbindDisplay(inputDeviceName);
    info.AddDisplay(id, name);
    infos_->Add(info);
    Store();
}

void InputDisplayBindHelper::AddLocalDisplay(int32_t id, const std::string &name)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Param: id:%{public}d, name:%{public}s", id, name.c_str());
    CHKPV(infos_);

    const auto &infos = infos_->GetInfos();
    std::vector<std::string> unbindDevices;
    for (const auto &info : infos) {
        if (info.DisplayNotBind()) {
            unbindDevices.push_back(info.GetInputDeviceName());
            MMI_HILOGI("Unbind InputDevice, id:%{public}d, inputDevice:%{public}s",
                info.GetInputDeviceId(), info.GetInputDeviceName().c_str());
        }
    }
    
    bool IsStore = false;
    for (auto &item : unbindDevices) {
        auto inputDeviceName = item;
        std::string deviceName = GetInputDeviceById(id);
        if (!deviceName.empty()) {
            inputDeviceName = deviceName;
        }
        BindInfo info = infos_->GetUnbindDisplay(inputDeviceName);
        info.AddDisplay(id, name);
        infos_->Add(info);
        IsStore = true;
    }
    if (IsStore) {
        Store();
    }
    unbindDevices.clear();
}

std::string InputDisplayBindHelper::GetInputDeviceById(int32_t id)
{
    CALL_DEBUG_ENTER;
    std::string inputNodeName = GetInputNodeNameByCfg(id);
    if (inputNodeName.empty()) {
        return "";
    }

    std::string inputNode = GetInputNode(inputNodeName);
    if (inputNode.empty()) {
        CHKPO(infos_);
        const auto &infos = infos_->GetInfos();
        for (const auto &item : infos) {
            if (inputNodeName == item.GetInputNodeName()) {
                return item.GetInputDeviceName();
            }
        }
        return "";
    }

    std::string inputEvent = inputNode;
    size_t pos = inputEvent.find(INPUT);
    if (pos != std::string::npos) {
        inputEvent.replace(pos, INPUT.length(), EVENT);
    }

    std::string inputDeviceName;
    inputDeviceName.append(DIRECTORY).append(SEPARATOR)
        .append(inputNode).append(SEPARATOR)
        .append(inputEvent).append(SUFFIX);
    
    MMI_HILOGI("GetInputDeviceById, id:%{public}d, inputDevice:%{public}s", id, inputDeviceName.c_str());
    return inputDeviceName;
}

std::string InputDisplayBindHelper::GetInputNodeNameByCfg(int32_t id)
{
    CALL_DEBUG_ENTER;
    std::ifstream file(INPUT_DEVICE_NAME_CONFIG);
    std::string res;
    if (file.is_open()) {
        std::string line;
        while (getline(file, line)) {
            const std::string delim = "<=>";
            size_t pos = line.find(delim);
            if (pos == std::string::npos) {
                continue;
            }
            std::string displayId = line.substr(0, pos);
            std::string inputNodeName = line.substr(pos + delim.length());
            if (!displayId.empty() && !inputNodeName.empty()
                && std::all_of(displayId.begin(), displayId.end(), ::isdigit)
                && std::atoi(displayId.c_str()) == id) {
                res = inputNodeName;
                break;
            }
        }
        file.close();
    }
    if (!res.empty() && (res.back() == '\n' || res.back() == '\r')) {
        res.pop_back();
    }
    return res;
}

std::string InputDisplayBindHelper::GetContent(const std::string &fileName)
{
    CALL_DEBUG_ENTER;
    std::string content;
    char realPath[PATH_MAX] = {};
    if (realpath(fileName.c_str(), realPath) == nullptr) {
        MMI_HILOGE("The realpath return nullptr");
        return content;
    }
    std::ifstream file(realPath);
    if (file.is_open()) {
        std::string line;
        while (getline(file, line)) {
            content.append(line);
        }
        file.close();
    }
    return content;
}

std::string InputDisplayBindHelper::GetInputNode(const std::string &inputNodeName)
{
    CALL_DEBUG_ENTER;
    std::string inputNode;
    if (fs::exists(DIRECTORY) && fs::is_directory(DIRECTORY)) {
        for (const auto& entry : fs::directory_iterator(DIRECTORY)) {
            std::string node = fs::path(entry.path()).filename();
            std::string file;
            file.append(DIRECTORY).append(SEPARATOR)
                .append(node).append(SEPARATOR)
                .append(NAME);
            if (inputNodeName == GetContent(file)) {
                inputNode = node;
                break;
            }
        }
    }
    return inputNode;
}

void InputDisplayBindHelper::RemoveDisplay(int32_t id)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Param: id:%{public}d", id);
    CHKPV(infos_);
    infos_->UnbindDisplay(id);
}

void InputDisplayBindHelper::Store()
{
    CALL_DEBUG_ENTER;
    CHKPV(infos_);
    char realPath[PATH_MAX] = {};
    CHKPV(realpath(fileName_.c_str(), realPath));
    if (!IsValidJsonPath(realPath)) {
        MMI_HILOGE("File path is invalid");
        return;
    }
    std::ofstream ofs(realPath, std::ios::trunc | std::ios::out | std::ios_base::binary);
    if (!ofs) {
        MMI_HILOGE("Open file fail.%{private}s, errno:%{public}d", realPath, errno);
        return;
    }
    ofs << *infos_;
    ofs.close();
}

int32_t InputDisplayBindHelper::GetDisplayBindInfo(DisplayBindInfos &infos)
{
    CALL_DEBUG_ENTER;
    CHKPR(infos_, RET_ERR);
    for (const auto &item : infos_->GetInfos()) {
        DisplayBindInfo info;
        info.inputDeviceId = item.GetInputDeviceId();
        info.inputDeviceName = item.GetInputDeviceName();
        info.displayId = item.GetDisplayId();
        info.displayName = item.GetDisplayName();
        infos.push_back(info);
    }
    return RET_OK;
}

int32_t InputDisplayBindHelper::SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("Param: deviceId:%{public}d, displayId:%{public}d", deviceId, displayId);
    if ((deviceId == -1) || (displayId == -1)) {
        msg = "The deviceId or displayId is invalid";
        MMI_HILOGE("%s", msg.c_str());
        return RET_ERR;
    }
    if (infos_ == nullptr) {
        msg = "Infos_ is nullptr";
        MMI_HILOGE("%s", msg.c_str());
        return RET_ERR;
    }

    BindInfo bindByDevice;
    BindInfo bindByDisplay;
    for (const auto &item : infos_->GetInfos()) {
        if (item.GetInputDeviceId() == deviceId) {
            bindByDevice = item;
        }
        if (item.GetDisplayId() == displayId) {
            bindByDisplay = item;
        }
    }
    if (bindByDevice.GetInputDeviceId() == -1) {
        msg = "The deviceId is invalid";
        MMI_HILOGE("%s", msg.c_str());
        return RET_ERR;
    }
    if (bindByDisplay.GetDisplayId() == -1) {
        msg = "The displayId is invalid";
        MMI_HILOGE("%s", msg.c_str());
        return RET_ERR;
    }

    if (infos_->GetBindDisplayIdByInputDevice(deviceId) == displayId) {
        msg = "The input device and display has alread bind";
        MMI_HILOGE("%s", msg.c_str());
        return RET_ERR;
    }

    infos_->UnbindInputDevice(bindByDevice.GetInputDeviceId());
    infos_->UnbindInputDevice(bindByDisplay.GetInputDeviceId());
    infos_->UnbindDisplay(bindByDevice.GetDisplayId());
    infos_->UnbindDisplay(bindByDisplay.GetDisplayId());

    BindInfo info1;
    info1.AddInputDevice(bindByDevice.GetInputDeviceId(), bindByDevice.GetInputNodeName(),
        bindByDevice.GetInputDeviceName());
    info1.AddDisplay(bindByDisplay.GetDisplayId(), bindByDisplay.GetDisplayName());
    infos_->Add(info1);

    if ((bindByDevice.GetDisplayId() != -1) && (bindByDisplay.GetInputDeviceId() != -1)) {
        MMI_HILOGD("Both display id and input device id are invalid");
        BindInfo info2;
        info2.AddInputDevice(bindByDisplay.GetInputDeviceId(), bindByDisplay.GetInputNodeName(),
            bindByDisplay.GetInputDeviceName());
        info2.AddDisplay(bindByDevice.GetDisplayId(), bindByDevice.GetDisplayName());
        infos_->Add(info2);
        return RET_OK;
    }

    if (bindByDevice.GetDisplayId() != -1) {
        MMI_HILOGD("The display id is invalid");
        AddDisplay(bindByDevice.GetDisplayId(), bindByDevice.GetDisplayName());
        return RET_OK;
    }

    if (bindByDisplay.GetInputDeviceId() != -1) {
        MMI_HILOGD("The input device id is invalid");
        AddInputDevice(bindByDisplay.GetInputDeviceId(), bindByDisplay.GetInputNodeName(),
            bindByDisplay.GetInputDeviceName());
        return RET_OK;
    }

    msg = "Can not reach here";
    return RET_ERR;
}

void InputDisplayBindHelper::Load()
{
    CALL_DEBUG_ENTER;
    char realPath[PATH_MAX] = {};
    CHKPV(realpath(fileName_.c_str(), realPath));
    if (!IsValidJsonPath(realPath)) {
        MMI_HILOGE("The file path is invalid");
        return;
    }
    std::ifstream ifs(realPath);
    MMI_HILOGEK("Open file end:%{private}s", realPath);
    if (!ifs) {
        MMI_HILOGE("Open file fail.%{private}s, errno:%{public}d", realPath, errno);
        return;
    }
    ifs >> *configFileInfos_;
    ifs.close();
}

std::string InputDisplayBindHelper::Dumps() const
{
    CALL_DEBUG_ENTER;
    CHKPO(infos_);
    std::ostringstream oss;
    oss << *infos_;
    return oss.str();
}
} // namespace MMI
} // namespace OHOS
