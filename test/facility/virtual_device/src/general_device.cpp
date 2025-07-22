/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "general_device.h"

#include <iostream>
#include <sstream>
#include <thread>

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t DEFAULT_BUF_SIZE { 1024 };
constexpr int32_t SLEEP_TIME { 500 };
}

void GeneralDevice::Close()
{
    vDev_.reset();
}

void GeneralDevice::SendEvent(uint16_t type, uint16_t code, int32_t value)
{
    if (vDev_ == nullptr) {
        std::cout << "No input device" << std::endl;
        return;
    }
    vDev_->SendEvent(type, code, value);
}

std::string GeneralDevice::GetDevPath() const
{
    return (vDev_ != nullptr ? vDev_->GetDevPath() : std::string());
}

bool GeneralDevice::OpenDevice(const std::string &name)
{
    int32_t nTries = 6;

    while (nTries-- > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
        std::string node;
        if (GeneralDevice::FindDeviceNode(name, node)) {
            std::cout << "Found node path: " << node << std::endl;
            auto vInpuDev = std::make_unique<VInputDevice>(node);
            vInpuDev->Open();
            if (vInpuDev->IsActive()) {
                vDev_ = std::move(vInpuDev);
                return true;
            }
        }
    }
    return false;
}

bool GeneralDevice::FindDeviceNode(const std::string &name, std::string &node)
{
    std::map<std::string, std::string> nodes;
    GetInputDeviceNodes(nodes);
    std::cout << "There are " << nodes.size() << " device nodes" << std::endl;

    std::map<std::string, std::string>::const_iterator cItr = nodes.find(name);
    if (cItr == nodes.cend()) {
        std::cout << "No virtual stylus were found" << std::endl;
        return false;
    }
    std::cout << "Node name : \'" << cItr->second << "\'" << std::endl;
    std::ostringstream ss;
    ss << "/dev/input/" << cItr->second;
    node = ss.str();
    return true;
}

void GeneralDevice::Execute(std::vector<std::string> &results)
{
    char buffer[DEFAULT_BUF_SIZE] {};
    FILE *pin = popen("cat /proc/bus/input/devices", "r");
    if (pin == nullptr) {
        std::cout << "Failed to popen command" << std::endl;
        return;
    }
    while (!feof(pin)) {
        if (fgets(buffer, sizeof(buffer), pin) != nullptr) {
            results.push_back(buffer);
        }
    }
    pclose(pin);
}

void GeneralDevice::GetInputDeviceNodes(std::map<std::string, std::string> &nodes)
{
    std::vector<std::string> results;
    Execute(results);
    if (results.empty()) {
        std::cout << "Failed to list devices" << std::endl;
        return;
    }
    const std::string kname { "Name=\"" };
    const std::string kevent { "event" };
    std::string name;
    for (const auto &res : results) {
        if (res[0] == 'N') {
            std::string::size_type spos = res.find(kname);
            if (spos != std::string::npos) {
                spos += kname.size();
                std::string::size_type tpos = res.find("\"", spos);
                if (tpos != std::string::npos) {
                    name = res.substr(spos, tpos - spos);
                }
            }
        } else if (!name.empty() && (res[0] == 'H')) {
            std::string::size_type spos = res.find(kevent);
            if (spos != std::string::npos) {
                std::map<std::string, std::string>::const_iterator cItr = nodes.find(name);
                if (cItr != nodes.end()) {
                    nodes.erase(cItr);
                }
                std::string::size_type tpos = spos + kevent.size();
                while (tpos < res.size() && std::isalnum(res[tpos])) {
                    ++tpos;
                }
                auto [_, ret] = nodes.emplace(name, res.substr(spos, tpos - spos));
                if (!ret) {
                    std::cout << "name is duplicated" << std::endl;
                }
                name.clear();
            }
        }
    }
}
} // namespace MMI
} // namespace OHOS