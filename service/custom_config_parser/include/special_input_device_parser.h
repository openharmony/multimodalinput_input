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

 
#ifndef SPECIAL_INPUT_DEVICE_PARSER_H
#define SPECIAL_INPUT_DEVICE_PARSER_H
 
#include <shared_mutex>
#include <string>
#include <map>
 
#include "json_parser.h"
#include "cJSON.h"
 
namespace OHOS {
namespace MMI {
 
class SpecialInputDeviceParser {
public:
    SpecialInputDeviceParser(const SpecialInputDeviceParser&) = delete;
    SpecialInputDeviceParser& operator=(const SpecialInputDeviceParser&) = delete;
    static SpecialInputDeviceParser& GetInstance();
    int32_t Init();
    int32_t IsPointerDevice(const std::string &name, bool &isPointerDevice);
    std::string GetInputDevName(const std::string &alias);
 
private:
    SpecialInputDeviceParser() = default;
    ~SpecialInputDeviceParser() = default;
 
    struct ExactlyMatchInputDevice {
        std::string devName;
        bool isMouse { false };
    };
 
    struct ContainMatchInputDevice {
        std::vector<std::string> keywords;
        bool isMouse { false };
    };
 
    struct SpecialInputDevice {
        std::string inputDevAlias;
        std::string inputDevName;
    };
 
private:
    int32_t ParseExactlyMatch(const JsonParser &jsonParser);
    int32_t ParseContainMatch(const JsonParser &jsonParser);
    int32_t ParseSpecialInputDevice(const JsonParser &jsonParser);
    int32_t ParseExactlyMatchItem(const cJSON *json, ExactlyMatchInputDevice &deviceProp);
    int32_t ParseContainMatchItem(const cJSON *json, ContainMatchInputDevice &deviceProp);
    int32_t ParseSpecialInputDeviceItem(const cJSON *json, SpecialInputDevice &specialInputDev);
    bool IsAllKeywordsMatched(const std::string &name, const std::vector<std::string> &keywords);
    void PrintSpecialInputDevice();
    int32_t InitializeImpl();

private:
    std::map<std::string, ExactlyMatchInputDevice> exactlyMatchInputDevice_;
    std::vector<ContainMatchInputDevice> containMatchInputDevice_;
    std::map<std::string, std::string> specialInputDevices_;
    std::shared_mutex lock_;
    std::atomic_bool isInitialized_ { false };
};
} // namespace MMI
} // namespace OHOS
#define SPECIAL_INPUT_DEVICE_PARSER OHOS::MMI::SpecialInputDeviceParser::GetInstance()
#endif // SPECIAL_INPUT_DEVICE_PARSER_H