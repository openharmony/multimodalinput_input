/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "injection_tools_help_func.h"

#include <getopt.h>

#include <algorithm>
#include <iostream>
#include <string>

#include <unistd.h>

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "InjectionToolsHelpFunc"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t SEND_EVENT_ARGV_COUNTS { 6 };
constexpr int32_t JSON_ARGV_COUNTS { 3 };
constexpr int32_t HELP_ARGV_COUNTS { 2 };
constexpr int32_t SHORT_OPTION_LENGTH { 2 };
} // namespace

bool InjectionToolsHelpFunc::CheckInjectionCommand(int32_t argc, char **argv)
{
    CALL_DEBUG_ENTER;
    int32_t c = -1;
    if (!SelectOptions(argc, argv, c)) {
        MMI_HILOGE("Select option failed");
        return false;
    }
    switch (c) {
        case 'S': {
            if (!SendEventOption(argc, argv)) {
                MMI_HILOGE("SendEvent option failed");
                return false;
            }
            break;
        }
        case 'J': {
            if (!JsonOption(argc, argv)) {
                MMI_HILOGE("Json option failed");
                return false;
            }
            break;
        }
        case '?': {
            if (!HelpOption(argc, argv)) {
                MMI_HILOGE("Help option failed");
                return false;
            }
            break;
        }
        default: {
            std::cout << "invalid command" << std::endl;
            return false;
        }
    }
    return true;
}

bool InjectionToolsHelpFunc::SelectOptions(int32_t argc, char **argv, int32_t &opt)
{
    CALL_DEBUG_ENTER;
    if (argc < SHORT_OPTION_LENGTH) {
        std::cout << "Please enter options or parameters" << std::endl;
        return false;
    }
    struct option longOptions[] = {
        {"sendevent", no_argument, nullptr, 'S'},
        {"json", no_argument, nullptr, 'J'},
        {"help", no_argument, nullptr, '?'},
        {nullptr, 0, nullptr, 0}
    };
    std::string inputOptions = argv[optind];
    if (inputOptions.find('-') == inputOptions.npos) {
        for (uint32_t i = 0; i < sizeof(longOptions) / sizeof(struct option) - 1; ++i) {
            if (longOptions[i].name == inputOptions) {
                opt = longOptions[i].val;
                optind++;
                break;
            }
        }
    } else if ((inputOptions.length() != SHORT_OPTION_LENGTH) && (inputOptions[inputOptions.find('-') + 1] != '-')) {
        std::cout << "More than one short option is not supported" << std::endl;
        return false;
    } else {
        int32_t optionIndex = 0;
        opt = getopt_long(argc, argv, "SJ?", longOptions, &optionIndex);
    }
    if (opt == -1) {
        std::cout << "Nonstandard input parameters" << std::endl;
        return false;
    }
    return true;
}

bool InjectionToolsHelpFunc::SendEventOption(int32_t argc, char **argv)
{
    CALL_DEBUG_ENTER;
    if (argc != SEND_EVENT_ARGV_COUNTS) {
        std::cout << "Wrong number of input parameters" << std::endl;
        return false;
    }
    std::string deviceNode = argv[optind];
    if (deviceNode.empty()) {
        std::cout << "Device node does not exist: " << deviceNode.c_str() << std::endl;
        return false;
    }
    char realPath[PATH_MAX] = {};
    if (realpath(deviceNode.c_str(), realPath) == nullptr) {
        std::cout << "Device node path is error, path: " << deviceNode.c_str() << std::endl;
        return false;
    }
    while (++optind < argc) {
        std::string deviceInfo = argv[optind];
        if (!IsNumberic(deviceInfo)) {
            std::cout << "Parameter is error, element: " << deviceInfo.c_str() << std::endl;
            return false;
        }
    }
    SetArgvs(argc, argv, "sendevent");
    return true;
}

bool InjectionToolsHelpFunc::JsonOption(int32_t argc, char **argv)
{
    CALL_DEBUG_ENTER;
    if (argc < JSON_ARGV_COUNTS) {
        std::cout << "Wrong number of input parameters" << std::endl;
        return false;
    }
    const std::string jsonFile = argv[optind];
    std::string jsonBuf = ReadJsonFile(jsonFile);
    if (jsonBuf.empty()) {
        return false;
    }
    SetArgvs(argc, argv, "json");
    return true;
}

bool InjectionToolsHelpFunc::HelpOption(int32_t argc, char **argv)
{
    CALL_DEBUG_ENTER;
    if (argc != HELP_ARGV_COUNTS) {
        std::cout << "Wrong number of input parameters" << std::endl;
        return false;
    }
    SetArgvs(argc, argv, "help");
    return true;
}

bool InjectionToolsHelpFunc::IsNumberic(const std::string &str)
{
    return !str.empty() && std::all_of(str.begin(), str.end(), ::isdigit);
}

void InjectionToolsHelpFunc::SetArgvs(int32_t argc, char **argv, const std::string &str)
{
    injectArgvs_.clear();
    injectArgvs_.push_back(str);
    for (int32_t i = SHORT_OPTION_LENGTH; i < argc; ++i) {
        injectArgvs_.push_back(argv[i]);
    }
}

std::vector<std::string> InjectionToolsHelpFunc::GetArgvs() const
{
    return injectArgvs_;
}

void InjectionToolsHelpFunc::ShowUsage()
{
    std::cout << "Usage: mmi-event-injection <option> <command> <arg>..." << std::endl;
    std::cout << "The option are:                                       " << std::endl;
    std::cout << "commands for sendevent:                               " << std::endl;
    std::cout << "                                 -inject the original event to the device node" << std::endl;
    std::cout << "-S <device_node> <type> <code> <value>                " << std::endl;
    std::cout << "--sendevent <device_node> <type> <code> <value>       " << std::endl;
    std::cout << "sendevent <device_node> <type> <code> <value>         " << std::endl;
    std::cout << "commands for json:                                    " << std::endl;
    std::cout << "  -Inject a json file that writes all action information to the virtual device" << std::endl;
    std::cout << "-J <file_name>   --json <file_name>   josn <file_name>" << std::endl;
    std::cout << "-?  --help  help                                      " << std::endl;
}
} // namespace MMI
} // namespace OHOS
