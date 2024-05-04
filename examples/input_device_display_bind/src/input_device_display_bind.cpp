/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <iostream>
#include <cstdio>
#include <sstream>
#include <getopt.h>
#include <vector>
#include <array>
#include <iomanip>
#include <algorithm>

#include "input_manager.h"

constexpr int32_t INVALID_ID = -1;
enum Option {
    QUERY = 'q',
    SET = 's',
    HELP = 'h'
};

void PrintHelp(const std::string &title = {})
{
    std::cout << title << std::endl;
    printf("Usage\n"
        "-q     --query                             Query input device and display infomation\n"
        "-s     --set 'inputDeivceId displayId'     Set inputDeivceId and displayId of the input device\n");
}

void QueryDisplayBindInfo()
{
    printf("Query\n");
    OHOS::MMI::DisplayBindInfos infos;
    auto ret = OHOS::MMI::InputManager::GetInstance()->GetDisplayBindInfo(infos);
    if (ret != 0) {
        printf("Get display bind info failed.\n");
        return;
    }
    constexpr int32_t len = 5;
    std::vector<std::array<std::string, len>> arrStrings;
    std::array<std::string, len> arr0 = { "No.", "Input device Id", "Input device Name", "Display id", "Display name" };
    arrStrings.push_back(arr0);
    for (size_t i = 0; i < infos.size(); ++i) {
        const auto &info = infos[i];
        std::array<std::string, len> arr;
        arr[0] = std::to_string(i + 1);
        arr[1] = (info.inputDeviceId == INVALID_ID) ? "" : std::to_string(info.inputDeviceId);
        arr[2] = info.inputDeviceName;
        arr[3] = (info.displayId == INVALID_ID) ? "" : std::to_string(info.displayId);
        arr[4] = info.displayName;
        arrStrings.push_back(arr);
    }
    std::array<size_t, len> arrWidth{};
    for (const auto &[a, b, c, d, e] : arrStrings) {
        arrWidth[0] = std::max(arrWidth[0], a.length());
        arrWidth[1] = std::max(arrWidth[1], b.length());
        arrWidth[2] = std::max(arrWidth[2], c.length());
        arrWidth[3] = std::max(arrWidth[3], d.length());
        arrWidth[4] = std::max(arrWidth[4], e.length());
    }
    for (const auto &[a, b, c, d, e] : arrStrings) {
        std::cout << "|"
                  << " " << std::setw(arrWidth[0]) << std::setfill(' ') << std::left << a << " "
                  << "|"
                  << " " << std::setw(arrWidth[1]) << std::setfill(' ') << std::left << b << " "
                  << "|"
                  << " " << std::setw(arrWidth[2]) << std::setfill(' ') << std::left << c << " "
                  << "|"
                  << " " << std::setw(arrWidth[3]) << std::setfill(' ') << std::left << d << " "
                  << "|"
                  << " " << std::setw(arrWidth[4]) << std::setfill(' ') << std::left << e << " "
                  << "|" << std::endl;
    }
}

void SetDisplayBind(const char* optarg)
{
    std::istringstream iss(optarg);
    int32_t deviceId = INVALID_ID;
    int32_t displayId = INVALID_ID;
    iss >> deviceId >> displayId;
    if (iss.fail()) {
        PrintHelp("Arg is not right");
        return;
    }
    printf("args: deviceId:%d, displayId:%d\n", deviceId, displayId);
    std::string msg;
    auto ret = OHOS::MMI::InputManager::GetInstance()->SetDisplayBind(deviceId, displayId, msg);
    if (ret != 0) {
        printf("Set display bind failed, %s\n", msg.c_str());
        return;
    }
}

void HandleOptions(int argc, char* argv[])
{
    static struct option headOptions[] = {
        {"query", no_argument, nullptr, 'q'},
        {"set", required_argument, nullptr, 's'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    if (argc < 2) {
        PrintHelp();
        return;
    }

    int32_t optionIndex = 0;
    optind = 0;
    int32_t cases = 0;
    if ((cases = getopt_long(argc, argv, "qs:h?", headOptions, &optionIndex)) != -1) {
        switch (cases) {
            case QUERY: {
                QueryDisplayBindInfo();
                break;
            }
            case SET: {
                SetDisplayBind(optarg);
                break;
            }
            case HELP:
            default: {
                PrintHelp();
                break;
            }
        }
    };
}

int main(int argc, char* argv[])
{
    HandleOptions(argc, argv);
    return 0;
}