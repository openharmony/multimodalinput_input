/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "virtual_device.h"

int32_t main(int32_t argc, const char *argv[])
{
    if (argc == 1 || argc > PARAMETERS_NUMBER) {
        std::cout << "Invalid Input Para, Please Check the validity of the para" << std::endl;
        return 0;
    }
    DIR* dir = opendir(OHOS::MMI::g_folderPath.c_str());
    if (dir == nullptr) {
        mkdir(OHOS::MMI::g_folderPath.c_str(), SYMBOL_FOLDER_PERMISSIONS);
    } else {
        if (closedir(dir) != 0) {
            std::cout << "Close dir:" << OHOS::MMI::g_folderPath << "failed" << std::endl;
        }
    }
    std::vector<std::string> argvList;
    for (uint16_t i = 0; i < argc; i++) {
        argvList.push_back(argv[i]);
    }
    if (!OHOS::MMI::VirtualDevice::CommandBranch(argvList)) {
        return 0;
    }
    static constexpr std::int32_t usleepTime = 1500000;
    while (true) {
        usleep(usleepTime);
    }

    return 0;
}
