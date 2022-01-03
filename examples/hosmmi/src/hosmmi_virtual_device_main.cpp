/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
    if (argc == 1 || argc > MAX_PARAMETER_NUMBER) {
        printf("Invaild Input Para, Plase Check the validity of the para!\n");
        return 0;
    }
    const std::int32_t usleepTime = 1500000;
    OHOS::MMI::VirtualDevice::MakeFolder(OHOS::MMI::g_folderpath.c_str());

    StringList argvList = {};
    for (uint16_t i = 0; i < argc; i++) {
        argvList.push_back(argv[i]);
    }
    std::string firstArgv = argvList[1];

    if (OHOS::MMI::VirtualDevice::FunctionalShunt(firstArgv, argvList)) {
        while (true) {
            usleep(usleepTime);
        }
    } else {
        return 0;
    }
}
