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
 /**
 * @addtogroup multiInput
 * @{
 *
 * @brief Defines multiInput-related tests, including case data and functions for auto test,
 *
 * @since 1.0
 * @version 1.0
 */
#ifndef MULTI_INPUT_COMMON_H
#define MULTI_INPUT_COMMON_H
#include <string>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#include <cstdio>
#include "libmmi_util.h"
namespace OHOS {
namespace MMI {
class MultiInputCommon {
public:
    void InjectionIni(const std::string &iniFilePath, const std::string &fileName,
                      const std::string &jsonEventValue);
    void SetIniFile(const std::string &fileName, const std::string &jsonEventValue);
};
} // namespace MMI
} // namespace OHOS
#endif // MULTI_INPUT_COMMON_H