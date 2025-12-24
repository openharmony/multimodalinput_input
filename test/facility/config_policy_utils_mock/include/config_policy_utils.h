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

#ifndef MMI_CONFIG_POLICY_UTILS_H
#define MMI_CONFIG_POLICY_UTILS_H
#include <gmock/gmock.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif // __cplusplus

#define MAX_CFG_POLICY_DIRS_CNT 32
#define MAX_PATH_LEN    256  // max length of a filepath

struct CfgFiles {
    char *paths[MAX_CFG_POLICY_DIRS_CNT];
};

char* GetOneCfgFile(const char *pathSuffix, char *buf, unsigned int bufLength);
CfgFiles *GetCfgFiles(const char *pathSuffix);
void FreeCfgFiles(CfgFiles *res);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif // __cplusplus

namespace OHOS {
namespace MMI {
class IConfigPolicyUtils {
public:
    IConfigPolicyUtils();
    virtual ~IConfigPolicyUtils() = default;

    virtual char* GetOneCfgFile(const char *pathSuffix, char *buf, unsigned int bufLength) = 0;
    virtual CfgFiles *GetCfgFiles(const char *pathSuffix) = 0;
    virtual void FreeCfgFiles(CfgFiles *res) = 0;
};

class ConfigPolicyUtilsMock : public IConfigPolicyUtils {
public:
    ConfigPolicyUtilsMock() = default;
    virtual ~ConfigPolicyUtilsMock() override = default;

    MOCK_METHOD(char*, GetOneCfgFile, (const char*, char*, unsigned int));
    MOCK_METHOD(CfgFiles*, GetCfgFiles, (const char*));
    MOCK_METHOD(void, FreeCfgFiles, (CfgFiles *res));
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_CONFIG_POLICY_UTILS_H