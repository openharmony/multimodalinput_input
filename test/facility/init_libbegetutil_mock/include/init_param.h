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

#ifndef MMI_INIT_PARAM_MOCK_H
#define MMI_INIT_PARAM_MOCK_H
#include <gmock/gmock.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif // __cplusplus

int SystemReadParam(const char *name, char *value, uint32_t *len);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif // __cplusplus

namespace OHOS {
namespace MMI {
class IInitParam {
public:
    IInitParam();
    virtual ~IInitParam() = default;

    virtual int SystemReadParam(const char *name, char *value, uint32_t *len) = 0;
};

class InitParamMock : public IInitParam {
public:
    InitParamMock() = default;
    virtual ~InitParamMock() override = default;

    MOCK_METHOD(int, SystemReadParam, (const char *, char*, uint32_t*));
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_INIT_PARAM_MOCK_H