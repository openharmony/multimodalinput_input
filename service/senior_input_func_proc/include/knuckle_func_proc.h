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
#ifndef KNUCKLE_FUNC_PROC_H
#define KNUCKLE_FUNC_PROC_H
#include "senior_input_func_proc_base.h"

namespace OHOS {
namespace MMI {
class KnuckleFuncProc : public SeniorInputFuncProcBase {
public:
    int32_t DeviceEventDispatchProcess(const RawInputEvent &event) override;
    int32_t GetDevType() override;
    int32_t CheckEventCode(const RawInputEvent& event);
};
} // namespace MMI
} // namespace OHOS
#endif // KNUCKLE_FUNC_PROC_H