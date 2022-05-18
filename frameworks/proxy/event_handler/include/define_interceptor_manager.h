/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef DEFINE_INTERCEPTOR_MANAGER_H
#define DEFINE_INTERCEPTOR_MANAGER_H

#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    #include "input_interceptor_manager.h"
#else
    #include "i_input_interceptor_manager.h"
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR

namespace OHOS {
namespace MMI {
#ifdef OHOS_BUILD_ENABLE_INTERCEPTOR
    #define InputInterMgr InputInterceptorManager::GetInstance()
#else
    #define InputInterMgr IInputInterceptorManager::GetInstance()
#endif
} // namespace MMI
} // namespace OHOS
#endif // DEFINE_INTERCEPTOR_MANAGER_H