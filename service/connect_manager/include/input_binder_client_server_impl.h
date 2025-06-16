/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef INPUT_BINDER_CLIENT_SERVER_IMPL_H
#define INPUT_BINDER_CLIENT_SERVER_IMPL_H

#include "input_binder_client_stub.h"
#include "iremote_object.h"

namespace OHOS {
namespace MMI {
class InputBinderClientServerImpl final: public InputBinderClientStub {
    DISALLOW_COPY_AND_MOVE(InputBinderClientServerImpl);
public:
    InputBinderClientServerImpl() = default;
    ~InputBinderClientServerImpl() = default;
public:
     ErrCode NoticeRequestInjectionResult(int32_t reqId, int32_t status) override;
};
} // namespace MMI
} // namespace OHOS
#endif // INPUT_BINDER_CLIENT_SERVER_IMPL_H