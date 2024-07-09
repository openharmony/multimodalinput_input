/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef INPUT_BINDER_CLIENT_SERVER_H
#define INPUT_BINDER_CLIENT_SERVER_H

#include <mutex>

#include "singleton.h"

#include "i_multimodal_input_connect.h"
#include "input_binder_client_stub.h"

namespace OHOS {
namespace MMI {
class InputBinderClientServer final {
    DECLARE_DELAYED_SINGLETON(InputBinderClientServer);
public:
    DISALLOW_COPY_AND_MOVE(InputBinderClientServer);
    sptr<IRemoteObject> GetClientSrv();
private:
    void InitClientSrv();
    std::mutex clientSrvMutex_;
    sptr<InputBinderClientStub> clientSrvStub_ = nullptr;
};
#define INPUT_BINDER_CLIENT_SERVICE ::OHOS::DelayedSingleton<InputBinderClientServer>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_BINDER_CLIENT_SERVER_H