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

#ifndef CLIENT_DEATH_HANDLER_H
#define CLIENT_DEATH_HANDLER_H

#include <functional>
#include <map>
#include <mutex>
#include <vector>

#include "iremote_object.h"
#include "refbase.h"
#include "nocopyable.h"

#include "input_binder_client_death_recipient.h"

namespace OHOS {
namespace MMI {
enum class CallBackType : int32_t {
    CALLBACK_TYPE_AUTHORIZE_HELPER,
};
using ClientDeathCallback = std::function<void(int32_t)>;
class ClientDeathHandler final : RefBase {
public:
    ClientDeathHandler();
    ~ClientDeathHandler();
    DISALLOW_COPY_AND_MOVE(ClientDeathHandler);
    bool RegisterClientDeathRecipient(const sptr<IRemoteObject> &binderClientSrv, int32_t pid);
    bool AddClientDeathCallback(CallBackType type, ClientDeathCallback callback);
    bool UnregisterClientDeathRecipient(const wptr<IRemoteObject> &remoteObj);
    void RemoveClientDeathCallback(CallBackType type);

protected:
    bool RegisterClientDeathRecipient(const sptr<IRemoteObject> &binderClientSrv);
    bool AddClientPid(const sptr<IRemoteObject> &binderClientSrv, int32_t pid);
    void RemoveClientPid(int32_t pid);
    int32_t FindClientPid(const sptr<IRemoteObject> &binderClientSrv);
    void NotifyDeath(int32_t pid);

private:
    void OnDeath(const wptr<IRemoteObject> &remoteObj);
    std::mutex mutexPidMap_;
    std::map<int32_t, sptr<IRemoteObject>> clientPidMap_;
    std::mutex mutexDeathRecipient_;
    sptr<InputBinderClientDeathRecipient> deathRecipient_ = nullptr;
    std::mutex mutexCallbacks_;
    std::map<CallBackType, ClientDeathCallback> deathCallbacks_;
};
} // namespace MMI
} // namespace OHOS
#endif // CLIENT_DEATH_HANDLER_H
