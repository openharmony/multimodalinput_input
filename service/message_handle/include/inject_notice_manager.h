/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef INJECT_NOTICE_MANAGER_H
#define INJECT_NOTICE_MANAGER_H

#include "ability_connect_callback_stub.h"

namespace OHOS {
namespace MMI {
struct InjectNoticeInfo {
    int32_t pid { 0 };
};

class InjectNoticeManager {
public:
    InjectNoticeManager();
    ~InjectNoticeManager();

public:
    class InjectNoticeConnection : public OHOS::AAFwk::AbilityConnectionStub {
    public:
        void OnAbilityConnectDone(const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject,
            int resultCode) override;
        void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode) override;
        bool SendNotice(const InjectNoticeInfo &noticeInfo);
        bool CancelNotice(const InjectNoticeInfo &noticeInfo);
        bool IsConnected() const;

    private:
        sptr<IRemoteObject> remoteObject_ { nullptr };
        std::atomic_bool isConnected_ = false;
    };
    bool StartNoticeAbility();
    bool ConnectNoticeSrv();
    bool IsAbilityStart() const;
    sptr<InjectNoticeConnection> GetConnection() const;

private:
    sptr<InjectNoticeConnection> connectionCallback_ { nullptr };
    std::atomic_bool isStartSrv_ = false;
};
} // namespace MMI
} // namespace OHOS
#endif // INJECT_NOTICE_MANAGE_H