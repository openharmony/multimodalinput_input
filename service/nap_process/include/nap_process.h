/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef NAP_PROCESS_H
#define NAP_PROCESS_H

#include <map>
#include <memory>
#include <mutex>

#include "nocopyable.h"
#include "singleton.h"

#include "define_multimodal.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {
class NapProcess final {
public:

    virtual ~NapProcess() = default;

    static NapProcess *GetInstance();

struct NapStatusData {
    int32_t pid;
    int32_t uid;
    std::string bundleName;
    bool operator==(const NapStatusData b) const
    {
        return pid == b.pid && uid == b.uid && bundleName == b.bundleName;
    }
    bool operator<(const NapStatusData b) const
    {
        if (pid != b.pid) return pid < b.pid;
        if (uid != b.uid) return uid < b.uid;
        return bundleName < b.bundleName;
    }
};
    std::map<NapStatusData, int32_t> napMap_;
    int32_t NotifyBundleName(NapStatusData napData, int32_t syncState);
    int32_t SetNapStatus(int32_t pid, int32_t uid, std::string bundleName, int32_t napState);
    int32_t NotifyNapOnline();
    int32_t GetAllMmiSubscribedEvents(std::map<std::tuple<int32_t, int32_t, std::string>, int32_t> &datas);
    int32_t RemoveInputEventObserver();
    int32_t AddMmiSubscribedEventData(const NapStatusData& napData, int32_t syncState);
    int32_t RemoveMmiSubscribedEventData(const NapStatusData& napData);
    int32_t GetNapClientPid();
    bool IsNeedNotify(const NapStatusData& napData);
    void Init(UDSServer& udsServer);
    int32_t napClientPid_ { -1 };

private:
    UDSServer* udsServer_ { nullptr };
    NapProcess() = default;
    DISALLOW_COPY_AND_MOVE(NapProcess);
    static NapProcess *instance_;
    std::mutex mapMtx_;
};
} // namespace MMI
} // namespace OHOS
#endif // NAP_PROCESS_H
