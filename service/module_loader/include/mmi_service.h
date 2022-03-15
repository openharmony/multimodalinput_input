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

#ifndef MMI_SERVICE_H
#define MMI_SERVICE_H

#include <mutex>
#include <thread>

#include "iremote_object.h"
#include "nocopyable.h"
#include "singleton.h"
#include "system_ability.h"

#include "input_event_handler.h"
#include "multimodal_input_connect_stub.h"
#include "libinput_adapter.h"
#include "server_msg_handler.h"
#include "uds_server.h"

#ifdef OHOS_BUILD_HDF
    #include "hdf_event_manager.h"
#endif

namespace OHOS {
namespace MMI {

enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING, STATE_EXIT};
class MMIService : public UDSServer, public SystemAbility, public MultimodalInputConnectStub {
    DECLARE_DELAYED_SINGLETON(MMIService);
    DECLEAR_SYSTEM_ABILITY(MMIService);
    DISALLOW_COPY_AND_MOVE(MMIService);

public:
    virtual void OnStart() override;
    virtual void OnStop() override;
    virtual void OnDump() override;
    virtual int32_t AllocSocketFd(const std::string &programName, const int32_t moduleType, int32_t &socketFd) override;
    virtual int32_t AddInputEventFilter(sptr<IEventFilter> filter) override;

protected:
    virtual void OnConnected(SessionPtr s) override;
    virtual void OnDisconnected(SessionPtr s) override;
    virtual int32_t StubHandleAllocSocketFd(MessageParcel &data, MessageParcel &reply) override;

    virtual int32_t AddEpoll(EpollEventType type, int32_t fd) override;
    bool ChkAuthFd(int32_t fd) const;

    bool InitLibinputService();
    bool InitService();
    bool InitSignalHandler();
    int32_t Init();

    void OnTimer();
    void OnThread();
    void OnSignalEvent(int32_t signalFd);

private:
    ServiceRunningState state_ = ServiceRunningState::STATE_NOT_START;
    int32_t mmiFd_ = -1;
    std::mutex mu_;
    std::thread t_;

    LibinputAdapter libinputAdapter_;
    UDSServer udsServer_;
    ServerMsgHandler sMsgHandler_;
    std::set<int32_t> authFds_;
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_SERVICE_H