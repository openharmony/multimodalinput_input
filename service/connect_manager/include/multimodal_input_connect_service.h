/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef MULTIMODAL_INPUT_CONNECT_SERVICE_H
#define MULTIMODAL_INPUT_CONNECT_SERVICE_H

#include "singleton.h"
#include "iremote_object.h"
#include "system_ability.h"
#include "nocopyable.h"
#include "multimodal_input_connect_stub.h"
#include "i_uds_server.h"

namespace OHOS {
namespace MMI {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class MultimodalInputConnectService final : public SystemAbility, public MultimodalInputConnectStub {
    DECLARE_DELAYED_SINGLETON(MultimodalInputConnectService);
    DECLEAR_SYSTEM_ABILITY(MultimodalInputConnectService);

public:
    void SetUdsServer(IUdsServer *server);
    void OnStart() override;
    void OnStop() override;
    void OnDump() override;
    virtual int32_t AllocSocketFd(const std::string &programName, const int32_t moduleType, int32_t &socketFd) override;
    virtual int32_t AddInputEventFilter(sptr<IEventFilter> filter) override;

protected:
    virtual int32_t StubHandleAllocSocketFd(MessageParcel &data, MessageParcel &reply) override;

private:
    bool Initialize() const;
    ServiceRunningState state_;
    IUdsServer *udsServer_ = nullptr;
};

int32_t MultimodalInputConnectServiceSetUdsServer(IUdsServer *server);
int32_t MultimodalInputConnectServiceStart();
int32_t MultimodalInputConnectServiceStop();
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_INPUT_CONNECT_SERVICE_H