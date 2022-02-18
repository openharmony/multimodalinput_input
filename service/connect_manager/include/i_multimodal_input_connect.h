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

#ifndef I_MULTIMODAL_INPUT_CONNECT_H
#define I_MULTIMODAL_INPUT_CONNECT_H

#include "iremote_broker.h"
#include "i_event_filter.h"

namespace OHOS {
namespace MMI {
class IMultimodalInputConnect : public IRemoteBroker {
public:
    [[maybe_unused]] static constexpr int32_t INVALID_SOCKET_FD = -1;
    static const int32_t MULTIMODAL_INPUT_CONNECT_SERVICE_ID = 3101;
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.multimodalinput.IConnectManager");

    virtual int32_t AllocSocketFd(const std::string &programName, const int32_t moduleType, int32_t &socketFd) = 0;
    virtual int32_t AddInputEventFilter(sptr<IEventFilter> filter) = 0;

    enum {
        ALLOC_SOCKET_FD = 0,
        SET_EVENT_POINTER_FILTER = 1,
    };

    enum {
        CONNECT_MODULE_TYPE_MMI_CLIENT = 0,
        CONNECT_MODULE_TYPE_AI = 1,
        CONNECT_MODULE_TYPE_SIMULATE_INJECT = 2,
    };
};
} // namespace MMI
} // namespace OHOS

#endif // I_MULTIMODAL_INPUT_CONNECT_H