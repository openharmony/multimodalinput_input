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

#ifndef OHOS_MULTIMODAL_INPUT_CONNECT_PROXY_H
#define OHOS_MULTIMODAL_INPUT_CONNECT_PROXY_H

#include "i_multimodal_input_connect.h"
#include "iremote_proxy.h"
#include "singleton.h"
#include "iremote_object.h"
#include "system_ability.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class MultimodalInputConnectProxy final : public IRemoteProxy<IMultimodalInputConnect> {
public:
    explicit MultimodalInputConnectProxy(const sptr<IRemoteObject> &impl);
    virtual ~MultimodalInputConnectProxy() override;
    virtual int32_t AllocSocketFd(const std::string &programName, const int moduleType, int &socketFd) override;
    virtual int32_t AddInputEventFilter(sptr<IEventFilter> filter) override;
private:
    static inline BrokerDelegator<MultimodalInputConnectProxy> delegator_;
};
} // namespace MMI
} // namespace OHOS
#endif // OHOS_MULTIMODAL_INPUT_CONNECT_PROXY_H
