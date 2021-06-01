/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef MULTIMODALINPUT_SERVICE_PROXY_H
#define MULTIMODALINPUT_SERVICE_PROXY_H

#include "iremote_proxy.h"

#include "i_multimodal_input_service.h"

namespace OHOS {
class MultimodalInputServiceProxy : public IRemoteProxy<IMultimodalInputService> {
public:
    explicit MultimodalInputServiceProxy(const sptr<IRemoteObject> &impl);
    virtual ~MultimodalInputServiceProxy() = default;

    int32_t InjectEvent(const sptr<MultimodalEvent> &event) override;
private:
    static inline BrokerDelegator<MultimodalInputServiceProxy> delegator_;
};
} // namespace OHOS

#endif // MULTIMODALINPUT_SERVICE_PROXY_H
