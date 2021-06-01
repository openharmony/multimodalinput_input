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

#ifndef I_MULTIMODALINPUT_SERVICE_H
#define I_MULTIMODALINPUT_SERVICE_H

#include <memory>

#include "ipc_types.h"
#include "iremote_broker.h"

#include "multimodal_event.h"

namespace OHOS {
class IMultimodalInputService : public IRemoteBroker {
public:
    virtual int32_t InjectEvent(const sptr<MultimodalEvent> &event) = 0;

    enum {
        INJECT_EVENT = 0,
    };

public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.multimodalinput.IMultimodalInputService");
};
} // namespace OHOS

#endif // I_MULTIMODALINPUT_SERVICE_H
