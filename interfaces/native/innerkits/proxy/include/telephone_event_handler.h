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
#ifndef OHOS_TELEPHONE_EVENTS_HANDLER_H
#define OHOS_TELEPHONE_EVENTS_HANDLER_H

#include "standardized_event_handler.h"
#include "multimodal_event.h"

namespace OHOS {
namespace MMI {
class TelephoneEventHandler : public StandardizedEventHandler {
public:
    TelephoneEventHandler();
    virtual ~TelephoneEventHandler();
    virtual bool OnAnswer(const MultimodalEvent& event) override;
    virtual bool OnRefuse(const MultimodalEvent& event) override;
    virtual bool OnHangup(const MultimodalEvent& event) override;
    virtual bool OnTelephoneControl(const MultimodalEvent& event) override;
};
}
}
#endif
