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
#ifndef MEDIA_EVENT_HANDLER_H
#define MEDIA_EVENT_HANDLER_H

#include "standardized_event_handler.h"
#include "multimodal_event.h"

namespace OHOS {
namespace MMI {
class MediaEventHandler : public StandardizedEventHandler {
public:
    MediaEventHandler();
    virtual ~MediaEventHandler();
    virtual bool OnPlay(const MultimodalEvent& event) override;
    virtual bool OnPause(const MultimodalEvent& event) override;
    virtual bool OnMediaControl(const MultimodalEvent& event) override;
};
} // namespace MMI
} // namespace OHOS
#endif // MEDIA_EVENT_HANDLER_H