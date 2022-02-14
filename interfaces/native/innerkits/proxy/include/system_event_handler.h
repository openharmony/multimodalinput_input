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
#ifndef SYSTEM_EVENT_HANDLER_H
#define SYSTEM_EVENT_HANDLER_H

#include "multimodal_event.h"
#include "standardized_event_handler.h"

namespace OHOS {
namespace MMI {
class SystemEventHandler : public StandardizedEventHandler {
public:
    SystemEventHandler();
    virtual ~SystemEventHandler();
    virtual bool OnScreenShot(const MultimodalEvent& event) override;
    virtual bool OnScreenSplit(const MultimodalEvent& event) override;
    virtual bool OnStartScreenRecord(const MultimodalEvent& event) override;
    virtual bool OnStopScreenRecord(const MultimodalEvent& event) override;
    virtual bool OnGotoDesktop(const MultimodalEvent& event) override;
    virtual bool OnRecent(const MultimodalEvent& event) override;
    virtual bool OnShowNotification(const MultimodalEvent& event) override;
    virtual bool OnLockScreen(const MultimodalEvent& event) override;
    virtual bool OnSearch(const MultimodalEvent& event) override;
    virtual bool OnClosePage(const MultimodalEvent& event) override;
    virtual bool OnLaunchVoiceAssistant(const MultimodalEvent& event) override;
    virtual bool OnMute(const MultimodalEvent& event) override;
};
}
}
#endif // SYSTEM_EVENT_HANDLER_H