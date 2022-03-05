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
#ifndef MMI_EVENT_HANDLER_H
#define MMI_EVENT_HANDLER_H
#include "event_handler.h"
#include "if_mmi_client.h"

namespace OHOS {
namespace MMI {
#define EVENT_TIME_ONRECONNECT (3*1000)

enum MmiEventHandlerId : uint32_t {
    MMI_EVENT_HANDLER_ID_INVALID = 0,
    MMI_EVENT_HANDLER_ID_BEGIN = 1,
    MMI_EVENT_HANDLER_ID_RECONNECT = MMI_EVENT_HANDLER_ID_BEGIN,
    MMI_EVENT_HANDLER_ID_STOP,

    MMI_EVENT_HANDLER_ID_END,
};

class MMIEventHandler : public AppExecFwk::EventHandler
{
public:
    explicit MMIEventHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner, MMIClientPtr client);
    virtual ~MMIEventHandler();
    DISALLOW_COPY_AND_MOVE(MMIEventHandler);

    const std::string& GetErrorStr(ErrCode code) const;

protected:
    void OnReconnect(const AppExecFwk::InnerEvent::Pointer &event);
    void OnStop(const AppExecFwk::InnerEvent::Pointer &event);

protected:
    virtual void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;

private:
    MMIClientPtr mmiClient_ = nullptr;
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_EVENT_HANDLER_H

