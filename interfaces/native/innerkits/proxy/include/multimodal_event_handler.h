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
#ifndef OHOS_MULTIMODAL_EVENTS_HANDLER_H
#define OHOS_MULTIMODAL_EVENTS_HANDLER_H

#include "singleton.h"
#include "if_client_msg_handler.h"
#include "multimodal_standardized_event_manager.h"

namespace OHOS {
namespace MMI {
enum RES_STATUS : uint8_t {
    REG_STATUS_NOT_SYNC = 0, // 未同步
    REG_STATUS_SYNCED = 1,   // 以同步
};
struct EventRegesterInfo {
    RES_STATUS sync;
    sptr<IRemoteObject> token;
    int32_t windowId;
    StandEventPtr standardizedEventHandle;
};

class MultimodalEventHandler : public Singleton<OHOS::MMI::MultimodalEventHandler> {
public:
    MultimodalEventHandler();
    ~MultimodalEventHandler() = default;

    int32_t RegisterStandardizedEventHandle(const sptr<IRemoteObject> token,
                                            int32_t windowId, StandEventPtr standardizedEventHandle);
    int32_t UnregisterStandardizedEventHandle(const sptr<IRemoteObject> token,
                                              int32_t windowId, StandEventPtr standardizedEventHandle);
    int32_t GetMultimodeInputInfo();
    std::vector<EventRegesterInfo>& GetAbilityInfoVec();
    int32_t InjectEvent(const KeyEvent& keyEvent);

/**
* Default constructor used to create a {@code MultimodalEventHandler} instance.
*/
private:
    bool InitClient();

private:
    MMIClientPtr mClient_;
    IClientMsgHandlerPtr mcMsgHandler_;
    std::vector<EventRegesterInfo> mAbilityInfoVec_;
    StandEventPtr mStandardizedEventHandle_;
};
}
}
#define MMIEventHdl OHOS::MMI::MultimodalEventHandler::GetInstance()

#endif
