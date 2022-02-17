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
#ifndef MULTIMODAL_EVENT_HANDLER_H
#define MULTIMODAL_EVENT_HANDLER_H

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
    MMIClientPtr GetMMIClient();
    std::vector<EventRegesterInfo>& GetAbilityInfoVec();
    int32_t InjectEvent(const OHOS::KeyEvent& keyEvent);
    int32_t InjectEvent(const OHOS::MMI::KeyEvent& keyEvent);
    int32_t InjectEvent(const std::shared_ptr<OHOS::MMI::KeyEvent> keyEventPtr);
    
    int32_t AddKeyEventFIlter(int32_t id, std::string name, Authority authority);
    int32_t RemoveKeyEventFIlter(int32_t id);
    int32_t AddTouchEventFilter(int32_t id, std::string name, Authority authority);
    int32_t RemoveTouchEventFilter(int32_t id);
    int32_t AddEventInterceptor(int32_t id, std::string name, Authority authority);
    int32_t RemoveEventInterceptor(int32_t id);
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t GetDevice(int32_t taskId, int32_t deviceId);
    int32_t GetDeviceIds(int32_t taskId);    
    int32_t AddInputEventMontior(int32_t keyEventType);
    void RemoveInputEventMontior(int32_t keyEventType);
    int32_t AddInputEventTouchpadMontior(int32_t pointerEventType);
    void RemoveInputEventTouchpadMontior(int32_t pointerEventType);
    int32_t AddInterceptor(int32_t sourceType, int32_t id);
    int32_t RemoveInterceptor(int32_t id);

/**
* Default constructor used to create a {@code MultimodalEventHandler} instance.
*/
private:
    bool InitClient();

private:
    MMIClientPtr client_;
    IClientMsgHandlerPtr cMsgHandler_;
    std::vector<EventRegesterInfo> abilityInfoVec_;
    StandEventPtr standardizedEventHandle_;
};
} // namespace MMI
} // namespace OHOS
#define MMIEventHdl OHOS::MMI::MultimodalEventHandler::GetInstance()

#endif // MULTIMODAL_EVENT_HANDLER_H