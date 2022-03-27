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
#ifndef MULTIMODAL_EVENT_HANDLER_H
#define MULTIMODAL_EVENT_HANDLER_H

#include "nocopyable.h"
#include "singleton.h"

#include "if_client_msg_handler.h"
#include "pointer_event.h"
#include "proto.h"
#include "standardized_event_manager.h"

namespace OHOS {
namespace MMI {
enum RES_STATUS : uint8_t {
    REG_STATUS_NOT_SYNC = 0,
    REG_STATUS_SYNCED = 1
};

class MultimodalEventHandler : public Singleton<MultimodalEventHandler> {
public:
    MultimodalEventHandler();
    ~MultimodalEventHandler() = default;
    DISALLOW_COPY_AND_MOVE(MultimodalEventHandler);
    int32_t GetMultimodeInputInfo();
    MMIClientPtr GetMMIClient();
    int32_t InjectEvent(const std::shared_ptr<KeyEvent> keyEventPtr);
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t GetDevice(int32_t taskId, int32_t deviceId);
    int32_t GetDeviceIds(int32_t taskId);
    int32_t AddInputEventMontior(int32_t keyEventType);
    void RemoveInputEventMontior(int32_t keyEventType);
    int32_t AddInputEventTouchpadMontior(int32_t pointerEventType);
    void RemoveInputEventTouchpadMontior(int32_t pointerEventType);
    int32_t AddInterceptor(int32_t sourceType, int32_t id);
    int32_t RemoveInterceptor(int32_t id);

private:
    bool InitClient();

private:
    MMIClientPtr client_ = nullptr;
    IClientMsgHandlerPtr cMsgHandler_ = nullptr;
};

#define MMIEventHdl MultimodalEventHandler::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_EVENT_HANDLER_H