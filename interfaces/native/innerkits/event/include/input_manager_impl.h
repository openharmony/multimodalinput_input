/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_MULTIMDOALINPUT_INPUT_EVENT_MANAGER_H
#define OHOS_MULTIMDOALINPUT_INPUT_EVENT_MANAGER_H

#include <vector>
#include "singleton.h"
#include "display_info.h"
#include "i_input_event_consumer.h"
#include "pointer_event.h"
#include "if_mmi_client.h"
#include "net_packet.h"
#include "if_client_msg_handler.h"
#include "event_filter_service.h"

namespace OHOS {
namespace MMI {
class InputManagerImpl : public DelayedSingleton<InputManagerImpl> {
public:
    virtual ~InputManagerImpl() = default;
    InputManagerImpl() = default;

    void UpdateDisplayInfo(const std::vector<PhysicalDisplayInfo> &physicalDisplays,
        const std::vector<LogicalDisplayInfo> &logicalDisplays);                         // 建议本地调用，可IPC
    int32_t AddInputEventFilter(std::function<bool(std::shared_ptr<PointerEvent>)> filter);

    void SetWindowInputEventConsumer(std::shared_ptr<OHOS::MMI::IInputEventConsumer> inputEventConsumer);

    void OnKeyEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent);
    void OnPointerEvent(std::shared_ptr<OHOS::MMI::PointerEvent> pointerEvent);
    int32_t PackDisplayData(NetPacket &ckt);

    int32_t AddMonitor(std::function<void(std::shared_ptr<KeyEvent>)> monitor);
    int32_t AddMontior(std::function<void(std::shared_ptr<PointerEvent>)> monitor);
    int32_t AddMonitor(std::shared_ptr<IInputEventConsumer> consumer);
    void RemoveMonitor(int32_t monitorId);
    void MarkConsumed(int32_t monitorId, int32_t eventId);

    int32_t AddInterceptor(int32_t sourceType, std::function<void(std::shared_ptr<PointerEvent>)> interceptor);
    int32_t AddInterceptor(std::function<void(std::shared_ptr<KeyEvent>)> interceptor);
    void RemoveInterceptor(int32_t interceptorId);

    void SimulateInputEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent);

private:
    int32_t PackPhysicalDisplay(NetPacket &ckt);
    int32_t PackLogicalDisplay(NetPacket &ckt);
    void PrintDisplayDebugInfo();

private:
    sptr<EventFilterService> eventFilterService_ {nullptr};
    std::shared_ptr<OHOS::MMI::IInputEventConsumer> consumer;
    std::vector<PhysicalDisplayInfo> physicalDisplays_;
    std::vector<LogicalDisplayInfo> logicalDisplays_;
};
}
} // namespace OHOS::MMI
#endif // OHOS_MULTIMDOALINPUT_INPUT_MANAGER_H
