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
#ifndef MULTIMODAL_STANDARDIZED_EVENT_MANAGER_H
#define MULTIMODAL_STANDARDIZED_EVENT_MANAGER_H

#include <set>
#include "if_mmi_client.h"
#include "iremote_object.h"
#include "key_event_input_subscribe_manager.h"
#include "nocopyable.h"
#include "pointer_event.h"
#include "singleton.h"

namespace OHOS {
namespace MMI {
class NetPacket;
class MultimodalStandardizedEventManager {
public:
    MultimodalStandardizedEventManager();
    ~MultimodalStandardizedEventManager();
    DISALLOW_COPY_AND_MOVE(MultimodalStandardizedEventManager);

    void SetClientHandle(MMIClientPtr client);
    const std::set<std::string> *GetRegisterEvent();
    int32_t InjectionVirtual(bool isPressed, int32_t keyCode, int32_t keyDownDuration, int32_t maxKeyCode);
    int32_t InjectEvent(const std::shared_ptr<OHOS::MMI::KeyEvent> keyEventPtr);
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t GetDevice(int32_t userData, int32_t deviceId);
    int32_t GetDeviceIds(int32_t userData);
    int32_t SubscribeKeyEvent(const KeyEventInputSubscribeManager::SubscribeKeyEventInfo& subscribeInfo);
    int32_t UnSubscribeKeyEvent(int32_t subscribeId);
protected:
    bool SendMsg(NetPacket& pkt) const;

protected:
    MMIClientPtr client_ = nullptr;
};
} // namespace MMI
} // namespace OHOS
#define EventManager OHOS::Singleton<OHOS::MMI::MultimodalStandardizedEventManager>::GetInstance()
#endif // MULTIMODAL_STANDARDIZED_EVENT_MANAGER_H
