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
#ifndef STANDARDIZED_EVENT_MANAGER_H
#define STANDARDIZED_EVENT_MANAGER_H

#include <set>

#include "iremote_object.h"
#include "nocopyable.h"
#include "singleton.h"

#include "if_mmi_client.h"
#include "key_event_input_subscribe_manager.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class NetPacket;
class StandardizedEventManager {
public:
    StandardizedEventManager();
    ~StandardizedEventManager();
    DISALLOW_COPY_AND_MOVE(StandardizedEventManager);

    void SetClientHandle(MMIClientPtr client);
    const std::set<std::string> *GetRegisterEvent();
    int32_t InjectEvent(const std::shared_ptr<KeyEvent> keyEventPtr);
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t GetDevice(int32_t userData, int32_t deviceId);
    int32_t GetDeviceIds(int32_t userData);
    int32_t SupportKeys(int32_t userData, int32_t deviceId, std::vector<int32_t> keyCodes);
    int32_t GetKeyboardType(int32_t userData, int32_t deviceId) const;
    int32_t RegisterInputDeviceMonitor();
    int32_t UnRegisterInputDeviceMonitor();
    int32_t SubscribeKeyEvent(const KeyEventInputSubscribeManager::SubscribeKeyEventInfo& subscribeInfo);
    int32_t UnSubscribeKeyEvent(int32_t subscribeId);
#ifdef OHOS_BUILD_ENABLE_POINTER_DRAWING
    int32_t MoveMouseEvent(int32_t offsetX, int32_t offsetY);
#endif // OHOS_BUILD_ENABLE_POINTER_DRAWING

protected:
    bool SendMsg(NetPacket& pkt) const;

protected:
    MMIClientPtr client_ = nullptr;
};

#define EventManager OHOS::Singleton<StandardizedEventManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // STANDARDIZED_EVENT_MANAGER_H
