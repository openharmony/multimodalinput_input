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
#include "singleton.h"

#include "if_mmi_client.h"
#include "key_event_input_subscribe_manager.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class NetPacket;
class StandardizedEventManager final {
    DECLARE_SINGLETON(StandardizedEventManager);

public:
    DISALLOW_MOVE(StandardizedEventManager);

    void SetClientHandle(MMIClientPtr client);
    const std::set<std::string> *GetRegisterEvent();
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t InjectEvent(const std::shared_ptr<KeyEvent> keyEventPtr);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t SubscribeKeyEvent(const KeyEventInputSubscribeManager::SubscribeKeyEventInfo& subscribeInfo);
    int32_t UnsubscribeKeyEvent(int32_t subscribeId);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t MoveMouseEvent(int32_t offsetX, int32_t offsetY);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWIN

protected:
    bool SendMsg(NetPacket& pkt) const;

protected:
    MMIClientPtr client_ { nullptr };
};

#define EventManager ::OHOS::Singleton<StandardizedEventManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // STANDARDIZED_EVENT_MANAGER_H
