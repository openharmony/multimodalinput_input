/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef MULTIMODAL_EVENT_HANDLER_H
#define MULTIMODAL_EVENT_HANDLER_H

#include "if_mmi_client.h"
#include "key_event_input_subscribe_manager.h"
#include "long_press_event.h"
#include "pointer_event.h"
#include "switch_event_input_subscribe_manager.h"
#include "touchpad_control_display_gain.h"

namespace OHOS {
namespace MMI {
enum RES_STATUS : uint8_t {
    REG_STATUS_NOT_SYNC = 0,
    REG_STATUS_SYNCED = 1
};

class MultimodalEventHandler final {
    DECLARE_SINGLETON(MultimodalEventHandler);

public:
    DISALLOW_MOVE(MultimodalEventHandler);

    MMIClientPtr GetMMIClient();
    bool InitClient(EventHandlerPtr eventHandler = nullptr);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t SubscribeKeyEvent(const KeyEventInputSubscribeManager::SubscribeKeyEventInfo& subscribeInfo);
    int32_t UnsubscribeKeyEvent(int32_t subscribeId);
    int32_t SubscribeHotkey(const KeyEventInputSubscribeManager::SubscribeKeyEventInfo &subscribeInfo);
    int32_t UnsubscribeHotkey(int32_t subscribeId);
    int32_t InjectEvent(const std::shared_ptr<KeyEvent> keyEvent, bool isNativeInject);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_SWITCH
    int32_t SubscribeSwitchEvent(int32_t subscribeId, int32_t switchType);
    int32_t UnsubscribeSwitchEvent(int32_t subscribeId);
#endif // OHOS_BUILD_ENABLE_SWITCH
    int32_t SubscribeLongPressEvent(int32_t subscribeId, const LongPressRequest &longPressRequest);
    int32_t UnsubscribeLongPressEvent(int32_t subscribeId);
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent, bool isNativeInject);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t InjectTouchPadEvent(std::shared_ptr<PointerEvent> pointerEvent, const TouchpadCDG &touchpadCDG,
        bool isNativeInject);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t MoveMouseEvent(int32_t offsetX, int32_t offsetY);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    int32_t Authorize(bool isAuthorize);
    int32_t CancelInjection();

private:
    int32_t SetClientInfo(int32_t pid, uint64_t readThreadId);
    std::mutex mtx_;
    MMIClientPtr client_ { nullptr };
};

#define MMIEventHdl ::OHOS::Singleton<MultimodalEventHandler>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // MULTIMODAL_EVENT_HANDLER_H