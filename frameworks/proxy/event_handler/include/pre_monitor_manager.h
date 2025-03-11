/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef PRE_MONITOR_MANAGER_H
#define PRE_MONITOR_MANAGER_H

#include <map>
#include "singleton.h"

#include "i_input_event_consumer.h"

namespace OHOS {
namespace MMI {
class PreMonitorManager final {
    DECLARE_SINGLETON(PreMonitorManager);

public:
    DISALLOW_MOVE(PreMonitorManager);

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void OnPreKeyEvent(std::shared_ptr<KeyEvent> keyEvent, int32_t handlerId);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_MONITOR)
    void OnConnected();
#endif // OHOS_BUILD_ENABLE_MONITOR
    HandleEventType GetEventType() const;
    int32_t AddHandler(
        std::shared_ptr<IInputEventConsumer> consumer, HandleEventType eventType, std::vector<int32_t> keys);
    int32_t RemoveHandler(int32_t handlerId);

private:
    struct Handler {
        int32_t handlerId_ { 0 };
        HandleEventType eventType_ { HANDLE_EVENT_TYPE_PRE_KEY };
        std::shared_ptr<IInputEventConsumer> callback_ { nullptr };
        std::vector<int32_t> keys_;
    };

private:
    int32_t GetNextId();
    virtual bool CheckMonitorValid(TouchGestureType type, int32_t fingers)
    {
        return false;
    }
    int32_t AddLocal(int32_t handlerId, HandleEventType eventType, std::vector<int32_t> keys,
        std::shared_ptr<IInputEventConsumer> consumer);
    int32_t AddToServer(int32_t handlerId, HandleEventType eventType, std::vector<int32_t> keys);
    int32_t RemoveLocal(int32_t handlerId);
    int32_t RemoveFromServer(int32_t handlerId);
    std::shared_ptr<IInputEventConsumer> FindHandler(int32_t handlerId);

private:
    std::map<int32_t, Handler> monitorHandlers_;
    int32_t nextId_ { 1 };
    std::mutex mtxHandlers_;
};
#define PRE_MONITOR_MGR ::OHOS::Singleton<PreMonitorManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // PRE_MONITOR_MANAGER_H
