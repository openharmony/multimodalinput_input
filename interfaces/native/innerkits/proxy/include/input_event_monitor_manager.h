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
#ifndef OHOS_INPUT_EVENT_MONITOR_MANAGER_H
#define OHOS_INPUT_EVENT_MONITOR_MANAGER_H

#include "key_event.h"
#include "pointer_event.h"
#include "multimodal_event_handler.h"
#include "proto.h"
#include "singleton.h"

#include <list>

namespace OHOS {
namespace MMI {
struct MonitorItem {
    int32_t id;
    std::function<void (std::shared_ptr<OHOS::MMI::KeyEvent>)> keyEventMonitor;
    bool operator == (const MonitorItem& item) const
    {
        return id == item.id;
    }
    std::string name;
    std::function<void (std::shared_ptr<OHOS::MMI::PointerEvent>)> TouchPadEventMonitor;
};

class InputEventMonitorManager {
public:
    InputEventMonitorManager();
    virtual ~InputEventMonitorManager();

    int32_t AddInputEventMontior(std::function<void (std::shared_ptr<OHOS::MMI::KeyEvent>)> keyEventMonitor);
    void RemoveInputEventMontior(int32_t monitorId);
    int32_t OnMonitorInputEvent(std::shared_ptr<OHOS::MMI::KeyEvent> keyEvent);

    int32_t AddInputEventTouchpadMontior(std::function<void (std::shared_ptr<OHOS::MMI::PointerEvent>)>
                                        TouchPadEventMonitor);
    void RemoveInputEventTouchpadMontior(int32_t monitorId);
    int32_t OnTouchpadMonitorInputEvent(std::shared_ptr<OHOS::MMI::PointerEvent> pointerEvent);

public:
    static const int32_t INVALID_MONITOR_ID { -1 };

private:
    std::list<MonitorItem> monitors_;
};
}
}
#define InputMonitorMgr OHOS::Singleton<OHOS::MMI::InputEventMonitorManager>::GetInstance()
#endif
