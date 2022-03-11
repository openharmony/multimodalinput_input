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

#ifndef INPUT_EVENT_MONITOR_H
#define INPUT_EVENT_MONITOR_H

#include <algorithm>
#include <list>
#include <map>
#include <vector>

#include "nocopyable.h"
#include "singleton.h"

#include "key_event.h"
#include "pointer_event.h"
#include "struct_multimodal.h"
#include "uds_session.h"

namespace OHOS {
namespace MMI {
struct MonitorItem {
    int32_t eventType;
    SessionPtr session = nullptr;
    bool operator == (const MonitorItem& item)
    {
        return eventType == item.eventType && session == item.session;
    }
};

class InputEventMonitorManager {
public:
    InputEventMonitorManager();
    DISALLOW_COPY_AND_MOVE(InputEventMonitorManager);
    virtual ~InputEventMonitorManager();

    int32_t AddInputEventMontior(SessionPtr session, int32_t eventType);
    void RemoveInputEventMontior(SessionPtr session, int32_t eventType);
    void OnMonitorInputEvent(std::shared_ptr<KeyEvent> keyEvent);

    int32_t AddInputEventTouchpadMontior(int32_t eventType, SessionPtr session);
    void RemoveInputEventTouchpadMontior(int32_t eventType, SessionPtr session);
    bool ReportTouchpadEvent(std::shared_ptr<PointerEvent> pointerEvent);

private:
    std::list<MonitorItem> monitors_;
    std::list<MonitorItem> monitorsTouch_;

    void OnTouchpadMonitorInputEvent(std::shared_ptr<PointerEvent> PointerEvent);
};

#define InputMonitorServiceMgr OHOS::Singleton<InputEventMonitorManager>::GetInstance()
} // namespace MMI
} // namespace OHOS
#endif // INPUT_EVENT_MONITOR_H
