/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef DFX_HISYSEVENT_H
#define DFX_HISYSEVENT_H

#include <string.h>

#include "hisysevent.h"
#include "error_multimodal.h"
#include "key_event.h"
#include "mmi_log.h"
#include "pointer_event.h"
#include "uds_session.h"
#include "input_device_manager.h"

namespace OHOS {
namespace MMI {
class DfxHisysevent {
public:
    static void InputDeviceConnection(int32_t id);
    static void InputDeviceConnection(int32_t id, OHOS::HiviewDFX::HiSysEvent::EventType type);
    static void InputDeviceConnection(void);
    static void InputDeviceConnection1(void);
    static void InputDeviceConnection2(void);
    static void InputDeviceDisconnection(int32_t id);
    static void InputDeviceDisconnection(void);
    static void ClientConnectionEvent(const int32_t pid, const int32_t uid, const int32_t moduleType,
        const std::string &programName);
    static void ClientConnectionEvent(const int32_t pid, const int32_t uid, const int32_t moduleType,
        const std::string &programName, const int32_t serverFd);
    static void ClientDisconnectionEvent(void);
    static void ClientDisconnectionEvent(const SessionPtr& secPtr, int32_t fd);
    static void TargetPointerEvent(std::shared_ptr<PointerEvent> pointer);
    static void TargetPointerEvent(std::shared_ptr<PointerEvent> pointer, int32_t fd);
    static void TargetKeyEvent(std::shared_ptr<KeyEvent> key);
    static void TargetKeyEvent(std::shared_ptr<KeyEvent> key, int32_t fd);
    static void FocusWindowChange(const DisplayGroupInfo& oldDisplayGroupInfo,
        const DisplayGroupInfo& newDisplayGroupInfo);
    static void ZorderWindowChange(const DisplayGroupInfo& oldDisplayGroupInfo,
        const DisplayGroupInfo& newDisplayGroupInfo);
    static void ApplicationBlockInput(const SessionPtr& sess);
};
} // namespace MMI
} // namespace OHOS
#endif // BYTRACE_ADAPTER_H
