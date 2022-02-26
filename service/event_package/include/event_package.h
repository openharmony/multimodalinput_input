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
#ifndef EVENT_PACKAGE_H
#define EVENT_PACKAGE_H
#include "pointer_event.h"
#include "key_event.h"
#include "input_windows_manager.h"
#include "nocopyable.h"
#include "uds_server.h"
#include "util.h"
#define KEYSTATUS 0

namespace OHOS {
namespace MMI {
    class EventPackage {
        static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "EventPackage" };
        static constexpr uint32_t TabletPadButtonNumberPrefix = 0x100;
    public:
        EventPackage();
        DISALLOW_COPY_AND_MOVE(EventPackage);
        virtual ~EventPackage();
        int32_t PackageKeyEvent(libinput_event *event, EventKeyboard& key);
        int32_t PackageKeyEvent(libinput_event *event, std::shared_ptr<KeyEvent> kevnPtr);
        static int32_t PackageVirtualKeyEvent(VirtualKey& event, EventKeyboard& key);
        static int32_t KeyboardToKeyEvent(const EventKeyboard& key, std::shared_ptr<KeyEvent> keyEventPtr);
    };
} // namespace MMI
} // namespace OHOS
#endif // EVENT_PACKAGE_H