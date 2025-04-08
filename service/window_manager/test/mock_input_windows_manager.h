/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_INPUT_WINDOWS_MANAGER_H
#define MOCK_INPUT_WINDOWS_MANAGER_H

#include <gmock/gmock.h>

#include "event_dispatch_handler.h"
#include "event_normalize_handler.h"
#include "input_windows_manager.h"
#include "uds_server.h"
#include "window_info.h"
#include "i_pointer_drawing_manager.h"

namespace OHOS {
namespace MMI {
class InputWindowsManagerInterface {
public:
    InputWindowsManagerInterface(){};
    virtual ~InputWindowsManagerInterface(){};
    virtual std::shared_ptr<EventNormalizeHandler> GetEventNormalizeHandler() = 0;
    virtual std::shared_ptr<EventDispatchHandler> GetEventDispatchHandler() = 0;
    virtual UDSServer* GetUDSServer() = 0;
    virtual bool IsAncoWindow(const WindowInfo &window) = 0;
};

class MockInputWindowsManager : public InputWindowsManagerInterface {
public:
    MockInputWindowsManager();
    ~MockInputWindowsManager() override;

    MOCK_METHOD(std::shared_ptr<EventNormalizeHandler>, GetEventNormalizeHandler, ());
    MOCK_METHOD(std::shared_ptr<EventDispatchHandler>, GetEventDispatchHandler, ());
    MOCK_METHOD(UDSServer*, GetUDSServer, ());
    MOCK_METHOD(bool, IsAncoWindow, (const WindowInfo &));
};
}  // namespace MMI
}  // namespace OHOS
#endif
