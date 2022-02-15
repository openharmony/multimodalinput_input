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
#ifndef SYSTEM_EVENT_HANDLER_H
#define SYSTEM_EVENT_HANDLER_H

#include <functional>
#include <map>
#include "singleton.h"
#include "proto.h"
#include "msg_handler.h"

namespace OHOS {
namespace MMI {
class SystemEventHandler : public DelayedSingleton<SystemEventHandler>, public MsgHandler<std::function<void()>> {
public:
    SystemEventHandler();
    virtual ~SystemEventHandler();

    int32_t OnSystemEventHandler(MmiMessageId idMsg);

protected:
    void OnGotoDesktop();
    void OnScreenShot();
    void OnScreenSplit();
    void OnStopScreenRecord();
    void OnStartScreenRecord();
    void OnShowNotification();
    void OnRecent();
    void OnLockScreen();
    void OnSearch();
    void OnClosePage();
    void OnLaunchVoiceAssistant();
    void OnMute();
    void OnBack();
};
} // namespace MMI
} // namespace OHOS
#define SysEveHdl OHOS::MMI::SystemEventHandler::GetInstance()

#endif // SYSTEM_EVENT_HANDLER_H