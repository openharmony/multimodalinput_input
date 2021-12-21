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

#include "standardized_event_handler.h"
#include "log.h"

OHOS::MMI::StandardizedEventHandler::StandardizedEventHandler() : type_(MmiMessageId::INVALID) {}

OHOS::MMI::StandardizedEventHandler::~StandardizedEventHandler() {}

bool OHOS::MMI::StandardizedEventHandler::OnKey(const OHOS::KeyEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnTouch(const TouchEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnShowMenu(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnSend(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnCopy(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnPaste(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnCut(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnUndo(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnRefresh(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnStartDrag(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnCancel(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnEnter(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnPrevious(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnNext(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnBack(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnPrint(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnPlay(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnPause(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnMediaControl(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnScreenShot(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnScreenSplit(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnStartScreenRecord(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnStopScreenRecord(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnGotoDesktop(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnRecent(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnShowNotification(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnLockScreen(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnSearch(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnClosePage(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnLaunchVoiceAssistant(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnMute(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnAnswer(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnRefuse(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnHangup(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnTelephoneControl(const MultimodalEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnDeviceAdd(const DeviceEvent& event)
{
    return false;
}

bool OHOS::MMI::StandardizedEventHandler::OnDeviceRemove(const DeviceEvent& event)
{
    return false;
}
