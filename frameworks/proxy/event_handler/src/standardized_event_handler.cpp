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

#include "standardized_event_handler.h"
#include "log.h"

namespace OHOS {
namespace MMI {
StandardizedEventHandler::StandardizedEventHandler() : type_(MmiMessageId::INVALID) {}
StandardizedEventHandler::~StandardizedEventHandler() {}

bool StandardizedEventHandler::OnKey(const OHOS::KeyEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnTouch(const TouchEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnShowMenu(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnSend(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnCopy(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnPaste(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnCut(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnUndo(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnRefresh(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnStartDrag(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnCancel(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnEnter(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnPrevious(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnNext(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnBack(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnPrint(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnPlay(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnPause(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnMediaControl(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnScreenShot(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnScreenSplit(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnStartScreenRecord(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnStopScreenRecord(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnGotoDesktop(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnRecent(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnShowNotification(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnLockScreen(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnSearch(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnClosePage(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnLaunchVoiceAssistant(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnMute(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnAnswer(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnRefuse(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnHangup(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnTelephoneControl(const MultimodalEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnDeviceAdd(const DeviceEvent& event)
{
    return false;
}

bool StandardizedEventHandler::OnDeviceRemove(const DeviceEvent& event)
{
    return false;
}
} // namespace MMI
} // namespace OHOS