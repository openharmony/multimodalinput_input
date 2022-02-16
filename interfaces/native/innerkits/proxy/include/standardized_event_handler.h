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
#ifndef STANDARDIZED_EVENT_HANDLER_H
#define STANDARDIZED_EVENT_HANDLER_H

#include "proto.h"
#include "key_event.h"
#include "key_event_pre.h"
#include "touch_event.h"
#include "device_event.h"
#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class StandardizedEventHandler;
typedef sptr<StandardizedEventHandler> StandEventPtr;
class StandardizedEventHandler : public RefBase {
public:
    explicit StandardizedEventHandler();
    virtual ~StandardizedEventHandler();

    template<class T>
    static StandEventPtr Create();

    virtual bool OnKey(const OHOS::KeyEvent& event);
    virtual bool OnTouch(const TouchEvent& event);

    virtual bool OnShowMenu(const MultimodalEvent& event);
    virtual bool OnSend(const MultimodalEvent& event);
    virtual bool OnCopy(const MultimodalEvent& event);
    virtual bool OnPaste(const MultimodalEvent& event);
    virtual bool OnCut(const MultimodalEvent& event);
    virtual bool OnUndo(const MultimodalEvent& event);
    virtual bool OnRefresh(const MultimodalEvent& event);
    virtual bool OnStartDrag(const MultimodalEvent& event);
    virtual bool OnCancel(const MultimodalEvent& event);
    virtual bool OnEnter(const MultimodalEvent& event);
    virtual bool OnPrevious(const MultimodalEvent& event);
    virtual bool OnNext(const MultimodalEvent& event);
    virtual bool OnBack(const MultimodalEvent& event);
    virtual bool OnPrint(const MultimodalEvent& event);

    virtual bool OnPlay(const MultimodalEvent& event);
    virtual bool OnPause(const MultimodalEvent& event);
    virtual bool OnMediaControl(const MultimodalEvent& event);

    virtual bool OnScreenShot(const MultimodalEvent& event);
    virtual bool OnScreenSplit(const MultimodalEvent& event);
    virtual bool OnStartScreenRecord(const MultimodalEvent& event);
    virtual bool OnStopScreenRecord(const MultimodalEvent& event);
    virtual bool OnGotoDesktop(const MultimodalEvent& event);
    virtual bool OnRecent(const MultimodalEvent& event);
    virtual bool OnShowNotification(const MultimodalEvent& event);
    virtual bool OnLockScreen(const MultimodalEvent& event);
    virtual bool OnSearch(const MultimodalEvent& event);
    virtual bool OnClosePage(const MultimodalEvent& event);
    virtual bool OnLaunchVoiceAssistant(const MultimodalEvent& event);
    virtual bool OnMute(const MultimodalEvent& event);

    virtual bool OnAnswer(const MultimodalEvent& event);
    virtual bool OnRefuse(const MultimodalEvent& event);
    virtual bool OnHangup(const MultimodalEvent& event);
    virtual bool OnTelephoneControl(const MultimodalEvent& event);

    virtual bool OnDeviceAdd(const DeviceEvent& event);
    virtual bool OnDeviceRemove(const DeviceEvent& event);

    MmiMessageId GetType() const
    {
        return type_;
    }
    void SetType(MmiMessageId type)
    {
        type_ = type;
    }
protected:
    MmiMessageId type_ = MmiMessageId::INVALID;
};

template<class T>
StandEventPtr OHOS::MMI::StandardizedEventHandler::Create()
{
    return StandEventPtr(new T());
}
} // namespace MMI
} // namespace OHOS
#endif // STANDARDIZED_EVENT_HANDLER_H