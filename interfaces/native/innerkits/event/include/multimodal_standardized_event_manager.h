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
#ifndef OHOS_MULTIMODAL_STANDARDIZED_EVENTS_MANAGER_H
#define OHOS_MULTIMODAL_STANDARDIZED_EVENTS_MANAGER_H

#include <set>
#include "singleton.h"
#include "iremote_object.h"
#include "if_mmi_client.h"
#include "standardized_event_handler.h"

namespace OHOS {
namespace MMI {
class NetPacket;
struct StandEventCallBack {
    int32_t windowId;
    StandEventPtr eventCallBack;
};
typedef std::multimap<MmiMessageId, StandEventCallBack> StandEventMMaps;
class MultimodalStandardizedEventManager {
public:
    MultimodalStandardizedEventManager();
    ~MultimodalStandardizedEventManager();
    MultimodalStandardizedEventManager(const MultimodalStandardizedEventManager&) = delete;
    MultimodalStandardizedEventManager& operator=(const MultimodalStandardizedEventManager&) = delete;

    void SetClientHandle(MMIClientPtr client);
    const std::set<std::string> *GetRegisterEvent();
    void ClearAll();
    int32_t InjectionVirtual(bool isPressed, int32_t keyCode, int32_t keyDownDuration, int32_t maxKeyCode);
    int32_t InjectEvent(const OHOS::KeyEvent& keyEvent);
    int32_t InjectEvent(const OHOS::MMI::KeyEvent& keyEvent);
    int32_t InjectPointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
    int32_t GetDevice(int32_t taskId, int32_t deviceId);
    int32_t GetDeviceIds(int32_t taskId);
    int32_t RegisterStandardizedEventHandle(const sptr<IRemoteObject> token,
        int32_t windowId, StandEventPtr standardizedEventHandle);
    int32_t UnregisterStandardizedEventHandle(const sptr<IRemoteObject> token,
        int32_t windowId, StandEventPtr standardizedEventHandle);

public:
    int32_t OnKey(const OHOS::KeyEvent& event);
    int32_t OnTouch(const TouchEvent& event);

    int32_t OnShowMenu(const MultimodalEvent& event);
    int32_t OnSend(const MultimodalEvent& event);
    int32_t OnCopy(const MultimodalEvent& event);
    int32_t OnPaste(const MultimodalEvent& event);
    int32_t OnCut(const MultimodalEvent& event);
    int32_t OnUndo(const MultimodalEvent& event);
    int32_t OnRefresh(const MultimodalEvent& event);
    int32_t OnStartDrag(const MultimodalEvent& event);
    int32_t OnCancel(const MultimodalEvent& event);
    int32_t OnEnter(const MultimodalEvent& event);
    int32_t OnPrevious(const MultimodalEvent& event);
    int32_t OnNext(const MultimodalEvent& event);
    int32_t OnBack(const MultimodalEvent& event);
    int32_t OnPrint(const MultimodalEvent& event);

    int32_t OnPlay(const MultimodalEvent& event);
    int32_t OnPause(const MultimodalEvent& event);
    int32_t OnMediaControl(const MultimodalEvent& event);

    int32_t OnScreenShot(const MultimodalEvent& event);
    int32_t OnScreenSplit(const MultimodalEvent& event);
    int32_t OnStartScreenRecord(const MultimodalEvent& event);
    int32_t OnStopScreenRecord(const MultimodalEvent& event);
    int32_t OnGotoDesktop(const MultimodalEvent& event);
    int32_t OnRecent(const MultimodalEvent& event);
    int32_t OnShowNotification(const MultimodalEvent& event);
    int32_t OnLockScreen(const MultimodalEvent& event);
    int32_t OnSearch(const MultimodalEvent& event);
    int32_t OnClosePage(const MultimodalEvent& event);
    int32_t OnLaunchVoiceAssistant(const MultimodalEvent& event);
    int32_t OnMute(const MultimodalEvent& event);

    int32_t OnAnswer(const MultimodalEvent& event);
    int32_t OnRefuse(const MultimodalEvent& event);
    int32_t OnHangup(const MultimodalEvent& event);
    int32_t OnTelephoneControl(const MultimodalEvent& event);

    int32_t OnDeviceAdd(const DeviceEvent& event);
    int32_t OnDeviceRemove(const DeviceEvent& event);

protected:
    bool MakeRegisterHandle(MmiMessageId typeId, int32_t windowId, std::string& rhandle);
    bool SendMsg(NetPacket& pkt) const;

protected:
    MMIClientPtr client_ = nullptr;
    StandEventMMaps mapEvents_;
    std::set<std::string> registerEvents_;
};
}
}
#define EventManager OHOS::Singleton<OHOS::MMI::MultimodalStandardizedEventManager>::GetInstance()
#endif
