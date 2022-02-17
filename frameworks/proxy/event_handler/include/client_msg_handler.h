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
#ifndef CLIENT_MSG_HANDLER_H
#define CLIENT_MSG_HANDLER_H

#include "if_client_msg_handler.h"
#include "key_event_input_subscribe_manager.h"
#include "msg_handler.h"
#include "uds_client.h"
#include "multimodal_event.h"

namespace OHOS {
namespace MMI {
typedef std::function<int32_t(const UDSClient&, NetPacket&)> ClientMsgFun;
static const bool fSkipId = false;
class ClientMsgHandler : public MsgHandler<ClientMsgFun>,
    public IfClientMsgHandler, public std::enable_shared_from_this<IfClientMsgHandler> {
public:
    ClientMsgHandler();
    virtual ~ClientMsgHandler();
    virtual bool Init() override;
    virtual void OnMsgHandler(const UDSClient& client, NetPacket& pkt) override;

protected:
    virtual int32_t OnKey(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnKeyEvent(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnKeyMonitor(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnTouchPadMonitor(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnPointerEvent(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnSubscribeKeyEventCallback(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnTouch(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnCopy(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnShowMenu(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnSend(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnPaste(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnCut(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnUndo(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnRefresh(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnStartDrag(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnCancel(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnEnter(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnPrevious(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnNext(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnBack(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnPrint(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnPlay(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnPause(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnMediaControl(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnScreenShot(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnScreenSplit(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnStartScreenRecord(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnStopScreenRecord(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnGotoDesktop(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnRecent(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnShowNotification(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnLockScreen(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnSearch(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnClosePage(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnLaunchVoiceAssistant(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnMute(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnAnswer(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnRefuse(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnHangup(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnTelephoneControl(const UDSClient& client, NetPacket& pkt);
    virtual int32_t GetMultimodeInputInfo(const UDSClient& client, NetPacket& pkt);
    virtual int32_t DeviceAdd(const UDSClient& client, NetPacket& pkt);
    virtual int32_t DeviceRemove(const UDSClient& client, NetPacket& pkt);
    virtual int32_t KeyEventFilter(const UDSClient& client, NetPacket& pkt);
    virtual int32_t TouchEventFilter(const UDSClient& client, NetPacket& pkt);
    virtual int32_t PointerEventInterceptor(const UDSClient& client, NetPacket& pkt);
    virtual int32_t ReportKeyEvent(const UDSClient& client, NetPacket& pkt);
    virtual int32_t ReportPointerEvent(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnInputDevice(const UDSClient& client, NetPacket& pkt);
    virtual int32_t OnInputDeviceIds(const UDSClient& client, NetPacket& pkt);
    virtual int32_t TouchpadEventInterceptor(const UDSClient& client, NetPacket& pkt);
    virtual int32_t KeyEventInterceptor(const UDSClient& client, NetPacket& pkt);

private:
    int32_t PackedData(const UDSClient& client, NetPacket& pkt, const std::string& funName, MultimodalEvent& multe);
    void AnalysisPointEvent(const UDSClient& client, NetPacket& pkt) const;
    void AnalysisTouchEvent(const UDSClient& client, NetPacket& pkt) const;
    void AnalysisJoystickEvent(const UDSClient& client, NetPacket& pkt) const;
    void AnalysisTouchPadEvent(const UDSClient& client, NetPacket& pkt) const;
    void GetStandardStylusActionType(int32_t curRventType, int32_t &stylusAction, int32_t &touchAction) const;
    int32_t GetNonStandardStylusActionType(int32_t tableToolState) const;
    void GetMouseActionType(int32_t eventType, int32_t proximityState, int32_t &mouseAction,
                            int32_t &touchAction) const;
    void PrintEventTabletToolInfo(EventTabletTool tableTool, uint64_t serverStartTime,
                                  int32_t abilityId, int32_t windowId, int32_t fd) const;
    void AnalysisStandardTabletToolEvent(NetPacket& pkt, int32_t curRventType, EventTabletTool tableTool,
                                         int32_t windowId) const;
    void AnalysisTabletToolEvent(const UDSClient& client, NetPacket& pkt) const;
    void AnalysisGestureEvent(const UDSClient& client, NetPacket& pkt) const;
    static void OnEventProcessed(int32_t eventId);

private:
    bool isServerReqireStMessage_ = true;
    std::function<void(int32_t)> eventProcessedCallback_;
};
} // namespace MMI
} // namespace OHOS
#endif // CLIENT_MSG_HANDLER_H