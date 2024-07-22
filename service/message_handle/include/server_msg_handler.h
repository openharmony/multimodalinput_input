/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SERVER_MSG_HANDLER_H
#define SERVER_MSG_HANDLER_H

#include "nocopyable.h"

#include "event_dispatch_handler.h"
#include "i_event_filter.h"
#include "input_handler_type.h"
#include "key_option.h"
#include "mouse_event_normalize.h"
#include "msg_handler.h"
#include "pixel_map.h"
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
#include "sec_comp_enhance_kit.h"
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
#include "window_info.h"
#include "inject_notice_manager.h"
#include "client_death_handler.h"

namespace OHOS {
namespace MMI {
enum class AuthorizationStatus : int32_t {
    UNKNOWN,
    AUTHORIZED,
    UNAUTHORIZED
};

enum class InjectionType : int32_t {
    UNKNOWN,
    KEYEVENT,
    POINTEREVENT
};

typedef std::function<int32_t(SessionPtr sess, NetPacket& pkt)> ServerMsgFun;
class ServerMsgHandler final : public MsgHandler<MmiMessageId, ServerMsgFun> {
public:
    ServerMsgHandler() = default;
    DISALLOW_COPY_AND_MOVE(ServerMsgHandler);
    ~ServerMsgHandler() override = default;

    void Init(UDSServer& udsServer);
    void OnMsgHandler(SessionPtr sess, NetPacket& pkt);
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    int32_t OnAddInputHandler(SessionPtr sess, InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags);
    int32_t OnRemoveInputHandler(SessionPtr sess, InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
#ifdef OHOS_BUILD_ENABLE_MONITOR
    int32_t OnMarkConsumed(SessionPtr sess, int32_t eventId);
#endif // OHOS_BUILD_ENABLE_MONITOR
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t OnSubscribeKeyEvent(IUdsServer *server, int32_t pid,
        int32_t subscribeId, const std::shared_ptr<KeyOption> option);
    int32_t OnUnsubscribeKeyEvent(IUdsServer *server, int32_t pid, int32_t subscribeId);
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_SWITCH
    int32_t OnSubscribeSwitchEvent(IUdsServer *server, int32_t pid, int32_t subscribeId, int32_t switchType);
    int32_t OnUnsubscribeSwitchEvent(IUdsServer *server, int32_t pid, int32_t subscribeId);
#endif // OHOS_BUILD_ENABLE_SWITCH

#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t OnMoveMouse(int32_t offsetX, int32_t offsetY);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t OnInjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent, int32_t pid, bool isNativeInject);
    int32_t OnGetFunctionKeyState(int32_t funcKey, bool &state);
    int32_t OnSetFunctionKeyState(int32_t funcKey, bool enable);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t OnInjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent, int32_t pid,
        bool isNativeInject, bool isShell);
    int32_t OnInjectPointerEventExt(const std::shared_ptr<PointerEvent> pointerEvent, bool isShell);
    int32_t SaveTargetWindowId(std::shared_ptr<PointerEvent> pointerEvent, bool isShell);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t AddInputEventFilter(sptr<IEventFilter> filter, int32_t filterId, int32_t priority, uint32_t deviceTags,
        int32_t clientPid);
    int32_t RemoveInputEventFilter(int32_t clientPid, int32_t filterId);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t SetShieldStatus(int32_t shieldMode, bool isShield);
    int32_t GetShieldStatus(int32_t shieldMode, bool &isShield);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    int32_t OnAuthorize(bool isAuthorize);
    int32_t OnCancelInjection();
    int32_t SetPixelMapData(int32_t infoId, void* pixelMap);
    bool InitInjectNoticeSource();
    bool AddInjectNotice(const InjectNoticeInfo& noticeInfo);
    int32_t OnTransferBinderClientSrv(const sptr<IRemoteObject> &binderClientObject, int32_t pid);

protected:
    int32_t OnRegisterMsgHandler(SessionPtr sess, NetPacket& pkt);
    int32_t OnDisplayInfo(SessionPtr sess, NetPacket& pkt);
    int32_t OnWindowAreaInfo(SessionPtr sess, NetPacket& pkt);
    int32_t OnWindowGroupInfo(SessionPtr sess, NetPacket &pkt);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    int32_t OnEnhanceConfig(SessionPtr sess, NetPacket& pkt);
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    void SetWindowInfo(int32_t infoId, WindowInfo &info);

private:
#ifdef OHOS_BUILD_ENABLE_TOUCH
    bool FixTargetWindowId(std::shared_ptr<PointerEvent> pointerEvent, int32_t action, bool isShell);
#endif // OHOS_BUILD_ENABLE_TOUCH
    void LaunchAbility();
    int32_t AccelerateMotion(std::shared_ptr<PointerEvent> pointerEvent);
    void UpdatePointerEvent(std::shared_ptr<PointerEvent> pointerEvent);
    void CalculateOffset(Direction direction, Offset &offset);
    bool CloseInjectNotice(int32_t pid);
    int32_t OnUiExtentionWindowInfo(NetPacket &pkt, WindowInfo& info);
private:
    UDSServer *udsServer_ { nullptr };
    std::map<int32_t, int32_t> nativeTargetWindowIds_;
    std::map<int32_t, int32_t> shellTargetWindowIds_;
    std::map<int32_t, AuthorizationStatus> authorizationCollection_;
    int32_t CurrentPID_ { -1 };
    InjectionType InjectionType_ { InjectionType::UNKNOWN };
    std::shared_ptr<KeyEvent> keyEvent_ { nullptr };
    std::shared_ptr<PointerEvent> pointerEvent_ { nullptr };
    std::map<int32_t, std::unique_ptr<Media::PixelMap>> transparentWins_;
    std::shared_ptr<InjectNoticeManager> injectNotice_ { nullptr };
    ClientDeathHandler clientDeathHandler_;
};
} // namespace MMI
} // namespace OHOS
#endif // SERVER_MSG_HANDLER_H
