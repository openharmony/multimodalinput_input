/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef COOPERATE_CONTEXT_H
#define COOPERATE_CONTEXT_H

#include "event_handler.h"
#include "nocopyable.h"

#ifdef ENABLE_PERFORMANCE_CHECK
#include <chrono>
#include <mutex>
#endif // ENABLE_PERFORMANCE_CHECK

#include "common_event_adapter.h"
#include "common_event_observer.h"
#include "cooperate_events.h"
#include "ddm_adapter.h"
#include "dsoftbus_handler.h"
#include "event_manager.h"
#include "hot_area.h"
#include "input_device_mgr.h"
#include "input_event_transmission/input_event_builder.h"
#include "input_event_transmission/input_event_interceptor.h"
#include "i_context.h"
#include "mouse_location.h"

namespace OHOS {
namespace Msdp {
namespace DeviceStatus {
namespace Cooperate {
class Context final {
public:
    Context(IContext *env);
    ~Context() = default;
    DISALLOW_COPY_AND_MOVE(Context);

    void AttachSender(Channel<CooperateEvent>::Sender sender);
    void AddObserver(std::shared_ptr<ICooperateObserver> observer);
    void RemoveObserver(std::shared_ptr<ICooperateObserver> observer);
    void Enable();
    void Disable();

    Channel<CooperateEvent>::Sender Sender() const;
    std::shared_ptr<AppExecFwk::EventHandler> EventHandler() const;
    std::string Local() const;
    std::string Peer() const;
    int32_t StartDeviceId() const;
    Coordinate CursorPosition() const;
    NormalizedCoordinate NormalizedCursorPosition() const;
    uint32_t CooperateFlag() const;

    bool IsLocal(const std::string &networkId) const;
    bool IsPeer(const std::string &networkId) const;
    bool NeedHideCursor() const;

    void EnableCooperate(const EnableCooperateEvent &event);
    void DisableCooperate(const DisableCooperateEvent &event);
    void StartCooperate(const StartCooperateEvent &event);
    void RemoteStartSuccess(const DSoftbusStartCooperateFinished &event);
    void RelayCooperate(const DSoftbusRelayCooperate &event);
    void OnPointerEvent(const InputPointerEvent &event);
    void UpdateCooperateFlag(const UpdateCooperateFlagEvent &event);
    void UpdateCursorPosition();
    void ResetCursorPosition();

    bool IsAllowCooperate();
    void OnStartCooperate(StartCooperateData &data);
    void OnRemoteStartCooperate(RemoteStartCooperateData &data);
    void OnTransitionOut();
    void OnTransitionIn();
    void OnBack();
    void OnRelayCooperation(const std::string &networkId, const NormalizedCoordinate &cursorPos);
    void OnResetCooperation();
    void CloseDistributedFileConnection(const std::string &remoteNetworkId);

#ifdef ENABLE_PERFORMANCE_CHECK
    void StartTrace(const std::string &name);
    void FinishTrace(const std::string &name);
#endif // ENABLE_PERFORMANCE_CHECK

    DDMAdapter ddm_;
    DSoftbusHandler dsoftbus_;
    EventManager eventMgr_;
    HotArea hotArea_;
    MouseLocation mouseLocation_;
    InputDeviceMgr inputDevMgr_;
    InputEventBuilder inputEventBuilder_;
    InputEventInterceptor inputEventInterceptor_;
    CommonEventAdapter commonEvent_;

private:
    int32_t StartEventHandler();
    void StopEventHandler();
    int32_t EnableDDM();
    void DisableDDM();
    int32_t EnableDevMgr();
    void DisableDevMgr();
    int32_t EnableInputDevMgr();
    void DisableInputDevMgr();
    void SetCursorPosition(const Coordinate &cursorPos);

    IContext *env_ { nullptr };
    Channel<CooperateEvent>::Sender sender_;
    std::string remoteNetworkId_;
    int32_t startDeviceId_ { -1 };
    uint32_t flag_ {};
    Coordinate cursorPos_ {};
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_;
    std::shared_ptr<IBoardObserver> boardObserver_;
    std::shared_ptr<IDeviceObserver> hotplugObserver_;
    std::set<std::shared_ptr<ICooperateObserver>> observers_;

#ifdef ENABLE_PERFORMANCE_CHECK
    std::mutex lock_;
    std::map<std::string, std::chrono::time_point<std::chrono::steady_clock>> traces_;
#endif // ENABLE_PERFORMANCE_CHECK
};

inline Channel<CooperateEvent>::Sender Context::Sender() const
{
    return sender_;
}

inline std::shared_ptr<AppExecFwk::EventHandler> Context::EventHandler() const
{
    return eventHandler_;
}

inline std::string Context::Local() const
{
    return DSoftbusHandler::GetLocalNetworkId();
}

inline std::string Context::Peer() const
{
    return remoteNetworkId_;
}

inline int32_t Context::StartDeviceId() const
{
    return startDeviceId_;
}

inline Coordinate Context::CursorPosition() const
{
    return cursorPos_;
}

inline uint32_t Context::CooperateFlag() const
{
    return flag_;
}

inline bool Context::IsLocal(const std::string &networkId) const
{
    return (networkId == DSoftbusHandler::GetLocalNetworkId());
}

inline bool Context::IsPeer(const std::string &networkId) const
{
    return (networkId == remoteNetworkId_);
}

inline bool Context::NeedHideCursor() const
{
    return (flag_ & COOPERATE_FLAG_HIDE_CURSOR);
}
} // namespace Cooperate
} // namespace DeviceStatus
} // namespace Msdp
} // namespace OHOS
#endif // COOPERATE_CONTEXT_H
