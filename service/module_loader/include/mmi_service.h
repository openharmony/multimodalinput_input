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

#ifndef MMI_SERVICE_H
#define MMI_SERVICE_H

#include <atomic>
#include <mutex>
#include <thread>

#include "iremote_object.h"
#include "singleton.h"
#include "system_ability.h"

#include "delegate_tasks.h"
#include "input_event_handler.h"
#include "multimodal_input_connect_stub.h"
#include "libinput_adapter.h"
#include "server_msg_handler.h"
#include "uds_server.h"

namespace OHOS {
namespace MMI {

enum class ServiceRunningState {STATE_NOT_START, STATE_RUNNING, STATE_EXIT};
class MMIService final : public UDSServer, public SystemAbility, public MultimodalInputConnectStub {
    DECLARE_DELAYED_SINGLETON(MMIService);
    DECLEAR_SYSTEM_ABILITY(MMIService);
    DISALLOW_COPY_AND_MOVE(MMIService);

public:
    virtual void OnStart() override;
    virtual void OnStop() override;
    int32_t Dump(int32_t fd, const std::vector<std::u16string> &args) override;
    virtual int32_t AllocSocketFd(const std::string &programName, const int32_t moduleType,
        int32_t &toReturnClientFd, int32_t &tokenType) override;
    virtual int32_t AddInputEventFilter(sptr<IEventFilter> filter) override;
    virtual int32_t SetPointerVisible(bool visible) override;
    virtual int32_t IsPointerVisible(bool &visible) override;
    virtual int32_t SetPointerSpeed(int32_t speed) override;
    virtual int32_t GetPointerSpeed(int32_t &speed) override;
    virtual int32_t SetPointerStyle(int32_t windowId, int32_t pointerStyle) override;
    virtual int32_t GetPointerStyle(int32_t windowId, int32_t &pointerStyle) override;
    virtual int32_t SupportKeys(int32_t userData, int32_t deviceId, std::vector<int32_t> &keys) override;
    virtual int32_t GetDeviceIds(int32_t userData) override;
    virtual int32_t GetDevice(int32_t userData, int32_t deviceId) override;
    virtual int32_t RegisterDevListener() override;
    virtual int32_t UnregisterDevListener() override;
    virtual int32_t GetKeyboardType(int32_t userData, int32_t deviceId) override;
    virtual int32_t AddInputHandler(InputHandlerType handlerType, HandleEventType eventType) override;
    virtual int32_t RemoveInputHandler(InputHandlerType handlerType, HandleEventType eventType) override;
    virtual int32_t MarkEventConsumed(int32_t eventId) override;
    virtual int32_t MoveMouseEvent(int32_t offsetX, int32_t offsetY) override;
    virtual int32_t InjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
    virtual int32_t SubscribeKeyEvent(int32_t subscribeId, const std::shared_ptr<KeyOption> option) override;
    virtual int32_t UnsubscribeKeyEvent(int32_t subscribeId) override;
    virtual int32_t InjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
    virtual int32_t SetAnrObserver() override;
    virtual int32_t RegisterCooperateListener() override;
    virtual int32_t UnregisterCooperateListener() override;
    virtual int32_t EnableInputDeviceCooperate(int32_t userData, bool enabled) override;
    virtual int32_t StartInputDeviceCooperate(int32_t userData, const std::string &sinkDeviceId,
        int32_t srcInputDeviceId) override;
    virtual int32_t StopDeviceCooperate(int32_t userData) override;
    virtual int32_t GetInputDeviceCooperateState(int32_t userData, const std::string &deviceId) override;
    virtual int32_t SetInputDevice(const std::string& dhid, const std::string& screenId) override;
    virtual int32_t GetFunctionKeyState(int32_t funcKey, bool &state) override;
    virtual int32_t SetFunctionKeyState(int32_t funcKey, bool enable) override;

#ifdef OHOS_RSS_CLIENT
    virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
#endif

protected:
    virtual void OnConnected(SessionPtr s) override;
    virtual void OnDisconnected(SessionPtr s) override;
    virtual int32_t AddEpoll(EpollEventType type, int32_t fd) override;
    int32_t DelEpoll(EpollEventType type, int32_t fd);
    virtual bool IsRunning() const override;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t CheckPointerVisible(bool &visible);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ReadPointerSpeed(int32_t &speed);
#endif // OHOS_BUILD_ENABLE_POINTER
    int32_t OnRegisterDevListener(int32_t pid);
    int32_t OnUnregisterDevListener(int32_t pid);
    int32_t OnGetDeviceIds(int32_t pid, int32_t userData);
    int32_t OnGetDevice(int32_t pid, int32_t userData, int32_t deviceId);
    int32_t OnSupportKeys(int32_t pid, int32_t userData, int32_t deviceId, std::vector<int32_t> &keys);
    int32_t OnGetKeyboardType(int32_t pid, int32_t userData, int32_t deviceId);
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    int32_t CheckAddInput(int32_t pid, InputHandlerType handlerType, HandleEventType eventType);
    int32_t CheckRemoveInput(int32_t pid, InputHandlerType handlerType, HandleEventType eventType);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
    int32_t CheckMarkConsumed(int32_t pid, int32_t eventId);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t CheckInjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    int32_t CheckInjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_COOPERATE
    int32_t OnRegisterCooperateListener(int32_t pid);
    int32_t OnUnregisterCooperateListener(int32_t pid);
    int32_t OnEnableInputDeviceCooperate(int32_t pid, int32_t userData, bool enabled);
    int32_t OnStartInputDeviceCooperate(int32_t pid, int32_t userData, const std::string &sinkDeviceId,
        int32_t srcInputDeviceId);
    int32_t OnStopDeviceCooperate(int32_t pid, int32_t userData);
    int32_t OnGetInputDeviceCooperateState(int32_t pid, int32_t userData, const std::string &deviceId);
#endif // OHOS_BUILD_ENABLE_COOPERATE
    bool InitLibinputService();
    bool InitService();
    bool InitSignalHandler();
    bool InitDelegateTasks();
    int32_t Init();

    void OnThread();
    void OnSignalEvent(int32_t signalFd);
    void OnDelegateTask(epoll_event& ev);

    void AddReloadDeviceTimer();

private:
    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t mmiFd_ { -1 };
    std::mutex mu_;
    std::thread t_;
#ifdef OHOS_RSS_CLIENT
    std::atomic<uint64_t> tid_ = 0;
#endif

    LibinputAdapter libinputAdapter_;
    ServerMsgHandler sMsgHandler_;
    DelegateTasks delegateTasks_;
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_SERVICE_H
