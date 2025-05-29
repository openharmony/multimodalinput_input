/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef MMI_SERVICE_H
#define MMI_SERVICE_H

#include <system_ability_definition.h>
#include "system_ability.h"

#include "app_debug_listener.h"
#include "cJSON.h"
#include "input_event_handler.h"
#ifndef OHOS_BUILD_ENABLE_WATCH
#include "knuckle_drawing_manager.h"
#endif // OHOS_BUILD_ENABLE_WATCH
#include "libinput_adapter.h"
#include "multimodal_input_connect_stub.h"
#include "server_msg_handler.h"
#include "input_device_consumer_handler.h"

namespace OHOS {
namespace MMI {
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
class TouchGestureManager;
#endif // defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)

struct JsonParser {
    JsonParser() = default;
    ~JsonParser()
    {
        if (json_ != nullptr) {
            cJSON_Delete(json_);
        }
    }
    operator cJSON *()
    {
        return json_;
    }
    cJSON *json_ { nullptr };
};

struct DeviceConsumer {
    std::string name {};
    std::vector<int32_t> uids {};
};

struct ConsumersData {
    std::vector<DeviceConsumer> consumers {};
};

enum class ServiceRunningState {STATE_NOT_START, STATE_RUNNING, STATE_EXIT};
class MMIService final : public UDSServer, public SystemAbility, public MultimodalInputConnectStub {
    DECLARE_SYSTEM_ABILITY(MMIService);

public:
    static constexpr int32_t INVALID_SOCKET_FD = -1;
    static constexpr int32_t MULTIMODAL_INPUT_CONNECT_SERVICE_ID = MULTIMODAL_INPUT_SERVICE_ID;
    void OnStart() override;
    void OnStop() override;
    static MMIService* GetInstance();
    int32_t Dump(int32_t fd, const std::vector<std::u16string> &args) override;
    ErrCode AllocSocketFd(const std::string &programName, const int32_t moduleType,
        int32_t &toReturnClientFd, int32_t &tokenType) override;
    ErrCode AddInputEventFilter(const sptr<IEventFilter>& filter, int32_t filterId, int32_t priority,
        uint32_t deviceTags) override;
    ErrCode RemoveInputEventFilter(int32_t filterId) override;
    ErrCode SetPointerSize(int32_t size) override;
    ErrCode GetPointerSize(int32_t &size) override;
    ErrCode GetCursorSurfaceId(uint64_t &surfaceId) override;
    ErrCode SetMouseScrollRows(int32_t rows) override;
    ErrCode GetMouseScrollRows(int32_t &rows) override;
    ErrCode SetCustomCursorPixelMap(int32_t windowId, int32_t focusX, int32_t focusY,
        const CursorPixelMap& curPixelMap) override;
    ErrCode SetCustomCursor(int32_t windowId,
        const CustomCursorParcel& curParcel, const CursorOptionsParcel& cOptionParcel) override;
    ErrCode SetMouseIcon(int32_t windowId, const CursorPixelMap& curPixelMap) override;
    ErrCode ClearWindowPointerStyle(int32_t pid, int32_t windowId) override;
    ErrCode SetMouseHotSpot(int32_t pid, int32_t windowId, int32_t hotSpotX, int32_t hotSpotY) override;
    ErrCode SetNapStatus(int32_t pid, int32_t uid, const std::string& bundleName, int32_t napStatus) override;
    ErrCode SetMousePrimaryButton(int32_t primaryButton) override;
    ErrCode GetMousePrimaryButton(int32_t &primaryButton) override;
    ErrCode SetHoverScrollState(bool state) override;
    ErrCode GetHoverScrollState(bool &state) override;
    ErrCode SetPointerVisible(bool visible, int32_t priority) override;
    ErrCode IsPointerVisible(bool &visible) override;
    ErrCode MarkProcessed(int32_t eventType, int32_t eventId) override;
    ErrCode SetPointerColor(int32_t color) override;
    ErrCode GetPointerColor(int32_t &color) override;
    ErrCode EnableCombineKey(bool enable) override;
    ErrCode SetPointerSpeed(int32_t speed) override;
    ErrCode GetPointerSpeed(int32_t &speed) override;
    ErrCode SetPointerStyle(int32_t windowId, const PointerStyle& pointerStyle, bool isUiExtension = false) override;
    ErrCode NotifyNapOnline() override;
    ErrCode RemoveInputEventObserver() override;
    ErrCode GetPointerStyle(int32_t windowId, PointerStyle& pointerStyle, bool isUiExtension = false) override;
    ErrCode SupportKeys(int32_t deviceId, const std::vector<int32_t>& keys, std::vector<bool>& keystroke) override;
    ErrCode GetDeviceIds(std::vector<int32_t> &ids) override;
    ErrCode GetDevice(int32_t deviceId, InputDevice& inputDevice) override;
    ErrCode RegisterDevListener() override;
    ErrCode UnregisterDevListener() override;
    ErrCode GetKeyboardType(int32_t deviceId, int32_t &keyboardType) override;
    ErrCode SetKeyboardRepeatDelay(int32_t delay) override;
    ErrCode SetKeyboardRepeatRate(int32_t rate) override;
    ErrCode GetKeyboardRepeatDelay(int32_t &delay) override;
    ErrCode GetKeyboardRepeatRate(int32_t &rate) override;
    ErrCode AddInputHandler(int32_t handlerType, uint32_t eventType, int32_t priority, uint32_t deviceTags,
        const std::vector<int32_t>& actionsType = std::vector<int32_t>()) override;
    ErrCode RemoveInputHandler(int32_t handlerType, uint32_t eventType, int32_t priority, uint32_t deviceTags,
        const std::vector<int32_t>& actionsType = std::vector<int32_t>()) override;
    ErrCode AddPreInputHandler(int32_t handlerId, uint32_t eventType, const std::vector<int32_t>& keys) override;
    ErrCode RemovePreInputHandler(int32_t handlerId) override;
    ErrCode AddGestureMonitor(int32_t handlerType, uint32_t eventType, uint32_t gestureType, int32_t fingers) override;
    ErrCode RemoveGestureMonitor(int32_t handlerType, uint32_t eventType,
        uint32_t gestureType, int32_t fingers) override;
    ErrCode MarkEventConsumed(int32_t eventId) override;
    ErrCode MoveMouseEvent(int32_t offsetX, int32_t offsetY) override;
    ErrCode InjectKeyEvent(const KeyEvent& keyEvent, bool isNativeInject) override;
    ErrCode SubscribeKeyEvent(int32_t subscribeId, const KeyOption& keyOption) override;
    ErrCode UnsubscribeKeyEvent(int32_t subscribeId) override;
    ErrCode SubscribeHotkey(int32_t subscribeId, const KeyOption& keyOption) override;
    ErrCode UnsubscribeHotkey(int32_t subscribeId) override;
#ifdef OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
    ErrCode SubscribeKeyMonitor(const KeyMonitorOption &keyOption) override;
    ErrCode UnsubscribeKeyMonitor(const KeyMonitorOption &keyOption) override;
#endif // OHOS_BUILD_ENABLE_KEY_PRESSED_HANDLER
    ErrCode SubscribeSwitchEvent(int32_t subscribeId, int32_t switchType) override;
    ErrCode UnsubscribeSwitchEvent(int32_t subscribeId) override;
    ErrCode QuerySwitchStatus(int32_t switchType, int32_t& state) override;
    ErrCode SubscribeTabletProximity(int32_t subscribeId) override;
    ErrCode UnsubscribetabletProximity(int32_t subscribeId) override;
    ErrCode SubscribeLongPressEvent(int32_t subscribeId, const LongPressRequest &longPressRequest) override;
    ErrCode UnsubscribeLongPressEvent(int32_t subscribeId) override;
    ErrCode InjectPointerEvent(const PointerEvent& pointerEvent, bool isNativeInject) override;
    ErrCode InjectTouchPadEvent(const PointerEvent& pointerEvent, const TouchpadCDG& touchpadCDG,
        bool isNativeInject) override;
    ErrCode SetAnrObserver() override;
    ErrCode GetDisplayBindInfo(std::vector<DisplayBindInfo>& infos) override;
    ErrCode GetAllMmiSubscribedEvents(MmiEventMap& mmiEventMap) override;
    ErrCode SetDisplayBind(int32_t deviceId, int32_t displayId, std::string &msg) override;
    ErrCode GetFunctionKeyState(int32_t funcKey, bool &state) override;
    ErrCode SetFunctionKeyState(int32_t funcKey, bool enable) override;
    ErrCode SetPointerLocation(int32_t x, int32_t y, int32_t displayId) override;
    ErrCode SetMouseCaptureMode(int32_t windowId, bool isCaptureMode) override;
    ErrCode GetWindowPid(int32_t windowId, int32_t &windowPid) override;
    ErrCode AppendExtraData(const ExtraData &extraData) override;
    ErrCode EnableInputDevice(bool enable) override;
    ErrCode SetKeyDownDuration(const std::string &businessId, int32_t delay) override;
    ErrCode SetTouchpadScrollSwitch(bool switchFlag) override;
    ErrCode GetTouchpadScrollSwitch(bool &switchFlag) override;
    ErrCode SetTouchpadScrollDirection(bool state) override;
    ErrCode GetTouchpadScrollDirection(bool &state) override;
    ErrCode SetTouchpadTapSwitch(bool switchFlag) override;
    ErrCode GetTouchpadTapSwitch(bool &switchFlag) override;
    ErrCode SetTouchpadPointerSpeed(int32_t speed) override;
    ErrCode GetTouchpadPointerSpeed(int32_t &speed) override;
    ErrCode GetTouchpadCDG(TouchpadCDG &touchpadCDG) override;
    ErrCode SetTouchpadPinchSwitch(bool switchFlag) override;
    ErrCode GetTouchpadPinchSwitch(bool &switchFlag) override;
    ErrCode SetTouchpadSwipeSwitch(bool switchFlag) override;
    ErrCode GetTouchpadSwipeSwitch(bool &switchFlag) override;
    ErrCode SetTouchpadRightClickType(int32_t type) override;
    ErrCode GetTouchpadRightClickType(int32_t &type) override;
    ErrCode SetTouchpadRotateSwitch(bool rotateSwitch) override;
    ErrCode GetTouchpadRotateSwitch(bool &rotateSwitch) override;
    ErrCode SetTouchpadDoubleTapAndDragState(bool switchFlag) override;
    ErrCode GetTouchpadDoubleTapAndDragState(bool &switchFlag) override;
    ErrCode SetShieldStatus(int32_t shieldMode, bool isShield) override;
    ErrCode GetShieldStatus(int32_t shieldMode, bool &isShield) override;
    ErrCode GetKeyState(std::vector<int32_t>& pressedKeys,
        std::unordered_map<int32_t, int32_t>& specialKeysState) override;
    ErrCode Authorize(bool isAuthorize) override;
    ErrCode CancelInjection() override;
    ErrCode SetMoveEventFilters(bool flag) override;
#ifdef OHOS_RSS_CLIENT
    void OnAddResSchedSystemAbility(int32_t systemAbilityId, const std::string &deviceId);
#endif // OHOS_RSS_CLIENT
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    ErrCode HasIrEmitter(bool &hasIrEmitter) override;
    ErrCode GetInfraredFrequencies(std::vector<InfraredFrequency>& frequencies) override;
    ErrCode TransmitInfrared(int64_t number, const std::vector<int64_t>& pattern) override;
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    ErrCode CreateVKeyboardDevice(sptr<IRemoteObject> &vkeyboardDevice) override;
    int32_t OnCreateVKeyboardDevice(sptr<IRemoteObject> &vkeyboardDevice);
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    int32_t OnHasIrEmitter(bool &hasIrEmitter);
    ErrCode SetPixelMapData(int32_t infoId, const CursorPixelMap& curPixelMap) override;
    ErrCode SetCurrentUser(int32_t userId) override;
    ErrCode SetTouchpadThreeFingersTapSwitch(bool switchFlag) override;
    ErrCode GetTouchpadThreeFingersTapSwitch(bool &switchFlag) override;
    ErrCode AddVirtualInputDevice(const InputDevice& device, int32_t& deviceId) override;
    ErrCode RemoveVirtualInputDevice(int32_t deviceId) override;
    ErrCode EnableHardwareCursorStats(bool enable) override;
    ErrCode GetHardwareCursorStats(uint32_t &frameCount, uint32_t &vsyncCount) override;
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
    ErrCode GetPointerSnapshot(CursorPixelMap& pixelMap) override;
#endif // OHOS_BUILD_ENABLE_MAGICCURSOR
    ErrCode TransferBinderClientSrv(const sptr<IRemoteObject> &binderClientObject) override;
    ErrCode SetTouchpadScrollRows(int32_t rows) override;
    ErrCode GetTouchpadScrollRows(int32_t &rows) override;
    ErrCode SkipPointerLayer(bool isSkip) override;
    void CalculateFuntionRunningTime(std::function<void()> func, const std::string &flag);
    ErrCode SetClientInfo(int32_t pid, uint64_t readThreadId) override;
    ErrCode GetIntervalSinceLastInput(int64_t &timeInterval) override;
#ifdef OHOS_BUILD_ENABLE_ANCO
    void InitAncoUds();
    void StopAncoUds();
    int32_t InjectKeyEventExt(const std::shared_ptr<KeyEvent> keyEvent, int32_t pid, bool isNativeInject);
    int32_t InjectPointerEventExt(const std::shared_ptr<PointerEvent> pointerEvent, int32_t pid,
        bool isNativeInject, bool isShell);
    ErrCode AncoAddChannel(const sptr<IAncoChannel>& channel) override;
    ErrCode AncoRemoveChannel(const sptr<IAncoChannel>& channel) override;
    ErrCode CheckKnuckleEvent(float pointX, float pointY, bool &isKnuckleType) override;
    int32_t SyncKnuckleStatus();
#endif // OHOS_BUILD_ENABLE_ANCO
#if defined(OHOS_BUILD_ENABLE_MONITOR) && defined(PLAYER_FRAMEWORK_EXISTS)
    static void ScreenCaptureCallback(int32_t pid, bool isStart);
    void RegisterScreenCaptureCallback();
#endif // OHOS_BUILD_ENABLE_MONITOR && PLAYER_FRAMEWORK_EXISTS

    int32_t OnGetAllSystemHotkey(std::vector<std::unique_ptr<KeyOption>> &keyOptions);
    ErrCode GetAllSystemHotkeys(std::vector<KeyOption>& keyOptions) override;
    ErrCode SetInputDeviceEnabled(int32_t deviceId, bool enable, int32_t index) override;
    ErrCode ShiftAppPointerEvent(const ShiftWindowParam &param, bool autoGenDown) override;
    ErrCode SetMultiWindowScreenId(uint64_t screenId, uint64_t displayNodeScreenId) override;
    int32_t SetMultiWindowScreenIdInner(uint64_t screenId, uint64_t displayNodeScreenId);
    ErrCode SetKnuckleSwitch(bool knuckleSwitch) override;
    ErrCode LaunchAiScreenAbility() override;
    ErrCode GetMaxMultiTouchPointNum(int32_t &pointNum) override;
    ErrCode SubscribeInputActive(int32_t subscribeId, int64_t interval) override;
    ErrCode UnsubscribeInputActive(int32_t subscribeId) override;
    ErrCode SwitchTouchTracking(bool touchTracking) override;
    ErrCode SetMouseAccelerateMotionSwitch(int32_t deviceId, bool enable) override;
    ErrCode SwitchScreenCapturePermission(uint32_t permissionType, bool enable) override;

protected:
    void OnConnected(SessionPtr s) override;
    void OnDisconnected(SessionPtr s) override;
    int32_t AddEpoll(EpollEventType type, int32_t fd, bool readOnly = false) override;
    int32_t DelEpoll(EpollEventType type, int32_t fd);
    bool IsRunning() const;
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    int32_t CheckPointerVisible(bool &visible);
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
#ifdef OHOS_BUILD_ENABLE_POINTER
    int32_t ReadMouseScrollRows(int32_t &rows);
    int32_t ReadPointerSize(int32_t &size);
    int32_t ReadMousePrimaryButton(int32_t &primaryButton);
    int32_t ReadPointerSpeed(int32_t &speed);
    int32_t ReadHoverScrollState(bool &state);
    int32_t ReadPointerColor(int32_t &color);
    int32_t ReadTouchpadScrollSwich(bool &switchFlag);
    int32_t ReadTouchpadScrollDirection(bool &state);
    int32_t ReadTouchpadTapSwitch(bool &switchFlag);
    int32_t ReadTouchpadPointerSpeed(int32_t &speed);
    int32_t ReadTouchpadCDG(TouchpadCDG &touchpadCDG);
    int32_t ReadTouchpadPinchSwitch(bool &switchFlag);
    int32_t ReadTouchpadSwipeSwitch(bool &switchFlag);
    int32_t ReadTouchpadRightMenuType(int32_t &type);
    int32_t ReadTouchpadRotateSwitch(bool &rotateSwitch);
    int32_t ReadTouchpadDoubleTapAndDragState(bool &switchFlag);
    int32_t ReadTouchpadScrollRows(int32_t &rows);
#endif // OHOS_BUILD_ENABLE_POINTER
    int32_t OnRegisterDevListener(int32_t pid);
    int32_t OnUnregisterDevListener(int32_t pid);
    int32_t OnGetDeviceIds(std::vector<int32_t> &ids);
    int32_t OnGetDevice(int32_t deviceId, std::shared_ptr<InputDevice> inputDevice);
    int32_t OnSupportKeys(int32_t deviceId, std::vector<int32_t> &keys, std::vector<bool> &keystroke);
    int32_t OnGetKeyboardType(int32_t deviceId, int32_t &keyboardType);
    int32_t OnGetWindowPid(int32_t windowId, int32_t &windowPid);
#if defined(OHOS_BUILD_ENABLE_INTERCEPTOR) || defined(OHOS_BUILD_ENABLE_MONITOR)
    int32_t CheckAddInput(int32_t pid, InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags);
    int32_t CheckRemoveInput(int32_t pid, InputHandlerType handlerType, HandleEventType eventType,
        int32_t priority, uint32_t deviceTags);
    int32_t ObserverAddInputHandler(int32_t pid);
#endif // OHOS_BUILD_ENABLE_INTERCEPTOR || OHOS_BUILD_ENABLE_MONITOR
    int32_t CheckMarkConsumed(int32_t pid, int32_t eventId);
    int32_t CheckInjectKeyEvent(const std::shared_ptr<KeyEvent> keyEvent, int32_t pid, bool isNativeInject);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    int32_t OnGetKeyState(std::vector<int32_t> &pressedKeys, std::unordered_map<int32_t, int32_t> &specialKeysState);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
    int32_t CheckInjectPointerEvent(const std::shared_ptr<PointerEvent> pointerEvent,
        int32_t pid, bool isNativeInject, bool isShell);
    int32_t CheckTouchPadEvent(const std::shared_ptr<PointerEvent> pointerEvent,
        int32_t pid, const TouchpadCDG &touchpadCDG, bool isNativeInject, bool isShell);
    bool InitLibinputService();
    bool InitService();
    bool InitSignalHandler();
    bool InitDelegateTasks();
    int32_t Init();
    void InitPreferences();
#ifdef OHOS_BUILD_PC_PRIORITY
    void SetMmiServicePriority(int32_t tid);
#endif // OHOS_BUILD_PC_PRIORITY
    void OnThread();
    void PreEventLoop();
    void OnSignalEvent(int32_t signalFd);
    void OnDelegateTask(epoll_event& ev);

    void AddReloadDeviceTimer();
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_COMBINATION_KEY)
    int32_t UpdateSettingsXml(const std::string &businessId, int32_t delay);
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_COMBINATION_KEY
    void AddAppDebugListener();
    void RemoveAppDebugListener();
#if defined(OHOS_BUILD_ENABLE_KEYBOARD) && defined(OHOS_BUILD_ENABLE_COMBINATION_KEY)
    int32_t UpdateCombineKeyState(bool enable);
#endif // OHOS_BUILD_ENABLE_KEYBOARD && OHOS_BUILD_ENABLE_COMBINATION_KEY
    int32_t OnAuthorize(bool isAuthorize);
    int32_t OnCancelInjection(int32_t callPid = 0);
    void InitPrintClientInfo();
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    void InitVKeyboardFuncHandler();
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
    int32_t SetInputDeviceEnable(int32_t deviceId, bool enable, int32_t index, int32_t pid, SessionPtr sess);
    ErrCode SetInputDeviceConsumer(const std::vector<std::string>& deviceNames) override;
    ErrCode ClearInputDeviceConsumer(const std::vector<std::string>& deviceNames) override;
private:
    MMIService();
    ~MMIService();

    int32_t CheckPidPermission(int32_t pid);
    void PrintLog(const std::string &flag, int32_t duration, int32_t pid, int32_t tid);
    void OnSessionDelete(SessionPtr session);
    bool IsValidType(int32_t type);
    int32_t CheckInputHandlerVaild(InputHandlerType handlerType);
    int32_t CheckRemoveInputHandlerVaild(InputHandlerType handlerType);
    void DealConsumers(std::vector<std::string>& filterNames, const DeviceConsumer &consumer);
    std::vector<std::string> FilterConsumers(const std::vector<std::string> &deviceNames);
    void UpdateConsumers(const cJSON* consumer);
    bool ParseDeviceConsumerConfig();
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    void SetupTouchGestureHandler();
#endif // defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    void OnRemoveAccessibility();

    std::atomic<ServiceRunningState> state_ = ServiceRunningState::STATE_NOT_START;
    int32_t mmiFd_ { -1 };
    std::atomic<bool> isCesStart_ { false };
    std::mutex mu_;
    std::thread t_;
    std::thread eventMonitorThread_;
    ConsumersData consumersData_;
#ifdef OHOS_BUILD_ENABLE_ANCO
    int32_t shellAssitentPid_ { -1 };
#endif // OHOS_BUILD_ENABLE_ANCO
#ifdef OHOS_RSS_CLIENT
    std::atomic<uint64_t> tid_ = 0;
#endif // OHOS_RSS_CLIENT
    LibinputAdapter libinputAdapter_;
    ServerMsgHandler sMsgHandler_;
    DelegateTasks delegateTasks_;
#if defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    std::shared_ptr<TouchGestureManager> touchGestureMgr_ { nullptr };
#endif // defined(OHOS_BUILD_ENABLE_TOUCH) && defined(OHOS_BUILD_ENABLE_MONITOR)
    std::shared_ptr<DelegateInterface> delegateInterface_ { nullptr };
    sptr<AppDebugListener> appDebugListener_;
    std::atomic_bool threadStatusFlag_ { false };
    struct ClientInfo {
        int32_t pid { -1 };
        uint64_t readThreadId { -1 };
    };
    std::map<std::string, ClientInfo> clientInfos_;
    std::mutex mutex_;
#if defined(OHOS_BUILD_ENABLE_MONITOR) && defined(PLAYER_FRAMEWORK_EXISTS)
    bool hasRegisterListener_ { false };
#endif // OHOS_BUILD_ENABLE_MONITOR && PLAYER_FRAMEWORK_EXISTS
#ifdef OHOS_BUILD_ENABLE_VKEYBOARD
    std::atomic_bool isHPR_ { false };
#endif // OHOS_BUILD_ENABLE_VKEYBOARD
#ifndef OHOS_BUILD_ENABLE_WATCH
    std::shared_ptr<KnuckleDrawingManager> knuckleDrawMgr_ { nullptr };
#endif // OHOS_BUILD_ENABLE_WATCH
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_SERVICE_H
