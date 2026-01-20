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

#ifndef KEY_COMMAND_HANDLER_H
#define KEY_COMMAND_HANDLER_H

#include "old_display_info.h"

#include "i_input_event_handler.h"
#include "input_handler_type.h"
#include <mutex>

#include "i_key_command_service.h"
#include "short_key_handler.h"
#include "sequence_key_handler.h"
#include "repeat_key_handler.h"
#include "key_command_context.h"
#include "key_command_types.h"
#include "key_config_parser.h"
#include "two_finger_gesture_handler.h"

namespace OHOS {
namespace MMI {
using MistouchPreventionCallbackFunc = std::function<void(int32_t)>;
class IMistouchPrevention  {
public:
    IMistouchPrevention() = default;
    virtual ~IMistouchPrevention() = default;

    virtual int32_t MistouchPreventionConnector(MistouchPreventionCallbackFunc callbackFunc) = 0;

    virtual int32_t MistouchPreventionClose() = 0;
};

class KeyCommandHandler final : public IInputEventHandler,
                                public std::enable_shared_from_this<KeyCommandHandler>,
                                public IKeyCommandService { // 实现这个接口，共享的方法放在接口中
public:
    friend class KnuckleContextImpl;
    KeyCommandHandler();
    DISALLOW_COPY_AND_MOVE(KeyCommandHandler);
    ~KeyCommandHandler() override;
    int32_t UpdateSettingsXml(const std::string &businessId, int32_t delay);
    int32_t EnableCombineKey(bool enable);
    void Dump(int32_t fd, const std::vector<std::string> &args);
    void PrintGestureInfo(int32_t fd);
    std::string ConvertKeyActionToString(int32_t keyAction);
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    void HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent) override;
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#ifdef OHOS_BUILD_ENABLE_POINTER
    void HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
#endif // OHOS_BUILD_ENABLE_POINTER
#ifdef OHOS_BUILD_ENABLE_TOUCH
    void HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent) override;
    void HandlePointerActionDownEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void HandlePointerActionUpEvent(const std::shared_ptr<PointerEvent> touchEvent);
#endif // OHOS_BUILD_ENABLE_TOUCH
#ifdef OHOS_BUILD_ENABLE_KEYBOARD
    bool OnHandleEvent(const std::shared_ptr<KeyEvent> keyEvent);
    int32_t SetIsFreezePowerKey(const std::string pageName);
#endif // OHOS_BUILD_ENABLE_KEYBOARD
#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
    bool OnHandleEvent(const std::shared_ptr<PointerEvent> pointerEvent);
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH
    void InitKeyObserver();
    bool PreHandleEvent();
    void RegisterProximitySensor();
    void UnregisterProximitySensor();
    int32_t LaunchAiScreenAbility(int32_t pid);
    int32_t SwitchScreenCapturePermission(uint32_t permissionType, bool enable);
#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    void UnregisterMistouchPrevention() override;
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    uint32_t GetScreenCapturePermission() override;

private:
    bool ParseKnuckleConfig();
    bool ParseKnuckleJson(const std::string &configFile);
    void ParseRepeatKeyMaxCount();
    void ParseStatusConfigObserver();
    bool PreHandleEvent(const std::shared_ptr<KeyEvent> key);
    bool HandleEvent(const std::shared_ptr<KeyEvent> key);
    bool HandleMulFingersTap(const std::shared_ptr<PointerEvent> pointerEvent);
    bool IsEnableCombineKey(const std::shared_ptr<KeyEvent> key);
    bool IsExcludeKey(const std::shared_ptr<KeyEvent> key);
    void HandleSpecialKeys(int32_t keyCode, int32_t keyAction) override;
    void HandlePointerVisibleKeys(const std::shared_ptr<KeyEvent> &keyEvent);

    template <class T>
    void CreateStatusConfigObserver(T& item);

#ifdef OHOS_BUILD_ENABLE_TOUCH
    void OnHandleTouchEvent(const std::shared_ptr<PointerEvent> touchEvent);
    void InitializeLongPressConfigurations();
#endif // OHOS_BUILD_ENABLE_TOUCH
    bool TouchPadKnuckleDoubleClickHandle(std::shared_ptr<KeyEvent> event);
    void TouchPadKnuckleDoubleClickProcess(const std::string bundleName, const std::string abilityName,
        const std::string action);
    void SendNotSupportMsg(std::shared_ptr<PointerEvent> touchEvent);
    bool CheckBundleName(const std::shared_ptr<PointerEvent> touchEvent);
    bool HasScreenCapturePermission(uint32_t permissionType) override;
#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    void CallMistouchPrevention() override;
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    void InitParse();
    void InitParse(const std::string funcName, const std::shared_ptr<KeyEvent> key);
    void InitExcludeParse(const std::string funcName, const std::shared_ptr<KeyEvent> key);
    void HandleSosAbilityLaunched() override;
    void SetupSosDelayTimer() override;
    void ClearSpecialKeys() override;
    void ResetLaunchAbilityCount() override;
    void ClearRepeatKeyCountMap() override;
    int32_t GetRetValue() override;
    void InitHandlers();

private:
    KeyCommandContext context_;
    std::unique_ptr<ShortKeyHandler> shortkeyHandler_;
    std::unique_ptr<SequenceKeyHandler> sequenceHandler_;
    std::unique_ptr<RepeatKeyHandler> repeatKeyHandler_;
    std::unique_ptr<KeyConfigParser> configParser_;
    std::unique_ptr<TwoFingerGestureHandler> twoFingerGestureHandler_;

    std::map<std::string, ShortcutKey> shortcutKeys_;
    std::vector<Sequence> sequences_;
    std::vector<RepeatKey> repeatKeys_;
    std::vector<ExcludeKey> excludeKeys_;

private:
    bool isKnuckleParseConfig_ { false };
    std::set<std::string> appWhiteList_;
    bool enableCombineKey_ { true };
    bool isParseMaxCount_ { false };
    bool isParseStatusConfig_ { false };
    int32_t lastKeyEventCode_ { -1 };
    std::string sessionKey_ { };
    bool isStartBase_ { false };
    std::mutex mutex_;
    int64_t sosLaunchTime_ { -1 };
    int64_t powerUpTime_ { 0 };
    bool hasRegisteredSensor_ { false };
    uint32_t screenCapturePermission_;
    void *mistouchLibHandle_ {nullptr};
    IMistouchPrevention *mistouchPrevention_ {nullptr};
    std::atomic<int32_t> ret_ { 5 };
    std::mutex dataMutex_;
};
} // namespace MMI
} // namespace OHOS
#endif // KEY_COMMAND_HANDLER_H