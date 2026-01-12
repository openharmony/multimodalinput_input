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

#include "key_command_handler.h"

#include "ability_launcher.h"
#include "ability_manager_client.h"
#include "cursor_drawing_component.h"
#include "device_event_monitor.h"
#include "bundle_name_parser.h"
#include "product_type_parser.h"
#include "json_parser.h"
#include "product_name_definition.h"
#include "event_log_helper.h"
#ifdef SHORTCUT_KEY_MANAGER_ENABLED
#include "key_shortcut_manager.h"
#endif // SHORTCUT_KEY_MANAGER_ENABLED
#include "key_command_handler_util.h"
#include "key_event_normalize.h"
#include "long_press_subscriber_handler.h"
#include "pointer_device_manager.h"
#include "pull_throw_subscriber_handler.h"
#include "sensor_agent.h"
#include "sensor_agent_type.h"
#include "stylus_key_handler.h"
#include "timer_manager.h"
#include "whitelist_data_share_accessor.h"
#include "multimodal_input_plugin_manager.h"
#include <dlfcn.h>
#include <iostream>
#ifdef OHOS_BUILD_KNUCKLE
#include "knuckle_handler_component.h"
#endif // OHOS_BUILD_KNUCKLE

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyCommandHandler"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t EVEN_NUMBER { 2 };
constexpr int64_t NO_DELAY { 0 };
constexpr int64_t FREQUENCY { 1000 };
constexpr int64_t SOS_DELAY_TIMES { 1000000 };
constexpr int64_t SOS_COUNT_DOWN_TIMES { 4000000 };
constexpr int32_t MAX_TAP_COUNT { 2 };
constexpr int32_t ANCO_KNUCKLE_POINTER_ID { 15000 };
constexpr int32_t DEFAULT_VALUE { -1 };
constexpr int64_t POWER_ACTION_INTERVAL { 600 };
constexpr int64_t SOS_WAIT_TIME { 3000 };
const char* KEY_ENABLE { "enable" };
const char* KEY_STATUS { "status" };
constexpr int32_t SENSOR_SAMPLING_INTERVAL = 100000000;
constexpr int32_t SENSOR_REPORT_INTERVAL = 100000000;
const std::string SYS_PRODUCT_TYPE = OHOS::system::GetParameter("const.build.product", SYS_GET_DEVICE_TYPE_PARAM);
struct SensorUser g_user = {.name = {0}, .callback = nullptr, .userData = nullptr};
std::atomic<int32_t> g_distance { 0 };
#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
const char* LOADMISTOUCH_LIBPATH = "libmistouch_prevention.z.so";
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
} // namespace

static void SensorDataCallbackImpl(SensorEvent *event)
{
    if (event == nullptr) {
        MMI_HILOGE("Event is nullptr");
        return;
    }
    if (event->sensorTypeId != SENSOR_TYPE_ID_PROXIMITY) {
        MMI_HILOGE("Event sensorTypeId is not SENSOR_TYPE_ID_PROXIMITY");
        return;
    }
    ProximityData* proximityData = reinterpret_cast<ProximityData*>(event->data);
    CHKPV(proximityData);
    int32_t distance = static_cast<int32_t>(proximityData->distance);
    MMI_HILOGI("Proximity distance %{public}d", distance);
    g_distance = distance;
}

KeyCommandHandler::KeyCommandHandler()
{
    CALL_DEBUG_ENTER;
    InitHandlers();
}

void KeyCommandHandler::InitHandlers()
{
    CALL_DEBUG_ENTER;
    context_.shortcutKeys_ = &shortcutKeys_;
    context_.sequences_ = &sequences_;
    context_.repeatKeys_ = &repeatKeys_;
    context_.excludeKeys_ = &excludeKeys_;
    configParser_ = std::make_unique<KeyConfigParser>(context_, *this);
    shortkeyHandler_ = std::make_unique<ShortKeyHandler>(context_, *this);
    sequenceHandler_ = std::make_unique<SequenceKeyHandler>(context_, *this);
    repeatKeyHandler_ = std::make_unique<RepeatKeyHandler>(context_, *this);
    twoFingerGestureHandler_ = std::make_unique<TwoFingerGestureHandler>(context_, *this);
    LAUNCHER_ABILITY->SetKeyCommandService(this);
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
void KeyCommandHandler::HandleKeyEvent(const std::shared_ptr<KeyEvent> keyEvent)
{
    CHKPV(keyEvent);
    if (TouchPadKnuckleDoubleClickHandle(keyEvent)) {
        return;
    }
    if (OnHandleEvent(keyEvent)) {
        if (DISPLAY_MONITOR->GetScreenStatus() == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
            auto monitorHandler = InputHandler->GetMonitorHandler();
            CHKPV(monitorHandler);
            keyEvent->SetFourceMonitorFlag(true);
#ifndef OHOS_BUILD_EMULATOR
            monitorHandler->OnHandleEvent(keyEvent);
#endif // OHOS_BUILD_EMULATOR
            keyEvent->SetFourceMonitorFlag(false);
        }
        MMI_HILOGD("The keyEvent start launch an ability:%{private}d", keyEvent->GetKeyCode());
        BytraceAdapter::StartBytrace(keyEvent, BytraceAdapter::KEY_LAUNCH_EVENT);
        return;
    }
    CHKPV(nextHandler_);
    nextHandler_->HandleKeyEvent(keyEvent);
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#ifdef OHOS_BUILD_ENABLE_POINTER
void KeyCommandHandler::HandlePointerEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    if (OnHandleEvent(pointerEvent)) {
        if (EventLogHelper::IsBetaVersion() && !pointerEvent->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
            MMI_HILOGD("The pointerEvent start launch an ability, pointAction:%{public}s",
                pointerEvent->DumpPointerAction());
        } else {
            MMI_HILOGD("The pointerEvent start launch an ability, pointAction:%s", pointerEvent->DumpPointerAction());
        }
    }
    CHKPV(nextHandler_);
    nextHandler_->HandlePointerEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_POINTER

#ifdef OHOS_BUILD_ENABLE_TOUCH
void KeyCommandHandler::HandleTouchEvent(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CHKPV(pointerEvent);
    CHKPV(nextHandler_);
#ifdef OHOS_BUILD_KNUCKLE
    KnuckleHandlerComponent::GetInstance().HandleKnuckleEvent(pointerEvent);
#endif // OHOS_BUILD_KNUCKLE
    OnHandleTouchEvent(pointerEvent);
    int32_t id = pointerEvent->GetPointerId();
    PointerEvent::PointerItem item;
    pointerEvent->GetPointerItem(id, item);
    int32_t toolType = item.GetToolType();
    if (toolType == PointerEvent::TOOL_TYPE_KNUCKLE) {
        pointerEvent->AddFlag(InputEvent::EVENT_FLAG_NO_INTERCEPT);
    }
    nextHandler_->HandleTouchEvent(pointerEvent);
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_ENABLE_TOUCH
void KeyCommandHandler::OnHandleTouchEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    STYLUS_HANDLER->SetLastEventState(false);
    InitParse();
    InitializeLongPressConfigurations();
    context_.twoFingerGesture_.touchEvent = touchEvent;
    switch (touchEvent->GetPointerAction()) {
        case PointerEvent::POINTER_ACTION_PULL_MOVE:
            if (SYS_PRODUCT_TYPE == DEVICE_TYPE_FOLD_PC) {
                PULL_THROW_EVENT_HANDLER->HandleFingerGesturePullMoveEvent(touchEvent);
            }
            break;
        case PointerEvent::POINTER_ACTION_CANCEL:
        case PointerEvent::POINTER_ACTION_UP: {
            HandlePointerActionUpEvent(touchEvent);
            break;
        }
        case PointerEvent::POINTER_ACTION_MOVE: {
            twoFingerGestureHandler_->HandlePointerActionMoveEvent(touchEvent);
            LONG_PRESS_EVENT_HANDLER->HandleFingerGestureMoveEvent(touchEvent);
            if (SYS_PRODUCT_TYPE == DEVICE_TYPE_FOLD_PC) {
                PULL_THROW_EVENT_HANDLER->HandleFingerGestureMoveEvent(touchEvent);
            }
            break;
        }
        case PointerEvent::POINTER_ACTION_DOWN: {
            HandlePointerActionDownEvent(touchEvent);
            break;
        }
        default:
            MMI_HILOGD("Unknown pointer action:%{public}d", touchEvent->GetPointerAction());
            break;
    }
}

void KeyCommandHandler::InitializeLongPressConfigurations()
{
}

void KeyCommandHandler::HandlePointerActionDownEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    int32_t toolType = item.GetToolType();
    MMI_HILOGD("Pointer tool type:%{public}d", toolType);
    switch (toolType) {
#ifdef OHOS_BUILD_KNUCKLE
        case PointerEvent::TOOL_TYPE_FINGER: {
            twoFingerGestureHandler_->HandleFingerGestureDownEvent(touchEvent);
            if (CheckBundleName(touchEvent)) {
                LONG_PRESS_EVENT_HANDLER->HandleFingerGestureDownEvent(touchEvent);
            }
            if (SYS_PRODUCT_TYPE == DEVICE_TYPE_FOLD_PC) {
                PULL_THROW_EVENT_HANDLER->HandleFingerGestureDownEvent(touchEvent);
            }
            break;
        }
#endif // OHOS_BUILD_KNUCKLE
        default: {
            MMI_HILOGD("Current touch event tool type:%{public}d", toolType);
            break;
        }
    }
}

void KeyCommandHandler::HandlePointerActionUpEvent(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    int32_t id = touchEvent->GetPointerId();
    PointerEvent::PointerItem item;
    touchEvent->GetPointerItem(id, item);
    int32_t toolType = item.GetToolType();
    switch (toolType) {
#ifdef OHOS_BUILD_KNUCKLE
        case PointerEvent::TOOL_TYPE_FINGER: {
            twoFingerGestureHandler_->HandleFingerGestureUpEvent(touchEvent);
            LONG_PRESS_EVENT_HANDLER->HandleFingerGestureUpEvent(touchEvent);
            if (SYS_PRODUCT_TYPE == DEVICE_TYPE_FOLD_PC) {
                PULL_THROW_EVENT_HANDLER->HandleFingerGestureUpEvent(touchEvent);
            }
            break;
        }
#endif // OHOS_BUILD_KNUCKLE
        default: {
            MMI_HILOGD("Current touch event tool type:%{public}d", toolType);
            break;
        }
    }
}
#endif // OHOS_BUILD_ENABLE_TOUCH

#ifdef OHOS_BUILD_KNUCKLE
void KeyCommandHandler::SendNotSupportMsg(std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(touchEvent);
    auto tempEvent = std::make_shared<PointerEvent>(*touchEvent);
    std::list<PointerEvent::PointerItem> pointerItems = tempEvent->GetAllPointerItems();
    tempEvent->RemoveAllPointerItems();
    for (auto &pointerItem : pointerItems) {
        pointerItem.SetPointerId(ANCO_KNUCKLE_POINTER_ID);
        pointerItem.SetOriginPointerId(ANCO_KNUCKLE_POINTER_ID);
        tempEvent->AddPointerItem(pointerItem);
    }
    tempEvent->SetPointerAction(PointerEvent::POINTER_ACTION_DOWN);
    tempEvent->SetPointerId(ANCO_KNUCKLE_POINTER_ID);
    tempEvent->SetAgentWindowId(tempEvent->GetTargetWindowId());
    MMI_HILOGW("Event is %{private}s", tempEvent->ToString().c_str());
    auto fd = WIN_MGR->GetClientFd(tempEvent);
    auto udsServer = InputHandler->GetUDSServer();
    CHKPV(udsServer);
    NetPacket pkt(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(tempEvent, pkt);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    InputEventDataTransformation::MarshallingEnhanceData(tempEvent, pkt);
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    udsServer->SendMsg(fd, pkt);

    tempEvent->SetPointerAction(PointerEvent::POINTER_ACTION_UP);
    std::list<PointerEvent::PointerItem> tmpPointerItems = tempEvent->GetAllPointerItems();
    tempEvent->RemoveAllPointerItems();
    for (auto &pointerItem : tmpPointerItems) {
        pointerItem.SetPressed(false);
        tempEvent->AddPointerItem(pointerItem);
    }
    NetPacket pktUp(MmiMessageId::ON_POINTER_EVENT);
    InputEventDataTransformation::Marshalling(tempEvent, pktUp);
#ifdef OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    InputEventDataTransformation::MarshallingEnhanceData(tempEvent, pktUp);
#endif // OHOS_BUILD_ENABLE_SECURITY_COMPONENT
    udsServer->SendMsg(fd, pktUp);
}
#endif // OHOS_BUILD_KNUCKLE
void KeyCommandHandler::InitParse()
{
    if (configParser_ == nullptr) {
        MMI_HILOGE("configParser_ is null");
        return;
    }
    if (!context_.isParseConfig_) {
        if (!configParser_->ParseConfig()) {
            MMI_HILOGE("Parse config failed");
            return;
        }
        context_.isParseConfig_ = true;
    }
}

void KeyCommandHandler::InitParse(const std::string funcName, const std::shared_ptr<KeyEvent> key)
{
    if (key == nullptr || configParser_ == nullptr) {
        MMI_HILOGE("key or configParser_ is null");
        return;
    }
    if (!context_.isParseConfig_) {
        if (!configParser_->ParseConfig()) {
            MMI_HILOGE("Parse configFile failed");
            DfxHisysevent::ReportFailHandleKey(funcName, key->GetKeyCode(),
                DfxHisysevent::KEY_ERROR_CODE::FAILED_PARSE_CONFIG);
            return;
        }
        context_.isParseConfig_ = true;
    }
}

void KeyCommandHandler::InitExcludeParse(const std::string funcName, const std::shared_ptr<KeyEvent> key)
{
    if (key == nullptr || configParser_ == nullptr) {
        MMI_HILOGE("key or configParser_ is null");
        return;
    }
    if (!context_.isParseExcludeConfig_) {
        if (!configParser_->ParseExcludeConfig()) {
            DfxHisysevent::ReportFailHandleKey(funcName, key->GetKeyCode(),
                DfxHisysevent::KEY_ERROR_CODE::FAILED_PARSE_CONFIG);
            MMI_HILOGE("Parse Exclude configFile failed");
            return;
        }
        context_.isParseExcludeConfig_ = true;
    }
}

void KeyCommandHandler::HandleSosAbilityLaunched()
{
    if (context_.isDownStart_) {
        context_.isDownStart_ = false;
    }

    context_.isFreezePowerKey_ = true;
    sosLaunchTime_ = OHOS::MMI::GetSysClockTime();
    context_.count_ = 0;
    context_.launchAbilityCount_ = 0;
    context_.repeatKeyCountMap_.clear();
    context_.repeatKey_.keyCode = -1;
    context_.repeatKey_.keyAction = -1;
    SetupSosDelayTimer();
}

void KeyCommandHandler::SetupSosDelayTimer()
{
    context_.sosDelayTimerId_ = TimerMgr->AddTimer(SOS_DELAY_TIMES / SECONDS_SYSTEM, 1, [this] () {
        context_.isFreezePowerKey_ = false;
        context_.sosDelayTimerId_ = -1;
        MMI_HILOGW("Timeout, restore the power button");
    }, "KeyCommandHandler-SosDelay");

    if (context_.sosDelayTimerId_ < 0) {
        context_.isFreezePowerKey_ = false;
        MMI_HILOGE("Add timer failed");
    }
}

void KeyCommandHandler::ClearSpecialKeys()
{
    context_.specialKeys_.clear();
}

void KeyCommandHandler::ResetLaunchAbilityCount()
{
    context_.launchAbilityCount_ = 0;
}

void KeyCommandHandler::ClearRepeatKeyCountMap()
{
    context_.repeatKeyCountMap_.clear();
}

int32_t KeyCommandHandler::GetRetValue()
{
    return ret_.load(std::memory_order_relaxed);
}

void KeyCommandHandler::ParseRepeatKeyMaxCount()
{
    if (repeatKeys_.empty()) {
        context_.maxCount_ = 0;
    }
    int32_t tempCount = 0;
    int32_t tempDelay = 0;
    auto walletBundleName = BUNDLE_NAME_PARSER.GetBundleName("WALLET_BUNDLE_NAME");
    for (RepeatKey& item : repeatKeys_) {
        if (item.times > tempCount) {
            tempCount = item.times;
        }
        if (item.delay > tempDelay) {
            tempDelay = item.delay;
        }
        if (item.ability.bundleName == walletBundleName) {
            context_.walletLaunchDelayTimes_ = item.delay;
        }
    }
    context_.maxCount_ = tempCount;
    context_.intervalTime_ = tempDelay;
}

bool KeyCommandHandler::IsExcludeKey(const std::shared_ptr<KeyEvent> key)
{
    size_t keysSize = excludeKeys_.size();
    for (size_t i = 0; i < keysSize; i++) {
        if (key->GetKeyCode() == excludeKeys_[i].keyCode) {
            if (key->GetKeyAction() == excludeKeys_[i].keyAction) {
                return true;
            }
        }
    }
    return false;
}

bool KeyCommandHandler::IsEnableCombineKey(const std::shared_ptr<KeyEvent> key)
{
    CHKPF(key);
    if (enableCombineKey_) {
        return true;
    }

    InitExcludeParse("IsEnableCombineKey", key);
    if (IsExcludeKey(key)) {
        if (EventLogHelper::IsBetaVersion() && !key->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
            MMI_HILOGD("ExcludekeyCode:%{private}d,ExcludekeyAction:%{public}d",
                key->GetKeyCode(), key->GetKeyAction());
        } else {
            MMI_HILOGD("ExcludekeyCode:%{private}d, ExcludekeyAction:%{public}d",
                key->GetKeyCode(), key->GetKeyAction());
        }
        auto items = key->GetKeyItems();
        MMI_HILOGI("KeyItemsSize:%{public}zu", items.size());
        if (items.size() != 1) {
            return enableCombineKey_;
        }
        return true;
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_L) {
        for (const auto &item : key->GetKeyItems()) {
            int32_t keyCode = item.GetKeyCode();
            if (keyCode != KeyEvent::KEYCODE_L && keyCode != KeyEvent::KEYCODE_META_LEFT &&
                keyCode != KeyEvent::KEYCODE_META_RIGHT) {
                MMI_HILOGI("GetKeyCode:%{private}d", keyCode);
                return enableCombineKey_;
            }
        }
        return true;
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_SYSRQ) {
        auto iterms = key->GetKeyItems();
        MMI_HILOGI("Recording response VM");
        return iterms.size() != 1 ? enableCombineKey_ : true;
    }
    return enableCombineKey_;
}

int32_t KeyCommandHandler::EnableCombineKey(bool enable)
{
    enableCombineKey_ = enable;
    MMI_HILOGI("Enable combineKey is successful in keyCommand handler, enable:%{public}d", enable);
    return RET_OK;
}

void KeyCommandHandler::ParseStatusConfigObserver()
{
    CALL_DEBUG_ENTER;
    for (Sequence& item : sequences_) {
        if (item.statusConfig.empty()) {
            continue;
        }
        CreateStatusConfigObserver<Sequence>(item);
    }

    for (auto& item : shortcutKeys_) {
        ShortcutKey &shortcutKey = item.second;
        if (shortcutKey.statusConfig.empty()) {
            continue;
        }
        CreateStatusConfigObserver<ShortcutKey>(shortcutKey);
    }
}

template <class T>
void KeyCommandHandler::CreateStatusConfigObserver(T& item)
{
    CALL_DEBUG_ENTER;
    SettingObserver::UpdateFunc updateFunc = [weak = weak_from_this(), &item](const std::string& key) {
        auto ptr = weak.lock();
        if (ptr == nullptr) {
            return;
        }
        bool statusValue = true;
        auto ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
            .GetBoolValue(key, statusValue);
        if (ret != RET_OK) {
            MMI_HILOGE("Get value from setting date fail");
            return;
        }
        MMI_HILOGI("Config changed key:%s, value:%{public}d", key.c_str(), statusValue);
        item.statusConfigValue = statusValue;
    };
    sptr<SettingObserver> statusObserver = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .CreateObserver(item.statusConfig, updateFunc);
    ErrCode ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID).RegisterObserver(statusObserver);
    if (ret != ERR_OK) {
        MMI_HILOGE("Register setting observer failed, ret:%{public}d", ret);
        statusObserver = nullptr;
    }
    bool configVlaue = true;
    ret = SettingDataShare::GetInstance(MULTIMODAL_INPUT_SERVICE_ID)
        .GetBoolValue(item.statusConfig, configVlaue);
    if (ret != RET_OK) {
        MMI_HILOGE("Get value from setting date fail");
        return;
    }
    MMI_HILOGI("Get value success key:%s, value:%{public}d", item.statusConfig.c_str(), configVlaue);
    item.statusConfigValue = configVlaue;
}

bool KeyCommandHandler::PreHandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CHKPF(key);
    if (EventLogHelper::IsBetaVersion() && !key->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
        MMI_HILOGD("KeyEvent occured. code:%{private}d, keyAction:%{public}d",
            key->GetKeyCode(), key->GetKeyAction());
    } else {
        MMI_HILOGD("KeyEvent occured. code:%{private}d, keyAction:%{public}d",
            key->GetKeyCode(), key->GetKeyAction());
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_F1) {
        DfxHisysevent::ReportKeyEvent("screen on");
    }
    if (!IsEnableCombineKey(key)) {
        MMI_HILOGI("Combine key is taken over in key command");
        return false;
    }
    InitParse("PreHandleEvent", key);
    if (!isParseMaxCount_) {
        ParseRepeatKeyMaxCount();
        isParseMaxCount_ = true;
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_VOLUME_DOWN || key->GetKeyCode() == KeyEvent::KEYCODE_VOLUME_UP) {
        context_.lastVolumeDownActionTime_ = key->GetActionTime();
    }
    return true;
}

bool KeyCommandHandler::PreHandleEvent()
{
    CALL_INFO_TRACE;
    InitParse();
    if (!isParseMaxCount_) {
        ParseRepeatKeyMaxCount();
        isParseMaxCount_ = true;
    }
    return true;
}

bool KeyCommandHandler::HandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);
    if (!PreHandleEvent(key)) {
        return false;
    }

    if (STYLUS_HANDLER->HandleStylusKey(key)) {
        DfxHisysevent::ReportKeyEvent("stylus");
        return true;
    }

    bool shortKeysHandleRet = shortkeyHandler_->HandleShortKeys(key);
    if (key->GetKeyCode() == KeyEvent::KEYCODE_POWER && key->GetKeyAction() == KeyEvent::KEY_ACTION_UP) {
        powerUpTime_ = key->GetActionTime();
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_POWER && key->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        if ((key->GetActionTime() - powerUpTime_) > POWER_ACTION_INTERVAL * FREQUENCY &&
            (key->GetActionTime() - sosLaunchTime_) > SOS_WAIT_TIME * FREQUENCY) {
                MMI_HILOGI("Set isFreezePowerKey as false");
                context_.isFreezePowerKey_ = false;
            }
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_POWER && context_.isFreezePowerKey_) {
        MMI_HILOGI("Freeze power key");
        return true;
    }
    bool sequencesHandleRet = sequenceHandler_->HandleSequences(key);
    MMI_HILOGD("shortKeysHandleRet:%{public}d, sequencesHandleRet:%{public}d",
        shortKeysHandleRet, sequencesHandleRet);
    if (shortKeysHandleRet) {
        context_.launchAbilityCount_ = 0;
        context_.isHandleSequence_ = false;
        return true;
    }
    if (sequencesHandleRet) {
        context_.isHandleSequence_ = true;
        return true;
    }
    if (key->GetKeyCode() == KeyEvent::KEYCODE_POWER) {
        MMI_HILOGI("Handle power key DownStart:%{public}d", context_.isDownStart_);
    }
    if (key->GetKeyCode() != context_.repeatKey_.keyCode &&
        key->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN) {
        context_.isDownStart_ = false;
    }
    if (!context_.isDownStart_) {
        repeatKeyHandler_->HandleRepeatKeys(key);
        return false;
    } else {
        if (repeatKeyHandler_->HandleRepeatKeys(key)) {
            MMI_HILOGI("Handle power key lifting event");
            return true;
        }
    }
    context_.count_ = 0;
    context_.repeatKeyCountMap_.clear();
    context_.isDownStart_ = false;
    return false;
}

void KeyCommandHandler::InitKeyObserver()
{
    if (!isParseStatusConfig_) {
        ParseStatusConfigObserver();
        isParseStatusConfig_ = true;
    }
}

#ifdef OHOS_BUILD_ENABLE_KEYBOARD
bool KeyCommandHandler::OnHandleEvent(const std::shared_ptr<KeyEvent> key)
{
    CALL_DEBUG_ENTER;
    CHKPF(key);
    HandlePointerVisibleKeys(key);
    if (HandleEvent(key)) {
        return true;
    }

    if (context_.specialKeys_.find(key->GetKeyCode()) != context_.specialKeys_.end()) {
        HandleSpecialKeys(key->GetKeyCode(), key->GetKeyAction());
        return true;
    }

    if (IsSpecialType(key->GetKeyCode(), SpecialType::SUBSCRIBER_BEFORE_DELAY)) {
        auto tmpKey = KeyEvent::Clone(key);
        int32_t timerId = TimerMgr->AddTimer(SPECIAL_KEY_DOWN_DELAY, 1, [this, tmpKey] () {
            MMI_HILOGD("Timer callback");
            auto it = context_.specialTimers_.find(tmpKey->GetKeyCode());
            if (it != context_.specialTimers_.end() && !it->second.empty()) {
                it->second.pop_front();
            }
            auto handler = InputHandler->GetSubscriberHandler();
            CHKPV(handler);
            handler->HandleKeyEvent(tmpKey);
        }, "KeyCommandHandler-OnHandleEvent");
        if (timerId < 0) {
            DfxHisysevent::ReportFailHandleKey("OnHandleEvent", key->GetKeyCode(),
                DfxHisysevent::KEY_ERROR_CODE::FAILED_TIMER);
            MMI_HILOGE("Add timer failed");
            return false;
        }

        auto it = context_.specialTimers_.find(key->GetKeyCode());
        if (it == context_.specialTimers_.end()) {
            std::list<int32_t> timerIds;
            timerIds.push_back(timerId);
            auto it = context_.specialTimers_.emplace(key->GetKeyCode(), timerIds);
            if (!it.second) {
                MMI_HILOGE("Keycode duplicated");
                return false;
            }
        } else {
            it->second.push_back(timerId);
        }
        MMI_HILOGD("Add timer success");
        return true;
    }
    return false;
}
#endif // OHOS_BUILD_ENABLE_KEYBOARD

#if defined(OHOS_BUILD_ENABLE_POINTER) || defined(OHOS_BUILD_ENABLE_TOUCH)
bool KeyCommandHandler::OnHandleEvent(const std::shared_ptr<PointerEvent> pointer)
{
    CALL_DEBUG_ENTER;
    CHKPF(pointer);
    STYLUS_HANDLER->SetLastEventState(false);
    InitParse();
    return HandleMulFingersTap(pointer);
}
#endif // OHOS_BUILD_ENABLE_POINTER || OHOS_BUILD_ENABLE_TOUCH

int32_t KeyCommandHandler::SetIsFreezePowerKey(const std::string pageName)
{
    CALL_INFO_TRACE;
    std::lock_guard<std::mutex> lock(mutex_);
    if (pageName != "SosCountdown") {
        context_.isFreezePowerKey_ = false;
        return RET_OK;
    }
    context_.isFreezePowerKey_ = true;
    sosLaunchTime_ = OHOS::MMI::GetSysClockTime();
    context_.count_ = 0;
    context_.launchAbilityCount_ = 0;
    context_.repeatKeyCountMap_.clear();
    if (context_.sosDelayTimerId_ >= 0) {
        TimerMgr->RemoveTimer(context_.sosDelayTimerId_);
        context_.sosDelayTimerId_ = DEFAULT_VALUE;
    }
    int32_t timerId = TimerMgr->AddTimer(
        SOS_COUNT_DOWN_TIMES / SECONDS_SYSTEM, 1, [this] () {
        MMI_HILOGW("Timeout, restore the power button");
        context_.isFreezePowerKey_ = false;
    }, "KeyCommandHandler-SetIsFreezePowerKey");
    if (timerId < 0) {
        MMI_HILOGE("Add timer failed");
        context_.isFreezePowerKey_ = false;
        return RET_ERR;
    }
    return RET_OK;
}

bool KeyCommandHandler::HandleMulFingersTap(const std::shared_ptr<PointerEvent> pointerEvent)
{
    CALL_DEBUG_ENTER;
    if (pointerEvent->GetPointerAction() == PointerEvent::POINTER_ACTION_TRIPTAP) {
        MMI_HILOGI("The touchpad trip tap will launch ability");
        BytraceAdapter::StartLaunchAbility(KeyCommandType::TYPE_MULTI_FINGERS,
            context_.threeFingersTap_.ability.bundleName);
        LAUNCHER_ABILITY->LaunchAbility(context_.threeFingersTap_.ability, NO_DELAY);
        BytraceAdapter::StopLaunchAbility();
        return true;
    }
    return false;
}

void KeyCommandHandler::HandleSpecialKeys(int32_t keyCode, int32_t keyAction)
{
    CALL_INFO_TRACE;
    auto iter = context_.specialKeys_.find(keyCode);
    if (keyAction == KeyEvent::KEY_ACTION_UP) {
        if (iter != context_.specialKeys_.end()) {
            context_.specialKeys_.erase(iter);
            return;
        }
    }

    if (keyAction == KeyEvent::KEY_ACTION_DOWN) {
        if (iter == context_.specialKeys_.end()) {
            auto it = context_.specialKeys_.emplace(keyCode, keyAction);
            if (!it.second) {
                MMI_HILOGD("KeyCode duplicated");
                return;
            }
        }
    }
}

void KeyCommandHandler::HandlePointerVisibleKeys(const std::shared_ptr<KeyEvent> &keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    if (keyEvent->GetKeyCode() == KeyEvent::KEYCODE_F9 && lastKeyEventCode_ == KeyEvent::KEYCODE_CTRL_LEFT) {
        MMI_HILOGI("Force make pointer visible");
#if defined(OHOS_BUILD_ENABLE_POINTER) && defined(OHOS_BUILD_ENABLE_POINTER_DRAWING)
    if (POINTER_DEV_MGR.isInit) {
        CursorDrawingComponent::GetInstance().ForceClearPointerVisibleStatus();
    }
#endif // OHOS_BUILD_ENABLE_POINTER && OHOS_BUILD_ENABLE_POINTER_DRAWING
    }
    lastKeyEventCode_ = keyEvent->GetKeyCode();
}


int32_t KeyCommandHandler::UpdateSettingsXml(const std::string &businessId, int32_t delay)
{
    CALL_DEBUG_ENTER;
    if (businessId.empty() || context_.businessIds_.empty()) {
        MMI_HILOGE("The business id or business ids is empty");
        return PARAMETER_ERROR;
    }
    if (std::find(context_.businessIds_.begin(), context_.businessIds_.end(),
        businessId) == context_.businessIds_.end()) {
        MMI_HILOGE("%{public}s not in the config file", businessId.c_str());
        return PARAMETER_ERROR;
    }
    if (delay < MIN_SHORT_KEY_DOWN_DURATION || delay > MAX_SHORT_KEY_DOWN_DURATION) {
        MMI_HILOGE("Delay is not in valid range");
        return PARAMETER_ERROR;
    }
    return PREFERENCES_MGR->SetShortKeyDuration(businessId, delay);
}

void KeyCommandHandler::Dump(int32_t fd, const std::vector<std::string> &args)
{
    static const std::unordered_map<int32_t, std::string> actionMap = { {0, "UNKNOWN"},
        {1, "CANCEL"}, {2, "DOWN"}, {3, "UP"} };
    CALL_DEBUG_ENTER;
    mprintf(fd, "----------------------------- ShortcutKey information ----------------------------\t");
    mprintf(fd, "ShortcutKey: count = %zu", shortcutKeys_.size());
    for (const auto &item : shortcutKeys_) {
        auto &shortcutKey = item.second;
        for (const auto &prekey : shortcutKey.preKeys) {
            mprintf(fd, "PreKey:%d", prekey);
        }
        mprintf(fd,
            "BusinessId: %s | StatusConfig: %s | StatusConfigValue: %s "
            "| FinalKey: %d | keyDownDuration: %d | TriggerType: %d | BundleName: %s | AbilityName: %s "
            "| Action: %s \t", shortcutKey.businessId.c_str(), shortcutKey.statusConfig.c_str(),
            shortcutKey.statusConfigValue ? "true" : "false", shortcutKey.finalKey, shortcutKey.keyDownDuration,
            shortcutKey.triggerType, shortcutKey.ability.bundleName.c_str(), shortcutKey.ability.abilityName.c_str(),
            shortcutKey.ability.action.c_str());
    }
    mprintf(fd, "-------------------------- Sequence information ----------------------------------\t");
    mprintf(fd, "Sequence: count = %zu", sequences_.size());
    for (const auto &item : sequences_) {
        for (const auto& sequenceKey : item.sequenceKeys) {
            mprintf(fd, "code: %{private}d | keyAction: %s",
                sequenceKey.keyCode, ConvertKeyActionToString(sequenceKey.keyAction).c_str());
        }
        mprintf(fd, "BundleName: %s | AbilityName: %s | Action: %s ",
            item.ability.bundleName.c_str(), item.ability.abilityName.c_str(), item.ability.action.c_str());
    }
    mprintf(fd, "-------------------------- ExcludeKey information --------------------------------\t");
    mprintf(fd, "ExcludeKey: count = %zu", excludeKeys_.size());
    for (const auto &item : excludeKeys_) {
        mprintf(fd, "code: %{private}d | keyAction: %s", item.keyCode,
            ConvertKeyActionToString(item.keyAction).c_str());
    }
    mprintf(fd, "-------------------------- RepeatKey information ---------------------------------\t");
    mprintf(fd, "RepeatKey: count = %zu", repeatKeys_.size());
    for (const auto &item : repeatKeys_) {
        mprintf(fd,
            "KeyCode: %{private}d | KeyAction: %s | Times: %d"
            "| StatusConfig: %s | StatusConfigValue: %s | BundleName: %s | AbilityName: %s"
            "| Action:%s \t", item.keyCode, ConvertKeyActionToString(item.keyAction).c_str(), item.times,
            item.statusConfig.c_str(), item.statusConfigValue ? "true" : "false",
            item.ability.bundleName.c_str(), item.ability.abilityName.c_str(), item.ability.action.c_str());
    }
    PrintGestureInfo(fd);
}

void KeyCommandHandler::PrintGestureInfo(int32_t fd)
{
    mprintf(fd, "-------------------------- TouchPad Two Fingers Gesture --------------------------\t");
    mprintf(fd,
        "GestureActive: %s | GestureBundleName: %s | GestureAbilityName: %s"
        "| GestureAction: %s \t", context_.twoFingerGesture_.active ? "true" : "false",
        context_.twoFingerGesture_.ability.bundleName.c_str(),
        context_.twoFingerGesture_.ability.abilityName.c_str(),
        context_.twoFingerGesture_.ability.action.c_str());
    mprintf(fd, "-------------------------- TouchPad Three Fingers Tap Gesture --------------------\t");
    mprintf(fd,
        "TapBundleName: %s | TapAbilityName: %s"
        "| TapAction: %s \t", context_.threeFingersTap_.ability.bundleName.c_str(),
        context_.threeFingersTap_.ability.abilityName.c_str(), context_.threeFingersTap_.ability.action.c_str());
#ifdef OHOS_BUILD_KNUCKLE
    KnuckleHandlerComponent::GetInstance().Dump(fd);
#endif // OHOS_BUILD_KNUCKLE
}
std::string KeyCommandHandler::ConvertKeyActionToString(int32_t keyAction)
{
    static const std::unordered_map<int32_t, std::string> actionMap = {
        {0, "UNKNOWN"},
        {1, "CANCEL"},
        {2, "DOWN"},
        {3, "UP"}
    };
    auto it = actionMap.find(keyAction);
    if (it != actionMap.end()) {
        return it->second;
    } else {
        return "UNKNOWN_ACTION";
    }
}
std::ostream& operator<<(std::ostream& os, const Sequence& seq)
{
    os << "keys: [";
    for (const SequenceKey &singleKey: seq.sequenceKeys) {
        os << "(kc:" << singleKey.keyCode << ",ka:" << singleKey.keyAction << ",d:" << singleKey.delay << "),";
    }
    os << "]: " << seq.ability.bundleName << ":" << seq.ability.abilityName;
    return os;
}

bool KeyCommandHandler::TouchPadKnuckleDoubleClickHandle(std::shared_ptr<KeyEvent> event)
{
    CHKPF(event);
    auto actionType = event->GetKeyAction();
    if (actionType == KNUCKLE_1F_DOUBLE_CLICK || actionType == KNUCKLE_2F_DOUBLE_CLICK) {
        MMI_HILOGI("Knuckle in TouchPadKnuckleDoubleClickHandle, actionType is %{public}d, "
                   "screenCapturePermission_ is %{public}d",
            actionType,
            screenCapturePermission_);
    }
    if (actionType == KNUCKLE_1F_DOUBLE_CLICK && HasScreenCapturePermission(TOUCHPAD_KNUCKLE_SCREENSHOT)) {
        auto bundleName = BUNDLE_NAME_PARSER.GetBundleName("PC_PRO_SCREENSHOT_BUNDLE_NAME");
        auto abilityName = BUNDLE_NAME_PARSER.GetBundleName("PC_PRO_SCREENSHOT_ABILITY_NAME");
        TouchPadKnuckleDoubleClickProcess(bundleName, abilityName, "single_knuckle");
        return true;
    }
    if (actionType == KNUCKLE_2F_DOUBLE_CLICK && HasScreenCapturePermission(TOUCHPAD_KNUCKLE_SCREEN_RECORDING)) {
        auto bundleName = BUNDLE_NAME_PARSER.GetBundleName("PC_PRO_SCREENRECORDER_BUNDLE_NAME");
        auto abilityName = BUNDLE_NAME_PARSER.GetBundleName("PC_PRO_SCREENRECORDER_ABILITY_NAME");
        TouchPadKnuckleDoubleClickProcess(bundleName, abilityName, "double_knuckle");
        return true;
    }
    return false;
}

void KeyCommandHandler::TouchPadKnuckleDoubleClickProcess(const std::string bundleName,
    const std::string abilityName, const std::string action)
{
    std::string screenStatus = DISPLAY_MONITOR->GetScreenStatus();
    bool isScreenLocked = DISPLAY_MONITOR->GetScreenLocked();
    if (screenStatus == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF || isScreenLocked) {
        MMI_HILOGI("The current screen is not in the unlocked state with the screen on");
        return;
    }
    Ability ability;
    ability.bundleName = bundleName;
    ability.abilityName = abilityName;
    ability.params.emplace(std::make_pair("trigger_type", action));
    LAUNCHER_ABILITY->LaunchAbility(ability, NO_DELAY);
}

bool KeyCommandHandler::CheckBundleName(const std::shared_ptr<PointerEvent> touchEvent)
{
    CALL_DEBUG_ENTER;
    int32_t windowPid = WIN_MGR->GetWindowPid(touchEvent->GetTargetWindowId());
    if (windowPid == RET_ERR) {
        MMI_HILOGE("Get window pid failed");
        return false;
    }

    std::string bundleName;
    if (LONG_PRESS_EVENT_HANDLER->GetBundleName(bundleName, windowPid) == RET_ERR) {
        MMI_HILOGE("Failed to get bundle name, pid %{public}d", windowPid);
        return false;
    }
    if (!WhitelistDataShareAccessor::GetInstance().IsWhitelisted(bundleName)) {
        MMI_HILOGW("%{public}s not support long-press drag", bundleName.c_str());
        return false;
    }
    return true;
}

void KeyCommandHandler::RegisterProximitySensor()
{
    CALL_INFO_TRACE;
    if (hasRegisteredSensor_) {
        MMI_HILOGE("Has SubscribeSensor %{public}d", SENSOR_TYPE_ID_PROXIMITY);
        return;
    }
    if (!KeyEventHdr->IsScreenFold()) {
        MMI_HILOGD("Screen not fold");
        return;
    }
    g_user.callback = SensorDataCallbackImpl;
    int32_t ret = SubscribeSensor(SENSOR_TYPE_ID_PROXIMITY, &g_user);
    if (ret != 0) {
        MMI_HILOGE("Failed to SubscribeSensor: %{public}d ret:%{public}d", SENSOR_TYPE_ID_PROXIMITY, ret);
        return;
    }
    ret = SetBatch(SENSOR_TYPE_ID_PROXIMITY, &g_user, SENSOR_SAMPLING_INTERVAL, SENSOR_REPORT_INTERVAL);
    if (ret != 0) {
        MMI_HILOGE("Failed to SetBatch: %{public}d ret:%{public}d", SENSOR_TYPE_ID_PROXIMITY, ret);
        return;
    }
    ret = ActivateSensor(SENSOR_TYPE_ID_PROXIMITY, &g_user);
    if (ret != 0) {
        MMI_HILOGE("Failed to ActivateSensor: %{public}d ret:%{public}d", SENSOR_TYPE_ID_PROXIMITY, ret);
        return;
    }
    hasRegisteredSensor_ = true;
}

int32_t KeyCommandHandler::LaunchAiScreenAbility(int32_t pid)
{
    if (twoFingerGestureHandler_ == nullptr) {
        MMI_HILOGE("The twoFingerHandler_ is null");
        return RET_ERR;
    }
    int32_t ret = twoFingerGestureHandler_->LaunchAiScreenAbility(pid);
    if (ret != RET_OK) {
        MMI_HILOGE("Failed to call LaunchAiScreenAbility");
        return RET_ERR;
    }
    return RET_OK;
}

void KeyCommandHandler::UnregisterProximitySensor()
{
    if (!hasRegisteredSensor_) {
        MMI_HILOGI("Has registered sensor: %{public}d", SENSOR_TYPE_ID_PROXIMITY);
        return;
    }
    hasRegisteredSensor_ = false;
    int32_t ret = DeactivateSensor(SENSOR_TYPE_ID_PROXIMITY, &g_user);
    if (ret != 0) {
        MMI_HILOGE("Failed to DeactiveSensor: %{public}d ret:%{public}d", SENSOR_TYPE_ID_PROXIMITY, ret);
    }
    ret = UnsubscribeSensor(SENSOR_TYPE_ID_PROXIMITY, &g_user);
    if (ret != 0) {
        MMI_HILOGE("Failed to UnsubscribeSensor: %{public}d ret:%{public}d", SENSOR_TYPE_ID_PROXIMITY, ret);
    }
}

int32_t KeyCommandHandler::SwitchScreenCapturePermission(uint32_t permissionType, bool enable)
{
    uint32_t knucklePermissions = permissionType & KNUCKLE_ALL_PERMISSIONS;
    uint32_t otherPermissions = permissionType & (~KNUCKLE_ALL_PERMISSIONS);
    if (knucklePermissions != 0) {
#ifdef OHOS_BUILD_KNUCKLE
        KnuckleHandlerComponent::GetInstance().SetKnucklePermissions(knucklePermissions, enable);
#endif // OHOS_BUILD_KNUCKLE
    }

    if (otherPermissions != 0) {
        if (enable) {
            screenCapturePermission_ |= otherPermissions;
        } else {
            screenCapturePermission_ &= ~otherPermissions;
        }
    }

    MMI_HILOGW("SwitchScreenCapturePermission is successful in keyCommand handler, "
               "screenCapturePermission_:%{public}d, permissionType:%{public}d, "
               "enable:%{public}d", screenCapturePermission_, permissionType, enable);
    return RET_OK;
}

bool KeyCommandHandler::HasScreenCapturePermission(uint32_t permissionType)
{
    bool hasScreenCapturePermission = ((screenCapturePermission_ & permissionType) == permissionType);
    MMI_HILOGD("HasScreenCapturePermission is successful in keyCommand handler, screenCapturePermission_:%{public}d, "
               "permissionType:%{public}d, hasScreenCapturePermission:%{public}d ",
        screenCapturePermission_, permissionType, hasScreenCapturePermission);
    return hasScreenCapturePermission;
}

#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
void KeyCommandHandler::CallMistouchPrevention()
{
    if (hasRegisteredSensor_) {
        MMI_HILOGE("Has SubscribeSensor %{public}d", SENSOR_TYPE_ID_PROXIMITY);
        return;
    }
    if (mistouchLibHandle_ == nullptr) {
        mistouchLibHandle_ = dlopen(LOADMISTOUCH_LIBPATH, RTLD_LAZY);
        if (!mistouchLibHandle_) {
            MMI_HILOGE("Failed to load library: %s", dlerror());
            return;
        }
        typedef IMistouchPrevention* (*funCreate_ptr) (void);
        funCreate_ptr fnCreate = nullptr;
        fnCreate = (funCreate_ptr)dlsym(mistouchLibHandle_, "ConsumerMpImplGetInstance");
        if (fnCreate == nullptr) {
            MMI_HILOGE("dlsym mistouchPrevention wrapper symbol failed, error:%{public}s", dlerror());
            dlclose(mistouchLibHandle_);
            return;
        }
        mistouchPrevention_ = (IMistouchPrevention*)fnCreate();
        if (mistouchPrevention_ == nullptr) {
            MMI_HILOGE("mistouchPrevention wrapper symbol failed, error:%{public}s", dlerror());
            dlclose(mistouchLibHandle_);
            return;
        }
    }

    std::weak_ptr<KeyCommandHandler> weakPtr = shared_from_this();
    auto callback = [weakPtr](int32_t ret) -> void {
        if (auto sharedPtr = weakPtr.lock()) {
            sharedPtr->ret_ = ret;
            MMI_HILOGD("UserStatusDataCallback received data:ret_ %{public}d", sharedPtr->ret_.load());
        } else {
            MMI_HILOGE("callback fired, but object is already destroyed.");
        }
    };
    CHKPV(mistouchPrevention_);
    int ret = mistouchPrevention_->MistouchPreventionConnector(callback);
    hasRegisteredSensor_ = true;
    MMI_HILOGD("CallMistouchPrevention yes MistouchPreventionConnector:%{public}d", ret);

    timerId_ = TimerMgr->AddTimer(FREQUENCY, 1, [weakPtr]() {
        if (auto sharedPtr = weakPtr.lock()) {
            sharedPtr->UnregisterMistouchPrevention();
        } else {
            MMI_HILOGE("Timer fired, but object is already destroyed.");
        }
    }, "KeyCommandHandler-CheckSpecialRepeatKey");
    if (timerId_ < 0) {
        MMI_HILOGE("Add timer failed");
    }
}
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION

#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
void KeyCommandHandler::UnregisterMistouchPrevention()
{
    if (!hasRegisteredSensor_) {
        MMI_HILOGD("Has unregistered sensor: %{public}d", SENSOR_TYPE_ID_PROXIMITY);
        return;
    }
    CHKPV(mistouchPrevention_);
    mistouchPrevention_->MistouchPreventionClose();
    hasRegisteredSensor_ = false;
    ret_ = -1;
    MMI_HILOGD("UnregisterMistouchPrevention:ret_ %{public}d", ret_.load());
    if (timerId_ >= 0) {
        MMI_HILOGD("lzc RemoveTimer:%{public}d", timerId_);
        TimerMgr->RemoveTimer(timerId_);
        timerId_ = -1;
    }
}
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION

KeyCommandHandler::~KeyCommandHandler()
{
#ifdef OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
    if (mistouchLibHandle_ != nullptr) {
        if (mistouchPrevention_ != nullptr) {
            typedef void (*funCreate_ptr) (IMistouchPrevention* mistouchPrevention);
            funCreate_ptr fnDestory = nullptr;
            fnDestory = (funCreate_ptr)dlsym(mistouchLibHandle_, "ConsumerMpImplDestoryInstance");
            if (fnDestory != nullptr) {
                fnDestory(mistouchPrevention_);
            }
            mistouchPrevention_ = nullptr;
        }
        dlclose(mistouchLibHandle_);
        mistouchLibHandle_ = nullptr;
    }
#endif // OHOS_BUILD_ENABLE_MISTOUCH_PREVENTION
}

uint32_t KeyCommandHandler::GetScreenCapturePermission()
{
    return screenCapturePermission_;
}
} // namespace MMI
} // namespace OHOS