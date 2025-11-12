/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "inputConsumer_keyOptions_impl.h"
#include "inputConsumer_hotkeyOptions_impl.h"
#include "inputConsumer_keyPressed_impl.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniConsumerImpl"

using namespace taihe;
using namespace ohos::multimodalInput::inputConsumer;
using namespace OHOS::MMI;

namespace {
using HotkeyOptions_t = ::ohos::multimodalInput::inputConsumer::HotkeyOptions;
static constexpr size_t PRE_KEYS_SIZE { 4 };
static constexpr int32_t INVALID_SUBSCRIBER_ID { -1 };
static constexpr int32_t OCCUPIED_BY_SYSTEM = -3;
static constexpr int32_t OCCUPIED_BY_OTHER = -4;
constexpr size_t FIRST_INDEX { 0 };
constexpr size_t SECOND_INDEX { 1 };
constexpr size_t THIRD_INDEX { 2 };
const int64_t MILLISECONDS_IN_SECOND = 1000;

enum ETS_CALLBACK_EVENT {
    ETS_CALLBACK_EVENT_FAILED = -1,
    ETS_CALLBACK_EVENT_SUCCESS = 1,
    ETS_CALLBACK_EVENT_EXIST = 2,
    ETS_CALLBACK_EVENT_NOT_EXIST = 3,
};

enum EtsErrorCode : int32_t {
    OTHER_ERROR = -1,
    COMMON_PERMISSION_CHECK_ERROR = 201,
    COMMON_USE_SYSAPI_ERROR = 202,
    COMMON_PARAMETER_ERROR = 401,
    INPUT_DEVICE_NOT_SUPPORTED = 801,
    COMMON_DEVICE_NOT_EXIST = 3900001,
    COMMON_KEYBOARD_DEVICE_NOT_EXIST = 3900002,
    COMMON_NON_INPUT_APPLICATION = 3900003,
    PRE_KEY_NOT_SUPPORTED = 4100001,
    INPUT_OCCUPIED_BY_SYSTEM = 4200002,
    INPUT_OCCUPIED_BY_OTHER = 4200003,
    ERROR_WINDOW_ID_PERMISSION_DENIED = 26500001,
};

struct KeyMonitor {
    int32_t subscriberId { -1 };
    KeyMonitorOption keyOption {};
};

struct KeyEventMonitorInfo {
    std::string eventType;
    int32_t subscribeId{ 0 };
    std::shared_ptr<KeyOption> keyOption{ nullptr };
    ~KeyEventMonitorInfo();
};
typedef std::map<std::string, std::list<std::shared_ptr<KeyEventMonitorInfo>>> Callbacks;
static Callbacks hotkeyCallbacks = {};
static Callbacks keyCallbacks = {};

using callbackType = std::variant<
    taihe::callback<void(KeyOptions const&)>,
    taihe::callback<void(HotkeyOptions const&)>,
    taihe::callback<void(ohos::multimodalInput::keyEvent::KeyEvent const&)>
>;

struct CallbackObject {
    CallbackObject(callbackType cb, ani_ref ref) : callback(cb), ref(ref)
    {
        CALL_DEBUG_ENTER;
    }
    ~CallbackObject()
    {
        CALL_DEBUG_ENTER;
        if (auto *env = taihe::get_env()) {
            if (ref) {
                env->GlobalReference_Delete(ref);
                ref = nullptr;
            }
        }
    }
    callbackType callback;
    ani_ref ref;
};

class GlobalRefGuard {
    ani_env *env_ = nullptr;
    ani_ref ref_ = nullptr;

public:
    GlobalRefGuard(ani_env *env, ani_object obj) : env_(env)
    {
        if (!env_) {
            return;
        }
        if (ANI_OK != env_->GlobalReference_Create(obj, &ref_)) {
            ref_ = nullptr;
        }
    }
    explicit operator bool() const
    {
        return ref_ != nullptr;
    }
    ani_ref get() const
    {
        return ref_;
    }
    ~GlobalRefGuard()
    {
        if (env_ && ref_) {
            env_->GlobalReference_Delete(ref_);
        }
    }

    GlobalRefGuard(const GlobalRefGuard &) = delete;
    GlobalRefGuard &operator=(const GlobalRefGuard &) = delete;
};

std::map<size_t, KeyMonitor> monitors_;
std::map<std::string, std::vector<std::shared_ptr<CallbackObject>>> jsCbMap_;
std::mutex g_mutex;
std::mutex sCallBacksMutex;
std::mutex jsCbMapMutex;
std::atomic<size_t> g_baseId { 0 };

KeyEventMonitorInfo::~KeyEventMonitorInfo() {}

void HandleCommonErrors(int32_t ret)
{
    int32_t errorCode = std::abs(ret);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        taihe::set_business_error(COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode == COMMON_PERMISSION_CHECK_ERROR) {
        MMI_HILOGE("Shield api need ohos.permission.INPUT_CONTROL_DISPATCHING");
        taihe::set_business_error(COMMON_PERMISSION_CHECK_ERROR,
            "Shield api need ohos.permission.INPUT_CONTROL_DISPATCHING");
    } else if (errorCode != RET_OK) {
        MMI_HILOGE("Dispatch control failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error");
    }
}

int32_t RegisterListener(std::string const &type, callbackType &&cb, uintptr_t opq)
{
    std::lock_guard<std::mutex> lock(jsCbMapMutex);
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_ref callbackRef;
    ani_env *env = taihe::get_env();
    if (env == nullptr || ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        MMI_HILOGE("ani_env is nullptr or GlobalReference_Create failed");
        return ETS_CALLBACK_EVENT_FAILED;
    }
    auto &cbVec = jsCbMap_[type];
    bool isDuplicate = std::any_of(cbVec.begin(), cbVec.end(),
        [env, callbackRef](std::shared_ptr<CallbackObject> &obj) {
        ani_boolean isEqual = false;
        return (ANI_OK == env->Reference_StrictEquals(callbackRef, obj->ref, &isEqual)) && isEqual;
    });
    if (isDuplicate) {
        env->GlobalReference_Delete(callbackRef);
        MMI_HILOGD("callback already registered");
        return ETS_CALLBACK_EVENT_EXIST;
    }
    cbVec.emplace_back(std::make_shared<CallbackObject>(cb, callbackRef));
    MMI_HILOGI("register callback success, type: %{public}s", type.c_str());
    return ETS_CALLBACK_EVENT_SUCCESS;
}

bool UnregisterListener(std::string const &type, taihe::optional_view<uintptr_t> opq)
{
    std::lock_guard<std::mutex> lock(jsCbMapMutex);
    const auto iter = jsCbMap_.find(type);
    if (iter == jsCbMap_.end()) {
        MMI_HILOGE("Already unRegistered!");
        return false;
    }
    if (!opq.has_value()) {
        jsCbMap_.erase(iter);
        MMI_HILOGE("callback is nullptr!");
        return false;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        MMI_HILOGE("ani_env is nullptr!");
        return false;
    }
    GlobalRefGuard guard(env, reinterpret_cast<ani_object>(opq.value()));
    if (!guard) {
        MMI_HILOGE("GlobalRefGuard is false!");
        return false;
    }
    const auto pred = [env, targetRef = guard.get()](std::shared_ptr<CallbackObject> &obj) {
        ani_boolean isEqual = false;
        return (ANI_OK == env->Reference_StrictEquals(targetRef, obj->ref, &isEqual)) && isEqual;
    };
    auto &callbacks = iter->second;
    const auto it = std::find_if(callbacks.begin(), callbacks.end(), pred);
    if (it != callbacks.end()) {
        callbacks.erase(it);
    } else {
        return false;
    }
    if (callbacks.empty()) {
        jsCbMap_.erase(iter);
    }
    MMI_HILOGI("Unregister callback success, type: %{public}s", type.c_str());
    return true;
}

size_t GenerateId()
{
    return g_baseId++;
}

void EmitKeyPerssedCallbackWork(size_t keyMonitorId, std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> lock(jsCbMapMutex);
    auto &cbVec = jsCbMap_[std::to_string(keyMonitorId)];
    for (auto &cb : cbVec) {
        if (cb == nullptr) {
            continue;
        }
        size_t typeIndex = cb->callback.index();
        if (typeIndex == THIRD_INDEX) {
            auto &func = std::get<
                taihe::callback<void(ohos::multimodalInput::keyEvent::KeyEvent const&)>>(cb->callback);
            auto keyPresseds = ConvertTaiheKeyPressed(keyEvent);
            func(keyPresseds);
        }
    }
}

void OnSubscribeKeyMonitor(size_t keyMonitorId, std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    std::lock_guard guard(g_mutex);
    auto mIter = monitors_.find(keyMonitorId);
    if (mIter == monitors_.end()) {
        MMI_HILOGE("No key monitor with ID(%{public}zu)", keyMonitorId);
        return;
    }
    EmitKeyPerssedCallbackWork(keyMonitorId, keyEvent);
}

bool CheckKeyMonitorOption(const KeyMonitorOption &keyOption)
{
    return ((allowedKeys_.find(keyOption.GetKey()) != allowedKeys_.cend()) &&
            (keyOption.GetAction() == KeyEvent::KEY_ACTION_DOWN));
}


bool ParseKeyMonitorOption(KeyPressedConfig const& options, KeyMonitor &keyMonitor)
{
    CALL_DEBUG_ENTER;
    keyMonitor.keyOption.SetKey(options.key);
    keyMonitor.keyOption.SetAction(EtsKeyActionToKeyAction(options.action));
    keyMonitor.keyOption.SetRepeat(options.isRepeat);
    if (!CheckKeyMonitorOption(keyMonitor.keyOption)) {
        MMI_HILOGE("Input for KeyPressedConfig is invalid");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Input for KeyPressedConfig is invalid");
        return false;
    }
    return true;
}


void SubscribeKeyMonitor(KeyPressedConfig const& options,
    callback_view<void(ohos::multimodalInput::keyEvent::KeyEvent const&)> f, uintptr_t opq)
{
    std::lock_guard guard(g_mutex);
    KeyMonitor keyMonitor {};
    if (!ParseKeyMonitorOption(options, keyMonitor)) {
        MMI_HILOGE("Invalid KeyMonitorOption");
        return;
    }
    MMI_HILOGI("[ETS] Subscribe key monitor");
    auto keyMonitorId = GenerateId();
    auto result = RegisterListener(std::to_string(keyMonitorId), f, opq);
    if (result == ETS_CALLBACK_EVENT_FAILED) {
        MMI_HILOGE("Register listener failed");
        return;
    }
    if (result == ETS_CALLBACK_EVENT_EXIST) {
        MMI_HILOGE("Callback already exist");
        return;
    }
    auto subscriberId = InputManager::GetInstance()->SubscribeKeyMonitor(keyMonitor.keyOption,
        [keyMonitorId](std::shared_ptr<KeyEvent> keyEvent) {
            OnSubscribeKeyMonitor(keyMonitorId, keyEvent);
        });
    if (subscriberId < 0) {
        if (subscriberId == -CAPABILITY_NOT_SUPPORTED) {
            MMI_HILOGE("Capability not supported");
            taihe::set_business_error(INPUT_DEVICE_NOT_SUPPORTED, "Capability not supported.");
        } else if (subscriberId == -PARAM_INPUT_INVALID) {
            MMI_HILOGE("Input is invalid");
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Input is invalid");
        } else {
            MMI_HILOGE("SubscribeKeyMonitor fail, error:%{public}d", subscriberId);
        }
        jsCbMap_.erase(std::to_string(keyMonitorId));
        return;
    }
    MMI_HILOGI("[ETS] Subscribe key monitor(ID:%{public}zu, subscriberId:%{public}d)", keyMonitorId, subscriberId);
    if (result == ETS_CALLBACK_EVENT_SUCCESS) {
        keyMonitor.subscriberId = subscriberId;
        monitors_.emplace(keyMonitorId, keyMonitor);
    }
}

void UnsubscribeKeyMonitor(taihe::optional_view<uintptr_t> opq)
{
    std::lock_guard guard(g_mutex);
    for (auto iter = monitors_.begin(); iter != monitors_.end(); ++iter) {
        if (!UnregisterListener(std::to_string(iter->first), opq)) {
            MMI_HILOGE("UnregisterListener fail");
            continue;
        }
        MMI_HILOGI("[NAPI] Unsubscribe key monitor(ID:%{public}zu, subscriberId:%{public}d)",
            iter->first, iter->second.subscriberId);
        auto ret = InputManager::GetInstance()->UnsubscribeKeyMonitor(iter->second.subscriberId);
        if (ret == -CAPABILITY_NOT_SUPPORTED) {
            MMI_HILOGE("Capability not supported");
            taihe::set_business_error(INPUT_DEVICE_NOT_SUPPORTED, "Capability not supported.");
        } else if (ret == -PARAM_INPUT_INVALID) {
            MMI_HILOGE("Input is invalid");
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Input is invalid");
        } else if (ret != RET_OK) {
            MMI_HILOGE("UnsubscribeKeyMonitor fail, error:%{public}d", ret);
        }
        monitors_.erase(iter);
        return;
    }

    auto ret = InputManager::GetInstance()->UnsubscribeKeyMonitor(INVALID_SUBSCRIBER_ID);
    if (ret == -CAPABILITY_NOT_SUPPORTED) {
        MMI_HILOGE("Capability not supported");
        taihe::set_business_error(INPUT_DEVICE_NOT_SUPPORTED, "Capability not supported.");
    } else {
        MMI_HILOGE("Input is invalid");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Input is invalid");
    }
}

void UnsubscribeKeyMonitors()
{
    std::lock_guard guard(g_mutex);
    if (monitors_.empty()) {
        auto ret = InputManager::GetInstance()->UnsubscribeKeyMonitor(INVALID_SUBSCRIBER_ID);
        if (ret == -CAPABILITY_NOT_SUPPORTED) {
            MMI_HILOGE("Capability not supported");
            taihe::set_business_error(INPUT_DEVICE_NOT_SUPPORTED, "Capability not supported.");
        }
        return;
    }
    for (auto &[monitorId, monitor] : monitors_) {
        MMI_HILOGI("[NAPI] Unsubscribe key monitor(ID:%{public}zu, subscriberId:%{public}d)",
            monitorId, monitor.subscriberId);
        auto ret = InputManager::GetInstance()->UnsubscribeKeyMonitor(monitor.subscriberId);
        if (ret != RET_OK) {
            MMI_HILOGE("UnsubscribeKeyMonitor fail, error:%{public}d", ret);
        }
    }
    monitors_.clear();
}

int32_t GetPreSubscribeId(Callbacks &callbacks, std::shared_ptr<KeyEventMonitorInfo> event)
{
    CHKPR(event, ERROR_NULL_POINTER);
    std::lock_guard guard(sCallBacksMutex);
    auto it = callbacks.find(event->eventType);
    if (it == callbacks.end() || it->second.empty()) {
        MMI_HILOGE("The callbacks is empty");
        return ETS_CALLBACK_EVENT_FAILED;
    }
    CHKPR(it->second.front(), ERROR_NULL_POINTER);
    return it->second.front()->subscribeId;
}

int32_t GetPreKeys(std::vector<int32_t> &preKeys, std::set<int32_t> &params)
{
    CALL_DEBUG_ENTER;
    std::size_t arrayLength = preKeys.size();
    for (std::size_t i = 0; i < arrayLength; i++) {
        MMI_HILOGD("Get int array number:%{public}d", preKeys[i]);
        if (!params.insert(preKeys[i]).second) {
            MMI_HILOGE("Params insert value failed");
            return RET_ERR;
        }
    }
    return RET_OK;
}

bool IsMatchKeyAction(bool isFinalKeydown, int32_t keyAction)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("isFinalKeydown:%{public}d, keyAction:%{public}d", isFinalKeydown, keyAction);
    if (isFinalKeydown && keyAction == KeyEvent::KEY_ACTION_DOWN) {
        return true;
    }
    if (!isFinalKeydown && keyAction == KeyEvent::KEY_ACTION_UP) {
        return true;
    }
    MMI_HILOGE("isFinalKeydown not matched with keyAction");
    return false;
}

bool MatchCombinationKeys(std::shared_ptr<KeyEventMonitorInfo> monitorInfo, std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPF(monitorInfo);
    CHKPF(keyEvent);
    auto keyOption = monitorInfo->keyOption;
    CHKPF(keyOption);
    std::vector<KeyEvent::KeyItem> items = keyEvent->GetKeyItems();
    int32_t infoFinalKey = keyOption->GetFinalKey();
    int32_t keyEventFinalKey = keyEvent->GetKeyCode();
    bool isFinalKeydown = keyOption->IsFinalKeyDown();
    MMI_HILOGD("InfoFinalKey:%{private}d,keyEventFinalKey:%{private}d", infoFinalKey, keyEventFinalKey);
    if (infoFinalKey != keyEventFinalKey || items.size() > PRE_KEYS_SIZE ||
        !IsMatchKeyAction(isFinalKeydown, keyEvent->GetKeyAction())) {
        MMI_HILOGD("key Param invalid");
        return false;
    }
    std::set<int32_t> infoPreKeys = keyOption->GetPreKeys();
    int32_t infoSize = 0;
    for (auto it = infoPreKeys.begin(); it != infoPreKeys.end(); ++it) {
        if (*it >= 0) {
            infoSize++;
        }
    }
    int32_t count = 0;
    for (const auto &item : items) {
        if (item.GetKeyCode() == keyEventFinalKey) {
            continue;
        }
        auto iter = find(infoPreKeys.begin(), infoPreKeys.end(), item.GetKeyCode());
        if (iter == infoPreKeys.end()) {
            MMI_HILOGW("No keyCode in preKeys");
            return false;
        }
        count++;
    }
    MMI_HILOGD("keyEventSize:%{public}d, infoSize:%{public}d", count, infoSize);
    std::optional<KeyEvent::KeyItem> keyItem = keyEvent->GetKeyItem();
    if (!keyItem) {
        MMI_HILOGE("The keyItem is nullopt");
        return false;
    }
    auto downTime = keyItem->GetDownTime();
    auto upTime = keyEvent->GetActionTime();
    auto curDurationTime = keyOption->GetFinalKeyDownDuration();
    if (curDurationTime > 0 && (upTime - downTime >=
        (static_cast<int64_t>(curDurationTime) * MILLISECONDS_IN_SECOND))) {
        MMI_HILOGE("Skip, upTime - downTime >= duration");
        return false;
    }
    return count == infoSize;
}

using callbackType = std::variant<
    taihe::callback<void(KeyOptions const&)>,
    taihe::callback<void(HotkeyOptions const&)>,
    taihe::callback<void(ohos::multimodalInput::keyEvent::KeyEvent const&)>
>;

void EmitHotkeyCallbackWork(std::shared_ptr<KeyEventMonitorInfo> reportEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(reportEvent);
    CHKPV(reportEvent->keyOption);
    std::lock_guard<std::mutex> lock(jsCbMapMutex);
    auto &cbVec = jsCbMap_[reportEvent->eventType];
    for (auto &cb : cbVec) {
        if (cb == nullptr) {
            continue;
        }
        size_t typeIndex = cb->callback.index();
        if (typeIndex == FIRST_INDEX) {
            auto &func = std::get<taihe::callback<void(HotkeyOptions const&)>>(cb->callback);
            auto hotkeyOptions = ConvertTaiheHotkeyOptions(reportEvent->keyOption);
            func(hotkeyOptions);
        }
    }
}

static void SubHotkeyEventCallback(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    std::lock_guard guard(sCallBacksMutex);
    auto iter = hotkeyCallbacks.begin();
    while (iter != hotkeyCallbacks.end()) {
        auto &list = iter->second;
        ++iter;
        MMI_HILOGD("Callback list size:%{public}zu", list.size());
        auto infoIter = list.begin();
        while (infoIter != list.end()) {
            auto monitorInfo = *infoIter;
            if (MatchCombinationKeys(monitorInfo, keyEvent)) {
                EmitHotkeyCallbackWork(monitorInfo);
                MMI_HILOGD("need to async callback");
            }
            ++infoIter;
        }
    }
}

int32_t AddEventHotkeyCallback(Callbacks &callbacks, std::shared_ptr<KeyEventMonitorInfo> event,
    callback_view<void(HotkeyOptions const&)> f, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(sCallBacksMutex);
    CHKPR(event, RET_ERR);
    auto result = RegisterListener(event->eventType, f, opq);
    if (result == ETS_CALLBACK_EVENT_FAILED) {
        MMI_HILOGE("Register listener failed");
        return RET_ERR;
    }
    if (result == ETS_CALLBACK_EVENT_EXIST) {
        MMI_HILOGE("Callback already exist");
        return RET_ERR;
    }
    if (result == ETS_CALLBACK_EVENT_SUCCESS) {
        hotkeyCallbacks[event->eventType].push_back(event);
    }
    return RET_OK;
}

int32_t GetHotkeyEventInfo(HotkeyOptions const& hotkeyOptions,
    std::shared_ptr<KeyEventMonitorInfo> event, std::shared_ptr<KeyOption> keyOption)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, RET_ERR);
    CHKPR(keyOption, RET_ERR);
    if (hotkeyOptions.preKeys.empty()) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "PreKeys not found");
        return RET_ERR;
    }
    std::set<int32_t> preKeys;
    std::vector<int32_t> etsPreKeys(hotkeyOptions.preKeys.begin(), hotkeyOptions.preKeys.end());
    if (GetPreKeys(etsPreKeys, preKeys) != RET_OK) {
        MMI_HILOGE("Get preKeys failed");
        return RET_ERR;
    }
    if (preKeys.size() > PRE_KEYS_SIZE) {
        MMI_HILOGE("PreKeys size invalid");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "PreKeys size invalid");
        return RET_ERR;
    }
    MMI_HILOGD("PreKeys size:%{public}zu", preKeys.size());
    keyOption->SetPreKeys(preKeys);

    std::ostringstream oss;
    for (const auto &item : preKeys) {
        auto it = std::find(pressKeyCodes.begin(), pressKeyCodes.end(), item);
        if (it == pressKeyCodes.end()) {
            MMI_HILOGE("PreKeys is not expect");
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "PreKey not expected");
            return RET_ERR;
        }
        oss << item << ",";
        MMI_HILOGD("PreKeys:%{private}d", item);
    }

    if (hotkeyOptions.finalKey < 0) {
        MMI_HILOGE("FinalKey:%{private}d is less 0, can not process", hotkeyOptions.finalKey);
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "FinalKey must be greater than or equal to 0");
        return RET_ERR;
    }
    auto it = std::find(finalKeyCodes.begin(), finalKeyCodes.end(), hotkeyOptions.finalKey);
    if (it != finalKeyCodes.end()) {
        MMI_HILOGE("FinalKey is not expect");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "FinalKey is not expect");
        return RET_ERR;
    }
    oss << hotkeyOptions.finalKey << ",";
    keyOption->SetFinalKey(hotkeyOptions.finalKey);
    MMI_HILOGD("FinalKey:%{private}d", hotkeyOptions.finalKey);

    bool isFinalKeyDown = true;
    oss << isFinalKeyDown << ",";
    keyOption->SetFinalKeyDown(isFinalKeyDown);
    MMI_HILOGD("IsFinalKeyDown:%{private}d,", (isFinalKeyDown == true ? 1 : 0));

    int32_t finalKeyDownDuration = 0;
    oss << finalKeyDownDuration << ",";
    keyOption->SetFinalKeyDownDuration(finalKeyDownDuration);

    bool isRepeat = true;
    if (!hotkeyOptions.isRepeat.has_value()) {
        MMI_HILOGD("IsRepeat field is default");
    } else {
        isRepeat = hotkeyOptions.isRepeat.value();
    }
    oss << isRepeat;
    keyOption->SetRepeat(isRepeat);
    MMI_HILOGD("IsRepeat:%{public}s", (isRepeat ? "true" : "false"));

    event->eventType = oss.str();
    return RET_OK;
}

void SubscribeHotkey(HotkeyOptions const& hotkeyOptions, callback_view<void(HotkeyOptions const&)> f, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEventMonitorInfo> event = std::make_shared<KeyEventMonitorInfo>();
    CHKPV(event);
    auto keyOption = std::make_shared<KeyOption>();
    CHKPV(keyOption);
    if (GetHotkeyEventInfo(hotkeyOptions, event, keyOption) != RET_OK) {
        MMI_HILOGE("GetHotkeyEventInfo failed");
        return;
    }
    event->keyOption = keyOption;
    int32_t preSubscribeId = GetPreSubscribeId(hotkeyCallbacks, event);
    if (preSubscribeId < 0) {
        MMI_HILOGD("EventType:%{private}s", event->eventType.c_str());
        int32_t subscribeId = InputManager::GetInstance()->SubscribeHotkey(keyOption, SubHotkeyEventCallback);
        if (subscribeId == ERROR_UNSUPPORT) {
            MMI_HILOGE("SubscribeId invalid:%{public}d", subscribeId);
            taihe::set_business_error(INPUT_DEVICE_NOT_SUPPORTED, "Hotkey occupied by other");
            return;
        }
        if (subscribeId == OCCUPIED_BY_SYSTEM) {
            MMI_HILOGE("SubscribeId invalid:%{public}d", subscribeId);
            taihe::set_business_error(INPUT_OCCUPIED_BY_SYSTEM, "Hotkey occupied by system");
            return;
        }
        if (subscribeId == OCCUPIED_BY_OTHER) {
            MMI_HILOGE("SubscribeId invalid:%{public}d", subscribeId);
            taihe::set_business_error(INPUT_OCCUPIED_BY_OTHER, "Hotkey occupied by other");
            return;
        }
        MMI_HILOGD("SubscribeId:%{public}d", subscribeId);
        event->subscribeId = subscribeId;
    } else {
        event->subscribeId = preSubscribeId;
    }
    if (AddEventHotkeyCallback(hotkeyCallbacks, event, f, opq) != RET_OK) {
        MMI_HILOGE("AddEventHotkeyCallback failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "AddEventHotkeyCallback failed");
    }
}

int32_t DelEventCallbackRef(std::list<std::shared_ptr<KeyEventMonitorInfo>> &info, std::string const &type,
    optional_view<uintptr_t> opq, int32_t &subscribeId)
{
    CALL_DEBUG_ENTER;
    for (auto iter = info.begin(); iter != info.end();) {
        if (*iter == nullptr) {
            info.erase(iter++);
            continue;
        }
        if (opq.has_value()) {
            if (UnregisterListener(type, opq)) {
                std::shared_ptr<KeyEventMonitorInfo> monitorInfo = *iter;
                info.erase(iter++);
                if (info.empty()) {
                    subscribeId = monitorInfo->subscribeId;
                }
                MMI_HILOGD("Callback has deleted, size:%{public}zu", info.size());
                return ETS_CALLBACK_EVENT_SUCCESS;
            }
            ++iter;
            continue;
        }
        std::shared_ptr<KeyEventMonitorInfo> monitorInfo = *iter;
        info.erase(iter++);
        if (info.empty()) {
            subscribeId = monitorInfo->subscribeId;
        }
        MMI_HILOGD("Callback has deleted, size:%{public}zu", info.size());
    }
    MMI_HILOGD("Callback size:%{public}zu", info.size());
    return ETS_CALLBACK_EVENT_SUCCESS;
}

int32_t DelEventCallback(Callbacks &callbacks, std::shared_ptr<KeyEventMonitorInfo> event,
    optional_view<uintptr_t> opq, int32_t &subscribeId)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(sCallBacksMutex);
    CHKPR(event, ERROR_NULL_POINTER);
    if (callbacks.count(event->eventType) <= 0) {
        MMI_HILOGE("Callback doesn't exists");
        return ETS_CALLBACK_EVENT_FAILED;
    }
    auto &info = callbacks[event->eventType];
    MMI_HILOGD("EventType:%{private}s, keyEventMonitorInfos:%{public}zu", event->eventType.c_str(), info.size());
    return DelEventCallbackRef(info, event->eventType, opq, subscribeId);
}

void UnsubscribeHotkey(HotkeyOptions const& hotkeyOptions, optional_view<uintptr_t> opq)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEventMonitorInfo> event = std::make_shared<KeyEventMonitorInfo>();
    CHKPV(event);
    auto keyOption = std::make_shared<KeyOption>();
    CHKPV(keyOption);
    int32_t subscribeId = -1;
    if (GetHotkeyEventInfo(hotkeyOptions, event, keyOption) != RET_OK) {
        MMI_HILOGE("GetHotkeyEventInfo failed");
        return;
    }
    if (DelEventCallback(hotkeyCallbacks, event, opq, subscribeId) < 0) {
        MMI_HILOGE("DelEventCallback failed");
        return;
    }
    MMI_HILOGI("Unsubscribe hot key(%{public}d)", subscribeId);
    InputManager::GetInstance()->UnsubscribeHotkey(subscribeId);
}

void EmitKeyCallbackWork(std::shared_ptr<KeyEventMonitorInfo> reportEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(reportEvent);
    CHKPV(reportEvent->keyOption);
    std::lock_guard<std::mutex> lock(jsCbMapMutex);
    auto &cbVec = jsCbMap_[reportEvent->eventType];
    for (auto &cb : cbVec) {
        if (cb == nullptr) {
            continue;
        }
        size_t typeIndex = cb->callback.index();
        if (typeIndex == SECOND_INDEX) {
            auto &func = std::get<taihe::callback<void(KeyOptions const&)>>(cb->callback);
            auto keyOptions = ConvertTaiheKeyOptions(reportEvent->keyOption);
            func(keyOptions);
        }
    }
}

static void SubKeyEventCallback(std::shared_ptr<KeyEvent> keyEvent, const std::string& keyOptionKey)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    std::lock_guard guard(sCallBacksMutex);
    auto iter = keyCallbacks.find(keyOptionKey);
    if (iter != keyCallbacks.end()) {
        auto &list = iter->second;
        MMI_HILOGD("list size:%{public}zu", list.size());
        for (auto monitorInfo : list) {
            if (MatchCombinationKeys(monitorInfo, keyEvent)) {
                EmitKeyCallbackWork(monitorInfo);
            }
        }
    } else {
        MMI_HILOGE("No Matches found for SubKeyEventCallback");
    }
}

int32_t AddEventKeyCallback(Callbacks &callbacks, std::shared_ptr<KeyEventMonitorInfo> event,
    callback_view<void(KeyOptions const&)> f, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(sCallBacksMutex);
    CHKPR(event, RET_ERR);
    auto result = RegisterListener(event->eventType, f, opq);
    if (result == ETS_CALLBACK_EVENT_FAILED) {
        MMI_HILOGE("Register listener failed");
        return RET_ERR;
    }
    if (result == ETS_CALLBACK_EVENT_SUCCESS) {
        keyCallbacks[event->eventType].push_back(event);
    }
    return RET_OK;
}

int32_t GetEventInfoAPI9(KeyOptions const& keyOptions, std::shared_ptr<KeyEventMonitorInfo> event,
    std::shared_ptr<KeyOption> keyOption)
{
    CALL_DEBUG_ENTER;
    CHKPR(event, RET_ERR);
    CHKPR(keyOption, RET_ERR);
    if (keyOptions.preKeys.empty()) {
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "preKeys not found");
        return RET_ERR;
    }
    std::set<int32_t> preKeys;
    std::vector<int32_t> etsPreKeys(keyOptions.preKeys.begin(), keyOptions.preKeys.end());
    if (GetPreKeys(etsPreKeys, preKeys) != RET_OK) {
        MMI_HILOGE("Get preKeys failed");
        return RET_ERR;
    }
    if (preKeys.size() > PRE_KEYS_SIZE) {
        MMI_HILOGE("PreKeys size invalid");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "PreKeys size invalid");
        return RET_ERR;
    }
    MMI_HILOGD("PreKeys size:%{public}zu", preKeys.size());
    keyOption->SetPreKeys(preKeys);
    std::string subKeyNames = "";
    for (const auto &item : preKeys) {
        subKeyNames += std::to_string(item);
        subKeyNames += ",";
        MMI_HILOGD("preKeys:%{private}d", item);
    }

    if (keyOptions.finalKey < 0) {
        MMI_HILOGE("finalKey:%{private}d is less 0, can not process", keyOptions.finalKey);
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "finalKey must be greater than or equal to 0");
        return RET_ERR;
    }
    subKeyNames += std::to_string(keyOptions.finalKey);
    subKeyNames += ",";
    keyOption->SetFinalKey(keyOptions.finalKey);
    MMI_HILOGD("FinalKey:%{private}d", keyOptions.finalKey);

    subKeyNames += std::to_string(keyOptions.isFinalKeyDown);
    subKeyNames += ",";
    keyOption->SetFinalKeyDown(keyOptions.isFinalKeyDown);
    MMI_HILOGD("IsFinalKeyDown:%{private}d,map_key:%{private}s",
        (keyOptions.isFinalKeyDown == true ? 1 : 0), subKeyNames.c_str());

    if (keyOptions.finalKeyDownDuration < 0) {
        MMI_HILOGE("finalKeyDownDuration:%{public}d is less 0, can not process", keyOptions.finalKeyDownDuration);
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "finalKeyDownDuration must be greater than or equal to 0");
        return RET_ERR;
    }
    subKeyNames += std::to_string(keyOptions.finalKeyDownDuration);
    subKeyNames += ",";
    keyOption->SetFinalKeyDownDuration(keyOptions.finalKeyDownDuration);
    MMI_HILOGD("FinalKeyDownDuration:%{public}d", keyOptions.finalKeyDownDuration);

    bool isRepeat = true;
    if (!keyOptions.isRepeat.has_value()) {
        MMI_HILOGD("IsRepeat field is default");
    } else {
        isRepeat = keyOptions.isRepeat.value();
    }
    subKeyNames += std::to_string(isRepeat);
    keyOption->SetRepeat(isRepeat);
    MMI_HILOGD("IsRepeat:%{public}s", (isRepeat ? "true" : "false"));
    event->eventType = subKeyNames;
    return RET_OK;
}

void SubscribeKey(KeyOptions const& keyOptions, callback_view<void(KeyOptions const&)> f, uintptr_t opq)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEventMonitorInfo> event = std::make_shared<KeyEventMonitorInfo>();
    CHKPV(event);
    auto keyOption = std::make_shared<KeyOption>();
    CHKPV(keyOption);
    if (GetEventInfoAPI9(keyOptions, event, keyOption) != RET_OK) {
        MMI_HILOGE("GetEventInfoAPI9 failed");
        return;
    }
    event->keyOption = keyOption;
    int32_t preSubscribeId = GetPreSubscribeId(keyCallbacks, event);
    if (preSubscribeId < 0) {
        CALL_DEBUG_ENTER;
        MMI_HILOGD("EventType:%{private}s", event->eventType.c_str());
        int32_t subscribeId = -1;
        subscribeId = InputManager::GetInstance()->SubscribeKeyEvent(keyOption,
            [keyOption](std::shared_ptr<KeyEvent> keyEvent) {
                CALL_DEBUG_ENTER;
                std::string keyOptionKey = GenerateKeyOptionKey(keyOption);
                SubKeyEventCallback(keyEvent, keyOptionKey);
            });
        if (subscribeId < 0) {
            MMI_HILOGE("SubscribeId invalid:%{public}d", subscribeId);
            return;
        }
        MMI_HILOGD("SubscribeId:%{public}d", subscribeId);
        event->subscribeId = subscribeId;
    } else {
        event->subscribeId = preSubscribeId;
    }
    if (AddEventKeyCallback(keyCallbacks, event, f, opq) != RET_OK) {
        MMI_HILOGE("AddEventKeyCallback failed");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "AddEventKeyCallback failed");
    }
}

void UnsubscribeKey(KeyOptions const& keyOptions, optional_view<uintptr_t> opq)
{
    CALL_DEBUG_ENTER;
    std::shared_ptr<KeyEventMonitorInfo> event = std::make_shared<KeyEventMonitorInfo>();
    CHKPV(event);
    auto keyOption = std::make_shared<KeyOption>();
    CHKPV(keyOption);
    int32_t subscribeId = -1;
    if (GetEventInfoAPI9(keyOptions, event, keyOption) != RET_OK) {
        MMI_HILOGE("GetEventInfoAPI9 failed");
        return;
    }
    if (DelEventCallback(keyCallbacks, event, opq, subscribeId) < 0) {
        MMI_HILOGE("DelEventCallback failed");
        return;
    }
    MMI_HILOGI("Unsubscribe key event(%{public}d)", subscribeId);
    InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId);
}

void onKeyImpl(KeyOptions const& keyOptions, callback_view<void(KeyOptions const&)> f, uintptr_t opq)
{
    SubscribeKey(keyOptions, f, opq);
}

void offKeyImpl(KeyOptions const& keyOptions, optional_view<uintptr_t> opq)
{
    UnsubscribeKey(keyOptions, opq);
}

void onHotkeyChangeImpl(HotkeyOptions const& hotkeyOptions, callback_view<void(HotkeyOptions const&)> f, uintptr_t opq)
{
    SubscribeHotkey(hotkeyOptions, f, opq);
}

void offHotkeyChangeImpl(HotkeyOptions const& hotkeyOptions, optional_view<uintptr_t> opq)
{
    UnsubscribeHotkey(hotkeyOptions, opq);
}

void onKeyPressedImpl(KeyPressedConfig const& options,
    callback_view<void(ohos::multimodalInput::keyEvent::KeyEvent const&)> f, uintptr_t opq)
{
    SubscribeKeyMonitor(options, f, opq);
}

void offKeyPressedImpl(optional_view<uintptr_t> opq)
{
    if (opq.has_value()) {
        MMI_HILOGI("[ETS] Unsubscribe key monitor");
        UnsubscribeKeyMonitor(opq);
    } else {
        UnsubscribeKeyMonitors();
    }
}

void SetShieldStatus(::ohos::multimodalInput::inputConsumer::ShieldMode shieldMode, bool isShield)
{
    OHOS::MMI::SHIELD_MODE mode = static_cast<OHOS::MMI::SHIELD_MODE>(shieldMode.get_value());
    if (mode < FACTORY_MODE || mode > OOBE_MODE) {
        MMI_HILOGE("Undefined shield mode");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Shield mode does not exist");
        return;
    }
    int32_t ret = InputManager::GetInstance()->SetShieldStatus(shieldMode, isShield);
    HandleCommonErrors(ret);
}

bool GetShieldStatus(::ohos::multimodalInput::inputConsumer::ShieldMode shieldMode)
{
    bool isShield { false };
    OHOS::MMI::SHIELD_MODE mode = static_cast<OHOS::MMI::SHIELD_MODE>(shieldMode.get_value());
    if (mode < FACTORY_MODE || mode > OOBE_MODE) {
        MMI_HILOGE("Undefined shield mode");
        taihe::set_business_error(COMMON_PARAMETER_ERROR, "Shield mode does not exist");
        return isShield;
    }

    auto ret = InputManager::GetInstance()->GetShieldStatus(shieldMode, isShield);
    HandleCommonErrors(ret);
    return true;
}

::taihe::array<inputConsumer::HotkeyOptions> GetAllSystemHotkeysSync()
{
    std::vector<std::unique_ptr<KeyOption>> keyOptions;
    int32_t count = 0;
    std::vector<inputConsumer::HotkeyOptions> result;
    auto ret = InputManager::GetInstance()->GetAllSystemHotkeys(keyOptions, count);
    if (ret != RET_OK) {
        int32_t errorCode = std::abs(ret);
        if (errorCode == COMMON_USE_SYSAPI_ERROR) {
            MMI_HILOGE("Non system applications use system API");
            taihe::set_business_error(COMMON_USE_SYSAPI_ERROR,
                "Permission denied, non-system application called system api.");
        } else if (errorCode == COMMON_PERMISSION_CHECK_ERROR) {
            MMI_HILOGE("Shield api need ohos.permission.INPUT_CONTROL_DISPATCHING");
            taihe::set_business_error(COMMON_PERMISSION_CHECK_ERROR,
                "Permission denied,forbidden by permission");
        } else {
            taihe::set_business_error(COMMON_PARAMETER_ERROR, "Parameter error.");
        }
        return taihe::array<inputConsumer::HotkeyOptions>(result);
    }
    for (auto &iter : keyOptions) {
        auto tmpOpts = ConvertTaiheHotkeyOptions(std::move(iter));
        result.push_back(tmpOpts);
    }
    return  taihe::array<inputConsumer::HotkeyOptions>(result);
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_onKeyImpl(onKeyImpl);
TH_EXPORT_CPP_API_offKeyImpl(offKeyImpl);
TH_EXPORT_CPP_API_onHotkeyChangeImpl(onHotkeyChangeImpl);
TH_EXPORT_CPP_API_offHotkeyChangeImpl(offHotkeyChangeImpl);
TH_EXPORT_CPP_API_onKeyPressedImpl(onKeyPressedImpl);
TH_EXPORT_CPP_API_offKeyPressedImpl(offKeyPressedImpl);
TH_EXPORT_CPP_API_SetShieldStatus(SetShieldStatus);
TH_EXPORT_CPP_API_GetShieldStatus(GetShieldStatus);
TH_EXPORT_CPP_API_GetAllSystemHotkeysSync(GetAllSystemHotkeysSync);
// NOLINTEND