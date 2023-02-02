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

#include "js_register_module.h"

#include <algorithm>
#include <cinttypes>

#include "input_manager.h"
#include "js_register_util.h"
#include "napi_constants.h"
#include "util_napi_error.h"
#include "util_napi.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JSRegisterModule" };
constexpr size_t EVENT_NAME_LEN = 64;
constexpr size_t PRE_KEYS_SIZE = 4;
} // namespace

static Callbacks callbacks = {};

napi_value GetEventInfoAPI9(napi_env env, napi_callback_info info, KeyEventMonitorInfo* event,
    std::shared_ptr<KeyOption> keyOption)
{
    CALL_DEBUG_ENTER;
    CHKPP(event);
    CHKPP(keyOption);
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    napi_valuetype valueType = napi_undefined;
    if (!UtilNapi::TypeOf(env, argv[0], napi_string)) {
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "type", "string");
        MMI_HILOGE("The first parameter is not string");
        return nullptr;
    }
    if (!UtilNapi::TypeOf(env, argv[1], napi_object)) {
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "keyOptions", "object");
        MMI_HILOGE("The second parameter is not napi_object");
        return nullptr;
    }
    char eventType[EVENT_NAME_LEN] = { 0 };
    size_t typeLen = 0;
    CHKRP(env, napi_get_value_string_utf8(env, argv[0], eventType, EVENT_NAME_LEN - 1, &typeLen), GET_STRING_UTF8);
    std::string type = eventType;
    if (type != SUBSCRIBE_TYPE) {
        MMI_HILOGE("Type is not key");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "type must be key");
        return nullptr;
    }
    napi_value receiveValue = nullptr;
    CHKRP(env, napi_get_named_property(env, argv[1], "preKeys", &receiveValue), GET_NAMED_PROPERTY);
    if (receiveValue == nullptr) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "preKeys not found");
        return nullptr;
    }
    std::set<int32_t> preKeys;
    if (GetPreKeys(env, receiveValue, preKeys) == nullptr) {
        MMI_HILOGE("Get preKeys failed");
        return nullptr;
    }
    if (preKeys.size() > PRE_KEYS_SIZE) {
        MMI_HILOGE("preKeys size invalid");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "preKeys size invalid");
        return nullptr;
    }
    MMI_HILOGD("PreKeys size:%{public}zu", preKeys.size());
    keyOption->SetPreKeys(preKeys);
    std::string subKeyNames = "";
    for (const auto &item : preKeys) {
        subKeyNames += std::to_string(item);
        subKeyNames += ",";
        MMI_HILOGD("preKeys:%{public}d", item);
    }
    std::optional<int32_t> tempFinalKey = GetNamedPropertyInt32(env, argv[1], "finalKey");
    if (!tempFinalKey) {
        MMI_HILOGE("GetNamedPropertyInt32 failed");
        return nullptr;
    }
    int32_t finalKey = tempFinalKey.value();
    if (finalKey < 0) {
        MMI_HILOGE("finalKey:%{public}d is less 0, can not process", finalKey);
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "finalKey must be greater than or equal to 0");
        return nullptr;
    }
    subKeyNames += std::to_string(finalKey);
    subKeyNames += ",";
    keyOption->SetFinalKey(finalKey);
    MMI_HILOGD("FinalKey:%{public}d", finalKey);
    bool isFinalKeyDown;
    if (!GetNamedPropertyBool(env, argv[1], "isFinalKeyDown", isFinalKeyDown)) {
        MMI_HILOGE("GetNamedPropertyBool failed");
        return nullptr;
    }
    subKeyNames += std::to_string(isFinalKeyDown);
    subKeyNames += ",";
    keyOption->SetFinalKeyDown(isFinalKeyDown);
    MMI_HILOGD("IsFinalKeyDown:%{public}d,map_key:%{public}s",
        (isFinalKeyDown == true?1:0), subKeyNames.c_str());
    std::optional<int32_t> tempKeyDownDuration = GetNamedPropertyInt32(env, argv[1], "finalKeyDownDuration");
    if (!tempKeyDownDuration) {
        MMI_HILOGE("GetNamedPropertyInt32 failed");
        return nullptr;
    }
    int32_t finalKeyDownDuration = tempKeyDownDuration.value();
    if (finalKeyDownDuration < 0) {
        MMI_HILOGE("finalKeyDownDuration:%{public}d is less 0, can not process", finalKeyDownDuration);
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "finalKeyDownDuration must be greater than or equal to 0");
        return nullptr;
    }
    subKeyNames += std::to_string(finalKeyDownDuration);
    keyOption->SetFinalKeyDownDuration(finalKeyDownDuration);
    event->eventType = subKeyNames;
    MMI_HILOGD("FinalKeyDownDuration:%{public}d", finalKeyDownDuration);
    if (argc == 3) {
        CHKRP(env, napi_typeof(env, argv[2], &valueType), TYPEOF);
        if (valueType != napi_function) {
            MMI_HILOGE("the third parameter is not napi_function");
            THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
            return nullptr;
        }
        CHKRP(env, napi_create_reference(env, argv[2], 1, &event->callback[0]), REFERENCE_REF);
    } else {
        event->callback[0] = nullptr;
    }
    napi_value ret;
    CHKRP(env, napi_create_int32(env, RET_OK, &ret), CREATE_INT32);
    return ret;
}

static bool IsMatchKeyAction(bool isFinalKeydown, int32_t keyAction)
{
    CALL_DEBUG_ENTER;
    MMI_HILOGD("isFinalKeydown:%{public}d,keyAction:%{public}d", isFinalKeydown, keyAction);
    if (isFinalKeydown && keyAction == KeyEvent::KEY_ACTION_DOWN) {
        return true;
    }

    if (!isFinalKeydown && keyAction == KeyEvent::KEY_ACTION_UP) {
        return true;
    }
    MMI_HILOGE("isFinalKeydown not matched with keyAction");
    return false;
}

static bool MatchCombinationKeys(KeyEventMonitorInfo* monitorInfo, std::shared_ptr<KeyEvent> keyEvent)
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
    MMI_HILOGD("infoFinalKey:%{public}d,keyEventFinalKey:%{public}d", infoFinalKey, keyEventFinalKey);
    if (infoFinalKey != keyEventFinalKey || items.size() > PRE_KEYS_SIZE ||
        !IsMatchKeyAction(isFinalKeydown, keyEvent->GetKeyAction())) {
        MMI_HILOGE("Param invalid");
        return false;
    }
    std::set<int32_t> infoPreKeys = keyOption->GetPreKeys();
    int32_t infoSize = 0;
    auto it = infoPreKeys.begin();
    while (it != infoPreKeys.end()) {
        if (*it >= 0) {
            infoSize++;
        }
        ++it;
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
    MMI_HILOGD("kevEventSize:%{public}d,infoSize:%{public}d", count, infoSize);
    auto keyItem = keyEvent->GetKeyItem();
    CHKPF(keyItem);
    auto upTime = keyEvent->GetActionTime();
    auto downTime = keyItem->GetDownTime();
    auto curDurationTime = keyOption->GetFinalKeyDownDuration();
    if (curDurationTime > 0 && (upTime - downTime >= (static_cast<int64_t>(curDurationTime) * 1000))) {
        MMI_HILOGE("Skip, upTime - downTime >= duration");
        return false;
    }
    return count == infoSize;
}

static void SubKeyEventCallback(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_DEBUG_ENTER;
    CHKPV(keyEvent);
    std::lock_guard guard(sCallBacksMutex_);
    auto iter = callbacks.begin();
    while (iter != callbacks.end()) {
        auto &list = iter->second;
        ++iter;
        MMI_HILOGD("list size:%{public}zu", list.size());
        auto infoIter = list.begin();
        while (infoIter != list.end()) {
            auto monitorInfo = *infoIter;
            if (MatchCombinationKeys(monitorInfo, keyEvent)) {
                monitorInfo->keyEvent = keyEvent;
                EmitAsyncCallbackWork(monitorInfo);
            }
            ++infoIter;
        }
    }
}

static napi_value JsOn(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 3) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "parameter number error");
        return nullptr;
    }
    KeyEventMonitorInfo *event = new (std::nothrow) KeyEventMonitorInfo {
        .env = env,
        .asyncWork = nullptr,
    };
    CHKPP(event);
    auto keyOption = std::make_shared<KeyOption>();
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[0], &valueType) != napi_ok) {
        delete event;
        MMI_HILOGE("Napi typeof failed");
        return nullptr;
    }
    if (GetEventInfoAPI9(env, info, event, keyOption) == nullptr) {
        delete event;
        MMI_HILOGE("GetEventInfo failed");
        return nullptr;
    }
    event->keyOption = keyOption;
    int32_t preSubscribeId = GetPreSubscribeId(callbacks, event);
    if (preSubscribeId < 0) {
        MMI_HILOGD("eventType:%{public}s,eventName:%{public}s", event->eventType.c_str(), event->name.c_str());
        int32_t subscribeId = -1;
        subscribeId = InputManager::GetInstance()->SubscribeKeyEvent(keyOption, SubKeyEventCallback);
        if (subscribeId < 0) {
            MMI_HILOGE("SubscribeId invalid:%{public}d", subscribeId);
            napi_delete_reference(env, event->callback[0]);
            delete event;
            return nullptr;
        }
        MMI_HILOGD("SubscribeId:%{public}d", subscribeId);
        event->subscribeId = subscribeId;
    } else {
        event->subscribeId = preSubscribeId;
    }
    if (AddEventCallback(env, callbacks, event) < 0) {
        delete event;
        MMI_HILOGE("AddEventCallback failed");
        return nullptr;
    }
    return nullptr;
}

static napi_value JsOff(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    CHKRP(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 2) {
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "parameter number error");
        return nullptr;
    }
    KeyEventMonitorInfo *event = new (std::nothrow) KeyEventMonitorInfo {
        .env = env,
        .asyncWork = nullptr,
    };
    CHKPP(event);
    auto keyOption = std::make_shared<KeyOption>();
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, argv[0], &valueType) != napi_ok) {
        delete event;
        MMI_HILOGE("Napi typeof failed");
        return nullptr;
    }
    if (GetEventInfoAPI9(env, info, event, keyOption) == nullptr) {
        delete event;
        MMI_HILOGE("GetEventInfo failed");
        return nullptr;
    }
    int32_t subscribeId = -1;
    if (DelEventCallback(env, callbacks, event, subscribeId) < 0) {
        delete event;
        MMI_HILOGE("DelEventCallback failed");
        return nullptr;
    }
    MMI_HILOGD("SubscribeId:%{public}d", subscribeId);
    if (subscribeId >= 0) {
        InputManager::GetInstance()->UnsubscribeKeyEvent(subscribeId);
    }
    if (event->callback[0] != nullptr) {
        napi_delete_reference(env, event->callback[0]);
    }
    delete event;
    return nullptr;
}

EXTERN_C_START
static napi_value MmiInit(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("on", JsOn),
        DECLARE_NAPI_FUNCTION("off", JsOff),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}
EXTERN_C_END

static napi_module mmiModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = MmiInit,
    .nm_modname = "multimodalInput.inputConsumer",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&mmiModule);
}
} // namespace MMI
} // namespace OHOS