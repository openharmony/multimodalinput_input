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

#include "js_register_module.h"

#include <algorithm>
#include <cinttypes>

#include "input_manager.h"
#include "js_register_util.h"
#include "napi_constants.h"
#include "util_napi.h"
#include "util_napi_error.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JSRegisterModule"

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t EVENT_NAME_LEN { 64 };
constexpr size_t PRE_KEYS_SIZE { 4 };
constexpr size_t INPUT_PARAMETER_MIDDLE { 2 };
constexpr size_t INPUT_PARAMETER_MAX { 3 };
} // namespace

static Callbacks callbacks = {};
static std::mutex sCallBacksMutex;

bool JsCommon::TypeOf(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype valueType = napi_undefined;
    CHKRF(napi_typeof(env, value, &valueType), TYPEOF);
    if (valueType != type) {
        return false;
    }
    return true;
}

void JsCommon::ThrowError(napi_env env, int32_t code)
{
    int32_t errorCode = std::abs(code);
    if (errorCode == COMMON_USE_SYSAPI_ERROR) {
        MMI_HILOGE("Non system applications use system API");
        THROWERR_CUSTOM(env, COMMON_USE_SYSAPI_ERROR, "Non system applications use system API");
    } else if (errorCode == COMMON_PERMISSION_CHECK_ERROR) {
        MMI_HILOGE("Shield api need ohos.permission.INPUT_CONTROL_DISPATCHING");
        THROWERR_API9(env, COMMON_PERMISSION_CHECK_ERROR, "shiled API", "ohos.permission.INPUT_CONTROL_DISPATCHING");
    } else {
        MMI_HILOGE("Dispatch control failed");
    }
}

napi_value GetEventInfoAPI9(napi_env env, napi_callback_info info, KeyEventMonitorInfo* event,
    std::shared_ptr<KeyOption> keyOption)
{
    CALL_DEBUG_ENTER;
    CHKPP(event);
    CHKPP(keyOption);
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
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
    CHKRP(napi_get_value_string_utf8(env, argv[0], eventType, EVENT_NAME_LEN - 1, &typeLen), GET_VALUE_STRING_UTF8);
    std::string type = eventType;
    if (type != SUBSCRIBE_TYPE) {
        MMI_HILOGE("Type is not key");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "type must be key");
        return nullptr;
    }
    napi_value receiveValue = nullptr;
    CHKRP(napi_get_named_property(env, argv[1], "preKeys", &receiveValue), GET_NAMED_PROPERTY);
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
        (isFinalKeyDown == true ? 1 : 0), subKeyNames.c_str());
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
    bool isRepeat = true;
    if (!GetNamedPropertyBool(env, argv[1], "isRepeat", isRepeat)) {
        MMI_HILOGD("IsRepeat field is default");
    }
    subKeyNames += std::to_string(isRepeat);
    subKeyNames += ",";
    keyOption->SetRepeat(isRepeat);
    MMI_HILOGD("IsRepeat:%{public}s", (isRepeat ? "true" : "false"));
    if (argc == INPUT_PARAMETER_MAX) {
        CHKRP(napi_typeof(env, argv[INPUT_PARAMETER_MIDDLE], &valueType), TYPEOF);
        if (valueType != napi_function) {
            MMI_HILOGE("The third parameter is not napi_function");
            THROWERR_API9(env, COMMON_PARAMETER_ERROR, "callback", "function");
            return nullptr;
        }
        CHKRP(napi_create_reference(env, argv[INPUT_PARAMETER_MIDDLE], 1, &event->callback), REFERENCE_REF);
    } else {
        event->callback = nullptr;
    }
    napi_value ret;
    CHKRP(napi_create_int32(env, RET_OK, &ret), CREATE_INT32);
    return ret;
}

static bool IsMatchKeyAction(bool isFinalKeydown, int32_t keyAction)
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
        MMI_HILOGD("Param invalid");
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
    MMI_HILOGD("kevEventSize:%{public}d, infoSize:%{public}d", count, infoSize);
    std::optional<KeyEvent::KeyItem> keyItem = keyEvent->GetKeyItem();
    if (!keyItem) {
        MMI_HILOGE("The keyItem is nullopt");
        return false;
    }
    auto downTime = keyItem->GetDownTime();
    auto upTime = keyEvent->GetActionTime();
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
    std::lock_guard guard(sCallBacksMutex);
    auto iter = callbacks.begin();
    while (iter != callbacks.end()) {
        auto &list = iter->second;
        ++iter;
        MMI_HILOGD("list size:%{public}zu", list.size());
        auto infoIter = list.begin();
        while (infoIter != list.end()) {
            auto monitorInfo = *infoIter;
            if (MatchCombinationKeys(monitorInfo, keyEvent)) {
                EmitAsyncCallbackWork(monitorInfo);
            }
            ++infoIter;
        }
    }
}

static napi_value JsOn(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    std::lock_guard guard(sCallBacksMutex);
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < INPUT_PARAMETER_MAX) {
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
        MMI_HILOGD("eventType:%{public}s, eventName:%{public}s", event->eventType.c_str(), event->name.c_str());
        int32_t subscribeId = -1;
        subscribeId = InputManager::GetInstance()->SubscribeKeyEvent(keyOption, SubKeyEventCallback);
        if (subscribeId < 0) {
            MMI_HILOGE("SubscribeId invalid:%{public}d", subscribeId);
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
    std::lock_guard guard(sCallBacksMutex);
    size_t argc = 3;
    napi_value argv[3] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < INPUT_PARAMETER_MIDDLE) {
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
    delete event;
    return nullptr;
}

static napi_value SetShieldStatus(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 2;
    napi_value argv[2] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < INPUT_PARAMETER_MIDDLE) {
        MMI_HILOGE("At least two parameters is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "shieldMode", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("shieldMode parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "shieldMode", "number");
        return nullptr;
    }
    int32_t shieldMode = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &shieldMode), GET_VALUE_INT32);
    if (shieldMode < FACTORY_MODE || shieldMode > OOBE_MODE) {
        MMI_HILOGE("Undefined shield mode");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Shield mode does not exist");
        return nullptr;
    }

    if (!JsCommon::TypeOf(env, argv[1], napi_boolean)) {
        MMI_HILOGE("isShield parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "isShield", "boolean");
        return nullptr;
    }
    bool isShield = true;
    CHKRP(napi_get_value_bool(env, argv[1], &isShield), GET_VALUE_BOOL);

    int32_t errCode = InputManager::GetInstance()->SetShieldStatus(shieldMode, isShield);
    JsCommon::ThrowError(env, errCode);
    napi_value result = nullptr;
    if (napi_get_undefined(env, &result) != napi_ok) {
        MMI_HILOGE("Get undefined result is failed");
        return nullptr;
    }
    return result;
}

static napi_value GetShieldStatus(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    CHKRP(napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), GET_CB_INFO);
    if (argc < 1) {
        MMI_HILOGE("At least 1 parameter is required");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "shieldMode", "number");
        return nullptr;
    }
    if (!JsCommon::TypeOf(env, argv[0], napi_number)) {
        MMI_HILOGE("shieldMode parameter type is invalid");
        THROWERR_API9(env, COMMON_PARAMETER_ERROR, "shieldMode", "number");
        return nullptr;
    }
    int32_t shieldMode = 0;
    CHKRP(napi_get_value_int32(env, argv[0], &shieldMode), GET_VALUE_INT32);
    if (shieldMode < FACTORY_MODE || shieldMode > OOBE_MODE) {
        MMI_HILOGE("Undefined shield mode");
        THROWERR_CUSTOM(env, COMMON_PARAMETER_ERROR, "Shield mode does not exist");
        return nullptr;
    }
    bool isShield { false };
    auto errCode = InputManager::GetInstance()->GetShieldStatus(shieldMode, isShield);
    JsCommon::ThrowError(env, errCode);
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_boolean(env, isShield, &result));
    return result;
}

static napi_value EnumConstructor(napi_env env, napi_callback_info info)
{
    CALL_DEBUG_ENTER;
    size_t argc = 0;
    napi_value args[1] = { 0 };
    napi_value ret = nullptr;
    void *data = nullptr;
    CHKRP(napi_get_cb_info(env, info, &argc, args, &ret, &data), GET_CB_INFO);
    return ret;
}

static napi_value CreateShieldMode(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_value factory_mode = nullptr;
    CHKRP(napi_create_int32(env, SHIELD_MODE::FACTORY_MODE, &factory_mode), CREATE_INT32);
    napi_value oobe_mode = nullptr;
    CHKRP(napi_create_int32(env, SHIELD_MODE::OOBE_MODE, &oobe_mode), CREATE_INT32);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("FACTORY_MODE", factory_mode),
        DECLARE_NAPI_STATIC_PROPERTY("OOBE_MODE", oobe_mode),
    };
    napi_value result = nullptr;
    CHKRP(napi_define_class(env, "ShieldMode", NAPI_AUTO_LENGTH, EnumConstructor, nullptr,
        sizeof(desc) / sizeof(*desc), desc, &result), DEFINE_CLASS);
    CHKRP(napi_set_named_property(env, exports, "ShieldMode", result), SET_NAMED_PROPERTY);
    return exports;
}

KeyEventMonitorInfo::~KeyEventMonitorInfo()
{
    if (callback == nullptr) {
        return;
    }
    uint32_t refcount = 0;
    CHKRV(napi_reference_unref(env, callback, &refcount), REFERENCE_UNREF);
    if (refcount == 0) {
        CHKRV(napi_delete_reference(env, callback), DELETE_REFERENCE);
    }
    callback = nullptr;
}

EXTERN_C_START
static napi_value MmiInit(napi_env env, napi_value exports)
{
    CALL_DEBUG_ENTER;
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("on", JsOn),
        DECLARE_NAPI_FUNCTION("off", JsOff),
        DECLARE_NAPI_FUNCTION("setShieldStatus", SetShieldStatus),
        DECLARE_NAPI_FUNCTION("getShieldStatus", GetShieldStatus)
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    if (CreateShieldMode(env, exports) == nullptr) {
        THROWERR(env, "Failed to create shield mode");
        return nullptr;
    }
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
