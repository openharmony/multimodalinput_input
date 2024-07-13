/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "js_util.h"

#include <linux/input.h>

#include "mmi_log.h"
#include "napi_constants.h"
#include "util_napi.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "JsUtil"

namespace OHOS {
namespace MMI {
namespace {
std::map<int32_t, std::string> axisType = {
    { ABS_MT_TOUCH_MAJOR, "touchmajor" },
    { ABS_MT_TOUCH_MINOR, "touchminor" },
    { ABS_MT_ORIENTATION, "orientation" },
    { ABS_MT_POSITION_X, "x" },
    { ABS_MT_POSITION_Y, "y" },
    { ABS_MT_PRESSURE, "pressure" },
    { ABS_MT_WIDTH_MAJOR, "toolmajor" },
    { ABS_MT_WIDTH_MINOR, "toolminor" },
};

constexpr uint32_t EVDEV_UDEV_TAG_TOUCHSCREEN = (1 << 4);
constexpr uint32_t EVDEV_UDEV_TAG_JOYSTICK = (1 << 6);
constexpr uint32_t EVDEV_UDEV_TAG_TRACKBALL = (1 << 10);

JsUtil::DeviceType g_deviceType[] = {
    { "keyboard", EVDEV_UDEV_TAG_KEYBOARD },
    { "mouse", EVDEV_UDEV_TAG_MOUSE },
    { "touchpad", EVDEV_UDEV_TAG_TOUCHPAD },
    { "touchscreen", EVDEV_UDEV_TAG_TOUCHSCREEN },
    { "joystick", EVDEV_UDEV_TAG_JOYSTICK },
    { "trackball", EVDEV_UDEV_TAG_TRACKBALL },
};
} // namespace
bool JsUtil::IsSameHandle(napi_env env, napi_value handle, napi_ref ref)
{
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    napi_value handlerTemp = nullptr;
    CHKRF(napi_get_reference_value(env, ref, &handlerTemp), GET_REFERENCE_VALUE);
    bool isEqual = false;
    CHKRF(napi_strict_equals(env, handle, handlerTemp, &isEqual), STRICT_EQUALS);
    napi_close_handle_scope(env, scope);
    return isEqual;
}

napi_value JsUtil::GetDeviceInfo(sptr<CallbackInfo> cb)
{
    CHKPP(cb);
    CHKPP(cb->env);
    CHKPP(cb->data.device);
    napi_value object = nullptr;
    CHKRP(napi_create_object(cb->env, &object), CREATE_OBJECT);
    napi_value id = nullptr;
    CHKRP(napi_create_int32(cb->env, cb->data.device->GetId(), &id), CREATE_INT32);
    napi_value name = nullptr;
    CHKRP(napi_create_string_utf8(cb->env, (cb->data.device->GetName()).c_str(),
        NAPI_AUTO_LENGTH, &name), CREATE_STRING_UTF8);
    CHKRP(napi_set_named_property(cb->env, object, "id", id), SET_NAMED_PROPERTY);
    CHKRP(napi_set_named_property(cb->env, object, "name", name), SET_NAMED_PROPERTY);
    napi_value busType = nullptr;
    CHKRP(napi_create_int32(cb->env, cb->data.device->GetBus(), &busType), CREATE_INT32);
    CHKRP(napi_set_named_property(cb->env, object, "bus", busType), SET_NAMED_PROPERTY);
    napi_value product = nullptr;
    CHKRP(napi_create_int32(cb->env, cb->data.device->GetProduct(), &product), CREATE_INT32);
    CHKRP(napi_set_named_property(cb->env, object, "product", product), SET_NAMED_PROPERTY);
    napi_value vendor = nullptr;
    CHKRP(napi_create_int32(cb->env, cb->data.device->GetVendor(), &vendor), CREATE_INT32);
    CHKRP(napi_set_named_property(cb->env, object, "vendor", vendor), SET_NAMED_PROPERTY);
    napi_value version = nullptr;
    CHKRP(napi_create_int32(cb->env, cb->data.device->GetVersion(), &version), CREATE_INT32);
    CHKRP(napi_set_named_property(cb->env, object, "version", version), SET_NAMED_PROPERTY);
    napi_value uniq = nullptr;
    CHKRP(napi_create_string_utf8(cb->env, (cb->data.device->GetUniq()).c_str(),
        NAPI_AUTO_LENGTH, &uniq), CREATE_STRING_UTF8);
    CHKRP(napi_set_named_property(cb->env, object, "uniq", uniq), SET_NAMED_PROPERTY);
    napi_value phys = nullptr;
    CHKRP(napi_create_string_utf8(cb->env, (cb->data.device->GetPhys()).c_str(),
        NAPI_AUTO_LENGTH, &phys), CREATE_STRING_UTF8);
    CHKRP(napi_set_named_property(cb->env, object, "phys", phys), SET_NAMED_PROPERTY);

    if (!GetDeviceSourceType(cb, object)) {
        MMI_HILOGE("Get device source type failed");
        return nullptr;
    }
    if (!GetDeviceAxisInfo(cb, object)) {
        MMI_HILOGE("Get device axis failed");
        return nullptr;
    }
    return object;
}

bool JsUtil::GetDeviceAxisInfo(sptr<CallbackInfo> cb, napi_value &object)
{
    CHKPF(cb);
    CHKPF(cb->env);
    CHKPF(cb->data.device);
    napi_value sourceType = nullptr;
    uint32_t types = static_cast<uint32_t>(cb->data.device->GetType());
    for (const auto &item : g_deviceType) {
        if (types &item.typeBit) {
            CHKRF(napi_create_string_utf8(cb->env, item.sourceTypeName.c_str(),
                NAPI_AUTO_LENGTH, &sourceType), CREATE_STRING_UTF8);
            break;
        }
    }
    napi_value axisRanges = nullptr;
    CHKRF(napi_create_array(cb->env, &axisRanges), CREATE_ARRAY);
    if (sourceType == nullptr) {
        CHKRF(napi_set_named_property(cb->env, object, "axisRanges", axisRanges), SET_NAMED_PROPERTY);
        MMI_HILOGD("SourceType not found");
        return true;
    }
    napi_value axisRange = nullptr;
    uint32_t i = 0;
    for (const auto &item : cb->data.device->GetAxisInfo()) {
        auto iter = axisType.find(item.GetAxisType());
        if (iter == axisType.end()) {
            MMI_HILOGD("Find axisType failed");
            continue;
        }
        CHKRF(napi_create_object(cb->env, &axisRange), CREATE_OBJECT);
        CHKRF(napi_set_named_property(cb->env, axisRange, "source", sourceType), SET_NAMED_PROPERTY);
        napi_value axisType = nullptr;
        CHKRF(napi_create_string_utf8(cb->env, iter->second.c_str(),
            NAPI_AUTO_LENGTH, &axisType), CREATE_STRING_UTF8);
        CHKRF(napi_set_named_property(cb->env, axisRange, "axis", axisType), SET_NAMED_PROPERTY);
        napi_value min = nullptr;
        CHKRF(napi_create_int32(cb->env, item.GetMinimum(), &min), CREATE_INT32);
        CHKRF(napi_set_named_property(cb->env, axisRange, "min", min), SET_NAMED_PROPERTY);
        napi_value max = nullptr;
        CHKRF(napi_create_int32(cb->env, item.GetMaximum(), &max), CREATE_INT32);
        CHKRF(napi_set_named_property(cb->env, axisRange, "max", max), SET_NAMED_PROPERTY);
        napi_value fuzz = nullptr;
        CHKRF(napi_create_int32(cb->env, item.GetFuzz(), &fuzz), CREATE_INT32);
        CHKRF(napi_set_named_property(cb->env, axisRange, "fuzz", fuzz), SET_NAMED_PROPERTY);
        napi_value flat = nullptr;
        CHKRF(napi_create_int32(cb->env, item.GetFlat(), &flat), CREATE_INT32);
        CHKRF(napi_set_named_property(cb->env, axisRange, "flat", flat), SET_NAMED_PROPERTY);
        napi_value resolution = nullptr;
        CHKRF(napi_create_int32(cb->env, item.GetResolution(), &resolution), CREATE_INT32);
        CHKRF(napi_set_named_property(cb->env, axisRange, "resolution", resolution), SET_NAMED_PROPERTY);
        CHKRF(napi_set_element(cb->env, axisRanges, i, axisRange), SET_ELEMENT);
        ++i;
    }
    CHKRF(napi_set_named_property(cb->env, object, "axisRanges", axisRanges), SET_NAMED_PROPERTY);
    return true;
}

bool JsUtil::GetDeviceSourceType(sptr<CallbackInfo> cb, napi_value &object)
{
    CHKPF(cb);
    CHKPF(cb->env);
    CHKPF(cb->data.device);
    uint32_t types = static_cast<uint32_t>(cb->data.device->GetType());
    std::vector<std::string> sources;
    for (const auto &item : g_deviceType) {
        if (types &item.typeBit) {
            sources.push_back(item.sourceTypeName);
        }
    }
    napi_value devSources = nullptr;
    CHKRF(napi_create_array(cb->env, &devSources), CREATE_ARRAY);
    napi_value value = nullptr;
    for (size_t i = 0; i < sources.size(); ++i) {
        CHKRF(napi_create_string_utf8(cb->env, sources[i].c_str(), NAPI_AUTO_LENGTH, &value),
            CREATE_STRING_UTF8);
        CHKRF(napi_set_element(cb->env, devSources, i, value), SET_ELEMENT);
    }
    CHKRF(napi_set_named_property(cb->env, object, "sources", devSources), SET_NAMED_PROPERTY);
    return true;
}

bool JsUtil::TypeOf(napi_env env, napi_value value, napi_valuetype type)
{
    napi_valuetype valueType = napi_undefined;
    CHKRF(napi_typeof(env, value, &valueType), TYPEOF);
    if (valueType != type) {
        return false;
    }
    return true;
}

void JsUtil::DeleteCallbackInfo(std::unique_ptr<CallbackInfo> callback)
{
    CALL_DEBUG_ENTER;
    if (callback->ref != nullptr && callback->env != nullptr) {
        CHKRV(napi_delete_reference(callback->env, callback->ref), DELETE_REFERENCE);
        callback->env = nullptr;
    }
}
} // namespace MMI
} // namespace OHOS