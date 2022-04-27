/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "js_util.h"

#include "mmi_log.h"
#include "util_napi.h"

namespace OHOS {
namespace MMI {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "JsUtil" };
const std::string GET_REFERENCE = "napi_get_reference_value";
const std::string STRICT_EQUALS = "napi_strict_equals";
const std::string DELETE_REFERENCE = "napi_delete_reference";
const std::string CREATE_ARRAY = "napi_create_array";
const std::string CREATE_INT32 = "napi_create_int32";
const std::string SET_ELEMENT = "napi_set_element";
const std::string SET_NAMED_PROPERTY = "napi_set_named_property";
const std::string CREATE_STRING_UTF8 = "napi_create_string_utf8";
const std::string CREATE_OBJECT = "napi_create_object";
const std::string DELETE_ASYNC_WORK = "napi_delete_async_work";

constexpr int32_t ABS_MT_TOUCH_MAJOR = 0x30;
constexpr int32_t ABS_MT_TOUCH_MINOR = 0x31;
constexpr int32_t ABS_MT_ORIENTATION = 0x34;
constexpr int32_t ABS_MT_POSITION_X  = 0x35;
constexpr int32_t ABS_MT_POSITION_Y = 0x36;
constexpr int32_t ABS_MT_PRESSURE = 0x3a;
constexpr int32_t ABS_MT_WIDTH_MAJOR = 0x32;
constexpr int32_t ABS_MT_WIDTH_MINOR = 0x33;

JsUtil::AxisType g_axisType[] = {
    {"touchMajor", ABS_MT_TOUCH_MAJOR},
    {"touchMinor", ABS_MT_TOUCH_MINOR},
    {"orientation", ABS_MT_ORIENTATION},
    {"x", ABS_MT_POSITION_X},
    {"y", ABS_MT_POSITION_Y},
    {"pressure", ABS_MT_PRESSURE},
    {"toolMajor", ABS_MT_WIDTH_MAJOR},
    {"toolMinor", ABS_MT_WIDTH_MINOR},
};

constexpr uint32_t EVDEV_UDEV_TAG_KEYBOARD = (1 << 1);
constexpr uint32_t EVDEV_UDEV_TAG_MOUSE = (1 << 2);
constexpr uint32_t EVDEV_UDEV_TAG_TOUCHPAD = (1 << 3);
constexpr uint32_t EVDEV_UDEV_TAG_TOUCHSCREEN = (1 << 4);
constexpr uint32_t EVDEV_UDEV_TAG_JOYSTICK = (1 << 6);
constexpr uint32_t EVDEV_UDEV_TAG_TRACKBALL = (1 << 10);

JsUtil::DeviceType g_deviceType[] = {
    {"keyboard", EVDEV_UDEV_TAG_KEYBOARD},
    {"mouse", EVDEV_UDEV_TAG_MOUSE},
    {"touchpad", EVDEV_UDEV_TAG_TOUCHPAD},
    {"touchscreen", EVDEV_UDEV_TAG_TOUCHSCREEN},
    {"joystick", EVDEV_UDEV_TAG_JOYSTICK},
    {"trackball", EVDEV_UDEV_TAG_TRACKBALL},
};
} // namespace
bool JsUtil::IsHandleEquals(napi_env env, napi_value handle, napi_ref ref)
{
    napi_value handlerTemp = nullptr;
    CHKRF(env, napi_get_reference_value(env, ref, &handlerTemp), GET_REFERENCE);
    bool isEqual = false;
    CHKRF(env, napi_strict_equals(env, handle, handlerTemp, &isEqual), STRICT_EQUALS);
    return isEqual;
}

bool JsUtil::GetDeviceInfo(std::unique_ptr<CallbackInfo> &cbTemp, napi_value &object)
{
    CHKPF(cbTemp);
    CHKPF(cbTemp->env);
    napi_value id = nullptr;
    CHKRF(cbTemp->env, napi_create_int32(cbTemp->env, cbTemp->data.device->id, &id), CREATE_INT32);
    napi_value name = nullptr;
    CHKRF(cbTemp->env, napi_create_string_utf8(cbTemp->env, (cbTemp->data.device->name).c_str(),
        NAPI_AUTO_LENGTH, &name), CREATE_STRING_UTF8);
    CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, object, "id", id), SET_NAMED_PROPERTY);
    CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, object, "name", name), SET_NAMED_PROPERTY);
    napi_value busType = nullptr;
    CHKRF(cbTemp->env, napi_create_int32(cbTemp->env, cbTemp->data.device->busType, &busType), CREATE_INT32);
    CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, object, "bus", busType), SET_NAMED_PROPERTY);
    napi_value product = nullptr;
    CHKRF(cbTemp->env, napi_create_int32(cbTemp->env, cbTemp->data.device->product, &product), CREATE_INT32);
    CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, object, "product", product), SET_NAMED_PROPERTY);
    napi_value vendor = nullptr;
    CHKRF(cbTemp->env, napi_create_int32(cbTemp->env, cbTemp->data.device->vendor, &vendor), CREATE_INT32);
    CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, object, "vendor", vendor), SET_NAMED_PROPERTY);
    napi_value version = nullptr;
    CHKRF(cbTemp->env, napi_create_int32(cbTemp->env, cbTemp->data.device->version, &version), CREATE_INT32);
    CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, object, "version", version), SET_NAMED_PROPERTY);
    napi_value uniq = nullptr;
    CHKRF(cbTemp->env, napi_create_string_utf8(cbTemp->env, (cbTemp->data.device->uniq).c_str(),
        NAPI_AUTO_LENGTH, &uniq), CREATE_STRING_UTF8);
    CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, object, "uniq", uniq), SET_NAMED_PROPERTY);
    napi_value phys = nullptr;
    CHKRF(cbTemp->env, napi_create_string_utf8(cbTemp->env, (cbTemp->data.device->phys).c_str(),
        NAPI_AUTO_LENGTH, &phys), CREATE_STRING_UTF8);
    CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, object, "phys", phys), SET_NAMED_PROPERTY);

    if (!GetDeviceSourceType(cbTemp, object)) {
        MMI_HILOGE("get device source type info failed");
        return false;
    }
    if (!GetDeviceAxisInfo(cbTemp, object)) {
        MMI_HILOGE("get device axis info failed");
        return false;
    }
    return true;
}

bool JsUtil::GetDeviceAxisInfo(std::unique_ptr<CallbackInfo> &cbTemp, napi_value &object)
{
    CHKPF(cbTemp);
    CHKPF(cbTemp->env);
    napi_value sourceType = nullptr;
    uint32_t types = cbTemp->data.device->devcieType;
    for (const auto & item : g_deviceType) {
        if (types & item.typeBit) {
            CHKRF(cbTemp->env, napi_create_string_utf8(cbTemp->env, item.sourceTypeName.c_str(),
                NAPI_AUTO_LENGTH, &sourceType), CREATE_STRING_UTF8);
            break;
        }
    }
    napi_value axisRanges = nullptr;
    CHKRF(cbTemp->env, napi_create_array(cbTemp->env, &axisRanges), CREATE_ARRAY);
    napi_value axisRange = nullptr;
    uint32_t i = 0;
    for (const auto &item : cbTemp->data.device->axis) {
        for (const auto &axisTemp : g_axisType) {
            if (item.axisType == axisTemp.axisType) {
                CHKRF(cbTemp->env, napi_create_object(cbTemp->env, &axisRange), CREATE_OBJECT);
                CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, axisRange, "source", sourceType),
                    SET_NAMED_PROPERTY);
                napi_value axisType = nullptr;
                CHKRF(cbTemp->env, napi_create_string_utf8(cbTemp->env, axisTemp.axisTypeName.c_str(),
                    NAPI_AUTO_LENGTH, &axisType), CREATE_STRING_UTF8);
                CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, axisRange, "axis", axisType),
                    SET_NAMED_PROPERTY);
                napi_value min = nullptr;
                CHKRF(cbTemp->env, napi_create_int32(cbTemp->env, item.min, &min), CREATE_INT32);
                CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, axisRange, "min", min), SET_NAMED_PROPERTY);
                napi_value max = nullptr;
                CHKRF(cbTemp->env, napi_create_int32(cbTemp->env, item.max, &max), CREATE_INT32);
                CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, axisRange, "max", max), SET_NAMED_PROPERTY);
                napi_value fuzz = nullptr;
                CHKRF(cbTemp->env, napi_create_int32(cbTemp->env, item.fuzz, &fuzz), CREATE_INT32);
                CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, axisRange, "fuzz", fuzz), SET_NAMED_PROPERTY);
                napi_value flat = nullptr;
                CHKRF(cbTemp->env, napi_create_int32(cbTemp->env, item.flat, &flat), CREATE_INT32);
                CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, axisRange, "flat", flat), SET_NAMED_PROPERTY);
                napi_value resolution = nullptr;
                CHKRF(cbTemp->env, napi_create_int32(cbTemp->env, item.resolution, &resolution), CREATE_INT32);
                CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, axisRange, "resolution", resolution),
                    SET_NAMED_PROPERTY);
                CHKRF(cbTemp->env, napi_set_element(cbTemp->env, axisRanges, i, axisRange), SET_ELEMENT);
                ++i;
            }
        }
    }
    CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, object, "axisRanges", axisRanges), SET_NAMED_PROPERTY);
    return true;
}

bool JsUtil::GetDeviceSourceType(std::unique_ptr<CallbackInfo> &cbTemp, napi_value &object)
{
    CHKPF(cbTemp);
    CHKPF(cbTemp->env);
    uint32_t types = cbTemp->data.device->devcieType;
    std::vector<std::string> sources;
    for (const auto & item : g_deviceType) {
        if (types & item.typeBit) {
            sources.push_back(item.sourceTypeName);
        }
    }
    napi_value devSources = nullptr;
    CHKRF(cbTemp->env, napi_create_array(cbTemp->env, &devSources), CREATE_ARRAY);
    napi_value value = nullptr;
    for (size_t i = 0; i < sources.size(); ++i) {
        CHKRF(cbTemp->env, napi_create_string_utf8(cbTemp->env, sources[i].c_str(), NAPI_AUTO_LENGTH, &value),
            CREATE_STRING_UTF8);
        CHKRF(cbTemp->env, napi_set_element(cbTemp->env, devSources, i, value), SET_ELEMENT);
    }
    CHKRF(cbTemp->env, napi_set_named_property(cbTemp->env, object, "sources", devSources), SET_NAMED_PROPERTY);
    return true;
}

JsUtil::CallbackInfo::CallbackInfo() {}

JsUtil::CallbackInfo::~CallbackInfo()
{
    CALL_LOG_ENTER;
    if (ref != nullptr && env != nullptr) {
        CHKRV(env, napi_delete_reference(env, ref), DELETE_REFERENCE);
        env = nullptr;
    }
}

AsyncContext::~AsyncContext()
{
    CALL_LOG_ENTER;
    if (work != nullptr) {
        CHKRV(env, napi_delete_async_work(env, work), DELETE_ASYNC_WORK);
    }
    if (callback != nullptr && env != nullptr) {
        CHKRV(env, napi_delete_reference(env, callback), DELETE_REFERENCE);
        env = nullptr;
    }
}
} // namespace MMI
} // namespace OHOS