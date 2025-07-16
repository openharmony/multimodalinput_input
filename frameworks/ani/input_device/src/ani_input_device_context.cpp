/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ani_input_device_context.h"

#include <ani.h>
#include <array>
#include <iostream>
#include <linux/input.h>
#include <list>
#include <map>
#include <set>
#include <string>

#include "define_multimodal.h"
#include "input_device.h"
#include "input_manager.h"
#include "mmi_log.h"
#include "napi_constants.h"
#include "oh_input_manager.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniInputDeviceContext"

using namespace OHOS::MMI;

enum AniErrorCode : int32_t {
    COMMON_PARAMETER_ERROR = 401,
};

static std::unordered_map<int32_t, std::string> axisType = {
    { ABS_MT_TOUCH_MAJOR, "touchmajor" }, { ABS_MT_TOUCH_MINOR, "touchminor" }, { ABS_MT_ORIENTATION, "orientation" },
    { ABS_MT_POSITION_X, "x" },           { ABS_MT_POSITION_Y, "y" },           { ABS_MT_PRESSURE, "pressure" },
    { ABS_MT_WIDTH_MAJOR, "toolmajor" },  { ABS_MT_WIDTH_MINOR, "toolminor" },
};


constexpr uint32_t EVDEV_UDEV_TAG_TOUCHSCREEN = (1 << 4);
constexpr uint32_t EVDEV_UDEV_TAG_JOYSTICK = (1 << 6);
constexpr uint32_t EVDEV_UDEV_TAG_TRACKBALL = (1 << 10);

static AniUtil::DeviceType g_deviceType[] = {
    { "keyboard", EVDEV_UDEV_TAG_KEYBOARD },
    { "mouse", EVDEV_UDEV_TAG_MOUSE },
    { "touchpad", EVDEV_UDEV_TAG_TOUCHPAD },
    { "touchscreen", EVDEV_UDEV_TAG_TOUCHSCREEN },
    { "joystick", EVDEV_UDEV_TAG_JOYSTICK },
    { "trackball", EVDEV_UDEV_TAG_TRACKBALL },
};

static void ThrowBusinessError(ani_env *env, int errCode, std::string&& errMsg)
{
    MMI_HILOGD("Begin ThrowBusinessError.");
    static const char *errorClsName = "@ohos.base.BusinessError";
    ani_class cls {};
    if (ANI_OK != env->FindClass(errorClsName, &cls)) {
        MMI_HILOGE("find class BusinessError %{public}s failed", errorClsName);
        return;
    }
    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", ":", &ctor)) {
        MMI_HILOGE("find method BusinessError.constructor failed");
        return;
    }
    ani_object errorObject;
    if (ANI_OK != env->Object_New(cls, ctor, &errorObject)) {
        MMI_HILOGE("create BusinessError object failed");
        return;
    }
    ani_double aniErrCode = static_cast<ani_double>(errCode);
    ani_string errMsgStr;
    if (ANI_OK != env->String_NewUTF8(errMsg.c_str(), errMsg.size(), &errMsgStr)) {
        MMI_HILOGE("convert errMsg to ani_string failed");
        return;
    }
    if (ANI_OK != env->Object_SetFieldByName_Double(errorObject, "code", aniErrCode)) {
        MMI_HILOGE("set error code failed");
        return;
    }
    if (ANI_OK != env->Object_SetPropertyByName_Ref(errorObject, "message", errMsgStr)) {
        MMI_HILOGE("set error message failed");
        return;
    }
    env->ThrowError(static_cast<ani_error>(errorObject));
    return;
}

static bool SetID(ani_env *env, ani_object obj, std::shared_ptr<InputDevice> &inputDevice)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (inputDevice == nullptr) {
        MMI_HILOGE("inputDevice is nullptr");
        return false;
    }
    double id = inputDevice->GetId();
    if (ANI_OK != env->Object_SetPropertyByName_Double(obj, "id", id)) {
        MMI_HILOGE("Set id Failed");
        return false;
    }
    return true;
}

static bool SetDeviceName(ani_env *env, ani_object obj, std::shared_ptr<InputDevice> &inputDevice)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (inputDevice == nullptr) {
        MMI_HILOGE("inputDevice is nullptr");
        return false;
    }

    std::string name = inputDevice->GetName();
    ani_string aniStr = nullptr;
    if (ANI_OK != env->String_NewUTF8(name.data(), name.size(), &aniStr)) {
        MMI_HILOGE("Create aniStr Failed");
        return false;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Ref(obj, "name", aniStr)) {
        MMI_HILOGE("Set deviceName Failed");
        return false;
    }
    return true;
}

static bool SetDeviceBus(ani_env *env, ani_object obj, std::shared_ptr<InputDevice> &inputDevice)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (inputDevice == nullptr) {
        MMI_HILOGE("inputDevice is nullptr");
        return false;
    }

    int32_t bus = inputDevice->GetBus();
    if (ANI_OK != env->Object_SetPropertyByName_Double(obj, "bus", bus)) {
        MMI_HILOGE("Set deviceBus Failed");
        return false;
    }
    return true;
}

static bool SetDeviceVendor(ani_env *env, ani_object obj, std::shared_ptr<InputDevice> &inputDevice)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (inputDevice == nullptr) {
        MMI_HILOGE("inputDevice is nullptr");
        return false;
    }

    int32_t vendor = inputDevice->GetVendor();
    if (ANI_OK != env->Object_SetPropertyByName_Double(obj, "vendor", vendor)) {
        MMI_HILOGE("Set deviceVendor Failed");
        return false;
    }
    return true;
}

static bool SetDeviceProduct(ani_env *env, ani_object obj, std::shared_ptr<InputDevice> &inputDevice)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (inputDevice == nullptr) {
        MMI_HILOGE("inputDevice is nullptr");
        return false;
    }

    int32_t product = inputDevice->GetProduct();
    if (ANI_OK != env->Object_SetPropertyByName_Double(obj, "product", product)) {
        MMI_HILOGE("Set deviceProduct Failed");
        return false;
    }
    return true;
}

static bool SetDeviceVersion(ani_env *env, ani_object obj, std::shared_ptr<InputDevice> inputDevice)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (inputDevice == nullptr) {
        MMI_HILOGE("inputDevice is nullptr");
        return false;
    }

    int32_t version = inputDevice->GetVersion();
    if (ANI_OK != env->Object_SetPropertyByName_Double(obj, "version", version)) {
        MMI_HILOGE("Set deviceVersion Failed");
        return false;
    }
    return true;
}

static bool SetDeviceUniq(ani_env *env, ani_object obj, std::shared_ptr<InputDevice> &inputDevice)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (inputDevice == nullptr) {
        MMI_HILOGE("inputDevice is nullptr");
        return false;
    }

    std::string uniq = inputDevice->GetUniq();
    ani_string aniUniq = nullptr;
    if (ANI_OK != env->String_NewUTF8(uniq.data(), uniq.size(), &aniUniq)) {
        MMI_HILOGE("Create aniUniq Failed");
        return false;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Ref(obj, "uniq", aniUniq)) {
        MMI_HILOGE("Set uniq Failed");
        return false;
    }
    return true;
}

static bool SetDevicePhys(ani_env *env, ani_object obj, std::shared_ptr<InputDevice> &inputDevice)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (inputDevice == nullptr) {
        MMI_HILOGE("inputDevice is nullptr");
        return false;
    }

    std::string phys = inputDevice->GetPhys();
    ani_string aniPhys = nullptr;
    if (ANI_OK != env->String_NewUTF8(phys.data(), phys.size(), &aniPhys)) {
        MMI_HILOGE("Create aniUniq Failed");
        return false;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Ref(obj, "phys", aniPhys)) {
        MMI_HILOGE("Set uniq Failed");
        return false;
    }
    return true;
}

static ani_object StringArrayToObject(ani_env *env, const std::vector<std::string> &values)
{
    ani_object arrayObj = nullptr;
    ani_class arrayCls = nullptr;
    if (ANI_OK != env->FindClass("escompat.Array", &arrayCls)) {
        MMI_HILOGE("FindClass Lescompat/Array; Failed");
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor)) {
        MMI_HILOGE("Class_FindMethod <ctor> Failed");
        return arrayObj;
    }

    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size())) {
        MMI_HILOGE("Object_New Array Faild");
        return arrayObj;
    }
    ani_size index = 0;
    for (auto value : values) {
        ani_string ani_str;
        if (ANI_OK != env->String_NewUTF8(value.c_str(), value.size(), &ani_str)) {
            MMI_HILOGE("String_NewUTF8 Faild ");
            break;
        }
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "iC{std.core.Object}:", index, ani_str)) {
            MMI_HILOGE("Object_CallMethodByName_Void  $_set Faild ");
            break;
        }
        index++;
    }
    return arrayObj;
}

static bool SetDeviceSources(ani_env *env, ani_object obj, std::shared_ptr<InputDevice> &inputDevice)
{
    ani_object arrayStringObj = nullptr;
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (inputDevice == nullptr) {
        MMI_HILOGE("inputDevice is nullptr");
        return false;
    }

    uint32_t types = static_cast<uint32_t>(inputDevice->GetType());
    std::vector<std::string> sources;
    for (const auto &item : g_deviceType) {
        if (types & item.typeBit) {
            sources.push_back(item.sourceTypeName);
        }
    }

    arrayStringObj = StringArrayToObject(env, sources);
    if (arrayStringObj == nullptr) {
        MMI_HILOGE("Create Sources arrayStringObj Failed");
        return false;
    }
    if (ANI_OK != env->Object_SetPropertyByName_Ref(obj, "sources", arrayStringObj)) {
        MMI_HILOGE("Set uniq Failed");
        return false;
    }
    return true;
}

static std::string EmptyAxisRangesSource(ani_env *env, ani_object obj, std::shared_ptr<InputDevice> &inputDevice)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return "";
    }

    if (inputDevice == nullptr) {
        MMI_HILOGE("inputDevice is nullptr");
        return "";
    }

    std::string sourceType = nullptr;
    uint32_t types = static_cast<uint32_t>(inputDevice->GetType());
    for (const auto &item : g_deviceType) {
        if (types & item.typeBit) {
            sourceType = item.sourceTypeName;
            break;
        }
    }

    if (sourceType.empty()) {
        MMI_HILOGD("SourceType not found");
        ani_object arrayObj = nullptr;
        ani_class arrayCls = nullptr;
        if (ANI_OK != env->FindClass("escompat.Array", &arrayCls)) {
            MMI_HILOGE("FindClass Lescompat/Array; Failed");
        }

        ani_method arrayCtor;
        if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", ":", &arrayCtor)) {
            MMI_HILOGE("Class_FindMethod <ctor> Failed");
            return "";
        }

        if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj)) {
            MMI_HILOGE("Object_New Array Faild");
            return "";
        }

        if (ANI_OK != env->Object_SetPropertyByName_Ref(obj, "axisRanges", arrayObj)) {
            MMI_HILOGE("Set axisRanges Failed");
        }
    }
    return sourceType;
}

static bool SetAxisRangesResolution(ani_env *env, ani_object obj, const InputDevice::AxisInfo &axisInfo)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Double(obj, "resolution", axisInfo.GetResolution())) {
        MMI_HILOGE("Set AxisResolution Failed");
        return false;
    }
    return true;
}

static bool SetAxisRangesFlat(ani_env *env, ani_object obj, const InputDevice::AxisInfo &axisInfo)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Double(obj, "flat", axisInfo.GetFlat())) {
        MMI_HILOGE("Set AxisFlat Failed");
        return false;
    }
    return true;
}

static bool SetAxisRangesFuzz(ani_env *env, ani_object obj, const InputDevice::AxisInfo &axisInfo)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Double(obj, "fuzz", axisInfo.GetFuzz())) {
        MMI_HILOGE("Set AxisFuzz Failed");
        return false;
    }
    return true;
}

static bool SetAxisRangesMax(ani_env *env, ani_object obj, const InputDevice::AxisInfo &axisInfo)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Double(obj, "max", axisInfo.GetMaximum())) {
        MMI_HILOGE("Set AxisMax Failed");
        return false;
    }
    return true;
}

static bool SetAxisRangesMin(ani_env *env, ani_object obj, const InputDevice::AxisInfo &axisInfo)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Double(obj, "min", axisInfo.GetMinimum())) {
        MMI_HILOGE("Set AxisMin Failed");
        return false;
    }
    return true;
}

static bool SetAxisRangesAxis(ani_env *env, ani_object obj, const InputDevice::AxisInfo &axisInfo)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    auto iter = axisType.find(axisInfo.GetAxisType());
    std::string axis = iter->second;
    ani_string aniStr = nullptr;
    if (ANI_OK != env->String_NewUTF8(axis.data(), axis.size(), &aniStr)) {
        MMI_HILOGE("Create aniStr Failed");
        return false;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Ref(obj, "axis", aniStr)) {
        MMI_HILOGE("Set AxisRangesAxis Failed");
        return false;
    }
    return true;
}

static bool SetAxisRangesSource(ani_env *env, ani_object obj, const std::string &sourceType)
{
    if (obj == nullptr) {
        MMI_HILOGE("obj is nullptr");
        return false;
    }

    ani_string aniStr = nullptr;
    if (ANI_OK != env->String_NewUTF8(sourceType.data(), sourceType.size(), &aniStr)) {
        MMI_HILOGE("Create aniStr Failed");
        return false;
    }

    if (ANI_OK != env->Object_SetPropertyByName_Ref(obj, "source", aniStr)) {
        MMI_HILOGE("Set AxisRangesSource Failed");
        return false;
    }
    return true;
}

static ani_object CreatAxisRangesObj(ani_env *env, const std::string &sourceType, const InputDevice::AxisInfo &axisInfo)
{
    ani_object AxisRangesObj = nullptr;

    ani_namespace ns{};
    if (ANI_OK != env->FindNamespace("L@ohos/multimodalInput/inputDevice/inputDevice;", &ns)) {
        MMI_HILOGE("Not found namespace 'LinputDevice'");
        return AxisRangesObj;
    }

    static const char *className = "LAxisRangeImpl;";
    ani_class cls;
    if (ANI_OK != env->Namespace_FindClass(ns, className, &cls)) {
        MMI_HILOGE("Not found className %{public}s.", className);
        return AxisRangesObj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "l:", &ctor)) {
        MMI_HILOGE("get ctor Failed %{public}s.'", className);
        return AxisRangesObj;
    }

    int64_t nativePtr = 0;
    if (ANI_OK != env->Object_New(cls, ctor, &AxisRangesObj, reinterpret_cast<ani_long>(nativePtr))) {
        MMI_HILOGE("Create Object Failed %{public}s.", className);
        return AxisRangesObj;
    }

    if (!SetAxisRangesAxis(env, AxisRangesObj, axisInfo) || !SetAxisRangesSource(env, AxisRangesObj, sourceType) ||
        !SetAxisRangesMax(env, AxisRangesObj, axisInfo) || !SetAxisRangesMin(env, AxisRangesObj, axisInfo) ||
        !SetAxisRangesFuzz(env, AxisRangesObj, axisInfo) || !SetAxisRangesResolution(env, AxisRangesObj, axisInfo) ||
        !SetAxisRangesFlat(env, AxisRangesObj, axisInfo)) {
        MMI_HILOGE("Set AxisRanges Failed");
        return AxisRangesObj;
    }
    return AxisRangesObj;
}

static ani_object SetCreateArrayAxisRangesObj(ani_env *env, std::shared_ptr<InputDevice> &inputDevice,
    const std::string &sourceType)
{
    ani_object arrayAxisRangesObj = nullptr;
    ani_class arrayCls = nullptr;
    if (ANI_OK != env->FindClass("escompat.Array", &arrayCls)) {
        MMI_HILOGE("FindClass Lescompat/Array; Failed");
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", ":", &arrayCtor)) {
        MMI_HILOGE("Class_FindMethod <ctor> Failed");
        return arrayAxisRangesObj;
    }

    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayAxisRangesObj)) {
        MMI_HILOGE("Object_New Array Faild");
        return arrayAxisRangesObj;
    }

    ani_size index = 0;
    for (const auto &item : inputDevice->GetAxisInfo()) {
        auto iter = axisType.find(item.GetAxisType());
        if (iter == axisType.end()) {
            MMI_HILOGD("Find axisType failed");
            continue;
        }
        ani_object objAxisRanges = CreatAxisRangesObj(env, sourceType, item);
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayAxisRangesObj, "$_set", "iC{std.core.Object}:", index,
            objAxisRanges)) {
            MMI_HILOGE("%{public}s Object_CallMethodByName_Void  $_set Faild", __FUNCTION__);
            return arrayAxisRangesObj;
        }
        index++;
    }
    MMI_HILOGI("Create CreateAxisRangesObj succeed.");
    return arrayAxisRangesObj;
}

static ani_object CreateDeviceInfoObj(ani_env *env, std::shared_ptr<InputDevice> &inputDevice)
{
    ani_namespace ns{};
    if (ANI_OK != env->FindNamespace("L@ohos/multimodalInput/inputDevice/inputDevice;", &ns)) {
        MMI_HILOGE("Not found namespace 'LinputDevice'");
        return nullptr;
    }

    static const char *className = "LInputDeviceDataImpl;";
    ani_class cls;
    if (ANI_OK != env->Namespace_FindClass(ns, className, &cls)) {
        MMI_HILOGE("Not found className %{public}s.", className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "l:", &ctor)) {
        MMI_HILOGE("get ctor Failed %{public}s.'", className);
        return nullptr;
    }
    ani_object inputDeviceDataObj = nullptr;
    int64_t nativePtr = 0;
    if (ANI_OK != env->Object_New(cls, ctor, &inputDeviceDataObj, reinterpret_cast<ani_long>(nativePtr))) {
        MMI_HILOGE("Create Object Failed %{public}s.", className);
        return nullptr;
    }

    if (!SetID(env, inputDeviceDataObj, inputDevice) || !SetDeviceName(env, inputDeviceDataObj, inputDevice) ||
        !SetDeviceBus(env, inputDeviceDataObj, inputDevice) || !SetDeviceVendor(env, inputDeviceDataObj, inputDevice) ||
        !SetDeviceProduct(env, inputDeviceDataObj, inputDevice) ||
        !SetDeviceVersion(env, inputDeviceDataObj, inputDevice) ||
        !SetDeviceUniq(env, inputDeviceDataObj, inputDevice) || !SetDevicePhys(env, inputDeviceDataObj, inputDevice) ||
        !SetDeviceSources(env, inputDeviceDataObj, inputDevice)) {
        MMI_HILOGE("Set DeviceInfoObj Failed");
        return nullptr;
    }

    std::string sourceType = EmptyAxisRangesSource(env, inputDeviceDataObj, inputDevice);
    if (!sourceType.empty()) {
        MMI_HILOGD("Set Empty AxisRanges to axisRanges");
        SetCreateArrayAxisRangesObj(env, inputDevice, sourceType);
    }
    MMI_HILOGI("Create DeviceInfoObj succeed.");
    return inputDeviceDataObj;
}

static ani_object DoubleToObject(ani_env *env, double value)
{
    ani_object aniObject = nullptr;
    ani_double doubleValue = static_cast<ani_double>(value);
    static const char *className = "std.core.Double";
    ani_class aniClass;
    if (ANI_OK != env->FindClass(className, &aniClass)) {
        MMI_HILOGE("Not found '%{public}s'.", className);
        return aniObject;
    }
    ani_method objCtor;
    if (ANI_OK != env->Class_FindMethod(aniClass, "<ctor>", "d:", &objCtor)) {
        MMI_HILOGE("Class_GetMethod Failed '%{public}s <ctor>.'", className);
        return aniObject;
    }

    if (ANI_OK != env->Object_New(aniClass, objCtor, &aniObject, doubleValue)) {
        MMI_HILOGE("Object_New Failed '%{public}s. <ctor>", className);
        return aniObject;
    }
    return aniObject;
}

static ani_object DoubleArrayToObject(ani_env *env, const std::shared_ptr<std::vector<int32_t>> &ids)
{
    ani_object arrayObj = nullptr;
    ani_class arrayCls = nullptr;
    if (ANI_OK != env->FindClass("escompat.Array", &arrayCls)) {
        MMI_HILOGE("FindClass Lescompat/Array; Failed");
        return arrayObj;
    }

    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor)) {
        MMI_HILOGE("Class_FindMethod <ctor> Failed");
        return arrayObj;
    }

    if (ids == nullptr) {
        MMI_HILOGE("ids is null");
        return arrayObj;
    }
    size_t size = ids->size();
    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, size)) {
        MMI_HILOGE("Object_New Array Faild");
        return arrayObj;
    }
    ani_int index = 0;
    for (auto id : *ids) {
        ani_object aniValue = DoubleToObject(env, id);
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "iC{std.core.Object}:", index, aniValue)) {
            MMI_HILOGI("Object_CallMethodByName_Void  $_set Faild ");
            break;
        }
        index++;
    }
    return arrayObj;
}

static std::string AniStringToString(ani_env *env, ani_string aniStr)
{
    ani_size strSize;
    env->String_GetUTF8Size(aniStr, &strSize);

    std::vector<char> buffer(strSize + 1);
    char *utf8Buffer = buffer.data();

    ani_size bytes_written = 0;
    env->String_GetUTF8(aniStr, utf8Buffer, strSize + 1, &bytes_written);

    utf8Buffer[bytes_written] = '\0';
    std::string content = std::string(utf8Buffer);
    return content;
}

static ani_object GetDeviceList(ani_env *env)
{
    std::shared_ptr<std::vector<int32_t>> deviceIds = std::make_shared<std::vector<int32_t>>();
    auto callback = [deviceIds](std::vector<int32_t> &ids) { deviceIds->assign(ids.begin(), ids.end()); };
    InputManager::GetInstance()->GetDeviceIds(callback);

    ani_object object = DoubleArrayToObject(env, deviceIds);
    return object;
}

static ani_object GetDeviceInfo(ani_env *env, ani_double deviceId)
{
    std::shared_ptr<InputDevice> inputDevice = nullptr;
    InputManager::GetInstance()->GetDevice(deviceId, [&](std::shared_ptr<InputDevice> device) {
        inputDevice = device;
    });

    if (inputDevice == nullptr) {
        MMI_HILOGE("Get DeviceInfo Failed");
        return nullptr;
    }

    ani_object object = CreateDeviceInfoObj(env, inputDevice);
    return object;
}

std::shared_ptr<AniInputDeviceContext> g_inputDeviceContext = nullptr;

AniInputDeviceContext::AniInputDeviceContext()
{
    CALL_DEBUG_ENTER;
    mgr_ = std::make_shared<AniInputDeviceManager>();
}

AniInputDeviceContext::~AniInputDeviceContext()
{
    CALL_DEBUG_ENTER;
    std::lock_guard<std::mutex> guard(mtx_);
    auto aniInputDeviceMgr = mgr_;
    mgr_.reset();
    if (aniInputDeviceMgr) {
        aniInputDeviceMgr->ResetEnv();
    }
}

void AniInputDeviceContext::On(ani_env *env, ani_string aniStr, ani_object callback)
{
    CALL_DEBUG_ENTER;
    std::string type = AniStringToString(env, aniStr);
    if (type != CHANGED_TYPE) {
        MMI_HILOGE("%{public}s: Type is not change", __func__);
        ThrowBusinessError(env, COMMON_PARAMETER_ERROR, "type must be change");
        return;
    }
    if (mgr_ == nullptr) {
        MMI_HILOGE("%{public}s: aniInputDeviceMgr is nullptr", __func__);
        ThrowBusinessError(env, COMMON_PARAMETER_ERROR, "aniInputDeviceMgr is nullptr");
        return;
    }
    mgr_->RegisterDevListener(env, type, callback);
}

static void OnChange(ani_env *env, ani_string aniStr, ani_object callback)
{
    CALL_DEBUG_ENTER;
    if (g_inputDeviceContext == nullptr) {
        MMI_HILOGE("%{public}s: g_inputDeviceContext is nullptr", __func__);
        return;
    }
    g_inputDeviceContext->On(env, aniStr, callback);
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    MMI_HILOGD("%{public}s: enter ANI_Constructor", __func__);
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        MMI_HILOGE("%{public}s: Unsupported ANI_VERSION_1", __func__);
        return ANI_ERROR;
    }

    static const char *name = "@ohos.multimodalInput.inputDevice.inputDevice";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(name, &ns)) {
        MMI_HILOGE("%{public}s: Not found %{public}s", __func__, name);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function{ "getDeviceListInner", nullptr, reinterpret_cast<void *>(GetDeviceList) },
        ani_native_function{ "getDeviceInfoInner", nullptr, reinterpret_cast<void *>(GetDeviceInfo) },
        ani_native_function{ "on", nullptr, reinterpret_cast<void *>(OnChange) },
    };

    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size())) {
        MMI_HILOGE("%{public}s:Cannot bind native methods to '%{public}s'", __func__, name);
        return ANI_ERROR;
    };

    g_inputDeviceContext = std::make_shared<AniInputDeviceContext>();

    *result = ANI_VERSION_1;
    return ANI_OK;
}