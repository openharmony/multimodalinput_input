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

#include "ani_util.h"

#include <unordered_map>
#include <linux/input.h>

#include "mmi_log.h"
#include "napi_constants.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "AniUtil"

namespace OHOS {
namespace MMI {
namespace {

constexpr uint32_t EVDEV_UDEV_TAG_TOUCHSCREEN = (1 << 4);
constexpr uint32_t EVDEV_UDEV_TAG_JOYSTICK = (1 << 6);
constexpr uint32_t EVDEV_UDEV_TAG_TRACKBALL = (1 << 10);

AniUtil::DeviceType g_deviceType[] = {
    { "keyboard", EVDEV_UDEV_TAG_KEYBOARD },
    { "mouse", EVDEV_UDEV_TAG_MOUSE },
    { "touchpad", EVDEV_UDEV_TAG_TOUCHPAD },
    { "touchscreen", EVDEV_UDEV_TAG_TOUCHSCREEN },
    { "joystick", EVDEV_UDEV_TAG_JOYSTICK },
    { "trackball", EVDEV_UDEV_TAG_TRACKBALL },
};
} // namespace

bool AniUtil::CallbackInfo::SetCallback(ani_object handle)
{
    if (ANI_OK != env_->GlobalReference_Create(handle, &callback_)) {
        MMI_HILOGE("%{public}s: Create global callback failed", __func__);
        return false;
    }
    return true;
}

AniUtil::CallbackInfo::~CallbackInfo()
{
    CALL_DEBUG_ENTER;
    if (env_ == nullptr) {
        return;
    }
    if (callback_ != nullptr) {
        env_->GlobalReference_Delete(callback_);
    }
    callback_ = nullptr;
}

bool AniUtil::IsSameHandle(ani_env *env, ani_ref handle, ani_env *iterEnv, ani_ref iterhandle)
{
    if (env != iterEnv) {
        MMI_HILOGD("%{public}s: not the same env", __func__);
        return false;
    }
    ani_boolean isEquals = false;
    if (ANI_OK != env->Reference_StrictEquals(handle, iterhandle, &isEquals)) {
        MMI_HILOGD("%{public}s: check observer equal failed!", __func__);
        return false;
    }
    return isEquals;
}

ani_string AniUtil::StdStringToANIString(ani_env* env, const std::string& str)
{
    ani_string stringAni = nullptr;
    if (ANI_OK != env->String_NewUTF8(str.c_str(), str.size(), &stringAni)) {
        MMI_HILOGD("%{public}s: String_NewUTF8 Failed", __func__);
    }
    return stringAni;
}

ani_boolean AniUtil::IsInstanceOf(ani_env *env, const std::string &cls_name, ani_object obj)
{
    ani_class cls;
    if (ANI_OK != env->FindClass(cls_name.c_str(), &cls)) {
        MMI_HILOGE("%{public}s: FindClass failed", __func__);
        return ANI_FALSE;
    }

    ani_boolean ret;
    env->Object_InstanceOf(obj, cls, &ret);
    return ret;
}

ani_object AniUtil::CreateAniObject(ani_env *env, const char *nsName, const char *className)
{
    ani_class cls;
    const std::string fullClassName = std::string(nsName) + "." + className;
    if (ANI_OK != env->FindClass(fullClassName.c_str(), &cls)) {
        MMI_HILOGE("%{public}s: FindClass %{public}s failed",  __func__, className);
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        MMI_HILOGE("%{public}s: Class_FindMethod 'constructor' failed",  __func__);
        return nullptr;
    }

    ani_object obj;
    if (ANI_OK != env->Object_New(cls, ctor, &obj)) {
        MMI_HILOGE("%{public}s: Object_New ani_object failed",  __func__);
        return nullptr;
    }
    return obj;
}

} // namespace MMI
} // namespace OHOS