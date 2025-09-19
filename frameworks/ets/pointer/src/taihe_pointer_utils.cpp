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

#include "taihe_pointer_utils.h"
#include "define_multimodal.h"
#include "mmi_log.h"
#include "pixel_map_taihe_ani.h"

#undef MMI_LOG_TAG
#define MMI_LOG_TAG "TaihePointerUtils"

namespace OHOS {
namespace MMI {
CustomCursor TaihePointerUtils::ConverterToCustomCursor(const ohos::multimodalInput::pointer::CustomCursor &value)
{
    CustomCursor cursor;
    ani_env *env = taihe::get_env();
    CHKPR(env, cursor);
    ani_object obj = reinterpret_cast<ani_object>(value.pixelMap);
    ani_ref pixelMapAni;
    if (ANI_OK != env->GlobalReference_Create(obj, &pixelMapAni)) {
        MMI_HILOGE("get pixelMap failed.");
        return cursor;
    }

    auto pixelMap = OHOS::Media::PixelMapTaiheAni::GetNativePixelMap(env,
        reinterpret_cast<ani_object>(pixelMapAni));
    if (pixelMap == nullptr) {
        MMI_HILOGE("pixelMap is null");
        env->GlobalReference_Delete(pixelMapAni);
        return cursor;
    }
    cursor.pixelMap = (void *)pixelMap.get();
    if (value.focusX.has_value()) {
        cursor.focusX = static_cast<int32_t> (value.focusX.value());
    }
    if (value.focusY.has_value()) {
        cursor.focusY = static_cast<int32_t> (value.focusY.value());
    }
    env->GlobalReference_Delete(pixelMapAni);
    return cursor;
}

CursorOptions TaihePointerUtils::ConverterToCursorConfig(const ohos::multimodalInput::pointer::CursorConfig &value)
{
    CursorOptions opts;
    opts.followSystem = value.followSystem;
    return opts;
}

} // namespace MMI
} // namespace OHOS