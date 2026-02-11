/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef MOUSE_PREFERENCE_ACCESSOR_H
#define MOUSE_PREFERENCE_ACCESSOR_H

#include "i_input_service_context.h"
#include "pointer_event.h"
#include "struct_multimodal.h"

#include <atomic>
#include <memory>
#include <shared_mutex>

namespace OHOS {
namespace MMI {
class MousePreferenceAccessor final {
public:
    MousePreferenceAccessor() = default;
    ~MousePreferenceAccessor() = default;

    static int32_t SetMouseScrollRows(IInputServiceContext &env, int32_t userId, int32_t rows);
    static int32_t GetMouseScrollRows(IInputServiceContext &env, int32_t userId);
    static int32_t SetMousePrimaryButton(IInputServiceContext &env, int32_t userId, int32_t primaryButton);
    static int32_t GetMousePrimaryButton(IInputServiceContext &env, int32_t userId);
    static int32_t SetPointerSpeed(IInputServiceContext &env, int32_t userId, int32_t speed);
    static int32_t GetPointerSpeed(IInputServiceContext &env, int32_t userId);
    static int32_t GetTouchpadSpeed(IInputServiceContext &env, int32_t userId);
    static int32_t SetTouchpadScrollSwitch(IInputServiceContext &env, int32_t userId, int32_t pid, bool switchFlag);
    static void GetTouchpadScrollSwitch(IInputServiceContext &env, int32_t userId, bool &switchFlag);
    static int32_t SetTouchpadScrollDirection(IInputServiceContext &env, int32_t userId, bool state);
    static void GetTouchpadScrollDirection(IInputServiceContext &env, int32_t userId, bool &state);
    static int32_t SetTouchpadTapSwitch(IInputServiceContext &env, int32_t userId, bool switchFlag);
    static void GetTouchpadTapSwitch(IInputServiceContext &env, int32_t userId, bool &switchFlag);
    static int32_t SetTouchpadRightClickType(IInputServiceContext &env, int32_t userId, int32_t type);
    static void GetTouchpadRightClickType(IInputServiceContext &env, int32_t userId, int32_t &type);
    static int32_t SetTouchpadPointerSpeed(IInputServiceContext &env, int32_t userId, int32_t speed);
    static void GetTouchpadPointerSpeed(IInputServiceContext &env, int32_t userId, int32_t &speed);
    static int32_t GetTouchpadScrollRows(IInputServiceContext &env, int32_t userId);

private:
    static int32_t PutConfigDataToDatabase(IInputServiceContext &env, int32_t userId, const std::string &key,
        const std::string &field, bool value);
    static void GetConfigDataFromDatabase(IInputServiceContext &env, int32_t userId, const std::string &key,
        const std::string &field, bool &value);
    static int32_t PutConfigDataToDatabase(IInputServiceContext &env, int32_t userId, const std::string &key,
        const std::string &field, int32_t value);
    static void GetConfigDataFromDatabase(IInputServiceContext &env, int32_t userId, const std::string &key,
        const std::string &field, int32_t &value);
};
} // namespace MMI
} // namespace OHOS
#endif // MOUSE_PREFERENCE_ACCESSOR_H