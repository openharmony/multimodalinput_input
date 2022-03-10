/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef INPUT_HANDLER_TYPE_H
#define INPUT_HANDLER_TYPE_H
#include <limits>

namespace OHOS {
namespace MMI {
namespace {
constexpr size_t    MAX_N_INPUT_HANDLERS { 16 };
constexpr size_t    MAX_N_INPUT_MONITORS { MAX_N_INPUT_HANDLERS };
constexpr size_t    MAX_N_INPUT_INTERCEPTORS { MAX_N_INPUT_HANDLERS };
constexpr int32_t   MIN_HANDLER_ID { 1 };
constexpr int32_t   INVALID_HANDLER_ID { -1 };
} // namespace

enum InputHandlerType : int32_t {
    NONE,
    INTERCEPTOR,
    MONITOR,
};

inline bool IsValidHandlerType(InputHandlerType handlerType)
{
    return ((handlerType == InputHandlerType::INTERCEPTOR) ||
        (handlerType == InputHandlerType::MONITOR));
}

inline bool IsValidHandlerId(int32_t handlerId)
{
    return ((handlerId >= MIN_HANDLER_ID) && (handlerId < std::numeric_limits<int32_t>::max()));
}
} // namespace MMI
} // namespace OHOS
#endif // INPUT_HANDLER_TYPE_H