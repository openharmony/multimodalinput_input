/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef LIBINPUT_WRAPPER_H
#define LIBINPUT_WRAPPER_H

#include <thread>
#include <unordered_map>

#include "libinput.h"
#include "nocopyable.h"

namespace OHOS {
namespace MMI {
class LibinputWrapper final {
public:
    LibinputWrapper() = default;
    DISALLOW_COPY_AND_MOVE(LibinputWrapper);
    ~LibinputWrapper();

    bool Init();
    struct libinput_event* Dispatch();
    void DrainEvents();
    bool AddPath(const std::string &path);
    void RemovePath(const std::string &path);

private:
    int32_t fd_ { -1 };
    libinput *input_ { nullptr };
    std::unordered_map<std::string, libinput_device*> devices_;
};
} // namespace MMI
} // namespace OHOS
#endif // LIBINPUT_WRAPPER_H