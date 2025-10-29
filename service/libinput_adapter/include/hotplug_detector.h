/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef MMI_HOT_PLUG_DETECTOR_H
#define MMI_HOT_PLUG_DETECTOR_H

#include <string>

#include "nocopyable.h"
#include "unique_fd.h"

namespace OHOS {
namespace MMI {
class HotplugDetector final {
public:
    using callback = std::function<void(std::string)>;
    HotplugDetector();
    ~HotplugDetector();
    DISALLOW_COPY_AND_MOVE(HotplugDetector);

    bool Init(const callback& addFunc, const callback& removeFunc);
    void Stop();
    void OnEvent() const;

    int32_t GetFd() const
    {
        return inotifyFd_;
    }

private:
    bool Scan() const;

    callback addFunc_;
    callback removeFunc_;

    UniqueFd inotifyFd_;
};
} // namespace MMI
} // namespace OHOS
#endif // MMI_HOT_PLUG_DETECTOR_H