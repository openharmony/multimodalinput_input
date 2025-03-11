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

#ifndef EVENT_STATISTIC_H
#define EVENT_STATISTIC_H

#include <fstream>
#include <queue>
#include <sys/stat.h>
#include <unistd.h>

#include "pointer_event.h"

namespace OHOS {
namespace MMI {
class EventStatistic final {
public:
    static void PushEvent(std::shared_ptr<InputEvent> eventPtr);
    static void PushPointerEvent(std::shared_ptr<PointerEvent> eventPtr);
    static std::string PopEvent();
    static void WriteEventFile();
    static void Dump(int32_t fd, const std::vector<std::string> &args);
    static std::string ConvertEventToStr(const std::shared_ptr<InputEvent> eventPtr);
    static std::string ConvertTimeToStr(int64_t timestamp);

private:
    static std::queue<std::string> eventQueue_;
    static std::list<std::string> dumperEventList_;
    static std::mutex queueMutex_;
    static std::condition_variable queueCondition_;
    static bool writeFileEnabled_;
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_STATISTIC_H