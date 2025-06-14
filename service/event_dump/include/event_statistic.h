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

#include <algorithm>
#include <fstream>
#include <queue>
#include <sys/stat.h>
#include <unistd.h>

#include "pointer_event.h"
#include "key_event.h"
#include "switch_event.h"

namespace OHOS {
namespace MMI {
class EventStatistic final {
public:
    static void PushEventStr(std::string eventStr);
    static void PushPointerEvent(std::shared_ptr<PointerEvent> eventPtr);
    static void PushKeyEvent(std::shared_ptr<KeyEvent> eventPtr);
    static void PushSwitchEvent(std::shared_ptr<SwitchEvent> eventPtr);
    static void PushPointerRecord(std::shared_ptr<PointerEvent> eventPtr);
    static int32_t QueryPointerRecord(int32_t count, std::vector<std::shared_ptr<PointerEvent>> &pointerList);
    static std::string PopEvent();
    static void WriteEventFile();
    static void Dump(int32_t fd, const std::vector<std::string> &args);
    static std::string ConvertInputEventToStr(const std::shared_ptr<InputEvent> eventPtr);
    static std::string ConvertTimeToStr(int64_t timestamp);
    static const char* ConvertEventTypeToString(int32_t eventType);
    static const char* ConvertSourceTypeToString(int32_t sourceType_);
    static const char* ConvertPointerActionToString(std::shared_ptr<PointerEvent> eventPtr);
    static const char* ConvertKeyActionToString(int32_t keyAction);
    static const char* ConvertSwitchTypeToString(int32_t switchType);

private:
    struct PointerEventRecord {
        int64_t actionTime;
        int32_t sourceType;
        bool isInject;
        std::vector<double> pressures;
        std::vector<double> tiltXs;
        std::vector<double> tiltYs;
        PointerEventRecord(int64_t actionTime, int32_t sourceType, bool isInject, std::vector<double> pressures,
            std::vector<double> tiltXs, std::vector<double> tiltYs)
            : actionTime(actionTime), sourceType(sourceType), isInject(isInject), pressures(pressures), tiltXs(tiltXs),
              tiltYs(tiltYs)
        {}
    };
    static std::queue<std::string> eventQueue_;
    static std::list<std::string> dumperEventList_;
    static std::mutex queueMutex_;
    static std::condition_variable queueCondition_;
    static bool writeFileEnabled_;
    static std::deque<EventStatistic::PointerEventRecord> pointerRecordDeque_;
};
} // namespace MMI
} // namespace OHOS
#endif // EVENT_STATISTIC_H