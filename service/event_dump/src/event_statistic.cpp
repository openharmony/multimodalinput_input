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

#include "event_statistic.h"
#include "mmi_log.h"
#include "util_ex.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "EventStatistic"

namespace OHOS {
namespace MMI {
namespace {
const char* EVENT_FILE_NAME = "/data/service/el1/public/multimodalinput/multimodal_event.dmp";
const char* EVENT_FILE_NAME_HISTORY = "/data/service/el1/public/multimodalinput/multimodal_event_history.dmp";
constexpr int32_t FILE_MAX_SIZE = 100 * 1024 * 1024;
constexpr int32_t EVENT_OUT_SIZE = 30;
constexpr int32_t FUNC_EXE_OK = 0;
constexpr int32_t STRING_WIDTH = 3;
}

std::queue<std::string> EventStatistic::eventQueue_;
std::list<std::string> EventStatistic::dumperEventList_;
std::mutex EventStatistic::queueMutex_;
std::condition_variable EventStatistic::queueCondition_;
bool EventStatistic::writeFileEnabled_ = false;

std::string EventStatistic::ConvertEventToStr(const std::shared_ptr<InputEvent> eventPtr)
{
    auto nowTime = std::chrono::system_clock::now();
    std::time_t timeT = std::chrono::system_clock::to_time_t(nowTime);
    auto milsecsCount = std::chrono::duration_cast<std::chrono::milliseconds>(nowTime.time_since_epoch()).count();
    std::string handleTime = ConvertTimeToStr(static_cast<int64_t>(timeT));
    int32_t milsec = milsecsCount % 1000;
    std::stringstream strStream;
    strStream << std::left << std::setw(STRING_WIDTH) << milsec;
    std::string milsecStr(strStream.str());
    handleTime += "." + milsecStr;
    std::string eventStr = "{" + handleTime + "," + eventPtr->ToString() + "}";
    return eventStr;
}

std::string EventStatistic::ConvertTimeToStr(int64_t timestamp)
{
    std::string timeStr = std::to_string(timestamp);
    std::time_t timeT = timestamp;
    std::tm tmInfo;
    localtime_r(&timeT, &tmInfo);
    char buffer[32] = {0};
    if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tmInfo) > 0) {
        timeStr = buffer;
    }
    return timeStr;
}

void EventStatistic::PushPointerEvent(std::shared_ptr<PointerEvent> eventPtr)
{
    CHKPV(eventPtr);
    int32_t pointerAction = eventPtr->GetPointerAction();
    if (pointerAction == PointerEvent::POINTER_ACTION_MOVE ||
        eventPtr->HasFlag(InputEvent::EVENT_FLAG_PRIVACY_MODE)) {
        MMI_HILOGD("PointEvent is filtered");
        return;
    }
    PushEvent(eventPtr);
}

void EventStatistic::PushEvent(std::shared_ptr<InputEvent> eventPtr)
{
    std::lock_guard<std::mutex> lock(queueMutex_);
    CHKPV(eventPtr);
    std::string eventStr = ConvertEventToStr(eventPtr);
    dumperEventList_.push_back(eventStr);
    if (dumperEventList_.size() > EVENT_OUT_SIZE) {
        dumperEventList_.pop_front();
    }
    if (writeFileEnabled_) {
        eventQueue_.push(eventStr);
        queueCondition_.notify_all();
    }
}

std::string EventStatistic::PopEvent()
{
    std::unique_lock<std::mutex> lock(queueMutex_);
    if (eventQueue_.empty()) {
        queueCondition_.wait(lock, []() { return !eventQueue_.empty(); });
    }
    std::string eventStr = eventQueue_.front();
    eventQueue_.pop();
    return eventStr;
}

void EventStatistic::WriteEventFile()
{
    while (writeFileEnabled_) {
        std::string eventStr = PopEvent();
        struct stat statbuf;
        int32_t fileSize = 0;
        if (stat(EVENT_FILE_NAME, &statbuf) == FUNC_EXE_OK) {
            fileSize = static_cast<int32_t>(statbuf.st_size);
        }
        if (fileSize >= FILE_MAX_SIZE) {
            if (access(EVENT_FILE_NAME_HISTORY, F_OK) == FUNC_EXE_OK &&
                remove(EVENT_FILE_NAME_HISTORY) != FUNC_EXE_OK) {
                MMI_HILOGE("Remove history file failed");
            }
            if (rename(EVENT_FILE_NAME, EVENT_FILE_NAME_HISTORY) != FUNC_EXE_OK) {
                MMI_HILOGE("Rename file failed");
            }
        }
        std::ofstream file(EVENT_FILE_NAME, std::ios::app);
        if (file.is_open()) {
            file << eventStr << std::endl;
            file.close();
        } else {
            MMI_HILOGE("Open file failed");
        }
    }
}

void EventStatistic::Dump(int32_t fd, const std::vector<std::string> &args)
{
    std::lock_guard<std::mutex> lock(queueMutex_);
    for (auto it = dumperEventList_.begin(); it != dumperEventList_.end(); ++it) {
        mprintf(fd, (*it).c_str());
    }
}
} // namespace MMI
} // namespace OHOS