/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef MESSAGE_POST_H
#define MESSAGE_POST_H
#ifdef OHOS_WESTEN_MODEL

#include <map>
#include <string>
#include <list>
#include "singleton.h"
#include "libweston.h"

namespace OHOS {
namespace MMI {
class MessagePost : public OHOS::Singleton<OHOS::MMI::MessagePost> {
public:
    void SetFd(int32_t fd);
    void RunOnWestonThread(std::function<void(struct weston_compositor *)> taskItem);
    static int32_t RunTaskOnWestonThread(int32_t fd, uint32_t mask, void *data);
    void SetWestonCompositor(struct weston_compositor *ec);

private:
    void NotifyWestonThread();
    void RunTasks();

    std::mutex lk_;
    std::list<std::function<void(struct weston_compositor *)>> asyncTasks_;
    int32_t fd_;
    struct weston_compositor *ec_ {nullptr};
};
} // namespace MMI
} // namespace OHOS
#define MMIMsgPost OHOS::MMI::MessagePost::GetInstance()

#endif // OHOS_WESTEN_MODEL
#endif // MESSAGE_POST_H