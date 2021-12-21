/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef OHOS_S_INPUT_H
#define OHOS_S_INPUT_H
#include <thread>
#include <libudev.h>
#include <functional>
#include <libinput.h>

namespace OHOS {
namespace MMI {
typedef std::function<void()> FunOnTimer;
typedef std::function<void(void *event)> FunInputEvent;
class SInput {
public:
    SInput();
    virtual ~SInput();

    virtual bool Init(FunInputEvent funInputEvent, const std::string& seat_id = "seat0");
    virtual bool Start();
    virtual void Stop();

protected:
    virtual void OnEventHandler();
    virtual void EventDispatch();
    virtual void OnThread();

protected:
    int32_t lfd_ = -1;
    bool isrun_ = false;
    udev *udev_ = nullptr;
    libinput *input_ = nullptr;

    std::thread t_;
    FunInputEvent funInputEvent_;
    std::string seat_id_;
};
}
}
#endif
