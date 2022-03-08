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

#include "keyboard_inject.h"
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <mutex>
#include "mmi_log.h"

using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace MMI {
namespace {
    std::shared_ptr<KeyboardInject> g_instance = nullptr;
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, MMI_LOG_DOMAIN, "keyBoardInject"};
}
std::mutex KeyboardInject::mutex_;
std::unique_ptr<VirtualKeyboard> g_pKeyboard = nullptr;
std::unique_ptr<InjectThread> KeyboardInject::injectThread_ = nullptr;

KeyboardInject::KeyboardInject()
{
    std::lock_guard<std::mutex> keyboardLock(mutex_);
    auto it = keyCodeMap_.find(INPUT_KEY_BACK);
    if (it == keyCodeMap_.end()) {
        auto ret = keyCodeMap_.insert(std::make_pair(INPUT_KEY_BACK, LINUX_KEY_BACK));
        MMI_LOGD("ret.second:%{public}d", ret.second);
    }
    injectThread_ = std::make_unique<InjectThread>();
    if (injectThread_ == nullptr) {
        MMI_LOGE("injectThread_ is null");
        return;
    }
    g_pKeyboard = std::make_unique<VirtualKeyboard>();
    g_pKeyboard->SetUp();
}

void KeyboardInject::InjectKeyEvent(uint16_t code, uint32_t value) const
{
    std::lock_guard<std::mutex> keyboardLock(mutex_);
    auto it = keyCodeMap_.find(code);
    if (it == keyCodeMap_.end()) {
        return;
    }
    InjectInputEvent injectInputEvent = {injectThread_->KEYBOARD_DEVICE_ID, EV_KEY, it->second, value};
    injectThread_->WaitFunc(injectInputEvent);
    InjectInputEvent injectInputSync = {injectThread_->KEYBOARD_DEVICE_ID, EV_SYN, SYN_REPORT, 0};
    injectThread_->WaitFunc(injectInputSync);
}
} // namespace MMI
} // namespace OHOS
