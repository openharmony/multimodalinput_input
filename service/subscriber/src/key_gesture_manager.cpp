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

#include "key_gesture_manager.h"

#include <algorithm>

#include "define_multimodal.h"
#include "timer_manager.h"
#include "util.h"

#undef MMI_LOG_DOMAIN
#define MMI_LOG_DOMAIN MMI_LOG_HANDLER
#undef MMI_LOG_TAG
#define MMI_LOG_TAG "KeyGestureManager"

namespace OHOS {
namespace MMI {
namespace {
constexpr int32_t COMBINATION_KEY_TIMEOUT { 150 };
constexpr int32_t REPEAT_ONCE { 1 };
constexpr size_t SINGLE_KEY_PRESSED { 1 };
}

void KeyGestureManager::KeyGestureId::Dump(std::ostringstream &output) const
{
    output << "[";
    auto iter = keys_.begin();
    if (iter != keys_.end()) {
        output << *iter;
        for (++iter; iter != keys_.end(); ++iter) {
            output << "," << *iter;
        }
    }
    output << "]";
}

bool KeyGestureManager::KeyGesture::IsWorking()
{
    return true;
}

int32_t KeyGestureManager::KeyGesture::AddHandler(int32_t downDuration,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    static int32_t baseId { 0 };

    auto ret = handlers_.emplace(++baseId, std::max(downDuration, COMBINATION_KEY_TIMEOUT), callback);
    return ret.first->GetId();
}

bool KeyGestureManager::KeyGesture::RemoveHandler(int32_t id)
{
    for (auto iter = handlers_.begin(); iter != handlers_.end(); ++iter) {
        if (iter->GetId() == id) {
            handlers_.erase(iter);
            return true;
        }
    }
    return false;
}

void KeyGestureManager::KeyGesture::Reset()
{
    if (timerId_ >= 0) {
        TimerMgr->RemoveTimer(timerId_);
        timerId_ = -1;
    }
}

bool KeyGestureManager::LongPressSingleKey::ShouldIntercept(std::shared_ptr<KeyOption> keyOption) const
{
    std::set<int32_t> keys = keyOption->GetPreKeys();
    return (keys.empty() && (keyOption->GetFinalKey() == keyCode_));
}

bool KeyGestureManager::LongPressSingleKey::Intercept(std::shared_ptr<KeyEvent> keyEvent)
{
    if ((keyEvent->GetKeyCode() == keyCode_) && (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN)) {
        if (timerId_ >= 0) {
            if (!TimerMgr->IsExist(timerId_) && !handlers_.empty()) {
                handlers_.rbegin()->Run(keyEvent);
            }
        } else {
            if (handlers_.empty()) {
                return false;
            }
            timerId_ = TimerMgr->AddTimer(handlers_.rbegin()->GetDownDuration(), REPEAT_ONCE,
                [this, tKeyEvent = KeyEvent::Clone(keyEvent)]() {
                    handlers_.rbegin()->Run(tKeyEvent);
                });
        }
        return true;
    }
    if (timerId_ >= 0) {
        if (TimerMgr->IsExist(timerId_)) {
            TimerMgr->RemoveTimer(timerId_);
            if (!handlers_.empty()) {
                handlers_.rbegin()->Run(keyEvent);
            }
        }
        TimerMgr->RemoveTimer(timerId_);
        timerId_ = -1;
    }
    return false;
}

void KeyGestureManager::LongPressSingleKey::Dump(std::ostringstream &output) const
{
    output << "[" << keyCode_ << "] --> {";
    auto iter = handlers_.begin();
    if (iter != handlers_.end()) {
        output << iter->GetDownDuration();
        for (++iter; iter != handlers_.end(); ++iter) {
            output << "," << iter->GetDownDuration();
        }
    }
    output << "}";
}

bool KeyGestureManager::LongPressCombinationKey::ShouldIntercept(std::shared_ptr<KeyOption> keyOption) const
{
    std::set<int32_t> keys = keyOption->GetPreKeys();
    keys.insert(keyOption->GetFinalKey());
    return (keys_ == keys);
}

bool KeyGestureManager::LongPressCombinationKey::Intercept(std::shared_ptr<KeyEvent> keyEvent)
{
    if ((keys_.find(keyEvent->GetKeyCode()) != keys_.end()) &&
        (keyEvent->GetKeyAction() == KeyEvent::KEY_ACTION_DOWN)) {
        if (timerId_ >= 0) {
            std::ostringstream output("LongPressCombinationKey::Intercept ");
            Dump(output);
            MMI_HILOGI("%{public}s is active now", output.str().c_str());
            return true;
        }
        if (!IsWorking()) {
            std::ostringstream output("LongPressCombinationKey::Intercept, Switch off ");
            Dump(output);
            MMI_HILOGI("%{public}s", output.str().c_str());
            return false;
        }
        if (handlers_.empty()) {
            std::ostringstream output("LongPressCombinationKey::Intercept, No handler for ");
            Dump(output);
            MMI_HILOGI("%{public}s", output.str().c_str());
            return false;
        }
        if (keyEvent->GetPressedKeys().size() == SINGLE_KEY_PRESSED) {
            firstDownTime_ = GetSysClockTime();
        }
        int32_t now = GetSysClockTime();
        bool isMatch = std::all_of(keys_.cbegin(), keys_.cend(), [this, keyEvent, now](auto keyCode) {
            auto itemOpt = keyEvent->GetKeyItem(keyCode);
            return (itemOpt && itemOpt->IsPressed() &&
                    (now < (firstDownTime_ + MS2US(COMBINATION_KEY_TIMEOUT))));
        });
        if (isMatch) {
            std::ostringstream output("LongPressCombinationKey::Intercept, trigger ");
            Dump(output);
            MMI_HILOGI("%{public}s", output.str().c_str());
            Trigger(handlers_.rbegin()->GetDownDuration(), keyEvent);
            return true;
        }
    }
    if (timerId_ >= 0) {
        TimerMgr->RemoveTimer(timerId_);
        timerId_ = -1;
    }
    return false;
}

void KeyGestureManager::LongPressCombinationKey::Dump(std::ostringstream &output) const
{
    output << "[";
    auto keyIter = keys_.begin();
    if (keyIter != keys_.end()) {
        output << *keyIter;
        for (++keyIter; keyIter != keys_.end(); ++keyIter) {
            output << "," << *keyIter;
        }
    }
    output << "] --> {";
    auto iter = handlers_.begin();
    if (iter != handlers_.end()) {
        output << iter->GetDownDuration();
        for (++iter; iter != handlers_.end(); ++iter) {
            output << "," << iter->GetDownDuration();
        }
    }
    output << "}";
}

void KeyGestureManager::LongPressCombinationKey::Trigger(int32_t delay, std::shared_ptr<KeyEvent> keyEvent)
{
    timerId_ = TimerMgr->AddTimer(delay, REPEAT_ONCE,
        [this, tKeyEvent = KeyEvent::Clone(keyEvent)]() {
            if (!handlers_.empty()) {
                handlers_.rbegin()->Run(tKeyEvent);
            }
        });
}

bool KeyGestureManager::PullUpAccessibility::IsWorking()
{
    return true;
}

KeyGestureManager::KeyGestureManager()
{
    keyGestures_.push_back(std::make_unique<PullUpAccessibility>(std::set({
        KeyEvent::KEYCODE_VOLUME_DOWN, KeyEvent::KEYCODE_VOLUME_UP
    })));
    keyGestures_.push_back(std::make_unique<LongPressSingleKey>(KeyEvent::KEYCODE_VOLUME_DOWN));
    keyGestures_.push_back(std::make_unique<LongPressSingleKey>(KeyEvent::KEYCODE_VOLUME_UP));
}

bool KeyGestureManager::ShouldIntercept(std::shared_ptr<KeyOption> keyOption) const
{
    CALL_INFO_TRACE;
    CHKPF(keyOption);
    return std::any_of(keyGestures_.cbegin(), keyGestures_.cend(),
        [keyOption](const auto &keyGesture) {
            return keyGesture->ShouldIntercept(keyOption);
        });
}

int32_t KeyGestureManager::AddKeyGesture(std::shared_ptr<KeyOption> keyOption,
    std::function<void(std::shared_ptr<KeyEvent>)> callback)
{
    for (auto &keyGesture : keyGestures_) {
        if (keyGesture->ShouldIntercept(keyOption)) {
            auto downDuration = std::max(keyOption->GetFinalKeyDownDuration(), COMBINATION_KEY_TIMEOUT);
            return keyGesture->AddHandler(downDuration, callback);
        }
    }
    return -1;
}

void KeyGestureManager::RemoveKeyGesture(int32_t id)
{
    for (auto &keyGesture : keyGestures_) {
        if (keyGesture->RemoveHandler(id)) {
            break;
        }
    }
}

bool KeyGestureManager::Intercept(std::shared_ptr<KeyEvent> keyEvent)
{
    CALL_INFO_TRACE;
    CHKPF(keyEvent);
    for (auto iter = keyGestures_.begin(); iter != keyGestures_.end(); ++iter) {
        if ((*iter)->Intercept(keyEvent)) {
            std::ostringstream output;
            output << "Intercepted by ";
            (*iter)->Dump(output);
            MMI_HILOGI("%{public}s", output.str().c_str());
            for (++iter; iter != keyGestures_.end(); ++iter) {
                (*iter)->Reset();
            }
            return true;
        }
    }
    return false;
}

void KeyGestureManager::Dump() const
{
    for (const auto &keyGesture : keyGestures_) {
        std::ostringstream output;
        keyGesture->Dump(output);
        MMI_HILOGI("%{public}s", output.str().c_str());
    }
}
} // namespace MMI
} // namespace OHOS
