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

#ifndef KEY_GESTURE_MANAGER_H
#define KEY_GESTURE_MANAGER_H

#include <functional>
#include <set>
#include <sstream>

#include <nocopyable.h>

#include "key_event.h"
#include "key_option.h"
#include "setting_observer.h"

namespace OHOS {
namespace MMI {

class KeyGestureManager final {
    class Handler final {
    public:
        Handler(int32_t id, int32_t downDuration, std::function<void(std::shared_ptr<KeyEvent>)> callback)
            : id_(id), longPressTime_(downDuration), callback_(callback) {}

        bool operator<(const Handler &other) const
        {
            return (longPressTime_ < other.longPressTime_);
        }

        int32_t GetId() const
        {
            return id_;
        }

        int32_t GetLongPressTime() const
        {
            return longPressTime_;
        }

        void SetLongPressTime(int32_t longPressTime)
        {
            longPressTime_ = longPressTime;
        }

        void Run(std::shared_ptr<KeyEvent> keyEvent) const
        {
            if (callback_ != nullptr) {
                callback_(keyEvent);
            }
        }

    private:
        int32_t id_ { -1 };
        int32_t longPressTime_ { -1 };
        std::function<void(std::shared_ptr<KeyEvent>)> callback_;
    };

    class KeyGesture {
    public:
        KeyGesture() = default;
        virtual ~KeyGesture() = default;

        virtual bool IsWorking();
        virtual bool ShouldIntercept(std::shared_ptr<KeyOption> keyOption) const = 0;
        virtual bool Intercept(std::shared_ptr<KeyEvent> KeyEvent) = 0;
        virtual void Dump(std::ostringstream &output) const = 0;
        virtual int32_t AddHandler(int32_t downDuration, std::function<void(std::shared_ptr<KeyEvent>)> callback);
        bool RemoveHandler(int32_t id);
        void Reset();
        bool IsActive() const;
        void MarkActive(bool active);

    protected:
        void ResetTimer();

        bool active_ { false };
        int32_t timerId_ { -1 };
        std::set<int32_t> keys_;
        std::set<Handler> handlers_;
    };

    class LongPressSingleKey : public KeyGesture {
    public:
        LongPressSingleKey(int32_t keyCode) : keyCode_(keyCode) {}
        ~LongPressSingleKey() = default;

        bool ShouldIntercept(std::shared_ptr<KeyOption> keyOption) const override;
        bool Intercept(std::shared_ptr<KeyEvent> KeyEvent) override;
        void Dump(std::ostringstream &output) const override;

    private:
        void TriggerHandler(int32_t delay, std::shared_ptr<KeyEvent> KeyEvent);

        int32_t keyCode_ { -1 };
    };

    class LongPressCombinationKey : public KeyGesture {
    public:
        LongPressCombinationKey(const std::set<int32_t> &keys) : keys_(keys) {}
        ~LongPressCombinationKey() = default;

        bool ShouldIntercept(std::shared_ptr<KeyOption> keyOption) const override;
        bool Intercept(std::shared_ptr<KeyEvent> KeyEvent) override;
        void Dump(std::ostringstream &output) const override;

    private:
        void TriggerHandler(int32_t delay, std::shared_ptr<KeyEvent> KeyEvent);

        int64_t firstDownTime_ {};
        std::set<int32_t> keys_;
    };

    class PullUpAccessibility final : public LongPressCombinationKey {
        struct Setting {
            bool enable;
            bool enableOnScreenLocked;
        };

    public:
        PullUpAccessibility();
        ~PullUpAccessibility();

        bool IsWorking() override;
        int32_t AddHandler(int32_t downDuration, std::function<void(std::shared_ptr<KeyEvent>)> callback) override;

    private:
        sptr<SettingObserver> RegisterSettingObserver(const std::string &key, SettingObserver::UpdateFunc onUpdate);
        void InitializeSetting();
        bool ReadSwitchStatus(const std::string &key, bool currentSwitchStatus);
        void ReadLongPressTime();

        sptr<SettingObserver> switchObserver_;
        sptr<SettingObserver> onScreenLockedSwitchObserver_;
        sptr<SettingObserver> configObserver_;
        Setting setting_ {};
    };

public:
    KeyGestureManager();
    ~KeyGestureManager() = default;
    DISALLOW_COPY_AND_MOVE(KeyGestureManager);

    bool ShouldIntercept(std::shared_ptr<KeyOption> keyOption) const;
    int32_t AddKeyGesture(std::shared_ptr<KeyOption> keyOption,
        std::function<void(std::shared_ptr<KeyEvent>)> callback);
    void RemoveKeyGesture(int32_t id);
    bool Intercept(std::shared_ptr<KeyEvent> KeyEvent);
    void Dump() const;

private:
    std::vector<std::unique_ptr<KeyGesture>> keyGestures_;
};

inline bool KeyGestureManager::KeyGesture::IsActive() const
{
    return active_;
}

inline void KeyGestureManager::KeyGesture::MarkActive(bool active)
{
    active_ = active;
}
} // namespace MMI
} // namespace OHOS
#endif // KEY_GESTURE_MANAGER_H