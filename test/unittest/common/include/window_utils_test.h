/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef WINDOW_UTILS_TEST_H
#define WINDOW_UTILS_TEST_H

#include <iostream>

#include "window.h"

namespace OHOS {
namespace MMI {
class WindowUtilsTest {
public:
    WindowUtilsTest() = default;
    virtual ~WindowUtilsTest();
    DISALLOW_COPY_AND_MOVE(WindowUtilsTest);
    static std::shared_ptr<WindowUtilsTest> GetInstance();
public:
    bool DrawTestWindow();
    void ClearTestWindow();
    sptr<Rosen::Window>& GetWindow();
    uint32_t GetWindowId();

private:
    struct TestWindowInfo {
        std::string name;
        Rosen::Rect rect;
        Rosen::WindowType type;
        Rosen::WindowMode mode;
        bool needAvoid { false };
        bool parentLimit { false };
        uint32_t parentId;
        bool focusable_ { true };
        Rosen::Orientation orientation_ { Rosen::Orientation::UNSPECIFIED };
    };
    void CreateSmoothWindow();
    sptr<Rosen::Window> CreateWindow(const TestWindowInfo& info);
private:
    sptr<Rosen::Window> testWindow_ { nullptr };
    static inline std::shared_ptr<WindowUtilsTest> windowUtils_ { nullptr };
};
} // namespace MMI
} // namespace OHOS

#endif // WINDOW_UTILS_TEST_H