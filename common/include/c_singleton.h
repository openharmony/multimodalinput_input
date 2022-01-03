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
#ifndef OHOS_C_SINGLETON_H
#define OHOS_C_SINGLETON_H
#include <utility>

namespace OHOS {
namespace MMI {
template<typename T>
class CSingleton {
public:
    template<typename ...Args>
    static T *GetInstance(Args &&... args)
    {
        if (mInstance_ == nullptr) {
            static T obj(std::forward<Args>(args)...);
            mInstance_ = &obj;
        }
        return mInstance_;
    }
protected:
    CSingleton() {};
    ~CSingleton() {};
    CSingleton(const CSingleton&);
    CSingleton& operator = (const CSingleton&);
private:
    static T *mInstance_;
};

template<class T> T *CSingleton<T>::mInstance_ = nullptr;
}
}
#endif
