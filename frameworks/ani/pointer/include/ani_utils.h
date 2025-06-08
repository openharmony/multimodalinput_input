/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef ANI_UTILS_H
#define ANI_UTILS_H

#include <ani.h>

#include <cstdarg>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <iostream>

class AniObjectUtils {
public:
    // 创建一个ani_object对象，使用命名空间和类名
    static ani_object Create(ani_env *env, const char* nsName, const char* clsName, ...)
    {
        // 创建一个空的对象
        ani_object nullobj{};

        // 查找命名空间
        ani_namespace ns;
        if (ANI_OK != env->FindNamespace(nsName, &ns)) {
            return nullobj;
        }

        // 查找类
        ani_class cls;
        if (ANI_OK != env->Namespace_FindClass(ns, clsName, &cls)) {
            return nullobj;
        }

        ani_method ctor;
        if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
            return nullobj;
        }

        ani_object obj;
        va_list args;
        va_start(args, clsName);
        ani_status status = env->Object_New_V(cls, ctor, &obj, args);
        va_end(args);
        if (ANI_OK != status)  {
            return nullobj;
        }
        return obj;
    }

    static ani_object Create(ani_env *env, const char* clsName, ...)
    {
        ani_object nullobj{};
        // 查找类
        ani_class cls;
        if (ANI_OK != env->FindClass(clsName, &cls)) {
            return nullobj;
        }
        ani_method ctor;
        if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
            return nullobj;
        }

        ani_object obj;
        va_list args;
        va_start(args, clsName);
        ani_status status = env->Object_New_V(cls, ctor, &obj, args);
        va_end(args);
        if (ANI_OK != status) {
            return nullobj;
        }
        return obj;
    }

    static ani_object Create(ani_env *env, ani_class cls, ...)
    {
        ani_object nullobj{};

        ani_method ctor;
        if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
            return nullobj;
        }

        ani_object obj;
        va_list args;
        va_start(args, cls);
        ani_status status = env->Object_New_V(cls, ctor, &obj, args);
        va_end(args);
        if (ANI_OK != status) {
            return nullobj;
        }
        return obj;
    }

    static ani_object From(ani_env *env, bool value)
    {
        return Create(env, "Lstd/core/Boolean;", static_cast<ani_boolean>(value));
    }

    template<typename T>
    static ani_status Wrap(ani_env *env, ani_object object, T* nativePtr, const char* propName = "nativePtr")
    {
        return env->Object_SetFieldByName_Long(object, propName, reinterpret_cast<ani_long>(nativePtr));
    }

    template<typename T>
    static T* Unwrap(ani_env *env, ani_object object, const char* propName = "nativePtr")
    {
        ani_long nativePtr;
        if (ANI_OK != env->Object_GetFieldByName_Long(object, propName, &nativePtr)) {
            return nullptr;
        }
        if (nativePtr == 0) {
            return nullptr;
        }
        return reinterpret_cast<T*>(nativePtr);
    }
};

class AniStringUtils {
public:
    static std::string ToStd(ani_env *env, ani_string ani_str)
    {
        ani_size strSize;
        env->String_GetUTF8Size(ani_str, &strSize);

        std::vector<char> buffer(strSize + 1); // +1 for null terminator
        char* utf8_buffer = buffer.data();

        ani_size bytes_written = 0;
        env->String_GetUTF8(ani_str, utf8_buffer, strSize + 1, &bytes_written);

        utf8_buffer[bytes_written] = '\0';
        std::string content = std::string(utf8_buffer);
        return content;
    }

    static ani_string ToAni(ani_env* env, const std::string& str)
    {
        ani_string aniStr = nullptr;
        if (ANI_OK != env->String_NewUTF8(str.data(), str.size(), &aniStr)) {
            return nullptr;
        }
        return aniStr;
    }
};

class UnionAccessor {
public:
    UnionAccessor(ani_env *env, ani_object &obj) : env_(env), obj_(obj)
    {
    }

    bool IsInstanceOf(const std::string& cls_name)
    {
        ani_class cls;
        env_->FindClass(cls_name.c_str(), &cls);

        ani_boolean ret;
        env_->Object_InstanceOf(obj_, cls, &ret);
        return ret;
    }

    template<typename T>
    bool IsInstanceOfType();

    template<typename T>
    bool TryConvert(T &value);

    template<typename T>
    bool TryConvertArray(std::vector<T> &value);

private:
    ani_env *env_;
    ani_object obj_;
};

template<>
bool UnionAccessor::IsInstanceOfType<bool>()
{
    return IsInstanceOf("Lstd/core/Boolean;");
}

template<>
bool UnionAccessor::IsInstanceOfType<int>()
{
    return IsInstanceOf("Lstd/core/Int;");
}

template<>
bool UnionAccessor::IsInstanceOfType<double>()
{
    return IsInstanceOf("Lstd/core/Double;");
}

template<>
bool UnionAccessor::IsInstanceOfType<std::string>()
{
    return IsInstanceOf("Lstd/core/String;");
}

template<>
bool UnionAccessor::TryConvert<bool>(bool &value)
{
    if (!IsInstanceOfType<bool>()) {
        return false;
    }

    ani_boolean aniValue;
    auto ret = env_->Object_CallMethodByName_Boolean(obj_, "unboxed", nullptr, &aniValue);
    if (ret != ANI_OK) {
        return false;
    }
    value = static_cast<bool>(aniValue);
    return true;
}

template<>
bool UnionAccessor::TryConvert<int>(int &value)
{
    if (!IsInstanceOfType<int>()) {
        return false;
    }

    ani_int aniValue;
    auto ret = env_->Object_CallMethodByName_Int(obj_, "unboxed", nullptr, &aniValue);
    if (ret != ANI_OK) {
        return false;
    }
    value = static_cast<int>(aniValue);
    return true;
}

template<>
bool UnionAccessor::TryConvert<double>(double &value)
{
    if (!IsInstanceOfType<double>()) {
        return false;
    }

    ani_double aniValue;
    auto ret = env_->Object_CallMethodByName_Double(obj_, "unboxed", nullptr, &aniValue);
    if (ret != ANI_OK) {
        return false;
    }
    value = static_cast<double>(aniValue);
    return true;
}

template<>
bool UnionAccessor::TryConvert<std::string>(std::string &value)
{
    if (!IsInstanceOfType<std::string>()) {
        return false;
    }

    value = AniStringUtils::ToStd(env_, static_cast<ani_string>(obj_));
    return true;
}

template<>
bool UnionAccessor::TryConvertArray<bool>(std::vector<bool> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "I:Lstd/core/Object;", &ref, (ani_int)i)) {
            return false;
        }
        ani_boolean val;
        if (ANI_OK != env_->Object_CallMethodByName_Boolean(static_cast<ani_object>(ref), "unboxed", nullptr, &val)) {
            return false;
        }
        value.push_back(static_cast<bool>(val));
    }
    return true;
}

template<>
bool UnionAccessor::TryConvertArray<int>(std::vector<int> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "I:Lstd/core/Object;", &ref, (ani_int)i)) {
            return false;
        }
        ani_int intValue;
        if (ANI_OK != env_->Object_CallMethodByName_Int(static_cast<ani_object>(ref), "unboxed", nullptr, &intValue)) {
            return false;
        }
        value.push_back(static_cast<int>(intValue));
    }
    return true;
}

template<>
bool UnionAccessor::TryConvertArray<double>(std::vector<double> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        return false;
    }
    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "I:Lstd/core/Object;", &ref, (ani_int)i)) {
            return false;
        }
        ani_double val;
        if (ANI_OK != env_->Object_CallMethodByName_Double(static_cast<ani_object>(ref), "unboxed", nullptr, &val)) {
            return false;
        }
        value.push_back(static_cast<double>(val));
    }
    return true;
}

template<>
bool UnionAccessor::TryConvertArray<uint8_t>(std::vector<uint8_t> &value)
{
    ani_ref buffer;
    if (ANI_OK != env_->Object_GetFieldByName_Ref(obj_, "buffer", &buffer)) {
        return false;
    }
    void* data;
    size_t length;
    if (ANI_OK != env_->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &data, &length)) {
        return false;
    }

    for (size_t i = 0; i < length; i++) {
        value.push_back(static_cast<uint8_t*>(data)[i]);
    }
    return true;
}

template<>
bool UnionAccessor::TryConvertArray<std::string>(std::vector<std::string> &value)
{
    ani_double length;
    if (ANI_OK != env_->Object_GetPropertyByName_Double(obj_, "length", &length)) {
        return false;
    }

    for (int i = 0; i < int(length); i++) {
        ani_ref ref;
        if (ANI_OK != env_->Object_CallMethodByName_Ref(obj_, "$_get", "I:Lstd/core/Object;", &ref, (ani_int)i)) {
            return false;
        }
        value.push_back(AniStringUtils::ToStd(env_, static_cast<ani_string>(ref)));
    }
    return true;
}

class OptionalAccessor {
public:
    OptionalAccessor(ani_env *env, ani_object &obj) : env_(env), obj_(obj)
    {
    }

    bool IsUndefined()
    {
        ani_boolean isUndefined;
        env_->Reference_IsUndefined(obj_, &isUndefined);
        return isUndefined;
    }

    template<typename T>
    std::optional<T> Convert();

private:
    ani_env *env_;
    ani_object obj_;
};

template<>
std::optional<double> OptionalAccessor::Convert<double>()
{
    if (IsUndefined()) {
        return std::nullopt;
    }

    ani_double aniValue;
    auto ret = env_->Object_CallMethodByName_Double(obj_, "doubleValue", nullptr, &aniValue);
    if (ret != ANI_OK) {
        return std::nullopt;
    }
    auto value = static_cast<double>(aniValue);
    return value;
}

template<>
std::optional<std::string> OptionalAccessor::Convert<std::string>()
{
    if (IsUndefined()) {
        return std::nullopt;
    }

    ani_size strSize;
    env_->String_GetUTF8Size(static_cast<ani_string>(obj_), &strSize);

    std::vector<char> buffer(strSize + 1);
    char* utf8_buffer = buffer.data();

    ani_size bytes_written = 0;
    env_->String_GetUTF8(static_cast<ani_string>(obj_), utf8_buffer, strSize + 1, &bytes_written);

    utf8_buffer[bytes_written] = '\0';
    std::string content = std::string(utf8_buffer);
    return content;
}


class EnumAccessor {
public:
    EnumAccessor(ani_env *env, const char* className, ani_int index) : env_(env), className_(className), index_(index)
    {
    }

    ani_status ToInt(int32_t &value)
    {
        ani_status status = ANI_ERROR;
        ani_enum_item item;
        status = GetItem(item);
        if (ANI_OK != status) {
            return status;
        }

        status = env_->EnumItem_GetValue_Int(item, &value);
        if (ANI_OK != status) {
            return status;
        }
        return ANI_OK;
    }

    ani_status ToString(std::string &value)
    {
        ani_status status = ANI_ERROR;
        ani_enum_item item;
        status = GetItem(item);
        if (ANI_OK != status) {
            return status;
        }

        ani_string strValue;
        status = env_->EnumItem_GetValue_String(item, &strValue);
        if (ANI_OK != status) {
            return status;
        }
        value = AniStringUtils::ToStd(env_, strValue);

        return ANI_OK;
    }

private:
    ani_status GetItem(ani_enum_item &item)
    {
        ani_status status = ANI_ERROR;
        ani_enum enumType;
        status = env_->FindEnum(className_.c_str(), &enumType);
        if (ANI_OK != status) {
            return status;
        }

        status = env_->Enum_GetEnumItemByIndex(enumType, index_, &item);
        if (ANI_OK != status) {
            return status;
        }
        return ANI_OK;
    }

private:
    ani_env *env_;
    std::string className_;
    ani_int index_;
};
#endif
