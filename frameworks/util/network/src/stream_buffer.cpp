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

#include "stream_buffer.h"
#include "define_multimodal.h"

namespace OHOS {
namespace MMI {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, MMI_LOG_DOMAIN, "StreamBuffer" };
}

template<typename T>
const char* GetTypeName()
{
    int status = 0;
    std::string tname = typeid(T).name();
    auto demName = abi::__cxa_demangle(tname.c_str(), nullptr, nullptr, &status);
    if (status == 0) {
        tname = demName;
        std::free(demName);
    }
    return tname.c_str();
}
#define TNAME(val) GetTypeName<decltype(val)>()
#define VNAME(name) (#name)

StreamBuffer::StreamBuffer()
{
    ResetBuf();
}

void StreamBuffer::ResetBuf()
{
    CHK(EOK == memset_sp(&szBuff_, sizeof(szBuff_), 0, sizeof(szBuff_)), MEMCPY_SEC_FUN_FAIL);
}

void StreamBuffer::Clean()
{
    rIdx_ = 0;
    wIdx_ = 0;
    ResetBuf();
    ResetError();
}

bool StreamBuffer::ChkError() const
{
    return (rwError_ != ErrorStatus::ES_OK);
}

const char* StreamBuffer::GetErrorString() const
{
    return rwErrStr_.c_str();
}

void StreamBuffer::ResetError()
{
    rwError_ = ErrorStatus::ES_OK
    rwErrStr_.clear();
}

bool StreamBuffer::SetReadIdx(uint32_t idx)
{
    CHKF(idx <= wIdx_, PARAM_INPUT_INVALID);
    rIdx_ = idx;
    return true;
}

bool StreamBuffer::Read(std::string &buf)
{
    if (rIdx_ == wIdx_) {
        MMI_LOGE("Not enough memory to read... errCode:%{public}d", MEM_NOT_ENOUGH);
        return false;
    }
    buf = ReadBuf();
    rIdx_ += static_cast<uint32_t>(buf.size()) + 1;
    return (buf.size() > 0);
}

bool StreamBuffer::Read(char *buf, size_t size)
{
    if (ChkError()) {
        return false; // No need to print log here, only the first error needs to be printed
    }
    if (buf == nullptr) {
        MMI_LOGE("Invalid input parameter buf=nullptr errCode:%{public}d", ERROR_NULL_POINTER);
        rwError_ = ErrorStatus::ES_READ;
        return false;
    }
    if (size <= 0) {
        MMI_LOGE("Invalid input parameter size=%{public}d errCode:%{public}d", size, PARAM_INPUT_INVALID);
        rwError_ = ErrorStatus::ES_READ;
        return false;
    }
    if (rIdx_ + size > wIdx_) {
        MMI_LOGE("Memory out of bounds on read... errCode:%{public}d", MEM_OUT_OF_BOUNDS);
        rwError = ErrorStatus::ES_READ;
        return false;
    }
    if (EOK != memcpy_sp(buf, size, ReadBuf(), size)) {
        MMI_LOGE("memcpy_sp call fail. errCode:%{public}d", MEMCPY_SEC_FUN_FAIL);
        rwError_ = ErrorStatus::ES_READ;
        return false;
    }
    rIdx_ += static_cast<uint32_t>(size);
    return true;
}

bool StreamBuffer::Write(const StreamBuffer &buf)
{
    return Write(buf.Data(), buf.Size());
}

const char *StreamBuffer::Data() const
{
    return &szBuff_[0];
}

const char *StreamBuffer::ReadBuf() const
{
    return &szBuff_[rIdx_];
}

const char *StreamBuffer::WriteBuf() const
{
    return &szBuff_[wIdx_];
}

bool StreamBuffer::Clone(const StreamBuffer &buf)
{
    Clean();
    return Write(buf.Data(), buf.Size());
}

size_t StreamBuffer::Size() const
{
    return wIdx_;
}

size_t StreamBuffer::UnreadSize() const
{
    CHKR(wIdx_ >= rIdx_, VAL_NOT_EXP, 0);
    return (wIdx_ - rIdx_);
}

bool StreamBuffer::Write(const char *buf, size_t size)
{
    if (ChkError()) {
        return false; // No need to print log here, only the first error needs to be printed
    }
    if (buf == nullptr) {
        MMI_LOGE("Invalid input parameter buf=nullptr errCode:%{public}d", ERROR_NULL_POINTER);
        rwError_ = ErrorStatus::ES_WRITE;
        return false;
    }
    if (size <= 0) {
        MMI_LOGE("Invalid input parameter size=%{public}d errCode:%{public}d", size, PARAM_INPUT_INVALID);
        rwError_ = ErrorStatus::ES_WRITE;
        return false;
    }
    if (wIdx_ + size >= MAX_STREAM_BUF_SIZE) {
        MMI_LOGE("The write length exceeds buffer. errCode:%{public}d", MEM_OUT_OF_BOUNDS);
        rwError_ = ErrorStatus::ES_WRITE;
        return false;
    }
    if (EOK != memcpy_sp(&szBuff_[wIdx_], (MAX_STREAM_BUF_SIZE - wIdx_), buf, size)) {
        MMI_LOGE("memcpy_sp call fail. errCode:%{public}d", MEMCPY_SEC_FUN_FAIL);
        rwError_ = ErrorStatus::ES_WRITE;
        return false;
    }
    wIdx_ += static_cast<uint32_t>(size);
    return true;
}

bool StreamBuffer::Read(StreamBuffer &buf)
{
    return buf.Write(Data(), Size());
}

bool StreamBuffer::Write(const std::string &buf)
{
    return Write(buf.c_str(), buf.size() + 1);
}

StreamBuffer &StreamBuffer::operator=(const StreamBuffer &other)
{
    Clone(other);
    return *this;
}

StreamBuffer::StreamBuffer(const StreamBuffer &buf)
{
    Clone(buf);
}

bool StreamBuffer::IsEmpty()
{
    if (rIdx_ == wIdx_) {
        return true;
    }
    return false;
}
}
}