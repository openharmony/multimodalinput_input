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

OHOS::MMI::StreamBuffer::StreamBuffer()
{
    ResetBuf();
}

void OHOS::MMI::StreamBuffer::ResetBuf()
{
    CHK(EOK == memset_sp(&szBuff_, sizeof(szBuff_), 0, sizeof(szBuff_)), MEMCPY_SEC_FUN_FAIL);
}

void OHOS::MMI::StreamBuffer::Clean()
{
    rIdx_ = 0;
    wIdx_ = 0;
    ResetBuf();
}

bool OHOS::MMI::StreamBuffer::SetReadIdx(uint32_t idx)
{
    CHKF(idx <= wIdx_, PARAM_INPUT_INVALID);
    rIdx_ = idx;
    return true;
}

bool OHOS::MMI::StreamBuffer::Read(std::string &buf)
{
    if (rIdx_ == wIdx_) {
        MMI_LOGE("Not enough memory to read... errCode:%{public}d", MEM_NOT_ENOUGH);
        return false;
    }
    buf = ReadBuf();
    rIdx_ += static_cast<uint32_t>(buf.size()) + 1;
    return (buf.size() > 0);
}

bool OHOS::MMI::StreamBuffer::Read(char *buf, size_t size)
{
    CHKF(buf && size > 0, PARAM_INPUT_INVALID);
    if (rIdx_ + size > wIdx_) {
        MMI_LOGE("Memory out of bounds on read... errCode:%{public}d", MEM_OUT_OF_BOUNDS);
        return false;
    }
    CHKF(EOK == memcpy_sp(buf, size, ReadBuf(), size), MEMCPY_SEC_FUN_FAIL);
    rIdx_ += static_cast<uint32_t>(size);
    return true;
}

bool OHOS::MMI::StreamBuffer::Write(const StreamBuffer &buf)
{
    return Write(buf.Data(), buf.Size());
}

const char *OHOS::MMI::StreamBuffer::Data() const
{
    return &szBuff_[0];
}

const char *OHOS::MMI::StreamBuffer::ReadBuf() const
{
    return &szBuff_[rIdx_];
}

const char *OHOS::MMI::StreamBuffer::WriteBuf() const
{
    return &szBuff_[wIdx_];
}

bool OHOS::MMI::StreamBuffer::Clone(const StreamBuffer &buf)
{
    Clean();
    return Write(buf.Data(), buf.Size());
}

size_t OHOS::MMI::StreamBuffer::Size() const
{
    return wIdx_;
}

size_t OHOS::MMI::StreamBuffer::UnreadSize() const
{
    CHKR(wIdx_ >= rIdx_, VAL_NOT_EXP, 0);
    return (wIdx_ - rIdx_);
}

bool OHOS::MMI::StreamBuffer::Write(const char *buf, size_t size)
{
    CHKF(buf && size > 0, PARAM_INPUT_INVALID);
    if (wIdx_ + size >= MAX_STREAM_BUF_SIZE) {
        MMI_LOGE("Memory out of bounds on write... errCode:%{public}d", MEM_OUT_OF_BOUNDS);
        return false;
    }
    CHKF(EOK == memcpy_sp(&szBuff_[wIdx_], (MAX_STREAM_BUF_SIZE - wIdx_), buf, size), MEMCPY_SEC_FUN_FAIL);
    wIdx_ += static_cast<uint32_t>(size);
    return true;
}

bool OHOS::MMI::StreamBuffer::Read(StreamBuffer &buf)
{
    return buf.Write(Data(), Size());
}

bool OHOS::MMI::StreamBuffer::Write(const std::string &buf)
{
    return Write(buf.c_str(), buf.size() + 1);
}

OHOS::MMI::StreamBuffer &OHOS::MMI::StreamBuffer::operator=(const StreamBuffer &other)
{
    Clone(other);
    return *this;
}

OHOS::MMI::StreamBuffer::StreamBuffer(const StreamBuffer &buf)
{
    Clone(buf);
}
