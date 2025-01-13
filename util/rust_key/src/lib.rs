/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

//!
use hilog_rust::{error, hilog, HiLogLabel, LogType};
use std::ffi::{c_char, CString};
use std::ffi::CStr;

const LOG_LABEL: HiLogLabel = HiLogLabel {
    log_type: LogType::LogCore,
    domain: 0xd002800,
    tag: "MMIRustKey",
};

static RET_OK: i32 = 0;
static RET_ERR: i32 = -1;
static KEY_ELEMENT_SIZE: usize = 4;
const NPOS: usize = usize::MAX;

#[no_mangle]
extern "C" fn ReadConfigInfo(
    info_line: *const c_char,
    len: i32,
    element_key: *mut i32,
    element_value: *mut i32,
) -> i32 {
    if len <= 0 {
        error!(LOG_LABEL, "The config info format is error");
        return RET_ERR;
    }
    let mut key: i32 = 0;
    let mut value: i32 = 0;
    let c_str: &CStr = unsafe { CStr::from_ptr(info_line) };
    let line_str: String = c_str.to_str().unwrap().to_owned();
    let pos = line_str.find('#');
    if let Some(pos) = pos {
        if pos != NPOS || pos != 0 {
            error!(LOG_LABEL, "The comment line format is error");
            return RET_ERR;
        }
    }
    if !line_str.is_empty() && !line_str.starts_with('#') {
        let key_element: Vec<&str> = line_str.split(' ').collect();
        if key_element.len() != KEY_ELEMENT_SIZE {
            error!(LOG_LABEL, "The key value data is incomplete");
            return RET_ERR;
        }
        if key_element[1].parse::<i32>().is_err() || key_element[2].parse::<i32>().is_err() {
            error!(LOG_LABEL, "Get key value is invalid");
            return RET_ERR;
        }
        key = key_element[1].parse::<i32>().unwrap();
        value = key_element[2].parse::<i32>().unwrap();
    }
    unsafe {
        *element_key = key;
        *element_value = value;
    }
    RET_OK
}

#[test]
fn test_read_config_info_normal()
{
    let info = String::from("KEY_BTN_0 256 3100 HOS_KEY_BTN_0");
    let info_line = info.as_ptr() as *const u8;
    let len: i32 = 33;
    let mut element_key: i32 = 0;
    let mut element_value: i32 = 0;
    let ret: i32 = ReadConfigInfo(info_line, len, &mut element_key as *mut i32, &mut element_value as *mut i32);
    assert_eq!(ret, RET_ERR);
}

#[test]
fn test_read_config_info_invalid()
{
    let info = "#KEY_BTN_0 256 3100 HOS_KEY_BTN_0";
    let info_line = info.as_ptr() as *const u8;
    let len: i32 = 34;
    let mut element_key: i32 = 0;
    let mut element_value: i32 = 0;
    let ret: i32 = ReadConfigInfo(info_line, len, &mut element_key as *mut i32, &mut element_value as *mut i32);
    assert_eq!(ret, RET_ERR);
}

#[test]
fn test_read_config_info_len_invalid()
{
    let info = "KEY_BTN_0 256 3100 HOS_KEY_BTN_0";
    let info_line = info.as_ptr() as *const u8;
    let len: i32 = 0;
    let mut element_key: i32 = 0;
    let mut element_value: i32 = 0;
    let ret: i32 = ReadConfigInfo(info_line, len, &mut element_key as *mut i32, &mut element_value as *mut i32);
    assert_eq!(ret, RET_ERR);
}