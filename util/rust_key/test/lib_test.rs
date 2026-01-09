/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#[cfg(test)]
mod tests {
    use std::ffi::{c_char, CString};
    use std::os::raw::c_int;

    extern "C" {
        fn ReadConfigInfo(
            info_line: *const c_char,
            len: c_int,
            element_key: *mut c_int,
            element_value: *mut c_int,
        ) -> c_int;
    }

    const RET_OK: i32 = 0;
    const RET_ERR: i32 = -1;

    /**
     * @tc.name: ReadConfigInfoTest_Normal_001
     * @tc.desc: Test the function ReadConfigInfo with normal input
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_normal() {
        let info = CString::new("KEY_BTN_0 256 3100 HOS_KEY_BTN_0").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;

        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(element_key, 256);
        assert_eq!(element_value, 3100);
    }

    /**
     * @tc.name: ReadConfigInfoTest_CommentLine_001
     * @tc.desc: Test the function ReadConfigInfo with comment line input
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_invalid() {
        let info = CString::new("#KEY_BTN_0 256 3100 HOS_KEY_BTN_0").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;

        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_ERR);
    }

    /**
     * @tc.name: ReadConfigInfoTest_InvalidLength_001
     * @tc.desc: Test the function ReadConfigInfo with invalid length input
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_len_invalid() {
        let info = CString::new("KEY_BTN_0 256 3100 HOS_KEY_BTN_0").unwrap();
        let len: i32 = 0;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;

        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_ERR);
    }

    /**
     * @tc.name: ReadConfigInfoTest_NegativeValues_001
     * @tc.desc: Test the function ReadConfigInfo with negative values
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_negative_values() {
        let info = CString::new("KEY_TEST -100 -200 TEST_KEY").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;

        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(element_key, -100);
        assert_eq!(element_value, -200);
    }

    /**
     * @tc.name: ReadConfigInfoTest_ZeroValues_001
     * @tc.desc: Test the function ReadConfigInfo with zero values
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_zero_values() {
        let info = CString::new("KEY_ZERO 0 0 ZERO_KEY").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;

        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(element_key, 0);
        assert_eq!(element_value, 0);
    }

    /**
     * @tc.name: ReadConfigInfoTest_TooManyElements_001
     * @tc.desc: Test the function ReadConfigInfo with too many elements
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_too_many_elements() {
        let info = CString::new("KEY_EXTRA 100 200 EXTRA_DATA MORE_DATA").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;

        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_ERR);
    }

    /**
     * @tc.name: ReadConfigInfoTest_NotEnoughElements_001
     * @tc.desc: Test the function ReadConfigInfo with not enough elements
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_not_enough_elements() {
        let info = CString::new("KEY_LESS 100").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;
        
        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_ERR);
    }

    /**
     * @tc.name: ReadConfigInfoTest_InvalidNumberFormat_001
     * @tc.desc: Test the function ReadConfigInfo with invalid number format
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_invalid_number_format() {
        let info = CString::new("KEY_INVALID abc def INVALID_KEY").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;
        
        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_ERR);
    }

    /**
     * @tc.name: ReadConfigInfoTest_EmptyLine_001
     * @tc.desc: Test the function ReadConfigInfo with empty line
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_empty_line() {
        let info = CString::new("").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;
        
        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_ERR);
        assert_eq!(element_key, 0);
        assert_eq!(element_value, 0);
    }

    /**
     * @tc.name: ReadConfigInfoTest_OnlySpaces_001
     * @tc.desc: Test the function ReadConfigInfo with only spaces
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_only_spaces() {
        let info = CString::new("   ").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;
        
        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_ERR);
        assert_eq!(element_key, 0);
        assert_eq!(element_value, 0);
    }

    /**
     * @tc.name: ReadConfigInfoTest_TabSeparated_001
     * @tc.desc: Test the function ReadConfigInfo with tab separated values
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_tab_separated() {
        let info = CString::new("KEY_TAB\t100\t200\tTAB_KEY").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;
        
        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_ERR); // 因为split(' ')不能正确分割tab
    }

    /**
     * @tc.name: ReadConfigInfoTest_MultipleSpaces_001
     * @tc.desc: Test the function ReadConfigInfo with multiple spaces
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_multiple_spaces() {
        let info = CString::new("KEY_SPACES   300   400   SPACES_KEY").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;
        
        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };

        assert_eq!(ret, RET_ERR);
    }

    /**
     * @tc.name: ReadConfigInfoTest_MaxIntValues_001
     * @tc.desc: Test the function ReadConfigInfo with maximum integer values
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_max_int_values() {
        let info = CString::new(format!("KEY_MAX {} {} MAX_KEY", i32::MAX, i32::MAX)).unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;
        
        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(element_key, i32::MAX);
        assert_eq!(element_value, i32::MAX);
    }

    /**
     * @tc.name: ReadConfigInfoTest_MinIntValues_001
     * @tc.desc: Test the function ReadConfigInfo with minimum integer values
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_min_int_values() {
        let info = CString::new("KEY_MIN -2147483648 -2147483648 MIN_KEY").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;
        
        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(element_key, i32::MIN);
        assert_eq!(element_value, i32::MIN);
    }

    /**
     * @tc.name: ReadConfigInfoTest_LargeNumbers_001
     * @tc.desc: Test the function ReadConfigInfo with large numbers
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_large_numbers() {
        let info = CString::new("KEY_LARGE 2147483647 -2147483648 LARGE_KEY").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;
        
        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(element_key, 2147483647);
        assert_eq!(element_value, -2147483648);
    }

    /**
     * @tc.name: ReadConfigInfoTest_MixedCase_001
     * @tc.desc: Test the function ReadConfigInfo with mixed case input
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_mixed_case() {
        let info = CString::new("key_mixed 123 456 Hos_Key_Mixed").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;
        
        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(element_key, 123);
        assert_eq!(element_value, 456);
    }

    /**
     * @tc.name: ReadConfigInfoTest_SpecialCharsInName_001
     * @tc.desc: Test the function ReadConfigInfo with special characters in name
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_read_config_info_special_chars_in_name() {
        let info = CString::new("KEY_WITH_UNDERSCORES 500 600 HOS_KEY_SPECIAL").unwrap();
        let len: i32 = info.to_bytes().len() as i32;
        let mut element_key: i32 = 0;
        let mut element_value: i32 = 0;
        
        let ret: i32 = unsafe {
            ReadConfigInfo(info.as_ptr(), len, 
                          &mut element_key as *mut i32, 
                          &mut element_value as *mut i32)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(element_key, 500);
        assert_eq!(element_value, 600);
    }
}