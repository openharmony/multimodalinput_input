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

    #[repr(C)]
    struct Offset {
        dx: f64,
        dy: f64,
    }

    extern "C" {
        fn HandleMotionDynamicAccelerateMouse(
            offset: *const Offset,
            mode: bool,
            abs_x: *mut f64,
            abs_y: *mut f64,
            speed: i32,
            delta_time: u64,
            display_ppi: f64,
            factor: f64
        ) -> i32;

        fn HandleMotionAccelerateMouse(
            offset: *const Offset,
            mode: bool,
            abs_x: *mut f64,
            abs_y: *mut f64,
            speed: i32,
            device_type: i32
        ) -> i32;

        fn HandleMotionDynamicAccelerateTouchpad(
            offset: *const Offset,
            mode: bool,
            abs_x: *mut f64,
            abs_y: *mut f64,
            speed: i32,
            display_size: f64,
            touchpad_size: f64,
            touchpad_ppi: f64,
            frequency: i32
        ) -> i32;

        fn HandleMotionAccelerateTouchpad(
            offset: *const Offset,
            mode: bool,
            abs_x: *mut f64,
            abs_y: *mut f64,
            speed: i32,
            device_type: i32
        ) -> i32;

        fn HandleAxisAccelerateTouchpad(
            mode: bool,
            abs_axis: *mut f64,
            device_type: i32
        ) -> i32;
    }

    const RET_OK: i32 = 0;
    const RET_ERR: i32 = -1;

    /**
     * @tc.name: HandleMotionDynamicAccelerateMouseTest_Normal_001
     * @tc.desc: Test the function HandleMotionDynamicAccelerateMouse with normal input
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_dynamic_accelerate_mouse_normal() {
        let offset = Offset { dx: 10.0, dy: 15.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;
        let old_abs_x = abs_x;
        let old_abs_y = abs_y;

        let ret: i32 = unsafe {
            HandleMotionDynamicAccelerateMouse(&offset, false, &mut abs_x, &mut abs_y, 5, 1000, 150.0, 1.0)
        };
        
        assert_eq!(ret, RET_OK);
        assert_ne!(abs_x, old_abs_x);
        assert_ne!(abs_y, old_abs_y);
    }

    /**
     * @tc.name: HandleMotionDynamicAccelerateMouseTest_CaptureMode_001
     * @tc.desc: Test the function HandleMotionDynamicAccelerateMouse with capture mode enabled
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_dynamic_accelerate_mouse_capture_mode() {
        let offset = Offset { dx: 10.0, dy: 15.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;
        let old_abs_x = abs_x;
        let old_abs_y = abs_y;

        let ret: i32 = unsafe {
            HandleMotionDynamicAccelerateMouse(&offset, true, &mut abs_x, &mut abs_y, 5, 1000, 150.0, 1.0)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(abs_x, old_abs_x);
        assert_eq!(abs_y, old_abs_y);
    }

    /**
     * @tc.name: HandleMotionDynamicAccelerateMouseTest_InvalidSpeed_001
     * @tc.desc: Test the function HandleMotionDynamicAccelerateMouse with invalid speed
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_dynamic_accelerate_mouse_invalid_speed() {
        let offset = Offset { dx: 10.0, dy: 15.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;

        let ret: i32 = unsafe {
            HandleMotionDynamicAccelerateMouse(&offset, false, &mut abs_x, &mut abs_y, 0, 1000, 150.0, 1.0)
        };
        
        assert_eq!(ret, RET_ERR);
    }

    /**
     * @tc.name: HandleMotionAccelerateMouseTest_Normal_001
     * @tc.desc: Test the function HandleMotionAccelerateMouse with normal input
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_accelerate_mouse_normal() {
        let offset = Offset { dx: 10.0, dy: 15.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;
        let old_abs_x = abs_x;
        let old_abs_y = abs_y;

        let ret: i32 = unsafe {
            HandleMotionAccelerateMouse(&offset, false, &mut abs_x, &mut abs_y, 5, 1)
        };
        
        assert_eq!(ret, RET_OK);
        assert_ne!(abs_x, old_abs_x);
        assert_ne!(abs_y, old_abs_y);
    }

    /**
     * @tc.name: HandleMotionAccelerateMouseTest_CaptureMode_001
     * @tc.desc: Test the function HandleMotionAccelerateMouse with capture mode enabled
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_accelerate_mouse_capture_mode() {
        let offset = Offset { dx: 10.0, dy: 15.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;
        let old_abs_x = abs_x;
        let old_abs_y = abs_y;

        let ret: i32 = unsafe {
            HandleMotionAccelerateMouse(&offset, true, &mut abs_x, &mut abs_y, 5, 1)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(abs_x, old_abs_x);
        assert_eq!(abs_y, old_abs_y);
    }

    /**
     * @tc.name: HandleMotionAccelerateMouseTest_InvalidSpeed_001
     * @tc.desc: Test the function HandleMotionAccelerateMouse with invalid speed
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_accelerate_mouse_invalid_speed() {
        let offset = Offset { dx: 10.0, dy: 15.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;

        let ret: i32 = unsafe {
            HandleMotionAccelerateMouse(&offset, false, &mut abs_x, &mut abs_y, 0, 1)
        };
        
        assert_eq!(ret, RET_ERR);
    }

    /**
     * @tc.name: HandleMotionDynamicAccelerateTouchpadTest_Normal_001
     * @tc.desc: Test the function HandleMotionDynamicAccelerateTouchpad with normal input
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_dynamic_accelerate_touchpad_normal() {
        let offset = Offset { dx: 5.0, dy: 8.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;
        let old_abs_x = abs_x;
        let old_abs_y = abs_y;

        let ret: i32 = unsafe {
            HandleMotionDynamicAccelerateTouchpad(&offset, false, &mut abs_x, &mut abs_y, 5, 15.0, 10.0, 120.0, 100)
        };
        
        assert_eq!(ret, RET_OK);
        assert_ne!(abs_x, old_abs_x);
        assert_ne!(abs_y, old_abs_y);
    }

    /**
     * @tc.name: HandleMotionDynamicAccelerateTouchpadTest_CaptureMode_001
     * @tc.desc: Test the function HandleMotionDynamicAccelerateTouchpad with capture mode enabled
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_dynamic_accelerate_touchpad_capture_mode() {
        let offset = Offset { dx: 5.0, dy: 8.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;
        let old_abs_x = abs_x;
        let old_abs_y = abs_y;

        let ret: i32 = unsafe {
            HandleMotionDynamicAccelerateTouchpad(&offset, true, &mut abs_x, &mut abs_y, 5, 15.0, 10.0, 120.0, 100)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(abs_x, old_abs_x);
        assert_eq!(abs_y, old_abs_y);
    }

    /**
     * @tc.name: HandleMotionDynamicAccelerateTouchpadTest_InvalidSpeed_001
     * @tc.desc: Test the function HandleMotionDynamicAccelerateTouchpad with invalid speed
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_dynamic_accelerate_touchpad_invalid_speed() {
        let offset = Offset { dx: 5.0, dy: 8.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;

        let ret: i32 = unsafe {
            HandleMotionDynamicAccelerateTouchpad(&offset, false, &mut abs_x, &mut abs_y, 0, 15.0, 10.0, 120.0, 100)
        };
        
        assert_eq!(ret, RET_ERR);
    }

    /**
     * @tc.name: HandleMotionAccelerateTouchpadTest_Normal_001
     * @tc.desc: Test the function HandleMotionAccelerateTouchpad with normal input
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_accelerate_touchpad_normal() {
        let offset = Offset { dx: 5.0, dy: 8.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;
        let old_abs_x = abs_x;
        let old_abs_y = abs_y;

        let ret: i32 = unsafe {
            HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x, &mut abs_y, 5, 1)
        };
        
        assert_eq!(ret, RET_OK);
        assert_ne!(abs_x, old_abs_x);
        assert_ne!(abs_y, old_abs_y);
    }

    /**
     * @tc.name: HandleMotionAccelerateTouchpadTest_CaptureMode_001
     * @tc.desc: Test the function HandleMotionAccelerateTouchpad with capture mode enabled
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_accelerate_touchpad_capture_mode() {
        let offset = Offset { dx: 5.0, dy: 8.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;
        let old_abs_x = abs_x;
        let old_abs_y = abs_y;

        let ret: i32 = unsafe {
            HandleMotionAccelerateTouchpad(&offset, true, &mut abs_x, &mut abs_y, 5, 1)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(abs_x, old_abs_x);
        assert_eq!(abs_y, old_abs_y);
    }

    /**
     * @tc.name: HandleMotionAccelerateTouchpadTest_InvalidSpeed_001
     * @tc.desc: Test the function HandleMotionAccelerateTouchpad with invalid speed
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_accelerate_touchpad_invalid_speed() {
        let offset = Offset { dx: 5.0, dy: 8.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;

        let ret: i32 = unsafe {
            HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x, &mut abs_y, 0, 1)
        };
        
        assert_eq!(ret, RET_ERR);
    }

    /**
     * @tc.name: HandleAxisAccelerateTouchpadTest_Normal_001
     * @tc.desc: Test the function HandleAxisAccelerateTouchpad with normal input
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_axis_accelerate_touchpad_normal() {
        let mut abs_axis: f64 = 10.0;

        let ret: i32 = unsafe {
            HandleAxisAccelerateTouchpad(false, &mut abs_axis, 1)
        };
        
        assert_eq!(ret, RET_OK);
        assert!(abs_axis > 0.0);
    }

    /**
     * @tc.name: HandleAxisAccelerateTouchpadTest_CaptureMode_001
     * @tc.desc: Test the function HandleAxisAccelerateTouchpad with capture mode enabled
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_axis_accelerate_touchpad_capture_mode() {
        let mut abs_axis: f64 = 10.0;
        let old_abs_axis = abs_axis;

        let ret: i32 = unsafe {
            HandleAxisAccelerateTouchpad(true, &mut abs_axis, 1)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(abs_axis, old_abs_axis);
    }

    /**
     * @tc.name: HandleMotionDynamicAccelerateMouseTest_ZeroOffset_001
     * @tc.desc: Test the function HandleMotionDynamicAccelerateMouse with zero offset
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_dynamic_accelerate_mouse_zero_offset() {
        let offset = Offset { dx: 0.0, dy: 0.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;
        let old_abs_x = abs_x;
        let old_abs_y = abs_y;

        let ret: i32 = unsafe {
            HandleMotionDynamicAccelerateMouse(&offset, false, &mut abs_x, &mut abs_y, 5, 1000, 150.0, 1.0)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(abs_x, old_abs_x);
        assert_eq!(abs_y, old_abs_y);
    }

    /**
     * @tc.name: HandleMotionAccelerateMouseTest_ZeroOffset_001
     * @tc.desc: Test the function HandleMotionAccelerateMouse with zero offset
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_accelerate_mouse_zero_offset() {
        let offset = Offset { dx: 0.0, dy: 0.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;
        let old_abs_x = abs_x;
        let old_abs_y = abs_y;

        let ret: i32 = unsafe {
            HandleMotionAccelerateMouse(&offset, false, &mut abs_x, &mut abs_y, 5, 1)
        };

        assert_eq!(ret, RET_ERR);
        assert_eq!(abs_x, old_abs_x);
        assert_eq!(abs_y, old_abs_y);
    }

    /**
     * @tc.name: HandleMotionDynamicAccelerateTouchpadTest_ZeroOffset_001
     * @tc.desc: Test the function HandleMotionDynamicAccelerateTouchpad with zero offset
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_dynamic_accelerate_touchpad_zero_offset() {
        let offset = Offset { dx: 0.0, dy: 0.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;

        let ret: i32 = unsafe {
            HandleMotionDynamicAccelerateTouchpad(&offset, false, &mut abs_x, &mut abs_y, 5, 15.0, 10.0, 120.0, 100)
        };

        assert_eq!(ret, RET_OK);
    }

    /**
     * @tc.name: HandleMotionAccelerateTouchpadTest_ZeroOffset_001
     * @tc.desc: Test the function HandleMotionAccelerateTouchpad with zero offset
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_accelerate_touchpad_zero_offset() {
        let offset = Offset { dx: 0.0, dy: 0.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;
        let old_abs_x = abs_x;
        let old_abs_y = abs_y;

        let ret: i32 = unsafe {
            HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x, &mut abs_y, 5, 1)
        };

        assert_eq!(ret, RET_ERR);
        assert_eq!(abs_x, old_abs_x);
        assert_eq!(abs_y, old_abs_y);
    }

    /**
     * @tc.name: HandleAxisAccelerateTouchpadTest_ZeroValue_001
     * @tc.desc: Test the function HandleAxisAccelerateTouchpad with zero value
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_axis_accelerate_touchpad_zero_value() {
        let mut abs_axis: f64 = 0.0;

        let ret: i32 = unsafe {
            HandleAxisAccelerateTouchpad(false, &mut abs_axis, 1)
        };
        
        assert_eq!(ret, RET_OK);
        assert_eq!(abs_axis, 0.0);
    }

    /**
     * @tc.name: HandleMotionDynamicAccelerateMouseTest_MaxValues_001
     * @tc.desc: Test the function HandleMotionDynamicAccelerateMouse with maximum values
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_dynamic_accelerate_mouse_max_values() {
        let offset = Offset { dx: 1000.0, dy: 1000.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;

        let ret: i32 = unsafe {
            HandleMotionDynamicAccelerateMouse(&offset, false, &mut abs_x, &mut abs_y, 20, 1000000, 300.0, 2.0)
        };
        
        assert_eq!(ret, RET_OK);
    }

    /**
     * @tc.name: HandleMotionAccelerateMouseTest_DifferentDeviceTypes_001
     * @tc.desc: Test the function HandleMotionAccelerateMouse with different device types
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_accelerate_mouse_different_device_types() {
        let offset = Offset { dx: 10.0, dy: 15.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;

        // Test PC Mouse
        let ret1: i32 = unsafe {
            HandleMotionAccelerateMouse(&offset, false, &mut abs_x, &mut abs_y, 5, 1)
        };
        assert_eq!(ret1, RET_OK);

        // Test Soft PC Pro Mouse
        let ret2: i32 = unsafe {
            HandleMotionAccelerateMouse(&offset, false, &mut abs_x, &mut abs_y, 5, 2)
        };
        assert_eq!(ret2, RET_OK);

        // Test Hard PC Pro Mouse
        let ret3: i32 = unsafe {
            HandleMotionAccelerateMouse(&offset, false, &mut abs_x, &mut abs_y, 5, 3)
        };
        assert_eq!(ret3, RET_OK);
    }

    /**
     * @tc.name: HandleMotionAccelerateTouchpadTest_DifferentDeviceTypes_001
     * @tc.desc: Test the function HandleMotionAccelerateTouchpad with different device types
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_motion_accelerate_touchpad_different_device_types() {
        let offset = Offset { dx: 5.0, dy: 8.0 };
        let mut abs_x: f64 = 100.0;
        let mut abs_y: f64 = 200.0;

        // Test PC Touchpad
        let ret1: i32 = unsafe {
            HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x, &mut abs_y, 5, 1)
        };
        assert_eq!(ret1, RET_OK);

        // Test Soft PC Pro Touchpad
        let ret2: i32 = unsafe {
            HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x, &mut abs_y, 5, 2)
        };
        assert_eq!(ret2, RET_OK);

        // Test Hard PC Pro Touchpad
        let ret3: i32 = unsafe {
            HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x, &mut abs_y, 5, 3)
        };
        assert_eq!(ret3, RET_OK);

        // Test Tablet Touchpad
        let ret4: i32 = unsafe {
            HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x, &mut abs_y, 5, 4)
        };
        assert_eq!(ret4, RET_OK);

        // Test Fold PC Touchpad
        let ret5: i32 = unsafe {
            HandleMotionAccelerateTouchpad(&offset, false, &mut abs_x, &mut abs_y, 5, 5)
        };
        assert_eq!(ret5, RET_OK);
    }

    /**
     * @tc.name: HandleAxisAccelerateTouchpadTest_DifferentDeviceTypes_001
     * @tc.desc: Test the function HandleAxisAccelerateTouchpad with different device types
     * @tc.type: FUNC
     * @tc.require:
     */
    #[test]
    fn test_handle_axis_accelerate_touchpad_different_device_types() {
        let abs_axis: f64 = 10.0;

        // Test different device types
        for device_type in 1..=8 {
            let mut axis = abs_axis;
            let ret: i32 = unsafe {
                HandleAxisAccelerateTouchpad(false, &mut axis, device_type)
            };
            assert_eq!(ret, RET_OK);
        }
    }
}