/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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


import inputMonitor from '@ohos.multimodalInput.inputMonitor';
import { KeyCode } from '@ohos.multimodalInput.keyCode';
import { KeyEvent } from '@ohos.multimodalInput.keyEvent';
import { TouchEvent } from '@ohos.multimodalInput.touchEvent';
import { MouseEvent } from '@ohos.multimodalInput.mouseEvent';
import  { Rotate, Pinch, ThreeFingersSwipe, FourFingersSwipe, SwipeInward } from '@ohos.multimodalInput.gestureEvent';
import { ThreeFingersTap, TouchGestureEvent } from '@ohos.multimodalInput.gestureEvent';
import { FingerprintEvent } from '@ohos.multimodalInput.shortKey';
import display from "@ohos.display";

const Tag:String = "inputMonitor"

function wait(delay: long) {
    let start = new Date().getTime();
    while (new Date().getTime() - start < delay) {
    }
}


function test_on_touch() {
    console.log(Tag, `into func on test_on_touch`);
    try {
        let fnCallBack = (info: TouchEvent):Boolean =>  {
            console.log(Tag,  `Monitor test_on_touch on success`);
            console.log(Tag,  `Monitor test_on_touch on success ${JSON.stringify(info)}`);
            return true;
        };
        inputMonitor.onTouch(fnCallBack);
        console.log(Tag, `test_on_touch begin wait`);
        wait(60000);
        console.log(Tag, `test_on_touch end wait`);
        inputMonitor.offTouch(fnCallBack);
    } catch (err) {
        console.log(Tag, `catch error:`, err);
    }
}

function test_on_mouse() {
    console.log(Tag, `into func on mouse`);
    try {
        let fnCallBack = (info: MouseEvent) => {
            console.log(Tag,  `Monitor test_on_mouse on success`);
            console.log(Tag,  `Monitor test_on_mouse on success ${JSON.stringify(info)}`);
        };
        inputMonitor.onMouse(fnCallBack);
        console.log(Tag, `test_on_mouse begin wait`);
        wait(60000);
        console.log(Tag, `test_on_mouse end wait`);
        inputMonitor.offMouse(fnCallBack);
    } catch (err) {
        console.log(Tag, `test_on_mouse catch error:`, err);
    }
     console.log(Tag, `end func test_on_mouse`);
}

function test_on_mouse_rect() {
    console.log(Tag, `into func on test_on_mouse_rect`);
    try {
        let fnCallBack = (info: MouseEvent) => {
            console.log(Tag,  `Monitor test_on_mouse on success`);
            console.log(Tag,  `Monitor test_on_mouse on success ${JSON.stringify(info)}`);
        };
        let rect: Array<display.Rect> = [{
            left: 100,
            top: 100,
            width: 100,
            height: 100
          }, {
            left: 600,
            top: 100,
            width: 100,
            height: 100
          }];
        inputMonitor.onMouse(rect, fnCallBack);
        console.log(Tag, `test_on_mouse_rect begin wait`);
        wait(60000);
        console.log(Tag, `test_on_mouse end wait`);
        inputMonitor.offMouse(fnCallBack);
    } catch (err) {
        console.log(Tag, `test_on_mouse_rect catch error:`, err);
    }
     console.log(Tag, `end func test_on_mouse_rect`);
}

function test_on_pinch() {
    let fun_name: string = 'test_on_pinch';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: Pinch) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputMonitor.onPinch(fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(60000);
        console.log(Tag, `${fun_name} end wait`);
        inputMonitor.offPinch(fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on test_on_pinch`);
}

function test_on_pinch_fingers() {
    let fun_name: string = 'test_on_pinch_fingers';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: Pinch) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        let fingers: int = 2;
        inputMonitor.onPinch(fingers, fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(60000);
        console.log(Tag, `${fun_name} end wait`);
        inputMonitor.offPinch(fingers, fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on test_on_pinch`);
}

function test_on_rotate_fingers() {
    let fun_name: string = 'test_on_rotate_fingers';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: Rotate) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        let fingers: int = 2;
        inputMonitor.onRotate(fingers, fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(60000);
        console.log(Tag, `${fun_name} end wait`);
        inputMonitor.offRotate(fingers, fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on test_on_pinch`);
}

function test_on_threeFingersSwipe() {
    let fun_name: string = 'test_on_threeFingersSwipe';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: ThreeFingersSwipe) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputMonitor.onThreeFingersSwipe(fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(60000);
        console.log(Tag, `${fun_name} end wait`);
        inputMonitor.offThreeFingersSwipe(fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on test_on_pinch`);
}

function test_on_fourFingersSwipe() {
    let fun_name: string = 'test_on_fourFingersSwipe';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: FourFingersSwipe) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputMonitor.onFourFingersSwipe(fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(60000);
        console.log(Tag, `${fun_name} end wait`);
        inputMonitor.offFourFingersSwipe(fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on test_on_pinch`);
}

function test_on_threeFingersTap() {
    let fun_name: string = 'test_on_threeFingersTap';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: ThreeFingersTap) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputMonitor.onThreeFingersTap(fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(60000);
        console.log(Tag, `${fun_name} end wait`);
        inputMonitor.offThreeFingersTap(fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on test_on_pinch`);
}

function test_on_fingerprint() {
    let fun_name: string = 'test_on_fingerprint';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: FingerprintEvent) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputMonitor.onFingerprint(fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(60000);
        console.log(Tag, `${fun_name} end wait`);
        inputMonitor.offFingerprint(fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on test_on_pinch`);
}

function test_on_swipeInward() {
    let fun_name: string = 'test_on_swipeInward';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: SwipeInward) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        inputMonitor.onSwipeInward(fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(60000);
        console.log(Tag, `${fun_name} end wait`);
        inputMonitor.offSwipeInward(fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on test_on_pinch`);
}

function test_on_touchscreenSwipe() {
    let fun_name: string = 'test_on_touchscreenSwipe';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: TouchGestureEvent) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        let fingers: int = 3;
        inputMonitor.onTouchscreenSwipe(fingers, fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(60000);
        console.log(Tag, `${fun_name} end wait`);
        inputMonitor.offTouchscreenSwipe(fingers, fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on test_on_pinch`);
}

function test_on_touchscreenPinch() {
    let fun_name: string = 'test_on_touchscreenPinch';
    console.log(Tag, `into func on ${fun_name}`);
    try {
        let fnCallBack = (info: TouchGestureEvent) => {
            console.log(Tag,  `Monitor ${fun_name} on success`);
            console.log(Tag,  `Monitor ${fun_name} on success ${JSON.stringify(info)}`);
        };
        let fingers: int = 4;
        inputMonitor.onTouchscreenPinch(fingers, fnCallBack);
        console.log(Tag, `${fun_name} begin wait`);
        wait(60000);
        console.log(Tag, `${fun_name} end wait`);
        inputMonitor.offTouchscreenPinch(fingers, fnCallBack);
    } catch (err) {
        console.log(Tag, `${fun_name} catch error:`, err);
    }
    console.log(Tag, `end func on test_on_pinch`);
}

function test_on_keypressd() {
    console.log(Tag, `into func on keyPressed`);
    try {
        let keys: Array<KeyCode> = [KeyCode.KEYCODE_VOLUME_UP, KeyCode.KEYCODE_POWER];
        inputMonitor.onKeyPressed(keys, (event: KeyEvent) => {
            console.log(Tag,  `Monitor test_on_keypressd on success`);
            console.log(Tag,  `Monitor test_on_keypressd on success ${JSON.stringify(event)}`);
        });
        console.log(Tag, `test_on_keypressd begin wait`);
        wait(60000);
        console.log(Tag, `test_on_keypressd end wait`);
        inputMonitor.offKeyPressed();
    } catch (err) {
        console.log(Tag, `catch error:`, err);
    }
}

function test_queryTouchEvents() {
    console.log(Tag, `into func test_queryTouchEvents`);
    try {
        let count: int = 2;
         inputMonitor.queryTouchEvents(count).then((data: Array<TouchEvent>):void => {
            console.log(Tag, `queryTouchEvents callback TouchEvent:${JSON.stringify(data)}`);
        });
    } catch (err) {
        console.log(Tag, `catch error:`, err);
    }
     console.log(Tag, `queryTouchEvents end`);
}


function main() {
    console.println(Tag + ` into main`);
    console.log(Tag + ` *************************************************`);
    test_queryTouchEvents();
    test_on_keypressd();
    console.log(Tag + ` out main`);
}