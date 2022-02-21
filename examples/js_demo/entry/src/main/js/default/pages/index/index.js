/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

import router from '@system.router';
import inputEventClient from '@ohos.multimodalInput.inputEventClient'; //替换ace-loader后新的方式
//import inputEventClient from 'multimodalinput/libinputeventclient.z.so'; //没有替换老的导入方式
//import inputEventClient from 'inputEventClient'; // 只是为了写代码有提示,

// 静态常量
const REGISTERED_SUCCESS = 1; // 1 成功
const REGISTERED_FAILED = -1; // 1 失败
const DEVICE_LIST_NUM = 3;
const ORIGINA_LIST_NUM = 10;
const TOUCH_LIST_NUM = 10;
const SCREEN_TOP_PX = 1240;
const SCREEN_LEFT_PX = 720;
const MOUSE_RADIUS = 30;
const SCREEN_HEIGHT = 960;
const SCREEN_WIDTH = 480;
const REFRESH_DELAY_TIME = 512;
const MOUSE_SENSITIVITY = 6;

export default {
  data: {
    buttonColor: 'box',
    windowId: 0,
    currentTime: 0,
    currentAction: 0,
    currentSourceType: 0,
    refreshDelayTime: REFRESH_DELAY_TIME,
    deviceList: [],
    originalList: [],
    touchList: [],
    registerList: '',
    systemList1: '',
    systemList2: '',
    systemList3: '',
    // 对象内的 属性值
    touchHandle: null,
    keyHandle: null,
    // 通用事件对象
    general: {
      showMenu: null,
      send: null,
      copy: null,
      paste: null,
      cut: null,
      undo: null,
      refresh: null,
      startDrag: null,
      cancel: null,
      enter: null,
      previous: null,
      next: null,
      back: null,
      print: null,
    },
    // 媒体事件
    media: {
      play: null,
      pause: null,
      mediaControl: null,
    },
    // 电话事件
    phone: {
      answer: null,
      refuse: null,
      hangup: null,
      telephoneControl: null,
    },
    // 系统事件
    system: {
      screenShot: null,
      screenSplit: null,
      startScreenRecord: null,
      stopScreenRecord: null,
      gotoDesktop: null,
      recent: null,
      showNotification: null,
      lockScreen: null,
      search: null,
      closePage: null,
      launchVoiceAssistant: null,
      mute: null,
    },
    // 热插拔
    device: {
      deviceAdd: null,
      deviceRemove: null,
    },
    mousePosX: 0,
    mousePosY: 0,
    currentPostionX: SCREEN_WIDTH / 2,
    currentPostionY: SCREEN_HEIGHT / 2,
  },

  // 时间戳转换
  formatTime(time) {
    let timer = Math.floor(time / 1000);  // 传递过来的时间戳都是微妙
    let date = new Date(timer);
    let Y = date.getFullYear();
    let M = (date.getMonth() + 1 < 10 ? '0' + (date.getMonth() + 1) : date.getMonth() + 1);
    let D = (date.getDate() < 10 ? '0' + date.getDate() : date.getDate());
    let h = (date.getHours() < 10 ? '0' + date.getHours() : date.getHours());
    let m = (date.getMinutes() < 10 ? '0' + date.getMinutes() : date.getMinutes());
    let s = (date.getSeconds() < 10 ? '0' + date.getSeconds() : date.getSeconds());
    return `${Y}-${M}-${D} ${h}:${m}:${s}`;
  },

  // 转换keyCode 键盘按键
  getKeyValue(keyCode) {
    let keyList = {
      '2000': 0,
      '2001': 1,
      '2002': 2,
      '2003': 3,
      '2004': 4,
      '2005': 5,
      '2006': 6,
      '2007': 7,
      '2008': 8,
      '2009': 9,
      '2017': "a",
      '2018': "b",
      '2019': "c",
      '2020': "d",
      '2021': "e",
      '2022': "f",
      '2023': "g",
      '2024': "h",
      '2025': "i",
      '2026': "j",
      '2027': "k",
      '2028': "l",
      '2029': "m",
      '2030': "n",
      '2031': "o",
      '2032': "p",
      '2033': "q",
      '2034': "r",
      '2035': "s",
      '2036': "t",
      '2037': "u",
      '2038': "v",
      '2039': "w",
      '2040': "x",
      '2041': "y",
      '2042': "z",
      '2': "BACK",
      '20': "HOME"
    };
    let keyValue = keyCode;
    if (keyList.hasOwnProperty(keyCode)) {
      keyValue = keyList[keyCode] + ':' + keyCode;
    }
    return keyValue;
  },

  // 转换系统按键
  getSystemKeyValue(keyCode) {
    let systemList = {
      '23': 'KEY_MUTE',
      '2067': 'KEY_MENU ',
      '18': 'KEY_POWER',
      '1': 'KEY_HOME',
      // '2': 'KEY_BACK',
      '3': 'KEY_CALL',
      '16': 'KEY_VOLUME_UP',
      '17': 'KEY_VOLUME_DOWN',
      '22': 'KEY_VOLUME_MUTE',
      '6': 'KEY_HEADSETHOOK',
      '2085': 'KEY_MEDIA_PLAY',
      '2086': 'KEY_MEDIA_PAUSE',
      '10': 'KEY_MEDIA_PLAY_PAUSE',
      '11': 'KEY_MEDIA_STOP',
      '12': 'KEY_MEDIA_NEXT',
      '13': 'KEY_MEDIA_PREVIOUS',
      '14': 'KEY_MEDIA_REWIND',
      '2089': 'KEY_MEDIA_RECORD',
      '15': 'KEY_MEDIA_FAST_FORWARD',
      '19': 'KEY_CAMERA',
      '9': 'KEY_SEARCH',
      '40': 'KEY_BRIGHTNESS_UP',
      '41': 'KEY_BRIGHTNESS_DOWN',
    }
    let keyValue = null;
    // 返回一个布尔值，判断对象是否包含特定的自身（非继承）属性。
    if (systemList.hasOwnProperty(keyCode)) {
      keyValue = systemList[keyCode];
    }
    return keyValue;
  },

  getAbsPositionX(x) {
    let absX = this.currentPostionX;
    absX += MOUSE_SENSITIVITY * parseFloat(x);
    if (absX < 0) {
      absX = 0;
    }
    if (absX > SCREEN_WIDTH) {
      absX = SCREEN_WIDTH;
    }
    return absX;
  },

  getAbsPositionY(y) {
    let absY = this.currentPostionY;
    absY += MOUSE_SENSITIVITY * parseFloat(y);
    if (absY < 0) {
      absY = 0;
    }
    if (absY > SCREEN_HEIGHT) {
      absY = SCREEN_HEIGHT;
    }
    return absY;
  },

  getDeviceInfo(deviceUdevTags, inputDeviceId) {
    let value = '';
    if (deviceUdevTags == 0) { //
      value = '触屏'
    } else if (deviceUdevTags == 0) {
      value = '注入' // 虚拟注入/AI/传感器/指关节
    } else if (deviceUdevTags == 2) {
      value = '鼠标类'  // 包括：鼠标/trackpad/轨迹球/旋钮（模式三）
    } else if (deviceUdevTags == 1) {//键盘设备是 1
      value = '键盘'  // 键盘/旋钮（模式一、二）/遥控器
    } else if (deviceUdevTags == 7) {
      value = '摇杆类' // 摇杆/手柄
      // 板子33  
    } else if (deviceUdevTags == 3 || deviceUdevTags == 8) {

      value = 'touchpad'
    } else {
      value = '未知'
    }
    value += `:${inputDeviceId}`;
    return value;
  },

  // 原始事件框渲染的字符串内容
  pushOriginalList(item) {
    let itemInfo = 'undefined type'
    let btnType = '';
    if (item.type == 1) { // 鼠标
      if (item.actionButton == 1) {
        btnType = 'LEFTBTN'
      } else if (item.actionButton == 2) {
        btnType = 'RIGHTBTN'
      } else if (item.actionButton == 4) {
        btnType = 'MIDDLEBTN'
      } else if (item.actionButton == 8) {
        btnType = 'BACKBTN'
      } else if (item.actionButton == 16) {
        btnType = 'FORWARDBTN  '
      } else if (item.actionButton == 32) {
        btnType = 'SIDEBTN'
      } else if (item.actionButton == 64) {
        btnType = 'EXTRABTN'
      } else if (item.actionButton == 128) {
        btnType = 'TASKBTN'
      } else {
        btnType = ''
      }

      switch (item.action) {
        case 1:
          itemInfo = `按下:${btnType}, X:${item.x}, Y:${item.y}`;
          break;
        case 2:
          itemInfo = `抬起:${btnType}, X:${item.x}, Y:${item.y}`;
          break;
        case 3:
          itemInfo = `按下${btnType}移动, X:${item.x}, Y:${item.y}`;
          break;
        case 5:  //pad上的环
          itemInfo = `AXIS_WHEEL移动:${item.ring}`;
          break;
        case 7: // 7 ~9 进入离开 悬移区 笔
          itemInfo = `HOVER_ENTER, X:${item.x}, Y:${item.y}`;
          break;
        case 8:
          itemInfo = `移动:${btnType}, X:${item.x}, Y:${item.y}`;
          break;
        case 9:
          itemInfo = `HOVER_EXIT, X:${item.x}, Y:${item.y}`;
          break;
      }
    } else if (item.type == 0) { // 键盘
      if (item.isPressed == 1) {
        itemInfo = `按下, ${item.keyCode}`;
      } else {
        itemInfo = `抬起, ${item.keyCode}`;
      }
    } else if (item.type == 3) { // 注入
      itemInfo = `指令编号, ${item.id}`;
    } else if (item.type == 255) { // 手柄摇杆
      itemInfo = `轴事件, ${item.name}:${item.value}`;
    } else if (item.type == 8) { // 触控笔
      if (item.action == 1) {
        itemInfo = `按下,${item.buttons}`
      } else if (item.action == 2) {
        itemInfo = `抬起,${item.buttons}`
      } else if (item.action == 3) {
        itemInfo = `笔接触, X:${item.x}, Y:${item.y}`
      } else if (item.action == 4) {
        itemInfo = `笔移动, X:${item.x}, Y:${item.y}`;
      } else if (item.action == 5) {
        itemInfo = `笔离开, X:${item.x}, Y:${item.y}`
      }
    }
    let deviceInfo = this.getDeviceInfo(item.deviceUdevTags, item.deviceId);
    itemInfo += `, ${deviceInfo}, ${item.time}`

    if (this.originalList.length >= ORIGINA_LIST_NUM) {
      this.originalList = [];
    }
    this.originalList.push(itemInfo);
  },

  // 标准化事件框渲染的字符串内容
  pushTouchList(item) {
    let itemInfo = 'undefined ation'
    switch (item.action) {
      case 1:
        itemInfo = `TouchDown, X:${item.x}, Y:${item.y}`;
        break;
      case 2:
        itemInfo = `TouchUp, X:${item.x}, Y:${item.y}`;
        break;
      case 3:
        if (item.pointerCount > 1) {
          itemInfo = `TouchMove, Finger${item.finger}, X:${item.x}, Y:${item.y}`;
        } else {
          itemInfo = `TouchMove, X:${item.x}, Y:${item.y}`;
        }
        break;
      case 4:
        itemInfo = `OtherDown, Finger${item.finger}, X:${item.x}, Y:${item.y}`;
        break;
      case 5:
        itemInfo = `OtherUp, Finger${item.finger}, X:${item.x}, Y:${item.y}`;
        break;
    }

    let deviceInfo = this.getDeviceInfo(item.deviceUdevTags, item.deviceId);
    itemInfo += `, ${deviceInfo}, ${item.time}`

    if (this.touchList.length >= TOUCH_LIST_NUM) {
      this.touchList = [];
    }
    this.touchList.push(itemInfo);
  },

  moveMouse(x, y) {
    let mX = (x / SCREEN_WIDTH) * SCREEN_LEFT_PX - MOUSE_RADIUS;
    let mY = (y / SCREEN_HEIGHT) * SCREEN_TOP_PX - MOUSE_RADIUS;
    if (mX < 0) {
      mX = 0;
    }
    if (mY < 0) {
      mY = 0;
    }
    this.mousePosX = Math.floor(mX) + 'px';
    this.mousePosY = Math.floor(mY) + 'px';
  },

  // 显示touch事件
  showTouchEvent(event) {
    let _this = this;
    let actionType = event.action;

    // touch事件,采样数据类型,不在界面显示
    if (event.eventType == 504) {
      return;
    }

    // actionType: 1按下 2抬起 3移动 4按下再按下 5按下再抬起
    if (actionType == 1 || actionType == 3 || actionType == 4 || actionType == 5) {
      _this.currentPostionX = parseFloat(event.fingerInfos[0].mmiPoint.px);
      _this.currentPostionY = parseFloat(event.fingerInfos[0].mmiPoint.py);
    }

    // 单指头抬起
    if (event.pointerCount == 1 && actionType == 2) {
      _this.pushTouchList({
        pointerCount: event.pointerCount,
        finger: 1,
        action: actionType,
        deviceId: event.inputDeviceId,
        deviceUdevTags: event.sourceDevice,
        x: _this.currentPostionX.toFixed(2),
        y: _this.currentPostionY.toFixed(2),
        time: _this.formatTime(event.occurredTime),
      });
    } else {
      // 多指
      for (var i = 0; i < event.pointerCount; i++) {
        _this.pushTouchList({
          pointerCount: event.pointerCount,
          finger: i + 1,
          action: actionType,
          deviceId: event.inputDeviceId,
          deviceUdevTags: event.sourceDevice,
          x: event.fingerInfos[i].mmiPoint.px.toFixed(2),
          y: event.fingerInfos[i].mmiPoint.py.toFixed(2),
          time: _this.formatTime(event.occurredTime),
        });
      }
    }
  },

  // 鼠标事件
  showMouseEvent(event) {
    if (!event.hasOwnProperty('mouseEvent')) {
      return;
    }
    let _this = this;
    let actionType = event.action; // 标准化值
    let isStandard = event.isStandard; // 是否标准化   0 没有标准化事件  1 有标准化事件
    let actionButton = event.mouseEvent.actionButton; // 按键类型：1 << 0=1-左键；1 << 1=10-右键; 1 << 2=100-中键

    // 预处理，后续server上报正确值---start
    if (actionType == 0) {
      actionType = 2;
    } else if (actionType == 1) {
      actionType = 1;
    }
    if (event.eventType == 400 && isStandard == 0) {
      actionType = 8;
    }
    if (event.eventType == 400 && isStandard == 1) {
      actionType = 3;
    }
    // 预处理，后续server上报正确值---start

    // 手指触摸 pad上的环
    // if (isStandard == 0 && event.mouseEvent.action == 5 && event.eventType == 701) {
    if (isStandard == 0 && event.eventType == 701) {
      _this.pushOriginalList({
        type: '1', //1 是鼠标
        deviceId: event.inputDeviceId,
        deviceUdevTags: event.sourceDevice,
        ring: event.mouseEvent.axis.AXIS_WHEEL,
        action: 5,  //**********************************后期修改************************* */
        actionButton: actionButton,
        time: _this.formatTime(event.mouseEvent.occurredTime),
      });
      return;
    }
    // 鼠标中键滚动
    if (event.eventType == 403) {
      actionType = 8;
    }
    // 预处理，后续server上报正确值---end
    if (event.eventType !== 801) {//802手势
      _this.currentPostionX = _this.getAbsPositionX(event.mouseEvent.mmiPoint.px);
      _this.currentPostionY = _this.getAbsPositionY(event.mouseEvent.mmiPoint.py);
      _this.moveMouse(_this.currentPostionX, _this.currentPostionY);
    } else {
      _this.currentPostionX = event.mouseEvent.mmiPoint.px;
      _this.currentPostionY = event.mouseEvent.mmiPoint.py;
    }

    // 0 没有标准化事件; 1 有标准化事件
    if (isStandard == 1 || (isStandard == 0 && actionType == 3)) {
      if (event.pointerCount > 1) {
        for (var i = 0; i < event.pointerCount; i++) {
          _this.pushTouchList({
            pointerCount: event.pointerCount,
            finger: i + 1,
            action: actionType,
            deviceId: event.inputDeviceId,
            deviceUdevTags: event.sourceDevice,
            x: event.fingerInfos[i].mmiPoint.px.toFixed(2),
            y: event.fingerInfos[i].mmiPoint.py.toFixed(2),
            time: _this.formatTime(event.occurredTime),
          });
        }
      } else {
        _this.pushTouchList({
          pointerCount: event.pointerCount,
          finger: 1,
          action: actionType,
          deviceId: event.inputDeviceId,
          deviceUdevTags: event.sourceDevice,
          x: _this.currentPostionX.toFixed(2),
          y: _this.currentPostionY.toFixed(2),
          time: _this.formatTime(event.occurredTime),
        });
      }
    } else if (event.action != 9) {
      //标准化缺数据 ,触控笔离开时最后报的原始事件,会清空标准化事件
      _this.touchList = [];
    }

    // 原始事件窗口显示内容刷新
    _this.pushOriginalList({
      type: '1', //1 是鼠标
      deviceId: event.inputDeviceId,
      deviceUdevTags: event.sourceDevice,
      x: _this.currentPostionX.toFixed(2),
      y: _this.currentPostionY.toFixed(2),
      action: actionType,
      actionButton: actionButton,
      time: _this.formatTime(event.mouseEvent.occurredTime),
    });
  },

  // 摇杆，手柄显示函数
  showJoystickEvent(event) {
    let _this = this;
    for (let key in event.mouseEvent.axis) {
      if (event.mouseEvent.axis[key] != '0') {
        _this.pushOriginalList({
          deviceId: event.inputDeviceId,
          deviceUdevTags: event.sourceDevice,
          type: 255,
          name: key,
          value: event.mouseEvent.axis[key].toFixed(6),
          time: _this.formatTime(event.mouseEvent.occurredTime),
        });
      }
    }
  },

  // 注册事件函数
  showRegisterList(event) {
    let _this = this;
    // if (event.eventType == 403 &&
    //   Math.abs(_this.currentTime - event.occurredTime) / 600 < _this.refreshDelayTime) {
    //   return;
    // }
    let eventInfo = {
      '0': { id: 1101, name: '显示菜单onShowMenu()' },
      '1': { id: 1102, name: '发送onSend()' },
      '2': { id: 1103, name: '复制onCopy()' },
      '3': { id: 1104, name: '粘贴onPaste()' },
      '4': { id: 1105, name: '剪切onCut()' },
      '5': { id: 1106, name: '撤销onUndo()' },
      '6': { id: 1107, name: '刷新onRefresh()' },
      '7': { id: 1108, name: '拖拽开始onStartDrag()' },
      '8': { id: 1109, name: '取消onCancel()' },
      '9': { id: 1110, name: '确定/进入onEnter()' },
      '10': { id: 1111, name: '上一个onPrevious()' },
      '11': { id: 1112, name: '下一个onNext()' },
      '12': { id: 1113, name: '上一级onBack()' },
      '13': { id: 1114, name: '打印onPrint()' },
      '14': { id: 5001, name: '接听onAnswer()' },
      '15': { id: 5002, name: '拒绝onRefuse()' },
      '16': { id: 5003, name: '挂起onHangup()' },
      '17': { id: 5004, name: '控制onTelephoneControl()' },
      '18': { id: 3001, name: '播放onPaly()' },
      '19': { id: 3002, name: '暂停onPause()' },
      '20': { id: 3003, name: '控制onMediaControl()' },
      '21': { id: 4001, name: '截屏onScreenShot()' },
      '22': { id: 4002, name: '分屏onScreenSplit()' },
      '23': { id: 4003, name: '启动录屏onStartScreenRecord()' },
      '24': { id: 4004, name: '停止录屏onStopScreenRecord()' },
      '25': { id: 4005, name: '显示桌面onGotoDesktop()' },
      '26': { id: 4006, name: '切换任务窗口onRecent()' },
      '27': { id: 4007, name: '显示通知中心onShowNotifiCation()' },
      '28': { id: 4008, name: '锁屏onLockScreen()' },
      '29': { id: 4009, name: '搜索onSearch()' },
      '30': { id: 4010, name: '关闭界面onClosePage()' },
      '31': { id: 4011, name: '语音助手onLaunchVoiceAssistant()' },
      '32': { id: 4012, name: '静音onMute()' },
    }

    if (eventInfo.hasOwnProperty(event.type)) {
      let eventValue = eventInfo[event.type];
      // 原始事件
      _this.pushOriginalList({
        type: 3,
        name: eventValue.name,
        deviceId: event.inputDeviceId,
        deviceUdevTags: event.sourceDevice,
        id: eventValue.id,
        time: _this.formatTime(event.occurredTime)
      });
      // 注册事件
      let deviceInfo = _this.getDeviceInfo(event.sourceDevice, event.inputDeviceId)
      _this.registerList = eventValue.name + ' ' + deviceInfo;
    }
  },

  // 触控笔
  showStylusEvent(event) {
    let _this = this;
    if (event.pointerCount > 0) {
      _this.currentPostionX = _this.getAbsPositionX(event.fingerInfos[0].mmiPoint.px);
      _this.currentPostionY = _this.getAbsPositionY(event.fingerInfos[0].mmiPoint.py);
    }
    _this.pushOriginalList({
      type: event.deviceEventType,
      deviceId: event.inputDeviceId,
      deviceUdevTags: event.sourceDevice,
      action: event.stylusEvent.action,
      buttons: event.stylusEvent.buttons,
      x: _this.currentPostionX.toFixed(2),
      y: _this.currentPostionY.toFixed(2),
      time: _this.formatTime(event.stylusEvent.occurredTime),//393930
    });
    if (event.isStandard == 1) {
      _this.pushTouchList({
        pointerCount: event.pointerCount,
        finger: 1,
        action: event.action,
        deviceId: event.inputDeviceId,
        deviceUdevTags: event.sourceDevice,
        x: _this.currentPostionX.toFixed(2),
        y: _this.currentPostionY.toFixed(2),
        time: _this.formatTime(event.occurredTime),
      });
    }
  },



  // touch
  touchReg() {
    let _this = this;
    _this.touchHandle = (event) => {
      if (_this.currentSourceType == event.eventType && _this.currentAction == event.action &&
        Math.abs(_this.currentTime - event.occurredTime) / 600 < _this.refreshDelayTime) {
        return;
      } else {
        _this.currentTime = event.occurredTime;
        _this.currentAction = event.action;
        _this.currentSourceType = event.eventType;
      }
      if (event.sourceDevice == 0) {
        _this.moveMouse(0, 0);
        _this.refreshDelayTime = (event.pointerCount > 1) ? (event.pointerCount * REFRESH_DELAY_TIME) : 0;
        if (event.eventType != 400 && event.pointerCount == 1) {
          _this.refreshDelayTime = REFRESH_DELAY_TIME;
        }
        _this.showTouchEvent(event);
      } else if (event.sourceDevice == 7) {
        let axisNum = 0;
        for (let key in event.mouseEvent.axis) {
          if (event.mouseEvent.axis[key] != '0') {
            axisNum++;
          }
        }
        _this.refreshDelayTime = (axisNum > 1) ? (axisNum * REFRESH_DELAY_TIME) : REFRESH_DELAY_TIME;
        if ((axisNum == 1 && event.mouseEvent.axis['AXIS_HAT_X'] != '0') ||
          (axisNum == 1 && event.mouseEvent.axis['AXIS_HAT_Y'] != '0')) {
          _this.refreshDelayTime = 0;
        }
        _this.showJoystickEvent(event);
      } else if ((event.sourceDevice == 3) || (event.sourceDevice == 8)) {
        _this.refreshDelayTime = 0;
        if (event.deviceEventType == 8) {
          _this.showStylusEvent(event);
        } else {
          _this.showMouseEvent(event);
        }
      } else {
        _this.refreshDelayTime = (event.eventType != 402) ? (2 * REFRESH_DELAY_TIME) : 0;
        _this.showMouseEvent(event);
      }
    }

    _this.registerEvent('touch', _this.touchHandle);
  },

  touchUnReg() {
    this.unregisterEvent('touch', this.touchHandle);
  },

  // key
  keyReg() {
    let _this = this;
    _this.keyHandle = (event) => {
      if (event.keyCode != 0) {
        let value = _this.getSystemKeyValue(event.keyCode); //系统按键
        if (value != null) {
          _this.systemList1 = `系统按键:${value}`;
          _this.systemList2 = '';
          _this.systemList3 = '';
        }

        _this.pushOriginalList({
          type: 0,
          deviceId: event.inputDeviceId,
          deviceUdevTags: event.sourceDevice,
          keyCode: _this.getKeyValue(event.keyCode),
          isPressed: event.isPressed,
          time: _this.formatTime(event.occurredTime),
        });

        // home按键
        if (event.keyCode == 20) {
          _this.systemList3 = ''
        }
        // back按键
        if (event.keyCode == 2) {
          _this.systemList3 = 'BACK键分发至应用'
        }
      }
    }
    _this.registerEvent('key', _this.keyHandle);
  },

  keyUnReg() {
    this.unregisterEvent('key', this.keyHandle);
  },

  // 注册函数封装
  registerEvent(name, handle) {
    if (handle === null) {
      console.error('inputEventClient::registerEvent: handle===null');
      return;
    }
    let ret = inputEventClient.on(this.windowId, name, handle);
    if (ret == REGISTERED_FAILED) {
      handle = null;
      console.error('inputEventClient:: registerEvent: ret:' + ret);
    }
  },

  // 反注册封装
  unregisterEvent(name, handle) {
    if (handle === null) {
      console.error('inputEventClient:: unregisterEvent: handle===null');
      return;
    }
    let ret = inputEventClient.off(this.windowId, name, handle);
    if (ret == REGISTERED_FAILED) {
      handle = null;
      console.error('inputEventClient:: unregisterEvent: ret:' + ret);
    }
  },

  // 通用事件
  generalReg() {
    let _this = this;
    _this.general.showMenu = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('showMenu', _this.general.showMenu);

    _this.general.send = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('send', _this.general.send);

    _this.general.copy = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('copy', _this.general.copy);

    _this.general.paste = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('paste', _this.general.paste);

    _this.general.cut = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('cut', _this.general.cut);

    _this.general.undo = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('undo', _this.general.undo);

    _this.general.refresh = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('refresh', _this.general.refresh);

    _this.general.startDrag = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('startDrag', _this.general.startDrag);

    _this.general.cancel = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('cancel', _this.general.cancel);

    _this.general.enter = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('enter', _this.general.enter);

    _this.general.previous = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('previous', _this.general.previous);

    _this.general.next = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('next', _this.general.next);

    _this.general.back = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('back', _this.general.back);

    _this.general.print = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('print', _this.general.print);
  },

  // 反注册
  generalUnReg() {
    let _this = this;
    _this.unregisterEvent('showMenu', _this.general.showMenu);
    _this.unregisterEvent('send', _this.general.send);
    _this.unregisterEvent('copy', _this.general.copy);
    _this.unregisterEvent('paste', _this.general.paste);
    _this.unregisterEvent('cut', _this.general.cut);
    _this.unregisterEvent('undo', _this.general.undo);
    _this.unregisterEvent('refresh', _this.general.refresh);
    _this.unregisterEvent('startDrag', _this.general.startDrag);
    _this.unregisterEvent('cancel', _this.general.cancel);
    _this.unregisterEvent('enter', _this.general.enter);
    _this.unregisterEvent('previous', _this.general.previous);
    _this.unregisterEvent('next', _this.general.next);
    _this.unregisterEvent('back', _this.general.back);
    _this.unregisterEvent('print', _this.general.print);
  },

  // 媒体事件
  mediaReg() {
    let _this = this;
    _this.media.play = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('play', _this.media.play);

    _this.media.pause = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('pause', _this.media.pause);

    _this.media.mediaControl = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('mediaControl', _this.media.mediaControl);

  },

  mediaUnReg() {
    let _this = this;
    _this.unregisterEvent('play', _this.media.play);
    _this.unregisterEvent('pause', _this.media.pause);
    _this.unregisterEvent('mediaControl', _this.media.mediaControl);
  },

  // 电话事件
  phoneReg() {
    let _this = this;
    _this.phone.answer = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('answer', _this.phone.answer);

    _this.phone.refuse = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('refuse', _this.phone.refuse);

    _this.phone.hangup = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('hangup', _this.phone.hangup);

    _this.phone.telephoneControl = (event) => {
      _this.showRegisterList(event);
    }
    _this.registerEvent('telephoneControl', _this.phone.telephoneControl);
  },

  phoneUnReg() {
    let _this = this;
    _this.unregisterEvent('answer', _this.phone.answer);
    _this.unregisterEvent('refuse', _this.phone.refuse);
    _this.unregisterEvent('hangup', _this.phone.hangup);
    _this.unregisterEvent('telephoneControl', _this.phone.telephoneControl);
  },

  // 系统事件
  systemReg() {
    let _this = this;
    _this.system.screenShot = function (event) {
      _this.showRegisterList(event);
    }
    _this.registerEvent('screenShot', _this.system.screenShot);

    _this.system.screenSplit = function (event) {
      _this.showRegisterList(event);
    }
    _this.registerEvent('screenSplit', _this.system.screenSplit);

    _this.system.startScreenRecord = function (event) {
      _this.showRegisterList(event);
    }
    _this.registerEvent('startScreenRecord', _this.system.startScreenRecord);

    _this.system.stopScreenRecord = function (event) {
      _this.showRegisterList(event);
    }
    _this.registerEvent('stopScreenRecord', _this.system.stopScreenRecord);

    _this.system.gotoDesktop = function (event) {
      _this.showRegisterList(event);
    }
    _this.registerEvent('gotoDesktop', _this.system.gotoDesktop);

    _this.system.recent = function (event) {
      _this.showRegisterList(event);
    }
    _this.registerEvent('recent', _this.system.recent);

    _this.system.showNotification = function (event) {
      _this.showRegisterList(event);
    }
    _this.registerEvent('showNotification', _this.system.showNotification);

    _this.system.lockScreen = function (event) {
      _this.showRegisterList(event);
    }
    _this.registerEvent('lockScreen', _this.system.lockScreen);

    _this.system.search = function (event) {
      _this.showRegisterList(event);
    }
    _this.registerEvent('search', _this.system.search);

    _this.system.closePage = function (event) {
      _this.showRegisterList(event);
    }
    _this.registerEvent('closePage', _this.system.closePage);

    _this.system.launchVoiceAssistant = function (event) {
      _this.showRegisterList(event);
    }
    _this.registerEvent('launchVoiceAssistant', _this.system.launchVoiceAssistant);

    _this.system.mute = function (event) {
      _this.showRegisterList(event);
    }
    _this.registerEvent('mute', _this.system.mute);
  },

  systemUnReg() {
    let _this = this;
    _this.unregisterEvent('screenShot', _this.system.screenShot);
    _this.unregisterEvent('screenSplit', _this.system.screenSplit);
    _this.unregisterEvent('startScreenRecord', _this.system.startScreenRecord);
    _this.unregisterEvent('stopScreenRecord', _this.system.stopScreenRecord);
    _this.unregisterEvent('gotoDesktop', _this.system.gotoDesktop);
    _this.unregisterEvent('recent', _this.system.recent);
    _this.unregisterEvent('showNotification', _this.system.showNotification);
    _this.unregisterEvent('lockScreen', _this.system.lockScreen);
    _this.unregisterEvent('search', _this.system.search);
    _this.unregisterEvent('closePage', _this.system.closePage);
    _this.unregisterEvent('launchVoiceAssistant', _this.system.launchVoiceAssistant);
    _this.unregisterEvent('mute', _this.system.mute);
  },

  // 热插拔
  deviceReg() {
    let _this = this;
    _this.device.deviceAdd = (event) => {
      let usb = {
        on: 1,   // 1 插入  0 拔出
        name: event.name,
        sysName: event.sysName,
        inputDeviceId: event.inputDeviceId,
      }
      if (_this.deviceList.length < DEVICE_LIST_NUM) {
        _this.deviceList.push(usb);
      } else if (_this.deviceList.length == DEVICE_LIST_NUM) {
        _this.deviceList.shift();
        _this.onClickClearData();   // 清除 数据
        _this.deviceList.push(usb);
      }
      return true;
    }
    _this.registerEvent('deviceAdd', _this.device.deviceAdd);


    _this.device.deviceRemove = (event) => {
      let usb = {
        on: 0,   // 1 插入  0 拔出
        name: event.name,
        sysName: event.sysName,
        inputDeviceId: event.inputDeviceId,
      }
      if (_this.deviceList.length < DEVICE_LIST_NUM) {
        _this.deviceList.push(usb);
      } else if (_this.deviceList.length == DEVICE_LIST_NUM) {
        _this.deviceList.shift();
        _this.deviceList.push(usb);
      }
      return true;
    }
    _this.registerEvent('deviceRemove', _this.device.deviceRemove);

  },

  deviceUnReg() {
    let _this = this;
    _this.unregisterEvent('deviceAdd', _this.device.deviceAdd);
    _this.unregisterEvent('deviceRemove', _this.device.deviceRemove);
  },

  // 底部菜单
  onClickHome() {
    this.systemList1 = 'HOME键开始注入';
    this.systemList2 = '';
    this.systemList3 = '';
    let keyEvent = {
      isPressed: true,
      keyCode: 20,
      keyDownDuration: 200,
      maxKeyCode: 300
    }
    setTimeout(() => {
      let ret = inputEventClient.injectEvent({
        KeyEvent: keyEvent
      });
      ret == 1 ? this.systemList2 = 'HOME键注入成功' : this.systemList2 = 'HOME键注入失败';
    }, 1000);
  },

  onClickBack() {
    this.systemList1 = 'BACK键开始注入';
    this.systemList3 = '';
    this.systemList2 = '';
    let keyEvent = {
      isPressed: true,
      keyCode: 2,
      keyDownDuration: 200,
      maxKeyCode: 300,
    }
    setTimeout(() => {
      let ret = inputEventClient.injectEvent({
        KeyEvent: keyEvent
      });
      ret == 1 ? this.systemList2 = 'BACK键注入成功' : this.systemList2 = 'BACK键注入失败';
    }, 500);
  },

  // 清除所有数据
  onClickClearData() {
    this.originalList = [];
    this.touchList = [];
    this.registerList = '';
    this.systemList1 = '';
    this.systemList2 = '';
    this.systemList3 = '';
  },

  // 跳转
  onClickGoEvents() {
    router.push({
      uri: 'pages/events/events',
    });
  },

  // 初始化页面,自动注册类型事件
  onShow() {
    this.windowId = Math.floor(Math.random() * 1000)
    this.touchReg();
    this.keyReg();
    this.generalReg();
    this.mediaReg();
    this.phoneReg();
    this.systemReg();
    this.deviceReg();
  },

  // 页面销毁时被调用
  onHide() {
    this.deviceUnReg();
    this.touchUnReg();
    this.keyUnReg();
    this.generalUnReg()
    this.mediaUnReg();
    this.phoneUnReg();
    this.systemUnReg();
  },
}
