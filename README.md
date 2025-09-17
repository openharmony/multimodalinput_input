# multimodalinput\_input<a name="EN-US_TOPIC_0000001147497185"></a>

-   [Introduction](#section11660541593)
-   [Directory Structure](#section14408467105)
-   [Usage](#section18111235161011)
    -   [Available APIs](#section86358081116)
    -   [Usage Guidelines](#section789634518111)
    -   [Equipment Capability Support](#section789634518112)

-   [Repositories Involved](#section135327891219)

## Introduction<a name="section11660541593"></a>

The module of this repository is applied on the basis of standard systems to provide devices with single-touch input capabilities. This module reports touch events to the JS UI framework or application framework, which then encapsulates the events and provides APIs for apps.

## Directory Structure<a name="section14408467105"></a>

```
/foundation/multimodalinput/input
├── interfaces                   # External APIs
│   └── native                   # Native APIs
│       └── innerkits            # Native APIs provided for internal subsystems
├── service                      # Service framework code
├── sa_profile                   # Service startup configuration file
├── uinput                       # Input event injection module
```

## Usage<a name="section18111235161011"></a>

### Available APIs<a name="section86358081116"></a>

Available APIs of Multimodal Input are event injection ones, which are open only to system apps currently.

-   The  **inputEventClient**  class provides methods for processing injection events.

    **Table  1**  Major APIs in inputEventClient

    <a name="t49c6a8df29a143a98ef6f66f43c7eac8"></a>
    <table><thead align="left"><tr id="rf815506c67654ad4ac014b339ee3292d"><th class="cellrowborder" valign="top" width="15.031503150315032%" id="mcps1.2.4.1.1"><p id="a59bc0498281e498289e11d5e584eb293"><a name="a59bc0498281e498289e11d5e584eb293"></a><a name="a59bc0498281e498289e11d5e584eb293"></a>Category</p>
    </th>
    <th class="cellrowborder" valign="top" width="23.152315231523154%" id="mcps1.2.4.1.2"><p id="aa1226795522e4609b6b1d210255beeff"><a name="aa1226795522e4609b6b1d210255beeff"></a><a name="aa1226795522e4609b6b1d210255beeff"></a>API</p>
    </th>
    <th class="cellrowborder" valign="top" width="61.816181618161814%" id="mcps1.2.4.1.3"><p id="a34777ce8d3174036ba45b9fd51dc4848"><a name="a34777ce8d3174036ba45b9fd51dc4848"></a><a name="a34777ce8d3174036ba45b9fd51dc4848"></a>Description</p>
    </th>
    </tr>
    </thead>
    <tbody><tr id="ra7599f41f04548858a77e2062aad2cf5"><td class="cellrowborder" valign="top" width="15.031503150315032%" headers="mcps1.2.4.1.1 "><p id="a63ab1186072d4bcdb32d4e11b9243b57"><a name="a63ab1186072d4bcdb32d4e11b9243b57"></a><a name="a63ab1186072d4bcdb32d4e11b9243b57"></a>Event injection</p>
    </td>
    <td class="cellrowborder" valign="top" width="23.152315231523154%" headers="mcps1.2.4.1.2 "><p id="a3d9b89df15074475a45ed26503e22c21"><a name="a3d9b89df15074475a45ed26503e22c21"></a><a name="a3d9b89df15074475a45ed26503e22c21"></a>function injectEvent({KeyEvent: KeyEvent}): void;</p>
    </td>
    <td class="cellrowborder" valign="top" width="61.816181618161814%" headers="mcps1.2.4.1.3 "><p id="a33c82952289f40a09773ce2fed14f6aa"><a name="a33c82952289f40a09773ce2fed14f6aa"></a><a name="a33c82952289f40a09773ce2fed14f6aa"></a>Injects events.</p>
    </td>
    </tr>
    </tbody>
    </table>


### Usage Guidelines<a name="section789634518111"></a>

Currently, only the  **BACK**  key event can be injected.

When a system app needs to return to the previous directory, you can call the API to inject the  **BACK**  key event to Multimodal Input, which then transfers this event to the system app, thereby achieving the return effect. The example code is as follows:

```
// Import the required JavaScript API library.
import input from '@ohos.multimodalInput.inputEventClient'

// Call the API for injecting events.
var keyEvent = {
    isPressed:true,           // Action type of the key event. true indicates that the key is being pressed down, and false indicates that the key is being released.
    code:2,                   // Keycode for the key, for example, 2 for the BACK key.
    keyDownDuration:10,       // Duration in which the current key is pressed down before it is released, in milliseconds.
};

var res = input.injectEvent({
    KeyEvent: keyEvent
});
```

>![](figures/icon-note.gif) **NOTE:**
>The new APIs must be compatible with the original capabilities.

### Equipment Capability Support<a name="section789634518112"></a>

|   device    | touch | touchpad | mouse | keyboard |
| :---------: | :---: | :------: | :---: | :------: |
|   rk3568    |   Y   |    Y     |   Y   |    Y     |
| hi3516dv300 |   Y   |    N     |   N   |    N     |

## Repositories Involved<a name="section135327891219"></a>

Multimodal input subsystem

**multimodalinput\_input**

