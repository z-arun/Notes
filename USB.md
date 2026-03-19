Universal serial bus

USB 1.0(UHCI/OHCI)
  Low speed = 1.5Mb/s
  Full speed = 12Mb/s

USB 2.0 (EHCI)
  high-speed = 480Mb/s 

One USB HC port supports up to 127 Devices

Each device is identified by VID/PID

PIN :
+5V (Vbus), GND, D+, D-
-------------------------------------------------
USB 3.0

GND
VBUS (Can provide diff voltag levels 5v, 12v ...)
CC - configuration channel (Used for role negotiationa and power delivery and max deliverable current based on the pull          up/down resisters on host / device side )
TX+
TX-
RX+
RX-
D+
D-
sbu - side band use - dp over usb , hdmi over use 


--------------------------------------------------

LSB always send first in USB 

---------------------------------------------------

OTG: On the Go - Role negotiation.
-----------------------------------------------------------
FUll speed (/high speed):

on host side:
D+ - 15k Ohm pull down
D- - 15K pull donw

on device side :
D+ - 1.5K pull up to 3.3v
------------------------------------------------------------
Low speed:

on host side:
D+ - 15k Ohm pull down
D- - 15K pull donw

on device side :
D- - 1.5K pull up to 3.3v

----------------------------------
NRZI - Non return to 0 inverted
Applicable for both Low and Full speed.
DIfferential 1 : D+ > D-
Differential 0: D+ < D-
Single ended 0 : Both D+ and D- are low
Single Ended 1 : both high
idle : default state , depends on speed.

Low speed:
J state -> differential 0
K state -> differential 1

Full/high speed:
J state -> differential 1
K state -> differential 0


Device side pull up resisters are used for device detections and speed detection.

Selective suspend - onlt the device is suspended
Global suspend - Entire bus suspended
Remote wakeup capability - device can initiate resume from suspended state

Devices are kept busy by sending packets continuously , if no packet send for predefined time, the device will be suspended.


Start of Packet: Also known as SOP. This state occurs when there is a change from Idle to K state. Every transmission of the packet begins with SOP.

End of Packet: Also known as EOP. This state occurs when SEO state occurs for two-bit times, followed by a J state for 1-bit time.

Disconnect: A downstream port at which the device is connected enters disconnect state when an SE0 state has lasted for at least 2.5 uS.

Connect:  A downstream port enters connect state when there is an Idle state for a minimum 2.5 uS and not more than 2 mS

  
---------------------------------------------------------
Types of descriptors :

1) Device desc
2) Configuration
3) Interface
4) endpoint
5) string


Device descriptor :
  -Configuration descriptor 1
    - interface descriptor 1
        - End point descriptor 1
        - End point descriptor 2
    - interface descriptor 2
    
  -Configuration descriptor 2

  Multiple configuration in a single device is rare (eg: Some Harddisks contains two configurations, 1 bus , 2 self powered  eg2: Some old printers config 1 - printer only , config 2  - printer + scanner )

  Multiple interfaces are common :
  Eg:
  Printer + scanner + fax....
---------------------------
usb device driver 
usb core
usb host contoller driver
host controller
device

