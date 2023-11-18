# FCTRL-tools
A remote control tool based on MQTT

DONT FORGET TO CHANGE THE KEY AND IV BEFORE YOU START THE TARGET  
```python
key = b"replacewithlen16"
iv = b"replacewithlen16"
```
## Usage:
List target:
```
>list
14976@LAPTOP-SF514
```
Connect:
```
>conn 14976@LAPTOP-SF514
```
Disconnect:
```
14976@LAPTOP-SF514>disconnect
```
Stop target:
```
14976@LAPTOP-SF514>exit
```
