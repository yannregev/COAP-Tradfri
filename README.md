# COAP - Tradfri
This is a fun project I am working on, a desktop app to control ikea tradfri smart home.
This is currently windows only.

# Requirments
OpenSSL >= 3.2.0-1

# Compile
use Makefile


## Get response:
{
  "9001": "Spot A1",               // user friendly name
  "9003": 65550,                   // instanceID
  "3": {                           // object with vendor information
    "0": "IKEA of Sweden",         // manufacturer name
    "1": "TRADFRIbulbGU10WS345lm", // model name
    "2": "",
    "6": 1,                        // power source (1=internal ?)
    "3": "1.0.012",                // firmware version of light bulb
    "7": 8709,                     // OTA image type
    "8": 5                         // unknown
  },
  "9002": 1641675281,              // creation timestamp
  "9054": 0,
  "9020": 1642111763,              // last seen timestamp
  "9019": 1,                       // reachability state
  "5750": 2,                       // device type (2=light bulb)
  "3311": [                        // light bulb object with data
    {
      "5850": 1,                   // onOff - type boolean
      "5849": 2,                   // action after power restored (1=remember on/off setting 2=always on/default), settable via IKEA Smart Home app
      "5851": 188,                 // brightness/dimmer - number from 0=dark to 254=bright
      "5717": 0,                   
      "9003": 0,
      "5711": 345,                 // color temperature in mireds - number from 250=warm to 454=cold
      "5709": 29090,               // colorX
      "5710": 26728,               // colorY
      "5706": "feb465"             // color rgb type rgb hex string
    }
  ]
}