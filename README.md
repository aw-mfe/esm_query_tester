# esm_query_tester
Build and test McAfee ESM queries with a YAML template

How it works:

1. Get the script via git or download.
    git clone https://github.com/andywalden/esm_query_tester
    
2. Plug in the ESM username, password and IP/hostname at the top of the esm_query_test.py file.

3. Modify the query.yaml file to the desired query.

4. Run the script:

```css
$ python esm_query_tester.py

ESM Query Syntax
{
  "config": {
    "fields": [
      {
        "name": "FirstTime"
      },
      {
        "name": "EventCount"
      },
      {
        "name": "DSIDSigID"
      },
      {
        "name": "IPSIDAlertID"
      },
      {
        "name": "AlertID"
      },
      {
        "name": "IPSID"
      },
      {
        "name": "Rule.NormID"
      },
      {
        "name": "SigID"
      },
      {
        "name": "SrcIP"
      },
      {
        "name": "DstIP"
      },
      {
        "name": "DomainID"
      },
      {
        "name": "Rule_NDSNormSigID.msg"
      },
      {
        "name": "Rule.msg"
      },
      {
        "name": "Sensor_Name"
      },
      {
        "name": "ThirdPartyType.Name"
      },
      {
        "name": "UserIDSrc"
      }
    ],
    "filters": [
      {
        "field": {
          "name": "NormID"
        },
        "values": [
          {
            "value": 408977408,
            "type": "EsmBasicValue"
          }
        ],
        "operator": "EQUALS",
        "type": "EsmFieldFilter"
      }
    ],
    "limit": 100,
    "timeRange": "LAST_HOUR",
    "order": [
      {
        "field": {
          "name": "FirstTime"
        },
        "direction": "DESCENDING"
      }
    ],
    "includeTotal": false
  }
}
['11/06/2019 15:17:01', '1', '65-1051850', '144116287604260864|14861', '14861', '144116287604260864', '408977408', '1051850', '22.22.24.4', '::', '', 'Linux crond Session opened', 'Unknown_0', 'Linux', 'root', '11/06/2019 15:17:01.000']
['11/06/2019 15:09:01', '1', '65-1051850', '144116287604260864|14823', '14823', '144116287604260864', '408977408', '1051850', '22.22.24.4', '::', '', 'Linux crond Session opened', 'Unknown_0', 'Linux', 'root', '11/06/2019 15:09:01.000']
['11/06/2019 14:39:01', '1', '65-1051850', '144116287604260864|14757', '14757', '144116287604260864', '408977408', '1051850', '22.22.24.4', '::', '', 'Linux crond Session opened', 'Unknown_0', 'Linux', 'root', '11/06/2019 14:39:01.000']
```
