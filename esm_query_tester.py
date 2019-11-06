# -*- coding: utf-8 -*-

import base64
import json
import requests
import sys
import time
import  yaml
from datetime import datetime, timezone
requests.packages.urllib3.disable_warnings()

USERNAME = ''
PASSWD = ''
HOST = ''

API_VERSION = 'v2' # 'v1' or 'v2'

class ESM(object):

    def __init__(self, hostname, username, password, api_version=None):
        """
        """
        self.api_ver = api_version
        
        self._base_url = 'https://{}/rs/esm/'.format(hostname)
        if self.api_ver == 'v2':
            self._base_url = 'https://{}/rs/esm/v2/'.format(hostname)
            
        self._int_url = 'https://{}/ess'.format(hostname)

        _v9_creds = '{}:{}'.format(username, password)
        self._v9_b64_creds = base64.b64encode(_v9_creds.encode('utf-8'))

        _v10_b64_user = base64.b64encode(username.encode('utf-8')).decode()
        _v10_b64_passwd = base64.b64encode(password.encode('utf-8')).decode()
        self._v10_params = {"username": _v10_b64_user,
                            "password": _v10_b64_passwd,
                            "locale": "en_US",
                            "os": "Win32"}
        self._headers = {'Content-Type': 'application/json'}
        
    def login(self):
        """
        Log into the ESM
        """
        self._headers = {'Authorization': 'Basic ' +
                         self._v9_b64_creds.decode('utf-8'),
                         'Content-Type': 'application/json'}
        _method = 'login'
        _data = self._v10_params
        _resp = self.post(_method, data=_data, 
                                parse_response=False, headers=self._headers)
        
        if _resp.status_code in [400, 401]:
            print('Invalid username or password for the ESM')
            sys.exit(1)
        elif 402 <= _resp.status_code <= 600:
            print('ESM Login Error:', _resp.text)
            sys.exit(1)
        
        self._headers = {'Content-Type': 'application/json'}
        self._headers['Cookie'] = _resp.headers.get('Set-Cookie')
        self._headers['X-Xsrf-Token'] = _resp.headers.get('Xsrf-Token')
        self._headers['SID'] = _resp.headers.get('Location')
        self._sid = self._headers['SID']

    def logout(self):
        """
        """
        self._url = self._base_url + 'logout'
        requests.delete(self._url, headers=self._headers, verify=False)
                

    def time(self):
        """
        Returns:
            str. ESM time (GMT).

        Example:
            '2017-07-06T12:21:59.0+0000'
        """

        _method = 'essmgtGetESSTime'
        _resp = self.post(self._method)
        return self.parse_response(self._resp)

    def get_fields(self):
        _method = 'qryGetSelectFields?type=EVENT&groupType=NO_GROUP'
        _resp = self.post(_method)
        self._resp = self._resp
        field_names = [field_info['name'] for field_info in _resp]
        return field_names

    def query(self, query_json):
        self._original_query = query_json
        
        """
        To retrieve more then 5000 results, the McAfee ESM limit, we will find 
        or add the LastTime field in case results are > 5000 rows.
        The time index stores where the lastTime field is in the field list so
        it can be examined later.
        """
        _time_index = None
        for i, _field in enumerate(query_json['config']['fields']):
            if _field['name'] == 'LastTime':
                _time_index = i
            
        if not _time_index:
            query_json['config']['fields'].append({'name': 'LastTime'})
            _time_index = len(query_json['config']['fields']) - 1
            _remove_lasttime = True
        
        _query_results = self._process_query(query_json)
        while len(_query_results['rows']) == 5000:
            self._start_time = fmt_esm_time(_query_results['rows'][-1]['values'][_time_index])            
            if _remove_lasttime:
                _query_results['rows'] = [row['values'][0:-1] for row in _query_results['rows']]
            yield _query_results
            query_json = self._update_query_time(query_json) 
            _query_results = self._process_query(query_json)
        

        if _remove_lasttime:
            _query_results['rows'] = [row['values'][0:-1] for row in _query_results['rows']]
        yield _query_results
        query_json = self._update_query_time(query_json) 
        _query_results = self._process_query(query_json)
        return _query_results
        
    def _process_query(self, query):
        """
        Coordinate the querying and result return
        Returns: results - generator object                
        """
        _query_resp = self._send_query(query)
        
        try:
            _ridval = _query_resp['resultID']['value']
            _rid = {"resultID": {"value": _ridval}} 
            self._start_time = fmt_esm_time(_query_resp['startTime'])
            self._stop_time = fmt_esm_time(_query_resp['stopTime'])
            
        except KeyError:
            print('Invalid query response: {}'.format(_query_resp))
            raise
        self._check_query_status(_rid)
        return self._get_results(_rid)
            
    def _send_query(self, query):
        _method = 'qryExecuteDetail?type=EVENT&reverse=false'
        return self.post(_method, data=query, headers=self._headers)
    
    def _check_query_status(self, result_id):
        _method = 'qryGetStatus'
        _status = self.post(_method, data=result_id, headers=self._headers)
        
        while not _status['complete']:
           time.sleep(2)
           _status = self.post(_method, data=result_id, headers=self._headers)

    def _get_results(self, result_id):
        _rows = 5000
        _method = 'qryGetResults?startPos=0&numRows={}&reverse=false'.format(_rows)
        return self.post(_method, data=result_id, headers=self._headers)

    def _update_query_time(self, query):
        if query.get('config').get('timeRange'):
            query['config']['timeRange'] = 'CUSTOM'
            query['config']['customStart'] = self._start_time
            query['config']['customEnd'] = self._stop_time
            return query
        
    def get_event_details(self, erc_record_id):
        method = 'IPS_GETALERTDATA'
        data = {'ID': erc_record_id}
        resp = self.post(method, data=data)
        print(data)
        sys.exit()

        return dehexify(resp['ITEMS'])
        
    def get_raw_log(self, erc_record_id):
        method = 'IPS_GETALERTPACKET'
        data = {'AID': erc_record_id}
        resp = self.post(method, data=data)
        print(data)
        sys.exit()

        return dehexify(resp['ITEMS'])
        

    def parse_response(self, response):
        '''Parse ESM response
        
        Args:
            response (obj): requests response object.
        
        Returns:
            str or list of dicts
        
        '''
        try:
            self._response = response.json()
        except json.decoder.JSONDecodeError:
            self._response = self._response.text

        if self.api_ver == 'v2':
            self._response = self._response.get('value')
        else:
            self._response = self._response.get('return')
            if 'value' in self._response:
                self._response = self._response.get('value')
        return self._response

        
    def post(self, method, data=None, parse_response=True,
                headers=None, verify=False):
        """Format and route query to ESM
        
        Args:
            method (str): ESM method to call.
            data (dict): Data for the call.
            headers (dict): Headers to be used.
            verify (bool): Verify the ESM SSL cert.
        """
        self._method = method
        self._data = data
        if headers is None:
            headers = self._headers
        self._verify = verify

        self._url = self._base_url + self._method
        if self._method == self._method.upper():
            self._url = self._int_url
            self._data = self._format_params(self._method, **self._data)
        else:
            self._url = self._base_url + self._method
            if self._data:
                self._data = json.dumps(self._data)
                
        self._resp = self._post(self._url, data=self._data,
                                    headers=self._headers, verify=self._verify)

        if 200 <= self._resp.status_code <= 300:
            if parse_response:
                return self.parse_response(self._resp)
            else: 
                return self._resp
        if 400 <= self._resp.status_code <= 600:
            print('ESM Error:', self._resp.text)
            return self._resp
           
    @staticmethod
    def _post(url, data=None, headers=None, verify=False):
        """
        Method that actually kicks off the HTTP client.

        Args:
            url (str): URL to send the post to.
            data (str): Any payload data for the post.
            headers (str): http headers that hold cookie data after
                            authentication.
            verify (bool): SSL cerificate verification

        Returns:
            Requests Response object
        """
        try:
            return requests.post(url, data=data, headers=headers,
                                 verify=verify)

        except requests.exceptions.ConnectionError:
            print("Unable to connect to ESM: {}".format(url))
            sys.exit(1)
            

def fmt_esm_time(time_str):
    _esm_out_time_fmt = '%m/%d/%Y %H:%M:%S'
    _esm_in_time_fmt = '%Y-%m-%dT%H:%M:%S.000Z'
    _time = datetime.strptime(time_str, _esm_out_time_fmt)
    return datetime.strftime(_time, _esm_in_time_fmt)
            
            
class Query(object):
    def __init__(self, yaml_obj, esm_obj):
        self._query = yaml_obj
        self._esm = esm_obj
        self._q = {'config': {
                    'timeRange': [],
                    'fields': [],
                    'filters': [],
                    'order': []
                    }}
        
        self._validate_filters()
        self._validate_fields()
        self._validate_timeframe()
        self._validate_sort()
        self._q['config']['limit'] = self._query.get('limit')
        self._q['config']['includeTotal'] = False
        
    def _validate_filters(self):
        try:
            _filters = self._query['filters'.lower()] 
        except KeyError:
            print('Error: filter section not found in query file')
            sys.exit(1)
        
        _filter_keys = ['field', 'op', 'type', 'value']
        for _filter in _filters:
            if len(_filter) != 4:
                print('Error: Invalid number of parameters for filter. '
                       'Should be 4 (field, op, type, value), but has {}'.format(len(_filter)))
                sys.exit(1)
            for key in _filter.keys():
                if key.lower() not in _filter_keys:
                    print('Error: Invalid filter key found {}'. format(key))
                    sys.exit(1)
            
            if _filter['type'].lower() == 'field':
                _vals = {'type': 'EsmBasicValue',
                          'value': _filter['value']}
            elif _filter['type'].lower() == 'variable':
                _vals = {'type': 'EsmVariableValue',
                           'variable': self._filter['value']}
            elif _filter['type'].lower() == 'watchlist':
                _wl_id = self._esm.get_watchlist_id(_filter['value'])
                if not _wl_id:
                    print('Error: watchlist not found: {}'.format(_filter['value']))
                _vals = {'type': 'EsmWatchlistValue',
                           'watchlist': {'value': _wl_id}}
      
            _ops = ['IN', 'NOT_IN', 'GREATER_THAN', 'LESS_THAN', 'GREATER_OR_EQUALS_THAN',
                    'LESS_OR_EQUALS_THAN', 'NUMERIC_EQUALS', 'NUMERIC_NOT_EQUALS', 
                    'DOES_NOT_EQUAL', 'EQUALS', 'CONTAINS', 'DOES_NOT_CONTAIN', 'REGEX']
            
            try:
                if _filter['op'].upper() in _ops:
                    _filter['op'] = _filter['op'].upper()
                else:
                    print('Error: Valid Operator not found for filter: {}'.format(_filter))
            except KeyError:
                print('Error: Valid Operator not found for filter: {}'.format(_filter))
            
            _filter_q = {'type': 'EsmFieldFilter',
                          'field': {'name': _filter['field']},
                          'operator': _filter['op'],
                          'values': [_vals]}
                
            self._q['config']['filters'].append(_filter_q)
                
    def _validate_fields(self):
        try:
            _fields = self._query['fields'] 
        except KeyError:
            print('Error: fields section not found in query file')
            
        if len(_fields) > 50:
            print('Error: Field limit is 50. Query has {}'.format(len(_fields)))
            sys.exit(1)
            
        self._all_fields = ','.join(self._esm.get_fields())
        
                    
        for _field in _fields:
            if _field + ',' not in self._all_fields:
                print('Error: Invalid field in query file: {}'.format(_field))
                #sys.exit(1)
            self._q['config']['fields'].append({'name': _field})
        
    def _validate_timeframe(self):
        self._timeframes = ['LAST_MINUTE',
                            'LAST_10_MINUTES',
                            'LAST_30_MINUTES',
                            'LAST_HOUR',
                            'CURRENT_DAY',
                            'PREVIOUS_DAY',
                            'LAST_24_HOURS',
                            'LAST_2_DAYS',
                            'LAST_3_DAYS',
                            'CURRENT_WEEK',
                            'PREVIOUS_WEEK',
                            'CURRENT_MONTH',
                            'PREVIOUS_MONTH',
                            'CURRENT_QUARTER',
                            'PREVIOUS_QUARTER',
                            'CURRENT_YEAR',
                            'PREVIOUS_YEAR']
        try:
            _timeframe = self._query['timeframe']
        except KeyError:
            print('Time range not found, using LAST_HOUR')
            self._q['config']['timeRange'.lower()] = 'LAST_HOUR'
            
        if _timeframe.get('predefined'):
            if _timeframe['predefined'] in self._timeframes:
                self._q['config']['timeRange'] = _timeframe['predefined']
                if _timeframe.get('start') or _timeframe.get('end'):
                    print('Error: Time conflict. Specify predefined time range or start/end times, not both')
                    sys.exit(1)
            else:
                print('Invalid pre-defined time: {}'.format(_timeframe))
                sys.exit(1)
        
        if _timeframe.get('start'.lower()):
            if not _timeframe.get('stop'.lower()):
                    print('Error: start time specified without end time')
                    sys.exit(1)
            self._q['config']['timeRange'] = 'CUSTOM'
            self._q['config']['customStart'] = _timeframe['start'.lower()]
            
        if _timeframe.get('stop'.lower()):
            if not _timeframe.get('start'.lower()):
                    print('Error: end time specified without start time')
                    sys.exit(1)
            self._q['config']['customEnd'] = _timeframe['stop'.lower()]

            
    def _validate_sort(self):
        try:
            _sort = self._query['sort']
        except KeyError:
            print('Error: sort section not found in query file')
            sys.exit(1)
            
        _directions = ['ASCENDING', 'DESCENDING']
        try:
            if _sort['order'].upper() in _directions:
                _direction = _sort['order']
            else:
                print('Error: Sort direction not valid: {}'.format(_sort['order']))
                sys.exit(1)
                
            if ',' + _sort['field'] + ',' in self._all_fields:
                _sort_field = _sort['field']
            else:
                print('Error: Sort direction not valid: {}'.format(_sort['order']))
                sys.exit(1)
            
            _sort_q = {'direction': _direction,
                        'field': {'name': _sort_field}}
            self._q['config']['order'] = []
            self._q['config']['order'].append(_sort_q)
        except:
            print('Error: sort section field or order not found')
            sys.exit(1)
            
    def json(self):
        return self._q
            
            
def main():

    esm = ESM(HOST, USERNAME, PASSWD)
    
    with open('query.yaml')  as f:
        yaml_data = yaml.full_load(f)



    esm.login()        
    query = Query(yaml_data, esm)
    print('--ESM Query Syntax--')
    print(json.dumps(query.json(), indent=2))
    
    results = []
    for row in esm.query(query.json()):
        if row.get('rows'):
            for r in row.get('rows'):
                print(r)
        
    esm.logout()
    
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Control-C Pressed, stopping...")
        sys.exit()
