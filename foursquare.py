"""
Foursquare API Python module
by John Wiseman <jjwiseman@gmail.com>

Based on a Fire Eagle module by Steve Marshall<steve@nascentguruism.com>.

Example usage:

* No authentication

>>> import foursquare
>>> fs = foursquare.Foursquare()
>>> fs.cities()
{'cities': [{'geolat': 52.378900000000002, 'name': 'Amsterdam', ...}]}

* Basic HTTP auth

>>> import foursquare
>>> fs = foursquare.Foursquare(foursquare.BasicCredentials(username, password))
>>> fs.switchcity(23)
{'data': {'status': '1', 'message': 'City switched successfully'}}
>>> fs.switchcity(34)
{'data': {'status': '1', 'message': 'City switched successfully'}}
>>> fs.user()
{'user': {'city': {'geolat': 34.0443, 'name': 'Los Angeles', ...}}}

* OAuth

>>> import foursquare
>>> credentials = foursquare.OAuthCredentials(oauth_key, oauth_secret)
>>> fs = foursquare.Foursquare(credentials)
>>> app_token = fs.request_token()
>>> auth_url = fs.authorize(app_token)
>>> print "Go to %s and authorize, then continue." % (auth_url,)
>>> user_token = fs.access_token(app_token)
>>> credentials.set_access_token(user_token)
>>> fs.user()
{'user': {'city': {'geolat': 34.0443, 'name': 'Los Angeles', ...}}}
"""

import httplib
import urllib
import string
import sys
import logging
import base64

import oauth

try:
    # Python 2.6?
    import json
    simplejson = json
except ImportError:
    try: 
        # Have simplejson?
        import simplejson
    except ImportError:
        # Have django or are running in the Google App Engine?
        from django.utils import simplejson


# General API setup
API_PROTOCOL = 'http'
API_SERVER   = 'api.foursquare.com'
API_VERSION  = 'v1'

OAUTH_SERVER = 'foursquare.com'


# Calling templates
API_URL_TEMPLATE   = string.Template(
    API_PROTOCOL + '://' + API_SERVER + '/' + API_VERSION + '/${method}.json'
)

OAUTH_URL_TEMPLATE = string.Template(
    API_PROTOCOL + '://' + OAUTH_SERVER + '/oauth/${method}'
)


POST_HEADERS = {
    'Content-type': 'application/x-www-form-urlencoded',
    'Accept'      : 'text/plain'
}



FOURSQUARE_METHODS = {}

def def_method(name, auth_required=False, server=API_SERVER,
               http_method="GET", optional=[], required=[],
               returns=None, url_template=API_URL_TEMPLATE):
    FOURSQUARE_METHODS[name] = {
        'server': server,
        'http_method': http_method,
        'auth_required': auth_required,
        'optional': optional,
        'required': required,
        'returns': returns,
        'url_template': url_template,
        }


# --------------------
# OAuth methods
# --------------------

def_method('request_token',
           server=OAUTH_SERVER,
           returns='oauth_token',
           url_template=OAUTH_URL_TEMPLATE)

def_method('authorize',
           server=OAUTH_SERVER,
           required=['token'],
           returns='request_url',
           url_template=OAUTH_URL_TEMPLATE)

def_method('access_token',
           server=OAUTH_SERVER,
           required=['token'],
           returns='oauth_token',
           url_template=OAUTH_URL_TEMPLATE)


# --------------------
# Geo methods
# --------------------

def_method('cities')

def_method('checkcity',
           auth_required=True,
           required=['geolat', 'geolong'])

def_method('switchcity',
           auth_required=True,
           http_method='POST',
           required=['cityid'])


# --------------------
# Check in methods
# --------------------

def_method('checkins',
           auth_required=True,
           optional=['cityid'])

def_method('checkin',
           auth_required=True,
           http_method='POST',
           optional=['vid', 'venue', 'shout', 'private',
                     'twitter', 'geolat', 'geolong'])

def_method('history',
           auth_required=True,
           optional=['l'])


# --------------------
# User methods
# --------------------

def_method('user',
           auth_required=True,
           optional=['uid', 'badges', 'mayor'])

def_method('friends',
           auth_required=True,
           optional=['uid'])


# --------------------
# Venue methods
# --------------------

def_method('venues',
           required=['geolat', 'geolong'],
           optional=['l', 'q'])

def_method('venue',
           required=['vid'])

def_method('addvenue',
           auth_required=True,
           http_method='POST',
           required=['name', 'address', 'crossstreet',
                     'city', 'state', 'cityid'],
           optional=['zip', 'phone'])


# --------------------
# Tip methods
# --------------------

def_method('tips',
           required=['geolat', 'geolong'],
           optional=['l'])

def_method('addtip',
           auth_required=True,
           http_method='POST',
           required=['vid', 'text'],
           optional=['type'])


# --------------------
# Settings methods
# --------------------

def_method('setpings',
           auth_required=True,
           http_method='POST',
           required=['self', 'uid'])


# --------------------
# Other methods
# --------------------

def_method('test')



class Credentials:
    pass

class OAuthCredentials(Credentials):
    def __init__(self, consumer_key, consumer_secret):
        self.consumer_key = consumer_key
        self.consumer_key = consumer_key
        self.oauth_consumer = oauth.OAuthConsumer(consumer_key, consumer_secret)
        self.signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1()
        self.access_token = None
        
    def build_request(self, http_method, url, parameters, token=None):
        if token == None:
            token = self.access_token
        request = oauth.OAuthRequest.from_consumer_and_token(
            self.oauth_consumer,
            token=token,
            http_method=http_method,
            http_url=url,
            parameters=parameters)
        request.sign_request(self.signature_method, self.oauth_consumer, token)
        if http_method == 'GET':
            return request.to_url(), request.to_postdata(), {}
        else:
            return url, request.to_postdata(), {}

    def set_access_token(self, token):
        self.access_token = token

    def get_access_token(self):
        return self.access_token

    def authorized(self):
        return self.access_token != None
    
        
class BasicCredentials(Credentials):
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def build_request(self, http_method, url, parameters, token=None):
        # Need to strip the newline off.
        auth_string = base64.encodestring('%s:%s' % (self.username, self.password))[:-1]
        query = urllib.urlencode(parameters)
        if http_method == 'POST':
            args = query
        else:
            args = None
        return url+ '?' + query, args, {'Authorization': 'Basic %s' % (auth_string,)}

    def authorized(self):
        return True

class NullCredentials(Credentials):
    def __init__(self):
        pass
    def authorized(self):
        return False
    def build_request(self, http_method, url, parameters, token=None):
        query = urllib.urlencode(parameters)
        if http_method == 'POST':
            args = query
        else:
            args = None
        return url + '?' + query, args, {}


                
    
class FoursquareException(Exception):
    pass

class FoursquareRemoteException(FoursquareException):
    def __init__(self, method, code, msg):
        self.method = method
        self.code = code
        self.msg = msg

    def __str__(self):
        return 'Error signaled by remote method %s: %s (%s)' % (self.method, self.msg, self.code)



# Used as a proxy for methods of the Foursquare class; when methods
# are called, __call__ in FoursquareAccumulator is called, ultimately
# calling the foursquare_obj's callMethod()
class FoursquareAccumulator:
    def __init__(self, foursquare_obj, name):
        self.foursquare_obj = foursquare_obj
        self.name = name
    
    def __repr__(self):
        return self.name
    
    def __call__(self, *args, **kw):
        return self.foursquare_obj.call_method(self.name, *args, **kw)
    

class Foursquare:
    def __init__(self, credentials=None):
        # Prepare object lifetime variables
        if credentials:
            self.credentials = credentials
        else:
            self.credentials = NullCredentials()

        # Prepare the accumulators for each method
        for method in FOURSQUARE_METHODS:
            if not hasattr(self, method):
                setattr(self, method, FoursquareAccumulator(self, method))

    def get_http_connection(self, server):
        return httplib.HTTPConnection(server)
        
    
    def fetch_response(self, server, http_method, url, body=None, headers=None):
        """Pass a request to the server and return the response as a
        string.
        """
        http_connection = self.get_http_connection(server)

        # Prepare the request
        if (body is not None) or (headers is not None):
            http_connection.request(http_method, url, body, merge_dicts(POST_HEADERS, headers))
        else:
            http_connection.request(http_method, url)
        
        # Get the response
        response = http_connection.getresponse()
        response_body = response.read()

        # If we've been informed of an error, raise it
        if response.status != 200:
            raise FoursquareRemoteException(url, response.status, response_body)
        
        # Return the body of the response
        return response_body
    

    def call_method(self, method, *args, **kw):
        logging.debug('Calling foursquare method %s %s %s' % (method, args, kw))
        logging.debug('Credentials: %s' % (self.credentials,))
        
        # Theoretically, we might want to do 'does this method exits?'
        # checks here, but as all the aggregators are being built in
        # __init__(), we actually don't need to: Python handles it for
        # us.
        meta = FOURSQUARE_METHODS[method]

        if meta['auth_required'] and (not self.credentials or not self.credentials.authorized()):
            raise FoursquareException('Remote method %s requires authorization.' % (`method`,))
        
        if args:
            # Positional arguments are mapped to meta['required'] and
            # meta['optional'] in order of specification of those
            # (with required first, obviously)
            names = meta['required'] + meta['optional']
            for i in xrange(len(args)):
                kw[names[i]] = args[i]
        
        # Check we have all required arguments
        if len(set(meta['required']) - set(kw.keys())) > 0:
            raise FoursquareException('Too few arguments were supplied for the method %s; required arguments are %s.' % (method, ', '.join(meta['required'])))

        # Check that we don't have extra arguments.
        for arg in kw:
            if (not arg in meta['required']) and (not arg in meta['optional']):
                raise FoursquareException('Unknown argument %s supplied to method %s; ' % \
                                          (arg, method) + \
                                          'required arguments are %s., optional arguments are %s.' % \
                                          (', '.join(meta['required']),
                                           ', '.join(meta['optional'])))
                                                                                                                                                 
        
        # Token shouldn't be handled as a normal arg, so strip it out
        # (but make sure we have it, even if it's None)
        if 'token' in kw:
            token = kw['token']
            del kw['token']
        else:
            token = None


        # Build the request.
        cred_url, cred_args, cred_headers = self.credentials.build_request(
            meta['http_method'],
            meta['url_template'].substitute(method=method),
            kw,
            token=token)

        # If the return type is the request_url, simply build the URL and 
        # return it witout executing anything    
        if 'returns' in meta and meta['returns'] == 'request_url':
            return cred_url
        
        server = API_SERVER
        if 'server' in meta:
            server = meta['server']
            
        if meta['http_method'] == 'POST':
            response = self.fetch_response(server, meta['http_method'],
                                           cred_url,
                                           body=cred_args,
                                           headers=cred_headers)
        else:
            response = self.fetch_response(server, meta['http_method'],
                                           cred_url,
                                           headers=cred_headers)
        
        # Method returns nothing, but finished fine
        # Return the oauth token
        if 'returns' in meta and meta['returns'] == 'oauth_token':
            return oauth.OAuthToken.from_string(response)
        
        results = simplejson.loads(response)
        return results
    

# TODO: Cached version

def merge_dicts(a, b):
    if a == None:
        return b
    if b == None:
        return a

    r = {}
    for key, value in a.items():
        r[key] = value
    for key, value in b.items():
        r[key] = value
    return r
