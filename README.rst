| Copyright 2009 `John Wiseman`_
| Covered by the MIT License, see `LICENSE.txt`_.

foursquare
==========

This Python module lets you access the `foursquare API`_.  It supports
unauthenticated access, `basic HTTP authentication`_, and `OAuth`_
authorization.

It supports all the v1 foursquare API methods as of 2009-12-17.

This module requires Leah Culver's oauth module, `oauth.py`_.

API method names are the same in Python, except for methods like
"friend/requests", which are translated to names like
"friend_requests" in Python.

All arguments are keyword arguments, though required arguments come
first and are in the order listed by the API documentation.

All methods return the Python equivalent of the JSON response returned
by the corresponding API method, if there is a response.

Examples
--------

No authentication::

 >>> import foursquare
 >>> fs = foursquare.Foursquare()
 >>> fs.cities()
 {'cities': [{'geolat': 52.378900000000002, 'name': 'Amsterdam', ...}]}

Basic HTTP authentication::

 >>> import foursquare
 >>> fs = foursquare.Foursquare(foursquare.BasicCredentials(username, password))
 >>> fs.switchcity(23)
 {'data': {'status': '1', 'message': 'City switched successfully'}}
 >>> fs.switchcity(34)
 {'data': {'status': '1', 'message': 'City switched successfully'}}
 >>> fs.user()
 {'user': {'city': {'geolat': 34.0443, 'name': 'Los Angeles', ...}}}

OAuth::

When foursquare added support for the ``oauth_callback`` parameter to
specify a callback URL, they made ``oauth_verifier`` argument a
required argument to the ``access_token`` method.  The
``oauth_verifier`` that you need to pass to ``access_token`` comes
from the URL that foursquare redirects the user to after
authorization.

 >>> import foursquare
 >>> credentials = foursquare.OAuthCredentials(oauth_key, oauth_secret)
 >>> fs = foursquare.Foursquare(credentials)
 >>> app_token = fs.request_token(oauth_callback='http://myapp.example/')
 >>> auth_url = fs.authorize(app_token)

 # Go to auth_url and authorize.  Once you've authorized, foursquare
 # will redirect you to a URL that looks like this:
 #
 #   http://myapp.example/?oauth_verifier=1234
 #
 # Take that oauth_verifier parameter and pass it to access_token.

 >>> oauth_verifier = '1234'
 >>> user_token = fs.access_token(app_token, oauth_verifier)
 >>> credentials.set_access_token(user_token)
 >>> fs.user()
 {'user': {'city': {'geolat': 34.0443, 'name': 'Los Angeles', ...}}}

The above is the most correct method, according to the `OAuth 1.0A
spec`_.  But foursquare supports a less stringent mode if you don't
pass a ``oauth_callback` argument, in which case you don't need to
pass an ``oauth_verifier`` to ``access_token``:

 >>> import foursquare
 >>> credentials = foursquare.OAuthCredentials(oauth_key, oauth_secret)
 >>> fs = foursquare.Foursquare(credentials)
 >>> app_token = fs.request_token(oauth_callback='http://myapp.example/')
 >>> auth_url = fs.authorize(app_token)
 
 # Go to auth_url and authorize.  Note that we're passing an empty
 # string for the oauth_verifier.
 
 >>> user_token = fs.access_token(app_token, '')
 >>> credentials.set_access_token(user_token)
 >>> fs.user()
 {'user': {'city': {'geolat': 34.0443, 'name': 'Los Angeles', ...}}}


.. _foursquare API: http://groups.google.com/group/foursquare-api
.. _basic HTTP authentication: http://en.wikipedia.org/wiki/Basic_access_authentication
.. _OAuth: http://groups.google.com/group/foursquare-api/web/oauth
.. _John Wiseman: http://twitter.com/lemonodor
.. _LICENSE.txt: http://github.com/wiseman/foursquare-python/blob/master/LICENSE.txt
.. _oauth.py: http://oauth.googlecode.com/svn/code/python/oauth/
.. _OAuth 1.0A spec: http://oauth.net/core/1.0a/
