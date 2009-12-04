| Copyright 2009 `John Wiseman`_
| Covered by the MIT License, see `LICENSE.txt`_.

foursquare
==========

This python module lets you access the `foursquare API`_.  It supports
unauthenticated access, `basic HTTP authentication`_, and `OAuth`_
authorization.

It supports all the v1 foursquare API methods as of 2009-12-03.

This module requires Leah Culver's oauth module, `oauth.py`_.

API method names are the same in python, except for methods like
"friend/requests", which are translated to names like
"friend_requests" in python.

All arguments are keyword arguments, though required arguments come
first and are in the order listed by the API documentation.

All methods return the Python equivalent of the JSON response returned
by the corresponding API method, if there is one.

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

 >>> import foursquare
 >>> credentials = foursquare.OAuthCredentials(oauth_key, oauth_secret)
 >>> fs = foursquare.Foursquare(credentials)
 >>> app_token = fs.request_token()
 >>> auth_url = fs.authorize(app_token)
 >>> # Go to auth_url and authorize, then continue.
 >>> user_token = fs.access_token(app_token)
 >>> credentials.set_access_token(user_token)
 >>> fs.user()
 {'user': {'city': {'geolat': 34.0443, 'name': 'Los Angeles', ...}}}


.. _foursquare API: http://groups.google.com/group/foursquare-api
.. _basic HTTP authentication: http://en.wikipedia.org/wiki/Basic_access_authentication
.. _OAuth: http://groups.google.com/group/foursquare-api/web/oauth
.. _John Wiseman: http://twitter.com/lemonodor
.. _LICENSE.txt: http://github.com/wiseman/foursquare-python/blob/master/LICENSE.txt
.. _oauth.py: http://oauth.googlecode.com/svn/code/python/oauth/
