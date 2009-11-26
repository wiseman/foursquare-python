| Copyright 2009 `John Wiseman`_
| Covered by the MIT License, see `LICENSE.txt`.

foursquare
==========

This python module lets you access the `foursquare API`_.  It supports no
authentication, `basic HTTP authentication`_, and `OAuth`_.

It supports all the v1 foursquare API methods.


Examples
--------

No authentication::

 >>> import foursquare
 >>> fs = foursquare.Foursquare()
 >>> fs.cities
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
 >>> print "Go to %s and authorize, then continue." % (auth_url,)
 >>> user_token = fs.access_token(app_token)
 >>> credentials.set_access_token(user_token)
 >>> fs.user()
 {'user': {'city': {'geolat': 34.0443, 'name': 'Los Angeles', ...}}}


.. _foursquare API: http://groups.google.com/group/foursquare-api
.. _basic HTTP authentication: http://en.wikipedia.org/wiki/Basic_access_authentication
.. _OAuth: http://groups.google.com/group/foursquare-api/web/oauth
.. _John Wiseman: http://twitter.com/
.. _LICENSE.txt: http://github.com/wiseman/foursquare-python/blob/master/LICENSE.txt
