import unittest
import time

import foursquare


TEST_OAUTH = True

MY_COORDS = [34.09075, -118.27516]


class TestFoursquare(unittest.TestCase):
  def test_unauthenticated(self):
    "Testing unauthenticated methods."
    fs = foursquare.Foursquare()
    test_result = fs.test()
    self.assertEqual(test_result['response'], 'ok')

    cities = fs.cities()
    self.failUnless('cities' in cities)
    self.failUnless(len(cities['cities']) > 0)
    self.failUnless(find_if(cities['cities'], lambda o: o['id'] == 34), "Where did LA go?")

    venues = fs.venues(MY_COORDS[0], MY_COORDS[1])
    self.failUnless('groups' in venues)
    local_cafe = find_if(venues['groups'][0]['venues'], lambda o: o['id'] == 20209)
    self.failUnless(local_cafe)

    self.assertRaises(foursquare.FoursquareException, lambda: fs.user())
    

  def test_basic_auth(self):
    "Testing basic HTTP authentication."
    fs = foursquare.Foursquare(foursquare.BasicCredentials(username, password))
    test_result = fs.test()
    self.assertEqual(test_result['response'], 'ok')
    user = fs.user()
    self.failUnless('user' in user)

    # Now try with a bad user/password
    fs = foursquare.Foursquare(foursquare.BasicCredentials(username, 'passworddontmatter' + password))
    self.assertRaises(foursquare.FoursquareRemoteException, lambda: fs.user())


  def test_oauth(self):
    if not TEST_OAUTH:
      return
    
    # Authorization dance.
    oauth_key = raw_input('Enter your foursquare oauth consumer key: ')
    oauth_secret = raw_input('Enter your foursquare oauth consumer secret: ')
    fs = foursquare.Foursquare(foursquare.OAuthCredentials(oauth_key, oauth_secret))
    app_token = fs.request_token()
    auth_url = fs.authorize(app_token)
    raw_input('Please go the following URL and authorize your app, then press enter: %s\n' % (auth_url,))
    # In case we're being piped usernames and passwords and keys and secrets and...
    time.sleep(15)
    user_token = fs.access_token(app_token)
    fs.credentials.set_access_token(user_token)
    
    # Now we can test some methods.
    test_result = fs.test()
    self.assertEqual(test_result['response'], 'ok')
    user = fs.user()
    self.failUnless('user' in user)


  def test_arg_handling(self):
    "Testing handling of API method arguments."
    fs = foursquare.Foursquare()
    # Missing required args.
    self.assertRaises(foursquare.FoursquareException, lambda: fs.venues())
    # Extra args
    self.assertRaises(foursquare.FoursquareException,
                      lambda: fs.venues(MY_COORDS[0], MY_COORDS[1],
                                        unknown_arg='BLUH'))
    # Different way of passing required args, and now optional args.
    venues = fs.venues(geolat=MY_COORDS[0], geolong=MY_COORDS[1], l=1)
    self.failUnless('groups' in venues)
    self.assertEqual(len(venues['groups'][0]['venues']), 1)


  def test_friends(self):
    "Testing friend methods."
    fs = foursquare.Foursquare(foursquare.BasicCredentials(username, password))
    self.failUnless('requests' in fs.friend_requests())
    users = fs.findfriends_byname('william')
    print len(users['users'])
    self.failUnless('users' in users)
    self.failUnless(len(users['users']) > 0)
    

def find_if(objs, pred):
  for o in objs:
    if pred(o):
      return o
  return None



username = None
password = None

if __name__ == '__main__':
  username = raw_input('Enter your foursquare username: ')
  password = raw_input('Enter your foursquare password: ')
  unittest.main()
    
