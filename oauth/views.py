import os
import requests
import logging
from requests_oauthlib import OAuth2Session
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.core.cache import cache

from seahub import auth
from seahub.profile.models import Profile

import seahub.settings as settings

logger = logging.getLogger(__name__)
# TODO
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

class Oauth2(object):

    CLIENT_ID = ''
    CLIENT_SECRET= ''
    AUTHORIZATION_BASE_URL = ''
    TOKEN_URL = ''
    REDIRECT_URI = ''
    SCOPE = []
    USER_INFO_URL = ''

    def __init__(self, provider=None):

        self.provider = provider

        if self.provider == 'github':

            self.CLIENT_ID = getattr(settings,
                    'OAUTH_GITHUB_CLIENT_ID', None)

            self.CLIENT_SECRET = getattr(settings,
                    'OAUTH_GITHUB_CLIENT_SECRET', None)

            self.AUTHORIZATION_BASE_URL = getattr(settings,
                    'OAUTH_GITHUB_AUTHORIZATION_BASE_URL', 'https://github.com/login/oauth/authorize')

            self.REDIRECT_URI = getattr(settings,
                    'OAUTH_GITHUB_REDIRECT_URI', None)

            self.TOKEN_URL = getattr(settings,
                    'OAUTH_GITHUB_TOKEN_URL', 'https://github.com/login/oauth/access_token')

            self.USER_INFO_URL = getattr(settings,
                    'OAUTH_GITHUB_USER_INFO_URL', 'https://api.github.com/user')

        if self.provider == 'google':

            self.CLIENT_ID = getattr(settings,
                    'OAUTH_GOOGLE_CLIENT_ID', None)

            self.CLIENT_SECRET = getattr(settings,
                    'OAUTH_GOOGLE_CLIENT_SECRET', None)

            self.AUTHORIZATION_BASE_URL = getattr(settings,
                    'OAUTH_GOOGLE_AUTHORIZATION_BASE_URL', 'https://accounts.google.com/o/oauth2/v2/auth')

            self.REDIRECT_URI = getattr(settings,
                    'OAUTH_GOOGLE_REDIRECT_URI', 'http://localhost:8000/oauth/google/callback')

            self.TOKEN_URL = getattr(settings,
                    'OAUTH_GOOGLE_TOKEN_URL', 'https://www.googleapis.com/oauth2/v4/token')

            self.SCOPE = [
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile"
            ]

            self.USER_INFO_URL = getattr(settings,
                    'OAUTH_GOOGLE_USER_INFO_URL', 'https://www.googleapis.com/oauth2/v1/userinfo')

    def get_authorization_url_and_state(self):
        session = OAuth2Session(self.CLIENT_ID,
                scope=self.SCOPE, redirect_uri=self.REDIRECT_URI)

        if self.provider == 'github':
            authorization_url, state = session.authorization_url(self.AUTHORIZATION_BASE_URL)

        if self.provider == 'google':
            authorization_url, state = session.authorization_url(self.AUTHORIZATION_BASE_URL,
                    access_type="offline", approval_prompt="force")

        return authorization_url, state

    def get_access_token(self, state, authorization_response):
        session = OAuth2Session(self.CLIENT_ID,
                state=state, redirect_uri=self.REDIRECT_URI)

        access_token = session.fetch_token(self.TOKEN_URL,
                client_secret=self.CLIENT_SECRET, authorization_response=authorization_response)

        return access_token

    def get_user_info(self, access_token):
        session = OAuth2Session(self.CLIENT_ID, token=access_token)
        user_info_response = session.get(self.USER_INFO_URL)

        user_info = {
            'email': '',
            'name': '',
            'contact_email': '',
        }

        if self.provider == 'github':
            login_id = user_info_response.json().get('login')
            name = user_info_response.json().get('name')
            contact_email = user_info_response.json().get('email')

            user_info['email'] = login_id + '@github.com'
            user_info['name'] = name
            user_info['contact_email'] = contact_email

        if self.provider == 'google':
            email = user_info_response.json().get('email')
            user_info['email'] = email

        return user_info

    def get_weixin_oauth_url_and_state(self):

        appid = 'wwcbae32011b764296'
        redirect_uri = 'https%3A%2F%2Fdemo.seafile.top%2Foauth%2Fweixin%2Fcallback'
        scope = 'snsapi_base'
        agentid = '1000004'
        state = '123'

        oauth_url = 'https://open.weixin.qq.com/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code&scope=%s&agentid=%s&state=%s#wechat_redirect' % (appid, redirect_uri, scope, agentid, state)

        logger.error('oauth_url: ', oauth_url)
        return oauth_url, state

    def get_weixin_access_token(self):
        return '8BRuOhv2JcR537ozHAAp9AiwiShFvGiNTur9c3f9RLaimUpVigjqD-iVQlHKDnaZ-3ifOyWIlmyij9bK5PNKK4N3X9TGwX9hFSjaxNSsa0T3OKJs_wQEqRB_mRYdJa9ZDjZchAtTp5qH9WBmve2X5ESZbNRxr5kHXfcNP4Cbpv7688X3DX6uF94ln3bEjH_hPPrgzrVOQZLeL3fSd2Jda6WZ-lUHoaoA1KoXJJAntIe0Sye-tyD8P0hH69zo7FOd1KgngC_dnUwHk4bkEmerUC4XrOWTxSfH4WKiJA3x7fg'

    def get_weixin_user_info(self, access_token, code):

        url = 'https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo?access_token=%s&code=%s' % (access_token, code)
        logger.error('user_url: ', url)
        resp = requests.get(url)
        logger.error('user_resp: ', str(resp.json()))

        user_id = resp.json().get('UserId')
        return {
            'email': user_id  + '@weixin.com',
            'name': user_id,
            'contact_email': user_id  + '-contact@weixin.com',
        }

def oauth_login(request, provider):
    """Step 1: User Authorization.
    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """

    cache_key = provider + '_oauth_state_cache_key'
    oauth = Oauth2(provider)

    if provider == 'weixin':
        authorization_url, state = oauth.get_weixin_oauth_url_and_state()
    else:
        authorization_url, state = oauth.get_authorization_url_and_state()

    cache.set(cache_key, state, 24 * 60 * 60)
    return HttpResponseRedirect(authorization_url)

# Step 2: User authorization, this happens on the provider.

def oauth_callback(request, provider):
    """ Step 3: Retrieving an access token.
    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """

    cache_key = provider + '_oauth_state_cache_key'
    oauth = Oauth2(provider)
    state = cache.get(cache_key)

    if provider == 'weixin':
        access_token = oauth.get_weixin_access_token()
    else:
        access_token = oauth.get_access_token(state, request.get_full_path())

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    logger.error('get: ', str(request.GET))

    code = request.GET.get('code')
    user_info = oauth.get_weixin_user_info(access_token, code)

    email = user_info['email']
    name = user_info['name']
    contact_email = user_info['contact_email']

    # seahub authenticate user
    user = auth.authenticate(remote_user=email)

    if not user or not user.is_active:
        # a page for authenticate user failed
        return HttpResponseRedirect(reverse('libraries'))

    # User is valid.  Set request.user and persist user in the session
    # by logging the user in.
    request.user = user
    auth.login(request, user)
    user.set_unusable_password()
    user.save()

    # update user's profile
    profile = Profile.objects.get_profile_by_user(email)
    if not profile:
        profile = Profile(user=email)

    if name.strip():
        profile.nickname = name

    if contact_email.strip():
        profile.contact_email = contact_email

    profile.save()

    # redirect user to home page
    return HttpResponseRedirect(reverse('libraries'))
