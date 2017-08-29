# -*- coding: utf-8 -*-

import os
import uuid
import logging
import requests
from requests_oauthlib import OAuth2Session
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.core.cache import cache
from pprint import pprint

from seahub import auth
from seahub.profile.models import Profile

import seahub.settings as settings

logger = logging.getLogger(__name__)

# TODO
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

def get_authorization_url_and_state(oauth_data):
    provider = oauth_data['provider']
    client_id = oauth_data['client_id']
    scope = oauth_data['scope']
    redirect_uri = oauth_data['redirect_uri']
    authorization_base_url = oauth_data['authorization_base_url']

    session = OAuth2Session(client_id,
            scope=scope, redirect_uri=redirect_uri)

    if provider == 'github':
        authorization_url, state = session.authorization_url(authorization_base_url)

    if provider == 'google':
        authorization_url, state = session.authorization_url(authorization_base_url,
                access_type="offline", approval_prompt="force")

    return authorization_url, state

def get_access_token(oauth_data):

    client_id = oauth_data['client_id']
    state = oauth_data['state']
    redirect_uri = oauth_data['redirect_uri']
    token_url = oauth_data['token_url']
    client_secret = oauth_data['client_secret']
    authorization_response = oauth_data['authorization_response']

    session = OAuth2Session(client_id,
            state=state, redirect_uri=redirect_uri)

    access_token = session.fetch_token(token_url,
            client_secret=client_secret,
            authorization_response=authorization_response)

    return access_token

def get_user_info(oauth_data):
    client_id = oauth_data['client_id']
    access_token = oauth_data['access_token']
    user_info_url = oauth_data['user_info_url']
    provider = oauth_data['provider']

    session = OAuth2Session(client_id, token=access_token)
    user_info_response = session.get(user_info_url)

    user_info = {
        'email': '',
        'name': '',
        'contact_email': '',
    }

    if provider == 'github':
        login_id = user_info_response.json().get('login')
        name = user_info_response.json().get('name')
        contact_email = user_info_response.json().get('email')

        user_info['email'] = login_id + '@github.com'
        user_info['name'] = name
        user_info['contact_email'] = contact_email

    if provider == 'google':
        email = user_info_response.json().get('email')
        user_info['email'] = email

    return user_info

# Oauth for Github
GITHUB_OAUTH_DATA = {
    'provider': 'github',
    'client_id': getattr(settings, 'OAUTH_GITHUB_CLIENT_ID', None),
    'client_secret': getattr(settings, 'OAUTH_GITHUB_CLIENT_SECRET', None),
    'authorization_base_url': getattr(settings,
        'OAUTH_GITHUB_AUTHORIZATION_BASE_URL',
        'https://github.com/login/oauth/authorize'),
    'redirect_uri': getattr(settings, 'OAUTH_GITHUB_REDIRECT_URI', None),
    'token_url': getattr(settings, 'OAUTH_GITHUB_TOKEN_URL',
        'https://github.com/login/oauth/access_token'),
    'scope': '',
    'user_info_url': getattr(settings, 'OAUTH_GITHUB_USER_INFO_URL',
        'https://api.github.com/user'),
}

def oauth_github_login(request):
    """Step 1: User Authorization.
    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """

    cache_key = 'github_oauth_state_cache_key'
    authorization_url, state = get_authorization_url_and_state(GITHUB_OAUTH_DATA)
    cache.set(cache_key, state, 24 * 60 * 60)
    return HttpResponseRedirect(authorization_url)

# Step 2: User authorization, this happens on the provider.
def oauth_github_callback(request):
    """ Step 3: Retrieving an access token.
    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """

    cache_key = 'github_oauth_state_cache_key'
    GITHUB_OAUTH_DATA['state'] = cache.get(cache_key)
    GITHUB_OAUTH_DATA['authorization_response'] = request.get_full_path()

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    access_token = get_access_token(GITHUB_OAUTH_DATA)

    GITHUB_OAUTH_DATA['access_token'] = access_token
    user_info = get_user_info(GITHUB_OAUTH_DATA)

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

# Oauth for Google
GOOGLE_OAUTH_DATA = {
    'google': 'google',
    'client_id': getattr(settings, 'OAUTH_GOOGLE_CLIENT_ID', None),
    'client_secret': getattr(settings, 'OAUTH_GOOGLE_CLIENT_SECRET', None),
    'authorization_base_url': getattr(settings,
        'OAUTH_GOOGLE_AUTHORIZATION_BASE_URL',
        'https://accounts.google.com/o/oauth2/v2/auth'),
    'redirect_uri': getattr(settings, 'OAUTH_GOOGLE_REDIRECT_URI',
        'http://localhost:8000/oauth/google/callback'),
    'token_url': getattr(settings, 'OAUTH_GOOGLE_TOKEN_URL',
        'https://www.googleapis.com/oauth2/v4/token'),
    'scope': [
        "www.googleapis.com/auth/userinfo.email",
        "www.googleapis.com/auth/userinfo.profile"
    ],
    'user_info_url': getattr(settings, 'OAUTH_GOOGLE_USER_INFO_URL',
        'https://www.googleapis.com/oauth2/v1/userinfo')
}

def oauth_google_login(request):
    """Step 1: User Authorization.
    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """

    cache_key = 'google_oauth_state_cache_key'
    authorization_url, state = get_authorization_url_and_state(GOOGLE_OAUTH_DATA)
    cache.set(cache_key, state, 24 * 60 * 60)
    return HttpResponseRedirect(authorization_url)

# Step 2: User authorization, this happens on the provider.
def oauth_google_callback(request):
    """ Step 3: Retrieving an access token.
    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.
    """

    cache_key = 'google_oauth_state_cache_key'
    GOOGLE_OAUTH_DATA['state'] = cache.get(cache_key)
    GOOGLE_OAUTH_DATA['authorization_response'] = request.get_full_path()

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    access_token = get_access_token(GOOGLE_OAUTH_DATA)

    GOOGLE_OAUTH_DATA['access_token'] = access_token
    user_info = get_user_info(GOOGLE_OAUTH_DATA)

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

        if self.provider == 'weixin':

            self.CORP_ID = getattr(settings,
                    'OAUTH_WEIXIN_CORP_ID', None)

            self.AGENT_ID = getattr(settings,
                    'OAUTH_WEIXIN_AGENT_ID', None)

            self.CORP_SECRET = getattr(settings,
                    'OAUTH_WEIXIN_CORP_SECRET', None)

            self.AUTHORIZATION_BASE_URL = getattr(settings,
                    'OAUTH_WEIXIN_AUTHORIZATION_BASE_URL',
                    'https://open.weixin.qq.com/connect/oauth2/authorize')

            self.REDIRECT_URI = getattr(settings,
                    'OAUTH_WEIXIN_REDIRECT_URI',
                    'https://demo.seafile.top/oauth/weixin/callback')

            self.TOKEN_URL = getattr(settings,
                    'OAUTH_WEIXIN_TOKEN_URL',
                    'https://qyapi.weixin.qq.com/cgi-bin/gettoken')

            self.SCOPE = 'snsapi_base'

            self.USER_INFO_URL = getattr(settings,
                    'OAUTH_WEIXIN_USER_INFO_URL',
                    'https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo')

    def get_authorization_url_and_state(self):
        session = OAuth2Session(self.CLIENT_ID,
                scope=self.SCOPE, redirect_uri=self.REDIRECT_URI)

        if self.provider == 'github':
            authorization_url, state = session.authorization_url(self.AUTHORIZATION_BASE_URL)

        if self.provider == 'google':
            authorization_url, state = session.authorization_url(self.AUTHORIZATION_BASE_URL,
                    access_type="offline", approval_prompt="force")

        if self.provider == 'weixin':

            auth_url = self.AUTHORIZATION_BASE_URL

            # appid, 企业微信的CorpID，在企业微信管理端查看
            appid = self.CORP_ID

            # redirect_uri, 重定向地址，需要进行UrlEncode
            redirect_uri = self.REDIRECT_URI

            scope = self.SCOPE

            # agentid, 授权方的网页应用ID，在具体的网页应用中查看
            agentid = self.AGENT_ID

            # state, 用于保持请求和回调的状态，授权请求后原样带回给企业。该参数可用于防止csrf攻击（跨站请求伪造攻击），建议企业带上该参数，可设置为简单的随机数加session进行校验
            uid = uuid.uuid4()
            state = uid.hex

            authorization_url = '%s?appid=%s&redirect_uri=%s&response_type=code&scope=%s&agentid=%s&state=%s#wechat_redirect' \
                    % (auth_url, appid, redirect_uri, scope, agentid, state)

        return authorization_url, state

    def get_access_token(self, state, authorization_response):

        if self.provider in ('github', 'google'):

            session = OAuth2Session(self.CLIENT_ID,
                    state=state, redirect_uri=self.REDIRECT_URI)

            access_token = session.fetch_token(self.TOKEN_URL,
                    client_secret=self.CLIENT_SECRET,
                    authorization_response=authorization_response)

        if self.provider == 'weixin':

            # corpid, 企业ID
            corpid = self.CORP_ID

            # corpsecret, 应用的凭证密钥
            corpsecret= self.CORP_SECRET

            token_url = self.TOKEN_URL

            access_token = requests.get('%s?corpid=%s&corpsecret=%s' \
                    % (token_url, corpid, corpsecret))

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

        if self.provider == 'weixin':

            # user_info_url = self.USER_INFO_URL
            # url = '%s?access_token=%s&code=%s' % (user_info_url, access_token, code)

            user_id = user_info_response.json().get('UserId')

            user_info['email'] = user_id + '@weixin.com'
            user_info['name'] = user_id
            user_info['contact_email'] = user_id  + '-contact@weixin.com',

        return user_info

def oauth_login(request, provider):
    """Step 1: User Authorization.
    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """

    cache_key = provider + '_oauth_state_cache_key'
    oauth = Oauth2(provider)
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
    access_token = oauth.get_access_token(state, request.get_full_path())

    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    user_info = oauth.get_user_info(access_token)

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
