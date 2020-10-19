import inspect
import json
import logging

from django.http import JsonResponse
from oidc_provider import settings
from oidc_provider.lib.errors import TokenError
from oidc_provider.lib.utils.oauth2 import extract_access_token
from oidc_provider.lib.utils.token import create_token, encode_id_token
from oidc_provider.models import Client, Code, Token

logger = logging.getLogger(__name__)

# Clase habilitada unicamente para el client_credentials grant type
class TokenRefreshEndpoint(object):
    def __init__(self, request):
        self.request = request
        self.params = {}
        self.client = None
        self._extract_params()
        

    def _extract_params(self):
        token = extract_access_token(self.request)

        self.params['refresh_token'] = token

        if settings.get('OIDC_ALLOW_PARAMS_JSON_BODY'):
            body_unicode = self.request.body.decode('utf-8')
            body = json.loads(body_unicode)
            b_dict = dict(body)
            logger.error(b_dict)
            self.params['scope'] = b_dict.get('scope', '')
            self.params['grant_type'] = b_dict.get('grant_type', '')
        else:
            self.params['scope'] = self.request.POST.get('scope', '')
            self.params['grant_type'] = self.request.POST.get('grant_type', '')

    
    def validate_params(self):

        if self.params['grant_type'] == 'refresh_token':
            if not self.params['refresh_token']:
                logger.debug('[Token] Missing refresh token')
                raise TokenError('invalid_grant')

            try:
                self.token = Token.objects.get(refresh_token=self.params['refresh_token'])

            except Token.DoesNotExist:
                logger.debug(
                    '[Token] Refresh token does not exist: %s', self.params['refresh_token'])
                raise TokenError('invalid_refresh_token')
            if self.token.token_refresh_has_expired():
                logger.debug('[Token] Token Refresh has expired: %s', self.params['refresh_token'])
                raise TokenError('expired_refresh_token')
        else:
            logger.debug('[Token] Invalid grant type: %s', self.params['grant_type'])
            raise TokenError('unsupported_grant_type')

    def create_response_dic(self):
        
        if self.params['grant_type'] == 'refresh_token':
            return self.create_refresh_response_dic()

    def create_refresh_response_dic(self):
        # See https://tools.ietf.org/html/rfc6749#section-6

        scope_param = self.params['scope']
        scope = (scope_param.split(' ') if scope_param else self.token.scope)
        unauthorized_scopes = set(scope) - set(self.token.scope)
        if unauthorized_scopes:
            raise TokenError('invalid_scope')

        token = create_token(
            user=None,
            client=self.token.client,
            scope=scope)

        id_token_dic = {}
        token.id_token = id_token_dic

        # Store the token.
        token.save()

        # Forget the old token.
        self.token.delete()

        dic = {
            'access_token': token.access_token,
            'refresh_token': token.refresh_token,
            'token_type': 'bearer',
            'expires_in': settings.get('OIDC_TOKEN_EXPIRE'),
            'scope': self.token.client._scope,
        }

        return dic

    @classmethod
    def response(cls, dic, status=200):
        """
        Create and return a response object.
        """
        response = JsonResponse(dic, status=status)
        response['Cache-Control'] = 'no-store'
        response['Pragma'] = 'no-cache'

        return response

