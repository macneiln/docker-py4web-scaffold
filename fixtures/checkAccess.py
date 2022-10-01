from dataclasses import dataclass
from py4web.core import Fixture, HTTP, redirect, URL, REGEX_APPJSON, request
from py4web.utils.auth import Auth
from py4web.utils.factories import ActionFactory
from pydal.tools.tags import Tags
from typing import Union
import re

class HasMembership(Fixture):

    def __init__(self, 
                 auth: Auth,
                 groups: Tags,
                 roles: Union[str, list],
                 has_all_groups: bool = False,
                 not_logged_in_redirect_url = None,
                 not_authorized_redirect_url = None,):

        self.__prerequisites__ = [auth]
        self.auth = auth
        self.groups = groups
        self.not_logged_in_redirect_url = not_logged_in_redirect_url
        self.not_authorized_redirect_url = not_authorized_redirect_url

        assert isinstance(roles, (str, list)), "Invalid role type provided."
        self.roles = roles if isinstance(roles, list) else [roles]

        assert isinstance(has_all_groups, bool), "A bool must be provided for the has_all_groups parameter."
        self.has_all_groups = has_all_groups

    def on_request(self, context):

        auth = self.auth
        db = auth.db
        groups = self.groups
        roles = self.roles
        has_all_groups = self.has_all_groups
        not_logged_in_redirect_url = self.not_logged_in_redirect_url
        not_authorized_redirect_url = self.not_authorized_redirect_url

        if not roles:
            return
            
        user_authorized = False

        user_id = auth.get_user().get('id', None)
        
        if not user_id:
            if not_logged_in_redirect_url:
                if callable(not_logged_in_redirect_url):
                    not_logged_in_redirect_url()
                redirect(URL(not_logged_in_redirect_url))
            raise HTTP(401)

        mode = "and" if has_all_groups else "or"

        user_authorized = not db(db.auth_user.id == user_id)(groups.find(roles, mode)).isempty()
        
        if not user_authorized:
            if not_authorized_redirect_url:
                if callable(not_authorized_redirect_url):
                    not_authorized_redirect_url()
                redirect(URL(not_authorized_redirect_url))
            raise HTTP(403)

REDIRECT_URL_OPTIONS = Union[callable, str, bool]

@dataclass
class CheckAccess:
    auth: Auth
    groups: Tags
    class_default_not_logged_in_redirect_url: REDIRECT_URL_OPTIONS = True
    class_default_not_authorized_redirect_url: REDIRECT_URL_OPTIONS = True


    def ajax_request(self):
        return re.search(REGEX_APPJSON, request.headers.get("accept", ""))            


    def perform_redirect(self, page, auth_route=None, vars=None, message=None):
        parts = []
        if auth_route:
            parts.append(auth_route)
        parts.append(page)

        redirect(URL(*parts,
                     vars=vars,
                     use_appname=self.auth.param.use_appname_in_redirects,))


    def not_logged_in_default(self, login_page="login", message="User not logged in"):
        # Return HTTP 401 if ajax request otherwise redirect to page.
        if self.ajax_request():
            raise HTTP(401)
            
        redirect_next = request.fullpath
        if request.query_string:
            redirect_next = f"{redirect_next}?{request.query_string}"
        vars=dict(next=redirect_next)

        self.perform_redirect(page=login_page, 
                              vars=vars, 
                              auth_route=self.auth.route,
                              message=message)


    def not_authorized_default(self, not_authorized_page="not-authorized", message="User not authorized"):
        # Return HTTP 403 if ajax request otherwise redirect to page.
        if self.ajax_request():
            raise HTTP(403)

        self.perform_redirect(page=not_authorized_page, 
                              message=message)


    def get_url_or_default(self,
                           current_url: REDIRECT_URL_OPTIONS,
                           default_url: REDIRECT_URL_OPTIONS, 
                           default_function: callable,) -> REDIRECT_URL_OPTIONS:
        
        if current_url != True:
            return current_url

        if default_url != True:
            return default_url

        return default_function
                                         

    def has_membership(self, 
                       roles: Union[str, list],
                       has_all_groups: bool = False,
                       not_logged_in_redirect_url: REDIRECT_URL_OPTIONS = True,
                       not_authorized_redirect_url: REDIRECT_URL_OPTIONS = True,) -> HasMembership:

        not_logged_in_redirect_url = self.get_url_or_default(current_url=not_logged_in_redirect_url,
                                                             default_url=self.class_default_not_logged_in_redirect_url,
                                                             default_function=self.not_logged_in_default)
        
        not_authorized_redirect_url = self.get_url_or_default(current_url=not_authorized_redirect_url,
                                                              default_url=self.class_default_not_authorized_redirect_url,
                                                              default_function=self.not_authorized_default)

        return HasMembership(auth=self.auth,
                             groups=self.groups,
                             roles=roles,
                             has_all_groups=has_all_groups,
                             not_logged_in_redirect_url=not_logged_in_redirect_url,
                             not_authorized_redirect_url=not_authorized_redirect_url,)

    
class AuthenticatedWithRole:

    def __init__(self, 
                 *fixtures):
        
        found = False
        
        fixtures = list(fixtures)

        for index, item in enumerate(fixtures):
            if isinstance(item, CheckAccess):
                found = True
                self.access_object_index = index

        assert found, "CheckAccess object must be provided."

        self.fixtures = fixtures

        
    def __call__(self,
                 path: Union[str, None] = None, 
                 roles: Union[str, list] = [],
                 template: Union[str, None] = None,
                 method = ["GET", "POST", "PUT", "HEAD", "DELETE"], 
                 has_all_groups: bool = False,
                 not_logged_in_redirect_url: REDIRECT_URL_OPTIONS = True,
                 not_authorized_redirect_url: REDIRECT_URL_OPTIONS = True,):
        
        fixtures = self.fixtures
        access_object_index  = self.access_object_index 

        new_fixtures = fixtures[:access_object_index]

        new_fixtures.append(fixtures[access_object_index].has_membership(roles=roles,
                                                                         has_all_groups=has_all_groups,
                                                                         not_logged_in_redirect_url=not_logged_in_redirect_url,
                                                                         not_authorized_redirect_url=not_authorized_redirect_url))
        
        new_fixtures.extend(fixtures[access_object_index + 1:])

        return ActionFactory(*new_fixtures)(path, template, method)