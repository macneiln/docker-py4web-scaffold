from dataclasses import dataclass
from py4web.core import Fixture, HTTP, redirect, URL, REGEX_APPJSON, request
from py4web.utils.auth import Auth
from py4web.utils.factories import ActionFactory
from pydal.tools.tags import Tags
from typing import Literal, Union
import re

class HasAccess(Fixture):

    def __init__(self,
                 *, 
                 auth: Auth,
                 all_roles: Tags,
                 allowed_roles: Union[str, list, None] = None,
                 has_all_roles: bool = False,
                 all_permissions: Union[Tags, None] = None,
                 allowed_permissions: Union[str, list, None] = None,
                 has_all_permissions: bool = False,
                 not_logged_in_redirect_url = None,
                 not_authorized_redirect_url = None,):

        self.__prerequisites__ = [auth]
        self.auth = auth

        assert isinstance(all_roles, Tags), "Invalid type provided for all_roles object."
        self.all_roles = all_roles

        assert (all_permissions is None) or isinstance(all_permissions, Tags), "Invalid type provided for all_permissions object."
        self.all_permissions = all_permissions
        
        self.not_logged_in_redirect_url = not_logged_in_redirect_url
        self.not_authorized_redirect_url = not_authorized_redirect_url

        if allowed_roles is None:
            allowed_roles = []

        if allowed_permissions is None:
            allowed_permissions = []

        assert isinstance(allowed_roles, (str, list)), "Invalid type provided for allowed_roles parameter."
        self.allowed_roles = allowed_roles if isinstance(allowed_roles, list) else [allowed_roles]

        assert isinstance(allowed_permissions, (str, list)), "Invalid type provided for allowed_permissions parameter."
        self.allowed_permissions = allowed_permissions if isinstance(allowed_permissions, list) else [allowed_permissions]

        assert isinstance(has_all_roles, bool), "Invalid type provided for has_all_groups parameter."
        self.has_all_roles = has_all_roles

        assert isinstance(has_all_permissions, bool), "Invalid type provided for has_all_permissions parameter."
        self.has_all_permissions = has_all_permissions

    def on_request(self, context):
        
        # Auth and DB objects
        auth = self.auth
        db = auth.db
        
        # Roles
        all_roles = self.all_roles
        allowed_roles = self.allowed_roles
        has_all_roles = self.has_all_roles

        # Permissions
        all_permissions = self.all_permissions
        allowed_permissions = self.allowed_permissions
        has_all_permissions = self.has_all_permissions
        
        # No access redirects
        not_logged_in_redirect_url = self.not_logged_in_redirect_url
        not_authorized_redirect_url = self.not_authorized_redirect_url

        user_id = auth.get_user().get('id', None)
        
        if not user_id:
            if not_logged_in_redirect_url:
                if callable(not_logged_in_redirect_url):
                    not_logged_in_redirect_url()
                redirect(URL(not_logged_in_redirect_url))
            raise HTTP(401)

        if not (allowed_roles or allowed_permissions):
            # Exit if there is a user but no specific role or permission restrictions.
            return
        
        if allowed_roles:
            mode = "and" if has_all_roles else "or"
            query = (db.auth_user.id == user_id) & (all_roles.find(allowed_roles, mode))   

        else:
            assert all_permissions, "The all_permissions object must be provided during class instantiation to be used."
            mode = "and" if has_all_permissions else "or"
            query = (all_roles.tag_table.record_id == user_id) & (db.auth_role.name == all_roles.tag_table.tagpath) & (all_permissions.find(allowed_permissions, mode)) 
          
        user_authorized = not db(query).isempty()
        
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
    all_roles: Tags
    all_permissions: Union[Tags, None] = None
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
                                         

    def __call__(self, 
                 *,
                 allowed_roles: Union[str, list, None] = None,
                 has_all_roles: bool = False,
                 allowed_permissions: Union[str, list, None] = None,
                 has_all_permissions: bool = False,
                 not_logged_in_redirect_url: REDIRECT_URL_OPTIONS = True,
                 not_authorized_redirect_url: REDIRECT_URL_OPTIONS = True,) -> HasAccess:

        not_logged_in_redirect_url = self.get_url_or_default(current_url=not_logged_in_redirect_url,
                                                             default_url=self.class_default_not_logged_in_redirect_url,
                                                             default_function=self.not_logged_in_default)
        
        not_authorized_redirect_url = self.get_url_or_default(current_url=not_authorized_redirect_url,
                                                              default_url=self.class_default_not_authorized_redirect_url,
                                                              default_function=self.not_authorized_default)

        return HasAccess(auth=self.auth,
                         all_roles=self.all_roles,
                         allowed_roles=allowed_roles,
                         has_all_roles=has_all_roles,
                         all_permissions=self.all_permissions,
                         allowed_permissions=allowed_permissions,
                         has_all_permissions=has_all_permissions,
                         not_logged_in_redirect_url=not_logged_in_redirect_url,
                         not_authorized_redirect_url=not_authorized_redirect_url,)

    
class AuthenticatedWithAccess:

    def __init__(self, 
                 *fixtures):
        
        found = False
        
        fixtures = list(fixtures)

        for index, item in enumerate(fixtures):
            if isinstance(item, CheckAccess):
                found = True
                self.access_object_index = index

        assert found, "CheckAccess Fixture must be provided."

        self.fixtures = fixtures

        
    def __call__(self,
                 path: Union[str, None] = None, 
                 *,
                 allowed_roles: Union[str, list] = None,
                 allowed_permissions: Union[str, list] = None,
                 template: Union[str, None] = None,
                 method: Union[Literal["GET", "POST", "PUT", "HEAD", "DELETE"], None] = None, 
                 has_all_roles: bool = False,
                 has_all_permissions: bool = False,
                 not_logged_in_redirect_url: REDIRECT_URL_OPTIONS = True,
                 not_authorized_redirect_url: REDIRECT_URL_OPTIONS = True,):
        
        fixtures = self.fixtures
        access_object_index  = self.access_object_index 

        new_fixtures = fixtures[:access_object_index]

        new_fixtures.append(fixtures[access_object_index](allowed_roles=allowed_roles,
                                                          allowed_permissions=allowed_permissions,
                                                          has_all_roles=has_all_roles,
                                                          has_all_permissions=has_all_permissions,
                                                          not_logged_in_redirect_url=not_logged_in_redirect_url,
                                                          not_authorized_redirect_url=not_authorized_redirect_url))
        
        new_fixtures.extend(fixtures[access_object_index + 1:])

        params = {k: v for k, v in dict(path=path, 
                                        template=template, 
                                        method=method,).items() if v is not None}

        return ActionFactory(*new_fixtures)(**params)