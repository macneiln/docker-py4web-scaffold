from py4web.core import Fixture, HTTP, redirect, URL, REGEX_APPJSON, request
from py4web.utils.auth import Auth
from py4web.utils.factories import ActionFactory
from py4web import Field, DAL
from pydal.tools.tags import IS_NOT_IN_DB, IS_NOT_EMPTY, IS_IN_DB
from pydal.objects import Table
from typing import Callable, Literal, Union, List 
from pydal.validators import Validator, ValidationError
import re

class TAG_FORMAT(Validator):

    @staticmethod
    def formatted_tag(value: str) -> str:
        
        value = value.replace(" ", "").replace("\\", "/").strip("/").lower()

        if not value:
            return value

        return f'/{value}/'

    def validate(self, value, record_id=None):
        formatted_tag = TAG_FORMAT.formatted_tag(value)

        if not formatted_tag:
            raise ValidationError('Enter a value')

        return formatted_tag

class AccessManager():

    def __init__(self, 
                 *,
                 auth_fixture: Auth) -> None:
        self.auth_fixture = auth_fixture         
        self.db: DAL  = self.auth_fixture.db
        self.auth_user: Table = self.db.auth_user
        self.setup_access_tables()

    def setup_access_tables(self):

        db = self.db
        auth_user_table: str = self.auth_user._tablename
        auth_roles_table = 'auth_roles'
        auth_permissions_table = 'auth_permissions'
        auth_user_to_role_table = 'auth_user_to_role'
        auth_role_to_permission_table = 'auth_role_to_permission'

        if auth_roles_table not in db.tables:

            db.define_table(auth_roles_table, 
                            Field('role_name', 
                                  label='Role Name',
                                  requires=[TAG_FORMAT(), 
                                            IS_NOT_IN_DB(db, f'{auth_roles_table}.role_name')],
                                  unique=True,
                                  filter_in=lambda value: TAG_FORMAT.formatted_tag(value),),
                            Field('description'),
                            format=lambda record: f'{record.id} - Role: {record.role_name}, Description: {record.description}')
            

        if auth_permissions_table not in db.tables:
            db.define_table(auth_permissions_table, 
                            Field('permission_name', 
                                  label='Permission Name',
                                  requires=[TAG_FORMAT(), 
                                            IS_NOT_IN_DB(db, f'{auth_permissions_table}.permission_name')],
                                  unique=True,
                                  filter_in=lambda value: TAG_FORMAT.formatted_tag(value),),
                            Field('description'),
                            format=lambda record: f'{record.id} - Permission: {record.permission_name}, Description: {record.description}')
            

        if auth_user_to_role_table not in db.tables:
            db.define_table(auth_user_to_role_table, 
                            Field('user_id',
                                  type=f'reference {auth_user_table}',
                                  requires=[IS_NOT_EMPTY(), IS_IN_DB(db, f'{auth_user_table}.id')],
                                  label='User'),
                            Field('role_id',
                                  type=f'reference {auth_roles_table}' ,
                                  requires=[IS_NOT_EMPTY(), IS_IN_DB(db, f'{auth_roles_table}.id')],
                                  label='Role'),
                            Field('description'),
                            format=lambda record: f'{record.id} - User: {record.user}, Role: {record.role} - {record.description}')


        if auth_role_to_permission_table not in db.tables:
            db.define_table(auth_role_to_permission_table, 
                            Field('role_id', 
                                type=f'reference {auth_roles_table}',
                                requires=[IS_NOT_EMPTY(), IS_IN_DB(db, f'{auth_roles_table}.id')],
                                label='Role',),
                            Field('permission_id', 
                                type=f'reference {auth_permissions_table}',
                                requires=[IS_NOT_EMPTY(), IS_IN_DB(db, f'{auth_permissions_table}.id')],
                                label='Permission',),
                            Field('description'),
                            format=lambda record: f'{record.id} - Role: {record.role}, Permission: {record.permission}, Description: {record.description}')
        
        db.commit()
        
        self.auth_roles = db.auth_roles
        self.auth_permissions = db.auth_permissions
        self.auth_user_to_role = db.auth_user_to_role
        self.auth_role_to_permission = db.auth_role_to_permission         


    def _remove(self, query):
        return self.db(query).delete()

    def _add(self, table, **kwargs):
        return table.validate_and_insert(**kwargs)

    def add_role(self, 
                 *,
                 role_name: str,
                 description: str = ''):
        return self._add(table=self.auth_roles, role_name=role_name, description=description)
    
    def remove_role(self, 
                    *, 
                    role_name: str):
        query=(self.auth_roles.role_name == TAG_FORMAT.formatted_tag(role_name))
        return self._remove(query)

    def add_permission(self, 
                       *,
                       permission_name: str, 
                       description: str = ''):
        return self._add(table=self.auth_permissions, permission_name=permission_name, description=description)
    
    def remove_permission(self, 
                          *,
                          permission_name: str):
        query=(self.auth_permissions.permission_name == TAG_FORMAT.formatted_tag(permission_name))
        return self._remove(query)

    def add_role_to_user(self, 
                         *,
                         user_id: int, 
                         role_id: int,
                         description: str = ''):
        return self._add(table=self.auth_user_to_role, user_id=user_id, role_id=role_id, description=description)

    def remove_role_from_user(self, 
                              *, 
                              user_id: int,
                              role_id: int):
        query = (self.auth_user_to_role.user_id == user_id) & (self.auth_user_to_role.role_id == role_id)
        return self._remove(query)

    def add_permission_to_role(self, 
                               *, 
                               role_id: int,
                               permission_id: int,
                               description: str = ''):
        return self._add(table=self.auth_role_to_permission, role_id=role_id, permission_id=permission_id, description=description)

    def remove_permission_from_role(self, 
                                    *, 
                                    role_id: int,
                                    permission_id: int):
        query = (self.auth_role_to_permission.role_id == role_id) & (self.auth_role_to_permission.permission_id == permission_id)
        return self._remove(query)

    def get_user_roles(self, user_id):
        raise NotImplementedError()

    def get_user_permissions(self, user_id):
        raise NotImplementedError()

    def user_has_role(self, role_name: str, user_id: int) -> bool:
        auth_roles = self.auth_roles
        auth_user_to_role = self.auth_user_to_role

        query = (auth_user_to_role.user_id == user_id) & \
                (auth_user_to_role.role_id == auth_roles.id) & \
                (auth_roles.role_name.startswith(TAG_FORMAT.formatted_tag(role_name)))
        
        has_role = not self.db(query).isempty()
        return has_role
        
    def user_has_permission(self, permission_name: str, user_id: int) -> bool:
        auth_user_to_role = self.auth_user_to_role
        auth_role_to_permission = self.auth_role_to_permission
        auth_permissions = self.auth_permissions

        query = (auth_user_to_role.user_id == user_id) & \
                (auth_user_to_role.role_id == auth_role_to_permission.role_id) & \
                (auth_role_to_permission.permission_id == auth_permissions.id) & \
                (auth_permissions.permission_name.startswith(TAG_FORMAT.formatted_tag(permission_name)))
        
        has_role = not self.db(query).isempty()
        return has_role


class AuthAccess(Fixture):

    def __init__(self, 
                 *,
                 auth_fixture: Auth,
                 access_function: Callable,
                 access_list: Union[str, List[str], None] = None, 
                 validity_function: Union[any, all] = any):

        self.auth_fixture = auth_fixture
        self.__prerequisites__ = [auth_fixture]

        if not access_list:
            self.access_list = []
        
        elif isinstance(access_list, str):
            self.access_list = [access_list]
        
        else:
            self.access_list = access_list

        assert isinstance(self.access_list, (str, list)), "Invalid access list provided."

        self.access_function = access_function
        self.validity_function = validity_function

    def ajax_request(self):
        return re.search(REGEX_APPJSON, request.headers.get("accept", ""))            

    def perform_redirect(self, page, auth_route=None, vars=None, message=None):
        parts = []
        if auth_route:
            parts.append(auth_route)
        parts.append(page)

        redirect(URL(*parts,
                     vars=vars,
                     use_appname=self.auth_fixture.param.use_appname_in_redirects,))


    def login_redirect(self, login_page="login", message="User not logged in"):
        # Return HTTP 401 if ajax request otherwise redirect to page.
        if self.ajax_request():
            raise HTTP(401)
            
        redirect_next = request.fullpath
        if request.query_string:
            redirect_next = f"{redirect_next}?{request.query_string}"
        vars=dict(next=redirect_next)

        self.perform_redirect(page=login_page, 
                              vars=vars, 
                              auth_route=self.auth_fixture.route,
                              message=message)

    def unauthorized_redirect(self, not_authorized_page="not-authorized", message="User not authorized"):
        # Return HTTP 403 if ajax request otherwise redirect to page.
        if self.ajax_request():
            raise HTTP(403)

        self.perform_redirect(page=not_authorized_page, 
                              message=message)

    def on_request(self, context):

        user_id = self.auth_fixture.get_user().get('id', None)

        if not user_id:
            self.login_redirect()

        if not self.access_list:
            # Exit if the user is logged in and there are no access restrictions.
            return

        user_authorized = self.validity_function((self.access_function(access_item, user_id) for access_item in self.access_list))
        
        if not user_authorized:
            self.unauthorized_redirect()



class CheckAccess:

    def __init__(self,
                 accessManager: AccessManager): 
        
        self.accessManager = accessManager

    def __call__(self, 
                 *,
                 access_list: Union[str, List[str], None] = None, 
                 access_type: Literal['role', 'permission'] = 'role',
                 validity_function: Union[any, all] = any) -> AuthAccess:

        if access_type == 'role':
            access_function = self.accessManager.user_has_role

        elif access_type == 'permission':
            access_function = self.accessManager.user_has_permission

        else:
            raise NotImplementedError()

        return AuthAccess(auth_fixture=self.accessManager.auth_fixture,
                          access_list=access_list,
                          access_function=access_function,
                          validity_function=validity_function)


class AuthenticatedWithAccess:

    def __init__(self,
                 path, 
                 *fixtures):
        
        self.path = path
        found = False
        
        fixtures = list(fixtures)

        for index, item in enumerate(fixtures):
            if isinstance(item, CheckAccess):
                found = True
                self.access_object_index = index
                break

        assert found, "CheckAccess Fixture must be provided."

        self.fixtures = fixtures
        
    def __call__(self,
                 path: Union[str, None] = None, 
                 *,
                 access_list: Union[str, List[str], None] = None, 
                 access_type: Literal['role', 'permission'] = 'role',
                 validity_function: Union[any, all] = any,
                 template: Union[str, None] = None,
                 method: Union[Literal["GET", "POST", "PUT", "HEAD", "DELETE"], None] = None):
        
        fixtures = self.fixtures
        access_object_index = self.access_object_index 

        new_fixtures = fixtures[:access_object_index]

        check_access: CheckAccess = fixtures[access_object_index]

        new_fixtures.append(check_access(access_list=access_list,
                                         access_type=access_type,
                                         validity_function=validity_function))
        
        new_fixtures.extend(fixtures[access_object_index + 1:])

        params = {k: v for k, v in dict(path=path, 
                                        template=template, 
                                        method=method,).items() if v is not None}
        
        return ActionFactory(*new_fixtures)(**params)