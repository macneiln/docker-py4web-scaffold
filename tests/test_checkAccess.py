from contextlib import nullcontext as does_not_raise
from dataclasses import dataclass
from typing import List, Union
import itertools

import pytest
from py4web import action
from py4web.core import bottle
from pydal.validators import ValidationError

from ..common import (accessManager, auth, auth_access, authenticated, db)
from ..utils.checkAccess import TAG_FORMAT
from .conftest import RequestTest, TestUser


@pytest.mark.parametrize(argnames = 'value, expected, description', 
                         argvalues = [('/value/', '/value/', 'Test standard.'), 
                                      ('//', '', 'Test forward slashes.'),
                                      ('/\\ \\/', '', 'Test only slashes.'),
                                      ('/\\/\\', '', 'Test only slashes 2.'),
                                      ('\\ value/', '/value/', 'Test backslash replacement.'),
                                      (' value ', '/value/', 'Test whitespace.'),
                                      ('some/value/blah', '/some/value/blah/', 'Test standard hierarchy.'),
                                      ('some\\value\\blah', '/some/value/blah/', 'Test backslash replacement hierarchy.'),])
def test_tag_validator_format(value, expected, description):
    print(description)
    assert TAG_FORMAT.formatted_tag(value) == expected

@pytest.mark.parametrize(argnames = 'value, expected, raises, description', 
                         argvalues = [('/value/', '/value/', does_not_raise(), 'Test standard.'), 
                                      ('   value ', '/value/', does_not_raise(), 'Test removing whitespace.'), 
                                      ('//', None, pytest.raises(ValidationError), 'Test removing forward slashes.'),
                                      (' ', None, pytest.raises(ValidationError), 'Test blank.'),])
def test_tag_validator_validate(value, expected, raises, description):
    print(description)    
    with raises:
        formatted = TAG_FORMAT().validate(value)
        assert formatted == expected


# Using new fixture directly.
@action('teachers-only-1')
@action.uses(auth, auth_access(access_list=['teacher'], access_type='role'))

# Using decorator.
@authenticated('teachers-only-2', access_list=['teacher'], access_type='role')

@authenticated('highschool-teachers-only', access_list=['teacher/highschool'], access_type='role')

# Must have one of the roles.
@authenticated('any-professions', access_list=['teacher', 'lawyer', 'doctor'], access_type='role')

# Must have all of the roles.
@authenticated('all-professions', access_list=['teacher', 'lawyer', 'doctor'], access_type='role', validity_function=all)

# Only authenticated but no specific role restrictions.
@authenticated('anyone-logged-in')

# Must have view permissions.
@authenticated('view-permissions', access_list=['view'], access_type='permission')

# Must have view and edit permissions.
@authenticated('view-and-edit-permissions', access_list=['view', 'edit'], access_type='permission', validity_function=all)

def restricted_function():
    return bottle.HTTPResponse(status=200)


@dataclass
class Role:
    value: str
    description = 'default description'
    column = 'role_name'
    table = accessManager.auth_roles

    def get_formatted_value(self):
        return TAG_FORMAT.formatted_tag(self.value)

@dataclass
class Permission(Role):
    column = 'permission_name'
    table=accessManager.auth_permissions

@dataclass
class AddRole(Role):
    item_function = accessManager.add_role

@dataclass
class RemoveRole(Role):
    item_function = accessManager.remove_role

@dataclass
class AddPermission(Permission):
    item_function = accessManager.add_permission

@dataclass
class RemovePermission(Permission):
    item_function = accessManager.remove_permission

@dataclass
class RoleToUser:
    role: Role
    user: TestUser
    description = 'default description'
    table = accessManager.auth_user_to_role

@dataclass
class AddRoleToUser(RoleToUser):
    item_function = accessManager.add_role_to_user

@dataclass
class RemoveRoleFromUser(RoleToUser):
    item_function = accessManager.remove_role_from_user

@dataclass
class PermissionToRole:
    permission: Permission
    role: Role
    description = 'default description'
    table = accessManager.auth_role_to_permission

@dataclass
class AddPermissionToRole(PermissionToRole):
    item_function = accessManager.add_permission_to_role

@dataclass
class RemovePermissionFromRole(PermissionToRole):
    item_function = accessManager.remove_permission_from_role

@dataclass
class PermissionCheck:
    permission: Permission
    user: TestUser
    item_function = accessManager.user_has_permission

@dataclass
class RoleCheck:
    role: Role
    user: TestUser
    item_function = accessManager.user_has_role

def base_access_setup(*args):

    return list(itertools.chain([AddRole('teacher'),
                                 AddRole('teacher/highschool'),
                                 AddRole('doctor'),
                                 AddRole('lawyer'),
                                 AddRole('mechanic'),

                                 AddPermission('view'),
                                 AddPermission('edit'),

                                 AddPermissionToRole(Permission('view'), Role('lawyer')),
                                 AddPermissionToRole(Permission('edit'), Role('lawyer')),
                                 AddPermissionToRole(Permission('edit'), Role('mechanic')),

                                 TestUser('John', 'Smith'),
                                 TestUser('Jane', 'Doe'),
                                 TestUser('James', 'Robert'),
                                 TestUser('William', 'Michael'),
                                 TestUser('Richard', 'Charles'),
                                 TestUser('Mark', 'Daniel'),

                                 AddRoleToUser(Role('teacher'), TestUser('John', 'Smith')),    

                                 AddRoleToUser(Role('teacher/highschool'), TestUser('Jane', 'Doe')),

                                 AddRoleToUser(Role('doctor'), TestUser('James', 'Robert')),

                                 AddRoleToUser(Role('lawyer'), TestUser('William', 'Michael')),

                                 AddRoleToUser(Role('mechanic'), TestUser('Richard', 'Charles')),

                                 AddRoleToUser(Role('teacher'), TestUser('Mark', 'Daniel')),

                                 AddRoleToUser(Role('teacher/highschool'), TestUser('Mark', 'Daniel')),
                                 AddRoleToUser(Role('doctor'), TestUser('Mark', 'Daniel')),
                                 AddRoleToUser(Role('lawyer'), TestUser('Mark', 'Daniel')),
                                 AddRoleToUser(Role('mechanic'), TestUser('Mark', 'Daniel')),
                                 AddRoleToUser(Role('mechanic'), TestUser('Mark', 'Daniel')),], list(args)))


@pytest.mark.parametrize(argnames = 'testItems, raises, description', 
                         argvalues = [
    ([AddRole('singer'),
      AddRole('dancer'),], 
      does_not_raise(), 
      'Test adding roles.'),
    
    ([AddRole('singer'),
      AddRole('singer'),], 
      pytest.raises(ValidationError), 
      'Test adding duplicate roles.'),
    
    ([AddRole('singer'),
      AddRole('dancer'),
      RemoveRole('singer')], 
      does_not_raise(), 
      'Test removing a role.'),
    
    ([AddPermission('view_records'),
      AddPermission('edit_records'),], 
      does_not_raise(), 
      'Test adding permissions.'),


    ([AddPermission('view_records'),
      AddPermission('view_records'),], 
      pytest.raises(ValidationError), 
      'Test adding duplicate permissions.'),
    
    ([AddPermission('view_records'),
      AddPermission('edit_records'),
      RemovePermission('view_records'),], 
      does_not_raise(), 
      'Test removing permissions.'),

    ([AddRole('singer'),
      AddRole('dancer'),
      AddPermission('view_records'),
      AddPermission('edit_records'),
      AddPermissionToRole(Permission('edit_records'), Role('dancer'),)], 
      does_not_raise(), 
      'Test adding permission to a role.'),
    
    ([AddRole('singer'),
      AddRole('dancer'),
      AddPermission('view_records'),
      AddPermission('edit_records'),
      AddPermissionToRole(Permission('edit_records'), Role('dancer')),
      RemovePermissionFromRole(Role('dancer'), Permission('edit_records'))], 
      does_not_raise(), 
      'Test removing permissions from a role.'),

    ([AddRole('singer'),
      AddRole('dancer'),
      AddPermission('view_records'),
      AddPermission('edit_records'),
      RemovePermissionFromRole(Permission('edit_records'), Role('dancer'),)], 
      pytest.raises(ValidationError), 
      'Test removing permission from a role where it does not exist.'),

    ([AddRole('singer'),
      AddRole('dancer'),
      TestUser('John', 'Smith'),
      AddRoleToUser(Role('dancer'), TestUser('John', 'Smith'))], 
      does_not_raise(), 
      'Test adding a role to a user.'),

    ([AddRole('singer'),
      AddRole('dancer'),
      TestUser('John', 'Smith'),
      AddRoleToUser(Role('dancer'), TestUser('John', 'Smith')),
      RemoveRoleFromUser(Role('dancer'), TestUser('John', 'Smith'))], 
      does_not_raise(), 
      'Test removing a role from a user.'),

    ([AddRole('singer'),
      AddRole('dancer'),
      TestUser('John', 'Smith'),
      RemoveRoleFromUser(Role('dancer'), TestUser('John', 'Smith'))], 
      pytest.raises(ValidationError), 
      'Test removing a non-existant role from a user.'),

    ([AddRole('singer'),
      AddRole('dancer'),
      TestUser('John', 'Smith'),
      AddRoleToUser(Role('dancer'), TestUser('John', 'Smith')),
      RoleCheck(Role('dancer'), TestUser('John', 'Smith'),)], 
      does_not_raise(), 
      'Test if a user has a role they should.'),

    ([AddRole('singer'),
      AddRole('dancer'),
      TestUser('John', 'Smith'),
      RoleCheck(Role('dancer'), TestUser('John', 'Smith'),)], 
      pytest.raises(AssertionError), 
      'Test if a user has a role they should not.'),
    
    ([AddRole('teacher'),
      AddRole('teacher/highschool'),
      TestUser('John', 'Smith'),
      AddRoleToUser(Role('teacher'), TestUser('John', 'Smith')),
      RoleCheck(Role('teacher/highschool'), TestUser('John', 'Smith'),)], 
      pytest.raises(AssertionError), 
      'Test if a user has hierarchical role they should not.'),
    
    ([AddRole('teacher'),
      AddRole('teacher/highschool'),
      TestUser('John', 'Smith'),
      AddRoleToUser(Role('teacher/highschool'), TestUser('John', 'Smith')),
      RoleCheck(Role('teacher'), TestUser('John', 'Smith'),)], 
      does_not_raise(), 
      'Test if a user has hierarchical role they should.'),

    ([AddRole('singer'),
      AddRole('dancer'),
      AddPermission('view_records'),
      AddPermission('edit_records'),
      AddPermissionToRole(Permission('edit_records'), Role('dancer')),
      TestUser('John', 'Smith'),
      AddRoleToUser(Role('dancer'), TestUser('John', 'Smith')),
      PermissionCheck(Permission('edit_records'), TestUser('John', 'Smith'))], 
      does_not_raise(), 
      'Test if a user has a permission they should.'),

    ([AddRole('singer'),
      AddRole('dancer'),
      AddPermission('view_records'),
      AddPermission('edit_records'),
      AddPermissionToRole(Permission('edit_records'), Role('dancer')),
      TestUser('John', 'Smith'),
      AddRoleToUser(Role('dancer'), TestUser('John', 'Smith')),
      PermissionCheck(Permission('view_records'), TestUser('John', 'Smith'))], 
      pytest.raises(AssertionError), 
      'Test if a user has a permission they should not.'),

    ([AddRole('teacher'),
      AddRole('teacher/highschool'),
      AddPermission('edit'),
      AddPermission('edit/users'),
      AddPermissionToRole(Permission('edit'), Role('teacher')),
      AddPermissionToRole(Permission('edit/users'), Role('teacher/highschool')),
      TestUser('John', 'Smith'),
      TestUser('Jane', 'Doe'),
      AddRoleToUser(Role('teacher'), TestUser('John', 'Smith')),
      AddRoleToUser(Role('teacher/highschool'), TestUser('Jane', 'Doe')),
      PermissionCheck(Permission('edit'), TestUser('John', 'Smith'),),
      PermissionCheck(Permission('edit/users'), TestUser('Jane', 'Doe'),),
      PermissionCheck(Permission('edit'), TestUser('Jane', 'Doe'),),], 
      does_not_raise(), 
      'Test if a user has hierarchical permission they should.'),

    ([AddRole('teacher'),
      AddRole('teacher/highschool'),
      AddPermission('edit'),
      AddPermission('edit/users'),
      AddPermissionToRole(Permission('edit'), Role('teacher')),
      AddPermissionToRole(Permission('edit/users'), Role('teacher/highschool')),
      TestUser('John', 'Smith'),
      TestUser('Jane', 'Doe'),
      AddRoleToUser(Role('teacher'), TestUser('John', 'Smith')),
      AddRoleToUser(Role('teacher/highschool'), TestUser('Jane', 'Doe')),
      PermissionCheck(Permission('edit/users'), TestUser('John', 'Smith'),),], 
      pytest.raises(AssertionError), 
      'Test if a user has hierarchical permission they should not.'),

    (base_access_setup(
        RequestTest('teachers-only-1', 'teachers-only-1', TestUser('John', 'Smith')),
        RequestTest('teachers-only-1', 'teachers-only-1', TestUser('Jane', 'Doe')),
        RequestTest('teachers-only-1', user=TestUser('James', 'Robert'), expected_status=403),
        RequestTest('teachers-only-1', expected_status=401),
     ), does_not_raise(), 
     'Ensure authorization is working using @action with fixture - AJAX.'),

    (base_access_setup(
        RequestTest('teachers-only-1', 'teachers-only-1', TestUser('John', 'Smith'), ajax_request=False),
        RequestTest('teachers-only-1', 'teachers-only-1', TestUser('Jane', 'Doe'), ajax_request=False),
        RequestTest('teachers-only-1', 'not-authorized', TestUser('James', 'Robert'), ajax_request=False),    
        RequestTest('teachers-only-1', '/auth/login?next=/teachers-only-1', ajax_request=False),
       ), does_not_raise(), 
      'Ensure authorization is working using @action with fixture - Standard.'),

    (base_access_setup(
        RequestTest('teachers-only-2', 'teachers-only-2', TestUser('John', 'Smith')),
        RequestTest('teachers-only-2', 'teachers-only-2', TestUser('Jane', 'Doe')),
        RequestTest('teachers-only-2', expected_status=401),      
     ), does_not_raise(), 
     'Ensure authorization is working using convenience decorator - AJAX.'),

    (base_access_setup(
        RequestTest('teachers-only-2', 'teachers-only-2', TestUser('John', 'Smith'), ajax_request=False),
        RequestTest('teachers-only-2', 'teachers-only-2', TestUser('Jane', 'Doe'), ajax_request=False),
        RequestTest('teachers-only-2', 'not-authorized', TestUser('James', 'Robert'), ajax_request=False),
        RequestTest('teachers-only-2', 'not-authorized', TestUser('James', 'Robert'), ajax_request=False),
        RequestTest('teachers-only-2', '/auth/login?next=/teachers-only-2', ajax_request=False),
     ), does_not_raise(), 
     'Ensure authorization is working using convenience decorator - AJAX.'),

    (base_access_setup(
        RequestTest('highschool-teachers-only', 'highschool-teachers-only', TestUser('Jane', 'Doe')),
        RequestTest('highschool-teachers-only', user=TestUser('John', 'Smith'), expected_status=403),
        RequestTest('highschool-teachers-only', user=TestUser('James', 'Robert'), expected_status=403),
        RequestTest('highschool-teachers-only', expected_status=401),
     ), does_not_raise(), 
     'Ensure that hierarchy access is working using convenience decorator - AJAX.'),

    (base_access_setup(
        RequestTest('highschool-teachers-only', 'highschool-teachers-only', TestUser('Jane', 'Doe'), ajax_request=False),
        RequestTest('highschool-teachers-only', 'not-authorized', TestUser('John', 'Smith'), ajax_request=False),
        RequestTest('highschool-teachers-only', 'not-authorized', TestUser('James', 'Robert'), ajax_request=False),
        RequestTest('highschool-teachers-only', '/auth/login?next=/highschool-teachers-only', ajax_request=False),
     ), does_not_raise(), 
     'Ensure that hierarchy access is working using convenience decorator - Standard.'),

    (base_access_setup(
        RequestTest('any-professions', 'any-professions', TestUser('John', 'Smith')),
        RequestTest('any-professions', 'any-professions', TestUser('Jane', 'Doe')),
        RequestTest('any-professions', 'any-professions', TestUser('James', 'Robert')),
        RequestTest('any-professions', 'any-professions', TestUser('William', 'Michael')),
        RequestTest('any-professions', user=TestUser('Richard', 'Charles'), expected_status=403),
        RequestTest('any-professions', expected_status=401),
     ), does_not_raise(), 
     'Ensure that one of any access is working using convenience decorator - AJAX.'),

    (base_access_setup(
        RequestTest('any-professions', 'any-professions', TestUser('John', 'Smith'), ajax_request=False),
        RequestTest('any-professions', 'any-professions', TestUser('Jane', 'Doe'), ajax_request=False),
        RequestTest('any-professions', 'any-professions', TestUser('James', 'Robert'), ajax_request=False),
        RequestTest('any-professions', 'any-professions', TestUser('William', 'Michael'), ajax_request=False),
        RequestTest('any-professions', 'not-authorized', TestUser('Richard', 'Charles'), ajax_request=False),
        RequestTest('any-professions', '/auth/login?next=/any-professions', ajax_request=False),
     ), does_not_raise(), 
     'Ensure that one of any access is working using convenience decorator - Standard.'),
      
    (base_access_setup(
        RequestTest('all-professions', 'all-professions', TestUser('Mark', 'Daniel')),
        RequestTest('all-professions', user=TestUser('John', 'Smith'), expected_status=403),
        RequestTest('all-professions', expected_status=401),
     ), does_not_raise(), 
     'Ensure that all of multiple access types are working using convenience decorator - AJAX.'),

    (base_access_setup(
        RequestTest('all-professions', 'all-professions', TestUser('Mark', 'Daniel'), ajax_request=False),
        RequestTest('all-professions', 'not-authorized', TestUser('John', 'Smith'), ajax_request=False),
        RequestTest('all-professions', '/auth/login?next=/all-professions', ajax_request=False),
     ), does_not_raise(), 
     'Ensure that all of multiple access types are working using convenience decorator - Standard.'),

    (base_access_setup(
        RequestTest('anyone-logged-in', 'anyone-logged-in', TestUser('Mark', 'Daniel')),
        RequestTest('anyone-logged-in', expected_status=401),
     ), does_not_raise(), 
     'Ensure no restrictions are working using convenience decorator - AJAX.'),

    (base_access_setup(
        RequestTest('anyone-logged-in', 'anyone-logged-in', TestUser('Mark', 'Daniel'), ajax_request=False),
        RequestTest('anyone-logged-in', '/auth/login?next=/anyone-logged-in', ajax_request=False),
     ), does_not_raise(), 
     'Ensure no restrictions are working using convenience decorator - Standard.'),
     
    (base_access_setup(
        RequestTest('view-permissions', 'view-permissions', TestUser('William', 'Michael')),
        RequestTest('view-permissions', user=TestUser('James', 'Robert'), expected_status=403),
        RequestTest('view-permissions', expected_status=401),
     ), does_not_raise(), 
     'Ensure permission restrictions are working using convenience decorator - AJAX.'),

    (base_access_setup(
        RequestTest('view-permissions', 'view-permissions', TestUser('William', 'Michael'), ajax_request=False),
        RequestTest('view-permissions', 'not-authorized', TestUser('James', 'Robert'), ajax_request=False),
        RequestTest('view-permissions', '/auth/login?next=/view-permissions', ajax_request=False),
     ), does_not_raise(), 
     'Ensure permission restrictions are working using convenience decorator - Standard.'),

])
def test_access_modifying_functions(initialize_application, testItems: List[Union[AddRole, 
                                                                                  RemoveRole,
                                                                                  AddPermission, 
                                                                                  RemovePermission, 
                                                                                  AddPermissionToRole,
                                                                                  RemovePermissionFromRole,
                                                                                  AddRoleToUser,
                                                                                  RemoveRoleFromUser,
                                                                                  TestUser,
                                                                                  PermissionCheck,
                                                                                  RoleCheck,
                                                                                  RequestTest,]], raises, description):
    
    print(description) # Test description, shown with -s or during failure.
    
    for table in db.tables:
        db[table].truncate()

    test_users = []
    def user_match(searchUser: TestUser) -> Union[TestUser, None]:
        match = [user for user in test_users if (user.first_name == searchUser.first_name) and (user.last_name == searchUser.last_name)] 
        if not match:
            return None
        return match[0]

    with raises:
        for testItem in testItems:            
            
            if isinstance(testItem, (AddRole, AddPermission)):  

                params = {
                    testItem.column: testItem.value,
                    'description': testItem.description
                }
                result = testItem.item_function(**params)
                
                if result.errors:
                    raise ValidationError(message=result.errors)
                
                assert (result.id)
                record = testItem.table[result.id]
                
                for key, value in params.items():
                    if key == testItem.column:
                        assert record[key] == testItem.get_formatted_value()
                    else:
                        assert record[key] == value

            elif isinstance(testItem, (RemoveRole, RemovePermission)):            
                # Check it exists and can be successfully removed.
                item_to_remove = db(testItem.table[testItem.column] == testItem.get_formatted_value()).select().first()
                assert item_to_remove

                total_items_query = db(testItem.table)
                total_items_before = total_items_query.count()

                params = {
                    testItem.column: testItem.value
                }

                result = testItem.item_function(**params)
                assert result
                assert not testItem.table[item_to_remove.get('id')]
                
                # Check other types are unimpacted.
                assert (total_items_before - 1) == total_items_query.count()
            
            elif isinstance(testItem, AddPermissionToRole):   
 
                permission = testItem.permission
                permission_record = db(permission.table[permission.column] == permission.get_formatted_value()).select().first()
                assert permission_record

                role = testItem.role
                role_record = db(role.table[role.column] == role.get_formatted_value()).select().first()
                assert role_record

                total_items_query = db(testItem.table)
                total_items_before = total_items_query.count()

                result = testItem.item_function(role_id=role_record.id, 
                                                permission_id=permission_record.id, 
                                                description=testItem.description)
                
                if result.errors:
                    raise ValidationError(message=result.errors)
                
                assert (result.id)
                record = testItem.table[result.id]

                assert role_record.id == record['role_id']
                assert permission_record.id == record['permission_id']
                assert testItem.description == record['description']

                # Check other types are unimpacted.
                assert (total_items_before + 1) == total_items_query.count()              
            
            elif isinstance(testItem, RemovePermissionFromRole):   
 
                permission = testItem.permission
                permission_record = db(permission.table[permission.column] == permission.get_formatted_value()).select().first()
                assert permission_record

                role = testItem.role
                role_record = db(role.table[role.column] == role.get_formatted_value()).select().first()
                assert role_record

                total_items_query = db(testItem.table)
                total_items_before = total_items_query.count()

                result = testItem.item_function(role_id=role_record.id, 
                                                permission_id=permission_record.id)
                
                if not result:
                    raise ValidationError(message="No result")

                record = testItem.table[result]

                assert (not record)

                # Check other types are unimpacted.
                assert (total_items_before - 1) == total_items_query.count()      
  
            elif isinstance(testItem, AddRoleToUser):
                role = testItem.role                
                role_record = db(role.table[role.column] == role.get_formatted_value()).select().first()

                assert role_record
          
                user = user_match(searchUser=testItem.user)
                assert user

                total_items_query = db(testItem.table)
                total_items_before = total_items_query.count()

                result = testItem.item_function(user_id=user.user_id,
                                                role_id=role_record.id,
                                                description=testItem.description)
                
                if result.errors:
                    raise ValidationError(message=result.errors)
                
                assert (result.id)
                record = testItem.table[result.id]

                assert record
                assert user.user_id == record['user_id']
                assert role_record.id == record['role_id']
                assert testItem.description == record['description']   
                
                # Check other types are unimpacted.
                assert (total_items_before + 1) == total_items_query.count()              
                
            elif isinstance(testItem, RemoveRoleFromUser):
                               
                role = testItem.role                
                role_record = db(role.table[role.column] == role.get_formatted_value()).select().first()

                assert role_record

                user = user_match(searchUser=testItem.user)

                assert user

                total_items_query = db(testItem.table)
                total_items_before = total_items_query.count()

                result = testItem.item_function(user_id=user.user_id,
                                                role_id=role_record.id,)
                
                if not result:
                    raise ValidationError(message="No result")

                record = testItem.table[result]
                assert (not record)
                    
                # Check other types are unimpacted.
                assert (total_items_before - 1) == total_items_query.count()   

            elif isinstance(testItem, TestUser):
                user = testItem
                user.create()
                test_users.append(user)


            elif isinstance(testItem, RoleCheck):
                user = user_match(searchUser=testItem.user)
                assert user

                assert testItem.item_function(role_name=testItem.role.value, user_id=user.user_id)

            elif isinstance(testItem, PermissionCheck):
                user = user_match(searchUser=testItem.user)
                assert user

                assert testItem.item_function(permission_name=testItem.permission.value, user_id=user.user_id)

            elif isinstance(testItem, RequestTest):
                
                session = None

                if testItem.user:
                    user = user_match(searchUser=testItem.user)
                    assert user
                    session = user.session
                
                response = testItem.send(session=session)
                assert response.status_code == testItem.expected_status
                
                if testItem.expected_body:
                    assert response.content == testItem.expected_body
                
                if testItem.response_url:
                    assert response.url.endswith(testItem.response_url)

            else:
                raise NotImplementedError("Unconfigured input class")
