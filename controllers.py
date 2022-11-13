"""
This file defines actions, i.e. functions the URLs are mapped into
The @action(path) decorator exposed the function at URL:

    http://127.0.0.1:8000/{app_name}/{path}

If app_name == '_default' then simply

    http://127.0.0.1:8000/{path}

If path == 'index' it can be omitted:

    http://127.0.0.1:8000/

The path follows the bottlepy syntax.

@action.uses('generic.html')  indicates that the action uses the generic.html template
@action.uses(session)         indicates that the action uses the session
@action.uses(db)              indicates that the action uses the db
@action.uses(T)               indicates that the action uses the i18n & pluralization
@action.uses(auth.user)       indicates that the action requires a logged in user
@action.uses(auth)            indicates that the action requires the auth object

session, db, T, auth, and tempates are examples of Fixtures.
Warning: Fixtures MUST be declared with @action.uses({fixtures}) else your app will result in undefined behavior
"""

from py4web import action, request, abort, redirect, URL
from py4web.utils.form import Form
from yatl.helpers import A
import mimetypes
from .common import db, \
                    session, \
                    T, \
                    cache,\
                    auth, \
                    logger, \
                    authenticated, \
                    unauthenticated, \
                    flash, \
                    dbUploads


#=======================================================
# In DB upload examples:
#=======================================================
@action("index", method=['GET', 'POST'])
@action.uses("index.html", auth, T)
def index():
    form=Form(db.upload_testing)
    rows = db(db.upload_testing.upload).select()
    for row in rows:
        upload_id = dbUploads.decode(row.upload)
        row['filename'] = db.uploads[upload_id]['filename']
        row['mimetype'] = mimetypes.guess_type(row['filename'])[0]

    return dict(form=form, rows=rows)


#=======================================================
# Default not authorized path.
#=======================================================
@action('not-authorized', method=['GET'])
def notAuthorized():
    return dict()