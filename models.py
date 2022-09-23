"""
This file defines the database models
"""
from .common import db, dbUploads
from py4web import Field
from pydal.validators import *

# Define your tables below:
db.define_table('upload_testing',
                Field('upload_description', 
                      label='Upload description:', 
                      requires=[IS_NOT_EMPTY()]),
                Field('upload',
                      type='upload',
                      label='Select an upload:',
                      required=True))


# Create the generic uploads table.
dbUploads.create_uploads_table()

# Should be at the end of your table definitions so it can correct all defined upload fields.
dbUploads.correct_upload_fields()

# always commit your models to avoid problems later
db.commit()