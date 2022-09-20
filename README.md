# Docker py4web Stateless Example

Stateless py4web application setup for Docker development. 

Summary Details:
- Table structure details and uploads are stored in database (pre-setup with PostgreSQL). 
- The uploads are stored in database and looked up efficiently via the upload table primary key (ID). 
- The client is always sent an encoded hashed version of this ID which can be decoded server side to look up the upload directly without additional indexes being added to the new generic "upload" table. 
- Uploads are stored in another table distinct from the primary table requiring an upload field to ensure they are only looked up when required and ensure the primary table doesn't have performance degradation.

## Installation
- Install [docker](https://docs.docker.com/get-docker/).

#### Clone this repo:
```
git clone https://github.com/macneiln/docker-py4web-stateless-example.git
```

#### Building Docker Image:
```
docker-compose -f .\docker-compose.development.yml build
OR
docker-compose -f .\docker-compose.development.yml build --no-cache
```

#### Running Docker Image:
```
docker-compose -f .\docker-compose.development.yml up
```

#### Open In Browser:
```
http://localhost:8000/index
OR
http://127.0.0.1:8000/index
```

#### Implementation Details:
- Core functionality for automatically storing and retrieving uploads from the database (non-filesystem) is implemented within ```db_file_storage.py```.
- Object is created in ```common.py``` and replaces the default download function implementation.
- Object is imported in ```models.py``` to call two object functions, one to create the new generic upload table for usage, and one to iterate through and correct the existing tables that have defined standard pydal "upload" field types to ensure they are stored in database. 
- Auto-correction of all "upload" fields is accomplished via setting standard pydal.Field options "custom_retrieve", "custom_store", and "filter_out".
- Upload/file retrieval is accomplished via an enhanced version of the bottlepy "static_file" functionality to accommodate the file retrieval from database rather than file system. 
 
## Usage:
- Use the standard pydal.Field functionality for "uploads" such as validators, field definition, etc. and the fields will be auto-corrected for you without additional setup (see example declaration/usage in ```models.py```, ```controllers.py```, and ```index.html```.

## License
[MIT](https://choosealicense.com/licenses/mit/)