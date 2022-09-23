import os,  mimetypes, time
from io import BytesIO
from pydal._compat import to_bytes
from pydal import Field
from hashids import Hashids
from . import settings
from py4web import request
import email.utils
from ombott.response import HTTPResponse, HTTPError
from ombott.common_helpers import parse_date
from ombott.static_stream import _file_iter_range, get_first_range
import brotli, gzip

class DBFileStorage():

    def __init__(self, 
                 db, 
                 table_name='uploads',
                 salt=settings.SESSION_SECRET_KEY,
                 min_hash_length = 50,
                 file_encoding = 'br'):

        self.db = db
        self.table_name = table_name
        
        # For hashing to encode/decide IDs (only integers) https://pypi.org/project/hashids/
        self.hashids = Hashids(salt=salt, min_length=min_hash_length)
        
        # Defines compression before saving in database. Options 'br', 'gzip', None.
        assert file_encoding in (None, 'br', 'gzip')    
        self.file_encoding = file_encoding 

    ################################################################################################
    # Custom Store in DB File Upload function.
    ################################################################################################
    def custom_store_db(self, file, filename):
        
        if not file:
            return "" # Nothing to store.

        filestats = os.fstat(file.fileno())

        content = file.read()

        filesizecompressed = None

        if self.file_encoding == 'br':
            content = brotli.compress(content)            
            filesizecompressed = len(content)

        elif self.file_encoding == 'gzip':
            content = gzip.compress(content)
            filesizecompressed = len(content)

        keys = dict(filename=filename,
                    content=content,
                    fileencoding=self.file_encoding,
                    filesize=filestats.st_size,
                    filesizecompressed=filesizecompressed,
                    filemodified=filestats.st_mtime,)

        id = self.db[self.table_name].insert(**keys)
        return f"{id}" # return value as string.
    ################################################################################################


    ################################################################################################
    # Custom Retrieve in DB File Upload function.
    ################################################################################################
    def custom_retrieve_db(self, upload_id: str):

        if (not upload_id) or (not upload_id.isdigit()):
            return (None, None)
        
        record = self.db[self.table_name][int(upload_id)]
        filestream = BytesIO(to_bytes(record.content or ""))
        return (record, filestream)
    ################################################################################################


    ################################################################################################
    # Custom Filter Out from DB upload function.
    ################################################################################################
    def custom_filter_out_upload(self, upload_id: str):

        if (not upload_id) or (not upload_id.isdigit()):            
            return upload_id
            
        return self.hashids.encode(int(upload_id))

    ################################################################################################


    ################################################################################################
    # Function to iterate all DB tables and setup the in
    # DB upload functionality.
    ################################################################################################
    def correct_upload_fields(self):
        for current_table_name in self.db.tables:
            table = self.db[current_table_name]
            for field_name in table.fields():
                field = table[field_name]
                if field.type == 'upload':
                    field.custom_retrieve=lambda upload_id, _:  self.custom_retrieve_db(upload_id=upload_id)
                    field.custom_store=lambda file, filename, _: self.custom_store_db(file=file, filename=filename)
                    field.filter_out=lambda upload_id: self.custom_filter_out_upload(upload_id)
    ################################################################################################


    ################################################################################################
    # Generic DB upload download function.
    ################################################################################################
    def db_download(self, encoded_id, charset='UTF-8'):
        id = self.hashids.decode(encoded_id)[0]
        record = self.db[self.table_name][id]
        attachment =  request.query.get("attachment", None)
        return self.static_file_db(record=record, attachment=attachment, charset=charset)
    ################################################################################################


    ################################################################################################
    # Generic upload table for usage.
    ################################################################################################
    def create_uploads_table(self):
        self.db.define_table(self.table_name,
                             Field('id', type='big-id'),
                             Field('filename', 'string', required=True),
                             Field('fileencoding', 'string', required=False),
                             Field('content', 'blob', required=True),
                             Field('filesize', 'bigint', required=True),
                             Field('filesizecompressed', 'bigint', required=False),
                             Field('filemodified', 'double', required=True),)
    ################################################################################################


    ################################################################################################
    # Pulled from bottle static_file function and 
    # updated to handle static files from the database.
    ################################################################################################
    def static_file_db(self, record, attachment, charset='UTF-8'):
        """ Open a file in a safe way and return :exc:`HTTPResponse` with status
            code 200, 305, 403 or 404. The ``Content-Type``, ``Content-Encoding``,
            ``Content-Length`` and ``Last-Modified`` headers are set if possible.
            Special support for ``If-Modified-Since``, ``Range`` and ``HEAD``
            requests.

            :param filename: Name or path of the file to send.
            :param root: Root path for file lookups. Should be an absolute directory
                path.
            :param mimetype: Defines the content-type header (default: guess from
                file extension)
            :param download: If True, ask the browser to open a `Save as...` dialog
                instead of opening the file with the associated program. You can
                specify a custom filename as a string. If not specified, the
                original filename is used (default: False).
            :param charset: The charset to use for files with a ``text/*``
                mime-type. (default: UTF-8)
        """
        
        headers = dict()
        env_get = request.environ.get

        if not record:
            return HTTPError(404, "File does not exist.")

        mimetype, encoding = mimetypes.guess_type(record.filename)
        
        # Get the accepted encoding response types.
        accepted_encodings = env_get('HTTP_ACCEPT_ENCODING').replace(' ', '').split(',') if env_get('HTTP_ACCEPT_ENCODING') else []

        if (record.fileencoding in('br', 'gzip')) and (record.fileencoding in accepted_encodings):            
            # Set content enoding if it's supported.
            headers['Content-Encoding'] = self.file_encoding

        elif encoding:
            headers['Content-Encoding'] = encoding

        if mimetype:
            if mimetype.startswith('text/') and charset and 'charset' not in mimetype:
                mimetype += f'; charset={charset}'
            headers['Content-Type'] = mimetype

        if attachment:
            headers['Content-Disposition'] = f'attachment; filename="{record.filename}"'

        if (not record.fileencoding) or (record.fileencoding not in accepted_encodings):
            filesize = record.filesize
        else:
            filesize = record.filesizecompressed 

        headers['Content-Length'] = clen = filesize

        headers['Last-Modified'] = email.utils.formatdate(record.filemodified, usegmt=True)

        ims = env_get('HTTP_IF_MODIFIED_SINCE')
        if ims:
            ims = parse_date(ims.split(";")[0].strip())
        if ims is not None and ims >= int(record.filemodified):
            headers['Date'] = email.utils.formatdate(time.time(), usegmt=True)
            return HTTPResponse(status=304, **headers)
        
        if request.method == 'HEAD':
            body = ''             
        else:
            body = to_bytes(record.content or "")

            if (record.fileencoding == 'br') and (record.fileencoding not in accepted_encodings):
                # Remove decompression if not accepted.
                body = brotli.decompress(body)

            elif (record.fileencoding == 'gzip') and (record.fileencoding not in accepted_encodings):
                # Remove decompression if not accepted.
                body = gzip.decompress(body)

            body = BytesIO(body)        

        headers["Accept-Ranges"] = "bytes"
        range_header = env_get('HTTP_RANGE')
        if range_header:
            first_range = get_first_range(range_header, clen)
            if not first_range:
                return HTTPError(416, "Requested Range Not Satisfiable")
            offset, end = first_range
            headers["Content-Range"] = f"bytes {offset}-{end-1}/{clen}"
            headers["Content-Length"] = f"{end - offset}"
            if body:
                body =  _file_iter_range(body, offset, end - offset)
            return HTTPResponse(body, status=206, **headers)
        return HTTPResponse(body, **headers)
    ################################################################################################
