from flask import current_app
from itsdangerous import URLSafeSerializer,BadSignature
import base64
import shortuuid
import subprocess
import socket
from contextlib import closing
import hashlib
from pathlib import Path

def bytesto(bytes, to, bsize=1024,humanize=False):
    '''bytesto(2345,'mb')'''
    a = {'kb' : 1, 'mb': 2, 'gb' : 3, 'tb' : 4, 'pb' : 5, 'eb' : 6 }
    r = float(bytes)
    for i in range(a[to]):
        r = r / bsize
    if not humanize:
        return(r)
    return "{} {}".format(r,to)

def get_size_of_directory(path):
    root_directory = Path(path)
    sum(f.stat().st_size for f in root_directory.glob('**/*') if f.is_file())

def generate_hash(values):
    if values:
        if not isinstance(values,list):
            values = [values]
    m = hashlib.md5()
    for key in values:
        m.update(key.encode('utf-8'))
    return m.hexdigest()

def get_table_object(table=None):
    if table is None:
        return current_app.models
    return current_app.models.get(table.lower())

def msg_to_json(message="None",result=False,label="warning",**kwargs):
    '''
    .Description --> Return JSON message for the result
    '''
    message = {
        "message":str(message),
        "result":result,
        "type":str(label),
        "id":kwargs.get("id")
    }
    return message

def get_TableSchema(table,column=None,is_date=False,is_int=False,is_str=False,is_json=False,is_bool=False):
    '''
    :Description - Get a tables col names and types Usage - ("table",column="message",is_str=True)
    '''
    data = {}
    for col in table.__table__.columns:
        try: # field type JSON does not have a type attribute
            col_type=str(col.type)
        except:
            col_type="JSON"
        data[col.name] = str(col_type)
    if column is not None:
        splice = data.get(column,None)
        if splice:
            if is_int and "INTEGER" in splice:
                return True
            if is_str and "VARCHAR" in splice:
                return True
            if is_json and "JSON" in splice:
                return True
            if is_bool and "BOOLEAN" in splice:
                return True
            if is_date and "DATETIME" in splice:
                return True
            return False
        raise Exception("Column not found")
    return data

def generate_uuid(length=12):
    id = shortuuid.ShortUUID().random(length=length)
    return id.lower()

def base64_encode(message):
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    return base64_bytes.decode('ascii')

def base64_decode(base64_message):
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    return message_bytes.decode('ascii')

def encode_token(object):
    '''
    {"message":"hello"}
    '''
    auth_s = URLSafeSerializer(current_app.config["SECRET_KEY"])
    token = auth_s.dumps(object)
    return token

def decode_token(token):
    auth_s = URLSafeSerializer(current_app.config["SECRET_KEY"])
    try:
        data = auth_s.loads(token)
    except BadSignature as e:
        current_app.logger.error("Unable to decode received token:{}".format(e))
        return False
    return data

def test_ping(host):
    try:
        command = ['ping', "-c","1","-w2",host]
        return subprocess.call(command,stderr=subprocess.DEVNULL,stdout=subprocess.DEVNULL) == 0
    except:
        return False

def test_port(host):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(1)
            if sock.connect_ex((host, 80)) == 0:
                return True
            else:
                return False
    except:
        return False

def test_up(host):
    if test_port(host):
        return True
    if test_ping(host):
        return True
    return False

