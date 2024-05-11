import requests
from requests import RequestException
from sqlalchemy import inspect
from sqlalchemy.orm import session
from sqlalchemy.exc import IntegrityError
from flask import jsonify, request, current_app
from functools import wraps
from datetime import datetime as dt
import jwt
import os

roles_dict = {
  1: "ADMIN",
  2: "RESEARCH",
  4: "EXTERNAL",
  8: "BILLING",
  10: "BILLING_ADMIN",
  20: "PATIENT_MANAGER",
  40: "OC_ADMIN",
  80: "OC_MANAGER",
  100: "INFUSION_MANAGER",
  200: "INFUSION_INTAKE",
  400: "READ_ONLY",
  800: "UNVERIFIED",
  1000: "PATIENT",
  2000: "BILLING_ERROR",
  4000: "BILLING_ERROR_ADMIN",
  8000: "PROVIDER_MATCH",
  10000: "SCORECARDS",
  20000: "SCORECARDS_ADMIN"
}
  
def decrypt_roles(target_num):    
    target_num = int(target_num)
    def func(num, nums:list=[]):
        if sum(nums) == target_num or nums == None:
            return [roles_dict[int(hex(dec).split('x')[1])] for dec in nums]
        else:
            for r in sorted(roles_dict.keys(), reverse=True):
                r = int(str(r),16)
                if r <= num and num % r == 0:
                  nums.append(r)
                  return func(num-r, nums)
    return func(target_num, [])

def encrypt_role(input):
    try:
        input = int(input)
        return input
    except:
        pass #it's fine to except:pass here i promise
    
    value = 0
    if not isinstance(input, list):
        input = [input]
    for i in input:
        for role in roles_dict.keys():
            if i == roles_dict[role]:
                value += int(f"0x{str(role)}", 16)
    return value

# dynamically adds data into a given db_model
# params -> sess: session, data: dictionary vals of data, db_name: model name
def add_to_db(sess: session, data: dict, db_name):
    new_obj = db_name()
    mapper = inspect(new_obj)
    for column in mapper.attrs:
        for val in data:
            if val == column.key and val != None:
                try:
                    setattr(new_obj, column.key, data[val])
                except:
                    print(
                        "Something went wrong with",
                        val,
                        data[val],
                        "assignment",
                    )
                    return False
    sess.add(new_obj)
    sess.flush()
    return new_obj


# helper class for add_to_db
def get_class_by_tablename(db, tablename: str):
    """Return class reference mapped to table.

    :param tablename: String with name of table.
    :return: Class reference or None.
    """
    for c in db.Model.__subclasses__():
        if hasattr(c, "__tablename__") and c.__tablename__ == tablename:
            return c


# helper class for camel_to_snake
def convert_str_to_snake(s: str) -> str:
    return_snake_string = ""
    for idx, letter in enumerate(s.strip()):
        if idx == 0 and letter.isupper():
            return_snake_string = return_snake_string + letter.lower()
        elif letter.isupper():
            return_snake_string = return_snake_string + "_" + letter.lower()
        else:
            return_snake_string = return_snake_string + letter
    return return_snake_string


# converts dictionary keys from camel case to snake case
def camel_to_snake(data):
    if type(data) == dict:
        snake_dictionary = dict()
        for key in data:
            if type(key) == str and any(ele.isupper() for ele in key):
                new_key = convert_str_to_snake(key)
                snake_dictionary[new_key] = data[key]
            else:
                snake_dictionary[key] = data[key]
        return snake_dictionary
    elif type(data) == str and any(ele.isupper() for ele in data):
        return convert_str_to_snake(data)
    else:
        return data


def retrive(connection, request_data):
    Table = get_class_by_tablename(connection.db, request_data["table"])

    sess = connection.session
    data = sess.query(Table)

    if "filter" in object.keys(request_data):
        filters = request_data["filter"]
        for obj in filters:
            data = switch_compartor(
                convert_str_to_snake(obj["comparotor"]),
                data,
                getattr(Table, obj["column"]),
                obj["value"],
            )
            if "orderBy" in object.keys(request_data):
                data = switch_order(
                    obj["orderBy"], data, data, getattr(Table, obj["column"])
                )

    if "limit" in object.keys(request_data):
        data = data.limit(request_data["limit"])

    if "exists" in object.keys(request_data):
        data = data.first()
        if data:
            return True
        else:
            return False

    return data


def switch_compartor(comparator, data, col, value):
    if comparator == "equal_to":
        data = data.filter(col == value)
    elif comparator == "not_equal_to":
        data = data.filter(col != value)
    elif comparator == "greater_than":
        data = data.filter(col > value)
    elif comparator == "greater_than_equal_to":
        data = data.filter(col >= value)
    elif comparator == "less_than":
        data = data.filter(col < value)
    elif comparator == "less_than_equal_to":
        data = data.filter(col <= value)
    return data


def switch_order(order, data, col):
    if order == "DESC":
        data = data.order_by(col).desc()
    elif order == "ASC":
        data = data.order_by(col).asc()
    return data


# Service Exception is a custom exception wrapper
# TODO: Move out of db_toolkit
class ServiceException(Exception):
    def __init__(
        self,
        title="Internal Server Error",
        message="Oops, an error occured.",
        code=500,
    ):
        self.title = title
        self.message = message
        self.code = code
        super().__init__(self.message)


# Exception handler is a wrapper for routes and returns custom, clean, and filtered error messages
# TODO: Move out of db_toolkit
def exception_handler(isAsync=0, showError=False):
    def wrapper(func):
        @wraps(func)
        def inner_func(*args, **kwargs):
            try:
                if isAsync:
                    return current_app.ensure_sync(func)(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
            except ServiceException as e:
                return (
                    jsonify(
                        {"title": e.title, "message": e.message, "code": e.code}
                    ),
                    e.code,
                )
            except NameError as e:
                print(repr(e))
                print(dir(e))
                return (
                    jsonify(
                        {
                            "title": "Error",
                            "message": "Could not find requested database. If the problem persists, please contact IT@cls.health.",
                            "code": 404,
                        }
                    ),
                    404,
                )
            except TypeError as e:
                print(repr(e))
                print(dir(e))
                return (
                    jsonify(
                        {
                            "title": "Error",
                            "message": "Could not find or process the requested data.",
                            "code": 404,
                        }
                    ),
                    404,
                )
            except IntegrityError as e:
                print(repr(e))
                print(dir(e))
                return (
                    jsonify(
                        {
                            "title": "Error",
                            "message": "Attempted to add a resource that already exists.",
                            "code": 409,
                        }
                    ),
                    409,
                )
            except RequestException as e:
                print(dir(e))
                print(repr(e))
                return (
                    jsonify(
                        {
                            "title": e.response.reason,
                            "message": e.response.text,
                            "code": e.response.status_code,
                        }
                    ),
                    e.response.status_code,
                )
            except Exception as e:
                print(repr(e))
                print(dir(e))
                message = str(e) if showError else "Oops! An internal server error occurred."
                return (
                    jsonify(
                        {
                            "title": "Error",
                            "message": message,
                            "code": 500,
                        }
                    ),
                    500,
                )

        return inner_func

    return wrapper


def find_token(array, substring):
    for i in array:
        if substring in i:
            return i
    return None


def verify_token(payload, csrf_token):
    isValid = "False"

    if payload and csrf_token:
        try:
            data = jwt.decode(
                payload,
                os.environ.get("public_key"),
                ["RS256"],
                options={"verify_exp": True},
            )
        except jwt.exceptions.ExpiredSignatureError:
            return jsonify(
                {
                    "Valid": isValid,
                    "Role": "UNAUTHORIZED",
                    "uid": "UNAUTHORIZED",
                }
            )

        headers = jwt.get_unverified_header(payload)
        if headers["alg"] != "RS256":
            return jsonify(
                {
                    "Valid": isValid,
                    "Role": "UNAUTHORIZED",
                    "uid": "UNAUTHORIZED",
                }
            )
        elif data["csrf"] != csrf_token:
            return jsonify(
                {
                    "Valid": isValid,
                    "Role": "UNAUTHORIZED",
                    "uid": "UNAUTHORIZED",
                }
            )
        else:
            isValid = "True"

    return jsonify({"Valid": isValid, "Role": data["role"], "uid": data["uid"]})


# Wrapper that authorizes based off the given list of authorized roles.
# TODO: Move out of db_toolkit
def auth_required(
    authorized_roles: list = ["ADMIN"], isAsync=0, use_perms=False
):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            try:
                if "Authorization" in request.headers:
                    token = request.headers['Authorization'].split(" ")[1]
                    url = "http://localhost:5000" if "localhost" in request.host_url else request.host_url
                    
                    r = requests.get(f"{url}/auth_api/verify", headers={"Authorization": f'Bearer {token}'})
                    if r.status_code == 498: raise ServiceException("Error", r.json(), r.status_code)
                    csrf_token = r.json()['csrf']
                    access_token = token
                elif 'access_token' in list(request.headers.keys()):
                    access_token = request.headers['access_token']
                    csrf_token = request.headers["X-CSRF-TOKEN"]
                else:
                    access_token = get_cookie_value(request, 'access_cookie')
                    csrf_token = request.headers["X-CSRF-TOKEN"]
            except Exception as e:
                raise ServiceException(
                    "Unauthorized", f"No access token found; {e}", 401
                )
            try:
                response = verify_token(access_token, csrf_token)
            except Exception:
                raise ServiceException(
                    "Unauthorized", "Could not verify token.", 401
                )

            if not response:
                raise ServiceException(
                    "Unauthorized", "Could not verify token.", 401
                )
            if "ADMIN" not in authorized_roles:
                authorized_roles.append("ADMIN")
            roles = (response.get_json()["Role"])
            uid = response.get_json()["uid"]
            if "UNAUTHORIZED" not in roles and "ALL" in authorized_roles:
                for r in roles:
                    authorized_roles.append(r)
            if not isinstance(roles, list):
                roles = [roles]
            if any(r in authorized_roles for r in roles):
                if isAsync and use_perms:
                    return current_app.ensure_sync(fn)(*args, **kwargs, uid=uid)
                elif isAsync and not use_perms:
                    return current_app.ensure_sync(fn)(*args, **kwargs)
                elif not isAsync and use_perms:
                    return fn(*args, **kwargs, uid=uid)
                else:
                    return fn(*args, **kwargs)
            else:
                raise ServiceException(
                    "Unauthorized", "Authorized Personnel Only!", 401
                )

        return decorator

    return wrapper


# write a method to get the access cookie from the request
def get_cookie_value(request, cookie_name):
    try:
        cookies = request.headers["Cookie"]
        cookie_array = cookies.split("; ")
        cookie = find_token(cookie_array, cookie_name + "=")
        cookie_value = cookie.split(cookie_name + "=")[1]
    except Exception:
        return ""
    return cookie_value


# Method to run after api requests to log user usage.
def log_requests(db, response):
    if "cookie" not in request.headers or not get_cookie_value(request, "access_cookie"):
        # if no cookie (anonymous)
        # Anonymous requests are not logged. Trying to do so is not handled behavior.
        # Maybe change; add placeholder data for anonymous users (uid, email, name)
        return response

    # METHOD
    payload = get_cookie_value(request, "access_cookie")
    key = f"{os.environ.get('public_key')}"

    userinfo = jwt.decode(
        payload, key, algorithms="RS256", options={"verify_exp": False}
    )
    # END METHOD

    uid = userinfo["uid"]
    email = userinfo["email"]
    name = userinfo["name"]
    ip_addr = ""
    sent_data = str(request.get_json())
    requested_route = str(request.url_rule)

    if request.environ.get("HTTP_X_FORWARDED_FOR") is None:
        ip_addr = request.environ["REMOTE_ADDR"]
    else:
        ip_addr = request.environ["HTTP_X_FORWARDED_FOR"]  # if behind a proxy

    sess = db.session

    QueryLogs = get_class_by_tablename(db, "QueryLogs")

    query_log = QueryLogs(
        IP_Address=ip_addr,
        UID=uid,
        Email=email,
        Name=name,
        Request_Time=dt.now(),
        Sent_Data=sent_data,
        Requested_Route=requested_route,
    )

    sess.add(query_log)
    sess.commit()

    return response


def decode_cookie(cookie, key):
    payload = cookie.split("; ")[0]
    payload = payload.split("access_cookie=")[1]

    decoded_cookie = jwt.decode(
        payload, key, algorithms="RS256", options={"verify_exp": False}
    )

    return decoded_cookie


def delete(connection, request_data):
    Table = get_class_by_tablename(request_data["table"])
    sess = connection.session
    data = sess.query(Table)
    for id in request_data["data"]:
        obj = data.filter(
            getattr(Table, request_data["deleteKey"]) == id
        ).first()
        if obj:
            sess.delete(obj)
            sess.commit()
        else:
            return jsonify("User does not exist"), 422
    return jsonify("Success"), 200


def edit(connection, request_data):
    sess = connection.session
    Table = get_class_by_tablename(request_data["table"])
    for obj in request_data["data"]:
        data = (
            sess.query(Table)
            .filter(getattr(Table, obj["editKey"]) == obj["editValue"])
            .first()
        )
        setattr(data, obj["column"], obj["value"])
    sess.commit()
    return jsonify("Success"), 200
