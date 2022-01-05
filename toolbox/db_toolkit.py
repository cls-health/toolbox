from sqlalchemy import inspect
from sqlalchemy.orm import session
from sqlalchemy.exc import IntegrityError
from flask import Flask, jsonify, request
from functools import wraps
import requests
import platform


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
                    print("Something went wrong with",
                        val,
                        data[val],
                        "assignment")
                    return False
    sess.add(new_obj) 
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
        return (convert_str_to_snake(data))
    else:
        return data

def retrive(connection, request_data):
    Table = get_class_by_tablename(connection.db, request_data['table'])

    sess = connection.session
    data=sess.query(Table)

    if 'filter' in object.keys(request_data):
        filters = request_data['filter']
        for obj in filters:
            data = switch_compartor(convert_str_to_snake(obj['comparotor']), data,getattr(Table, obj['column']),obj['value'])
            if 'orderBy' in object.keys(request_data):
                data = switch_order(obj['orderBy'], data, data,getattr(Table, obj['column']))

    if 'limit' in object.keys(request_data):
        data = data.limit(request_data['limit'])
        
    if 'exists' in object.keys(request_data):
        data = data.first()
        if data: return True
        else: return False
    
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
    def __init__(self, title="Internal Server Error", message="Oops, an error occured.", code=500):
        self.title = title
        self.message = message
        self.code = code
        super().__init__(self.message)   

# Exception handler is a wrapper for routes and returns custom, clean, and filtered error messages
# TODO: Move out of db_toolkit
def exception_handler():
    def wrapper(func):
        @wraps(func)
        def inner_func(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except ServiceException as e:
                return jsonify(
                    {
                        "title": e.title, 
                        "message": e.message, 
                        "code": e.code
                    }
                ), e.code
            except NameError as e:
                print(repr(e))
                return (
                    jsonify(
                        {
                            "title": "Error",
                            "message": "Could not find requested database. If the problem persists, please contact IT@cls.health.",
                            "code": 404
                        }
                    ),
                    404,
                )
            except TypeError as e:
                print(repr(e))
                return (
                    jsonify(
                        {
                            "title": "Error",
                            "message": "Could not find or process the requested data.",
                            "code": 404
                        }
                    ),
                    404,
                )
            except IntegrityError as e:
                return jsonify({"title": "Error", "message": "Attempted to add a resource that already exists.", "code": 409}), 409
            except Exception as e:
                print(repr(e))
                return (
                    jsonify(
                        {
                            "title": "Error", 
                            "message": "Oops! An internal server error occurred.", 
                            "code": 500
                        }
                    ),
                    500,
                )

        return inner_func

    return wrapper

# Wrapper that authorizes based off the given list of authorized roles.
#TODO: Move out of db_toolkit
def auth_required(authorized_roles: list=["ADMIN"]):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            try:
                access_token = request.headers["Cookie"]
                csrf_token = request.headers["X-CSRF-TOKEN"]
            except Exception:
                raise ServiceException("Unauthorized", "No access token found", 401)
            try:
                # DOCKER #
                if platform.system() == "Linux":
                    response = requests.post(
                        url="http://auth_api:5000/auth_api/verify",
                        json={
                            "access_token": access_token,
                            "csrf_token": csrf_token,
                        },
                    )
                # LOCAL #
                else:
                    response = requests.post(
                        url="http://localhost:5000/auth_api/verify",
                        json={
                            "access_token": access_token,
                            "csrf_token": csrf_token,
                        },
                    )
            except Exception:
                raise ServiceException("Unauthorized", "Could not verify token.", 401)

            role = response.json()["Role"]
            if role is not "UNAUTHORIZED" and "ALL" in authorized_roles:
                authorized_roles.append(role)
                
            if role == "ADMIN" or (role in authorized_roles):
                return fn(*args, **kwargs)
            else:
                raise ServiceException("Unauthorized", "Authorized Personnel Only!", 401)

        return decorator

    return wrapper


def delete(connection, request_data):
    Table = get_class_by_tablename(request_data["table"])
    sess = connection.session
    data = sess.query(Table)
    for id in request_data["data"]:
        obj = data.filter(getattr(Table, request_data["deleteKey"]) == id).first()
        if obj:
            sess.delete(obj)
            sess.commit()
        else:
            return jsonify("User does not exist"), 422
    return jsonify("Success"), 200


def edit(connection, request_data):
    sess = connection.session
    Table = get_class_by_tablename(request_data['table'])
    for obj in request_data['data']:
        data = sess.query(Table).filter(getattr(Table, obj['editKey']) == obj['editValue']).first()
        setattr(data, obj['column'], obj['value'])
    sess.commit()
    return jsonify("Success"), 200
