from sqlalchemy import inspect
from sqlalchemy.orm import session
from sqlalchemy.exc import IntegrityError
from flask import Flask, jsonify
from functools import wraps


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

# Service Exception is a custom exception wrapper 
class ServiceException(Exception):
    def __init__(self, title="Internal Server Error", message="Oops, an error occured.", code=500):
        self.title = title
        self.message = message
        self.code = code
        super().__init__(self.message)   

# Exception handler is a wrapper for routes and returns custom, clean, and filtered error messages
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
