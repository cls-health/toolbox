from sqlalchemy import inspect
from sqlalchemy.orm import session
from flask import Flask

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