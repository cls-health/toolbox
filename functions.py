from sqlalchemy import inspect
from sqlalchemy.orm import session

# dynamically adds data into a given db_model
# params -> sess: session, data: dictionary vals of data, db_name: model name
def add_to_db(sess: session, data: dict, db_name):
    new_obj = db_name()
    mapper = inspect(new_obj)
    for column in mapper.attrs:
        for val in data:
            if val == column.key and val != None:
                setattr(new_obj, column.key, data[val])

    sess.add(new_obj) 
    return new_obj

# converts dictionary keys from camel case to snake case 
def camel_to_snake(data: dict) -> dict:
    snake_dictionary = dict()
    for key in data:
        if type(key) == str and any(ele.isupper() for ele in key):
            new_key = ""
            for letter in key:
                if letter.isupper():
                    new_key = new_key + "_" + letter.lower()
                else:
                    new_key = new_key + letter
            snake_dictionary[new_key] = data[key]
        else:
            snake_dictionary[key] = data[key]
    return snake_dictionary
