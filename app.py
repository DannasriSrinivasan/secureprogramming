from flask import Flask, request, jsonify 
from configparser import ConfigParser
import logging, sqlite3, re ,os

logging.basicConfig(filename='/var/log/flask.log',
                level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s : %(message)s')
""" logging.basicConfig(filename='record.log',
                level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s : %(message)s') """

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config/config.ini')

def db_connect():
    config = ConfigParser()
    config.read(CONFIG_PATH)
    con = sqlite3.connect(config.get('main', 'datasource'))
    return con

def nameCheck(name):
    namecheck = re.compile("^[A-Z]\\'?([a-zA-Z]*?\\'?[a-zA-Z]*?\\,?[ ]?\\'?\\-?\\.?){1,3}$")
    return namecheck.match(name)

def phoneCheck(phone):
    phoneCheck=re.compile("(^\\d{5}$)|(^\\d{5}\\.\\d{5}$)|(^\\+[1-9]{1,2}[ ]?\\(|^[1][ ]?\\(|^[0][1][1][ ][1]?[ ]?\\(?|^\\(?)([1-9]\\d{1,2})?\\)?[- ]?(\\d{3})[-| ](\\d{4})$")
    if phoneCheck.match(phone):
        return True
    else:
        anoCheck=re.compile("^1?(\\(\\d{3}\\)|[ ]?\\d{3} |\\.?\\d{3}\\.|-?\\d{3}-)\\d{3}[ .-]?\\d{4}$")
        return anoCheck.match(phone)

def passwordCheck(password):
    checkpass=re.compile("^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,32}$")
    return checkpass.match(password)

def get_data():
    users = []
    try:
        conn = db_connect()
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM phonebook")
        rows = cur.fetchall()
        if len(rows) > 0:
            logging.info("listing all records in the database")
            for i in rows:
                user = {}
                user["name"] = i["name"]
                user["phonenumber"] = i["phonenumber"]
                logging.info("Name: %s  Phone Number: %s", user["name"], user["phonenumber"])
                users.append(user)
        else:
            users = []
    except:
        users = []
        logging.error("Data not retrieved from Phonebook table")
    return users

def insert_data(user):
    name = user['name']
    phone = user['phonenumber']
    if nameCheck(name):
        logging.info("-----------Name Validation Passed----------------")
        if phoneCheck(phone):
            logging.info("-----------Phone Number Validation Passed----------------")
            try:
                conn = db_connect()
                cur = conn.cursor()
                cur.execute("SELECT * from Phonebook WHERE name = ?", (name,))
                rows = cur.fetchall()
                if len(rows) == 0:
                    try:
                        cur.execute("INSERT INTO phonebook (name, phonenumber) VALUES (?, ?)", (name,   
                                    phone) )
                        conn.commit()
                        logging.info("Name: %s and Phone Number: %s added successfully", name, phone)
                        return jsonify({'description': 'Success','message' : 'User Inserted successfully'}), 200
                    except:
                        logging.error("%s Record not found.", name)
                        return jsonify({'description': 'Failure','message' : 'User Not inserted successfully'}), 400  
                    finally:
                        conn.close()
                else:
                    logging.error("%s Record already exists.", name)
                    return jsonify({'description': 'Failure','message' : 'Record already exists'}), 404 
            except:
                conn().rollback()
                logging.error("%s User Not found  due to DB connectivity.", name)
                return jsonify({'description': 'Failure','message' : 'User Not found  due to DB connectivity'}), 400
            finally:
                conn.close()
        else:
            logging.error("Phone: %s is not in proper acceptable format.", phone)
            return jsonify({'description': 'Failure','message' : 'Phone Number is not in proper acceptable format'}), 400
    else:
        logging.error("Name: %s is not in proper acceptable format.", name)
        return jsonify({'description': 'Failure','message' : 'Name is not in proper acceptable format'}), 400

def delete_data_byName(user):
    name = user["name"]
    if nameCheck(name):
        logging.info("-----------Name Validation Passed----------------")
        try:
            conn = db_connect()
            cur = conn.cursor()
            cur.execute("SELECT * from Phonebook WHERE name = ?", (name,))
            rows = cur.fetchall()
            if len(rows) > 0:
                try:
                    conn.execute("DELETE from Phonebook WHERE name = ?", (name,))
                    conn.commit()
                    logging.info("%s Record Deleted Successfully.", name)
                    return jsonify({'description': 'Success','message' : 'User deleted successfully'}), 200
                except:
                    conn.rollback()
                    logging.error("%s Record not Deleted Successfully.", name)
                    return jsonify({'description': 'Failure','message' : 'User not deleted successfully'}), 400
                finally:
                    conn.close()
            else:
               logging.error("%s Record not found.", name)
               return jsonify({'description': 'Failure','message' : 'User not found'}), 404  
        except:
            conn.rollback()
            logging.error("Failed to fetch %s due to issues with Db Connectivity .", name)
            return jsonify({'description': 'Failure','message' : 'Issues with DB Connection'}), 400
        finally:
            conn.close()
    else:
         logging.error("%s is not in proper acceptable format.", name)
         return jsonify({'description': 'Failure','message' : 'Name is not in proper acceptable format'}), 400



def delete_data_byPhonenumber(user):
    phone = user["phonenumber"]
    name = ""
    if phoneCheck(phone):
        logging.info("-----------Phone Number Validation Passed----------------")
        try:
            conn = db_connect()
            cur = conn.cursor()
            cur.execute("SELECT * from Phonebook WHERE phonenumber = ?", (phone,))
            rows = cur.fetchall()
            if len(rows) > 0:
                for i in rows:
                    name = i[0]
                try:
                    conn.execute("DELETE from Phonebook WHERE phonenumber = ?", (phone,))
                    conn.commit()
                    logging.info("%s, %s Record Deleted Successfully.", name, phone)
                    return jsonify({'description': 'Success', 'message' : 'User deleted successfully'}), 200
                except:
                    conn.rollback()
                    logging.error("%s, %s Record not Deleted Successfully.", name, phone)
                    return jsonify({'description': 'Failure','message' : 'User not deleted successfully'}), 400
                finally:
                    conn.close()
            else:
               logging.error("%s Record not found.", phone)
               return jsonify({'description': 'Failure','message' : 'User not found'}), 404  
        except:
            conn.rollback()
            logging.error("Failed to fetch %s Issues with DB Connection.", phone)
            return jsonify({'description': 'Failure','message' : 'Issues with DB Connection'}), 400
        finally:
            conn.close()
    else:
        logging.error("Phone Number: %s is not in proper acceptable format.", phone)
        return jsonify({'description': 'Failure','message' : 'Phone is not in proper acceptable format'}), 400

app = Flask(__name__)

#app.config["SECRET_KEY"] = "secret-key-phoneBook-api"  

""" @app.before_first_request
def create_db_table():
    app.logger.info("Info log information")
    try:
        conn = db_connect()
        conn.execute('''
            CREATE TABLE phonebook (
                name TEXT NOT NULL,
                phonenumber TEXT NOT NULL
            );
        ''')

        conn.commit()
        logging.info("Phonebook table created successfully")
    except:
        logging.info("Phonebook table exists already or not created successfully")
    finally:
        conn.close() """

""" def create_user_table():
    try:
        conn = db_connect()
        conn.execute('''
            CREATE TABLE userdata (
                name TEXT NOT NULL,
                password TEXT NOT NULL
            );
        ''')

        conn.commit()
        logging.info("Phonebook table created successfully")
    except:
        logging.info("Phonebook table exists already or not created successfully")
    finally:
        conn.close() """


""" @app.route("/usertable", methods=['GET'])
def usertable():
    create_user_table()
    name = request.authorization.username
    password = request.authorization.password
    if nameCheck(name):
        if passwordCheck(password):
            try:
                conn = db_connect()
                cur = conn.cursor()
                cur.execute("INSERT INTO userdata (name, password) VALUES (?, ?)", (name,   
                            password) )
                conn.commit()
                logging.info("Name: %s and Phone Number: %s added successfully", name, password)
                return jsonify({'description': 'Success','message' : 'User Inserted successfully'}), 200
            except:
                logging.error("%s Record not found.", name)
                return jsonify({'description': 'Failure','message' : 'User Not inserted successfully'}), 400  
            finally:
                conn.close()
        else:
            return jsonify({'description': 'failure','message' : 'incorrect password'}), 400
    else:
        return jsonify({'description': 'failure','message' : 'incorrect password'}), 400 """



""" def check_for_token(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = request.headers['token']
		if not token:
			return jsonify({'message' : 'Token missing'}), 403
		try:
			data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
		except:
			return jsonify({'message' : 'Invalid token'}), 403
		return f(*args, **kwargs)
	return decorated """

""" @app.route("/login", methods=['GET'])
def login():
	auth = request.authorization
	if auth and auth.password == 'Qwerty123':
		token = jwt.encode({'user' : auth.username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=20)}, app.config['SECRET_KEY'], "HS256")
		return jsonify({'token' : token})
	else:
		return make_response('Unable to verify'), 403 """


@app.route('/PhoneBook/list', methods=['GET'])
def api_get_users():
    app.logger.info("-----------------------------------------Inside List API--------------------------------------------")
    name = request.authorization.username
    password = request.authorization.password
    namedb = ''
    passworddb = ''
    if nameCheck(name):
        if passwordCheck(password):
            try:
                conn = db_connect()
                cur = conn.cursor()
                cur.execute("SELECT * from userdata WHERE name = ? and password = ?", (name, password))
                conn.commit()
                rows = cur.fetchall()
                if len(rows) > 0:
                    for i in rows:
                        namedb = i[0]
                        passworddb = i[1]
                if(namedb == name and passworddb == password):
                    logging.info("Authentication passed")
                    return jsonify(get_data())
                else:
                    logging.error("users does not matach", )
                    return jsonify({'description': 'Failure','message' : 'Authentication Failed, user does not match'}), 400 
            except:
                logging.error("Authentication Failed")
                return jsonify({'description': 'Failure','message' : 'Authentication Failed'}), 400  
            finally:
                conn.close()
        else:
            logging.error("password unacceptable", )
            return jsonify({'description': 'failure','message' : 'Password not accepted'}), 400
    else:
        logging.error("username unacceptable")
        return jsonify({'description': 'failure','message' : 'username not accepted'}), 400


@app.route('/PhoneBook/add',  methods = ['POST'])
def api_add_user():
    app.logger.info("-----------------------------------------Inside Inserting the record API--------------------------------------------")
    name = request.authorization.username
    password = request.authorization.password
    namedb = ''
    passworddb = ''
    if nameCheck(name):
        if passwordCheck(password):
            try:
                conn = db_connect()
                cur = conn.cursor()
                cur.execute("SELECT * from userdata WHERE name = ? and password = ?", (name, password))
                conn.commit()
                rows = cur.fetchall()
                if len(rows) > 0:
                    for i in rows:
                        namedb = i[0]
                        passworddb = i[1]
                if(namedb == name and passworddb == password):
                    logging.info("Authentication Passed")
                    user = request.get_json()
                    return insert_data(user)
                else:
                    logging.error("User Not found")
                    return jsonify({'description': 'Failure','message' : 'Authentication Failed, user does not match'}), 400 
            except:
                logging.error("Authentication failed")
                return jsonify({'description': 'Failure','message' : 'Authentication Failed'}), 400  
            finally:
                conn.close()
        else:
            logging.error("Password unacceptable")
            return jsonify({'description': 'failure','message' : 'Password not accepted'}), 400
    else:
        logging.error("username unacceptable")
        return jsonify({'description': 'failure','message' : 'username not accepted'}), 400
    
    
    


@app.route('/PhoneBook/deleteByName',  methods = ['PUT'])
def api_delete_userByName():
    app.logger.info("-----------------------------------------Inside Delete by name API--------------------------------------------")
    name = request.authorization.username
    password = request.authorization.password
    namedb = ''
    passworddb = ''
    if nameCheck(name):
        if passwordCheck(password):
            try:
                conn = db_connect()
                cur = conn.cursor()
                cur.execute("SELECT * from userdata WHERE name = ? and password = ?", (name, password))
                conn.commit()
                rows = cur.fetchall()
                if len(rows) > 0:
                    for i in rows:
                        namedb = i[0]
                        passworddb = i[1]
                if(namedb == name and passworddb == password):
                    logging.info("Authentication Passed")
                    user = request.get_json()
                    return delete_data_byName(user)
                else:
                    logging.error("User not found")
                    return jsonify({'description': 'Failure','message' : 'Authentication Failed, user does not match'}), 400 
            except:
                logging.error("Authentcation Failed")
                return jsonify({'description': 'Failure','message' : 'Authentication Failed'}), 400  
            finally:
                conn.close()
        else:
            logging.error("Passowrd unacceptable")
            return jsonify({'description': 'failure','message' : 'Password not accepted'}), 400
    else:
        logging.error("username unacceptable")
        return jsonify({'description': 'failure','message' : 'username not accepted'}), 400
    
    


@app.route('/PhoneBook/deleteByNumber',  methods = ['PUT'])
def api_delete_userByPhonenumber():
    app.logger.info("-----------------------------------------Inside Delete by phone API--------------------------------------------")
    name = request.authorization.username
    password = request.authorization.password
    namedb = ''
    passworddb = ''
    if nameCheck(name):
        if passwordCheck(password):
            try:
                conn = db_connect()
                cur = conn.cursor()
                cur.execute("SELECT * from userdata WHERE name = ? and password = ?", (name, password))
                conn.commit()
                rows = cur.fetchall()
                if len(rows) > 0:
                    for i in rows:
                        namedb = i[0]
                        passworddb = i[1]
                if(namedb == name and passworddb == password):
                    logging.info("Authentication Passed")
                    user = request.get_json()
                    return delete_data_byPhonenumber(user)
                else:
                    logging.error("User not found")
                    return jsonify({'description': 'Failure','message' : 'Authentication Failed, user does not match'}), 400 
            except:
                logging.error("Authentication failed")
                return jsonify({'description': 'Failure','message' : 'Authentication Failed'}), 400  
            finally:
                conn.close()
        else:
            logging.error("Password not accepted")
            return jsonify({'description': 'failure','message' : 'Password not accepted'}), 400
    else:
        logging.error("username not accepted")
        return jsonify({'description': 'failure','message' : 'username not accepted'}), 400
    


   

if __name__ == "__main__":
    app.debug = True
    app.logger.info("-----------------------------------------Satrting the Application--------------------------------------------")
    app.run(host='0.0.0.0', port=80)
    #app.run(debug = True) #run app
