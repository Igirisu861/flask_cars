from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from models import mongo, init_db
from flask_bcrypt import Bcrypt
from config import Config
from bson.json_util import ObjectId

#a continuación se inicializan los diferentes módulos para la app

app = Flask(__name__)
app.config.from_object(Config)

Bcrypt= Bcrypt(app)
jwt = JWTManager(app)

init_db(app)

#definir endpoint para registrar el usuario

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()#esto es como el req.body donde se solicitan los datos en json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    #hay que verificar si existe y asegurarnos de que no se repita
    if mongo.db.users.find_one({'email': email}):
        return jsonify({'msg': 'El usuario ya existe'}), 400 #es básicamente lo mismo que en Node
    
    hashed_password = Bcrypt.generate_password_hash(password).decode('utf-8')


    result = mongo.db.users.insert_one({"username": username, "email": email, "password": hashed_password})
    if result.acknowledged:
        return jsonify({"msg": "Usuario creado correctamente"}), 201
    else:
        return jsonify({"msg": "Hubo un error, los datos no fueron registrados"}), 400
    

#definimos la ruta del endpoint para el login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = mongo.db.users.find_one({"email":email})

    if user and Bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg":"Credenciales incorrectas"}), 401



@app.route('/userlist', methods=['GET'])
def get_users():
    user_list=[]
    for item in mongo.db.users.find({},{"_id":0, "username": 1, "email":1}):
        user_list.append({"username":item['username'], "email": item['email']})

    return jsonify(user_list)


if __name__ == '__main__':
    app.run(debug=True)

