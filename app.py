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
    
    



if __name__ == '__main__':
    app.run(debug=True)
