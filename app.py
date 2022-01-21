from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt

import os

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.sqlite')

db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
CORS(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = password


class UserSchema(ma.Schema):
    class Meta:
        fields = ("username", "password")

user_schema = UserSchema()
multiple_user_schema = UserSchema(many=True)


@app.route("/user/add", methods=["POST"])
def add_user():
    if request.content_type != "application/json":
        return jsonify("Error: Data must be sent as JSON")

    post_data = request.get_json()
    username = post_data.get("username")
    password = post_data.get("password")

    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    new_record = User(username, pw_hash)
    db.session.add(new_record)
    db.session.commit()

    return jsonify(user_schema.dump(new_record))

@app.route("/user/verification", methods=["POST"])
def verification():
    if request.content_type != "application/json":
        return jsonify("Error: Check your headers!")

    post_data = request.get_json()
    username = post_data.get("username")
    password = post_data.get("password")

    user = db.session.query(User).filter(User.username == username).first()

    if user is None:
        return jsonify("User NOT verified")

    if not bcrypt.check_password_hash(user.password, password):
        return jsonify("User NOT verified")

    return jsonify("User verified")

@app.route("/user/get", methods=["GET"])
def get_all_users():
    all_users = db.session.query(User).all()
    return jsonify(multiple_user_schema.dump(all_users))

@app.route("/user/updatePassword/<id>", methods=["PUT"])
def update_password(id):
    if request.content_type != "application/json":
        return jsonify("Error: Data must be sent as JSON")

    password = request.get_json().get("password")
    user = db.session.query(User).filter(User.id == id).first()
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    user.password = pw_hash

    db.session.commit()

    return jsonify(user_schema.dump(user))







if __name__ == "__main__":
    app.run(debug=True)