#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api, bcrypt
from models import User

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        #print("INSIDE SIGN UP:");
        json = request.get_json()
        #print(json);
        #print(json["username"]);
        #print(json["password"]);
        user = User(
            username=json['username'],
            password_hash=json['password']
        )
        #print("successfully created the user!");
        db.session.add(user)
        db.session.commit()
        #print(user.to_dict());
        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        skeys = session.keys();
        #print(skeys);
        #print(session.values());
        if (len(skeys) < 1 or "user_id" not in skeys or session["user_id"] == None):
            return {}, 204;
        else: return User.query.filter_by(id = session["user_id"]).first().to_dict(), 200;

class Login(Resource):
    def post(self):
        rjsn = request.get_json();
        #print(rjsn);
        usr = User.query.filter_by(username = rjsn["username"]).first();
        #print(usr);
        #print(usr._password_hash);
        #print(rjsn["password"]);
        #password_hash = bcrypt.generate_password_hash(
        #    rjsn["password"].encode('utf-8'))
        #print(password_hash);
        #self._password_hash = password_hash.decode('utf-8')
        #print(password_hash.decode('utf-8'));
        #if (usr._password_hash == password_hash.decode('utf-8'))
        if (usr.authenticate(rjsn["password"])):
            #print("You are in!");
            session["user_id"] = usr.id;
            return usr.to_dict(), 200;
        else:
            #print("You are out!");
            return {}, 401;

class Logout(Resource):
    def delete(self):
        print("INSIDE OF LOGOUT:");
        if (len(session.keys()) < 1 or "user_id" not in session.keys()): return {}, 204;
        else:
            session["user_id"] = None;
            return {}, 200;

api.add_resource(CheckSession, "/check_session");
api.add_resource(Login, "/login");
api.add_resource(Logout, "/logout");
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
