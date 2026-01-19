#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

user_schema = UserSchema()
recipe_schema = RecipeSchema()
recipes_schema = RecipeSchema(many=True)


with app.app_context():
    db.create_all()


class Signup(Resource):
    def post(self):
        data = request.get_json() or {}

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {'errors': ['Username and password are required']}, 422

        user = User(
            username=username,
            image_url=data.get('image_url'),
            bio=data.get('bio'),
        )

        try:
            user.password_hash = password
            db.session.add(user)
            db.session.commit()
        except (IntegrityError, ValueError) as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

        session['user_id'] = user.id
        return user_schema.dump(user), 201


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        user = User.query.get(user_id)
        if not user:
            return {'error': 'Unauthorized'}, 401

        return user_schema.dump(user), 200


class Login(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter(User.username == username).first()
        if user and password and user.authenticate(password):
            session['user_id'] = user.id
            return user_schema.dump(user), 200

        session['user_id'] = None
        return {'error': 'Unauthorized'}, 401


class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session.pop('user_id', None)
            return '', 204

        return {'error': 'Unauthorized'}, 401


class RecipeIndex(Resource):
    def get(self):
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401

        recipes = Recipe.query.all()
        return recipes_schema.dump(recipes), 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        data = request.get_json() or {}

        try:
            recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=user_id,
            )
            db.session.add(recipe)
            db.session.commit()
        except (IntegrityError, ValueError) as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

        return recipe_schema.dump(recipe), 201


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
