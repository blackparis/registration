from flask import Flask, render_template, url_for, redirect, request, jsonify, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import random
import envs
from models import *
import util
from datetime import datetime
import json

application = Flask(__name__)
application.config["SESSION_PERMANENT"] = True
application.config["SESSION_TYPE"] = "filesystem"
Session(application)

application.config["SQLALCHEMY_DATABASE_URI"] = envs.DATABASE_URL
application.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(application)

application.config["SECRET_KEY"] = envs.SECRET_KEY


@application.route("/")
def homepage():
    return redirect("https://paris-sanskrit.com/login", code=302)


@application.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "GET":
        return render_template(
            "register.html"
        )

    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    password1 = request.form.get("password1")

    if not username or not email or not password or not password1:
        return render_template(
            "register.html",
            register_error="All fields marked with (*) are required."
        )

    username = username.strip().lower()
    email = email.strip()
    password = password.strip()
    password1 = password1.strip()
    
    
    if "admin" in username or username in envs.reserved_keywords:
        return render_template(
            "register.html",
            register_error="Username not available."
        )
    
    if password1 != password:
        return render_template(
            "register.html",
            register_error="Passwords don't match."
        )


    if not util.validate_email(email):
        return render_template(
            "register.html",
            register_error="Enter a valid email address"
        )

    if not util.validate_password(password):
        return render_template(
            "register.html",
            register_error="Atleast 6 characters long alpha-numeric password."
        )
        
    if not util.validate_username(username):
        return render_template(
            "register.html",
            register_error="Username can have alphanumeric, ( . ), ( - ) or ( _ ) characters."
        )

    u = User.query.filter_by(username=username).first()
    if u != None:
        return render_template(
            "register.html",
            register_error="This username is not available."
        )

    e = User.query.filter_by(email=email).first()
    if e != None:
        return render_template(
            "register.html",
            register_error="This email is associated with another account"
        )

    password = generate_password_hash(password)
    code = str(random.randint(100000, 999999))

    session["registration"] = {
        "username": username,
        "password": password,
        "email": email,
        "code": code
    }
    
    if util.sendemail(email, code):
        return redirect(url_for('verification'))
    
    return redirect(url_for('cancelverification'))


@application.route("/verification", methods=["POST", "GET"])
def verification():
    if session.get("registration") == None:
        return redirect(url_for('homepage'))
    
    if request.method == "GET":
        return render_template(
            "verify.html",
            email=session["registration"]["email"]
        )

    code = request.form.get("code")
    if not code:
        return render_template(
            "verify.html",
            email=session["registration"]["email"],
            verify_error="enter the verification code"
        )
    
    if code != session["registration"]["code"]:
        return render_template(
            "verify.html",
            email=session["registration"]["email"],
            verify_error="Incorrect verification code."
        )
    
    return redirect(url_for('confirmation'))


@application.route("/confirmation")
def confirmation():
    if session.get("registration") == None:
        return redirect(url_for('homepage'))
    
    user = User(
        username=session["registration"]["username"],
        email=session["registration"]["email"],
        password=session["registration"]["password"]
    )

    db.session.add(user)
    db.session.commit()
    session["registration"].clear()
    session["registration"] = None
    
    return redirect(url_for('homepage'))


@application.route("/cancelverification")
def cancelverification():
    if session.get("registration") != None:
        session["registration"].clear()
        session["registration"] = None

    return redirect(url_for('homepage'))


@application.route("/resendVerificationCode")
def resendVerificationCode():
    if session.get("registration") == None:
        return redirect(url_for('homepage'))

    code = str(random.randint(100000, 999999))

    session["registration"]["code"] = code
    
    if util.sendemail(session["registration"]["email"], code):
        return redirect(url_for('verification'))
    
    return redirect(url_for('cancelverification'))
    


@application.route("/recover", methods=["POST", "GET"])
def recover():
    if request.method == "GET":
        return render_template(
            "recover.html"
        )

    email = request.form.get("email")

    if not email:
        return render_template(
            "recover.html",
            recover_error="Enter Your Email Address"
        )

    user = User.query.filter_by(email=email).first()
    if user == None:
        return render_template(
            "recover.html",
            recover_error="This email address is not associated with any account."
        )
    
    code = str(random.randint(100000, 999999))
    session["recoverpassword"] = {
        "username": user.username,
        "email": user.email,
        "code": code
    }
    
    if util.sendemail(user.email, code):
        return redirect(url_for('verify'))
    
    return redirect(url_for('cancelRecoverPassword'))


@application.route("/verify", methods=["POST", "GET"])
def verify():
    if session.get("recoverpassword") == None:
        return redirect(url_for('homepage'))

    if request.method == "GET":
        return render_template(
            "verify.html",
            recoverpassword = True,
            email=session["recoverpassword"]["email"]
        )
    
    code = request.form.get("code")
    if not code:
        return render_template(
            "verify.html",
            recoverpassword = True,
            email=session["recoverpassword"]["email"],
            verify_error="Enter the recovery code."
        )

    if code != session["recoverpassword"]["code"]:
        return render_template(
            "verify.html",
            recoverpassword = True,
            email=session["recoverpassword"]["email"],
            verify_error="Incorrect Code"
        )
    
    return redirect(url_for('resetpassword'))


@application.route("/resetpassword", methods=["POST", "GET"])
def resetpassword():
    if session.get("recoverpassword") == None:
        return redirect(url_for('homepage'))

    if request.method == "GET":
        return render_template(
            "reset.html"
        )

    password = request.form.get("password")
    password1 = request.form.get("password1")

    if not password or not password1:
        return render_template(
            "reset.html",
            reset_error="All fields marked with (*) are required."
        )
    
    if password != password1:
        return render_template(
            "reset.html",
            reset_error="Passwords don't match"
        )
    
    if not util.validate_password(password):
        return render_template(
            "reset.html",
            reset_error="Atleast 6 characters long alpha-numeric password."
        )

    user = User.query.filter_by(email=session["recoverpassword"]["email"]).first()
    if user == None:
        session["recoverpassword"].clear()
        session["recoverpassword"] = None
        return redirect(url_for('homepage'))
        
    password = generate_password_hash(password)

    user.password = password
    db.session.commit()

    session["recoverpassword"].clear()
    session["recoverpassword"] = None
    return redirect(url_for('homepage'))
    

@application.route("/resendRecoveryCode")
def resendRecoveryCode():
    if session.get("recoverpassword") == None:
        return redirect(url_for('homepage'))

    code = str(random.randint(100000, 999999))
    session["recoverpassword"]["code"] = code
    
    if util.sendemail(session["recoverpassword"]["email"], code):
        return redirect(url_for('verify'))
    
    return redirect(url_for('cancelRecoverPassword'))


@application.route("/cancelRecoverPassword")
def cancelRecoverPassword():
    if session.get("recoverpassword") != None:
        session["recoverpassword"].clear()
        session["recoverpassword"] = None
    
    return redirect(url_for('homepage'))
    

if __name__ == "__main__":
    application.run(port=8080)